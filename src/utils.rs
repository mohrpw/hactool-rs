#![allow(dead_code)]

use crate::sha::par_verify_blocks_with_suffix;
use crate::types::{Filepath, RandomAccessReader, Validity};
use std::cell::RefCell;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::process;
use std::sync::Mutex;

pub const SCRATCH_BUF_SIZE: usize = 0x40_0000;

thread_local! {
    static WORKER_SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Executes `f` with a thread-local reusable scratch buffer capped at `SCRATCH_BUF_SIZE` (4 MiB),
/// eliminating repeated large allocations and zero-fills across thousands of extracted files.
pub fn with_worker_scratch<R>(needed: usize, f: impl FnOnce(&mut [u8]) -> R) -> R {
    let target_len = needed.clamp(1, SCRATCH_BUF_SIZE);
    WORKER_SCRATCH.with(|cell| {
        if let Ok(mut vec) = cell.try_borrow_mut() {
            if vec.len() < target_len {
                vec.resize(target_len, 0);
            }
            f(&mut vec[..target_len])
        } else {
            let mut fallback = vec![0u8; target_len];
            f(&mut fallback[..])
        }
    })
}

/// Synchronized, buffered stdout writer for parallel `Saving ...` messages in completion order.
/// When `quiet` is true, all extraction progress lines are suppressed without taking the stdout lock.
pub struct BufferedLineWriter {
    inner: Option<Mutex<BufWriter<io::Stdout>>>,
}

impl BufferedLineWriter {
    pub fn new(quiet: bool) -> Self {
        if quiet {
            Self { inner: None }
        } else {
            let _ = io::stdout().flush();
            Self {
                inner: Some(Mutex::new(BufWriter::with_capacity(
                    64 * 1024,
                    io::stdout(),
                ))),
            }
        }
    }

    #[inline]
    pub fn log_saving(&self, display_path: &str) {
        if let Some(ref mtx) = self.inner {
            if let Ok(mut guard) = mtx.lock() {
                let _ = writeln!(guard, "Saving {}...", display_path);
            }
        }
    }

    #[inline]
    pub fn log_saving_to(&self, name: &str, dest_path: &str) {
        if let Some(ref mtx) = self.inner {
            if let Ok(mut guard) = mtx.lock() {
                let _ = writeln!(guard, "Saving {} to {}...", name, dest_path);
            }
        }
    }

    #[inline]
    pub fn flush(&self) {
        if let Some(ref mtx) = self.inner {
            if let Ok(mut guard) = mtx.lock() {
                let _ = guard.flush();
            }
        }
    }
}

impl Drop for BufferedLineWriter {
    fn drop(&mut self) {
        self.flush();
    }
}

pub const MEDIA_SIZE: u64 = 0x200;

#[inline]
pub fn align(offset: u32, alignment: u32) -> u32 {
    let mask = !(alignment - 1);
    (offset + (alignment - 1)) & mask
}

#[inline]
pub fn align64(offset: u64, alignment: u64) -> u64 {
    let mask = !(alignment - 1);
    (offset + (alignment - 1)) & mask
}

#[inline]
pub fn media_to_real(media: u64) -> u64 {
    MEDIA_SIZE * media
}

pub fn print_magic(prefix: &str, magic: u32) {
    let b = magic.to_le_bytes();
    println!(
        "{}{}{}{}{}",
        prefix, b[0] as char, b[1] as char, b[2] as char, b[3] as char
    );
}

pub fn memdump_stdout(prefix: &str, data: &[u8]) {
    let prefix_len = prefix.len();
    let mut offset = 0;
    let mut first = true;
    let mut remaining = data.len();

    while remaining > 0 {
        let max = remaining.min(32);
        if first {
            print!("{}", prefix);
            first = false;
        } else {
            print!("{:width$}", "", width = prefix_len);
        }
        for i in 0..max {
            print!("{:02X}", data[offset + i]);
        }
        println!();
        offset += max;
        remaining -= max;
    }
}

pub fn os_makedir<P: AsRef<Path>>(dir: P) {
    let _ = fs::create_dir_all(dir);
}

pub fn os_rmdir<P: AsRef<Path>>(dir: P) {
    let _ = fs::remove_dir(dir);
}

/// Creates/truncates an output file and, on Windows NTFS directories with inherited
/// `FILE_ATTRIBUTE_COMPRESSED`, clears LZNT1 compression via `FSCTL_SET_COMPRESSION`
/// before writing high-entropy Switch payloads. On uncompressed folders this adds
/// zero `DeviceIoControl` calls.
#[cfg(windows)]
pub fn create_uncompressed_file<P: AsRef<Path>>(path: P) -> io::Result<File> {
    use std::ffi::c_void;
    use std::fs::OpenOptions;
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::AsRawHandle;

    const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x0800;
    const FSCTL_SET_COMPRESSION: u32 = 0x0009_C040;
    const COMPRESSION_FORMAT_NONE: u16 = 0;

    #[link(name = "kernel32")]
    extern "system" {
        fn DeviceIoControl(
            h_device: *mut c_void,
            dw_io_control_code: u32,
            lp_in_buffer: *mut c_void,
            n_in_buffer_size: u32,
            lp_out_buffer: *mut c_void,
            n_out_buffer_size: u32,
            lp_bytes_returned: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
    }

    let path = path.as_ref();
    // FSCTL_SET_COMPRESSION requires FILE_READ_DATA | FILE_WRITE_DATA access.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .or_else(|_| File::create(path))?;

    let is_compressed = file
        .metadata()
        .map(|m| (m.file_attributes() & FILE_ATTRIBUTE_COMPRESSED) != 0)
        .unwrap_or(false);

    if is_compressed {
        let mut format = COMPRESSION_FORMAT_NONE;
        let mut bytes_returned: u32 = 0;
        // Best-effort: ignore unsupported filesystems (FAT32/exFAT/network shares).
        unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_SET_COMPRESSION,
                (&mut format as *mut u16).cast(),
                std::mem::size_of::<u16>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            );
        }
    }

    Ok(file)
}

/// Creates/truncates an output file (pass-through to `File::create` on non-Windows targets).
#[cfg(not(windows))]
pub fn create_uncompressed_file<P: AsRef<Path>>(path: P) -> io::Result<File> {
    File::create(path)
}

pub fn save_buffer_to_file(buf: &[u8], filepath: &Filepath) {
    match create_uncompressed_file(&filepath.char_path) {
        Ok(mut f) => {
            let _ = f.write_all(buf);
        }
        Err(_) => {
            eprintln!("Failed to open {}!", filepath.char_path);
        }
    }
}

pub fn save_buffer_to_directory_file(buf: &[u8], dirpath: &Filepath, filename: &str) {
    let mut fp = Filepath::new();
    fp.copy_from(dirpath);
    fp.append(filename);
    if fp.is_valid() {
        save_buffer_to_file(buf, &fp);
    } else {
        eprintln!("Failed to create filepath!");
        process::exit(1);
    }
}

/// Optimized file-section writer that reuses a thread-local scratch buffer up to 4 MiB,
/// eliminating repeated heap allocations and zero-fills while letting the OS stream sequentially.
pub fn save_file_section(
    reader: &dyn RandomAccessReader,
    mut ofs: u64,
    total_size: u64,
    filepath: &Filepath,
) {
    let mut f_out = match create_uncompressed_file(&filepath.char_path) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("Failed to open {}!", filepath.char_path);
            return;
        }
    };
    if total_size == 0 {
        return;
    }

    let end_ofs = ofs + total_size;
    with_worker_scratch(total_size.min(SCRATCH_BUF_SIZE as u64) as usize, |buf| {
        while ofs < end_ofs {
            let read_size = ((end_ofs - ofs) as usize).min(buf.len());
            if reader.read_exact_at(ofs, &mut buf[..read_size]).is_err() {
                eprintln!("Failed to read file!");
                process::exit(1);
            }
            if f_out.write_all(&buf[..read_size]).is_err() {
                eprintln!("Failed to write file!");
                process::exit(1);
            }
            ofs += read_size as u64;
        }
    });
}

pub fn check_memory_hash_table(
    reader: &dyn RandomAccessReader,
    hash_table: &[u8],
    data_ofs: u64,
    data_len: u64,
    block_size: u64,
    full_block: bool,
) -> Validity {
    check_memory_hash_table_with_suffix(
        reader,
        hash_table,
        data_ofs,
        data_len,
        block_size,
        None,
        full_block,
    )
}

pub fn check_memory_hash_table_with_suffix(
    reader: &dyn RandomAccessReader,
    hash_table: &[u8],
    data_ofs: u64,
    data_len: u64,
    block_size: u64,
    suffix: Option<&[u8]>,
    full_block: bool,
) -> Validity {
    if block_size == 0 {
        return Validity::Invalid;
    }
    let mut read_len = data_len as usize;
    if full_block && (read_len % (block_size as usize) != 0) {
        read_len = ((read_len / (block_size as usize)) + 1) * (block_size as usize);
    }
    let mut data = vec![0u8; read_len];
    let n = reader.read_at(data_ofs, &mut data).unwrap_or(0);
    if n < data_len as usize {
        eprintln!("Failed to read file!");
        process::exit(1);
    }
    if par_verify_blocks_with_suffix(&data, hash_table, block_size as usize, suffix) {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

pub fn check_file_hash_table(
    reader: &dyn RandomAccessReader,
    hash_ofs: u64,
    data_ofs: u64,
    data_len: u64,
    block_size: u64,
    full_block: bool,
) -> Validity {
    if block_size == 0 {
        return Validity::Invalid;
    }
    let mut num_blocks = data_len / block_size;
    if data_len % block_size != 0 {
        num_blocks += 1;
    }
    let hash_table_size = (num_blocks * 0x20) as usize;
    let mut hash_table = vec![0u8; hash_table_size];
    if reader.read_exact_at(hash_ofs, &mut hash_table).is_err() {
        eprintln!("Failed to read file!");
        process::exit(1);
    }
    check_memory_hash_table(reader, &hash_table, data_ofs, data_len, block_size, full_block)
}

pub fn get_key_revision_summary(key_rev: u8) -> &'static str {
    match key_rev {
        0 => "1.0.0-2.3.0",
        1 => "3.0.0",
        2 => "3.0.1-3.0.2",
        3 => "4.0.0-4.1.0",
        4 => "5.0.0-5.1.0",
        5 => "6.0.0-6.1.0",
        6 => "6.2.0",
        7 => "7.0.0-8.0.1",
        8 => "8.1.0-8.1.1",
        9 => "9.0.0-9.0.1",
        0xA => "9.1.0-",
        _ => "Unknown",
    }
}

pub fn open_key_file(prefix: &str) -> Option<File> {
    let home = env::var("HOME").or_else(|_| env::var("USERPROFILE")).ok();
    if let Some(ref h) = home {
        let mut p = Filepath::new();
        p.set(h);
        p.append(".switch");
        p.append(&format!("{}.keys", prefix));
        if p.is_valid() {
            if let Ok(f) = File::open(p.as_path()) {
                return Some(f);
            }
        }
    }

    let mut p = Filepath::new();
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        p.set(&xdg);
    } else if let Some(ref h) = home {
        p.set(h);
        p.append(".config");
    }
    p.append("switch");
    p.append(&format!("{}.keys", prefix));
    if p.is_valid() {
        if let Ok(f) = File::open(p.as_path()) {
            return Some(f);
        }
    }
    None
}

