#![allow(dead_code)]

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Validity {
    #[default]
    Unchecked = 0,
    Invalid = 1,
    Valid = 2,
}

impl Validity {
    #[inline]
    pub fn as_str(self) -> &'static str {
        if self == Validity::Valid {
            "GOOD"
        } else {
            "FAIL"
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeysetVariant {
    Dev,
    #[default]
    Retail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BaseFileType {
    #[default]
    None,
    Romfs,
    Nca,
    Fake,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileType {
    #[default]
    Nca,
    Pfs0,
    Romfs,
    Nca0Romfs,
    Hfs0,
    Xci,
    Npdm,
    Package1,
    Package2,
    Ini1,
    Kip1,
    Nso0,
    Nax0,
    Boot0,
    Save,
}

pub const ACTION_INFO: u32 = 1 << 0;
pub const ACTION_EXTRACT: u32 = 1 << 1;
pub const ACTION_VERIFY: u32 = 1 << 2;
pub const ACTION_RAW: u32 = 1 << 3;
pub const ACTION_LISTROMFS: u32 = 1 << 4;
pub const ACTION_DEV: u32 = 1 << 5;
pub const ACTION_EXTRACTINI1: u32 = 1 << 6;
pub const ACTION_ONLYUPDATEDROMFS: u32 = 1 << 7;
pub const ACTION_SAVEINIJSON: u32 = 1 << 8;
pub const ACTION_LISTFILES: u32 = 1 << 9;

pub const MAX_PATH: usize = 1024;

pub const MAGIC_META: u32 = 0x4154454D;
pub const MAGIC_ACID: u32 = 0x44494341;
pub const MAGIC_ACI0: u32 = 0x30494341;
pub const MAGIC_PFS0: u32 = 0x30534650;
pub const MAGIC_HFS0: u32 = 0x30534648;
pub const MAGIC_IVFC: u32 = 0x43465649;
pub const MAGIC_BKTR: u32 = 0x52544B42;
pub const MAGIC_NCA3: u32 = 0x3341434E;
pub const MAGIC_NCA2: u32 = 0x3241434E;
pub const MAGIC_NCA0: u32 = 0x3041434E;
pub const MAGIC_HEAD: u32 = 0x44414548;
pub const MAGIC_NSO0: u32 = 0x304F534E;
pub const MAGIC_INI1: u32 = 0x31494E49;
pub const MAGIC_KIP1: u32 = 0x3150494B;
pub const MAGIC_PK11: u32 = 0x31314B50;
pub const MAGIC_PK21: u32 = 0x31324B50;
pub const MAGIC_NAX0: u32 = 0x3058414E;
pub const MAGIC_DISF: u32 = 0x46534944;
pub const MAGIC_DPFS: u32 = 0x53465044;
pub const MAGIC_JNGL: u32 = 0x4C474E4A;
pub const MAGIC_SAVE: u32 = 0x45564153;
pub const MAGIC_RMAP: u32 = 0x50414D52;

/// Lock-free random-access reader abstraction (`ReadAt`).
/// Enables multi-threaded reading, hashing, and extraction without seek contention.
pub trait RandomAccessReader: Send + Sync {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    fn read_exact_at(&self, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = self.read_at(offset, buf)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ));
            }
            offset += n as u64;
            buf = &mut buf[n..];
        }
        Ok(())
    }
}

/// Platform-native positioned file reader.
#[derive(Clone)]
pub struct SharedFile {
    file: Arc<File>,
    len: u64,
}

impl SharedFile {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let f = File::open(path)?;
        Ok(Self::from_file(f))
    }

    pub fn from_file(file: File) -> Self {
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        Self {
            file: Arc::new(file),
            len,
        }
    }

    #[inline]
    pub fn new(file: File) -> Self {
        Self::from_file(file)
    }

    #[inline]
    pub fn len(&self) -> u64 {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        RandomAccessReader::read_at(self, offset, buf)
    }

    #[inline]
    pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        RandomAccessReader::read_exact_at(self, offset, buf)
    }
}

impl RandomAccessReader for SharedFile {
    #[cfg(windows)]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::windows::fs::FileExt;
        self.file.seek_read(buf, offset)
    }

    #[cfg(unix)]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        self.file.read_at(buf, offset)
    }

    #[cfg(not(any(windows, unix)))]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = self.file.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f.read(buf)
    }
}

impl RandomAccessReader for [u8] {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let ofs = offset as usize;
        if ofs >= self.len() {
            return Ok(0);
        }
        let avail = &self[ofs..];
        let to_copy = avail.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&avail[..to_copy]);
        Ok(to_copy)
    }
}

impl RandomAccessReader for Vec<u8> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.as_slice().read_at(offset, buf)
    }
}

/// Represents `filepath_t` from C hactool, preserving the exact string representation
/// (`char_path`) printed by hactool in `Saving ...` messages as well as OS path operations.
#[derive(Debug, Clone, Default)]
pub struct Filepath {
    pub char_path: String,
    pub valid: Validity,
}

impl Filepath {
    pub fn new() -> Self {
        Self {
            char_path: String::new(),
            valid: Validity::Invalid,
        }
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.valid == Validity::Valid
    }

    pub fn set(&mut self, path: &str) {
        if path.len() < 1023 {
            self.valid = Validity::Valid;
            self.char_path.clear();
            self.char_path.push_str(path);
        } else {
            self.valid = Validity::Invalid;
        }
    }

    pub fn copy_from(&mut self, other: &Filepath) {
        if other.valid == Validity::Valid {
            self.char_path = other.char_path.clone();
            self.valid = Validity::Valid;
        } else {
            self.char_path.clear();
            self.valid = Validity::Unchecked;
        }
    }

    #[inline]
    pub fn os_sep() -> &'static str {
        if cfg!(windows) {
            "\\"
        } else {
            "/"
        }
    }

    pub fn append(&mut self, segment: &str) {
        if self.valid != Validity::Valid {
            return;
        }
        self.char_path.push_str(Self::os_sep());
        self.char_path.push_str(segment);
    }

    pub fn append_n(&mut self, n: usize, segment: &str) {
        if self.valid != Validity::Valid || n > 1023 {
            return;
        }
        self.char_path.push_str(Self::os_sep());
        let bytes = segment.as_bytes();
        let take = bytes.len().min(n);
        let actual = bytes[..take]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(take);
        let s = String::from_utf8_lossy(&bytes[..actual]);
        self.char_path.push_str(&s);
    }

    pub fn as_path(&self) -> PathBuf {
        PathBuf::from(&self.char_path)
    }
}

#[derive(Debug, Clone, Default)]
pub struct OverrideFilepath {
    pub enabled: bool,
    pub path: Filepath,
}

// Little-endian binary reader helpers for zero-overhead struct field parsing
#[inline]
pub fn read_u16_le(buf: &[u8], ofs: usize) -> u16 {
    u16::from_le_bytes([buf[ofs], buf[ofs + 1]])
}

#[inline]
pub fn read_u32_le(buf: &[u8], ofs: usize) -> u32 {
    u32::from_le_bytes([buf[ofs], buf[ofs + 1], buf[ofs + 2], buf[ofs + 3]])
}

#[inline]
pub fn read_u64_le(buf: &[u8], ofs: usize) -> u64 {
    u64::from_le_bytes([
        buf[ofs],
        buf[ofs + 1],
        buf[ofs + 2],
        buf[ofs + 3],
        buf[ofs + 4],
        buf[ofs + 5],
        buf[ofs + 6],
        buf[ofs + 7],
    ])
}

#[inline]
pub fn write_u32_le(buf: &mut [u8], ofs: usize, val: u32) {
    buf[ofs..ofs + 4].copy_from_slice(&val.to_le_bytes());
}

#[inline]
pub fn write_u64_le(buf: &mut [u8], ofs: usize, val: u64) {
    buf[ofs..ofs + 8].copy_from_slice(&val.to_le_bytes());
}

