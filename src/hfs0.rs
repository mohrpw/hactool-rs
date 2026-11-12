#![allow(dead_code)]

//! HFS0 (Hashed FS) parsing, printing, and extraction matching `hfs0.c` and `hfs0.h`.

use crate::settings::HactoolCtx;
use crate::types::{
    read_u32_le, read_u64_le, FileType, Filepath, SharedFile, Validity, ACTION_EXTRACT,
    ACTION_INFO, ACTION_VERIFY, MAX_PATH,
};
use crate::utils::{
    check_memory_hash_table_with_suffix, memdump_stdout, os_makedir, print_magic,
    save_file_section, BufferedLineWriter,
};
use rayon::prelude::*;
use std::process;

pub const MAGIC_HFS0: u32 = 0x30534648;

#[derive(Clone, Debug)]
pub struct Hfs0FileEntry {
    pub offset: u64,
    pub size: u64,
    pub string_table_offset: u32,
    pub hashed_size: u32,
    pub reserved: u64,
    pub hash: [u8; 0x20],
}

pub struct Hfs0Ctx {
    pub file: Option<SharedFile>,
    pub offset: u64,
    pub size: u64,
    pub header_bytes: Vec<u8>,
    pub name: Option<String>,
    pub hash_suffix: Option<[u8; 1]>,
}

impl Default for Hfs0Ctx {
    fn default() -> Self {
        Self {
            file: None,
            offset: 0,
            size: 0,
            header_bytes: Vec::new(),
            name: None,
            hash_suffix: None,
        }
    }
}

impl Hfs0Ctx {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn magic(&self) -> u32 {
        read_u32_le(&self.header_bytes, 0)
    }

    pub fn num_files(&self) -> u32 {
        read_u32_le(&self.header_bytes, 4)
    }

    pub fn string_table_size(&self) -> u32 {
        read_u32_le(&self.header_bytes, 8)
    }

    pub fn header_size(&self) -> u64 {
        0x10 + (self.num_files() as u64) * 0x40 + (self.string_table_size() as u64)
    }

    pub fn get_file_entry(&self, i: u32) -> Option<Hfs0FileEntry> {
        if i >= self.num_files() {
            return None;
        }
        let base = 0x10 + (i as usize) * 0x40;
        if base + 0x40 > self.header_bytes.len() {
            return None;
        }
        let mut hash = [0u8; 0x20];
        hash.copy_from_slice(&self.header_bytes[base + 0x20..base + 0x40]);
        Some(Hfs0FileEntry {
            offset: read_u64_le(&self.header_bytes, base),
            size: read_u64_le(&self.header_bytes, base + 8),
            string_table_offset: read_u32_le(&self.header_bytes, base + 16),
            hashed_size: read_u32_le(&self.header_bytes, base + 20),
            reserved: read_u64_le(&self.header_bytes, base + 24),
            hash,
        })
    }

    pub fn get_file_name(&self, i: u32) -> String {
        let entry = match self.get_file_entry(i) {
            Some(e) => e,
            None => return String::new(),
        };
        let str_table_start = 0x10 + (self.num_files() as usize) * 0x40;
        let name_start = str_table_start + (entry.string_table_offset as usize);
        if name_start >= self.header_bytes.len() {
            return String::new();
        }
        let slice = &self.header_bytes[name_start..];
        let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[..nul_pos]).into_owned()
    }
}

pub fn hfs0_process(ctx: &mut Hfs0Ctx, tool_ctx: &mut HactoolCtx) {
    let file = match ctx.file.as_ref() {
        Some(f) => f.clone(),
        None => return,
    };

    let mut raw_header = [0u8; 0x10];
    if file.read_exact_at(ctx.offset, &mut raw_header).is_err() {
        eprintln!("Failed to read HFS0 header!");
        process::exit(1);
    }

    let magic = read_u32_le(&raw_header, 0);
    if magic != MAGIC_HFS0 {
        memdump_stdout("Sanity: ", &raw_header);
        println!("Error: HFS0 is corrupt!");
        process::exit(1);
    }

    let num_files = read_u32_le(&raw_header, 4) as usize;
    let string_table_size = read_u32_le(&raw_header, 8) as usize;
    let header_size = 0x10 + num_files * 0x40 + string_table_size;

    ctx.header_bytes = vec![0u8; header_size];
    if file
        .read_exact_at(ctx.offset, &mut ctx.header_bytes)
        .is_err()
    {
        eprintln!("Failed to read HFS0 header!");
        process::exit(1);
    }

    let mut cur_ofs = 0u64;
    for i in 0..(num_files as u32) {
        let cur_file = ctx.get_file_entry(i).unwrap();
        if cur_file.offset < cur_ofs {
            println!("Error: HFS0 is corrupt!");
            process::exit(1);
        }
        cur_ofs += cur_file.size;
    }

    if (tool_ctx.action & ACTION_INFO) != 0 {
        hfs0_print(ctx, tool_ctx);
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        hfs0_save(ctx, tool_ctx);
    }
}

pub struct Hfs0ExtractJob<'a> {
    pub file: Option<&'a SharedFile>,
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub filepath: Filepath,
}

pub fn hfs0_save_file(ctx: &Hfs0Ctx, i: u32, dirpath: &Filepath) {
    if i >= ctx.num_files() {
        eprintln!("Could not save file {}!", i as i32);
        process::exit(1);
    }
    let cur_file = ctx.get_file_entry(i).unwrap();
    let name = ctx.get_file_name(i);

    if name.len() >= MAX_PATH - dirpath.char_path.len() - 1 {
        eprintln!("Filename too long in HFS0!");
        process::exit(1);
    }

    let mut filepath = dirpath.clone();
    filepath.append(&name);

    println!("Saving {} to {}...", name, filepath.char_path);
    let ofs = ctx.header_size() + cur_file.offset;
    if let Some(ref f) = ctx.file {
        save_file_section(f, ctx.offset + ofs, cur_file.size, &filepath);
    }
}

pub fn hfs0_collect_jobs<'a>(
    ctx: &'a Hfs0Ctx,
    dirpath: &Filepath,
    jobs: &mut Vec<Hfs0ExtractJob<'a>>,
) {
    let num_files = ctx.num_files();
    let hdr_sz = ctx.header_size();
    jobs.reserve(num_files as usize);
    for i in 0..num_files {
        let cur_file = match ctx.get_file_entry(i) {
            Some(e) => e,
            None => {
                eprintln!("Could not save file {}!", i as i32);
                process::exit(1);
            }
        };
        let name = ctx.get_file_name(i);
        if name.len() >= MAX_PATH - dirpath.char_path.len() - 1 {
            eprintln!("Filename too long in HFS0!");
            process::exit(1);
        }
        let mut filepath = dirpath.clone();
        filepath.append(&name);
        let ofs = ctx.offset + hdr_sz + cur_file.offset;
        jobs.push(Hfs0ExtractJob {
            file: ctx.file.as_ref(),
            name,
            offset: ofs,
            size: cur_file.size,
            filepath,
        });
    }
}

pub fn hfs0_execute_jobs(mut jobs: Vec<Hfs0ExtractJob<'_>>, quiet: bool) {
    jobs.sort_unstable_by_key(|b| std::cmp::Reverse(b.size));
    let writer = BufferedLineWriter::new(quiet);
    jobs.par_iter().for_each(|job| {
        if let Some(f) = job.file {
            save_file_section(f, job.offset, job.size, &job.filepath);
        }
        writer.log_saving_to(&job.name, &job.filepath.char_path);
    });
    drop(writer);
}

pub fn hfs0_save(ctx: &Hfs0Ctx, tool_ctx: &HactoolCtx) {
    let mut dirpath: Option<&Filepath> = None;
    if tool_ctx.file_type == FileType::Hfs0 && tool_ctx.settings.out_dir_path.enabled {
        dirpath = Some(&tool_ctx.settings.out_dir_path.path);
    }
    if dirpath.is_none() || dirpath.unwrap().valid != Validity::Valid {
        dirpath = Some(&tool_ctx.settings.hfs0_dir_path);
    }
    if let Some(dp) = dirpath {
        if dp.valid == Validity::Valid {
            os_makedir(&dp.char_path);
            let mut jobs = Vec::new();
            hfs0_collect_jobs(ctx, dp, &mut jobs);
            hfs0_execute_jobs(jobs, tool_ctx.settings.quiet);
        }
    }
}

pub fn hfs0_print(ctx: &Hfs0Ctx, tool_ctx: &HactoolCtx) {
    println!("\nHFS0:");
    print_magic("Magic:                              ", ctx.magic());
    println!(
        "Number of files:                    {}",
        ctx.num_files() as i32
    );
    if ctx.num_files() > 0 {
        print!("Files:");
        let prefix_name = ctx.name.as_deref().unwrap_or("hfs0");
        for i in 0..ctx.num_files() {
            let cur_file = ctx.get_file_entry(i).unwrap();
            let file_name = ctx.get_file_name(i);
            let pad = if i == 0 {
                "                              "
            } else {
                "                                    "
            };
            if (tool_ctx.action & ACTION_VERIFY) != 0 {
                let hash_validity = if let Some(ref f) = ctx.file {
                    check_memory_hash_table_with_suffix(
                        f,
                        &cur_file.hash,
                        ctx.offset + ctx.header_size() + cur_file.offset,
                        cur_file.hashed_size as u64,
                        cur_file.hashed_size as u64,
                        ctx.hash_suffix.as_ref().map(|s| &s[..]),
                        false,
                    )
                } else {
                    Validity::Invalid
                };
                println!(
                    "{}{}:/{:<48} {:012x}-{:012x} ({})",
                    pad,
                    prefix_name,
                    file_name,
                    cur_file.offset,
                    cur_file.offset + cur_file.size,
                    hash_validity.as_str()
                );
            } else {
                println!(
                    "{}{}:/{:<48} {:012x}-{:012x}",
                    pad,
                    prefix_name,
                    file_name,
                    cur_file.offset,
                    cur_file.offset + cur_file.size
                );
            }
        }
    }
}
