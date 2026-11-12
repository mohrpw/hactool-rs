#![allow(dead_code)]

//! PFS0 (Partition FS) parsing, printing, and extraction matching `pfs0.c` and `pfs0.h`.

use crate::npdm::{npdm_process, MAGIC_META};
use crate::settings::HactoolCtx;
use crate::types::{
    read_u32_le, read_u64_le, FileType, Filepath, SharedFile, Validity, ACTION_EXTRACT,
    ACTION_INFO, MAX_PATH,
};
use crate::utils::{os_makedir, print_magic, save_file_section, BufferedLineWriter};
use rayon::prelude::*;
use std::process;

pub const MAGIC_PFS0: u32 = 0x30534650;

#[derive(Clone, Debug, Default)]
pub struct Pfs0Superblock {
    pub master_hash: [u8; 0x20],
    pub block_size: u32,
    pub always_2: u32,
    pub hash_table_offset: u64,
    pub hash_table_size: u64,
    pub pfs0_offset: u64,
    pub pfs0_size: u64,
}

impl Pfs0Superblock {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut master_hash = [0u8; 0x20];
        master_hash.copy_from_slice(&bytes[0..0x20]);
        Self {
            master_hash,
            block_size: read_u32_le(bytes, 0x20),
            always_2: read_u32_le(bytes, 0x24),
            hash_table_offset: read_u64_le(bytes, 0x28),
            hash_table_size: read_u64_le(bytes, 0x30),
            pfs0_offset: read_u64_le(bytes, 0x38),
            pfs0_size: read_u64_le(bytes, 0x40),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Pfs0FileEntry {
    pub offset: u64,
    pub size: u64,
    pub string_table_offset: u32,
    pub reserved: u32,
}

pub struct Pfs0Ctx {
    pub superblock: Option<Pfs0Superblock>,
    pub file: Option<SharedFile>,
    pub superblock_hash_validity: Validity,
    pub hash_table_validity: Validity,
    pub is_exefs: bool,
    pub npdm: Option<Vec<u8>>,
    pub header_bytes: Vec<u8>,
}

impl Default for Pfs0Ctx {
    fn default() -> Self {
        Self {
            superblock: None,
            file: None,
            superblock_hash_validity: Validity::Unchecked,
            hash_table_validity: Validity::Unchecked,
            is_exefs: false,
            npdm: None,
            header_bytes: Vec::new(),
        }
    }
}

impl Pfs0Ctx {
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
        0x10 + (self.num_files() as u64) * 0x18 + (self.string_table_size() as u64)
    }

    pub fn get_file_entry(&self, i: u32) -> Option<Pfs0FileEntry> {
        if i >= self.num_files() {
            return None;
        }
        let base = 0x10 + (i as usize) * 0x18;
        if base + 0x18 > self.header_bytes.len() {
            return None;
        }
        Some(Pfs0FileEntry {
            offset: read_u64_le(&self.header_bytes, base),
            size: read_u64_le(&self.header_bytes, base + 8),
            string_table_offset: read_u32_le(&self.header_bytes, base + 16),
            reserved: read_u32_le(&self.header_bytes, base + 20),
        })
    }

    pub fn get_file_name(&self, i: u32) -> String {
        let entry = match self.get_file_entry(i) {
            Some(e) => e,
            None => return String::new(),
        };
        let str_table_start = 0x10 + (self.num_files() as usize) * 0x18;
        let name_start = str_table_start + (entry.string_table_offset as usize);
        if name_start >= self.header_bytes.len() {
            return String::new();
        }
        let slice = &self.header_bytes[name_start..];
        let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[..nul_pos]).into_owned()
    }
}

pub fn pfs0_process(ctx: &mut Pfs0Ctx, tool_ctx: &mut HactoolCtx) {
    let file = match ctx.file.as_ref() {
        Some(f) => f.clone(),
        None => return,
    };

    let mut raw_header = [0u8; 0x10];
    if file.read_exact_at(0, &mut raw_header).is_err() {
        eprintln!("Failed to read PFS0 header!");
        process::exit(1);
    }

    let magic = read_u32_le(&raw_header, 0);
    if magic != MAGIC_PFS0 {
        println!("Error: PFS0 is corrupt!");
        process::exit(1);
    }

    let num_files = read_u32_le(&raw_header, 4) as usize;
    let string_table_size = read_u32_le(&raw_header, 8) as usize;
    let header_size = 0x10 + num_files * 0x18 + string_table_size;

    ctx.header_bytes = vec![0u8; header_size];
    if file.read_exact_at(0, &mut ctx.header_bytes).is_err() {
        eprintln!("Failed to read PFS0 header!");
        process::exit(1);
    }

    for i in 0..(num_files as u32) {
        if ctx.get_file_name(i) == "main.npdm" {
            if let Some(cur_file) = ctx.get_file_entry(i) {
                let mut npdm_buf = vec![0u8; cur_file.size as usize];
                let ofs = ctx.header_size() + cur_file.offset;
                if file.read_exact_at(ofs, &mut npdm_buf).is_err() {
                    eprintln!("Failed to read NPDM!");
                    process::exit(1);
                }
                if npdm_buf.len() >= 4 && read_u32_le(&npdm_buf, 0) == MAGIC_META {
                    ctx.is_exefs = true;
                }
                ctx.npdm = Some(npdm_buf);
            }
        }
    }

    if (tool_ctx.action & ACTION_INFO) != 0 {
        pfs0_print(ctx, tool_ctx);
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        pfs0_save(ctx, tool_ctx);
    }
}

pub fn pfs0_save(ctx: &Pfs0Ctx, tool_ctx: &HactoolCtx) {
    let mut dirpath: Option<&Filepath> = None;
    if ctx.is_exefs && tool_ctx.settings.exefs_dir_path.enabled {
        dirpath = Some(&tool_ctx.settings.exefs_dir_path.path);
    }
    if (dirpath.is_none() || dirpath.unwrap().valid != Validity::Valid)
        && (tool_ctx.file_type == FileType::Pfs0 && tool_ctx.settings.out_dir_path.enabled)
    {
        dirpath = Some(&tool_ctx.settings.out_dir_path.path);
    }
    if dirpath.is_none() || dirpath.unwrap().valid != Validity::Valid {
        dirpath = Some(&tool_ctx.settings.pfs0_dir_path);
    }
    if let Some(dp) = dirpath {
        if dp.valid == Validity::Valid {
            os_makedir(&dp.char_path);
            let num_files = ctx.num_files();
            let hdr_sz = ctx.header_size();
            let mut jobs = Vec::with_capacity(num_files as usize);
            for i in 0..num_files {
                let cur_file = match ctx.get_file_entry(i) {
                    Some(e) => e,
                    None => {
                        eprintln!("Could not save file {}!", i as i32);
                        process::exit(1);
                    }
                };
                let name = ctx.get_file_name(i);
                if name.len() >= MAX_PATH - dp.char_path.len() - 1 {
                    eprintln!("Filename too long in PFS0!");
                    process::exit(1);
                }
                let mut filepath = dp.clone();
                filepath.append(&name);
                let ofs = hdr_sz + cur_file.offset;
                jobs.push((name, ofs, cur_file.size, filepath));
            }
            jobs.sort_unstable_by_key(|b| std::cmp::Reverse(b.2));
            let writer = BufferedLineWriter::new(tool_ctx.settings.quiet);
            jobs.par_iter().for_each(|(name, ofs, size, filepath)| {
                if let Some(ref f) = ctx.file {
                    save_file_section(f, *ofs, *size, filepath);
                }
                writer.log_saving_to(name, &filepath.char_path);
            });
            drop(writer);
        }
    }
}

pub fn pfs0_print(ctx: &Pfs0Ctx, tool_ctx: &mut HactoolCtx) {
    println!("\n{}:", if ctx.is_exefs { "ExeFS" } else { "PFS0" });
    print_magic("Magic:                              ", ctx.magic());
    if ctx.is_exefs {
        if let Some(ref npdm) = ctx.npdm {
            let aci0_ofs = read_u32_le(npdm, 0x70) as usize;
            let title_id = read_u64_le(&npdm[aci0_ofs..], 0x10);
            println!("Title ID:                           {:016x}", title_id);
        }
    }
    println!(
        "Number of files:                    {}",
        ctx.num_files() as i32
    );
    if ctx.num_files() > 0 && ctx.num_files() < 15 {
        print!("Files:");
        for i in 0..ctx.num_files() {
            let cur_file = ctx.get_file_entry(i).unwrap();
            let name = ctx.get_file_name(i);
            let pad = if i == 0 {
                "                              "
            } else {
                "                                    "
            };
            println!(
                "{}pfs0:/{:<32} {:012x}-{:012x}",
                pad,
                name,
                cur_file.offset,
                cur_file.offset + cur_file.size
            );
        }
    }
    if ctx.is_exefs {
        if let Some(ref npdm) = ctx.npdm {
            npdm_process(npdm, tool_ctx);
        }
    }
}

