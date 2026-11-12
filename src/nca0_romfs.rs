#![allow(dead_code)]

//! NCA0 RomFS parsing and extraction matching `nca0_romfs.c` and `nca0_romfs.h`.

use crate::romfs::{parse_direntry, parse_fentry, ROMFS_ENTRY_EMPTY};
use crate::settings::HactoolCtx;
use crate::types::{
    read_u32_le, read_u64_le, FileType, Filepath, SharedFile, Validity, ACTION_EXTRACT,
    ACTION_LISTROMFS,
};
use crate::utils::{os_makedir, save_file_section, BufferedLineWriter};
use rayon::prelude::*;
use std::process;

pub const NCA0_ROMFS_HEADER_SIZE: u32 = 0x00000028;

#[derive(Clone, Copy, Debug, Default)]
pub struct Nca0RomfsHdr {
    pub header_size: u32,
    pub dir_hash_table_offset: u32,
    pub dir_hash_table_size: u32,
    pub dir_meta_table_offset: u32,
    pub dir_meta_table_size: u32,
    pub file_hash_table_offset: u32,
    pub file_hash_table_size: u32,
    pub file_meta_table_offset: u32,
    pub file_meta_table_size: u32,
    pub data_offset: u32,
}

impl Nca0RomfsHdr {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            header_size: read_u32_le(bytes, 0x00),
            dir_hash_table_offset: read_u32_le(bytes, 0x04),
            dir_hash_table_size: read_u32_le(bytes, 0x08),
            dir_meta_table_offset: read_u32_le(bytes, 0x0C),
            dir_meta_table_size: read_u32_le(bytes, 0x10),
            file_hash_table_offset: read_u32_le(bytes, 0x14),
            file_hash_table_size: read_u32_le(bytes, 0x18),
            file_meta_table_offset: read_u32_le(bytes, 0x1C),
            file_meta_table_size: read_u32_le(bytes, 0x20),
            data_offset: read_u32_le(bytes, 0x24),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Nca0RomfsSuperblock {
    pub master_hash: [u8; 0x20],
    pub block_size: u32,
    pub always_2: u32,
    pub hash_table_offset: u64,
    pub hash_table_size: u64,
    pub romfs_offset: u64,
    pub romfs_size: u64,
}

impl Nca0RomfsSuperblock {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut master_hash = [0u8; 0x20];
        master_hash.copy_from_slice(&bytes[0..0x20]);
        Self {
            master_hash,
            block_size: read_u32_le(bytes, 0x20),
            always_2: read_u32_le(bytes, 0x24),
            hash_table_offset: read_u64_le(bytes, 0x28),
            hash_table_size: read_u64_le(bytes, 0x30),
            romfs_offset: read_u64_le(bytes, 0x38),
            romfs_size: read_u64_le(bytes, 0x40),
        }
    }
}

pub struct Nca0RomfsCtx {
    pub superblock: Option<Nca0RomfsSuperblock>,
    pub file: Option<SharedFile>,
    pub superblock_hash_validity: Validity,
    pub hash_table_validity: Validity,
    pub romfs_offset: u64,
    pub header: Nca0RomfsHdr,
    pub directories: Vec<u8>,
    pub files: Vec<u8>,
}

impl Default for Nca0RomfsCtx {
    fn default() -> Self {
        Self {
            superblock: None,
            file: None,
            superblock_hash_validity: Validity::Unchecked,
            hash_table_validity: Validity::Unchecked,
            romfs_offset: 0,
            header: Nca0RomfsHdr::default(),
            directories: Vec::new(),
            files: Vec::new(),
        }
    }
}

struct Nca0RomfsExtractJob {
    offset: u64,
    size: u64,
    filepath: Filepath,
}

fn nca0_romfs_list_dir(ctx: &Nca0RomfsCtx, mut dir_offset: u32, parent_path: &Filepath) {
    while dir_offset != ROMFS_ENTRY_EMPTY {
        let entry = parse_direntry(&ctx.directories, dir_offset);
        let mut cur_path = parent_path.clone();
        if entry.name_size > 0 {
            cur_path.append_n(entry.name_size as usize, &entry.name);
        }

        let mut file_offset = entry.file;
        while file_offset != ROMFS_ENTRY_EMPTY {
            let fentry = parse_fentry(&ctx.files, file_offset);
            let mut fpath = cur_path.clone();
            if fentry.name_size > 0 {
                fpath.append_n(fentry.name_size as usize, &fentry.name);
            }
            println!("rom:{}", fpath.char_path);
            file_offset = fentry.sibling;
        }

        if entry.child != ROMFS_ENTRY_EMPTY {
            nca0_romfs_list_dir(ctx, entry.child, &cur_path);
        }
        dir_offset = entry.sibling;
    }
}

fn nca0_romfs_collect_dir(
    ctx: &Nca0RomfsCtx,
    mut dir_offset: u32,
    parent_path: &Filepath,
    dirs: &mut Vec<String>,
    jobs: &mut Vec<Nca0RomfsExtractJob>,
) {
    let base_data_ofs = ctx.romfs_offset + (ctx.header.data_offset as u64);
    while dir_offset != ROMFS_ENTRY_EMPTY {
        let entry = parse_direntry(&ctx.directories, dir_offset);
        let mut cur_path = parent_path.clone();
        if entry.name_size > 0 {
            cur_path.append_n(entry.name_size as usize, &entry.name);
        }

        dirs.push(cur_path.char_path.clone());

        let mut file_offset = entry.file;
        while file_offset != ROMFS_ENTRY_EMPTY {
            let fentry = parse_fentry(&ctx.files, file_offset);
            let mut fpath = cur_path.clone();
            if fentry.name_size > 0 {
                fpath.append_n(fentry.name_size as usize, &fentry.name);
            }
            jobs.push(Nca0RomfsExtractJob {
                offset: base_data_ofs + fentry.offset,
                size: fentry.size,
                filepath: fpath,
            });
            file_offset = fentry.sibling;
        }

        if entry.child != ROMFS_ENTRY_EMPTY {
            nca0_romfs_collect_dir(ctx, entry.child, &cur_path, dirs, jobs);
        }
        dir_offset = entry.sibling;
    }
}

fn nca0_romfs_execute_extract(
    ctx: &Nca0RomfsCtx,
    dirs: Vec<String>,
    mut jobs: Vec<Nca0RomfsExtractJob>,
    tool_ctx: &HactoolCtx,
) {
    for dir in &dirs {
        os_makedir(dir);
    }

    jobs.sort_unstable_by_key(|b| std::cmp::Reverse(b.size));
    let writer = BufferedLineWriter::new(tool_ctx.settings.quiet);
    jobs.par_iter().for_each(|job| {
        if let Some(ref f) = ctx.file {
            save_file_section(f, job.offset, job.size, &job.filepath);
        }
        writer.log_saving(&job.filepath.char_path);
    });
    drop(writer);
}

pub fn nca0_romfs_visit_dir(
    ctx: &Nca0RomfsCtx,
    dir_offset: u32,
    parent_path: &Filepath,
    tool_ctx: &HactoolCtx,
) {
    if (tool_ctx.action & ACTION_LISTROMFS) != 0 {
        nca0_romfs_list_dir(ctx, dir_offset, parent_path);
    } else {
        let mut dirs = Vec::new();
        let mut jobs = Vec::new();
        nca0_romfs_collect_dir(ctx, dir_offset, parent_path, &mut dirs, &mut jobs);
        nca0_romfs_execute_extract(ctx, dirs, jobs, tool_ctx);
    }
}

pub fn nca0_romfs_process(ctx: &mut Nca0RomfsCtx, tool_ctx: &mut HactoolCtx) {
    let file = match ctx.file.as_ref() {
        Some(f) => f.clone(),
        None => return,
    };

    ctx.romfs_offset = 0;
    let mut hdr_bytes = [0u8; 0x28];
    if file.read_exact_at(ctx.romfs_offset, &mut hdr_bytes).is_err() {
        eprintln!("Failed to read NCA0 RomFS header!");
        return;
    }
    ctx.header = Nca0RomfsHdr::from_bytes(&hdr_bytes);

    if (tool_ctx.action & (ACTION_EXTRACT | ACTION_LISTROMFS)) != 0
        && ctx.header.header_size == NCA0_ROMFS_HEADER_SIZE
    {
        ctx.directories = vec![0u8; ctx.header.dir_meta_table_size as usize];
        if file
            .read_exact_at(
                ctx.romfs_offset + (ctx.header.dir_meta_table_offset as u64),
                &mut ctx.directories,
            )
            .is_err()
        {
            eprintln!("Failed to read NCA0 RomFS directory cache!");
            process::exit(1);
        }

        ctx.files = vec![0u8; ctx.header.file_meta_table_size as usize];
        if file
            .read_exact_at(
                ctx.romfs_offset + (ctx.header.file_meta_table_offset as u64),
                &mut ctx.files,
            )
            .is_err()
        {
            eprintln!("Failed to read NCA0 RomFS file cache!");
            process::exit(1);
        }
    } else {
        eprintln!("NCA0 RomFS is corrupt?");
        return;
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        nca0_romfs_save(ctx, tool_ctx);
    }
}

pub fn nca0_romfs_save(ctx: &Nca0RomfsCtx, tool_ctx: &HactoolCtx) {
    if (tool_ctx.action & ACTION_LISTROMFS) != 0 {
        let mut fakepath = Filepath::new();
        fakepath.set("");
        nca0_romfs_visit_dir(ctx, 0, &fakepath, tool_ctx);
    } else {
        let mut dirpath: Option<&Filepath> = None;
        if tool_ctx.settings.romfs_dir_path.enabled {
            dirpath = Some(&tool_ctx.settings.romfs_dir_path.path);
        }
        if (dirpath.is_none() || dirpath.unwrap().valid != Validity::Valid)
            && (tool_ctx.file_type == FileType::Nca0Romfs && tool_ctx.settings.out_dir_path.enabled)
        {
            dirpath = Some(&tool_ctx.settings.out_dir_path.path);
        }
        if let Some(dp) = dirpath {
            if dp.valid == Validity::Valid {
                os_makedir(&dp.char_path);
                nca0_romfs_visit_dir(ctx, 0, dp, tool_ctx);
            }
        }
    }
}

