#![allow(dead_code)]

//! RomFS and IVFC parsing, directory traversal, and extraction matching `romfs.c` and `ivfc.h`.

use crate::settings::HactoolCtx;
use crate::types::{
    read_u32_le, read_u64_le, FileType, Filepath, SharedFile, Validity, ACTION_EXTRACT,
    ACTION_LISTROMFS,
};
use crate::utils::{os_makedir, save_file_section, BufferedLineWriter};
use rayon::prelude::*;
use std::process;

pub const IVFC_HEADER_SIZE: usize = 0xE0;
pub const IVFC_MAX_LEVEL: usize = 6;
pub const IVFC_MAX_BUFFERSIZE: usize = 0x4000;
pub const MAGIC_IVFC: u32 = 0x43465649;
pub const ROMFS_HEADER_SIZE: u64 = 0x00000050;
pub const ROMFS_ENTRY_EMPTY: u32 = 0xFFFFFFFF;

#[derive(Clone, Copy, Debug, Default)]
pub struct IvfcLevelHdr {
    pub logical_offset: u64,
    pub hash_data_size: u64,
    pub block_size: u32,
    pub reserved: u32,
}

impl IvfcLevelHdr {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            logical_offset: read_u64_le(bytes, 0),
            hash_data_size: read_u64_le(bytes, 8),
            block_size: read_u32_le(bytes, 16),
            reserved: read_u32_le(bytes, 20),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IvfcLevelCtx {
    pub data_offset: u64,
    pub data_size: u64,
    pub hash_offset: u64,
    pub hash_block_size: u32,
    pub hash_validity: Validity,
}

#[derive(Clone, Debug, Default)]
pub struct IvfcHdr {
    pub magic: u32,
    pub id: u32,
    pub master_hash_size: u32,
    pub num_levels: u32,
    pub level_headers: [IvfcLevelHdr; IVFC_MAX_LEVEL],
    pub _0xa0: [u8; 0x20],
    pub master_hash: [u8; 0x20],
}

impl IvfcHdr {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut level_headers = [IvfcLevelHdr::default(); IVFC_MAX_LEVEL];
        for i in 0..IVFC_MAX_LEVEL {
            level_headers[i] = IvfcLevelHdr::from_bytes(&bytes[0x10 + i * 0x18..0x10 + (i + 1) * 0x18]);
        }
        let mut _0xa0 = [0u8; 0x20];
        _0xa0.copy_from_slice(&bytes[0xA0..0xC0]);
        let mut master_hash = [0u8; 0x20];
        master_hash.copy_from_slice(&bytes[0xC0..0xE0]);
        Self {
            magic: read_u32_le(bytes, 0),
            id: read_u32_le(bytes, 4),
            master_hash_size: read_u32_le(bytes, 8),
            num_levels: read_u32_le(bytes, 12),
            level_headers,
            _0xa0,
            master_hash,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RomfsSuperblock {
    pub ivfc_header: IvfcHdr,
}

impl RomfsSuperblock {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            ivfc_header: IvfcHdr::from_bytes(bytes),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RomfsHdr {
    pub header_size: u64,
    pub dir_hash_table_offset: u64,
    pub dir_hash_table_size: u64,
    pub dir_meta_table_offset: u64,
    pub dir_meta_table_size: u64,
    pub file_hash_table_offset: u64,
    pub file_hash_table_size: u64,
    pub file_meta_table_offset: u64,
    pub file_meta_table_size: u64,
    pub data_offset: u64,
}

impl RomfsHdr {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            header_size: read_u64_le(bytes, 0x00),
            dir_hash_table_offset: read_u64_le(bytes, 0x08),
            dir_hash_table_size: read_u64_le(bytes, 0x10),
            dir_meta_table_offset: read_u64_le(bytes, 0x18),
            dir_meta_table_size: read_u64_le(bytes, 0x20),
            file_hash_table_offset: read_u64_le(bytes, 0x28),
            file_hash_table_size: read_u64_le(bytes, 0x30),
            file_meta_table_offset: read_u64_le(bytes, 0x38),
            file_meta_table_size: read_u64_le(bytes, 0x40),
            data_offset: read_u64_le(bytes, 0x48),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RomfsDirEntry {
    pub parent: u32,
    pub sibling: u32,
    pub child: u32,
    pub file: u32,
    pub hash: u32,
    pub name_size: u32,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct RomfsFileEntry {
    pub parent: u32,
    pub sibling: u32,
    pub offset: u64,
    pub size: u64,
    pub hash: u32,
    pub name_size: u32,
    pub name: String,
}

pub fn parse_direntry(directories: &[u8], offset: u32) -> RomfsDirEntry {
    let ofs = offset as usize;
    let parent = read_u32_le(directories, ofs);
    let sibling = read_u32_le(directories, ofs + 4);
    let child = read_u32_le(directories, ofs + 8);
    let file = read_u32_le(directories, ofs + 12);
    let hash = read_u32_le(directories, ofs + 16);
    let name_size = read_u32_le(directories, ofs + 20);
    let name_bytes = &directories[ofs + 24..(ofs + 24 + (name_size as usize)).min(directories.len())];
    let nul_pos = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
    let name = String::from_utf8_lossy(&name_bytes[..nul_pos]).into_owned();
    RomfsDirEntry {
        parent,
        sibling,
        child,
        file,
        hash,
        name_size,
        name,
    }
}

pub fn parse_fentry(files: &[u8], offset: u32) -> RomfsFileEntry {
    let ofs = offset as usize;
    let parent = read_u32_le(files, ofs);
    let sibling = read_u32_le(files, ofs + 4);
    let file_offset = read_u64_le(files, ofs + 8);
    let size = read_u64_le(files, ofs + 16);
    let hash = read_u32_le(files, ofs + 24);
    let name_size = read_u32_le(files, ofs + 28);
    let name_bytes = &files[ofs + 32..(ofs + 32 + (name_size as usize)).min(files.len())];
    let nul_pos = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
    let name = String::from_utf8_lossy(&name_bytes[..nul_pos]).into_owned();
    RomfsFileEntry {
        parent,
        sibling,
        offset: file_offset,
        size,
        hash,
        name_size,
        name,
    }
}

pub struct RomfsCtx {
    pub superblock: Option<RomfsSuperblock>,
    pub file: Option<SharedFile>,
    pub superblock_hash_validity: Validity,
    pub ivfc_levels: [IvfcLevelCtx; IVFC_MAX_LEVEL],
    pub romfs_offset: u64,
    pub header: RomfsHdr,
    pub directories: Vec<u8>,
    pub files: Vec<u8>,
}

impl Default for RomfsCtx {
    fn default() -> Self {
        Self {
            superblock: None,
            file: None,
            superblock_hash_validity: Validity::Unchecked,
            ivfc_levels: [IvfcLevelCtx::default(); IVFC_MAX_LEVEL],
            romfs_offset: 0,
            header: RomfsHdr::default(),
            directories: Vec::new(),
            files: Vec::new(),
        }
    }
}

struct RomfsExtractJob {
    offset: u64,
    size: u64,
    filepath: Filepath,
}

fn romfs_list_dir(ctx: &RomfsCtx, mut dir_offset: u32, parent_path: &Filepath) {
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
            romfs_list_dir(ctx, entry.child, &cur_path);
        }
        dir_offset = entry.sibling;
    }
}

fn romfs_collect_dir(
    ctx: &RomfsCtx,
    mut dir_offset: u32,
    parent_path: &Filepath,
    dirs: &mut Vec<String>,
    jobs: &mut Vec<RomfsExtractJob>,
) {
    let base_data_ofs = ctx.romfs_offset + ctx.header.data_offset;
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
            jobs.push(RomfsExtractJob {
                offset: base_data_ofs + fentry.offset,
                size: fentry.size,
                filepath: fpath,
            });
            file_offset = fentry.sibling;
        }

        if entry.child != ROMFS_ENTRY_EMPTY {
            romfs_collect_dir(ctx, entry.child, &cur_path, dirs, jobs);
        }
        dir_offset = entry.sibling;
    }
}

fn romfs_execute_extract(
    ctx: &RomfsCtx,
    dirs: Vec<String>,
    mut jobs: Vec<RomfsExtractJob>,
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

pub fn romfs_visit_dir(
    ctx: &RomfsCtx,
    dir_offset: u32,
    parent_path: &Filepath,
    tool_ctx: &HactoolCtx,
) {
    if (tool_ctx.action & ACTION_LISTROMFS) != 0 {
        romfs_list_dir(ctx, dir_offset, parent_path);
    } else {
        let mut dirs = Vec::new();
        let mut jobs = Vec::new();
        romfs_collect_dir(ctx, dir_offset, parent_path, &mut dirs, &mut jobs);
        romfs_execute_extract(ctx, dirs, jobs, tool_ctx);
    }
}

pub fn romfs_process(ctx: &mut RomfsCtx, tool_ctx: &mut HactoolCtx) {
    let file = match ctx.file.as_ref() {
        Some(f) => f.clone(),
        None => return,
    };

    ctx.romfs_offset = 0;
    let mut hdr_bytes = [0u8; 0x50];
    if file.read_exact_at(ctx.romfs_offset, &mut hdr_bytes).is_err() {
        eprintln!("Failed to read RomFS header!");
        return;
    }
    ctx.header = RomfsHdr::from_bytes(&hdr_bytes);

    if (tool_ctx.action & (ACTION_EXTRACT | ACTION_LISTROMFS)) != 0
        && ctx.header.header_size == ROMFS_HEADER_SIZE
    {
        ctx.directories = vec![0u8; ctx.header.dir_meta_table_size as usize];
        if file
            .read_exact_at(
                ctx.romfs_offset + ctx.header.dir_meta_table_offset,
                &mut ctx.directories,
            )
            .is_err()
        {
            eprintln!("Failed to read RomFS directory cache!");
            process::exit(1);
        }

        ctx.files = vec![0u8; ctx.header.file_meta_table_size as usize];
        if file
            .read_exact_at(
                ctx.romfs_offset + ctx.header.file_meta_table_offset,
                &mut ctx.files,
            )
            .is_err()
        {
            eprintln!("Failed to read RomFS file cache!");
            process::exit(1);
        }
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        romfs_save(ctx, tool_ctx);
    }
}

pub fn romfs_save(ctx: &RomfsCtx, tool_ctx: &HactoolCtx) {
    if (tool_ctx.action & ACTION_LISTROMFS) != 0 {
        let mut fakepath = Filepath::new();
        fakepath.set("");
        println!("Visiting romfs");
        romfs_visit_dir(ctx, 0, &fakepath, tool_ctx);
    } else {
        let mut dirpath: Option<&Filepath> = None;
        if tool_ctx.settings.romfs_dir_path.enabled {
            dirpath = Some(&tool_ctx.settings.romfs_dir_path.path);
        }
        if (dirpath.is_none() || dirpath.unwrap().valid != Validity::Valid)
            && (tool_ctx.file_type == FileType::Romfs && tool_ctx.settings.out_dir_path.enabled)
        {
            dirpath = Some(&tool_ctx.settings.out_dir_path.path);
        }
        if let Some(dp) = dirpath {
            if dp.valid == Validity::Valid {
                os_makedir(&dp.char_path);
                romfs_visit_dir(ctx, 0, dp, tool_ctx);
            }
        }
    }
}

