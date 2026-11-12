#![allow(dead_code)]

//! Nintendo Content Archive (NCA3, NCA2, NCA0, Beta NCA0) header decryption,
//! section decryption (CTR, XTS, BKTR, NCA0), multi-threaded IVFC/PFS0 verification,
//! and fast zero-overhead file extraction matching `nca.c` and `nca.h`.

use crate::aes::{AesCtx, AesMode};
use crate::bktr::{bktr_get_relocation, bktr_get_subsection, BktrHeader, MAGIC_BKTR};
use crate::extkeys::{settings_get_titlekey, settings_has_titlekey};
use crate::nca0_romfs::{Nca0RomfsCtx, Nca0RomfsHdr, Nca0RomfsSuperblock, NCA0_ROMFS_HEADER_SIZE};
use crate::npdm::{npdm_process, MAGIC_META};
use crate::pfs0::{Pfs0Ctx, Pfs0Superblock, MAGIC_PFS0};
use crate::pki::{
    pki_get_beta_nca0_exponent, pki_get_beta_nca0_label_hash, pki_get_beta_nca0_modulus,
};
use crate::romfs::{
    parse_direntry, parse_fentry, IvfcHdr, IvfcLevelCtx, RomfsCtx, RomfsHdr, RomfsSuperblock,
    IVFC_MAX_LEVEL, ROMFS_ENTRY_EMPTY, ROMFS_HEADER_SIZE,
};
use crate::rsa::{rsa2048_oaep_decrypt_verify, rsa2048_pss_verify};
use crate::settings::HactoolCtx;
use crate::sha::{par_verify_blocks, sha256_hash_buffer};
use crate::types::{
    read_u32_le, read_u64_le, BaseFileType, Filepath, SharedFile, Validity, ACTION_EXTRACT,
    ACTION_INFO, ACTION_LISTROMFS, ACTION_ONLYUPDATEDROMFS, ACTION_RAW, ACTION_VERIFY, MAX_PATH,
};
use crate::utils::{
    create_uncompressed_file, get_key_revision_summary, media_to_real, memdump_stdout, os_makedir,
    print_magic, with_worker_scratch, BufferedLineWriter, SCRATCH_BUF_SIZE,
};
use rayon::prelude::*;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::process;

pub const MAGIC_NCA3: u32 = 0x3341434E;
pub const MAGIC_NCA2: u32 = 0x3241434E;
pub const MAGIC_NCA0: u32 = 0x3041434E;

pub const NCACONTENTTYPE_PROGRAM: u32 = 0;
pub const NCACONTENTTYPE_META: u32 = 1;
pub const NCACONTENTTYPE_CONTROL: u32 = 2;
pub const NCACONTENTTYPE_MANUAL: u32 = 3;
pub const NCACONTENTTYPE_DATA: u32 = 4;
pub const NCACONTENTTYPE_PUBLICDATA: u32 = 5;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NcaSectionType {
    Pfs0,
    Romfs,
    Bktr,
    Nca0Romfs,
    Invalid,
}

impl Default for NcaSectionType {
    fn default() -> Self {
        NcaSectionType::Invalid
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NcaVersion {
    Unknown,
    Nca0Beta,
    Nca0,
    Nca2,
    Nca3,
}

impl Default for NcaVersion {
    fn default() -> Self {
        NcaVersion::Unknown
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SectionCryptType {
    None,
    Xts,
    Ctr,
    Bktr,
    Nca0,
}

impl Default for SectionCryptType {
    fn default() -> Self {
        SectionCryptType::None
    }
}

impl SectionCryptType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => SectionCryptType::None,
            2 => SectionCryptType::Xts,
            3 => SectionCryptType::Ctr,
            4 => SectionCryptType::Bktr,
            _ => SectionCryptType::None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BktrSuperblock {
    pub ivfc_header: IvfcHdr,
    pub relocation_header: BktrHeader,
    pub subsection_header: BktrHeader,
}

impl BktrSuperblock {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            ivfc_header: IvfcHdr::from_bytes(&bytes[0..0xE0]),
            relocation_header: BktrHeader::from_bytes(&bytes[0xF8..0x118]),
            subsection_header: BktrHeader::from_bytes(&bytes[0x118..0x138]),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BktrSectionCtx {
    pub superblock: BktrSuperblock,
    pub superblock_hash_validity: Validity,
    pub relocation_block: Vec<u8>,
    pub subsection_block: Vec<u8>,
    pub ivfc_levels: [IvfcLevelCtx; IVFC_MAX_LEVEL],
    pub romfs_offset: u64,
    pub header: RomfsHdr,
    pub directories: Vec<u8>,
    pub files: Vec<u8>,
    pub virtual_seek: u64,
    pub bktr_seek: u64,
    pub base_seek: u64,
}

pub struct NcaSectionCtx {
    pub is_present: bool,
    pub section_type: NcaSectionType,
    pub file: Option<SharedFile>,
    pub offset: u64,
    pub size: u64,
    pub section_num: u32,
    pub fs_header_raw: [u8; 0x200],
    pub is_decrypted: bool,
    pub sector_size: u64,
    pub sector_mask: u64,
    pub aes: Option<AesCtx>,
    pub pfs0_ctx: Pfs0Ctx,
    pub romfs_ctx: RomfsCtx,
    pub nca0_romfs_ctx: Nca0RomfsCtx,
    pub bktr_ctx: BktrSectionCtx,
    pub superblock_hash_validity: Validity,
    pub ctr: [u8; 0x10],
    pub cur_seek: u64,
    pub sector_num: usize,
    pub sector_ofs: usize,
    pub physical_reads: bool,
    pub crypt_type: SectionCryptType,
}

impl Default for NcaSectionCtx {
    fn default() -> Self {
        Self {
            is_present: false,
            section_type: NcaSectionType::Invalid,
            file: None,
            offset: 0,
            size: 0,
            section_num: 0,
            fs_header_raw: [0u8; 0x200],
            is_decrypted: false,
            sector_size: 0,
            sector_mask: 0,
            aes: None,
            pfs0_ctx: Pfs0Ctx::default(),
            romfs_ctx: RomfsCtx::default(),
            nca0_romfs_ctx: Nca0RomfsCtx::default(),
            bktr_ctx: BktrSectionCtx::default(),
            superblock_hash_validity: Validity::Unchecked,
            ctr: [0u8; 0x10],
            cur_seek: 0,
            sector_num: 0,
            sector_ofs: 0,
            physical_reads: false,
            crypt_type: SectionCryptType::None,
        }
    }
}

pub struct NcaCtx {
    pub file: Option<SharedFile>,
    pub file_size: u64,
    pub crypto_type: u8,
    pub has_rights_id: bool,
    pub is_decrypted: bool,
    pub is_cli_target: bool,
    pub format_version: NcaVersion,
    pub fixed_sig_validity: Validity,
    pub npdm_sig_validity: Validity,
    pub decrypted_keys: [[u8; 0x10]; 4],
    pub title_key: [u8; 0x10],
    pub section_contexts: [NcaSectionCtx; 4],
    pub npdm: Option<Vec<u8>>,
    pub header_bytes: [u8; 0xC00],
}

impl Default for NcaCtx {
    fn default() -> Self {
        Self {
            file: None,
            file_size: 0,
            crypto_type: 0,
            has_rights_id: false,
            is_decrypted: false,
            is_cli_target: false,
            format_version: NcaVersion::Unknown,
            fixed_sig_validity: Validity::Unchecked,
            npdm_sig_validity: Validity::Unchecked,
            decrypted_keys: [[0u8; 0x10]; 4],
            title_key: [0u8; 0x10],
            section_contexts: [
                NcaSectionCtx::default(),
                NcaSectionCtx::default(),
                NcaSectionCtx::default(),
                NcaSectionCtx::default(),
            ],
            npdm: None,
            header_bytes: [0u8; 0xC00],
        }
    }
}

impl NcaCtx {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn magic(&self) -> u32 {
        read_u32_le(&self.header_bytes, 0x200)
    }

    #[inline]
    pub fn distribution(&self) -> u8 {
        self.header_bytes[0x204]
    }

    #[inline]
    pub fn content_type(&self) -> u8 {
        self.header_bytes[0x205]
    }

    #[inline]
    pub fn hdr_crypto_type(&self) -> u8 {
        self.header_bytes[0x206]
    }

    #[inline]
    pub fn kaek_ind(&self) -> u8 {
        self.header_bytes[0x207]
    }

    #[inline]
    pub fn nca_size(&self) -> u64 {
        read_u64_le(&self.header_bytes, 0x208)
    }

    #[inline]
    pub fn title_id(&self) -> u64 {
        read_u64_le(&self.header_bytes, 0x210)
    }

    #[inline]
    pub fn sdk_revision(&self) -> u8 {
        self.header_bytes[0x21C]
    }

    #[inline]
    pub fn sdk_micro(&self) -> u8 {
        self.header_bytes[0x21D]
    }

    #[inline]
    pub fn sdk_minor(&self) -> u8 {
        self.header_bytes[0x21E]
    }

    #[inline]
    pub fn sdk_major(&self) -> u8 {
        self.header_bytes[0x21F]
    }

    #[inline]
    pub fn crypto_type2(&self) -> u8 {
        self.header_bytes[0x220]
    }

    #[inline]
    pub fn fixed_key_generation(&self) -> u8 {
        self.header_bytes[0x221]
    }

    #[inline]
    pub fn rights_id(&self) -> [u8; 0x10] {
        self.header_bytes[0x230..0x240].try_into().unwrap()
    }

    #[inline]
    pub fn section_entry_start(&self, i: usize) -> u32 {
        read_u32_le(&self.header_bytes, 0x240 + i * 0x10)
    }

    #[inline]
    pub fn section_entry_end(&self, i: usize) -> u32 {
        read_u32_le(&self.header_bytes, 0x240 + i * 0x10 + 4)
    }
}

#[inline]
pub fn nca_update_ctr(ctr: &mut [u8; 0x10], mut ofs: u64) {
    ofs >>= 4;
    for j in 0..8 {
        ctr[0x10 - j - 1] = (ofs & 0xFF) as u8;
        ofs >>= 8;
    }
}

#[inline]
pub fn nca_update_bktr_ctr(ctr: &mut [u8; 0x10], mut ctr_val: u32, mut ofs: u64) {
    ofs >>= 4;
    for j in 0..8 {
        ctr[0x10 - j - 1] = (ofs & 0xFF) as u8;
        ofs >>= 8;
    }
    for j in 0..4 {
        ctr[0x8 - j - 1] = (ctr_val & 0xFF) as u8;
        ctr_val >>= 8;
    }
}

#[inline]
fn nca_make_ctr_iv(ctx: &NcaSectionCtx, abs_offset: u64) -> [u8; 0x10] {
    let mut iv = [0u8; 0x10];
    iv[0..8].copy_from_slice(&ctx.ctr[0..8]);
    iv[8..16].copy_from_slice(&(abs_offset >> 4).to_be_bytes());
    iv
}

#[inline]
fn nca_make_bktr_ctr_iv(ctx: &NcaSectionCtx, ctr_val: u32, abs_offset: u64) -> [u8; 0x10] {
    let mut iv = [0u8; 0x10];
    iv[0..4].copy_from_slice(&ctx.ctr[0..4]);
    iv[4..8].copy_from_slice(&ctr_val.to_be_bytes());
    iv[8..16].copy_from_slice(&(abs_offset >> 4).to_be_bytes());
    iv
}

#[inline]
fn nca_section_read_ctr(
    ctx: &NcaSectionCtx,
    file: &SharedFile,
    iv: &[u8; 0x10],
    phys_ofs: u64,
    buffer: &mut [u8],
) -> usize {
    let count = buffer.len();
    if count == 0 {
        return 0;
    }
    let block_ofs = (phys_ofs & 0xF) as usize;
    if file.read_exact_at(phys_ofs, buffer).is_err() {
        return 0;
    }
    if let Some(ref aes) = ctx.aes {
        aes.ctr_decrypt_in_place_at(iv, block_ofs, buffer);
    }
    count
}

fn nca_bktr_physical_read_at(
    ctx: &NcaSectionCtx,
    mut bktr_ofs: u64,
    mut dst: &mut [u8],
    file: &SharedFile,
) -> usize {
    if ctx.is_decrypted {
        let n = dst.len();
        if file.read_exact_at(ctx.offset + bktr_ofs, dst).is_err() {
            return 0;
        }
        return n;
    }

    let mut total_read = 0usize;
    while !dst.is_empty() {
        let subsec = bktr_get_subsection(&ctx.bktr_ctx.subsection_block, bktr_ofs);
        let avail = subsec.next_offset.saturating_sub(bktr_ofs);
        if avail == 0 {
            return 0;
        }
        let chunk_len = (dst.len() as u64).min(avail) as usize;
        let phys_ofs = ctx.offset + bktr_ofs;
        let iv = nca_make_bktr_ctr_iv(ctx, subsec.ctr_val, phys_ofs);
        let (out_chunk, rest) = dst.split_at_mut(chunk_len);
        if nca_section_read_ctr(ctx, file, &iv, phys_ofs, out_chunk) != chunk_len {
            return 0;
        }
        bktr_ofs += chunk_len as u64;
        total_read += chunk_len;
        dst = rest;
    }
    total_read
}

/// Stateless, lock-free section reader enabling parallel reads from multiple `rayon` threads.
pub fn nca_section_read_at(
    ctx: &NcaSectionCtx,
    offset: u64,
    buffer: &mut [u8],
    tool_ctx: &HactoolCtx,
) -> usize {
    nca_section_read_at_ex(ctx, offset, buffer, tool_ctx, ctx.physical_reads)
}

pub fn nca_section_read_at_ex(
    ctx: &NcaSectionCtx,
    offset: u64,
    buffer: &mut [u8],
    tool_ctx: &HactoolCtx,
    physical_reads: bool,
) -> usize {
    let count = buffer.len();
    if count == 0 {
        return 0;
    }
    let has_base_file = tool_ctx.has_base_file();
    let file = match ctx.file.as_ref() {
        Some(f) => f,
        None => return 0,
    };

    if ctx.is_decrypted && ctx.section_type != NcaSectionType::Bktr {
        if file.read_exact_at(ctx.offset + offset, buffer).is_err() {
            return 0;
        }
        return count;
    }

    if ctx.crypt_type == SectionCryptType::Xts || ctx.crypt_type == SectionCryptType::Nca0 {
        let sec_sz = ctx.sector_size as usize;
        let sec_mask = ctx.sector_mask as usize;
        let (mut cur_seek, mut sector_num, sector_ofs) =
            if ctx.crypt_type == SectionCryptType::Xts {
                (
                    (ctx.offset + offset) & !ctx.sector_mask,
                    (offset / ctx.sector_size) as usize,
                    (offset & ctx.sector_mask) as usize,
                )
            } else {
                (
                    ((ctx.offset + offset - 0x400) & !ctx.sector_mask) + 0x400,
                    ((ctx.offset + offset - 0x400) / ctx.sector_size) as usize,
                    ((ctx.offset + offset - 0x400) & ctx.sector_mask) as usize,
                )
            };

        let mut stack_buf = [0u8; 0x200];
        let mut heap_buf;
        let sector_buf: &mut [u8] = if sec_sz <= stack_buf.len() {
            &mut stack_buf[..sec_sz]
        } else {
            heap_buf = vec![0u8; sec_sz];
            &mut heap_buf
        };

        if file.read_exact_at(cur_seek, sector_buf).is_err() {
            return 0;
        }
        cur_seek += sec_sz as u64;
        if let Some(ref aes) = ctx.aes {
            aes.xts_crypt_in_place(sector_buf, sector_num, sec_sz, false);
        }

        if count > sec_sz - sector_ofs {
            let first_part = sec_sz - sector_ofs;
            buffer[..first_part].copy_from_slice(&sector_buf[sector_ofs..sec_sz]);
            let mut remaining = count - first_part;
            let mut ofs = first_part;
            sector_num += 1;

            let mid_bytes = remaining & !sec_mask;
            if mid_bytes > 0 {
                if file
                    .read_exact_at(cur_seek, &mut buffer[ofs..ofs + mid_bytes])
                    .is_err()
                {
                    return ofs;
                }
                cur_seek += mid_bytes as u64;
                if let Some(ref aes) = ctx.aes {
                    aes.xts_crypt_in_place(
                        &mut buffer[ofs..ofs + mid_bytes],
                        sector_num,
                        sec_sz,
                        false,
                    );
                }
                sector_num += mid_bytes / sec_sz;
                ofs += mid_bytes;
                remaining &= sec_mask;
            }

            if remaining > 0 {
                if file.read_exact_at(cur_seek, sector_buf).is_err() {
                    return ofs;
                }
                if let Some(ref aes) = ctx.aes {
                    aes.xts_crypt_in_place(sector_buf, sector_num, sec_sz, false);
                }
                buffer[ofs..ofs + remaining].copy_from_slice(&sector_buf[..remaining]);
            }
            count
        } else {
            buffer.copy_from_slice(&sector_buf[sector_ofs..sector_ofs + count]);
            count
        }
    } else if ctx.crypt_type == SectionCryptType::Ctr
        || (ctx.crypt_type == SectionCryptType::Bktr && ctx.bktr_ctx.subsection_block.is_empty())
    {
        let phys_ofs = ctx.offset + offset;
        let iv = nca_make_ctr_iv(ctx, phys_ofs);
        nca_section_read_ctr(ctx, file, &iv, phys_ofs, buffer)
    } else if ctx.crypt_type == SectionCryptType::Bktr {
        if has_base_file && !physical_reads {
            let mut cur_virt = offset;
            let mut dst = buffer;
            let mut total_read = 0usize;
            let base_romfs_sec = tool_ctx.base_nca_ctx.as_ref().and_then(|base_nca| {
                (0..4)
                    .find(|&idx| base_nca.section_contexts[idx].section_type == NcaSectionType::Romfs)
                    .map(|idx| &base_nca.section_contexts[idx])
            });

            while !dst.is_empty() {
                let reloc = bktr_get_relocation(&ctx.bktr_ctx.relocation_block, cur_virt);
                let avail = reloc.next_virt_offset.saturating_sub(cur_virt);
                if avail == 0 {
                    return 0;
                }
                let chunk_len = (dst.len() as u64).min(avail) as usize;
                let section_ofs = cur_virt - reloc.virt_offset + reloc.phys_offset;
                let (out_chunk, rest) = dst.split_at_mut(chunk_len);

                if reloc.is_patch != 0 {
                    if nca_bktr_physical_read_at(ctx, section_ofs, out_chunk, file) != chunk_len {
                        return 0;
                    }
                } else {
                    match tool_ctx.base_file_type {
                        BaseFileType::Romfs => {
                            if let Some(ref bf) = tool_ctx.base_file {
                                if bf.read_exact_at(section_ofs, out_chunk).is_err() {
                                    return 0;
                                }
                            } else {
                                return 0;
                            }
                        }
                        BaseFileType::Nca => {
                            let base_sec = base_romfs_sec.expect("Missing base_nca_ctx RomFS");
                            if nca_section_read_at_ex(base_sec, section_ofs, out_chunk, tool_ctx, false)
                                != chunk_len
                            {
                                eprintln!("Failed to read from Base NCA RomFS!");
                                process::exit(1);
                            }
                        }
                        BaseFileType::Fake => {
                            out_chunk.fill(0xCC);
                        }
                        BaseFileType::None => {
                            eprintln!("Unknown Base File Type!");
                            process::exit(1);
                        }
                    }
                }

                cur_virt += chunk_len as u64;
                total_read += chunk_len;
                dst = rest;
            }
            total_read
        } else {
            nca_bktr_physical_read_at(ctx, offset, buffer, file)
        }
    } else {
        0
    }
}

pub fn nca_decrypt_header(ctx: &mut NcaCtx, tool_ctx: &HactoolCtx) -> bool {
    let file = match ctx.file.as_ref() {
        Some(f) => f.clone(),
        None => return false,
    };

    let file_len = file.len();
    let read_size = if file_len >= 0xC00 {
        0xC00
    } else if file_len >= 0xA00 {
        0xA00
    } else {
        eprintln!("Failed to read NCA header!");
        return false;
    };

    ctx.header_bytes.fill(0);
    if file
        .read_exact_at(0, &mut ctx.header_bytes[..read_size])
        .is_err()
    {
        eprintln!("Failed to read NCA header!");
        return false;
    }

    let raw_magic = read_u32_le(&ctx.header_bytes, 0x200);
    if raw_magic == MAGIC_NCA3 || raw_magic == MAGIC_NCA2 {
        if ctx.header_bytes[0x340..0x400].iter().all(|&b| b == 0) {
            ctx.is_decrypted = true;
            ctx.format_version = if raw_magic == MAGIC_NCA3 {
                NcaVersion::Nca3
            } else {
                NcaVersion::Nca2
            };
            return true;
        }
    }

    ctx.is_decrypted = false;
    let hdr_aes = AesCtx::new(&tool_ctx.settings.keyset.header_key, 32, AesMode::Xts);
    let mut dec_header = [0u8; 0xC00];
    hdr_aes.xts_decrypt(&ctx.header_bytes[..0x400], &mut dec_header[..0x400], 0, 0x200);

    let dec_magic = read_u32_le(&dec_header, 0x200);
    if read_size == 0xA00 && dec_magic != MAGIC_NCA0 {
        eprintln!("Failed to read NCA header!");
        return false;
    }

    if dec_magic == MAGIC_NCA3 {
        ctx.format_version = NcaVersion::Nca3;
        hdr_aes.xts_decrypt(&ctx.header_bytes, &mut dec_header, 0, 0x200);
        ctx.header_bytes = dec_header;
    } else if dec_magic == MAGIC_NCA2 {
        ctx.format_version = NcaVersion::Nca2;
        for i in 0..4 {
            let fs_ofs = 0x400 + i * 0x200;
            let pad_slice = &ctx.header_bytes[fs_ofs + 0x148..fs_ofs + 0x200];
            let all_equal = pad_slice.windows(2).all(|w| w[0] == w[1]) && pad_slice[0] == 0;
            if !all_equal {
                hdr_aes.xts_decrypt(
                    &ctx.header_bytes[fs_ofs..fs_ofs + 0x200],
                    &mut dec_header[fs_ofs..fs_ofs + 0x200],
                    0,
                    0x200,
                );
            } else {
                dec_header[fs_ofs..fs_ofs + 0x200].fill(0);
            }
        }
        ctx.header_bytes = dec_header;
    } else if dec_magic == MAGIC_NCA0 {
        ctx.decrypted_keys = [[0u8; 0x10]; 4];
        let mut out_keydata = [0u8; 0x100];
        let mut enc_oaep = [0u8; 0x100];
        enc_oaep.copy_from_slice(&dec_header[0x300..0x400]);
        let exp = pki_get_beta_nca0_exponent();
        let out_len = rsa2048_oaep_decrypt_verify(
            &mut out_keydata,
            &enc_oaep,
            pki_get_beta_nca0_modulus(),
            &exp,
            pki_get_beta_nca0_label_hash(),
        );
        if out_len >= 0x20 {
            ctx.decrypted_keys[0].copy_from_slice(&out_keydata[0..0x10]);
            ctx.decrypted_keys[1].copy_from_slice(&out_keydata[0x10..0x20]);
            ctx.format_version = NcaVersion::Nca0Beta;
        } else {
            let mut calc_hash = [0u8; 0x20];
            const EXPECTED_HASH: [u8; 0x20] = [
                0x9A, 0xBB, 0xD2, 0x11, 0x86, 0x00, 0x21, 0x9D, 0x7A, 0xDC, 0x5B, 0x43, 0x95, 0xF8,
                0x4E, 0xFD, 0xFF, 0x6B, 0x25, 0xEF, 0x9F, 0x96, 0x85, 0x28, 0x18, 0x9E, 0x76, 0xB0,
                0x92, 0xF0, 0x6A, 0xCB,
            ];
            sha256_hash_buffer(&mut calc_hash, &dec_header[0x300..0x320]);
            if calc_hash == EXPECTED_HASH {
                ctx.format_version = NcaVersion::Nca0;
                for k in 0..4 {
                    ctx.decrypted_keys[k]
                        .copy_from_slice(&dec_header[0x300 + k * 0x10..0x300 + (k + 1) * 0x10]);
                }
            } else {
                ctx.format_version = NcaVersion::Nca0;
                let kaek_ind = (dec_header[0x207] as usize).min(2);
                let mut aes_ctx = AesCtx::new(
                    &tool_ctx.settings.keyset.key_area_keys[ctx.crypto_type as usize][kaek_ind],
                    16,
                    AesMode::Ecb,
                );
                let mut dec_2 = [0u8; 0x20];
                aes_ctx.decrypt(&dec_header[0x300..0x320], &mut dec_2);
                ctx.decrypted_keys[0].copy_from_slice(&dec_2[0..0x10]);
                ctx.decrypted_keys[1].copy_from_slice(&dec_2[0x10..0x20]);
            }
        }

        if ctx.format_version != NcaVersion::Unknown {
            dec_header[0x400..0xC00].fill(0);
            let mut xts_key = [0u8; 0x20];
            xts_key[0..0x10].copy_from_slice(&ctx.decrypted_keys[0]);
            xts_key[0x10..0x20].copy_from_slice(&ctx.decrypted_keys[1]);
            let aes_ctx = AesCtx::new(&xts_key, 32, AesMode::Xts);
            for i in 0..4 {
                let start_media = read_u32_le(&dec_header, 0x240 + i * 0x10);
                if start_media != 0 {
                    let offset = media_to_real(start_media as u64);
                    let fs_ofs = 0x400 + i * 0x200;
                    if file
                        .read_exact_at(offset, &mut dec_header[fs_ofs..fs_ofs + 0x200])
                        .is_err()
                    {
                        eprintln!("Failed to read NCA0 FS header at {:x}!", offset);
                        process::exit(1);
                    }
                    aes_ctx.xts_crypt_in_place(
                        &mut dec_header[fs_ofs..fs_ofs + 0x200],
                        ((offset - 0x400) >> 9) as usize,
                        0x200,
                        false,
                    );
                }
            }
            ctx.header_bytes = dec_header;
        }
    }

    ctx.format_version != NcaVersion::Unknown
}

pub fn nca_decrypt_key_area(ctx: &mut NcaCtx, tool_ctx: &HactoolCtx) {
    if ctx.format_version == NcaVersion::Nca0Beta || ctx.format_version == NcaVersion::Nca0 {
        return;
    }
    let kaek_ind = (ctx.kaek_ind() as usize).min(2);
    let mut aes_ctx = AesCtx::new(
        &tool_ctx.settings.keyset.key_area_keys[ctx.crypto_type as usize][kaek_ind],
        16,
        AesMode::Ecb,
    );
    let mut dec = [0u8; 0x40];
    aes_ctx.decrypt(&ctx.header_bytes[0x300..0x340], &mut dec);
    for i in 0..4 {
        ctx.decrypted_keys[i].copy_from_slice(&dec[i * 0x10..(i + 1) * 0x10]);
    }
}

pub fn nca_process(ctx: &mut NcaCtx, tool_ctx: &mut HactoolCtx) {
    if !nca_decrypt_header(ctx, tool_ctx) {
        eprintln!("Invalid NCA header! Are keys correct?");
        return;
    }

    let fixed_gen = ctx.fixed_key_generation() as usize;
    let moduli = &tool_ctx.settings.keyset.nca_hdr_fixed_key_moduli;
    if fixed_gen < moduli.len() {
        let sig: &[u8; 0x100] = ctx.header_bytes[0..0x100].try_into().unwrap();
        if rsa2048_pss_verify(&ctx.header_bytes[0x200..0x400], sig, &moduli[fixed_gen]) {
            ctx.fixed_sig_validity = Validity::Valid;
        } else {
            ctx.fixed_sig_validity = Validity::Invalid;
        }
    } else {
        ctx.fixed_sig_validity = Validity::Invalid;
    }

    ctx.crypto_type = ctx.hdr_crypto_type();
    if ctx.crypto_type2() > ctx.crypto_type {
        ctx.crypto_type = ctx.crypto_type2();
    }
    if ctx.crypto_type > 0 {
        ctx.crypto_type -= 1;
    }
    ctx.crypto_type &= 0x1F;

    let rights_id = ctx.rights_id();
    ctx.has_rights_id = rights_id.iter().any(|&b| b != 0);

    if ctx.is_cli_target {
        if let Some(ref base_nca) = tool_ctx.base_nca_ctx {
            let base_tid = base_nca.title_id();
            let expectation = ctx.title_id() & 0xFFFFFFFFFFFFF7FF;
            if base_tid != expectation {
                println!(
                    "[WARN] Base NCA Title ID doesn't match expectation ({:016x} != {:016x})",
                    base_tid, expectation
                );
            }
        }
    }

    if tool_ctx.settings.has_expected_content_type {
        if tool_ctx.settings.expected_content_type != (ctx.content_type() as u32) {
            tool_ctx.action &= !ACTION_EXTRACT;
        }
    }

    if !ctx.has_rights_id {
        nca_decrypt_key_area(ctx, tool_ctx);
    } else {
        let mut aes_ctx = AesCtx::new(
            &tool_ctx.settings.keyset.titlekeks[ctx.crypto_type as usize],
            16,
            AesMode::Ecb,
        );
        if ctx.is_cli_target && tool_ctx.settings.has_cli_titlekey {
            let cli_tk = tool_ctx.settings.cli_titlekey;
            aes_ctx.decrypt(&cli_tk, &mut tool_ctx.settings.dec_cli_titlekey);
        } else if let Some(pos) = tool_ctx
            .settings
            .known_titlekeys
            .titlekeys
            .iter()
            .position(|e| e.rights_id == rights_id)
        {
            let tk = tool_ctx.settings.known_titlekeys.titlekeys[pos].titlekey;
            aes_ctx.decrypt(
                &tk,
                &mut tool_ctx.settings.known_titlekeys.titlekeys[pos].dec_titlekey,
            );
        }
    }

    for i in 0..4 {
        let start_media = ctx.section_entry_start(i);
        if start_media != 0 {
            let end_media = ctx.section_entry_end(i);
            let fs_ofs = 0x400 + i * 0x200;
            let mut fs_hdr = [0u8; 0x200];
            fs_hdr.copy_from_slice(&ctx.header_bytes[fs_ofs..fs_ofs + 0x200]);

            let sec = &mut ctx.section_contexts[i];
            sec.is_present = true;
            sec.is_decrypted = ctx.is_decrypted;
            sec.file = ctx.file.clone();
            sec.section_num = i as u32;
            sec.offset = media_to_real(start_media as u64);
            sec.size = media_to_real(end_media as u64) - sec.offset;
            sec.fs_header_raw = fs_hdr;
            sec.crypt_type = SectionCryptType::from_u8(fs_hdr[4]);
            if ctx.format_version == NcaVersion::Nca0 || ctx.format_version == NcaVersion::Nca0Beta
            {
                sec.crypt_type = SectionCryptType::Nca0;
            }

            let partition_type = fs_hdr[2];
            let fs_type = fs_hdr[3];
            let sb_bytes = &fs_hdr[0x8..0x140];

            if partition_type == 1 && fs_type == 2 {
                sec.section_type = NcaSectionType::Pfs0;
                sec.pfs0_ctx.superblock = Some(Pfs0Superblock::from_bytes(sb_bytes));
            } else if partition_type == 0 && fs_type == 3 {
                if sec.crypt_type == SectionCryptType::Bktr {
                    sec.section_type = NcaSectionType::Bktr;
                    sec.bktr_ctx.superblock = BktrSuperblock::from_bytes(sb_bytes);
                } else {
                    sec.section_type = NcaSectionType::Romfs;
                    sec.romfs_ctx.superblock = Some(RomfsSuperblock::from_bytes(sb_bytes));
                }
            } else if partition_type == 0
                && fs_type == 2
                && (ctx.format_version == NcaVersion::Nca0
                    || ctx.format_version == NcaVersion::Nca0Beta)
            {
                sec.section_type = NcaSectionType::Nca0Romfs;
                sec.nca0_romfs_ctx.superblock = Some(Nca0RomfsSuperblock::from_bytes(sb_bytes));
            } else {
                sec.section_type = NcaSectionType::Invalid;
            }

            let mut ofs_shifted = sec.offset >> 4;
            for j in 0..8 {
                sec.ctr[j] = fs_hdr[0x140 + 8 - j - 1];
                sec.ctr[0x10 - j - 1] = (ofs_shifted & 0xFF) as u8;
                ofs_shifted >>= 8;
            }
            sec.sector_num = 0;
            sec.sector_ofs = 0;

            if sec.crypt_type == SectionCryptType::None {
                sec.is_decrypted = true;
            }

            if ctx.is_cli_target && tool_ctx.settings.has_cli_contentkey {
                sec.aes = Some(AesCtx::new(
                    &tool_ctx.settings.cli_contentkey,
                    16,
                    AesMode::Ctr,
                ));
            } else if ctx.has_rights_id {
                if ctx.is_cli_target && tool_ctx.settings.has_cli_titlekey {
                    sec.aes = Some(AesCtx::new(
                        &tool_ctx.settings.dec_cli_titlekey,
                        16,
                        AesMode::Ctr,
                    ));
                } else if let Some(entry) = settings_get_titlekey(&tool_ctx.settings, &rights_id) {
                    sec.aes = Some(AesCtx::new(&entry.dec_titlekey, 16, AesMode::Ctr));
                } else {
                    if i == 0 {
                        println!(
                            "[WARN] Unable to match rights id to titlekey. Update title.keys?"
                        );
                    }
                    sec.aes = Some(AesCtx::new(&[0u8; 0x10], 16, AesMode::Ctr));
                }
            } else {
                if sec.crypt_type == SectionCryptType::Ctr
                    || sec.crypt_type == SectionCryptType::Bktr
                {
                    sec.aes = Some(AesCtx::new(&ctx.decrypted_keys[2], 16, AesMode::Ctr));
                } else if sec.crypt_type == SectionCryptType::Xts
                    || sec.crypt_type == SectionCryptType::Nca0
                {
                    let mut xts_key = [0u8; 0x20];
                    xts_key[0..0x10].copy_from_slice(&ctx.decrypted_keys[0]);
                    xts_key[0x10..0x20].copy_from_slice(&ctx.decrypted_keys[1]);
                    sec.aes = Some(AesCtx::new(&xts_key, 32, AesMode::Xts));
                    sec.sector_size = 0x200;
                    sec.sector_mask = 0x1FF;
                }
            }

            if (tool_ctx.action & ACTION_VERIFY) != 0 {
                println!("Verifying section {}...", i);
            }

            match sec.section_type {
                NcaSectionType::Pfs0 => {
                    nca_process_pfs0_section(sec, tool_ctx);
                    if sec.pfs0_ctx.is_exefs {
                        if let Some(ref npdm_bytes) = sec.pfs0_ctx.npdm {
                            let acid_ofs = read_u32_le(npdm_bytes, 0x78) as usize;
                            if acid_ofs + 0x200 <= npdm_bytes.len() {
                                let acid_mod: &[u8; 0x100] =
                                    npdm_bytes[acid_ofs + 0x100..acid_ofs + 0x200]
                                        .try_into()
                                        .unwrap();
                                let npdm_sig: &[u8; 0x100] =
                                    ctx.header_bytes[0x100..0x200].try_into().unwrap();
                                if rsa2048_pss_verify(
                                    &ctx.header_bytes[0x200..0x400],
                                    npdm_sig,
                                    acid_mod,
                                ) {
                                    ctx.npdm_sig_validity = Validity::Valid;
                                } else {
                                    ctx.npdm_sig_validity = Validity::Invalid;
                                }
                            }
                            ctx.npdm = Some(npdm_bytes.clone());
                        }
                    }
                }
                NcaSectionType::Romfs => {
                    nca_process_ivfc_section(sec, tool_ctx);
                }
                NcaSectionType::Nca0Romfs => {
                    nca_process_nca0_romfs_section(sec, tool_ctx);
                }
                NcaSectionType::Bktr => {
                    nca_process_bktr_section(sec, tool_ctx);
                }
                NcaSectionType::Invalid => {}
            }
        }
    }

    if (tool_ctx.action & ACTION_INFO) != 0 {
        nca_print(ctx, tool_ctx);
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        nca_save(ctx, tool_ctx);
    }
}

/// Multi-threaded section hash table verification
fn nca_section_check_external_hash_table(
    ctx: &NcaSectionCtx,
    hash_table: &[u8],
    data_ofs: u64,
    data_len: u64,
    block_size: u64,
    full_block: bool,
    tool_ctx: &HactoolCtx,
) -> Validity {
    if block_size == 0 {
        return Validity::Invalid;
    }
    let bsize = block_size as usize;

    // For large multi-block data (<= 64 MB chunked), decrypt and verify in parallel using par_verify_blocks!
    const CHUNK_BLOCKS: usize = 1024;
    let total_blocks = ((data_len + block_size - 1) / block_size) as usize;
    if total_blocks > 4 && bsize <= 0x100000 {
        let batch_blocks = CHUNK_BLOCKS.min(total_blocks).max(16);
        let batch_bytes = batch_blocks * bsize;
        let mut buf = vec![0u8; batch_bytes];

        let mut block_idx = 0usize;
        while block_idx < total_blocks {
            let cur_blocks = (total_blocks - block_idx).min(batch_blocks);
            let cur_ofs = data_ofs + (block_idx as u64) * block_size;
            let remaining_data = (data_len - (block_idx as u64) * block_size) as usize;
            let read_len = remaining_data.min(cur_blocks * bsize);
            let padded_len = if full_block {
                cur_blocks * bsize
            } else {
                read_len
            };

            if full_block && read_len < padded_len {
                buf[read_len..padded_len].fill(0);
            }

            if nca_section_read_at(ctx, cur_ofs, &mut buf[..read_len], tool_ctx) != read_len {
                eprintln!("Failed to read section!");
                process::exit(1);
            }

            let ht_slice = &hash_table[block_idx * 0x20..(block_idx + cur_blocks) * 0x20];
            if !par_verify_blocks(&buf[..padded_len], ht_slice, bsize) {
                return Validity::Invalid;
            }
            block_idx += cur_blocks;
        }
        return Validity::Valid;
    }

    let mut block = vec![0u8; bsize];
    let mut read_size = bsize;
    let mut ofs = 0u64;
    let mut ht_idx = 0usize;

    while ofs < data_len {
        if ofs + (read_size as u64) > data_len {
            block.fill(0);
            read_size = (data_len - ofs) as usize;
        }
        if nca_section_read_at(ctx, ofs + data_ofs, &mut block[..read_size], tool_ctx) != read_size
        {
            eprintln!("Failed to read section!");
            process::exit(1);
        }
        let mut cur_hash = [0u8; 0x20];
        let hash_input_len = if full_block { bsize } else { read_size };
        sha256_hash_buffer(&mut cur_hash, &block[..hash_input_len]);
        if cur_hash != hash_table[ht_idx..ht_idx + 0x20] {
            return Validity::Invalid;
        }
        ht_idx += 0x20;
        ofs += read_size as u64;
    }

    Validity::Valid
}

fn nca_section_check_hash_table(
    ctx: &NcaSectionCtx,
    hash_ofs: u64,
    data_ofs: u64,
    data_len: u64,
    block_size: u64,
    full_block: bool,
    tool_ctx: &HactoolCtx,
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

    if nca_section_read_at(ctx, hash_ofs, &mut hash_table, tool_ctx) != hash_table_size {
        eprintln!("Failed to read section!");
        process::exit(1);
    }

    nca_section_check_external_hash_table(
        ctx,
        &hash_table,
        data_ofs,
        data_len,
        block_size,
        full_block,
        tool_ctx,
    )
}

pub fn nca_process_pfs0_section(ctx: &mut NcaSectionCtx, tool_ctx: &HactoolCtx) {
    let sb = ctx.pfs0_ctx.superblock.clone().unwrap();
    ctx.superblock_hash_validity = nca_section_check_external_hash_table(
        ctx,
        &sb.master_hash,
        sb.hash_table_offset,
        sb.hash_table_size,
        sb.hash_table_size,
        false,
        tool_ctx,
    );
    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        ctx.pfs0_ctx.hash_table_validity = nca_section_check_hash_table(
            ctx,
            sb.hash_table_offset,
            sb.pfs0_offset,
            sb.pfs0_size,
            sb.block_size as u64,
            false,
            tool_ctx,
        );
    }

    if ctx.superblock_hash_validity != Validity::Valid {
        return;
    }

    let mut raw_header = [0u8; 0x10];
    if nca_section_read_at(ctx, sb.pfs0_offset, &mut raw_header, tool_ctx) != 0x10 {
        eprintln!("Failed to read PFS0 header!");
        process::exit(1);
    }

    let num_files = read_u32_le(&raw_header, 4) as usize;
    let string_table_size = read_u32_le(&raw_header, 8) as usize;
    let header_size = 0x10 + num_files * 0x18 + string_table_size;

    let mut hdr_buf = vec![0u8; header_size];
    if nca_section_read_at(ctx, sb.pfs0_offset, &mut hdr_buf, tool_ctx) != header_size {
        eprintln!("Failed to read PFS0 header!");
        process::exit(1);
    }
    ctx.pfs0_ctx.header_bytes = hdr_buf;

    for i in 0..(num_files as u32) {
        if ctx.pfs0_ctx.get_file_name(i) == "main.npdm" {
            let cur_file = ctx.pfs0_ctx.get_file_entry(i).unwrap();
            if cur_file.size >= sb.pfs0_size {
                eprintln!("NPDM too big!");
                process::exit(1);
            }
            let mut npdm_buf = vec![0u8; cur_file.size as usize];
            let ofs = sb.pfs0_offset + ctx.pfs0_ctx.header_size() + cur_file.offset;
            if nca_section_read_at(ctx, ofs, &mut npdm_buf, tool_ctx) != (cur_file.size as usize) {
                eprintln!("Failed to read NPDM!");
                process::exit(1);
            }
            if npdm_buf.len() >= 4 && read_u32_le(&npdm_buf, 0) == MAGIC_META {
                ctx.pfs0_ctx.is_exefs = true;
            }
            ctx.pfs0_ctx.npdm = Some(npdm_buf);
        }
    }
}

pub fn nca_process_ivfc_section(ctx: &mut NcaSectionCtx, tool_ctx: &HactoolCtx) {
    let sb = ctx.romfs_ctx.superblock.clone().unwrap();

    for i in 0..IVFC_MAX_LEVEL {
        let lhdr = sb.ivfc_header.level_headers[i];
        let data_offset = lhdr.logical_offset;
        let data_size = lhdr.hash_data_size;
        let hash_block_size = 1u32 << lhdr.block_size;
        let hash_offset = if i != 0 {
            ctx.romfs_ctx.ivfc_levels[i - 1].data_offset
        } else {
            0
        };

        ctx.romfs_ctx.ivfc_levels[i].data_offset = data_offset;
        ctx.romfs_ctx.ivfc_levels[i].data_size = data_size;
        ctx.romfs_ctx.ivfc_levels[i].hash_block_size = hash_block_size;
        ctx.romfs_ctx.ivfc_levels[i].hash_offset = hash_offset;

        if i == 0 {
            ctx.superblock_hash_validity = nca_section_check_external_hash_table(
                ctx,
                &sb.ivfc_header.master_hash,
                data_offset,
                data_size,
                hash_block_size as u64,
                true,
                tool_ctx,
            );
            ctx.romfs_ctx.ivfc_levels[i].hash_validity = ctx.superblock_hash_validity;
        }
        if (tool_ctx.action & ACTION_VERIFY) != 0 && i != 0 {
            println!("    Verifying IVFC Level {}...", i);
            ctx.romfs_ctx.ivfc_levels[i].hash_validity = nca_section_check_hash_table(
                ctx,
                hash_offset,
                data_offset,
                data_size,
                hash_block_size as u64,
                true,
                tool_ctx,
            );
        }
    }

    ctx.romfs_ctx.romfs_offset = ctx.romfs_ctx.ivfc_levels[IVFC_MAX_LEVEL - 1].data_offset;
    let mut hdr_bytes = [0u8; 0x50];
    if nca_section_read_at(ctx, ctx.romfs_ctx.romfs_offset, &mut hdr_bytes, tool_ctx) != 0x50 {
        eprintln!("Failed to read RomFS header!");
    }
    ctx.romfs_ctx.header = RomfsHdr::from_bytes(&hdr_bytes);

    if (tool_ctx.action & (ACTION_EXTRACT | ACTION_LISTROMFS)) != 0
        && ctx.romfs_ctx.header.header_size == ROMFS_HEADER_SIZE
    {
        let dir_sz = ctx.romfs_ctx.header.dir_meta_table_size as usize;
        let mut dirs = vec![0u8; dir_sz];
        if nca_section_read_at(
            ctx,
            ctx.romfs_ctx.romfs_offset + ctx.romfs_ctx.header.dir_meta_table_offset,
            &mut dirs,
            tool_ctx,
        ) != dir_sz
        {
            eprintln!("Failed to read RomFS directory cache!");
            process::exit(1);
        }
        ctx.romfs_ctx.directories = dirs;

        let file_sz = ctx.romfs_ctx.header.file_meta_table_size as usize;
        let mut files = vec![0u8; file_sz];
        if nca_section_read_at(
            ctx,
            ctx.romfs_ctx.romfs_offset + ctx.romfs_ctx.header.file_meta_table_offset,
            &mut files,
            tool_ctx,
        ) != file_sz
        {
            eprintln!("Failed to read RomFS file cache!");
            process::exit(1);
        }
        ctx.romfs_ctx.files = files;
    }
}

pub fn nca_process_nca0_romfs_section(ctx: &mut NcaSectionCtx, tool_ctx: &HactoolCtx) {
    let sb = ctx.nca0_romfs_ctx.superblock.clone().unwrap();

    ctx.superblock_hash_validity = nca_section_check_external_hash_table(
        ctx,
        &sb.master_hash,
        sb.hash_table_offset,
        sb.hash_table_size,
        sb.hash_table_size,
        false,
        tool_ctx,
    );
    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        ctx.nca0_romfs_ctx.hash_table_validity = nca_section_check_hash_table(
            ctx,
            sb.hash_table_offset,
            sb.romfs_offset,
            sb.romfs_size,
            sb.block_size as u64,
            false,
            tool_ctx,
        );
    }

    if ctx.superblock_hash_validity != Validity::Valid {
        return;
    }

    ctx.nca0_romfs_ctx.romfs_offset = sb.romfs_offset;
    let mut hdr_bytes = [0u8; 0x28];
    if nca_section_read_at(
        ctx,
        ctx.nca0_romfs_ctx.romfs_offset,
        &mut hdr_bytes,
        tool_ctx,
    ) != 0x28
    {
        eprintln!("Failed to read NCA0 RomFS header!");
    }
    ctx.nca0_romfs_ctx.header = Nca0RomfsHdr::from_bytes(&hdr_bytes);

    if (tool_ctx.action & (ACTION_EXTRACT | ACTION_LISTROMFS)) != 0
        && ctx.nca0_romfs_ctx.header.header_size == NCA0_ROMFS_HEADER_SIZE
    {
        let dir_sz = ctx.nca0_romfs_ctx.header.dir_meta_table_size as usize;
        let mut dirs = vec![0u8; dir_sz];
        if nca_section_read_at(
            ctx,
            ctx.nca0_romfs_ctx.romfs_offset
                + (ctx.nca0_romfs_ctx.header.dir_meta_table_offset as u64),
            &mut dirs,
            tool_ctx,
        ) != dir_sz
        {
            eprintln!("Failed to read NCA0 RomFS directory cache!");
            process::exit(1);
        }
        ctx.nca0_romfs_ctx.directories = dirs;

        let file_sz = ctx.nca0_romfs_ctx.header.file_meta_table_size as usize;
        let mut files = vec![0u8; file_sz];
        if nca_section_read_at(
            ctx,
            ctx.nca0_romfs_ctx.romfs_offset
                + (ctx.nca0_romfs_ctx.header.file_meta_table_offset as u64),
            &mut files,
            tool_ctx,
        ) != file_sz
        {
            eprintln!("Failed to read NCA0 RomFS file cache!");
            process::exit(1);
        }
        ctx.nca0_romfs_ctx.files = files;
    }
}

pub fn nca_process_bktr_section(ctx: &mut NcaSectionCtx, tool_ctx: &HactoolCtx) {
    let sb = ctx.bktr_ctx.superblock.clone();
    let has_base_file = tool_ctx.has_base_file();

    if sb.relocation_header.magic == MAGIC_BKTR && sb.subsection_header.magic == MAGIC_BKTR {
        if sb.relocation_header.offset + sb.relocation_header.size != sb.subsection_header.offset
            || sb.subsection_header.offset + sb.subsection_header.size != ctx.size
        {
            eprintln!("Invalid BKTR layout!");
            process::exit(1);
        }

        let reloc_sz = sb.relocation_header.size as usize;
        let mut relocs = vec![0u8; reloc_sz + (0x3FF0 / 8) * 20];
        let subsec_sz = sb.subsection_header.size as usize;
        let mut subs = vec![0u8; subsec_sz + (0x3FF0 / 8) * 16 + 16];

        if nca_section_read_at_ex(
            ctx,
            sb.relocation_header.offset,
            &mut relocs[..reloc_sz],
            tool_ctx,
            true,
        ) != reloc_sz
        {
            eprintln!("Failed to read relocation header!");
            process::exit(1);
        }
        if nca_section_read_at_ex(
            ctx,
            sb.subsection_header.offset,
            &mut subs[..subsec_sz],
            tool_ctx,
            true,
        ) != subsec_sz
        {
            eprintln!("Failed to read subsection header!");
            process::exit(1);
        }

        let subsec_total_size = read_u64_le(&subs, 8);
        if subsec_total_size != sb.subsection_header.offset {
            ctx.superblock_hash_validity = Validity::Invalid;
            return;
        }

        // Expand relocation buckets in place matching nca.c lines 1193-1215
        let reloc_num_buckets = read_u32_le(&relocs, 4) as usize;
        for i in (1..reloc_num_buckets).rev() {
            let src_ofs = 0x4000 + i * 0x4000;
            let dst_ofs = 0x4000 + i * 0x4014;
            relocs.copy_within(src_ofs..src_ofs + 0x4000, dst_ofs);
        }
        for i in 0..reloc_num_buckets.saturating_sub(1) {
            let b_ofs = 0x4000 + i * 0x4014;
            let num_entries = read_u32_le(&relocs, b_ofs + 4) as usize;
            let next_virt_ofs = read_u64_le(&relocs, 0x10 + (i + 1) * 8);
            let entry_ofs = b_ofs + 0x10 + num_entries * 20;
            relocs[entry_ofs..entry_ofs + 8].copy_from_slice(&next_virt_ofs.to_le_bytes());
        }

        let subsec_num_buckets = read_u32_le(&subs, 4) as usize;
        for i in (1..subsec_num_buckets).rev() {
            let src_ofs = 0x4000 + i * 0x4000;
            let dst_ofs = 0x4000 + i * 0x4010;
            subs.copy_within(src_ofs..src_ofs + 0x4000, dst_ofs);
        }
        for i in 0..subsec_num_buckets.saturating_sub(1) {
            let b_ofs = 0x4000 + i * 0x4010;
            let next_b_ofs = 0x4000 + (i + 1) * 0x4010;
            let num_entries = read_u32_le(&subs, b_ofs + 4) as usize;
            let next_e0_ofs = read_u64_le(&subs, next_b_ofs + 0x10);
            let next_e0_ctr = read_u32_le(&subs, next_b_ofs + 0x10 + 12);
            let entry_ofs = b_ofs + 0x10 + num_entries * 16;
            subs[entry_ofs..entry_ofs + 8].copy_from_slice(&next_e0_ofs.to_le_bytes());
            subs[entry_ofs + 12..entry_ofs + 16].copy_from_slice(&next_e0_ctr.to_le_bytes());
        }

        if reloc_num_buckets > 0 {
            let last_r_ofs = 0x4000 + (reloc_num_buckets - 1) * 0x4014;
            let last_r_entries = read_u32_le(&relocs, last_r_ofs + 4) as usize;
            let total_r_size = read_u64_le(&relocs, 8);
            let entry_ofs = last_r_ofs + 0x10 + last_r_entries * 20;
            relocs[entry_ofs..entry_ofs + 8].copy_from_slice(&total_r_size.to_le_bytes());
        }

        if subsec_num_buckets > 0 {
            let last_s_ofs = 0x4000 + (subsec_num_buckets - 1) * 0x4010;
            let last_s_entries = read_u32_le(&subs, last_s_ofs + 4) as usize;
            let section_ctr_low = read_u32_le(&ctx.fs_header_raw, 0x140);
            let e1_ofs = last_s_ofs + 0x10 + last_s_entries * 16;
            subs[e1_ofs..e1_ofs + 8].copy_from_slice(&sb.relocation_header.offset.to_le_bytes());
            subs[e1_ofs + 12..e1_ofs + 16].copy_from_slice(&section_ctr_low.to_le_bytes());
            let e2_ofs = e1_ofs + 16;
            subs[e2_ofs..e2_ofs + 8].copy_from_slice(&ctx.size.to_le_bytes());
            subs[e2_ofs + 12..e2_ofs + 16].copy_from_slice(&0u32.to_le_bytes());
        }

        ctx.bktr_ctx.relocation_block = relocs;
        ctx.bktr_ctx.subsection_block = subs;

        for i in 0..IVFC_MAX_LEVEL {
            let lhdr = sb.ivfc_header.level_headers[i];
            let data_offset = lhdr.logical_offset;
            let data_size = lhdr.hash_data_size;
            let hash_block_size = 1u32 << lhdr.block_size;
            let hash_offset = if i != 0 {
                ctx.bktr_ctx.ivfc_levels[i - 1].data_offset
            } else {
                0
            };

            ctx.bktr_ctx.ivfc_levels[i].data_offset = data_offset;
            ctx.bktr_ctx.ivfc_levels[i].data_size = data_size;
            ctx.bktr_ctx.ivfc_levels[i].hash_block_size = hash_block_size;
            ctx.bktr_ctx.ivfc_levels[i].hash_offset = hash_offset;

            if i == 0 && has_base_file {
                ctx.superblock_hash_validity = nca_section_check_external_hash_table(
                    ctx,
                    &sb.ivfc_header.master_hash,
                    data_offset,
                    data_size,
                    hash_block_size as u64,
                    true,
                    tool_ctx,
                );
                ctx.bktr_ctx.ivfc_levels[i].hash_validity = ctx.superblock_hash_validity;
            }
            if (tool_ctx.action & ACTION_VERIFY) != 0 && i != 0 {
                println!("    Verifying IVFC Level {}...", i);
                ctx.bktr_ctx.ivfc_levels[i].hash_validity = nca_section_check_hash_table(
                    ctx,
                    hash_offset,
                    data_offset,
                    data_size,
                    hash_block_size as u64,
                    true,
                    tool_ctx,
                );
            }
        }

        ctx.bktr_ctx.romfs_offset = ctx.bktr_ctx.ivfc_levels[IVFC_MAX_LEVEL - 1].data_offset;
        if has_base_file {
            let mut hdr_bytes = [0u8; 0x50];
            if nca_section_read_at(ctx, ctx.bktr_ctx.romfs_offset, &mut hdr_bytes, tool_ctx) != 0x50
            {
                eprintln!("Failed to read BKTR Virtual RomFS header!");
            }
            ctx.bktr_ctx.header = RomfsHdr::from_bytes(&hdr_bytes);

            if (tool_ctx.action & (ACTION_EXTRACT | ACTION_LISTROMFS)) != 0
                && ctx.bktr_ctx.header.header_size == ROMFS_HEADER_SIZE
            {
                let dir_sz = ctx.bktr_ctx.header.dir_meta_table_size as usize;
                let mut dirs = vec![0u8; dir_sz];
                if nca_section_read_at(
                    ctx,
                    ctx.bktr_ctx.romfs_offset + ctx.bktr_ctx.header.dir_meta_table_offset,
                    &mut dirs,
                    tool_ctx,
                ) != dir_sz
                {
                    eprintln!("Failed to read RomFS directory cache!");
                    process::exit(1);
                }
                ctx.bktr_ctx.directories = dirs;

                let file_sz = ctx.bktr_ctx.header.file_meta_table_size as usize;
                let mut files = vec![0u8; file_sz];
                if nca_section_read_at(
                    ctx,
                    ctx.bktr_ctx.romfs_offset + ctx.bktr_ctx.header.file_meta_table_offset,
                    &mut files,
                    tool_ctx,
                ) != file_sz
                {
                    eprintln!("Failed to read RomFS file cache!");
                    process::exit(1);
                }
                ctx.bktr_ctx.files = files;
            }
        }
    }
}

fn nca_get_distribution_type(ctx: &NcaCtx) -> &'static str {
    match ctx.distribution() {
        0 => "Download",
        1 => "Gamecard",
        _ => "Unknown",
    }
}

fn nca_get_content_type(ctx: &NcaCtx) -> &'static str {
    match ctx.content_type() {
        0 => "Program",
        1 => "Meta",
        2 => "Control",
        3 => "Manual",
        4 => "Data",
        5 => "PublicData",
        _ => "Unknown",
    }
}

fn nca_get_encryption_type(ctx: &NcaCtx) -> &'static str {
    if ctx.has_rights_id {
        "Titlekey crypto"
    } else {
        "Standard crypto"
    }
}

fn nca_get_section_type(meta: &NcaSectionCtx) -> &'static str {
    match meta.section_type {
        NcaSectionType::Pfs0 => {
            if meta.pfs0_ctx.is_exefs {
                "ExeFS"
            } else {
                "PFS0"
            }
        }
        NcaSectionType::Nca0Romfs => "NCA0 RomFS",
        NcaSectionType::Romfs => "RomFS",
        NcaSectionType::Bktr => "Patch RomFS",
        NcaSectionType::Invalid => "Unknown/Invalid",
    }
}

fn nca_get_section_type_name(t: NcaSectionType) -> &'static str {
    match t {
        NcaSectionType::Pfs0 => "pfs0",
        NcaSectionType::Romfs | NcaSectionType::Bktr | NcaSectionType::Nca0Romfs => "romfs",
        NcaSectionType::Invalid => "unknown",
    }
}

fn nca_print_key_area(ctx: &NcaCtx, tool_ctx: &HactoolCtx) {
    if ctx.format_version == NcaVersion::Nca0Beta {
        println!("Key Area (Encrypted):");
        memdump_stdout(
            "Key (RSA-OAEP Encrypted):           ",
            &ctx.header_bytes[0x300..0x400],
        );
        if !tool_ctx.settings.suppress_keydata_output {
            println!("Key Area (Decrypted):");
            for i in 0..2 {
                print!("    Key {} (Decrypted):              ", i);
                memdump_stdout("", &ctx.decrypted_keys[i]);
            }
        }
    } else if ctx.format_version == NcaVersion::Nca0 {
        println!("Key Area (Encrypted):");
        for i in 0..2 {
            print!("    Key {} (Encrypted):              ", i);
            memdump_stdout(
                "",
                &ctx.header_bytes[0x300 + i * 0x10..0x300 + (i + 1) * 0x10],
            );
        }
        if !tool_ctx.settings.suppress_keydata_output {
            println!("Key Area (Decrypted):");
            for i in 0..2 {
                print!("    Key {} (Decrypted):              ", i);
                memdump_stdout("", &ctx.decrypted_keys[i]);
            }
        }
    } else {
        println!("Key Area (Encrypted):");
        for i in 0..4 {
            print!("    Key {} (Encrypted):              ", i);
            memdump_stdout(
                "",
                &ctx.header_bytes[0x300 + i * 0x10..0x300 + (i + 1) * 0x10],
            );
        }
        if !tool_ctx.settings.suppress_keydata_output {
            println!("Key Area (Decrypted):");
            for i in 0..4 {
                print!("    Key {} (Decrypted):              ", i);
                memdump_stdout("", &ctx.decrypted_keys[i]);
            }
        }
    }
}

pub fn nca_print_pfs0_section(ctx: &NcaSectionCtx, tool_ctx: &HactoolCtx) {
    let sb = ctx.pfs0_ctx.superblock.as_ref().unwrap();
    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        if ctx.superblock_hash_validity == Validity::Valid {
            memdump_stdout("        Superblock Hash (GOOD):     ", &sb.master_hash);
        } else {
            memdump_stdout("        Superblock Hash (FAIL):     ", &sb.master_hash);
        }
        println!(
            "        Hash Table ({}):",
            ctx.pfs0_ctx.hash_table_validity.as_str()
        );
    } else {
        memdump_stdout("        Superblock Hash:            ", &sb.master_hash);
        println!("        Hash Table:");
    }
    println!(
        "            Offset:                 {:012x}",
        sb.hash_table_offset
    );
    println!(
        "            Size:                   {:012x}",
        sb.hash_table_size
    );
    println!("            Block Size:             0x{:x}", sb.block_size);
    println!("        PFS0 Offset:                {:012x}", sb.pfs0_offset);
    println!("        PFS0 Size:                  {:012x}", sb.pfs0_size);
}

pub fn nca_print_ivfc_section(ctx: &NcaSectionCtx, tool_ctx: &HactoolCtx) {
    let sb = ctx.romfs_ctx.superblock.as_ref().unwrap();
    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        if ctx.superblock_hash_validity == Validity::Valid {
            memdump_stdout(
                "        Superblock Hash (GOOD):     ",
                &sb.ivfc_header.master_hash,
            );
        } else {
            memdump_stdout(
                "        Superblock Hash (FAIL):     ",
                &sb.ivfc_header.master_hash,
            );
        }
    } else {
        memdump_stdout(
            "        Superblock Hash:            ",
            &sb.ivfc_header.master_hash,
        );
    }
    print_magic("        Magic:                      ", sb.ivfc_header.magic);
    println!("        ID:                         {:08x}", sb.ivfc_header.id);
    for i in 0..IVFC_MAX_LEVEL {
        let lvl = &ctx.romfs_ctx.ivfc_levels[i];
        if (tool_ctx.action & ACTION_VERIFY) != 0 {
            println!("        Level {} ({}):", i, lvl.hash_validity.as_str());
        } else {
            println!("        Level {}:", i);
        }
        println!(
            "            Data Offset:            0x{:012x}",
            lvl.data_offset
        );
        println!("            Data Size:              0x{:012x}", lvl.data_size);
        if i != 0 {
            println!(
                "            Hash Offset:            0x{:012x}",
                lvl.hash_offset
            );
        }
        println!(
            "            Hash Block Size:        0x{:08x}",
            lvl.hash_block_size
        );
    }
}

pub fn nca_print_nca0_romfs_section(ctx: &NcaSectionCtx, tool_ctx: &HactoolCtx) {
    let sb = ctx.nca0_romfs_ctx.superblock.as_ref().unwrap();
    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        if ctx.superblock_hash_validity == Validity::Valid {
            memdump_stdout("        Superblock Hash (GOOD):     ", &sb.master_hash);
        } else {
            memdump_stdout("        Superblock Hash (FAIL):     ", &sb.master_hash);
        }
        println!(
            "        Hash Table ({}):",
            ctx.nca0_romfs_ctx.hash_table_validity.as_str()
        );
    } else {
        memdump_stdout("        Superblock Hash:            ", &sb.master_hash);
        println!("        Hash Table:");
    }
    println!(
        "            Offset:                 {:012x}",
        sb.hash_table_offset
    );
    println!(
        "            Size:                   {:012x}",
        sb.hash_table_size
    );
    println!("            Block Size:             0x{:x}", sb.block_size);
    println!("        RomFS Offset:               {:012x}", sb.romfs_offset);
    println!("        RomFS Size:                 {:012x}", sb.romfs_size);
}

pub fn nca_print_bktr_section(ctx: &NcaSectionCtx, tool_ctx: &HactoolCtx) {
    if ctx.bktr_ctx.subsection_block.is_empty() {
        println!("        BKTR section seems to be corrupted.");
        return;
    }
    let did_verify = (tool_ctx.action & ACTION_VERIFY) != 0 && tool_ctx.has_base_file();
    let sb = &ctx.bktr_ctx.superblock;
    if did_verify {
        if ctx.superblock_hash_validity == Validity::Valid {
            memdump_stdout(
                "        Superblock Hash (GOOD):     ",
                &sb.ivfc_header.master_hash,
            );
        } else {
            memdump_stdout(
                "        Superblock Hash (FAIL):     ",
                &sb.ivfc_header.master_hash,
            );
        }
    } else {
        memdump_stdout(
            "        Superblock Hash:            ",
            &sb.ivfc_header.master_hash,
        );
    }
    print_magic("        Magic:                      ", sb.ivfc_header.magic);
    println!("        ID:                         {:08x}", sb.ivfc_header.id);
    for i in 0..IVFC_MAX_LEVEL {
        let lvl = &ctx.bktr_ctx.ivfc_levels[i];
        if did_verify {
            println!("        Level {} ({}):", i, lvl.hash_validity.as_str());
        } else {
            println!("        Level {}:", i);
        }
        println!(
            "            Data Offset:            0x{:012x}",
            lvl.data_offset
        );
        println!("            Data Size:              0x{:012x}", lvl.data_size);
        if i != 0 {
            println!(
                "            Hash Offset:            0x{:012x}",
                lvl.hash_offset
            );
        }
        println!(
            "            Hash Block Size:        0x{:08x}",
            lvl.hash_block_size
        );
    }
}

fn nca_print_sections(ctx: &mut NcaCtx, tool_ctx: &HactoolCtx) {
    println!("Sections:");
    let is_nca0 =
        ctx.format_version == NcaVersion::Nca0 || ctx.format_version == NcaVersion::Nca0Beta;
    for i in 0..4 {
        let sec = &mut ctx.section_contexts[i];
        if sec.is_present {
            println!("    Section {}:", i);
            println!("        Offset:                     0x{:012x}", sec.offset);
            println!("        Size:                       0x{:012x}", sec.size);
            println!(
                "        Partition Type:             {}",
                nca_get_section_type(sec)
            );
            if !is_nca0 {
                nca_update_ctr(&mut sec.ctr, sec.offset);
                memdump_stdout("        Section CTR:                ", &sec.ctr);
            }
            match sec.section_type {
                NcaSectionType::Pfs0 => nca_print_pfs0_section(sec, tool_ctx),
                NcaSectionType::Romfs => nca_print_ivfc_section(sec, tool_ctx),
                NcaSectionType::Nca0Romfs => nca_print_nca0_romfs_section(sec, tool_ctx),
                NcaSectionType::Bktr => nca_print_bktr_section(sec, tool_ctx),
                NcaSectionType::Invalid => {
                    print!("        Unknown/invalid superblock!");
                }
            }
        }
    }
}

pub fn nca_print(ctx: &mut NcaCtx, tool_ctx: &mut HactoolCtx) {
    println!("\nNCA:");
    print_magic("Magic:                              ", ctx.magic());

    let fixed_gen = ctx.fixed_key_generation();
    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        if (fixed_gen as usize) < tool_ctx.settings.keyset.nca_hdr_fixed_key_moduli.len() {
            println!("Fixed-Key Index (GOOD):             0x{:X}", fixed_gen);
        } else {
            println!("Fixed-Key Index (FAIL):             0x{:X}", fixed_gen);
        }
    } else {
        println!("Fixed-Key Index:                    0x{:X}", fixed_gen);
    }

    if (tool_ctx.action & ACTION_VERIFY) != 0 && ctx.fixed_sig_validity != Validity::Unchecked {
        if ctx.fixed_sig_validity == Validity::Valid {
            memdump_stdout(
                "Fixed-Key Signature (GOOD):         ",
                &ctx.header_bytes[0..0x100],
            );
        } else {
            memdump_stdout(
                "Fixed-Key Signature (FAIL):         ",
                &ctx.header_bytes[0..0x100],
            );
        }
    } else {
        memdump_stdout(
            "Fixed-Key Signature:                ",
            &ctx.header_bytes[0..0x100],
        );
    }

    if (tool_ctx.action & ACTION_VERIFY) != 0 && ctx.npdm_sig_validity != Validity::Unchecked {
        if ctx.npdm_sig_validity == Validity::Valid {
            memdump_stdout(
                "NPDM Signature (GOOD):              ",
                &ctx.header_bytes[0x100..0x200],
            );
        } else {
            memdump_stdout(
                "NPDM Signature (FAIL):              ",
                &ctx.header_bytes[0x100..0x200],
            );
        }
    } else {
        memdump_stdout(
            "NPDM Signature:                     ",
            &ctx.header_bytes[0x100..0x200],
        );
    }

    println!("Content Size:                       0x{:012x}", ctx.nca_size());
    println!("Title ID:                           {:016x}", ctx.title_id());
    println!(
        "SDK Version:                        {}.{}.{}.{}",
        ctx.sdk_major(),
        ctx.sdk_minor(),
        ctx.sdk_micro(),
        ctx.sdk_revision()
    );
    println!(
        "Distribution type:                  {}",
        nca_get_distribution_type(ctx)
    );
    println!(
        "Content Type:                       {}",
        nca_get_content_type(ctx)
    );
    println!(
        "Master Key Revision:                0x{:X} ({})",
        ctx.crypto_type,
        get_key_revision_summary(ctx.crypto_type)
    );
    println!(
        "Encryption Type:                    {}",
        nca_get_encryption_type(ctx)
    );

    if ctx.has_rights_id {
        let rights_id = ctx.rights_id();
        memdump_stdout("Rights ID:                          ", &rights_id);
        if ctx.is_cli_target && tool_ctx.settings.has_cli_titlekey {
            if !tool_ctx.settings.suppress_keydata_output {
                memdump_stdout(
                    "Titlekey (Encrypted) (From CLI)     ",
                    &tool_ctx.settings.cli_titlekey,
                );
                memdump_stdout(
                    "Titlekey (Decrypted) (From CLI)     ",
                    &tool_ctx.settings.dec_cli_titlekey,
                );
            }
        } else if settings_has_titlekey(&tool_ctx.settings, &rights_id) {
            let entry = settings_get_titlekey(&tool_ctx.settings, &rights_id).unwrap();
            if !tool_ctx.settings.suppress_keydata_output {
                memdump_stdout("Titlekey (Encrypted)                ", &entry.titlekey);
                memdump_stdout("Titlekey (Decrypted)                ", &entry.dec_titlekey);
            }
        } else {
            println!("Titlekey:                           Unknown");
        }
    } else {
        println!(
            "Key Area Encryption Key:            {:x}",
            ctx.kaek_ind()
        );
        nca_print_key_area(ctx, tool_ctx);
    }

    if let Some(ref npdm_bytes) = ctx.npdm {
        let npdm_clone = npdm_bytes.clone();
        npdm_process(&npdm_clone, tool_ctx);
    }

    nca_print_sections(ctx, tool_ctx);
    println!();
}

struct NcaExtractJob {
    phys_offset: u64,
    size: u64,
    filepath: Filepath,
}

/// Optimized `nca_save_section_file` that reuses a thread-local 4 MiB scratch buffer.
pub fn nca_save_section_file(
    ctx: &NcaSectionCtx,
    ofs: u64,
    total_size: u64,
    filepath: &Filepath,
    tool_ctx: &HactoolCtx,
) {
    nca_save_section_file_ex(ctx, ofs, total_size, filepath, tool_ctx, ctx.physical_reads);
}

fn nca_save_section_file_ex(
    ctx: &NcaSectionCtx,
    mut ofs: u64,
    total_size: u64,
    filepath: &Filepath,
    tool_ctx: &HactoolCtx,
    physical_reads: bool,
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
    let needed = total_size.min(SCRATCH_BUF_SIZE as u64) as usize;
    with_worker_scratch(needed, |buf| {
        while ofs < end_ofs {
            let read_size = ((end_ofs - ofs) as usize).min(buf.len());
            if nca_section_read_at_ex(
                ctx,
                ofs,
                &mut buf[..read_size],
                tool_ctx,
                physical_reads,
            ) != read_size
            {
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

pub fn nca_save_pfs0_section(ctx: &NcaSectionCtx, tool_ctx: &HactoolCtx) {
    if ctx.superblock_hash_validity == Validity::Valid && ctx.pfs0_ctx.magic() == MAGIC_PFS0 {
        let mut dirpath: Option<Filepath> = None;
        if ctx.pfs0_ctx.is_exefs && tool_ctx.settings.exefs_dir_path.enabled {
            dirpath = Some(tool_ctx.settings.exefs_dir_path.path.clone());
        }
        if dirpath.is_none() || dirpath.as_ref().unwrap().valid != Validity::Valid {
            dirpath = Some(
                tool_ctx.settings.section_dir_paths[ctx.section_num as usize].clone(),
            );
        }
        if let Some(mut dp) = dirpath {
            if dp.valid == Validity::Valid {
                if tool_ctx.settings.append_section_types {
                    let formatted = format!(
                        "{}_{}",
                        dp.char_path,
                        nca_get_section_type_name(ctx.section_type)
                    );
                    dp.set(&formatted);
                }
                os_makedir(&dp.char_path);
                let num_files = ctx.pfs0_ctx.num_files();
                let pfs0_ofs = ctx.pfs0_ctx.superblock.as_ref().unwrap().pfs0_offset;
                let hdr_sz = ctx.pfs0_ctx.header_size();
                let mut jobs = Vec::with_capacity(num_files as usize);
                for i in 0..num_files {
                    let cur_file = match ctx.pfs0_ctx.get_file_entry(i) {
                        Some(e) => e,
                        None => {
                            eprintln!("Could not save file {}!", i as i32);
                            process::exit(1);
                        }
                    };
                    if cur_file.size >= ctx.size {
                        eprintln!(
                            "File {} too big in PFS0 (section {})!",
                            i as i32, ctx.section_num as i32
                        );
                        process::exit(1);
                    }
                    let name = ctx.pfs0_ctx.get_file_name(i);
                    if name.len() >= MAX_PATH - dp.char_path.len() - 1 {
                        eprintln!("Filename too long in PFS0!");
                        process::exit(1);
                    }
                    let mut filepath = dp.clone();
                    filepath.append(&name);
                    let ofs = pfs0_ofs + hdr_sz + cur_file.offset;
                    jobs.push((name, ofs, cur_file.size, filepath));
                }
                jobs.sort_unstable_by_key(|b| std::cmp::Reverse(b.2));
                let writer = BufferedLineWriter::new(tool_ctx.settings.quiet);
                jobs.par_iter().for_each(|(name, ofs, size, filepath)| {
                    nca_save_section_file_ex(ctx, *ofs, *size, filepath, tool_ctx, false);
                    writer.log_saving_to(name, &filepath.char_path);
                });
                drop(writer);
            }
        }
    } else {
        eprintln!("Error: section {} is corrupted!", ctx.section_num as i32);
    }
}

fn nca_is_romfs_file_updated(ctx: &NcaSectionCtx, file_offset: u64, file_size: u64) -> bool {
    if ctx.section_type == NcaSectionType::Romfs {
        return true;
    }
    let mut cur_ofs = file_offset;
    let end_ofs = file_offset + file_size;
    loop {
        let reloc = bktr_get_relocation(&ctx.bktr_ctx.relocation_block, cur_ofs);
        if reloc.is_patch != 0 {
            return true;
        }
        if reloc.next_virt_offset >= end_ofs || reloc.next_virt_offset <= cur_ofs {
            break;
        }
        cur_ofs = reloc.next_virt_offset;
    }
    false
}

fn nca_list_romfs_dir(
    ctx: &NcaSectionCtx,
    mut dir_offset: u32,
    parent_path: &Filepath,
    tool_ctx: &HactoolCtx,
) {
    let only_updated = (tool_ctx.action & ACTION_ONLYUPDATEDROMFS) != 0;
    let (dir_bytes, file_bytes, base_data_ofs) = if ctx.section_type == NcaSectionType::Romfs {
        (
            &ctx.romfs_ctx.directories,
            &ctx.romfs_ctx.files,
            ctx.romfs_ctx.romfs_offset + ctx.romfs_ctx.header.data_offset,
        )
    } else {
        (
            &ctx.bktr_ctx.directories,
            &ctx.bktr_ctx.files,
            ctx.bktr_ctx.romfs_offset + ctx.bktr_ctx.header.data_offset,
        )
    };

    while dir_offset != ROMFS_ENTRY_EMPTY {
        let entry = parse_direntry(dir_bytes, dir_offset);
        let mut cur_path = parent_path.clone();
        if entry.name_size > 0 {
            cur_path.append_n(entry.name_size as usize, &entry.name);
        }

        let mut file_ofs = entry.file;
        while file_ofs != ROMFS_ENTRY_EMPTY {
            let fentry = parse_fentry(file_bytes, file_ofs);
            let mut fpath = cur_path.clone();
            if fentry.name_size > 0 {
                fpath.append_n(fentry.name_size as usize, &fentry.name);
            }
            let phys_offset = base_data_ofs + fentry.offset;
            if !only_updated || nca_is_romfs_file_updated(ctx, phys_offset, fentry.size) {
                println!("rom:{}", fpath.char_path);
            }
            file_ofs = fentry.sibling;
        }

        if entry.child != ROMFS_ENTRY_EMPTY {
            nca_list_romfs_dir(ctx, entry.child, &cur_path, tool_ctx);
        }
        dir_offset = entry.sibling;
    }
}

fn nca_collect_romfs_dir(
    ctx: &NcaSectionCtx,
    mut dir_offset: u32,
    parent_path: &Filepath,
    tool_ctx: &HactoolCtx,
    dirs: &mut Vec<String>,
    jobs: &mut Vec<NcaExtractJob>,
) -> bool {
    let only_updated = (tool_ctx.action & ACTION_ONLYUPDATEDROMFS) != 0;
    let only_updated_bktr = ctx.section_type == NcaSectionType::Bktr && only_updated;
    let (dir_bytes, file_bytes, base_data_ofs) = if ctx.section_type == NcaSectionType::Romfs {
        (
            &ctx.romfs_ctx.directories,
            &ctx.romfs_ctx.files,
            ctx.romfs_ctx.romfs_offset + ctx.romfs_ctx.header.data_offset,
        )
    } else {
        (
            &ctx.bktr_ctx.directories,
            &ctx.bktr_ctx.files,
            ctx.bktr_ctx.romfs_offset + ctx.bktr_ctx.header.data_offset,
        )
    };

    let mut any_in_branch = false;
    while dir_offset != ROMFS_ENTRY_EMPTY {
        let entry = parse_direntry(dir_bytes, dir_offset);
        let mut cur_path = parent_path.clone();
        if entry.name_size > 0 {
            cur_path.append_n(entry.name_size as usize, &entry.name);
        }

        let dir_slot = dirs.len();
        dirs.push(cur_path.char_path.clone());

        let mut any_here = false;
        let mut file_ofs = entry.file;
        while file_ofs != ROMFS_ENTRY_EMPTY {
            let fentry = parse_fentry(file_bytes, file_ofs);
            let phys_offset = base_data_ofs + fentry.offset;
            if !only_updated || nca_is_romfs_file_updated(ctx, phys_offset, fentry.size) {
                let mut fpath = cur_path.clone();
                if fentry.name_size > 0 {
                    fpath.append_n(fentry.name_size as usize, &fentry.name);
                }
                jobs.push(NcaExtractJob {
                    phys_offset,
                    size: fentry.size,
                    filepath: fpath,
                });
                any_here = true;
            }
            file_ofs = fentry.sibling;
        }

        if entry.child != ROMFS_ENTRY_EMPTY {
            any_here |= nca_collect_romfs_dir(
                ctx,
                entry.child,
                &cur_path,
                tool_ctx,
                dirs,
                jobs,
            );
        }

        if !any_here && only_updated_bktr {
            dirs.truncate(dir_slot);
        }

        any_in_branch |= any_here;
        dir_offset = entry.sibling;
    }
    any_in_branch
}

fn nca_list_nca0_romfs_dir(ctx: &NcaSectionCtx, mut dir_offset: u32, parent_path: &Filepath) {
    while dir_offset != ROMFS_ENTRY_EMPTY {
        let entry = parse_direntry(&ctx.nca0_romfs_ctx.directories, dir_offset);
        let mut cur_path = parent_path.clone();
        if entry.name_size > 0 {
            cur_path.append_n(entry.name_size as usize, &entry.name);
        }

        let mut file_ofs = entry.file;
        while file_ofs != ROMFS_ENTRY_EMPTY {
            let fentry = parse_fentry(&ctx.nca0_romfs_ctx.files, file_ofs);
            let mut fpath = cur_path.clone();
            if fentry.name_size > 0 {
                fpath.append_n(fentry.name_size as usize, &fentry.name);
            }
            println!("rom:{}", fpath.char_path);
            file_ofs = fentry.sibling;
        }

        if entry.child != ROMFS_ENTRY_EMPTY {
            nca_list_nca0_romfs_dir(ctx, entry.child, &cur_path);
        }
        dir_offset = entry.sibling;
    }
}

fn nca_collect_nca0_romfs_dir(
    ctx: &NcaSectionCtx,
    mut dir_offset: u32,
    parent_path: &Filepath,
    dirs: &mut Vec<String>,
    jobs: &mut Vec<NcaExtractJob>,
) {
    let base_data_ofs =
        ctx.nca0_romfs_ctx.romfs_offset + (ctx.nca0_romfs_ctx.header.data_offset as u64);
    while dir_offset != ROMFS_ENTRY_EMPTY {
        let entry = parse_direntry(&ctx.nca0_romfs_ctx.directories, dir_offset);
        let mut cur_path = parent_path.clone();
        if entry.name_size > 0 {
            cur_path.append_n(entry.name_size as usize, &entry.name);
        }

        dirs.push(cur_path.char_path.clone());

        let mut file_ofs = entry.file;
        while file_ofs != ROMFS_ENTRY_EMPTY {
            let fentry = parse_fentry(&ctx.nca0_romfs_ctx.files, file_ofs);
            let mut fpath = cur_path.clone();
            if fentry.name_size > 0 {
                fpath.append_n(fentry.name_size as usize, &fentry.name);
            }
            jobs.push(NcaExtractJob {
                phys_offset: base_data_ofs + fentry.offset,
                size: fentry.size,
                filepath: fpath,
            });
            file_ofs = fentry.sibling;
        }

        if entry.child != ROMFS_ENTRY_EMPTY {
            nca_collect_nca0_romfs_dir(ctx, entry.child, &cur_path, dirs, jobs);
        }
        dir_offset = entry.sibling;
    }
}

fn nca_execute_romfs_extract(
    ctx: &NcaSectionCtx,
    dirs: Vec<String>,
    mut jobs: Vec<NcaExtractJob>,
    tool_ctx: &HactoolCtx,
) {
    // Pass 1: Create all directories sequentially upfront to avoid NTFS MFT lock contention.
    for dir in &dirs {
        os_makedir(dir);
    }

    // Pass 2: Extract largest files first (LPT scheduling) across the rayon work-stealing pool.
    jobs.sort_unstable_by_key(|b| std::cmp::Reverse(b.size));
    let writer = BufferedLineWriter::new(tool_ctx.settings.quiet);
    jobs.par_iter().for_each(|job| {
        nca_save_section_file_ex(ctx, job.phys_offset, job.size, &job.filepath, tool_ctx, false);
        writer.log_saving(&job.filepath.char_path);
    });
    drop(writer);
}

fn nca_resolve_romfs_dirpath(ctx: &NcaSectionCtx, tool_ctx: &HactoolCtx) -> Option<Filepath> {
    let mut dirpath: Option<Filepath> = None;
    if tool_ctx.settings.romfs_dir_path.enabled {
        dirpath = Some(tool_ctx.settings.romfs_dir_path.path.clone());
    }
    if dirpath.is_none() || dirpath.as_ref().unwrap().valid != Validity::Valid {
        dirpath = Some(tool_ctx.settings.section_dir_paths[ctx.section_num as usize].clone());
    }
    if let Some(mut dp) = dirpath {
        if dp.valid == Validity::Valid {
            if tool_ctx.settings.append_section_types {
                let formatted = format!(
                    "{}_{}",
                    dp.char_path,
                    nca_get_section_type_name(ctx.section_type)
                );
                dp.set(&formatted);
            }
            return Some(dp);
        }
    }
    None
}

pub fn nca_save_ivfc_section(ctx: &NcaSectionCtx, tool_ctx: &HactoolCtx) {
    if ctx.superblock_hash_validity == Validity::Valid
        && ctx.romfs_ctx.header.header_size == ROMFS_HEADER_SIZE
    {
        if (tool_ctx.action & ACTION_LISTROMFS) != 0 {
            let mut fakepath = Filepath::new();
            fakepath.set("");
            nca_list_romfs_dir(ctx, 0, &fakepath, tool_ctx);
        } else if let Some(dp) = nca_resolve_romfs_dirpath(ctx, tool_ctx) {
            let mut dirs = Vec::new();
            let mut jobs = Vec::new();
            nca_collect_romfs_dir(ctx, 0, &dp, tool_ctx, &mut dirs, &mut jobs);
            nca_execute_romfs_extract(ctx, dirs, jobs, tool_ctx);
        }
        return;
    }
    eprintln!("Error: section {} is corrupted!", ctx.section_num as i32);
}

pub fn nca_save_nca0_romfs_section(ctx: &NcaSectionCtx, tool_ctx: &HactoolCtx) {
    if ctx.superblock_hash_validity == Validity::Valid
        && ctx.nca0_romfs_ctx.header.header_size == NCA0_ROMFS_HEADER_SIZE
    {
        if (tool_ctx.action & ACTION_LISTROMFS) != 0 {
            let mut fakepath = Filepath::new();
            fakepath.set("");
            nca_list_nca0_romfs_dir(ctx, 0, &fakepath);
        } else if let Some(dp) = nca_resolve_romfs_dirpath(ctx, tool_ctx) {
            let mut dirs = Vec::new();
            let mut jobs = Vec::new();
            nca_collect_nca0_romfs_dir(ctx, 0, &dp, &mut dirs, &mut jobs);
            nca_execute_romfs_extract(ctx, dirs, jobs, tool_ctx);
        }
        return;
    }
    eprintln!("Error: section {} is corrupted!", ctx.section_num as i32);
}

pub fn nca_save_bktr_section(ctx: &NcaSectionCtx, tool_ctx: &HactoolCtx) {
    if ctx.superblock_hash_validity == Validity::Valid
        && ctx.bktr_ctx.header.header_size == ROMFS_HEADER_SIZE
    {
        if (tool_ctx.action & ACTION_LISTROMFS) != 0 {
            let mut fakepath = Filepath::new();
            fakepath.set("");
            nca_list_romfs_dir(ctx, 0, &fakepath, tool_ctx);
        } else if let Some(dp) = nca_resolve_romfs_dirpath(ctx, tool_ctx) {
            let mut dirs = Vec::new();
            let mut jobs = Vec::new();
            nca_collect_romfs_dir(ctx, 0, &dp, tool_ctx, &mut dirs, &mut jobs);
            nca_execute_romfs_extract(ctx, dirs, jobs, tool_ctx);
        }
        return;
    }
    eprintln!("Error: section {} is corrupted!", ctx.section_num as i32);
}

pub fn nca_save_section(ctx: &NcaSectionCtx, tool_ctx: &HactoolCtx) {
    let mut offset = 0u64;
    let mut size = ctx.size;

    if (tool_ctx.action & ACTION_RAW) == 0 {
        match ctx.section_type {
            NcaSectionType::Pfs0 => {
                if let Some(ref sb) = ctx.pfs0_ctx.superblock {
                    offset = sb.pfs0_offset;
                    size = sb.pfs0_size;
                }
            }
            NcaSectionType::Romfs => {
                offset = ctx.romfs_ctx.ivfc_levels[IVFC_MAX_LEVEL - 1].data_offset;
                size = ctx.romfs_ctx.ivfc_levels[IVFC_MAX_LEVEL - 1].data_size;
            }
            NcaSectionType::Nca0Romfs => {
                if let Some(ref sb) = ctx.nca0_romfs_ctx.superblock {
                    offset = sb.romfs_offset;
                    size = sb.romfs_size;
                }
            }
            NcaSectionType::Bktr => {
                if tool_ctx.has_base_file() {
                    offset = ctx.bktr_ctx.ivfc_levels[IVFC_MAX_LEVEL - 1].data_offset;
                    size = ctx.bktr_ctx.ivfc_levels[IVFC_MAX_LEVEL - 1].data_size;
                }
            }
            NcaSectionType::Invalid => {}
        }
    } else if ctx.section_type == NcaSectionType::Bktr
        && !ctx.bktr_ctx.subsection_block.is_empty()
        && tool_ctx.has_base_file()
    {
        size = read_u64_le(&ctx.bktr_ctx.relocation_block, 8);
    }

    let mut secpath = tool_ctx.settings.section_paths[ctx.section_num as usize].clone();
    if ctx.section_type == NcaSectionType::Pfs0
        && ctx.pfs0_ctx.is_exefs
        && tool_ctx.settings.exefs_path.enabled
        && tool_ctx.settings.exefs_path.path.valid == Validity::Valid
    {
        secpath = tool_ctx.settings.exefs_path.path.clone();
    } else if (ctx.section_type == NcaSectionType::Romfs
        || ctx.section_type == NcaSectionType::Nca0Romfs)
        && tool_ctx.settings.romfs_path.enabled
        && tool_ctx.settings.romfs_path.path.valid == Validity::Valid
    {
        secpath = tool_ctx.settings.romfs_path.path.clone();
    }

    if secpath.valid == Validity::Valid {
        if tool_ctx.settings.append_section_types {
            let formatted = format!(
                "{}.{}",
                secpath.char_path,
                nca_get_section_type_name(ctx.section_type)
            );
            secpath.set(&formatted);
        }
        if !tool_ctx.settings.quiet {
            println!(
                "Saving Section {} to {}...",
                ctx.section_num as i32, secpath.char_path
            );
            println!("Size: {:012x}", size);
        }
        nca_save_section_file(ctx, offset, size, &secpath, tool_ctx);
    }

    match ctx.section_type {
        NcaSectionType::Pfs0 => nca_save_pfs0_section(ctx, tool_ctx),
        NcaSectionType::Romfs => nca_save_ivfc_section(ctx, tool_ctx),
        NcaSectionType::Nca0Romfs => nca_save_nca0_romfs_section(ctx, tool_ctx),
        NcaSectionType::Bktr => {
            if !tool_ctx.has_base_file() {
                eprintln!("Note: cannot save BKTR section without base romfs.");
            } else {
                nca_save_bktr_section(ctx, tool_ctx);
            }
        }
        NcaSectionType::Invalid => {}
    }
}

fn nca_save(ctx: &NcaCtx, tool_ctx: &HactoolCtx) {
    if tool_ctx.settings.header_path.valid == Validity::Valid {
        let header_path = &tool_ctx.settings.header_path;
        if !tool_ctx.settings.quiet {
            println!("Saving Header to {}...", header_path.char_path);
        }
        match create_uncompressed_file(&header_path.char_path) {
            Ok(mut f_hdr) => {
                let _ = f_hdr.write_all(&ctx.header_bytes);
            }
            Err(_) => {
                eprintln!("Failed to open {}!", header_path.char_path);
            }
        }
    }

    for i in 0..4 {
        if ctx.section_contexts[i].is_present {
            nca_save_section(&ctx.section_contexts[i], tool_ctx);
            if !tool_ctx.settings.quiet {
                println!();
            }
        }
    }

    if tool_ctx.settings.plaintext_path.valid == Validity::Valid {
        let dec_path = &tool_ctx.settings.plaintext_path;
        if !tool_ctx.settings.quiet {
            println!("Saving Decrypted NCA to {}...", dec_path.char_path);
        }
        match create_uncompressed_file(&dec_path.char_path) {
            Ok(mut f_dec) => {
                if f_dec.write_all(&ctx.header_bytes).is_err() {
                    eprintln!("Failed to write header!");
                    process::exit(1);
                }

                with_worker_scratch(SCRATCH_BUF_SIZE, |buf| {
                    for i in 0..4 {
                        let sec = &ctx.section_contexts[i];
                        if sec.is_present {
                            let _ = f_dec.seek(SeekFrom::Start(sec.offset));
                            let mut ofs = 0u64;
                            let end_ofs = sec.size;
                            while ofs < end_ofs {
                                let read_size = ((end_ofs - ofs) as usize).min(buf.len());
                                if nca_section_read_at_ex(
                                    sec,
                                    ofs,
                                    &mut buf[..read_size],
                                    tool_ctx,
                                    true,
                                ) != read_size
                                {
                                    eprintln!("Failed to read file!");
                                    process::exit(1);
                                }
                                if f_dec.write_all(&buf[..read_size]).is_err() {
                                    eprintln!("Failed to write file!");
                                    process::exit(1);
                                }
                                ofs += read_size as u64;
                            }
                        }
                    }
                });
            }
            Err(_) => {
                eprintln!("Failed to open {}!", dec_path.char_path);
            }
        }
    }
}

