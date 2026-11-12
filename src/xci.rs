#![allow(dead_code)]

//! XCI (Gamecard Image) parsing, printing, and extraction matching `xci.c` and `xci.h`.

use crate::aes::{AesCtx, AesMode};
use crate::hfs0::{hfs0_collect_jobs, hfs0_execute_jobs, hfs0_process, Hfs0Ctx};
use crate::rsa::rsa2048_pkcs1_verify;
use crate::settings::HactoolCtx;
use crate::types::{
    read_u32_le, read_u64_le, Filepath, SharedFile, Validity, ACTION_EXTRACT, ACTION_INFO,
    ACTION_VERIFY,
};
use crate::utils::{
    check_memory_hash_table_with_suffix, media_to_real, memdump_stdout, os_makedir, print_magic,
};
use std::process;

pub const MAGIC_HEAD: u32 = 0x44414548;

const XCI_HEADER_PUBK: [u8; 0x100] = [
    0x98, 0xC7, 0x26, 0xB6, 0x0D, 0x0A, 0x50, 0xA7, 0x39, 0x21, 0x0A, 0xE3, 0x2F, 0xE4, 0x3E, 0x2E,
    0x5B, 0xA2, 0x86, 0x75, 0xAA, 0x5C, 0xEE, 0x34, 0xF1, 0xA3, 0x3A, 0x7E, 0xBD, 0x90, 0x4E, 0xF7,
    0x8D, 0xFA, 0x17, 0xAA, 0x6B, 0xC6, 0x36, 0x6D, 0x4C, 0x9A, 0x6D, 0x57, 0x2F, 0x80, 0xA2, 0xBC,
    0x38, 0x4D, 0xDA, 0x99, 0xA1, 0xD8, 0xC3, 0xE2, 0x99, 0x79, 0x36, 0x71, 0x90, 0x20, 0x25, 0x9D,
    0x4D, 0x11, 0xB8, 0x2E, 0x63, 0x6B, 0x5A, 0xFA, 0x1E, 0x9C, 0x04, 0xD1, 0xC5, 0xF0, 0x9C, 0xB1,
    0x0F, 0xB8, 0xC1, 0x7B, 0xBF, 0xE8, 0xB0, 0xD2, 0x2B, 0x47, 0x01, 0x22, 0x6B, 0x23, 0xC9, 0xD0,
    0xBC, 0xEB, 0x75, 0x6E, 0x41, 0x7D, 0x4C, 0x26, 0xA4, 0x73, 0x21, 0xB4, 0xF0, 0x14, 0xE5, 0xD9,
    0x8D, 0xB3, 0x64, 0xEE, 0xA8, 0xFA, 0x84, 0x1B, 0xB8, 0xB8, 0x7C, 0x88, 0x6B, 0xEF, 0xCC, 0x97,
    0x04, 0x04, 0x9A, 0x67, 0x2F, 0xDF, 0xEC, 0x0D, 0xB2, 0x5F, 0xB5, 0xB2, 0xBD, 0xB5, 0x4B, 0xDE,
    0x0E, 0x88, 0xA3, 0xBA, 0xD1, 0xB4, 0xE0, 0x91, 0x81, 0xA7, 0x84, 0xEB, 0x77, 0x85, 0x8B, 0xEF,
    0xA5, 0xE3, 0x27, 0xB2, 0xF2, 0x82, 0x2B, 0x29, 0xF1, 0x75, 0x2D, 0xCE, 0xCC, 0xAE, 0x9B, 0x8D,
    0xED, 0x5C, 0xF1, 0x8E, 0xDB, 0x9A, 0xD7, 0xAF, 0x42, 0x14, 0x52, 0xCD, 0xE3, 0xC5, 0xDD, 0xCE,
    0x08, 0x12, 0x17, 0xD0, 0x7F, 0x1A, 0xAA, 0x1F, 0x7D, 0xE0, 0x93, 0x54, 0xC8, 0xBC, 0x73, 0x8A,
    0xCB, 0xAD, 0x6E, 0x93, 0xE2, 0x19, 0x72, 0x6B, 0xD3, 0x45, 0xF8, 0x73, 0x3D, 0x2B, 0x6A, 0x55,
    0xD2, 0x3A, 0x8B, 0xB0, 0x8A, 0x42, 0xE3, 0x3D, 0xF1, 0x92, 0x23, 0x42, 0x2E, 0xBA, 0xCC, 0x9C,
    0x9A, 0xC1, 0xDD, 0x62, 0x86, 0x9C, 0x2E, 0xE1, 0x2D, 0x6F, 0x62, 0x67, 0x51, 0x08, 0x0E, 0xCF,
];

pub struct XciCtx {
    pub file: Option<SharedFile>,
    pub header_sig_validity: Validity,
    pub cert_sig_validity: Validity,
    pub hfs0_hash_validity: Validity,
    pub partition_ctx: Hfs0Ctx,
    pub normal_ctx: Hfs0Ctx,
    pub update_ctx: Hfs0Ctx,
    pub secure_ctx: Hfs0Ctx,
    pub logo_ctx: Hfs0Ctx,
    pub iv: [u8; 0x10],
    pub has_decrypted_header: bool,
    pub decrypted_header: [u8; 0x70],
    pub header_bytes: [u8; 0x200],
    pub has_fake_compat_type: bool,
    pub fake_compat_type: u8,
}

impl Default for XciCtx {
    fn default() -> Self {
        Self {
            file: None,
            header_sig_validity: Validity::Unchecked,
            cert_sig_validity: Validity::Unchecked,
            hfs0_hash_validity: Validity::Unchecked,
            partition_ctx: Hfs0Ctx::default(),
            normal_ctx: Hfs0Ctx::default(),
            update_ctx: Hfs0Ctx::default(),
            secure_ctx: Hfs0Ctx::default(),
            logo_ctx: Hfs0Ctx::default(),
            iv: [0u8; 0x10],
            has_decrypted_header: false,
            decrypted_header: [0u8; 0x70],
            header_bytes: [0u8; 0x200],
            has_fake_compat_type: false,
            fake_compat_type: 0,
        }
    }
}

pub fn xci_process(ctx: &mut XciCtx, tool_ctx: &mut HactoolCtx) {
    let file = match ctx.file.as_ref() {
        Some(f) => f.clone(),
        None => return,
    };

    if file.read_exact_at(0, &mut ctx.header_bytes).is_err() {
        eprintln!("Failed to read XCI header!");
        return;
    }

    let magic = read_u32_le(&ctx.header_bytes, 0x100);
    if magic != MAGIC_HEAD {
        eprintln!("Error: XCI header is corrupt!");
        process::exit(1);
    }

    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        let sig: &[u8; 0x100] = ctx.header_bytes[0..0x100].try_into().unwrap();
        if rsa2048_pkcs1_verify(&ctx.header_bytes[0x100..0x200], sig, &XCI_HEADER_PUBK) {
            ctx.header_sig_validity = Validity::Valid;
        } else {
            ctx.header_sig_validity = Validity::Invalid;
        }
    }

    for i in 0..0x10 {
        ctx.iv[i] = ctx.header_bytes[0x120 + (0xF - i)];
    }

    if tool_ctx
        .settings
        .keyset
        .xci_header_key
        .iter()
        .any(|&b| b != 0)
    {
        let mut aes_ctx = AesCtx::new(
            &tool_ctx.settings.keyset.xci_header_key,
            0x10,
            AesMode::CbcDec,
        );
        aes_ctx.set_iv(&ctx.iv);
        aes_ctx.decrypt(&ctx.header_bytes[0x190..0x200], &mut ctx.decrypted_header);
        ctx.has_decrypted_header = true;
    } else {
        ctx.has_decrypted_header = false;
    }

    let hfs0_offset = read_u64_le(&ctx.header_bytes, 0x130);
    let hfs0_header_size = read_u64_le(&ctx.header_bytes, 0x138);
    let hfs0_header_hash = &ctx.header_bytes[0x140..0x160];

    ctx.has_fake_compat_type = false;
    ctx.fake_compat_type = 0; // COMPAT_GLOBAL

    if ctx.has_decrypted_header {
        let compat_type = ctx.decrypted_header[0x10 + 0x24];
        let sfx = if compat_type != 0 {
            Some([compat_type])
        } else {
            None
        };
        ctx.hfs0_hash_validity = check_memory_hash_table_with_suffix(
            &file,
            hfs0_header_hash,
            hfs0_offset,
            hfs0_header_size,
            hfs0_header_size,
            sfx.as_ref().map(|s| &s[..]),
            false,
        );
    } else {
        ctx.hfs0_hash_validity = check_memory_hash_table_with_suffix(
            &file,
            hfs0_header_hash,
            hfs0_offset,
            hfs0_header_size,
            hfs0_header_size,
            None,
            false,
        );
        if ctx.hfs0_hash_validity != Validity::Valid {
            ctx.has_fake_compat_type = true;
            ctx.fake_compat_type = 1; // COMPAT_CHINA
            let sfx = [ctx.fake_compat_type];
            ctx.hfs0_hash_validity = check_memory_hash_table_with_suffix(
                &file,
                hfs0_header_hash,
                hfs0_offset,
                hfs0_header_size,
                hfs0_header_size,
                Some(&sfx[..]),
                false,
            );
        }
        if ctx.hfs0_hash_validity != Validity::Valid {
            eprintln!("Error: XCI partition is corrupt!");
            process::exit(1);
        }
    }

    let mut blank_ctx = HactoolCtx::new();
    blank_ctx.action = tool_ctx.action & !(ACTION_EXTRACT | ACTION_INFO);

    ctx.partition_ctx.file = Some(file.clone());
    ctx.partition_ctx.offset = hfs0_offset;
    ctx.partition_ctx.name = Some("rootpt".to_string());
    ctx.partition_ctx.hash_suffix = None;
    hfs0_process(&mut ctx.partition_ctx, &mut blank_ctx);

    let num_files = ctx.partition_ctx.num_files();
    if num_files > 4 {
        eprintln!("Error: Invalid XCI partition!");
        process::exit(1);
    }

    for i in 0..num_files {
        let cur_file = ctx.partition_ctx.get_file_entry(i).unwrap();
        let cur_name = ctx.partition_ctx.get_file_name(i);
        let part_ofs = ctx.partition_ctx.offset + ctx.partition_ctx.header_size() + cur_file.offset;

        let cur_ctx = match cur_name.as_str() {
            "update" if ctx.update_ctx.file.is_none() => &mut ctx.update_ctx,
            "normal" if ctx.normal_ctx.file.is_none() => &mut ctx.normal_ctx,
            "secure" if ctx.secure_ctx.file.is_none() => &mut ctx.secure_ctx,
            "logo" if ctx.logo_ctx.file.is_none() => &mut ctx.logo_ctx,
            _ => {
                eprintln!("Unknown XCI partition: {}", cur_name);
                process::exit(1);
            }
        };

        cur_ctx.name = Some(cur_name);
        cur_ctx.offset = part_ofs;
        cur_ctx.file = Some(file.clone());
        cur_ctx.hash_suffix = None;
        hfs0_process(cur_ctx, &mut blank_ctx);
    }

    if (tool_ctx.action & ACTION_INFO) != 0 {
        xci_print(ctx, tool_ctx);
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        xci_save(ctx, tool_ctx);
    }
}

pub fn xci_save(ctx: &XciCtx, tool_ctx: &HactoolCtx) {
    let quiet = tool_ctx.settings.quiet;
    if tool_ctx.settings.out_dir_path.enabled
        && tool_ctx.settings.out_dir_path.path.valid == Validity::Valid
    {
        if !quiet {
            println!("Extracting XCI...");
        }
        let dirpath = &tool_ctx.settings.out_dir_path.path;
        os_makedir(&dirpath.char_path);
        let mut jobs = Vec::new();
        for i in 0..ctx.partition_ctx.num_files() {
            let cur_name = ctx.partition_ctx.get_file_name(i);
            let cur_ctx = match cur_name.as_str() {
                "update" => &ctx.update_ctx,
                "normal" => &ctx.normal_ctx,
                "secure" => &ctx.secure_ctx,
                "logo" => &ctx.logo_ctx,
                _ => {
                    eprintln!("Unknown XCI partition found in extraction: {}", cur_name);
                    process::exit(1);
                }
            };
            let mut partition_dirpath = dirpath.clone();
            partition_dirpath.append(&cur_name);
            os_makedir(&partition_dirpath.char_path);
            hfs0_collect_jobs(cur_ctx, &partition_dirpath, &mut jobs);
        }
        hfs0_execute_jobs(jobs, quiet);
    } else {
        let partitions: [(&Filepath, &str, &Hfs0Ctx); 5] = [
            (
                &tool_ctx.settings.rootpt_dir_path,
                "Saving Root Partition...",
                &ctx.partition_ctx,
            ),
            (
                &tool_ctx.settings.update_dir_path,
                "Saving Update Partition...",
                &ctx.update_ctx,
            ),
            (
                &tool_ctx.settings.normal_dir_path,
                "Saving Normal Partition...",
                &ctx.normal_ctx,
            ),
            (
                &tool_ctx.settings.secure_dir_path,
                "Saving Secure Partition...",
                &ctx.secure_ctx,
            ),
            (
                &tool_ctx.settings.logo_dir_path,
                "Saving Logo Partition...",
                &ctx.logo_ctx,
            ),
        ];
        for (dir, label, part_ctx) in partitions {
            if dir.valid == Validity::Valid {
                if !quiet {
                    println!("{}", label);
                }
                os_makedir(&dir.char_path);
                let mut jobs = Vec::new();
                hfs0_collect_jobs(part_ctx, dir, &mut jobs);
                hfs0_execute_jobs(jobs, quiet);
                if !quiet {
                    println!();
                }
            }
        }
    }
}

fn xci_get_cartridge_type(cart_type: u8) -> &'static str {
    match cart_type {
        0xF8 => "2GB",
        0xF0 => "4GB",
        0xE0 => "8GB",
        0xE1 => "16GB",
        _ => "Unknown/Invalid",
    }
}

fn xci_get_firmware_type(fw_ver: u64) -> &'static str {
    match fw_ver {
        0 => "Development",
        1 => "Retail (1.0.0+)",
        2 => "Retail (4.0.0+)",
        _ => "Unknown",
    }
}

fn xci_get_access_control_type(ac: u32) -> &'static str {
    match ac {
        0x00A10011 => "25MHz",
        0x00A10010 => "50MHz",
        _ => "Unknown/Invalid",
    }
}

fn xci_get_region_compatibility_type_name(compat: u8) -> &'static str {
    match compat {
        0 => "Global",
        1 => "China",
        _ => "Unknown/Invalid",
    }
}

fn xci_print_hfs0(ctx: &Hfs0Ctx, tool_ctx: &HactoolCtx) {
    if ctx.header_bytes.len() < 0x10 {
        return;
    }
    print_magic("    Magic:                          ", ctx.magic());
    println!("    Offset:                         {:012x}", ctx.offset);
    println!(
        "    Number of files:                {}",
        ctx.num_files() as i32
    );

    let num_files = ctx.num_files();
    if num_files > 0 && (num_files < 100 || (tool_ctx.action & ACTION_VERIFY) != 0) {
        print!("    Files:");
        let prefix_name = ctx.name.as_deref().unwrap_or("hfs0");
        for i in 0..num_files {
            let cur_file = ctx.get_file_entry(i).unwrap();
            let file_name = ctx.get_file_name(i);
            let pad = if i == 0 {
                "                          "
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

pub fn xci_print(ctx: &XciCtx, tool_ctx: &HactoolCtx) {
    println!("\nXCI:");
    let magic = read_u32_le(&ctx.header_bytes, 0x100);
    print_magic("Magic:                              ", magic);

    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        if ctx.header_sig_validity == Validity::Valid {
            memdump_stdout(
                "Header Signature (GOOD):            ",
                &ctx.header_bytes[0..0x100],
            );
        } else {
            memdump_stdout(
                "Header Signature (FAIL):            ",
                &ctx.header_bytes[0..0x100],
            );
        }
    } else {
        memdump_stdout(
            "Header Signature:                   ",
            &ctx.header_bytes[0..0x100],
        );
    }

    let cart_type = ctx.header_bytes[0x10D];
    let cart_size = read_u64_le(&ctx.header_bytes, 0x118);
    println!(
        "Cartridge Type:                     {}",
        xci_get_cartridge_type(cart_type)
    );
    println!(
        "Cartridge Size:                     {:012x}",
        media_to_real((cart_size + 1) as u32 as u64)
    );

    memdump_stdout("Header IV:                          ", &ctx.iv);
    memdump_stdout(
        "Encrypted Header:                   ",
        &ctx.header_bytes[0x190..0x200],
    );

    if ctx.has_fake_compat_type || !ctx.has_decrypted_header {
        println!("Encrypted Header Data:");
        println!(
            "    Compatibility Type:             {}",
            xci_get_region_compatibility_type_name(ctx.fake_compat_type)
        );
    }

    if ctx.has_decrypted_header {
        let gc = &ctx.decrypted_header[0x10..];
        let fw_ver = read_u64_le(gc, 0);
        let access_ctrl = read_u32_le(gc, 8);
        let rt_wait1 = read_u32_le(gc, 12);
        let rt_wait2 = read_u32_le(gc, 16);
        let wt_wait1 = read_u32_le(gc, 20);
        let wt_wait2 = read_u32_le(gc, 24);
        let fw_mode = read_u32_le(gc, 28);
        let cup_ver = read_u32_le(gc, 32);
        let compat_type = gc[36];
        let upd_hash = &gc[40..48];
        let cup_tid = read_u64_le(gc, 48);

        println!("Encrypted Header Data:");
        println!(
            "    Firmware Version:               {}",
            xci_get_firmware_type(fw_ver)
        );
        println!(
            "    Access Control:                 {}",
            xci_get_access_control_type(access_ctrl)
        );
        println!("    Read Time Wait1:                {:08x}", rt_wait1);
        println!("    Read Time Wait2:                {:08x}", rt_wait2);
        println!("    Write Time Wait1:               {:08x}", wt_wait1);
        println!("    Write Time Wait2:               {:08x}", wt_wait2);
        println!("    Firmware Mode:                  {:08x}", fw_mode);

        let v0 = (cup_ver >> 26) & 0x3f;
        let v1 = (cup_ver >> 20) & 0x3f;
        let v2 = (cup_ver >> 16) & 0xf;
        let v3 = cup_ver & 0xffff;
        println!(
            "    CUP Version                     v{}.{}.{}-{}",
            v0, v1, v2, v3
        );
        println!(
            "    Compatibility Type:             {}",
            xci_get_region_compatibility_type_name(compat_type)
        );
        memdump_stdout("    Update Hash                     ", upd_hash);
        println!("    CUP TitleId:                    {:016x}", cup_tid);
    }

    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        println!("Root Partition ({}):", ctx.hfs0_hash_validity.as_str());
    } else {
        println!("Root Partition:");
    }
    xci_print_hfs0(&ctx.partition_ctx, tool_ctx);

    println!("Update Partition:");
    xci_print_hfs0(&ctx.update_ctx, tool_ctx);

    println!("Normal Partition:");
    xci_print_hfs0(&ctx.normal_ctx, tool_ctx);

    println!("Secure Partition:");
    xci_print_hfs0(&ctx.secure_ctx, tool_ctx);

    if ctx.partition_ctx.num_files() == 4 {
        println!("Logo Partition:");
        xci_print_hfs0(&ctx.logo_ctx, tool_ctx);
    }
}

