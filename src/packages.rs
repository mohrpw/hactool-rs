use crate::aes::{AesCtx, AesMode};
use crate::kip::{
    ini1_print, ini1_save, kip1_get_size_from_header, Ini1Ctx, Ini1Header, Kip1Ctx, Kip1Header,
    INI1_HEADER_SIZE, INI1_MAX_KIPS, KIP1_HEADER_SIZE,
};
use crate::rsa::rsa2048_pss_verify;
use crate::settings::HactoolCtx;
use crate::sha::sha256_hash_buffer;
use crate::types::{
    read_u16_le, read_u32_le, read_u64_le, FileType, Filepath, SharedFile, Validity,
    ACTION_EXTRACT, ACTION_EXTRACTINI1, ACTION_INFO, ACTION_VERIFY, MAGIC_INI1, MAGIC_KIP1,
    MAGIC_PK11, MAGIC_PK21,
};
use crate::utils::{
    align64, get_key_revision_summary, memdump_stdout, os_makedir, save_buffer_to_directory_file,
};
use std::process;

pub const PK11_MARIKO_OEM_HEADER_SIZE: usize = 0x170;
pub const PK11_METADATA_SIZE: usize = 0x20;
pub const PK11_LEGACY_STAGE1_SIZE: usize = 0x3FE0;
pub const PK11_MODERN_STAGE1_SIZE: usize = 0x6FE0;
pub const PK11_HEADER_SIZE: usize = 0x20;
pub const PK21_HEADER_SIZE: usize = 0x200;

#[derive(Clone, Debug)]
pub struct Pk11MarikoOemHeader {
    pub aes_mac: [u8; 0x10],
    pub rsa_sig: [u8; 0x100],
    pub salt: [u8; 0x20],
    pub hash: [u8; 0x20],
    pub bl_version: u32,
    pub bl_size: u32,
    pub bl_load_addr: u32,
    pub bl_entrypoint: u32,
    pub _0x160: [u8; 0x10],
    pub raw_bytes: [u8; PK11_MARIKO_OEM_HEADER_SIZE],
}

impl Default for Pk11MarikoOemHeader {
    fn default() -> Self {
        Self {
            aes_mac: [0u8; 0x10],
            rsa_sig: [0u8; 0x100],
            salt: [0u8; 0x20],
            hash: [0u8; 0x20],
            bl_version: 0,
            bl_size: 0,
            bl_load_addr: 0,
            bl_entrypoint: 0,
            _0x160: [0u8; 0x10],
            raw_bytes: [0u8; PK11_MARIKO_OEM_HEADER_SIZE],
        }
    }
}

impl Pk11MarikoOemHeader {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut h = Self::default();
        if data.len() < PK11_MARIKO_OEM_HEADER_SIZE {
            return h;
        }
        h.raw_bytes.copy_from_slice(&data[..PK11_MARIKO_OEM_HEADER_SIZE]);
        h.aes_mac.copy_from_slice(&data[0x00..0x10]);
        h.rsa_sig.copy_from_slice(&data[0x10..0x110]);
        h.salt.copy_from_slice(&data[0x110..0x130]);
        h.hash.copy_from_slice(&data[0x130..0x150]);
        h.bl_version = read_u32_le(data, 0x150);
        h.bl_size = read_u32_le(data, 0x154);
        h.bl_load_addr = read_u32_le(data, 0x158);
        h.bl_entrypoint = read_u32_le(data, 0x15C);
        h._0x160.copy_from_slice(&data[0x160..0x170]);
        h
    }
}

#[derive(Clone, Debug, Default)]
pub struct Pk11Metadata {
    pub ldr_hash: u32,
    pub sm_hash: u32,
    pub bl_hash: u32,
    pub _0xc: u32,
    pub build_date: [u8; 0xE],
    pub _0x1e: u8,
    pub version: u8,
    pub raw_bytes: [u8; PK11_METADATA_SIZE],
}

impl Pk11Metadata {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut m = Self::default();
        if data.len() < PK11_METADATA_SIZE {
            return m;
        }
        m.raw_bytes.copy_from_slice(&data[..PK11_METADATA_SIZE]);
        m.ldr_hash = read_u32_le(data, 0x0);
        m.sm_hash = read_u32_le(data, 0x4);
        m.bl_hash = read_u32_le(data, 0x8);
        m._0xc = read_u32_le(data, 0xC);
        m.build_date.copy_from_slice(&data[0x10..0x1E]);
        m._0x1e = data[0x1E];
        m.version = data[0x1F];
        m
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Pk11Header {
    pub magic: u32,
    pub wb_size: u32,
    pub wb_ep: u32,
    pub _0xc: u32,
    pub bl_size: u32,
    pub bl_ep: u32,
    pub sm_size: u32,
    pub sm_ep: u32,
}

impl Pk11Header {
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < PK11_HEADER_SIZE {
            return Self::default();
        }
        Self {
            magic: read_u32_le(data, 0x00),
            wb_size: read_u32_le(data, 0x04),
            wb_ep: read_u32_le(data, 0x08),
            _0xc: read_u32_le(data, 0x0C),
            bl_size: read_u32_le(data, 0x10),
            bl_ep: read_u32_le(data, 0x14),
            sm_size: read_u32_le(data, 0x18),
            sm_ep: read_u32_le(data, 0x1C),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pk11SectionId {
    Bl,
    Sm,
    Wb,
}

#[derive(Clone)]
pub struct Pk11Ctx {
    pub file: Option<SharedFile>,
    pub is_modern: bool,
    pub is_mariko: bool,
    pub is_decrypted: bool,
    pub key_rev: usize,
    pub mariko_oem_header: Pk11MarikoOemHeader,
    pub metadata: Pk11Metadata,
    pub stage1_bytes: [u8; PK11_MODERN_STAGE1_SIZE],
    pub pk11_size: u32,
    pub mariko_bl: Vec<u8>,
    pub pk11_bytes: Vec<u8>,
    pub pk11_hdr: Pk11Header,
    pub pk11_mac: [u8; 0x10],
}

impl Default for Pk11Ctx {
    fn default() -> Self {
        Self {
            file: None,
            is_modern: false,
            is_mariko: false,
            is_decrypted: false,
            key_rev: 0,
            mariko_oem_header: Pk11MarikoOemHeader::default(),
            metadata: Pk11Metadata::default(),
            stage1_bytes: [0u8; PK11_MODERN_STAGE1_SIZE],
            pk11_size: 0,
            mariko_bl: Vec::new(),
            pk11_bytes: Vec::new(),
            pk11_hdr: Pk11Header::default(),
            pk11_mac: [0u8; 0x10],
        }
    }
}

impl Pk11Ctx {
    pub fn get_section_idx(&self, section_id: Pk11SectionId) -> usize {
        if self.metadata.version >= 0x07 {
            match section_id {
                Pk11SectionId::Bl => 0,
                Pk11SectionId::Sm => 1,
                Pk11SectionId::Wb => 2,
            }
        } else if self.metadata.version >= 0x02 {
            match section_id {
                Pk11SectionId::Bl => 1,
                Pk11SectionId::Sm => 2,
                Pk11SectionId::Wb => 0,
            }
        } else {
            match section_id {
                Pk11SectionId::Bl => 1,
                Pk11SectionId::Sm => 0,
                Pk11SectionId::Wb => 2,
            }
        }
    }

    pub fn get_section_id(&self, id: usize) -> Pk11SectionId {
        if self.get_section_idx(Pk11SectionId::Bl) == id {
            Pk11SectionId::Bl
        } else if self.get_section_idx(Pk11SectionId::Sm) == id {
            Pk11SectionId::Sm
        } else {
            Pk11SectionId::Wb
        }
    }

    pub fn get_section_size(&self, section_id: Pk11SectionId) -> u32 {
        match section_id {
            Pk11SectionId::Bl => self.pk11_hdr.bl_size,
            Pk11SectionId::Sm => self.pk11_hdr.sm_size,
            Pk11SectionId::Wb => self.pk11_hdr.wb_size,
        }
    }

    pub fn get_section_ofs(&self, section_id: Pk11SectionId) -> u32 {
        match self.get_section_idx(section_id) {
            0 => 0,
            1 => self.get_section_size(self.get_section_id(0)),
            2 => {
                self.get_section_size(self.get_section_id(0))
                    + self.get_section_size(self.get_section_id(1))
            }
            _ => 0,
        }
    }

    pub fn get_section(&self, section_id: Pk11SectionId) -> &[u8] {
        let ofs = PK11_HEADER_SIZE + self.get_section_ofs(section_id) as usize;
        let sz = self.get_section_size(section_id) as usize;
        &self.pk11_bytes[ofs..ofs + sz]
    }
}

fn pk11_is_mariko(ctx: &mut Pk11Ctx, file: &SharedFile) -> bool {
    let mut oem_buf = [0u8; PK11_MARIKO_OEM_HEADER_SIZE];
    if file.read_exact_at(0, &mut oem_buf).is_err() {
        eprintln!("Failed to read PK11 OEM Header!");
        process::exit(1);
    }
    ctx.mariko_oem_header = Pk11MarikoOemHeader::from_bytes(&oem_buf);
    for i in 0..0x10 {
        if ctx.mariko_oem_header.aes_mac[i] != 0 || ctx.mariko_oem_header._0x160[i] != 0 {
            return false;
        }
    }
    true
}

fn pk11_is_legacy(ctx: &Pk11Ctx) -> bool {
    ctx.metadata.version < 0x0E || &ctx.metadata.build_date[..8] < b"20181107"
}

pub fn pk11_process(ctx: &mut Pk11Ctx, tool_ctx: &HactoolCtx) {
    let file = match &ctx.file {
        Some(f) => f.clone(),
        None => {
            eprintln!("Failed to read PK11 Stage 1!");
            process::exit(1);
        }
    };

    if file.read_exact_at(0, &mut ctx.stage1_bytes).is_err() {
        eprintln!("Failed to read PK11 Stage 1!");
        process::exit(1);
    }

    ctx.is_mariko = pk11_is_mariko(ctx, &file);

    let mut file_pos: u64;
    if ctx.is_mariko {
        file_pos = PK11_MARIKO_OEM_HEADER_SIZE as u64;
        if (ctx.mariko_oem_header.bl_size as usize) < PK11_METADATA_SIZE {
            eprintln!("PK11 seems corrupt!");
            process::exit(1);
        }

        ctx.mariko_bl = vec![0u8; ctx.mariko_oem_header.bl_size as usize];
        if file.read_exact_at(file_pos, &mut ctx.mariko_bl).is_err() {
            eprintln!("Failed to read Mariko PK11!");
            process::exit(1);
        }

        ctx.metadata = Pk11Metadata::from_bytes(&ctx.mariko_bl[..PK11_METADATA_SIZE]);
        ctx.is_decrypted = ctx.mariko_bl.len() >= 0x40
            && ctx.metadata.raw_bytes == ctx.mariko_bl[0x20..0x40];

        if !ctx.is_decrypted {
            let enc_size = ctx.mariko_oem_header.bl_size as usize - PK11_METADATA_SIZE;
            if enc_size > 0 {
                let mut iv = [0u8; 0x10];
                iv.copy_from_slice(&ctx.mariko_bl[0x10..0x20]);
                let mut crypt_ctx =
                    AesCtx::new(&tool_ctx.settings.keyset.mariko_bek, 16, AesMode::CbcDec);
                crypt_ctx.set_iv(&iv);
                let mut dec = vec![0u8; enc_size];
                crypt_ctx.decrypt(&ctx.mariko_bl[0x20..0x20 + enc_size], &mut dec);
                ctx.mariko_bl[0x20..0x20 + enc_size].copy_from_slice(&dec);

                ctx.is_decrypted = ctx.mariko_bl.len() >= 0x40
                    && ctx.metadata.raw_bytes == ctx.mariko_bl[0x20..0x40];
            }
        }
    } else {
        let mut meta_buf = [0u8; PK11_METADATA_SIZE];
        if file.read_exact_at(0, &mut meta_buf).is_err() {
            eprintln!("Failed to read PK11 Metadata!");
            process::exit(1);
        }
        ctx.metadata = Pk11Metadata::from_bytes(&meta_buf);
        file_pos = PK11_METADATA_SIZE as u64;
    }

    ctx.is_modern = !pk11_is_legacy(ctx);

    if ctx.is_mariko {
        if ctx.is_decrypted {
            if ctx.is_modern {
                ctx.stage1_bytes[..PK11_MODERN_STAGE1_SIZE]
                    .copy_from_slice(&ctx.mariko_bl[0x20..0x20 + PK11_MODERN_STAGE1_SIZE]);
                ctx.pk11_size = read_u32_le(&ctx.stage1_bytes, 0x6FC0);
            } else {
                ctx.stage1_bytes[..PK11_LEGACY_STAGE1_SIZE]
                    .copy_from_slice(&ctx.mariko_bl[0x20..0x20 + PK11_LEGACY_STAGE1_SIZE]);
                ctx.pk11_size = read_u32_le(&ctx.stage1_bytes, 0x3FC0);
            }
        } else if ctx.is_modern {
            ctx.pk11_size =
                ctx.mariko_oem_header.bl_size - 0x20 - PK11_MODERN_STAGE1_SIZE as u32;
        } else {
            ctx.pk11_size =
                ctx.mariko_oem_header.bl_size - 0x20 - PK11_LEGACY_STAGE1_SIZE as u32;
        }
    } else if ctx.is_modern {
        if file
            .read_exact_at(file_pos, &mut ctx.stage1_bytes[..PK11_MODERN_STAGE1_SIZE])
            .is_err()
        {
            eprintln!("Failed to read PK11 Stage1!");
            process::exit(1);
        }
        file_pos += PK11_MODERN_STAGE1_SIZE as u64;
        ctx.pk11_size = read_u32_le(&ctx.stage1_bytes, 0x6FC0);
    } else {
        if file
            .read_exact_at(file_pos, &mut ctx.stage1_bytes[..PK11_LEGACY_STAGE1_SIZE])
            .is_err()
        {
            eprintln!("Failed to read PK11 Stage1!");
            process::exit(1);
        }
        file_pos += PK11_LEGACY_STAGE1_SIZE as u64;
        ctx.pk11_size = read_u32_le(&ctx.stage1_bytes, 0x3FC0);
    }

    ctx.pk11_bytes = vec![0u8; ctx.pk11_size as usize];

    if ctx.is_mariko {
        let stage1_sz = if ctx.is_modern {
            PK11_MODERN_STAGE1_SIZE
        } else {
            PK11_LEGACY_STAGE1_SIZE
        };
        ctx.pk11_bytes.copy_from_slice(
            &ctx.mariko_bl[0x20 + stage1_sz..0x20 + stage1_sz + ctx.pk11_size as usize],
        );
    } else {
        if file.read_exact_at(file_pos, &mut ctx.pk11_bytes).is_err() {
            eprintln!("Failed to read PK11!");
            process::exit(1);
        }
        file_pos += ctx.pk11_size as u64;
        if ctx.is_modern {
            if file.read_exact_at(file_pos, &mut ctx.pk11_mac).is_err() {
                eprintln!("Failed to read PK11 MAC!");
                process::exit(1);
            }
        }
    }

    ctx.pk11_hdr = Pk11Header::from_bytes(&ctx.pk11_bytes);
    ctx.is_decrypted = ctx.pk11_hdr.magic == MAGIC_PK11;

    if !ctx.is_mariko && !ctx.is_decrypted {
        if ctx.is_modern {
            let mut iv = [0u8; 0x10];
            iv.copy_from_slice(&ctx.stage1_bytes[0x6FD0..0x6FE0]);
            for i in 6..0x20 {
                if ctx.is_decrypted {
                    break;
                }
                ctx.key_rev = i;
                let mut crypt_ctx = AesCtx::new(
                    &tool_ctx.settings.keyset.package1_keys[i],
                    16,
                    AesMode::CbcDec,
                );
                crypt_ctx.set_iv(&iv);
                let mut dec_hdr_bytes = [0u8; PK11_HEADER_SIZE];
                crypt_ctx.decrypt(&ctx.pk11_bytes[..PK11_HEADER_SIZE], &mut dec_hdr_bytes);
                if read_u32_le(&dec_hdr_bytes, 0) == MAGIC_PK11 {
                    crypt_ctx.set_iv(&iv);
                    let mut dec_all = vec![0u8; ctx.pk11_bytes.len()];
                    crypt_ctx.decrypt(&ctx.pk11_bytes, &mut dec_all);
                    ctx.pk11_bytes = dec_all;
                    ctx.pk11_hdr = Pk11Header::from_bytes(&ctx.pk11_bytes);
                    ctx.is_decrypted = true;
                }
            }
        } else {
            let mut ctr = [0u8; 0x10];
            ctr.copy_from_slice(&ctx.stage1_bytes[0x3FD0..0x3FE0]);
            for i in 0..6 {
                if ctx.is_decrypted {
                    break;
                }
                ctx.key_rev = i;
                let mut crypt_ctx = AesCtx::new(
                    &tool_ctx.settings.keyset.package1_keys[i],
                    16,
                    AesMode::Ctr,
                );
                crypt_ctx.set_iv(&ctr);
                let mut dec_hdr_bytes = [0u8; PK11_HEADER_SIZE];
                crypt_ctx.decrypt(&ctx.pk11_bytes[..PK11_HEADER_SIZE], &mut dec_hdr_bytes);
                if read_u32_le(&dec_hdr_bytes, 0) == MAGIC_PK11 {
                    crypt_ctx.set_iv(&ctr);
                    let mut dec_all = vec![0u8; ctx.pk11_bytes.len()];
                    crypt_ctx.decrypt(&ctx.pk11_bytes, &mut dec_all);
                    ctx.pk11_bytes = dec_all;
                    ctx.pk11_hdr = Pk11Header::from_bytes(&ctx.pk11_bytes);
                    ctx.is_decrypted = true;
                }
            }
        }
    }

    if ctx.is_decrypted {
        let calc_size = 0x20u64
            + ctx.get_section_size(Pk11SectionId::Wb) as u64
            + ctx.get_section_size(Pk11SectionId::Bl) as u64
            + ctx.get_section_size(Pk11SectionId::Sm) as u64;
        let calc_size = align64(calc_size, 0x10);
        if calc_size != ctx.pk11_size as u64 {
            eprintln!("PK11 seems corrupt!");
            process::exit(1);
        }
    }

    if (tool_ctx.action & ACTION_INFO) != 0 {
        pk11_print(ctx);
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        pk11_save(ctx, tool_ctx);
    }
}

pub fn pk11_print(ctx: &Pk11Ctx) {
    if ctx.is_mariko {
        println!("Mariko OEM Header:");
        memdump_stdout(
            "    Signature:                      ",
            &ctx.mariko_oem_header.rsa_sig,
        );
        memdump_stdout(
            "    Random Salt:                    ",
            &ctx.mariko_oem_header.salt,
        );
        memdump_stdout(
            "    OEM Bootloader Hash:            ",
            &ctx.mariko_oem_header.hash,
        );
        println!(
            "    OEM Bootloader Version:         {:02x}",
            ctx.mariko_oem_header.bl_version
        );
        println!(
            "    OEM Bootloader Size:            {:08x}",
            ctx.mariko_oem_header.bl_size
        );
        println!(
            "    OEM Bootloader Load Address:    {:08x}",
            ctx.mariko_oem_header.bl_load_addr
        );
        println!(
            "    OEM Bootloader Entrypoint:      {:08x}",
            ctx.mariko_oem_header.bl_entrypoint
        );
    }
    println!("Package1 Metadata:");
    let bd_len = ctx
        .metadata
        .build_date
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(ctx.metadata.build_date.len());
    let build_date = String::from_utf8_lossy(&ctx.metadata.build_date[..bd_len]);
    println!("    Build Date:                     {}", build_date);
    memdump_stdout(
        "    Package1ldr Hash:               ",
        &ctx.metadata.ldr_hash.to_le_bytes(),
    );
    memdump_stdout(
        "    Secure Monitor Hash:            ",
        &ctx.metadata.sm_hash.to_le_bytes(),
    );
    memdump_stdout(
        "    NX Bootloader Hash:             ",
        &ctx.metadata.bl_hash.to_le_bytes(),
    );
    println!(
        "    Version:                        {:02x}",
        ctx.metadata.version
    );
    if ctx.is_decrypted {
        println!("PK11:");
        if !ctx.is_mariko {
            println!(
                "    Key Revision:                   {:02x} ({})",
                ctx.key_rev,
                get_key_revision_summary(ctx.key_rev as u8)
            );
        }
        println!(
            "    PK11 Size:                      {:08x}",
            ctx.pk11_size
        );
        println!(
            "    Warmboot.bin Size:              {:08x}",
            ctx.get_section_size(Pk11SectionId::Wb)
        );
        println!(
            "    NX_Bootloader.bin Size          {:08x}",
            ctx.get_section_size(Pk11SectionId::Bl)
        );
        println!(
            "    Secure_Monitor.bin Size:        {:08x}",
            ctx.get_section_size(Pk11SectionId::Sm)
        );
    }
    println!();
}

pub fn pk11_save(ctx: &Pk11Ctx, tool_ctx: &HactoolCtx) {
    let mut dirpath: Option<&Filepath> = None;
    if tool_ctx.file_type == FileType::Package1 && tool_ctx.settings.out_dir_path.enabled {
        dirpath = Some(&tool_ctx.settings.out_dir_path.path);
    }
    if dirpath.is_none() || dirpath.unwrap().valid != Validity::Valid {
        dirpath = Some(&tool_ctx.settings.pk11_dir_path);
    }
    if let Some(dp) = dirpath {
        if dp.valid == Validity::Valid && ctx.is_decrypted {
            let _ = os_makedir(&dp.char_path);
            let quiet = tool_ctx.settings.quiet;

            if !quiet {
                println!("Saving decrypted binary to {}/Decrypted.bin", dp.char_path);
            }
            if ctx.is_mariko {
                let mut decrypted_bin =
                    Vec::with_capacity(PK11_MARIKO_OEM_HEADER_SIZE + ctx.mariko_bl.len());
                decrypted_bin.extend_from_slice(&ctx.mariko_oem_header.raw_bytes);
                decrypted_bin.extend_from_slice(&ctx.mariko_bl);
                save_buffer_to_directory_file(&decrypted_bin, dp, "Decrypted.bin");
            } else {
                let mut decrypted_bin =
                    Vec::with_capacity(PK11_MODERN_STAGE1_SIZE + ctx.pk11_bytes.len());
                decrypted_bin.extend_from_slice(&ctx.stage1_bytes);
                decrypted_bin.extend_from_slice(&ctx.pk11_bytes);
                save_buffer_to_directory_file(&decrypted_bin, dp, "Decrypted.bin");
            }

            if ctx.is_mariko {
                if !quiet {
                    println!(
                        "Saving Mariko_OEM_Bootloader.bin to {}/Mariko_OEM_Bootloader.bin...",
                        dp.char_path
                    );
                }
                save_buffer_to_directory_file(&ctx.mariko_bl, dp, "Mariko_OEM_Bootloader.bin");
            }

            if !quiet {
                println!("Saving Warmboot.bin to {}/Warmboot.bin...", dp.char_path);
            }
            let wb_data = ctx.get_section(Pk11SectionId::Wb);
            save_buffer_to_directory_file(wb_data, dp, "Warmboot.bin");

            if ctx.is_mariko {
                let mut wb_dec = wb_data.to_vec();
                if wb_dec.len() > 0x330 {
                    let mut crypt_ctx =
                        AesCtx::new(&tool_ctx.settings.keyset.mariko_bek, 16, AesMode::CbcDec);
                    crypt_ctx.set_iv(&[0u8; 0x10]);
                    let mut dec_tail = vec![0u8; wb_dec.len() - 0x330];
                    crypt_ctx.decrypt(&wb_dec[0x330..], &mut dec_tail);
                    wb_dec[0x330..].copy_from_slice(&dec_tail);
                }
                if !quiet {
                    println!(
                        "Saving Warmboot_Decrypted.bin to {}/Warmboot_Decrypted.bin...",
                        dp.char_path
                    );
                }
                save_buffer_to_directory_file(&wb_dec, dp, "Warmboot_Decrypted.bin");
            }

            if !quiet {
                println!(
                    "Saving NX_Bootloader.bin to {}/NX_Bootloader.bin...",
                    dp.char_path
                );
            }
            save_buffer_to_directory_file(
                ctx.get_section(Pk11SectionId::Bl),
                dp,
                "NX_Bootloader.bin",
            );

            if !quiet {
                println!(
                    "Saving Secure_Monitor.bin to {}/Secure_Monitor.bin...",
                    dp.char_path
                );
            }
            save_buffer_to_directory_file(
                ctx.get_section(Pk11SectionId::Sm),
                dp,
                "Secure_Monitor.bin",
            );
        }
    }
}

/* Package2 */

#[derive(Clone, Debug)]
pub struct Pk21Header {
    pub signature: [u8; 0x100],
    pub ctr: [u8; 0x10],
    pub ctr_dwords: [u32; 4],
    pub section_ctrs: [[u8; 0x10]; 4],
    pub magic: u32,
    pub base_offset: u32,
    pub _0x58: u32,
    pub version_max: u8,
    pub version_min: u8,
    pub _0x5e: u16,
    pub section_sizes: [u32; 4],
    pub section_offsets: [u32; 4],
    pub section_hashes: [[u8; 0x20]; 4],
    pub raw_bytes: [u8; PK21_HEADER_SIZE],
}

impl Default for Pk21Header {
    fn default() -> Self {
        Self {
            signature: [0u8; 0x100],
            ctr: [0u8; 0x10],
            ctr_dwords: [0u32; 4],
            section_ctrs: [[0u8; 0x10]; 4],
            magic: 0,
            base_offset: 0,
            _0x58: 0,
            version_max: 0,
            version_min: 0,
            _0x5e: 0,
            section_sizes: [0u32; 4],
            section_offsets: [0u32; 4],
            section_hashes: [[0u8; 0x20]; 4],
            raw_bytes: [0u8; PK21_HEADER_SIZE],
        }
    }
}

impl Pk21Header {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut h = Self::default();
        if data.len() < PK21_HEADER_SIZE {
            return h;
        }
        h.raw_bytes.copy_from_slice(&data[..PK21_HEADER_SIZE]);
        h.signature.copy_from_slice(&data[0x000..0x100]);
        h.ctr.copy_from_slice(&data[0x100..0x110]);
        for i in 0..4 {
            h.ctr_dwords[i] = read_u32_le(data, 0x100 + i * 4);
        }
        for i in 0..4 {
            h.section_ctrs[i].copy_from_slice(&data[0x110 + i * 0x10..0x120 + i * 0x10]);
        }
        h.magic = read_u32_le(data, 0x150);
        h.base_offset = read_u32_le(data, 0x154);
        h._0x58 = read_u32_le(data, 0x158);
        h.version_max = data[0x15C];
        h.version_min = data[0x15D];
        h._0x5e = read_u16_le(data, 0x15E);
        for i in 0..4 {
            h.section_sizes[i] = read_u32_le(data, 0x160 + i * 4);
            h.section_offsets[i] = read_u32_le(data, 0x170 + i * 4);
        }
        for i in 0..4 {
            h.section_hashes[i].copy_from_slice(&data[0x180 + i * 0x20..0x1A0 + i * 0x20]);
        }
        h
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KernelMap {
    pub text_start_offset: u32,
    pub text_end_offset: u32,
    pub rodata_start_offset: u32,
    pub rodata_end_offset: u32,
    pub data_start_offset: u32,
    pub data_end_offset: u32,
    pub bss_start_offset: u32,
    pub bss_end_offset: u32,
    pub ini1_start_offset: u32,
    pub dynamic_offset: u32,
    pub init_array_start_offset: u32,
    pub init_array_end_offset: u32,
    pub system_registers_offset: u32,
}

impl KernelMap {
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < 13 * 4 {
            return Self::default();
        }
        Self {
            text_start_offset: read_u32_le(data, 0x00),
            text_end_offset: read_u32_le(data, 0x04),
            rodata_start_offset: read_u32_le(data, 0x08),
            rodata_end_offset: read_u32_le(data, 0x0C),
            data_start_offset: read_u32_le(data, 0x10),
            data_end_offset: read_u32_le(data, 0x14),
            bss_start_offset: read_u32_le(data, 0x18),
            bss_end_offset: read_u32_le(data, 0x1C),
            ini1_start_offset: read_u32_le(data, 0x20),
            dynamic_offset: read_u32_le(data, 0x24),
            init_array_start_offset: read_u32_le(data, 0x28),
            init_array_end_offset: read_u32_le(data, 0x2C),
            system_registers_offset: read_u32_le(data, 0x30),
        }
    }

    pub fn add_offset(&mut self, adj: u32) {
        self.text_start_offset = self.text_start_offset.wrapping_add(adj);
        self.text_end_offset = self.text_end_offset.wrapping_add(adj);
        self.rodata_start_offset = self.rodata_start_offset.wrapping_add(adj);
        self.rodata_end_offset = self.rodata_end_offset.wrapping_add(adj);
        self.data_start_offset = self.data_start_offset.wrapping_add(adj);
        self.data_end_offset = self.data_end_offset.wrapping_add(adj);
        self.bss_start_offset = self.bss_start_offset.wrapping_add(adj);
        self.bss_end_offset = self.bss_end_offset.wrapping_add(adj);
        self.ini1_start_offset = self.ini1_start_offset.wrapping_add(adj);
        self.dynamic_offset = self.dynamic_offset.wrapping_add(adj);
        self.init_array_start_offset = self.init_array_start_offset.wrapping_add(adj);
        self.init_array_end_offset = self.init_array_end_offset.wrapping_add(adj);
    }
}

fn pk21_is_valid_kernel_map(raw_map: &KernelMap, max_size: u32, adj: u32) -> bool {
    let mut map = *raw_map;
    map.add_offset(adj);
    if map.text_start_offset != 0 {
        return false;
    }
    if map.text_start_offset >= map.text_end_offset {
        return false;
    }
    if (map.text_end_offset & 0xFFF) != 0 {
        return false;
    }
    if map.text_end_offset > map.rodata_start_offset {
        return false;
    }
    if (map.rodata_start_offset & 0xFFF) != 0 {
        return false;
    }
    if map.rodata_start_offset >= map.rodata_end_offset {
        return false;
    }
    if (map.rodata_end_offset & 0xFFF) != 0 {
        return false;
    }
    if map.rodata_end_offset > map.data_start_offset {
        return false;
    }
    if (map.data_start_offset & 0xFFF) != 0 {
        return false;
    }
    if map.data_start_offset >= map.data_end_offset {
        return false;
    }
    if map.data_end_offset > map.bss_start_offset {
        return false;
    }
    if map.bss_start_offset > map.bss_end_offset {
        return false;
    }
    if map.bss_end_offset > map.ini1_start_offset {
        return false;
    }
    if map.ini1_start_offset > max_size.saturating_sub(INI1_HEADER_SIZE as u32) {
        return false;
    }
    true
}

#[derive(Clone, Default)]
pub struct Pk21Ctx {
    pub file: Option<SharedFile>,
    pub key_rev: usize,
    pub package_size: u32,
    pub signature_validity: Validity,
    pub section_validities: [Validity; 4],
    pub sections: Vec<u8>,
    pub header: Pk21Header,
    pub ini1_ctx: Ini1Ctx,
    pub kernel_map: Option<KernelMap>,
}

pub fn pk21_process(ctx: &mut Pk21Ctx, tool_ctx: &mut HactoolCtx) {
    let file = match &ctx.file {
        Some(f) => f.clone(),
        None => {
            eprintln!("Failed to read PK21 Header!");
            process::exit(1);
        }
    };

    let mut hdr_buf = [0u8; PK21_HEADER_SIZE];
    if file.read_exact_at(0, &mut hdr_buf).is_err() {
        eprintln!("Failed to read PK21 Header!");
        process::exit(1);
    }
    ctx.header = Pk21Header::from_bytes(&hdr_buf);

    let is_encrypted = ctx.header.signature.iter().any(|&b| b != 0)
        && ctx.header.magic != MAGIC_PK21;

    if is_encrypted {
        if rsa2048_pss_verify(
            &ctx.header.raw_bytes[0x100..0x200],
            &ctx.header.signature,
            &tool_ctx.settings.keyset.package2_fixed_key_modulus,
        ) {
            ctx.signature_validity = Validity::Valid;
        } else {
            ctx.signature_validity = Validity::Invalid;
        }
    } else {
        ctx.signature_validity = Validity::Unchecked;
    }

    ctx.package_size =
        ctx.header.ctr_dwords[0] ^ ctx.header.ctr_dwords[2] ^ ctx.header.ctr_dwords[3];
    if ctx.package_size > 0x7FC000 || ctx.package_size < 0x200 {
        eprintln!("Error: Package2 Header is corrupt!");
        process::exit(1);
    }

    let mut crypt_ctx: Option<AesCtx> = None;
    if is_encrypted {
        let ctr = ctx.header.ctr;
        for i in 0..0x20 {
            ctx.key_rev = i;
            let mut temp_buf = ctx.header.raw_bytes;
            let mut aes = AesCtx::new(
                &tool_ctx.settings.keyset.package2_keys[i],
                16,
                AesMode::Ctr,
            );
            aes.set_iv(&ctr);
            let mut dec_part = [0u8; 0x100];
            aes.decrypt(&temp_buf[0x100..0x200], &mut dec_part);
            temp_buf[0x100..0x200].copy_from_slice(&dec_part);
            temp_buf[0x100..0x110].copy_from_slice(&ctr);
            let temp_hdr = Pk21Header::from_bytes(&temp_buf);
            if temp_hdr.magic == MAGIC_PK21 {
                ctx.header = temp_hdr;
                crypt_ctx = Some(aes);
                break;
            }
        }

        if crypt_ctx.is_none() {
            eprintln!("Failed to decrypt PK21! Is correct key present?");
            process::exit(1);
        }
    }

    if ctx.package_size
        != 0x200
            + ctx.header.section_sizes[0]
            + ctx.header.section_sizes[1]
            + ctx.header.section_sizes[2]
    {
        eprintln!("Error: Package2 Header is corrupt!");
        process::exit(1);
    }

    let sections_len = (ctx.package_size - 0x200) as usize;
    ctx.sections = vec![0u8; sections_len];
    if file.read_exact_at(0x200, &mut ctx.sections).is_err() {
        eprintln!("Failed to read PK21 Sections!");
        process::exit(1);
    }

    let mut offset = 0usize;
    for i in 0..3 {
        let sec_sz = ctx.header.section_sizes[i] as usize;
        let mut calc_hash = [0u8; 0x20];
        sha256_hash_buffer(&mut calc_hash, &ctx.sections[offset..offset + sec_sz]);
        if calc_hash == ctx.header.section_hashes[i] {
            ctx.section_validities[i] = Validity::Valid;
        } else {
            ctx.section_validities[i] = Validity::Invalid;
        }
        if let Some(ref mut aes) = crypt_ctx {
            aes.set_iv(&ctx.header.section_ctrs[i]);
            let mut dec_sec = vec![0u8; sec_sz];
            aes.decrypt(&ctx.sections[offset..offset + sec_sz], &mut dec_sec);
            ctx.sections[offset..offset + sec_sz].copy_from_slice(&dec_sec);
        }
        offset += sec_sz;
    }

    let mut ini1_offset: Option<usize> = None;
    if ctx.header.section_sizes[1] > 0 {
        ini1_offset = Some(ctx.header.section_sizes[0] as usize);
    } else if ctx.sections.len() >= 8 {
        let first_qword = read_u64_le(&ctx.sections, 0);
        if (first_qword & 0xFFFF_FFFF_FF00_0000) == 0x0000_0000_1400_0000 {
            let branch_target = (((first_qword as u32) & 0x00FF_FFFF) << 2) as usize;
            let mut cand = branch_target;
            while cand < branch_target + 0x1000 && cand + 52 <= ctx.sections.len() {
                let km = KernelMap::from_bytes(&ctx.sections[cand..]);
                if pk21_is_valid_kernel_map(&km, ctx.header.section_sizes[0], cand as u32) {
                    let ini_start = cand + km.ini1_start_offset as usize;
                    if ini_start + 4 <= ctx.sections.len()
                        && read_u32_le(&ctx.sections, ini_start) == MAGIC_INI1
                    {
                        let mut adj_km = km;
                        adj_km.add_offset(cand as u32);
                        adj_km.system_registers_offset =
                            adj_km.system_registers_offset.wrapping_add(cand as u32);
                        ctx.kernel_map = Some(adj_km);
                        ini1_offset = Some(ini_start);
                        break;
                    }
                }
                cand += 4;
            }
        } else {
            let mut cand = 0usize;
            while cand < 0x1000 && cand + 52 <= ctx.sections.len() {
                let km = KernelMap::from_bytes(&ctx.sections[cand..]);
                if pk21_is_valid_kernel_map(&km, ctx.header.section_sizes[0], 0) {
                    let ini_start = km.ini1_start_offset as usize;
                    if ini_start + 4 <= ctx.sections.len()
                        && read_u32_le(&ctx.sections, ini_start) == MAGIC_INI1
                    {
                        ctx.kernel_map = Some(km);
                        ini1_offset = Some(ini_start);
                        break;
                    }
                }
                cand += 4;
            }
        }
    }

    if let Some(ini_off) = ini1_offset {
        if ini_off + INI1_HEADER_SIZE <= ctx.sections.len() {
            let ini_hdr = Ini1Header::from_bytes(&ctx.sections[ini_off..]);
            ctx.ini1_ctx.header = ini_hdr;
            if ini_hdr.magic == MAGIC_INI1 && (ini_hdr.num_processes as usize) <= INI1_MAX_KIPS {
                let mut kip_off = ini_off + INI1_HEADER_SIZE;
                for _ in 0..ini_hdr.num_processes {
                    if kip_off + KIP1_HEADER_SIZE > ctx.sections.len() {
                        eprintln!("INI1 is corrupted!");
                        process::exit(1);
                    }
                    let kip_hdr = Kip1Header::from_bytes(&ctx.sections[kip_off..]);
                    if kip_hdr.magic != MAGIC_KIP1 {
                        eprintln!("INI1 is corrupted!");
                        process::exit(1);
                    }
                    let kip_sz = kip1_get_size_from_header(&kip_hdr) as usize;
                    if kip_off + kip_sz > ctx.sections.len() {
                        eprintln!("INI1 is corrupted!");
                        process::exit(1);
                    }
                    ctx.ini1_ctx.kips.push(Kip1Ctx {
                        file: None,
                        header: kip_hdr,
                        raw_data: ctx.sections[kip_off..kip_off + kip_sz].to_vec(),
                    });
                    kip_off += kip_sz;
                }
            }
        }
    }

    if (tool_ctx.action & ACTION_INFO) != 0 {
        pk21_print(ctx, tool_ctx);
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        pk21_save(ctx, tool_ctx);
    }
}

fn pk21_get_section_name(section: usize, is_ini1_embedded: bool) -> &'static str {
    match section {
        0 => "Kernel",
        1 => {
            if is_ini1_embedded {
                "Empty"
            } else {
                "INI1"
            }
        }
        2 => "Empty",
        _ => "Unknown",
    }
}

pub fn pk21_print(ctx: &Pk21Ctx, tool_ctx: &HactoolCtx) {
    println!("PK21:");
    if (tool_ctx.action & ACTION_VERIFY) != 0 && ctx.signature_validity != Validity::Unchecked {
        if ctx.signature_validity == Validity::Valid {
            memdump_stdout(
                "    Signature (GOOD):               ",
                &ctx.header.signature,
            );
        } else {
            memdump_stdout(
                "    Signature (FAIL):               ",
                &ctx.header.signature,
            );
        }
    } else {
        memdump_stdout(
            "    Signature:                      ",
            &ctx.header.signature,
        );
    }

    let hdr_ver = (ctx.header.ctr_dwords[1]
        ^ (ctx.header.ctr_dwords[1] >> 16)
        ^ (ctx.header.ctr_dwords[1] >> 24))
        & 0xFF;
    println!("    Header Version:                 {:02x}", hdr_ver);

    let is_ini1_embedded = ctx.header.section_sizes[1] == 0;
    for i in 0..3 {
        println!(
            "    Section {} ({}):",
            i,
            pk21_get_section_name(i, is_ini1_embedded)
        );
        if (tool_ctx.action & ACTION_VERIFY) != 0 {
            if ctx.section_validities[i] == Validity::Valid {
                memdump_stdout(
                    "        Hash (GOOD):                ",
                    &ctx.header.section_hashes[i],
                );
            } else {
                memdump_stdout(
                    "        Hash (FAIL):                ",
                    &ctx.header.section_hashes[i],
                );
            }
        } else {
            memdump_stdout(
                "        Hash:                       ",
                &ctx.header.section_hashes[i],
            );
        }
        // Replicate exact C quirk: C passes 0x20 for a 0x10 section_ctrs[i], reading into section_ctrs[i+1] (or magic.._0x5E for i=2)!
        let ctr_start = 0x110 + i * 0x10;
        memdump_stdout(
            "        CTR:                        ",
            &ctx.header.raw_bytes[ctr_start..ctr_start + 0x20],
        );
        println!(
            "        Load Address:               {:08x}",
            ctx.header.section_offsets[i].wrapping_add(0x80000000)
        );
        println!(
            "        Size:                       {:08x}",
            ctx.header.section_sizes[i]
        );
    }

    println!();
    ini1_print(&ctx.ini1_ctx);
}

pub fn pk21_save(ctx: &Pk21Ctx, tool_ctx: &mut HactoolCtx) {
    let dirpath_opt: Option<Filepath> =
        if tool_ctx.file_type == FileType::Package2 && tool_ctx.settings.out_dir_path.enabled {
            if tool_ctx.settings.out_dir_path.path.valid == Validity::Valid {
                Some(tool_ctx.settings.out_dir_path.path.clone())
            } else if tool_ctx.settings.pk21_dir_path.valid == Validity::Valid {
                Some(tool_ctx.settings.pk21_dir_path.clone())
            } else {
                None
            }
        } else if tool_ctx.settings.pk21_dir_path.valid == Validity::Valid {
            Some(tool_ctx.settings.pk21_dir_path.clone())
        } else {
            None
        };

    if let Some(ref dp) = dirpath_opt {
        let _ = os_makedir(&dp.char_path);
        let quiet = tool_ctx.settings.quiet;

        if !quiet {
            println!("Saving decrypted binary to {}/Decrypted.bin", dp.char_path);
        }
        let mut decrypted_bin = Vec::with_capacity(ctx.package_size as usize);
        decrypted_bin.extend_from_slice(&ctx.header.raw_bytes);
        decrypted_bin.extend_from_slice(&ctx.sections);
        save_buffer_to_directory_file(&decrypted_bin, dp, "Decrypted.bin");

        if !quiet {
            println!("Saving Kernel.bin to {}/Kernel.bin...", dp.char_path);
        }
        let k_size = ctx.header.section_sizes[0] as usize;
        save_buffer_to_directory_file(&ctx.sections[..k_size], dp, "Kernel.bin");

        if !quiet {
            println!("Saving INI1.bin to {}/INI1.bin...", dp.char_path);
        }
        if ctx.header.section_sizes[1] > 0 {
            let ini_sz = ctx.header.section_sizes[1] as usize;
            save_buffer_to_directory_file(&ctx.sections[k_size..k_size + ini_sz], dp, "INI1.bin");
        } else if let Some(ref km) = ctx.kernel_map {
            let ini_off = km.ini1_start_offset as usize;
            let ini_sz = ctx.ini1_ctx.header.size as usize;
            save_buffer_to_directory_file(
                &ctx.sections[ini_off..ini_off + ini_sz],
                dp,
                "INI1.bin",
            );
        }
    }

    if (tool_ctx.action & ACTION_EXTRACTINI1) != 0
        || tool_ctx.settings.ini1_dir_path.valid == Validity::Valid
    {
        if tool_ctx.settings.ini1_dir_path.valid != Validity::Valid {
            if let Some(ref dp) = dirpath_opt {
                let mut ini1_dp = dp.clone();
                ini1_dp.append("INI1");
                tool_ctx.settings.ini1_dir_path = ini1_dp;
            }
        }
        ini1_save(&ctx.ini1_ctx, tool_ctx);
    }
}

