use crate::aes::{AesCtx, AesMode};
use crate::settings::HactoolCtx;
use crate::sha::sha256_get_buffer_hmac;
use crate::types::{
    read_u32_le, read_u64_le, Filepath, SharedFile, Validity, ACTION_EXTRACT, ACTION_INFO,
    MAGIC_NAX0,
};
use crate::utils::{create_uncompressed_file, memdump_stdout, print_magic, SCRATCH_BUF_SIZE};
use std::fs::File;
use std::io::Write;
use std::process;
use std::sync::Arc;

pub const NAX0_HEADER_SIZE: usize = 0x80;

#[derive(Clone, Debug)]
pub struct Nax0Header {
    pub hmac_header: [u8; 0x20],
    pub magic: u32,
    pub _0x24: u32,
    pub keys: [[u8; 0x10]; 2],
    pub size: u64,
    pub _0x50: [u8; 0x30],
    pub raw_bytes: [u8; NAX0_HEADER_SIZE],
}

impl Default for Nax0Header {
    fn default() -> Self {
        Self {
            hmac_header: [0u8; 0x20],
            magic: 0,
            _0x24: 0,
            keys: [[0u8; 0x10]; 2],
            size: 0,
            _0x50: [0u8; 0x30],
            raw_bytes: [0u8; NAX0_HEADER_SIZE],
        }
    }
}

impl Nax0Header {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut h = Self::default();
        if data.len() < NAX0_HEADER_SIZE {
            return h;
        }
        h.raw_bytes.copy_from_slice(&data[..NAX0_HEADER_SIZE]);
        h.hmac_header.copy_from_slice(&data[0x00..0x20]);
        h.magic = read_u32_le(data, 0x20);
        h._0x24 = read_u32_le(data, 0x24);
        h.keys[0].copy_from_slice(&data[0x28..0x38]);
        h.keys[1].copy_from_slice(&data[0x38..0x48]);
        h.size = read_u64_le(data, 0x48);
        h._0x50.copy_from_slice(&data[0x50..0x80]);
        h
    }
}

#[derive(Clone, Default)]
pub struct Nax0Ctx {
    pub base_path: Filepath,
    pub aes_ctx: Option<Arc<AesCtx>>,
    pub files: Vec<SharedFile>,
    pub k: usize,
    pub encrypted_keys: [[u8; 0x10]; 2],
    pub header: Nax0Header,
}

impl Nax0Ctx {
    pub fn read(&self, offset: u64, dst: &mut [u8]) -> usize {
        if self.files.len() == 1 {
            return self.files[0].read_at(offset, dst).unwrap_or(0);
        }
        let chunk_limit = 0xFFFF_0000u64;
        let idx = (offset / chunk_limit) as usize;
        if idx >= self.files.len() {
            return 0;
        }
        let offset_in_file = offset % chunk_limit;
        let left_in_file = (chunk_limit - offset_in_file) as usize;
        if dst.len() > left_in_file {
            let n1 = self.files[idx]
                .read_at(offset_in_file, &mut dst[..left_in_file])
                .unwrap_or(0);
            let n2 = self.read(offset + left_in_file as u64, &mut dst[left_in_file..]);
            n1 + n2
        } else {
            self.files[idx].read_at(offset_in_file, dst).unwrap_or(0)
        }
    }
}

pub fn nax0_process(ctx: &mut Nax0Ctx, tool_ctx: &HactoolCtx) {
    ctx.files.clear();
    if let Ok(f) = File::open(&ctx.base_path.char_path) {
        if let Ok(meta) = f.metadata() {
            if meta.is_file() {
                ctx.files.push(SharedFile::new(f));
            }
        }
    }

    if ctx.files.is_empty() {
        let mut idx = 0u32;
        loop {
            let mut temp_path = ctx.base_path.clone();
            temp_path.append(&format!("{:02}", idx));
            match File::open(&temp_path.char_path) {
                Ok(f) => {
                    ctx.files.push(SharedFile::new(f));
                    idx += 1;
                }
                Err(_) => break,
            }
        }
        if ctx.files.is_empty() {
            eprintln!("Input path appears to neither be a NAX0, nor a NAX0 directory!");
            process::exit(1);
        }
    }

    let mut hdr_buf = [0u8; NAX0_HEADER_SIZE];
    ctx.read(0, &mut hdr_buf);
    ctx.header = Nax0Header::from_bytes(&hdr_buf);
    if ctx.header.magic != MAGIC_NAX0 {
        println!("Error: File has invalid NAX0 magic!");
        return;
    }

    ctx.encrypted_keys = ctx.header.keys;

    let mut found = false;
    for k in 0..2 {
        ctx.k = k;
        let mut nax_specific_keys = [0u8; 0x20];
        let sd_path_bytes = tool_ctx.settings.nax0_sd_path.char_path.as_bytes();
        sha256_get_buffer_hmac(
            &mut nax_specific_keys,
            &tool_ctx.settings.keyset.sd_card_keys[k][0x00..0x10],
            sd_path_bytes,
        );

        for i in 0..2 {
            let mut nax_k_ctx = AesCtx::new(
                &nax_specific_keys[i * 0x10..(i + 1) * 0x10],
                16,
                AesMode::Ecb,
            );
            nax_k_ctx.decrypt(&ctx.encrypted_keys[i], &mut ctx.header.keys[i]);
        }

        let mut mac_data = [0u8; 0x60];
        mac_data[..0x08].copy_from_slice(&ctx.header.raw_bytes[0x20..0x28]);
        mac_data[0x08..0x18].copy_from_slice(&ctx.header.keys[0]);
        mac_data[0x18..0x28].copy_from_slice(&ctx.header.keys[1]);
        mac_data[0x28..0x60].copy_from_slice(&ctx.header.raw_bytes[0x48..0x80]);

        let mut validation_mac = [0u8; 0x20];
        sha256_get_buffer_hmac(
            &mut validation_mac,
            &mac_data,
            &tool_ctx.settings.keyset.sd_card_keys[k][0x10..0x20],
        );
        if ctx.header.hmac_header == validation_mac {
            found = true;
            break;
        }
    }

    if !found {
        println!("Error: NAX0 key derivation failed. Check SD card seed and relative path?");
        return;
    }

    let mut xts_key = [0u8; 0x20];
    xts_key[0x00..0x10].copy_from_slice(&ctx.header.keys[0]);
    xts_key[0x10..0x20].copy_from_slice(&ctx.header.keys[1]);
    ctx.aes_ctx = Some(Arc::new(AesCtx::new(&xts_key, 32, AesMode::Xts)));

    if (tool_ctx.action & ACTION_INFO) != 0 {
        nax0_print(ctx);
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        nax0_save(ctx, tool_ctx);
    }
}

pub fn nax0_save(ctx: &Nax0Ctx, tool_ctx: &HactoolCtx) {
    let dec_path = &tool_ctx.settings.plaintext_path;
    if dec_path.valid != Validity::Valid {
        return;
    }

    if !tool_ctx.settings.quiet {
        println!("Saving Decrypted NAX0 Content to {}...", dec_path.char_path);
    }
    let mut f_dec = match create_uncompressed_file(&dec_path.char_path) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("Failed to open {}!", dec_path.char_path);
            return;
        }
    };

    let aes_ctx = match &ctx.aes_ctx {
        Some(a) => a,
        None => return,
    };

    let mut ofs = 0x4000u64;
    let end_ofs = ofs + ctx.header.size;
    let buf_cap = SCRATCH_BUF_SIZE;
    let mut in_buf = vec![0xCCu8; buf_cap];
    let mut out_buf = vec![0u8; buf_cap];

    while ofs < end_ofs {
        let read_size = ((end_ofs - ofs) as usize).min(buf_cap);
        if ctx.read(ofs, &mut in_buf[..read_size]) != read_size {
            eprintln!("Failed to read file!");
            process::exit(1);
        }

        let dec_size = (read_size + 0x3FFF) & !0x3FFF;
        aes_ctx.xts_decrypt(
            &in_buf[..dec_size],
            &mut out_buf[..dec_size],
            ((ofs - 0x4000) >> 14) as usize,
            0x4000,
        );

        if f_dec.write_all(&out_buf[..read_size]).is_err() {
            eprintln!("Failed to write file!");
            process::exit(1);
        }
        ofs += read_size as u64;
    }
}

fn nax0_get_key_summary(k: usize) -> &'static str {
    match k {
        0 => "Save",
        1 => "NCA",
        _ => "Unknown",
    }
}

pub fn nax0_print(ctx: &Nax0Ctx) {
    println!("\nNAX0:");
    print_magic("    Magic:                          ", ctx.header.magic);
    println!(
        "    Content Type:                   {}",
        nax0_get_key_summary(ctx.k)
    );
    println!(
        "    Content Size:                   {:012x}",
        ctx.header.size
    );
    memdump_stdout(
        "    Header HMAC:                    ",
        &ctx.header.hmac_header,
    );
    let mut enc_flat = [0u8; 0x20];
    enc_flat[..0x10].copy_from_slice(&ctx.encrypted_keys[0]);
    enc_flat[0x10..].copy_from_slice(&ctx.encrypted_keys[1]);
    memdump_stdout("    Encrypted Keys:                 ", &enc_flat);
    let mut dec_flat = [0u8; 0x20];
    dec_flat[..0x10].copy_from_slice(&ctx.header.keys[0]);
    dec_flat[0x10..].copy_from_slice(&ctx.header.keys[1]);
    memdump_stdout("    Decrypted Keys:                 ", &dec_flat);
}

