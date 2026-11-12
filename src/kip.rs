use crate::npdm::{kac_get_json, kac_print, npdm_get_proc_category, JsonValue};
use crate::settings::HactoolCtx;
use crate::types::{
    read_u32_le, read_u64_le, write_u32_le, write_u64_le, FileType, Filepath, SharedFile, Validity,
    ACTION_EXTRACT, ACTION_INFO, ACTION_SAVEINIJSON, MAGIC_INI1, MAGIC_KIP1,
};
use crate::utils::{align, create_uncompressed_file, os_makedir, save_buffer_to_directory_file};
use std::io::Write;
use std::process;

pub const INI1_MAX_KIPS: usize = 0x50;
pub const INI1_HEADER_SIZE: usize = 0x10;
pub const KIP1_HEADER_SIZE: usize = 0x100;

#[derive(Clone, Copy, Debug, Default)]
pub struct Ini1Header {
    pub magic: u32,
    pub size: u32,
    pub num_processes: u32,
    pub _0xc: u32,
}

impl Ini1Header {
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < INI1_HEADER_SIZE {
            return Self::default();
        }
        Self {
            magic: read_u32_le(data, 0x0),
            size: read_u32_le(data, 0x4),
            num_processes: read_u32_le(data, 0x8),
            _0xc: read_u32_le(data, 0xC),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KipSectionHeader {
    pub out_offset: u32,
    pub out_size: u32,
    pub compressed_size: u32,
    pub attribute: u32,
}

#[derive(Clone, Debug)]
pub struct Kip1Header {
    pub magic: u32,
    pub name: [u8; 0xC],
    pub title_id: u64,
    pub process_category: u32,
    pub main_thread_priority: u8,
    pub default_core: u8,
    pub _0x1e: u8,
    pub flags: u8,
    pub section_headers: [KipSectionHeader; 6],
    pub capabilities: [u32; 0x20],
}

impl Default for Kip1Header {
    fn default() -> Self {
        Self {
            magic: 0,
            name: [0u8; 0xC],
            title_id: 0,
            process_category: 0,
            main_thread_priority: 0,
            default_core: 0,
            _0x1e: 0,
            flags: 0,
            section_headers: [KipSectionHeader::default(); 6],
            capabilities: [0u32; 0x20],
        }
    }
}

impl Kip1Header {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hdr = Self::default();
        if data.len() < KIP1_HEADER_SIZE {
            return hdr;
        }
        hdr.magic = read_u32_le(data, 0x0);
        hdr.name.copy_from_slice(&data[0x4..0x10]);
        hdr.title_id = read_u64_le(data, 0x10);
        hdr.process_category = read_u32_le(data, 0x18);
        hdr.main_thread_priority = data[0x1C];
        hdr.default_core = data[0x1D];
        hdr._0x1e = data[0x1E];
        hdr.flags = data[0x1F];
        for i in 0..6 {
            let base = 0x20 + i * 0x10;
            hdr.section_headers[i] = KipSectionHeader {
                out_offset: read_u32_le(data, base),
                out_size: read_u32_le(data, base + 4),
                compressed_size: read_u32_le(data, base + 8),
                attribute: read_u32_le(data, base + 12),
            };
        }
        for i in 0..0x20 {
            hdr.capabilities[i] = read_u32_le(data, 0x80 + i * 4);
        }
        hdr
    }

    pub fn write_to_bytes(&self, out: &mut [u8]) {
        write_u32_le(out, 0x0, self.magic);
        out[0x4..0x10].copy_from_slice(&self.name);
        write_u64_le(out, 0x10, self.title_id);
        write_u32_le(out, 0x18, self.process_category);
        out[0x1C] = self.main_thread_priority;
        out[0x1D] = self.default_core;
        out[0x1E] = self._0x1e;
        out[0x1F] = self.flags;
        for i in 0..6 {
            let base = 0x20 + i * 0x10;
            write_u32_le(out, base, self.section_headers[i].out_offset);
            write_u32_le(out, base + 4, self.section_headers[i].out_size);
            write_u32_le(out, base + 8, self.section_headers[i].compressed_size);
            write_u32_le(out, base + 12, self.section_headers[i].attribute);
        }
        for i in 0..0x20 {
            write_u32_le(out, 0x80 + i * 4, self.capabilities[i]);
        }
    }

    pub fn name_str(&self) -> String {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        String::from_utf8_lossy(&self.name[..len]).into_owned()
    }
}

#[inline]
pub fn kip1_get_size_from_header(header: &Kip1Header) -> u64 {
    0x100
        + header.section_headers[0].compressed_size as u64
        + header.section_headers[1].compressed_size as u64
        + header.section_headers[2].compressed_size as u64
}

#[derive(Clone, Default)]
pub struct Kip1Ctx {
    pub file: Option<SharedFile>,
    pub header: Kip1Header,
    pub raw_data: Vec<u8>,
}

impl Kip1Ctx {
    #[inline]
    pub fn get_size(&self) -> u64 {
        kip1_get_size_from_header(&self.header)
    }
}

#[derive(Clone, Default)]
pub struct Ini1Ctx {
    pub file: Option<SharedFile>,
    pub header: Ini1Header,
    pub raw_data: Vec<u8>,
    pub kips: Vec<Kip1Ctx>,
}

pub fn ini1_process(ctx: &mut Ini1Ctx, tool_ctx: &HactoolCtx) {
    let file = match &ctx.file {
        Some(f) => f.clone(),
        None => {
            eprintln!("Failed to read INI1 header!");
            process::exit(1);
        }
    };

    let mut raw_hdr_bytes = [0u8; INI1_HEADER_SIZE];
    if file.read_exact_at(0, &mut raw_hdr_bytes).is_err() {
        eprintln!("Failed to read INI1 header!");
        process::exit(1);
    }

    let raw_header = Ini1Header::from_bytes(&raw_hdr_bytes);
    if raw_header.magic != MAGIC_INI1 || (raw_header.num_processes as usize) > INI1_MAX_KIPS {
        println!("Error: INI1 is corrupt!");
        process::exit(1);
    }

    ctx.raw_data = vec![0u8; raw_header.size as usize];
    if file.read_exact_at(0, &mut ctx.raw_data).is_err() {
        eprintln!("Failed to read INI1!");
        process::exit(1);
    }
    ctx.header = raw_header;
    ctx.kips.clear();

    let mut offset = INI1_HEADER_SIZE;
    for _ in 0..ctx.header.num_processes {
        if offset + KIP1_HEADER_SIZE > ctx.raw_data.len() {
            eprintln!("INI1 is corrupted!");
            process::exit(1);
        }
        let kip_hdr = Kip1Header::from_bytes(&ctx.raw_data[offset..]);
        if kip_hdr.magic != MAGIC_KIP1 {
            eprintln!("INI1 is corrupted!");
            process::exit(1);
        }
        let kip_size = kip1_get_size_from_header(&kip_hdr) as usize;
        if offset + kip_size > ctx.raw_data.len() {
            eprintln!("INI1 is corrupted!");
            process::exit(1);
        }
        let kip_raw = ctx.raw_data[offset..offset + kip_size].to_vec();
        ctx.kips.push(Kip1Ctx {
            file: None,
            header: kip_hdr,
            raw_data: kip_raw,
        });
        offset += kip_size;
    }

    if (tool_ctx.action & ACTION_INFO) != 0 {
        ini1_print(ctx);
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        ini1_save(ctx, tool_ctx);
    }
}

pub fn ini1_print(ctx: &Ini1Ctx) {
    println!("INI1:");
    println!(
        "    Number of Processes:            {:02x}",
        ctx.header.num_processes
    );
    println!("    Size:                           {:08x}", ctx.header.size);
    println!();
    for (i, kip) in ctx.kips.iter().enumerate() {
        println!("Process {:02x}:", i);
        kip1_print(kip, true);
        println!();
    }
    println!();
}

pub fn ini1_save(ctx: &Ini1Ctx, tool_ctx: &HactoolCtx) {
    let mut dirpath: Option<&Filepath> = None;
    if tool_ctx.file_type == FileType::Ini1 && tool_ctx.settings.out_dir_path.enabled {
        dirpath = Some(&tool_ctx.settings.out_dir_path.path);
    }
    if dirpath.is_none() || dirpath.unwrap().valid != Validity::Valid {
        dirpath = Some(&tool_ctx.settings.ini1_dir_path);
    }
    if let Some(dp) = dirpath {
        if dp.valid == Validity::Valid {
            let _ = os_makedir(&dp.char_path);
            for kip in &ctx.kips {
                let base_name = kip.header.name_str();
                let kip_filename = format!("{}.kip1", base_name);
                if !tool_ctx.settings.quiet {
                    println!(
                        "Saving {} to {}/{}...",
                        kip_filename, dp.char_path, kip_filename
                    );
                }
                save_buffer_to_directory_file(&kip.raw_data, dp, &kip_filename);
                if (tool_ctx.action & ACTION_SAVEINIJSON) != 0 {
                    if !tool_ctx.settings.quiet {
                        println!("SAVING INI JSON!");
                    }
                    let json_filename = format!("{}.json", base_name);
                    let mut json_path = dp.clone();
                    json_path.append(&json_filename);
                    let mut f_json = match create_uncompressed_file(&json_path.char_path) {
                        Ok(f) => f,
                        Err(_) => {
                            eprintln!("Failed to open {}!", json_path.char_path);
                            return;
                        }
                    };
                    let json = kip1_get_json(kip);
                    if f_json.write_all(json.as_bytes()).is_err() {
                        eprintln!("Failed to write JSON file!");
                        process::exit(1);
                    }
                }
            }
        }
    }
}

pub fn kip1_get_json(ctx: &Kip1Ctx) -> String {
    let mut obj = Vec::new();
    obj.push((
        "name".to_string(),
        JsonValue::String(ctx.header.name_str()),
    ));
    obj.push((
        "title_id".to_string(),
        JsonValue::String(format!("0x{:016x}", ctx.header.title_id)),
    ));
    obj.push((
        "main_thread_stack_size".to_string(),
        JsonValue::String(format!(
            "0x{:08x}",
            ctx.header.section_headers[1].attribute
        )),
    ));
    obj.push((
        "main_thread_priority".to_string(),
        JsonValue::Number(ctx.header.main_thread_priority as i64),
    ));
    obj.push((
        "default_cpu_id".to_string(),
        JsonValue::Number(ctx.header.default_core as i64),
    ));
    obj.push((
        "process_category".to_string(),
        JsonValue::Number(ctx.header.process_category as i64),
    ));
    obj.push((
        "kernel_capabilities".to_string(),
        kac_get_json(&ctx.header.capabilities),
    ));
    JsonValue::Object(obj).format_cjson()
}

fn kip1_blz_uncompress(section_slice: &mut [u8], compressed_size: usize) {
    if compressed_size < 12 || compressed_size > section_slice.len() {
        eprintln!("KIP1 decompression out of bounds!");
        process::exit(1);
    }
    let addl_size = read_u32_le(section_slice, compressed_size - 4) as usize;
    let header_size = read_u32_le(section_slice, compressed_size - 8) as usize;
    let cmp_and_hdr_size = read_u32_le(section_slice, compressed_size - 12) as usize;

    if cmp_and_hdr_size > compressed_size || header_size > cmp_and_hdr_size {
        eprintln!("KIP1 decompression out of bounds!");
        process::exit(1);
    }

    let cmp_start_offset = compressed_size - cmp_and_hdr_size;
    let cmp_start = &mut section_slice[cmp_start_offset..];
    let mut cmp_ofs = cmp_and_hdr_size - header_size;
    let mut out_ofs = cmp_and_hdr_size + addl_size;

    if out_ofs > cmp_start.len() {
        eprintln!("KIP1 decompression out of bounds!");
        process::exit(1);
    }

    while out_ofs > 0 {
        if cmp_ofs < 1 {
            eprintln!("KIP1 decompression out of bounds!");
            process::exit(1);
        }
        cmp_ofs -= 1;
        let mut control = cmp_start[cmp_ofs];
        for _ in 0..8 {
            if (control & 0x80) != 0 {
                if cmp_ofs < 2 {
                    eprintln!("KIP1 decompression out of bounds!");
                    process::exit(1);
                }
                cmp_ofs -= 2;
                let seg_val =
                    ((cmp_start[cmp_ofs + 1] as u16) << 8) | (cmp_start[cmp_ofs] as u16);
                let mut seg_size = (((seg_val >> 12) & 0xF) as usize) + 3;
                let seg_ofs = ((seg_val & 0x0FFF) as usize) + 3;
                if out_ofs < seg_size {
                    seg_size = out_ofs;
                }
                out_ofs -= seg_size;

                for j in 0..seg_size {
                    cmp_start[out_ofs + j] = cmp_start[out_ofs + j + seg_ofs];
                }
            } else {
                if cmp_ofs < 1 {
                    eprintln!("KIP1 decompression out of bounds!");
                    process::exit(1);
                }
                out_ofs -= 1;
                cmp_ofs -= 1;
                cmp_start[out_ofs] = cmp_start[cmp_ofs];
            }
            control <<= 1;
            if out_ofs == 0 {
                return;
            }
        }
    }
}

fn kip1_uncompress(ctx: &Kip1Ctx) -> Vec<u8> {
    let mut new_header = ctx.header.clone();
    for i in 0..3 {
        new_header.section_headers[i].compressed_size = new_header.section_headers[i].out_size;
    }
    new_header.flags &= 0xF8;

    let size = kip1_get_size_from_header(&new_header) as usize;
    let mut new_kip = vec![0u8; size];
    new_header.write_to_bytes(&mut new_kip[..KIP1_HEADER_SIZE]);

    let mut new_offset = 0x100usize;
    let mut old_offset = 0x100usize;
    for i in 0..3 {
        let cmp_size = ctx.header.section_headers[i].compressed_size as usize;
        let out_size = ctx.header.section_headers[i].out_size as usize;
        new_kip[new_offset..new_offset + cmp_size]
            .copy_from_slice(&ctx.raw_data[old_offset..old_offset + cmp_size]);
        if (ctx.header.flags & (1 << i)) != 0 {
            kip1_blz_uncompress(&mut new_kip[new_offset..new_offset + out_size], cmp_size);
        }
        new_offset += out_size;
        old_offset += cmp_size;
    }

    new_kip
}

pub fn kip1_process(ctx: &mut Kip1Ctx, tool_ctx: &HactoolCtx) {
    let file = match &ctx.file {
        Some(f) => f.clone(),
        None => {
            eprintln!("Failed to read KIP1 header!");
            process::exit(1);
        }
    };

    let mut raw_hdr_bytes = [0u8; KIP1_HEADER_SIZE];
    if file.read_exact_at(0, &mut raw_hdr_bytes).is_err() {
        eprintln!("Failed to read KIP1 header!");
        process::exit(1);
    }

    let raw_header = Kip1Header::from_bytes(&raw_hdr_bytes);
    if raw_header.magic != MAGIC_KIP1 {
        println!("Error: KIP1 is corrupt!");
        process::exit(1);
    }

    let size = kip1_get_size_from_header(&raw_header) as usize;
    ctx.raw_data = vec![0u8; size];
    if file.read_exact_at(0, &mut ctx.raw_data).is_err() {
        eprintln!("Failed to read KIP1!");
        process::exit(1);
    }
    ctx.header = raw_header;

    if (tool_ctx.action & ACTION_INFO) != 0 {
        kip1_print(ctx, false);
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        kip1_save(ctx, tool_ctx);
    }
}

pub fn kip1_print(ctx: &Kip1Ctx, suppress: bool) {
    if !suppress {
        println!("KIP1:");
    }
    println!(
        "    Title ID:                       {:016x}",
        ctx.header.title_id
    );
    println!(
        "    Name:                           {}",
        ctx.header.name_str()
    );
    println!(
        "    Process Category:               {}",
        npdm_get_proc_category(ctx.header.process_category as i32)
    );
    println!(
        "    Main Thread Priority:           {}",
        ctx.header.main_thread_priority as i8
    );
    println!(
        "    Default CPU Core:               {}",
        ctx.header.default_core as i8
    );
    println!(
        "    Is 64 Bit:                      {}",
        if (ctx.header.flags & (1 << 3)) != 0 {
            "True"
        } else {
            "False"
        }
    );
    println!(
        "    Is Address Space 64 Bit:        {}",
        if (ctx.header.flags & (1 << 4)) != 0 {
            "True"
        } else {
            "False"
        }
    );
    println!("    Sections:");
    println!(
        "        .text:                      {:08x}-{:08x}",
        ctx.header.section_headers[0].out_offset,
        ctx.header.section_headers[0].out_offset
            + align(ctx.header.section_headers[0].out_size, 0x1000)
    );
    println!(
        "        .rodata:                    {:08x}-{:08x}",
        ctx.header.section_headers[1].out_offset,
        ctx.header.section_headers[1].out_offset
            + align(ctx.header.section_headers[1].out_size, 0x1000)
    );
    println!(
        "        .rwdata:                    {:08x}-{:08x}",
        ctx.header.section_headers[2].out_offset,
        ctx.header.section_headers[2].out_offset + ctx.header.section_headers[2].out_size
    );
    println!(
        "        .bss:                       {:08x}-{:08x}",
        ctx.header.section_headers[2].out_offset + ctx.header.section_headers[2].out_size,
        align(
            ctx.header.section_headers[3].out_offset + ctx.header.section_headers[3].out_size,
            0x1000
        )
    );
    println!("    Kernel Access Control:");
    kac_print(&ctx.header.capabilities);
    println!();
}

pub fn kip1_save(ctx: &Kip1Ctx, tool_ctx: &HactoolCtx) {
    let json_path = &tool_ctx.settings.npdm_json_path;
    let uncmp_path = &tool_ctx.settings.uncompressed_path;
    if tool_ctx.file_type == FileType::Kip1 {
        if json_path.valid == Validity::Valid {
            let mut f_json = match create_uncompressed_file(&json_path.char_path) {
                Ok(f) => f,
                Err(_) => {
                    eprintln!("Failed to open {}!", json_path.char_path);
                    return;
                }
            };
            let json = kip1_get_json(ctx);
            if f_json.write_all(json.as_bytes()).is_err() {
                eprintln!("Failed to write JSON file!");
                process::exit(1);
            }
        }

        if uncmp_path.valid == Validity::Valid {
            let mut f_uncmp = match create_uncompressed_file(&uncmp_path.char_path) {
                Ok(f) => f,
                Err(_) => {
                    eprintln!("Failed to open {}!", uncmp_path.char_path);
                    return;
                }
            };
            let uncmp = kip1_uncompress(ctx);
            if f_uncmp.write_all(&uncmp).is_err() {
                eprintln!("Failed to write uncompressed kip!");
                process::exit(1);
            }
        }
    }
}

