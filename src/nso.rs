use crate::lz4::lz4_decompress_safe;
use crate::settings::HactoolCtx;
use crate::sha::sha256_hash_buffer;
use crate::types::{
    read_u32_le, write_u32_le, FileType, SharedFile, Validity, ACTION_EXTRACT, ACTION_INFO,
    ACTION_VERIFY, MAGIC_NSO0,
};
use crate::utils::{align, create_uncompressed_file, memdump_stdout};
use std::io::Write;
use std::process;

pub const NSO0_HEADER_SIZE: usize = 0x100;

#[derive(Clone, Copy, Debug, Default)]
pub struct Nso0Segment {
    pub file_off: u32,
    pub dst_off: u32,
    pub decomp_size: u32,
    pub align_or_total_size: u32,
}

#[derive(Clone, Debug)]
pub struct Nso0Header {
    pub magic: u32,
    pub _0x4: u32,
    pub _0x8: u32,
    pub flags: u32,
    pub segments: [Nso0Segment; 3],
    pub build_id: [u8; 0x20],
    pub compressed_sizes: [u32; 3],
    pub _0x6c: [u8; 0x24],
    pub dynstr_extents: u64,
    pub dynsym_extents: u64,
    pub section_hashes: [[u8; 0x20]; 3],
}

impl Default for Nso0Header {
    fn default() -> Self {
        Self {
            magic: 0,
            _0x4: 0,
            _0x8: 0,
            flags: 0,
            segments: [Nso0Segment::default(); 3],
            build_id: [0u8; 0x20],
            compressed_sizes: [0u32; 3],
            _0x6c: [0u8; 0x24],
            dynstr_extents: 0,
            dynsym_extents: 0,
            section_hashes: [[0u8; 0x20]; 3],
        }
    }
}

impl Nso0Header {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hdr = Self::default();
        if data.len() < NSO0_HEADER_SIZE {
            return hdr;
        }
        hdr.magic = read_u32_le(data, 0x0);
        hdr._0x4 = read_u32_le(data, 0x4);
        hdr._0x8 = read_u32_le(data, 0x8);
        hdr.flags = read_u32_le(data, 0xC);
        for i in 0..3 {
            let base = 0x10 + i * 0x10;
            hdr.segments[i] = Nso0Segment {
                file_off: read_u32_le(data, base),
                dst_off: read_u32_le(data, base + 4),
                decomp_size: read_u32_le(data, base + 8),
                align_or_total_size: read_u32_le(data, base + 12),
            };
        }
        hdr.build_id.copy_from_slice(&data[0x40..0x60]);
        for i in 0..3 {
            hdr.compressed_sizes[i] = read_u32_le(data, 0x60 + i * 4);
        }
        hdr._0x6c.copy_from_slice(&data[0x6C..0x90]);
        hdr.dynstr_extents = crate::types::read_u64_le(data, 0x90);
        hdr.dynsym_extents = crate::types::read_u64_le(data, 0x98);
        for i in 0..3 {
            hdr.section_hashes[i].copy_from_slice(&data[0xA0 + i * 0x20..0xC0 + i * 0x20]);
        }
        hdr
    }

    pub fn write_to_bytes(&self, out: &mut [u8]) {
        write_u32_le(out, 0x0, self.magic);
        write_u32_le(out, 0x4, self._0x4);
        write_u32_le(out, 0x8, self._0x8);
        write_u32_le(out, 0xC, self.flags);
        for i in 0..3 {
            let base = 0x10 + i * 0x10;
            write_u32_le(out, base, self.segments[i].file_off);
            write_u32_le(out, base + 4, self.segments[i].dst_off);
            write_u32_le(out, base + 8, self.segments[i].decomp_size);
            write_u32_le(out, base + 12, self.segments[i].align_or_total_size);
        }
        out[0x40..0x60].copy_from_slice(&self.build_id);
        for i in 0..3 {
            write_u32_le(out, 0x60 + i * 4, self.compressed_sizes[i]);
        }
        out[0x6C..0x90].copy_from_slice(&self._0x6c);
        crate::types::write_u64_le(out, 0x90, self.dynstr_extents);
        crate::types::write_u64_le(out, 0x98, self.dynsym_extents);
        for i in 0..3 {
            out[0xA0 + i * 0x20..0xC0 + i * 0x20].copy_from_slice(&self.section_hashes[i]);
        }
    }
}

#[inline]
pub fn nso_get_section_size(header: &Nso0Header, segment: usize) -> u64 {
    let is_compressed = ((header.flags >> segment) & 1) != 0;
    if is_compressed {
        header.compressed_sizes[segment] as u64
    } else {
        header.segments[segment].decomp_size as u64
    }
}

#[inline]
pub fn nso_get_size(header: &Nso0Header) -> u64 {
    header.segments[2].file_off as u64 + nso_get_section_size(header, 2)
}

#[derive(Clone, Default)]
pub struct Nso0Ctx {
    pub file: Option<SharedFile>,
    pub header: Nso0Header,
    pub raw_data: Vec<u8>,
    pub uncompressed_data: Vec<u8>,
    pub segment_validities: [Validity; 3],
}

fn nso_uncompress(ctx: &mut Nso0Ctx, tool_ctx: &HactoolCtx) -> Vec<u8> {
    let mut new_header = ctx.header.clone();
    for i in 0..3 {
        new_header.segments[i].file_off = new_header.segments[i].dst_off + NSO0_HEADER_SIZE as u32;
        new_header.compressed_sizes[i] = new_header.segments[i].decomp_size;
    }
    new_header.segments[0].align_or_total_size = 0x100;
    new_header.segments[1].align_or_total_size = 0;
    new_header.flags &= 0xF8;

    let size = nso_get_size(&new_header) as usize;
    let mut new_nso = vec![0u8; size];
    new_header.write_to_bytes(&mut new_nso[..NSO0_HEADER_SIZE]);

    for segment in 0..3 {
        let src_off = ctx.header.segments[segment].file_off as usize;
        let dst_off = new_header.segments[segment].file_off as usize;
        let decomp_size = new_header.segments[segment].decomp_size as usize;

        if ((ctx.header.flags >> segment) & 1) != 0 {
            let cmp_size = ctx.header.compressed_sizes[segment] as usize;
            let src_slice = &ctx.raw_data[src_off..src_off + cmp_size];
            let dst_slice = &mut new_nso[dst_off..dst_off + decomp_size];
            match lz4_decompress_safe(src_slice, dst_slice) {
                Ok(n) if n == decomp_size => {}
                _ => {
                    eprintln!("Error: Failed to decompress NSO0 segment {}!", segment);
                    process::exit(1);
                }
            }
        } else {
            new_nso[dst_off..dst_off + decomp_size]
                .copy_from_slice(&ctx.raw_data[src_off..src_off + decomp_size]);
        }

        if (tool_ctx.action & ACTION_VERIFY) != 0 && ((ctx.header.flags >> (segment + 3)) & 1) != 0
        {
            let mut calc_hash = [0u8; 0x20];
            sha256_hash_buffer(&mut calc_hash, &new_nso[dst_off..dst_off + decomp_size]);
            if calc_hash == new_header.section_hashes[segment] {
                ctx.segment_validities[segment] = Validity::Valid;
            } else {
                ctx.segment_validities[segment] = Validity::Invalid;
            }
        }
    }

    new_nso
}

pub fn nso0_process(ctx: &mut Nso0Ctx, tool_ctx: &HactoolCtx) {
    let file = match &ctx.file {
        Some(f) => f.clone(),
        None => {
            eprintln!("Failed to read NSO0 header!");
            process::exit(1);
        }
    };

    let mut raw_hdr_bytes = [0u8; NSO0_HEADER_SIZE];
    if file.read_exact_at(0, &mut raw_hdr_bytes).is_err() {
        eprintln!("Failed to read NSO0 header!");
        process::exit(1);
    }

    let raw_header = Nso0Header::from_bytes(&raw_hdr_bytes);
    if raw_header.magic != MAGIC_NSO0 {
        println!("Error: NSO0 is corrupt!");
        process::exit(1);
    }

    let size = nso_get_size(&raw_header) as usize;
    ctx.raw_data = vec![0u8; size];
    if file.read_exact_at(0, &mut ctx.raw_data).is_err() {
        eprintln!("Failed to read NSO0!");
        process::exit(1);
    }
    ctx.header = raw_header;
    ctx.uncompressed_data = nso_uncompress(ctx, tool_ctx);

    if (tool_ctx.action & ACTION_INFO) != 0 {
        nso0_print(ctx, tool_ctx);
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        nso0_save(ctx, tool_ctx);
    }
}

pub fn nso0_print(ctx: &Nso0Ctx, tool_ctx: &HactoolCtx) {
    println!("NSO0:");
    memdump_stdout(
        "    Build Id:                       ",
        &ctx.header.build_id,
    );
    println!("    Sections:");
    if (tool_ctx.action & ACTION_VERIFY) != 0 && ctx.segment_validities[0] != Validity::Unchecked {
        println!(
            "        .text   ({}):             {:08x}-{:08x}",
            ctx.segment_validities[0].as_str(),
            ctx.header.segments[0].dst_off,
            ctx.header.segments[0].dst_off + align(ctx.header.segments[0].decomp_size, 0x1000)
        );
    } else {
        println!(
            "        .text:                      {:08x}-{:08x}",
            ctx.header.segments[0].dst_off,
            ctx.header.segments[0].dst_off + align(ctx.header.segments[0].decomp_size, 0x1000)
        );
    }
    if (tool_ctx.action & ACTION_VERIFY) != 0 && ctx.segment_validities[1] != Validity::Unchecked {
        println!(
            "        .rodata ({}):             {:08x}-{:08x}",
            ctx.segment_validities[1].as_str(),
            ctx.header.segments[1].dst_off,
            ctx.header.segments[1].dst_off + align(ctx.header.segments[1].decomp_size, 0x1000)
        );
    } else {
        println!(
            "        .rodata:                    {:08x}-{:08x}",
            ctx.header.segments[1].dst_off,
            ctx.header.segments[1].dst_off + align(ctx.header.segments[1].decomp_size, 0x1000)
        );
    }
    if (tool_ctx.action & ACTION_VERIFY) != 0 && ctx.segment_validities[2] != Validity::Unchecked {
        println!(
            "        .rwdata ({}):             {:08x}-{:08x}",
            ctx.segment_validities[2].as_str(),
            ctx.header.segments[2].dst_off,
            ctx.header.segments[2].dst_off + ctx.header.segments[2].decomp_size
        );
    } else {
        println!(
            "        .rwdata:                    {:08x}-{:08x}",
            ctx.header.segments[2].dst_off,
            ctx.header.segments[2].dst_off + ctx.header.segments[2].decomp_size
        );
    }
    println!(
        "        .bss:                       {:08x}-{:08x}",
        ctx.header.segments[2].dst_off + ctx.header.segments[2].decomp_size,
        ctx.header.segments[2].dst_off
            + align(
                ctx.header.segments[2].decomp_size + ctx.header.segments[2].align_or_total_size,
                0x1000
            )
    );
}

pub fn nso0_save(ctx: &Nso0Ctx, tool_ctx: &HactoolCtx) {
    let uncmp_path = &tool_ctx.settings.uncompressed_path;
    if tool_ctx.file_type == FileType::Nso0 && uncmp_path.valid == Validity::Valid {
        let mut f_uncmp = match create_uncompressed_file(&uncmp_path.char_path) {
            Ok(f) => f,
            Err(_) => {
                eprintln!("Failed to open {}!", uncmp_path.char_path);
                return;
            }
        };
        if f_uncmp.write_all(&ctx.uncompressed_data).is_err() {
            eprintln!("Failed to write uncompressed nso!");
            process::exit(1);
        }
    }
}

