#![allow(dead_code)]

//! BKTR relocation and subsection table lookups matching `bktr.c` and `bktr.h`.

use crate::types::{read_u32_le, read_u64_le};
use std::process;

pub const MAGIC_BKTR: u32 = 0x52544B42;

#[derive(Clone, Copy, Debug, Default)]
pub struct BktrHeader {
    pub offset: u64,
    pub size: u64,
    pub magic: u32,
    pub _0x14: u32,
    pub num_entries: u32,
    pub _0x1c: u32,
}

impl BktrHeader {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            offset: read_u64_le(bytes, 0x00),
            size: read_u64_le(bytes, 0x08),
            magic: read_u32_le(bytes, 0x10),
            _0x14: read_u32_le(bytes, 0x14),
            num_entries: read_u32_le(bytes, 0x18),
            _0x1c: read_u32_le(bytes, 0x1C),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BktrRelocationEntry {
    pub virt_offset: u64,
    pub phys_offset: u64,
    pub is_patch: u32,
    /// Virtual offset of the following entry (or `bucket.virtual_offset_end` if last in bucket)
    pub next_virt_offset: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BktrSubsectionEntry {
    pub offset: u64,
    pub _0x8: u32,
    pub ctr_val: u32,
    /// Physical offset of the following entry (or `bucket.physical_offset_end` if last in bucket)
    pub next_offset: u64,
}

#[inline]
fn get_relocation_bucket_ofs(i: u32) -> usize {
    // block->buckets starts at 0x4000; each step in bktr.c is sizeof(bucket) + sizeof(entry) = 0x4000 + 20 = 0x4014
    0x4000 + (i as usize) * 0x4014
}

#[inline]
fn read_reloc_entry(bucket_bytes: &[u8], idx: u32, num_entries: u32, virt_end: u64) -> BktrRelocationEntry {
    let base = 0x10 + (idx as usize) * 20;
    let virt_offset = read_u64_le(bucket_bytes, base);
    let phys_offset = read_u64_le(bucket_bytes, base + 8);
    let is_patch = read_u32_le(bucket_bytes, base + 16);
    // In `nca.c`: `(reloc + 1)->virt_offset` reads 8 bytes at `base + 20`.
    // When `idx == num_entries - 1`, `entries[num_entries]` was filled with `virtual_offset_end` in `nca.c`!
    let next_virt_offset = if idx + 1 < num_entries {
        read_u64_le(bucket_bytes, base + 20)
    } else {
        virt_end
    };
    BktrRelocationEntry {
        virt_offset,
        phys_offset,
        is_patch,
        next_virt_offset,
    }
}

pub fn bktr_get_relocation(block: &[u8], offset: u64) -> BktrRelocationEntry {
    let num_buckets = read_u32_le(block, 4);
    let total_size = read_u64_le(block, 8);

    if offset > total_size {
        eprintln!("Too big offset looked up in BKTR relocation table!");
        process::exit(1);
    }

    let mut bucket_num = 0u32;
    for i in 1..num_buckets {
        let b_virt_ofs = read_u64_le(block, 0x10 + (i as usize) * 8);
        if b_virt_ofs <= offset {
            bucket_num += 1;
        }
    }

    let b_ofs = get_relocation_bucket_ofs(bucket_num);
    let bucket = &block[b_ofs..];
    let num_entries = read_u32_le(bucket, 4);
    let virt_end = read_u64_le(bucket, 8);

    if num_entries == 1 {
        return read_reloc_entry(bucket, 0, num_entries, virt_end);
    }

    let mut low = 0u32;
    let mut high = num_entries - 1;
    while low <= high {
        let mid = (low + high) / 2;
        let entry = read_reloc_entry(bucket, mid, num_entries, virt_end);
        if entry.virt_offset > offset {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        } else {
            if mid == num_entries - 1 || entry.next_virt_offset > offset {
                return entry;
            }
            low = mid + 1;
        }
    }

    eprintln!(
        "Failed to find offset {:012x} in BKTR relocation table!",
        offset
    );
    process::exit(1);
}

#[inline]
fn get_subsection_bucket_ofs(i: u32) -> usize {
    // block->buckets starts at 0x4000; each step in bktr.c is sizeof(bucket) + sizeof(entry) = 0x4000 + 16 = 0x4010
    0x4000 + (i as usize) * 0x4010
}

#[inline]
fn read_subsec_entry(bucket_bytes: &[u8], idx: u32) -> BktrSubsectionEntry {
    let base = 0x10 + (idx as usize) * 16;
    let offset = read_u64_le(bucket_bytes, base);
    let _0x8 = read_u32_le(bucket_bytes, base + 8);
    let ctr_val = read_u32_le(bucket_bytes, base + 12);
    let next_offset = read_u64_le(bucket_bytes, base + 16);
    BktrSubsectionEntry {
        offset,
        _0x8,
        ctr_val,
        next_offset,
    }
}

pub fn bktr_get_subsection(block: &[u8], offset: u64) -> BktrSubsectionEntry {
    let num_buckets = read_u32_le(block, 4);
    let last_b_ofs = get_subsection_bucket_ofs(num_buckets - 1);
    let last_bucket = &block[last_b_ofs..];
    let last_num_entries = read_u32_le(last_bucket, 4);
    let tail_entry = read_subsec_entry(last_bucket, last_num_entries);
    if offset >= tail_entry.offset {
        return tail_entry;
    }

    let mut bucket_num = 0u32;
    for i in 1..num_buckets {
        let b_phys_ofs = read_u64_le(block, 0x10 + (i as usize) * 8);
        if b_phys_ofs <= offset {
            bucket_num += 1;
        }
    }

    let b_ofs = get_subsection_bucket_ofs(bucket_num);
    let bucket = &block[b_ofs..];
    let num_entries = read_u32_le(bucket, 4);

    if num_entries == 1 {
        return read_subsec_entry(bucket, 0);
    }

    let mut low = 0u32;
    let mut high = num_entries - 1;
    while low <= high {
        let mid = (low + high) / 2;
        let entry = read_subsec_entry(bucket, mid);
        if entry.offset > offset {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        } else {
            if mid == num_entries - 1 || entry.next_offset > offset {
                return entry;
            }
            low = mid + 1;
        }
    }

    eprintln!(
        "Failed to find offset {:012x} in BKTR subsection table!",
        offset
    );
    process::exit(1);
}

