use crate::aes::aes_calculate_cmac;
use crate::romfs::{IvfcLevelHdr, IVFC_MAX_LEVEL};
use crate::settings::HactoolCtx;
use crate::sha::{sha256_get_buffer_hmac, Sha256};
use crate::types::{
    read_u32_le, read_u64_le, Filepath, SharedFile, Validity, ACTION_EXTRACT, ACTION_INFO,
    ACTION_LISTFILES, ACTION_LISTROMFS, ACTION_VERIFY, MAGIC_DISF, MAGIC_DPFS, MAGIC_IVFC,
    MAGIC_JNGL, MAGIC_RMAP, MAGIC_SAVE,
};
use crate::utils::{
    check_memory_hash_table, create_uncompressed_file, memdump_stdout, os_makedir, print_magic,
    with_worker_scratch, SCRATCH_BUF_SIZE,
};
use std::io::Write;
use std::process;

pub const SAVE_HEADER_SIZE: usize = 0x4000;
pub const SAVE_FAT_ENTRY_SIZE: usize = 8;
pub const SAVE_FS_LIST_MAX_NAME_LENGTH: usize = 0x40;
pub const SAVE_FS_LIST_ENTRY_SIZE: usize = 0x60;

#[derive(Clone, Debug, Default)]
pub struct FsLayout {
    pub magic: u32,
    pub version: u32,
    pub hash: [u8; 0x20],
    pub file_map_entry_offset: u64,
    pub file_map_entry_size: u64,
    pub meta_map_entry_offset: u64,
    pub meta_map_entry_size: u64,
    pub file_map_data_offset: u64,
    pub file_map_data_size: u64,
    pub duplex_l1_offset_a: u64,
    pub duplex_l1_offset_b: u64,
    pub duplex_l1_size: u64,
    pub duplex_data_offset_a: u64,
    pub duplex_data_offset_b: u64,
    pub duplex_data_size: u64,
    pub journal_data_offset: u64,
    pub journal_data_size_a: u64,
    pub journal_data_size_b: u64,
    pub journal_size: u64,
    pub duplex_master_offset_a: u64,
    pub duplex_master_offset_b: u64,
    pub duplex_master_size: u64,
    pub ivfc_master_hash_offset_a: u64,
    pub ivfc_master_hash_offset_b: u64,
    pub ivfc_master_hash_size: u64,
    pub journal_map_table_offset: u64,
    pub journal_map_table_size: u64,
    pub journal_physical_bitmap_offset: u64,
    pub journal_physical_bitmap_size: u64,
    pub journal_virtual_bitmap_offset: u64,
    pub journal_virtual_bitmap_size: u64,
    pub journal_free_bitmap_offset: u64,
    pub journal_free_bitmap_size: u64,
    pub ivfc_l1_offset: u64,
    pub ivfc_l1_size: u64,
    pub ivfc_l2_offset: u64,
    pub ivfc_l2_size: u64,
    pub ivfc_l3_offset: u64,
    pub ivfc_l3_size: u64,
    pub fat_offset: u64,
    pub fat_size: u64,
    pub duplex_index: u64,
    pub fat_ivfc_master_hash_a: u64,
    pub fat_ivfc_master_hash_b: u64,
    pub fat_ivfc_l1_offset: u64,
    pub fat_ivfc_l1_size: u64,
    pub fat_ivfc_l2_offset: u64,
    pub fat_ivfc_l2_size: u64,
}

impl FsLayout {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut l = Self::default();
        if data.len() < 0x200 {
            return l;
        }
        l.magic = read_u32_le(data, 0x00);
        l.version = read_u32_le(data, 0x04);
        l.hash.copy_from_slice(&data[0x08..0x28]);
        l.file_map_entry_offset = read_u64_le(data, 0x28);
        l.file_map_entry_size = read_u64_le(data, 0x30);
        l.meta_map_entry_offset = read_u64_le(data, 0x38);
        l.meta_map_entry_size = read_u64_le(data, 0x40);
        l.file_map_data_offset = read_u64_le(data, 0x48);
        l.file_map_data_size = read_u64_le(data, 0x50);
        l.duplex_l1_offset_a = read_u64_le(data, 0x58);
        l.duplex_l1_offset_b = read_u64_le(data, 0x60);
        l.duplex_l1_size = read_u64_le(data, 0x68);
        l.duplex_data_offset_a = read_u64_le(data, 0x70);
        l.duplex_data_offset_b = read_u64_le(data, 0x78);
        l.duplex_data_size = read_u64_le(data, 0x80);
        l.journal_data_offset = read_u64_le(data, 0x88);
        l.journal_data_size_a = read_u64_le(data, 0x90);
        l.journal_data_size_b = read_u64_le(data, 0x98);
        l.journal_size = read_u64_le(data, 0xA0);
        l.duplex_master_offset_a = read_u64_le(data, 0xA8);
        l.duplex_master_offset_b = read_u64_le(data, 0xB0);
        l.duplex_master_size = read_u64_le(data, 0xB8);
        l.ivfc_master_hash_offset_a = read_u64_le(data, 0xC0);
        l.ivfc_master_hash_offset_b = read_u64_le(data, 0xC8);
        l.ivfc_master_hash_size = read_u64_le(data, 0xD0);
        l.journal_map_table_offset = read_u64_le(data, 0xD8);
        l.journal_map_table_size = read_u64_le(data, 0xE0);
        l.journal_physical_bitmap_offset = read_u64_le(data, 0xE8);
        l.journal_physical_bitmap_size = read_u64_le(data, 0xF0);
        l.journal_virtual_bitmap_offset = read_u64_le(data, 0xF8);
        l.journal_virtual_bitmap_size = read_u64_le(data, 0x100);
        l.journal_free_bitmap_offset = read_u64_le(data, 0x108);
        l.journal_free_bitmap_size = read_u64_le(data, 0x110);
        l.ivfc_l1_offset = read_u64_le(data, 0x118);
        l.ivfc_l1_size = read_u64_le(data, 0x120);
        l.ivfc_l2_offset = read_u64_le(data, 0x128);
        l.ivfc_l2_size = read_u64_le(data, 0x130);
        l.ivfc_l3_offset = read_u64_le(data, 0x138);
        l.ivfc_l3_size = read_u64_le(data, 0x140);
        l.fat_offset = read_u64_le(data, 0x148);
        l.fat_size = read_u64_le(data, 0x150);
        l.duplex_index = read_u64_le(data, 0x158);
        l.fat_ivfc_master_hash_a = read_u64_le(data, 0x160);
        l.fat_ivfc_master_hash_b = read_u64_le(data, 0x168);
        l.fat_ivfc_l1_offset = read_u64_le(data, 0x170);
        l.fat_ivfc_l1_size = read_u64_le(data, 0x178);
        l.fat_ivfc_l2_offset = read_u64_le(data, 0x180);
        l.fat_ivfc_l2_size = read_u64_le(data, 0x188);
        l
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DuplexInfo {
    pub offset: u64,
    pub length: u64,
    pub block_size_power: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DuplexHeader {
    pub magic: u32,
    pub version: u32,
    pub layers: [DuplexInfo; 3],
}

impl DuplexHeader {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut h = Self::default();
        if data.len() < 0x44 {
            return h;
        }
        h.magic = read_u32_le(data, 0x00);
        h.version = read_u32_le(data, 0x04);
        for i in 0..3 {
            let base = 0x08 + i * 0x14;
            h.layers[i] = DuplexInfo {
                offset: read_u64_le(data, base),
                length: read_u64_le(data, base + 0x08),
                block_size_power: read_u32_le(data, base + 0x10),
            };
        }
        h
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IvfcSaveHdr {
    pub magic: u32,
    pub id: u32,
    pub master_hash_size: u32,
    pub num_levels: u32,
    pub level_headers: [IvfcLevelHdr; IVFC_MAX_LEVEL],
    pub salt_source: [u8; 0x20],
}

impl IvfcSaveHdr {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut h = Self::default();
        if data.len() < 0xC0 {
            return h;
        }
        h.magic = read_u32_le(data, 0x00);
        h.id = read_u32_le(data, 0x04);
        h.master_hash_size = read_u32_le(data, 0x08);
        h.num_levels = read_u32_le(data, 0x0C);
        for i in 0..IVFC_MAX_LEVEL {
            h.level_headers[i] = IvfcLevelHdr::from_bytes(&data[0x10 + i * 0x18..]);
        }
        h.salt_source.copy_from_slice(&data[0xA0..0xC0]);
        h
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct JournalHeader {
    pub magic: u32,
    pub version: u32,
    pub total_size: u64,
    pub journal_size: u64,
    pub block_size: u64,
}

impl JournalHeader {
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < 0x20 {
            return Self::default();
        }
        Self {
            magic: read_u32_le(data, 0x00),
            version: read_u32_le(data, 0x04),
            total_size: read_u64_le(data, 0x08),
            journal_size: read_u64_le(data, 0x10),
            block_size: read_u64_le(data, 0x18),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct JournalMapHeader {
    pub version: u32,
    pub main_data_block_count: u32,
    pub journal_block_count: u32,
    pub _0x0c: u32,
}

impl JournalMapHeader {
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < 0x10 {
            return Self::default();
        }
        Self {
            version: read_u32_le(data, 0x00),
            main_data_block_count: read_u32_le(data, 0x04),
            journal_block_count: read_u32_le(data, 0x08),
            _0x0c: read_u32_le(data, 0x0C),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SaveFsHeader {
    pub magic: u32,
    pub version: u32,
    pub block_count: u64,
    pub block_size: u64,
}

impl SaveFsHeader {
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < 0x18 {
            return Self::default();
        }
        Self {
            magic: read_u32_le(data, 0x00),
            version: read_u32_le(data, 0x04),
            block_count: read_u64_le(data, 0x08),
            block_size: read_u64_le(data, 0x10),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FatHeader {
    pub block_size: u64,
    pub allocation_table_offset: u64,
    pub allocation_table_block_count: u32,
    pub _0x14: u32,
    pub data_offset: u64,
    pub data_block_count: u32,
    pub _0x24: u32,
    pub directory_table_block: u32,
    pub file_table_block: u32,
}

impl FatHeader {
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < 0x30 {
            return Self::default();
        }
        Self {
            block_size: read_u64_le(data, 0x00),
            allocation_table_offset: read_u64_le(data, 0x08),
            allocation_table_block_count: read_u32_le(data, 0x10),
            _0x14: read_u32_le(data, 0x14),
            data_offset: read_u64_le(data, 0x18),
            data_block_count: read_u32_le(data, 0x20),
            _0x24: read_u32_le(data, 0x24),
            directory_table_block: read_u32_le(data, 0x28),
            file_table_block: read_u32_le(data, 0x2C),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RemapHeader {
    pub magic: u32,
    pub version: u32,
    pub map_entry_count: u32,
    pub map_segment_count: u32,
    pub segment_bits: u32,
}

impl RemapHeader {
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < 0x40 {
            return Self::default();
        }
        Self {
            magic: read_u32_le(data, 0x00),
            version: read_u32_le(data, 0x04),
            map_entry_count: read_u32_le(data, 0x08),
            map_segment_count: read_u32_le(data, 0x0C),
            segment_bits: read_u32_le(data, 0x10),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ExtraData {
    pub title_id: u64,
    pub user_id: [u8; 0x10],
    pub save_id: u64,
    pub save_data_type: u8,
    pub save_owner_id: u64,
    pub timestamp: u64,
    pub _0x50: u64,
    pub data_size: u64,
    pub journal_size: u64,
    pub commit_id: u64,
}

impl ExtraData {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut e = Self::default();
        if data.len() < 0x70 {
            return e;
        }
        e.title_id = read_u64_le(data, 0x00);
        e.user_id.copy_from_slice(&data[0x08..0x18]);
        e.save_id = read_u64_le(data, 0x18);
        e.save_data_type = data[0x20];
        e.save_owner_id = read_u64_le(data, 0x40);
        e.timestamp = read_u64_le(data, 0x48);
        e._0x50 = read_u64_le(data, 0x50);
        e.data_size = read_u64_le(data, 0x58);
        e.journal_size = read_u64_le(data, 0x60);
        e.commit_id = read_u64_le(data, 0x68);
        e
    }
}

#[derive(Clone)]
pub struct SaveHeader {
    pub cmac: [u8; 0x10],
    pub layout: FsLayout,
    pub duplex_header: DuplexHeader,
    pub data_ivfc_header: IvfcSaveHdr,
    pub journal_header: JournalHeader,
    pub map_header: JournalMapHeader,
    pub save_header: SaveFsHeader,
    pub fat_header: FatHeader,
    pub main_remap_header: RemapHeader,
    pub meta_remap_header: RemapHeader,
    pub extra_data: ExtraData,
    pub fat_ivfc_header: IvfcSaveHdr,
    pub raw_bytes: Vec<u8>,
}

impl Default for SaveHeader {
    fn default() -> Self {
        Self {
            cmac: [0u8; 0x10],
            layout: FsLayout::default(),
            duplex_header: DuplexHeader::default(),
            data_ivfc_header: IvfcSaveHdr::default(),
            journal_header: JournalHeader::default(),
            map_header: JournalMapHeader::default(),
            save_header: SaveFsHeader::default(),
            fat_header: FatHeader::default(),
            main_remap_header: RemapHeader::default(),
            meta_remap_header: RemapHeader::default(),
            extra_data: ExtraData::default(),
            fat_ivfc_header: IvfcSaveHdr::default(),
            raw_bytes: vec![0u8; SAVE_HEADER_SIZE],
        }
    }
}

impl SaveHeader {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut h = Self::default();
        if data.len() < SAVE_HEADER_SIZE {
            return h;
        }
        h.raw_bytes.copy_from_slice(&data[..SAVE_HEADER_SIZE]);
        h.cmac.copy_from_slice(&data[0x00..0x10]);
        h.layout = FsLayout::from_bytes(&data[0x100..0x300]);
        h.duplex_header = DuplexHeader::from_bytes(&data[0x300..0x344]);
        h.data_ivfc_header = IvfcSaveHdr::from_bytes(&data[0x344..0x404]);
        h.journal_header = JournalHeader::from_bytes(&data[0x408..0x428]);
        h.map_header = JournalMapHeader::from_bytes(&data[0x428..0x438]);
        h.save_header = SaveFsHeader::from_bytes(&data[0x608..0x620]);
        h.fat_header = FatHeader::from_bytes(&data[0x620..0x650]);
        h.main_remap_header = RemapHeader::from_bytes(&data[0x650..0x690]);
        h.meta_remap_header = RemapHeader::from_bytes(&data[0x690..0x6D0]);
        h.extra_data = ExtraData::from_bytes(&data[0x6D8..0x748]);
        h.fat_ivfc_header = IvfcSaveHdr::from_bytes(&data[0xAD8..0xB98]);
        h
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RemapEntry {
    pub virtual_offset: u64,
    pub physical_offset: u64,
    pub size: u64,
    pub alignment: u32,
    pub _0x1c: u32,
    pub virtual_offset_end: u64,
    pub physical_offset_end: u64,
    pub next_idx: Option<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct RemapSegment {
    pub offset: u64,
    pub length: u64,
    pub entry_indices: Vec<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct DuplexStorageCtx {
    pub block_size: u32,
    pub data_a: Vec<u8>,
    pub data_b: Vec<u8>,
    pub bitmap: Vec<u8>,
    pub length: u64,
}

#[inline]
fn save_bitmap_set_bit(buffer: &mut [u8], bit_offset: usize) {
    buffer[bit_offset >> 3] |= 1 << (bit_offset & 7);
}

#[inline]
fn save_bitmap_clear_bit(buffer: &mut [u8], bit_offset: usize) {
    buffer[bit_offset >> 3] &= !(1 << (bit_offset & 7));
}

#[inline]
fn save_bitmap_check_bit(buffer: &[u8], bit_offset: usize) -> bool {
    (buffer[bit_offset >> 3] & (1 << (bit_offset & 7))) != 0
}

impl DuplexStorageCtx {
    pub fn init(data_a: Vec<u8>, data_b: Vec<u8>, block_size_power: u32, raw_bitmap: &[u8], bitmap_size: u64) -> Self {
        let block_size = 1u32 << block_size_power;
        let mut bitmap = vec![0u8; (bitmap_size >> 3) as usize];
        let mut bits_remaining = bitmap_size as u32;
        let mut bitmap_pos = 0usize;
        let mut word_idx = 0usize;
        while bits_remaining > 0 {
            let bits_to_read = bits_remaining.min(32);
            let mut val = if (word_idx + 1) * 4 <= raw_bitmap.len() {
                read_u32_le(raw_bitmap, word_idx * 4)
            } else {
                0
            };
            for _ in 0..bits_to_read {
                if (val & 0x8000_0000) != 0 {
                    save_bitmap_set_bit(&mut bitmap, bitmap_pos);
                } else {
                    save_bitmap_clear_bit(&mut bitmap, bitmap_pos);
                }
                bitmap_pos += 1;
                bits_remaining -= 1;
                val <<= 1;
            }
            word_idx += 1;
        }
        Self {
            block_size,
            data_a,
            data_b,
            bitmap,
            length: 0,
        }
    }

    pub fn read(&self, buffer: &mut [u8], offset: u64) -> usize {
        let mut in_pos = offset as usize;
        let mut out_pos = 0usize;
        let mut remaining = buffer.len();
        let blk_sz = self.block_size as usize;

        while remaining > 0 {
            let block_num = in_pos / blk_sz;
            let block_pos = in_pos % blk_sz;
            let bytes_to_read = (blk_sz - block_pos).min(remaining);

            let data = if save_bitmap_check_bit(&self.bitmap, block_num) {
                &self.data_b
            } else {
                &self.data_a
            };
            buffer[out_pos..out_pos + bytes_to_read]
                .copy_from_slice(&data[in_pos..in_pos + bytes_to_read]);

            out_pos += bytes_to_read;
            in_pos += bytes_to_read;
            remaining -= bytes_to_read;
        }
        out_pos
    }
}

#[derive(Clone, Debug, Default)]
pub struct RemapStorageCtx {
    pub header: RemapHeader,
    pub map_entries: Vec<RemapEntry>,
    pub segments: Vec<RemapSegment>,
    pub base_storage_offset: u64,
}

impl RemapStorageCtx {
    pub fn init_segments(&mut self) {
        let mut segments = Vec::with_capacity(self.header.map_segment_count as usize);
        let num_entries = self.map_entries.len();
        let mut entry_idx = 0usize;

        for _ in 0..self.header.map_segment_count {
            let mut seg = RemapSegment::default();
            if entry_idx < num_entries {
                seg.entry_indices.push(entry_idx);
                seg.offset = self.map_entries[entry_idx].virtual_offset;
                entry_idx += 1;

                while entry_idx < num_entries
                    && self.map_entries[entry_idx - 1].virtual_offset_end
                        == self.map_entries[entry_idx].virtual_offset
                {
                    self.map_entries[entry_idx - 1].next_idx = Some(entry_idx);
                    seg.entry_indices.push(entry_idx);
                    entry_idx += 1;
                }
                let first_idx = *seg.entry_indices.first().unwrap();
                let last_idx = *seg.entry_indices.last().unwrap();
                seg.length = self.map_entries[last_idx].virtual_offset_end
                    - self.map_entries[first_idx].virtual_offset;
            }
            segments.push(seg);
        }
        self.segments = segments;
    }

    pub fn get_map_entry_index(&self, offset: u64) -> usize {
        let segment_idx = (offset >> (64 - self.header.segment_bits)) as usize;
        if segment_idx < self.segments.len() {
            for &e_idx in &self.segments[segment_idx].entry_indices {
                if self.map_entries[e_idx].virtual_offset_end > offset {
                    return e_idx;
                }
            }
        }
        eprintln!("Remap offset {:x} out of range!", offset);
        process::exit(1);
    }

    pub fn read_bytes(&self, file: &SharedFile, buffer: &mut [u8], offset: u64) -> usize {
        if buffer.is_empty() {
            return 0;
        }
        let mut entry_idx = self.get_map_entry_index(offset);
        let mut in_pos = offset;
        let mut out_pos = 0usize;
        let mut remaining = buffer.len();

        while remaining > 0 {
            let entry = &self.map_entries[entry_idx];
            let entry_pos = in_pos - entry.virtual_offset;
            let bytes_to_read = ((entry.virtual_offset_end - in_pos) as usize).min(remaining);

            let phys = self.base_storage_offset + entry.physical_offset + entry_pos;
            let _ = file.read_at(phys, &mut buffer[out_pos..out_pos + bytes_to_read]);

            out_pos += bytes_to_read;
            in_pos += bytes_to_read as u64;
            remaining -= bytes_to_read;

            if remaining > 0 && in_pos >= entry.virtual_offset_end {
                entry_idx = entry.next_idx.unwrap_or_else(|| {
                    eprintln!("Remap offset {:x} out of range!", in_pos);
                    process::exit(1);
                });
            }
        }
        out_pos
    }

    pub fn read_duplex(&self, duplex: &DuplexStorageCtx, buffer: &mut [u8], offset: u64) -> usize {
        if buffer.is_empty() {
            return 0;
        }
        let mut entry_idx = self.get_map_entry_index(offset);
        let mut in_pos = offset;
        let mut out_pos = 0usize;
        let mut remaining = buffer.len();

        while remaining > 0 {
            let entry = &self.map_entries[entry_idx];
            let entry_pos = in_pos - entry.virtual_offset;
            let bytes_to_read = ((entry.virtual_offset_end - in_pos) as usize).min(remaining);

            let phys = self.base_storage_offset + entry.physical_offset + entry_pos;
            duplex.read(&mut buffer[out_pos..out_pos + bytes_to_read], phys);

            out_pos += bytes_to_read;
            in_pos += bytes_to_read as u64;
            remaining -= bytes_to_read;

            if remaining > 0 && in_pos >= entry.virtual_offset_end {
                entry_idx = entry.next_idx.unwrap_or_else(|| {
                    eprintln!("Remap offset {:x} out of range!", in_pos);
                    process::exit(1);
                });
            }
        }
        out_pos
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct JournalMapEntry {
    pub physical_index: u32,
    pub virtual_index: u32,
}

#[derive(Clone, Debug, Default)]
pub struct JournalStorageCtx {
    pub entries: Vec<JournalMapEntry>,
    pub block_size: u64,
    pub journal_data_offset: u64,
    pub length: u64,
}

impl JournalStorageCtx {
    pub fn read(
        &self,
        data_remap: &RemapStorageCtx,
        file: &SharedFile,
        buffer: &mut [u8],
        offset: u64,
    ) -> usize {
        let mut in_pos = offset;
        let mut out_pos = 0usize;
        let mut remaining = buffer.len();

        while remaining > 0 {
            let block_num = (in_pos / self.block_size) as usize;
            let block_pos = in_pos % self.block_size;
            let physical_offset =
                self.entries[block_num].physical_index as u64 * self.block_size + block_pos;
            let bytes_to_read = ((self.block_size - block_pos) as usize).min(remaining);

            data_remap.read_bytes(
                file,
                &mut buffer[out_pos..out_pos + bytes_to_read],
                self.journal_data_offset + physical_offset,
            );

            out_pos += bytes_to_read;
            in_pos += bytes_to_read as u64;
            remaining -= bytes_to_read;
        }
        out_pos
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BaseStorageType {
    #[default]
    Bytes,
    Duplex,
    Remap,
    Journal,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IvfcLevelSaveCtx {
    pub data_offset: u64,
    pub data_size: u64,
    pub hash_offset: u64,
    pub hash_block_size: u32,
    pub hash_validity: Validity,
    pub storage_type: BaseStorageType,
}

#[derive(Clone, Debug, Default)]
pub struct IntegrityVerificationStorageCtx {
    pub hash_level_idx: usize,
    pub base_level_idx: usize,
    pub block_validities: Vec<Validity>,
    pub salt: [u8; 0x20],
    pub sector_size: u32,
    pub sector_count: u32,
    pub length: u64,
}

#[derive(Clone, Debug, Default)]
pub struct HierarchicalIntegrityVerificationStorageCtx {
    pub levels: [IvfcLevelSaveCtx; 5],
    pub integrity_storages: [IntegrityVerificationStorageCtx; 4],
    pub num_levels: usize,
    pub length: u64,
    pub initialized: bool,
}

const SALT_SOURCES: [&[u8]; 6] = [
    b"HierarchicalIntegrityVerificationStorage::Master",
    b"HierarchicalIntegrityVerificationStorage::L1",
    b"HierarchicalIntegrityVerificationStorage::L2",
    b"HierarchicalIntegrityVerificationStorage::L3",
    b"HierarchicalIntegrityVerificationStorage::L4",
    b"HierarchicalIntegrityVerificationStorage::L5",
];

impl HierarchicalIntegrityVerificationStorageCtx {
    pub fn init(&mut self, master_hash_offset: u64, ivfc: &IvfcSaveHdr) {
        self.num_levels = ivfc.num_levels as usize;
        self.levels[0].storage_type = BaseStorageType::Bytes;
        self.levels[0].hash_offset = master_hash_offset;
        for i in 1..4 {
            let level = &ivfc.level_headers[i - 1];
            self.levels[i].storage_type = BaseStorageType::Remap;
            self.levels[i].data_offset = level.logical_offset;
            self.levels[i].data_size = level.hash_data_size;
        }
        if self.num_levels == 5 {
            let data_level = &ivfc.level_headers[self.num_levels - 2];
            self.levels[self.num_levels - 1].storage_type = BaseStorageType::Journal;
            self.levels[self.num_levels - 1].data_offset = data_level.logical_offset;
            self.levels[self.num_levels - 1].data_size = data_level.hash_data_size;
        }

        for i in 1..self.num_levels {
            let block_size = 1u32 << ivfc.level_headers[i - 1].block_size;
            let mut salt = [0u8; 0x20];
            sha256_get_buffer_hmac(&mut salt, SALT_SOURCES[i - 1], &ivfc.salt_source);

            let data_len = self.levels[i].data_size;
            let sector_count = ((data_len + block_size as u64 - 1) / block_size as u64) as u32;

            self.integrity_storages[i - 1] = IntegrityVerificationStorageCtx {
                hash_level_idx: i - 1,
                base_level_idx: i,
                block_validities: vec![Validity::Unchecked; sector_count as usize],
                salt,
                sector_size: block_size,
                sector_count,
                length: data_len,
            };
        }
        self.length = self.integrity_storages[self.num_levels - 2].length;
        self.initialized = true;
    }

    fn level_fread(
        &self,
        level_idx: usize,
        file: &SharedFile,
        meta_remap: &RemapStorageCtx,
        duplex: &DuplexStorageCtx,
        journal: &JournalStorageCtx,
        data_remap: &RemapStorageCtx,
        buffer: &mut [u8],
        offset: u64,
    ) {
        let lvl = &self.levels[level_idx];
        match lvl.storage_type {
            BaseStorageType::Bytes => {
                let _ = file.read_at(lvl.hash_offset + offset, buffer);
            }
            BaseStorageType::Remap => {
                meta_remap.read_duplex(duplex, buffer, lvl.data_offset + offset);
            }
            BaseStorageType::Journal => {
                journal.read(data_remap, file, buffer, lvl.data_offset + offset);
            }
            BaseStorageType::Duplex => {}
        }
    }

    pub fn storage_read(
        &mut self,
        storage_idx: usize,
        file: &SharedFile,
        meta_remap: &RemapStorageCtx,
        duplex: &DuplexStorageCtx,
        journal: &JournalStorageCtx,
        data_remap: &RemapStorageCtx,
        buffer: &mut [u8],
        offset: u64,
        verify: bool,
    ) {
        let sector_size = self.integrity_storages[storage_idx].sector_size as usize;
        if buffer.len() > sector_size {
            eprintln!("IVFC read exceeds sector size!");
            process::exit(1);
        }

        let block_index = (offset / sector_size as u64) as usize;
        if self.integrity_storages[storage_idx].block_validities[block_index] == Validity::Invalid
            && verify
        {
            eprintln!("Hash error!");
            process::exit(1);
        }

        let mut hash_buffer = [0u8; 0x20];
        let hash_pos = (block_index * 0x20) as u64;
        if storage_idx > 0 {
            self.storage_read(
                storage_idx - 1,
                file,
                meta_remap,
                duplex,
                journal,
                data_remap,
                &mut hash_buffer,
                hash_pos,
                verify,
            );
        } else {
            let hash_lvl = self.integrity_storages[storage_idx].hash_level_idx;
            self.level_fread(
                hash_lvl,
                file,
                meta_remap,
                duplex,
                journal,
                data_remap,
                &mut hash_buffer,
                hash_pos,
            );
        }

        if hash_buffer == [0u8; 0x20] {
            buffer.fill(0);
            self.integrity_storages[storage_idx].block_validities[block_index] = Validity::Valid;
            return;
        }

        let base_lvl = self.integrity_storages[storage_idx].base_level_idx;
        self.level_fread(
            base_lvl,
            file,
            meta_remap,
            duplex,
            journal,
            data_remap,
            buffer,
            offset,
        );

        if !(verify
            && self.integrity_storages[storage_idx].block_validities[block_index]
                == Validity::Unchecked)
        {
            return;
        }

        let mut data_buffer = vec![0u8; sector_size];
        data_buffer[..buffer.len()].copy_from_slice(buffer);

        let mut sha = Sha256::new();
        sha.update(&self.integrity_storages[storage_idx].salt);
        sha.update(&data_buffer);
        let mut hash = sha.finalize();
        hash[0x1F] |= 0x80;

        if hash_buffer == hash {
            self.integrity_storages[storage_idx].block_validities[block_index] = Validity::Valid;
        } else {
            self.integrity_storages[storage_idx].block_validities[block_index] = Validity::Invalid;
        }

        if self.integrity_storages[storage_idx].block_validities[block_index] == Validity::Invalid
            && verify
        {
            eprintln!("Hash error!");
            process::exit(1);
        }
    }

    pub fn validate(
        &mut self,
        ivfc: &IvfcSaveHdr,
        file: &SharedFile,
        meta_remap: &RemapStorageCtx,
        duplex: &DuplexStorageCtx,
        journal: &JournalStorageCtx,
        data_remap: &RemapStorageCtx,
    ) -> Validity {
        let mut result = Validity::Valid;
        let num_storages = (ivfc.num_levels - 1) as usize;
        let last_storage_idx = num_storages - 1;

        for i in 0..num_storages {
            if result == Validity::Invalid {
                break;
            }
            let block_size = self.integrity_storages[i].sector_size as u64;
            let length = self.integrity_storages[i].length;
            let block_count = ((length + block_size - 1) / block_size) as usize;
            let mut buffer = vec![0u8; block_size as usize];

            for j in 0..block_count {
                // Replicate C check: `ctx->level_validities[ivfc->num_levels - 2][j]`
                let validity_j = self.integrity_storages[last_storage_idx]
                    .block_validities
                    .get(j)
                    .copied()
                    .unwrap_or(Validity::Unchecked);
                if validity_j == Validity::Unchecked {
                    let to_read = (length - block_size * j as u64).min(block_size) as usize;
                    self.storage_read(
                        i,
                        file,
                        meta_remap,
                        duplex,
                        journal,
                        data_remap,
                        &mut buffer[..to_read],
                        block_size * j as u64,
                        true,
                    );
                }
                let validity_after = self.integrity_storages[last_storage_idx]
                    .block_validities
                    .get(j)
                    .copied()
                    .unwrap_or(Validity::Unchecked);
                if validity_after == Validity::Invalid {
                    result = Validity::Invalid;
                    break;
                }
            }
        }
        result
    }

    pub fn set_level_validities(&mut self, ivfc: &IvfcSaveHdr) {
        let num_storages = (ivfc.num_levels - 1) as usize;
        for i in 0..num_storages {
            let mut level_validity = Validity::Valid;
            for &v in &self.integrity_storages[i].block_validities {
                if v == Validity::Invalid {
                    level_validity = Validity::Invalid;
                    break;
                }
                if v == Validity::Unchecked && level_validity != Validity::Invalid {
                    level_validity = Validity::Unchecked;
                }
            }
            self.levels[i].hash_validity = level_validity;
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AllocationTableEntry {
    pub prev: u32,
    pub next: u32,
}

impl AllocationTableEntry {
    #[inline]
    pub fn is_list_end(&self) -> bool {
        (self.next & 0x7FFF_FFFF) == 0
    }

    #[inline]
    pub fn is_list_start(&self) -> bool {
        self.prev == 0x8000_0000
    }

    #[inline]
    pub fn get_next(&self) -> u32 {
        self.next & 0x7FFF_FFFF
    }

    #[inline]
    pub fn get_prev(&self) -> u32 {
        self.prev & 0x7FFF_FFFF
    }
}

#[inline]
pub fn allocation_table_entry_index_to_block(entry_index: u32) -> u32 {
    entry_index.wrapping_sub(1)
}

#[inline]
pub fn allocation_table_block_to_entry_index(block_index: u32) -> u32 {
    block_index.wrapping_add(1)
}

pub fn save_allocation_table_read_entry(fat: &[u8], entry_index: u32) -> AllocationTableEntry {
    let off = (entry_index as usize) * SAVE_FAT_ENTRY_SIZE;
    AllocationTableEntry {
        prev: read_u32_le(fat, off),
        next: read_u32_le(fat, off + 4),
    }
}

pub fn save_allocation_table_read_entry_with_length(
    fat: &[u8],
    entry: &mut AllocationTableEntry,
) -> u32 {
    let mut length = 1u32;
    let entry_index = allocation_table_block_to_entry_index(entry.next);
    let e0 = save_allocation_table_read_entry(fat, entry_index);

    if (e0.next & 0x8000_0000) == 0 {
        if (e0.prev & 0x8000_0000) != 0 && e0.prev != 0x8000_0000 {
            eprintln!("Invalid iterated range entry in allocation table!");
            process::exit(1);
        }
    } else {
        let e1 = save_allocation_table_read_entry(fat, entry_index + 1);
        length = e1.next - entry_index + 1;
    }

    if e0.is_list_end() {
        entry.next = 0xFFFF_FFFF;
    } else {
        entry.next = allocation_table_entry_index_to_block(e0.get_next());
    }

    if e0.is_list_start() {
        entry.prev = 0xFFFF_FFFF;
    } else {
        entry.prev = allocation_table_entry_index_to_block(e0.get_prev());
    }

    length
}

pub fn save_allocation_table_get_list_length(
    fat: &[u8],
    fat_header: &FatHeader,
    block_index: u32,
) -> u32 {
    let mut entry = AllocationTableEntry {
        prev: 0,
        next: block_index,
    };
    let mut total_length = 0u32;
    let table_size = fat_header.allocation_table_block_count;
    let mut nodes_iterated = 0u32;

    while entry.next != 0xFFFF_FFFF {
        total_length += save_allocation_table_read_entry_with_length(fat, &mut entry);
        nodes_iterated += 1;
        if nodes_iterated > table_size {
            eprintln!("Cycle detected in allocation table!");
            process::exit(1);
        }
    }
    total_length
}

pub fn save_allocation_table_get_free_space_size(
    fat: &[u8],
    fat_header: &FatHeader,
    save_header: &SaveFsHeader,
) -> u64 {
    let free_entry = save_allocation_table_read_entry(fat, 0).get_next();
    let free_list_start = allocation_table_entry_index_to_block(free_entry);
    if free_list_start == 0xFFFF_FFFF {
        return 0;
    }
    save_header.block_size
        * save_allocation_table_get_list_length(fat, fat_header, free_list_start) as u64
}

pub struct AllocationTableIterator {
    pub virtual_block: u32,
    pub physical_block: u32,
    pub current_segment_size: u32,
    pub next_block: u32,
    pub prev_block: u32,
}

impl AllocationTableIterator {
    pub fn begin(fat: &[u8], initial_block: u32) -> Self {
        let mut entry = AllocationTableEntry {
            prev: 0,
            next: initial_block,
        };
        let current_segment_size = save_allocation_table_read_entry_with_length(fat, &mut entry);
        if entry.prev != 0xFFFF_FFFF {
            eprintln!(
                "Attempted to start FAT iteration from invalid block {:x}!",
                initial_block
            );
            process::exit(1);
        }
        Self {
            virtual_block: 0,
            physical_block: initial_block,
            current_segment_size,
            next_block: entry.next,
            prev_block: entry.prev,
        }
    }

    pub fn move_next(&mut self, fat: &[u8]) -> bool {
        if self.next_block == 0xFFFF_FFFF {
            return false;
        }
        self.virtual_block += self.current_segment_size;
        self.physical_block = self.next_block;

        let mut entry = AllocationTableEntry {
            prev: 0,
            next: self.next_block,
        };
        self.current_segment_size = save_allocation_table_read_entry_with_length(fat, &mut entry);
        self.next_block = entry.next;
        self.prev_block = entry.prev;
        true
    }

    pub fn move_prev(&mut self, fat: &[u8]) -> bool {
        if self.prev_block == 0xFFFF_FFFF {
            return false;
        }
        self.physical_block = self.prev_block;

        let mut entry = AllocationTableEntry {
            prev: 0,
            next: self.prev_block,
        };
        self.current_segment_size = save_allocation_table_read_entry_with_length(fat, &mut entry);
        self.next_block = entry.next;
        self.prev_block = entry.prev;
        self.virtual_block -= self.current_segment_size;
        true
    }

    pub fn seek(&mut self, fat: &[u8], block: u32) -> bool {
        loop {
            if block < self.virtual_block {
                if !self.move_prev(fat) {
                    return false;
                }
            } else if block >= self.virtual_block + self.current_segment_size {
                if !self.move_next(fat) {
                    return false;
                }
            } else {
                return true;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SaveFileInfo {
    pub start_block: u32,
    pub length: u64,
    pub _0xc: [u32; 2],
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SaveFindPosition {
    pub next_directory: u32,
    pub next_file: u32,
    pub _0x8: [u32; 3],
}

#[derive(Clone, Debug, Default)]
pub struct SaveFsListEntry {
    pub parent: u32,
    pub name: String,
    pub next_sibling: u32,
    pub file_info: SaveFileInfo,
    pub find_position: SaveFindPosition,
    pub next: u32,
}

impl SaveFsListEntry {
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < SAVE_FS_LIST_ENTRY_SIZE {
            return Self::default();
        }
        let parent = read_u32_le(data, 0x00);
        let name_slice = &data[0x04..0x44];
        let name_len = name_slice
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(SAVE_FS_LIST_MAX_NAME_LENGTH);
        let name = String::from_utf8_lossy(&name_slice[..name_len]).into_owned();
        let next_sibling = read_u32_le(data, 0x44);

        let file_info = SaveFileInfo {
            start_block: read_u32_le(data, 0x48),
            length: read_u64_le(data, 0x4C),
            _0xc: [read_u32_le(data, 0x54), read_u32_le(data, 0x58)],
        };
        let find_position = SaveFindPosition {
            next_directory: read_u32_le(data, 0x48),
            next_file: read_u32_le(data, 0x4C),
            _0x8: [
                read_u32_le(data, 0x50),
                read_u32_le(data, 0x54),
                read_u32_le(data, 0x58),
            ],
        };
        let next = read_u32_le(data, 0x5C);

        Self {
            parent,
            name,
            next_sibling,
            file_info,
            find_position,
            next,
        }
    }
}

#[derive(Clone, Default)]
pub struct SaveCtx {
    pub file: Option<SharedFile>,
    pub header: SaveHeader,
    pub header_cmac_validity: Validity,
    pub header_hash_validity: Validity,
    pub data_remap_storage: RemapStorageCtx,
    pub meta_remap_storage: RemapStorageCtx,
    pub duplex_layers: [DuplexStorageCtx; 2],
    pub journal_storage: JournalStorageCtx,
    pub core_data_ivfc_storage: HierarchicalIntegrityVerificationStorageCtx,
    pub fat_ivfc_storage: HierarchicalIntegrityVerificationStorageCtx,
    pub fat_storage: Vec<u8>,
    pub dir_table_block: u32,
    pub file_table_block: u32,
    pub block_size: u32,
}

impl SaveCtx {
    pub fn fat_storage_read(
        &mut self,
        initial_block: u32,
        buffer: &mut [u8],
        offset: u64,
        verify: bool,
    ) -> usize {
        if buffer.is_empty() {
            return 0;
        }
        let file = self.file.as_ref().unwrap().clone();
        let blk_size = self.block_size;
        let mut iterator = AllocationTableIterator::begin(&self.fat_storage, initial_block);
        let mut in_pos = offset;
        let mut out_pos = 0usize;
        let mut remaining = buffer.len();

        while remaining > 0 {
            let block_num = (in_pos / blk_size as u64) as u32;
            iterator.seek(&self.fat_storage, block_num);

            let segment_pos = (in_pos - iterator.virtual_block as u64 * blk_size as u64) as u32;
            let physical_offset =
                iterator.physical_block as u64 * blk_size as u64 + segment_pos as u64;

            let remaining_in_segment =
                iterator.current_segment_size * blk_size - segment_pos;
            let bytes_to_read = remaining.min(remaining_in_segment as usize);

            let sector_size = self.core_data_ivfc_storage.integrity_storages[3].sector_size as usize;
            let mut chunk_remaining = bytes_to_read;
            let mut i = 0usize;
            while i < bytes_to_read {
                let bytes_to_request = chunk_remaining.min(sector_size);
                self.core_data_ivfc_storage.storage_read(
                    3,
                    &file,
                    &self.meta_remap_storage,
                    &self.duplex_layers[1],
                    &self.journal_storage,
                    &self.data_remap_storage,
                    &mut buffer[out_pos + i..out_pos + i + bytes_to_request],
                    physical_offset + i as u64,
                    verify,
                );
                chunk_remaining -= bytes_to_request;
                i += sector_size;
            }

            out_pos += bytes_to_read;
            in_pos += bytes_to_read as u64;
            remaining -= bytes_to_read;
        }
        out_pos
    }

    pub fn fs_list_get_capacity(&mut self, table_block: u32, verify: bool) -> u32 {
        let mut buf = [0u8; 4];
        self.fat_storage_read(table_block, &mut buf, 4, verify);
        read_u32_le(&buf, 0)
    }

    pub fn fs_list_read_entry(
        &mut self,
        table_block: u32,
        index: u32,
        verify: bool,
    ) -> SaveFsListEntry {
        let mut buf = [0u8; SAVE_FS_LIST_ENTRY_SIZE];
        self.fat_storage_read(
            table_block,
            &mut buf,
            index as u64 * SAVE_FS_LIST_ENTRY_SIZE as u64,
            verify,
        );
        SaveFsListEntry::from_bytes(&buf)
    }

    pub fn fs_list_get_value(
        &mut self,
        table_block: u32,
        index: u32,
        verify: bool,
    ) -> Option<SaveFsListEntry> {
        let cap = self.fs_list_get_capacity(table_block, verify);
        if index >= cap {
            return None;
        }
        Some(self.fs_list_read_entry(table_block, index, verify))
    }

    pub fn fs_get_index_from_key(
        &mut self,
        table_block: u32,
        key_parent: u32,
        key_name: &str,
        verify: bool,
    ) -> u32 {
        let capacity = self.fs_list_get_capacity(table_block, verify);
        let head_entry = self.fs_list_read_entry(table_block, 1, verify);
        let mut index = head_entry.next;
        while index != 0 {
            if index > capacity {
                eprint!("Save entry index {} out of range!", index);
                process::exit(1);
            }
            let entry = self.fs_list_read_entry(table_block, index, verify);
            if entry.parent == key_parent && entry.name == key_name {
                return index;
            }
            index = entry.next;
        }
        0xFFFF_FFFF
    }
}

pub fn save_process_header(ctx: &mut SaveCtx, header_offset: u64) {
    if ctx.header.layout.magic != MAGIC_DISF
        || ctx.header.duplex_header.magic != MAGIC_DPFS
        || ctx.header.data_ivfc_header.magic != MAGIC_IVFC
        || ctx.header.journal_header.magic != MAGIC_JNGL
        || ctx.header.save_header.magic != MAGIC_SAVE
        || ctx.header.main_remap_header.magic != MAGIC_RMAP
        || ctx.header.meta_remap_header.magic != MAGIC_RMAP
    {
        eprintln!("Error: Save header is corrupt!");
        process::exit(1);
    }

    ctx.header.data_ivfc_header.num_levels = 5;
    if ctx.header.layout.version >= 0x50000 {
        ctx.header.fat_ivfc_header.num_levels = 4;
    }

    let file = ctx.file.as_ref().unwrap();
    ctx.header_hash_validity = check_memory_hash_table(
        file,
        &ctx.header.layout.hash,
        header_offset + 0x300,
        0x3D00,
        0x3D00,
        false,
    );
}

pub fn save_filesystem_verify(ctx: &mut SaveCtx) -> Validity {
    let file = ctx.file.as_ref().unwrap().clone();
    let data_ivfc_hdr = ctx.header.data_ivfc_header;
    let journal_validity = ctx.core_data_ivfc_storage.validate(
        &data_ivfc_hdr,
        &file,
        &ctx.meta_remap_storage,
        &ctx.duplex_layers[1],
        &ctx.journal_storage,
        &ctx.data_remap_storage,
    );
    ctx.core_data_ivfc_storage
        .set_level_validities(&data_ivfc_hdr);

    if !ctx.fat_ivfc_storage.initialized {
        return journal_validity;
    }

    let fat_ivfc_hdr = ctx.header.fat_ivfc_header;
    let fat_validity = ctx.fat_ivfc_storage.validate(
        &fat_ivfc_hdr,
        &file,
        &ctx.meta_remap_storage,
        &ctx.duplex_layers[1],
        &ctx.journal_storage,
        &ctx.data_remap_storage,
    );
    ctx.fat_ivfc_storage.set_level_validities(&fat_ivfc_hdr);

    if journal_validity != Validity::Valid {
        return journal_validity;
    }
    if fat_validity != Validity::Valid {
        return fat_validity;
    }
    journal_validity
}

pub fn save_process(ctx: &mut SaveCtx, tool_ctx: &HactoolCtx) {
    let file = match &ctx.file {
        Some(f) => f.clone(),
        None => {
            eprintln!("Failed to read save header!");
            process::exit(1);
        }
    };

    let mut hdr_buf = vec![0u8; SAVE_HEADER_SIZE];
    if file.read_exact_at(0, &mut hdr_buf).is_err() {
        eprintln!("Failed to read save header!");
        process::exit(1);
    }
    ctx.header = SaveHeader::from_bytes(&hdr_buf);
    save_process_header(ctx, 0);

    if ctx.header_hash_validity == Validity::Invalid {
        if file.read_exact_at(0x4000, &mut hdr_buf).is_err() {
            eprintln!("Failed to read save header!");
            process::exit(1);
        }
        ctx.header = SaveHeader::from_bytes(&hdr_buf);
        // Note: In C, check_memory_hash_table(ctx->file, ctx->header.layout.hash, 0x300, 0x3D00, 0x3D00, 0)
        // always checks file offset 0x300 even when reading Header B at 0x4000!
        save_process_header(ctx, 0);

        if ctx.header_hash_validity == Validity::Invalid {
            eprintln!("Error: Save header is invalid!");
            process::exit(1);
        }
    }

    let mut cmac = [0u8; 0x10];
    aes_calculate_cmac(
        &mut cmac,
        &ctx.header.raw_bytes[0x100..0x300],
        &tool_ctx.settings.keyset.save_mac_key,
    );
    if cmac == ctx.header.cmac {
        ctx.header_cmac_validity = Validity::Valid;
    } else {
        ctx.header_cmac_validity = Validity::Invalid;
    }

    // Initialize data remap storage
    ctx.data_remap_storage.base_storage_offset = ctx.header.layout.file_map_data_offset;
    ctx.data_remap_storage.header = ctx.header.main_remap_header;
    let main_entry_count = ctx.data_remap_storage.header.map_entry_count as usize;
    ctx.data_remap_storage.map_entries.clear();
    let mut entry_buf = vec![0u8; main_entry_count * 0x20];
    let _ = file.read_at(ctx.header.layout.file_map_entry_offset, &mut entry_buf);
    for i in 0..main_entry_count {
        let base = i * 0x20;
        let virtual_offset = read_u64_le(&entry_buf, base);
        let physical_offset = read_u64_le(&entry_buf, base + 0x08);
        let size = read_u64_le(&entry_buf, base + 0x10);
        let alignment = read_u32_le(&entry_buf, base + 0x18);
        let _0x1c = read_u32_le(&entry_buf, base + 0x1C);
        ctx.data_remap_storage.map_entries.push(RemapEntry {
            virtual_offset,
            physical_offset,
            size,
            alignment,
            _0x1c,
            virtual_offset_end: virtual_offset + size,
            physical_offset_end: physical_offset + size,
            next_idx: None,
        });
    }
    ctx.data_remap_storage.init_segments();

    // Initialize duplex storage
    let master_off = if ctx.header.layout.duplex_index == 1 {
        ctx.header.layout.duplex_master_offset_b as usize
    } else {
        ctx.header.layout.duplex_master_offset_a as usize
    };
    let master_sz = ctx.header.layout.duplex_master_size as usize;
    let master_bitmap = ctx.header.raw_bytes[master_off..master_off + master_sz].to_vec();

    let l1_sz = ctx.header.layout.duplex_l1_size as usize;
    let mut l1_data_a = vec![0u8; l1_sz];
    let mut l1_data_b = vec![0u8; l1_sz];
    ctx.data_remap_storage.read_bytes(
        &file,
        &mut l1_data_a,
        ctx.header.layout.duplex_l1_offset_a,
    );
    ctx.data_remap_storage.read_bytes(
        &file,
        &mut l1_data_b,
        ctx.header.layout.duplex_l1_offset_b,
    );

    let data_sz = ctx.header.layout.duplex_data_size as usize;
    let mut dup_data_a = vec![0u8; data_sz];
    let mut dup_data_b = vec![0u8; data_sz];
    ctx.data_remap_storage.read_bytes(
        &file,
        &mut dup_data_a,
        ctx.header.layout.duplex_data_offset_a,
    );
    ctx.data_remap_storage.read_bytes(
        &file,
        &mut dup_data_b,
        ctx.header.layout.duplex_data_offset_b,
    );

    let mut layer0 = DuplexStorageCtx::init(
        l1_data_a,
        l1_data_b,
        ctx.header.duplex_header.layers[1].block_size_power,
        &master_bitmap,
        ctx.header.layout.duplex_master_size,
    );
    layer0.length = ctx.header.layout.duplex_l1_size;

    let mut l1_bitmap = vec![0u8; layer0.length as usize];
    layer0.read(&mut l1_bitmap, 0);

    let mut layer1 = DuplexStorageCtx::init(
        dup_data_a,
        dup_data_b,
        ctx.header.duplex_header.layers[2].block_size_power,
        &l1_bitmap,
        layer0.length,
    );
    layer1.length = ctx.header.layout.duplex_data_size;

    ctx.duplex_layers = [layer0, layer1];

    // Initialize meta remap storage
    ctx.meta_remap_storage.base_storage_offset = 0;
    ctx.meta_remap_storage.header = ctx.header.meta_remap_header;
    let meta_entry_count = ctx.meta_remap_storage.header.map_entry_count as usize;
    ctx.meta_remap_storage.map_entries.clear();
    let mut meta_entry_buf = vec![0u8; meta_entry_count * 0x20];
    let _ = file.read_at(ctx.header.layout.meta_map_entry_offset, &mut meta_entry_buf);
    for i in 0..meta_entry_count {
        let base = i * 0x20;
        let virtual_offset = read_u64_le(&meta_entry_buf, base);
        let physical_offset = read_u64_le(&meta_entry_buf, base + 0x08);
        let size = read_u64_le(&meta_entry_buf, base + 0x10);
        let alignment = read_u32_le(&meta_entry_buf, base + 0x18);
        let _0x1c = read_u32_le(&meta_entry_buf, base + 0x1C);
        ctx.meta_remap_storage.map_entries.push(RemapEntry {
            virtual_offset,
            physical_offset,
            size,
            alignment,
            _0x1c,
            virtual_offset_end: virtual_offset + size,
            physical_offset_end: physical_offset + size,
            next_idx: None,
        });
    }
    ctx.meta_remap_storage.init_segments();

    // Initialize journal map & storage
    let jmap_sz = ctx.header.layout.journal_map_table_size as usize;
    let mut jmap_storage = vec![0u8; jmap_sz];
    ctx.meta_remap_storage.read_duplex(
        &ctx.duplex_layers[1],
        &mut jmap_storage,
        ctx.header.layout.journal_map_table_offset,
    );

    let main_blk_count = ctx.header.map_header.main_data_block_count as usize;
    let mut j_entries = Vec::with_capacity(main_blk_count);
    for i in 0..main_blk_count {
        let phys = read_u32_le(&jmap_storage, i * 8) & 0x7FFF_FFFF;
        j_entries.push(JournalMapEntry {
            physical_index: phys,
            virtual_index: i as u32,
        });
    }
    ctx.journal_storage = JournalStorageCtx {
        entries: j_entries,
        block_size: ctx.header.journal_header.block_size,
        journal_data_offset: ctx.header.layout.journal_data_offset,
        length: ctx.header.journal_header.total_size - ctx.header.journal_header.journal_size,
    };

    // Initialize core IVFC storage
    ctx.core_data_ivfc_storage.init(
        ctx.header.layout.ivfc_master_hash_offset_a,
        &ctx.header.data_ivfc_header,
    );

    // Initialize FAT storage
    if ctx.header.layout.version < 0x50000 {
        ctx.fat_storage = vec![0u8; ctx.header.layout.fat_size as usize];
        ctx.meta_remap_storage.read_duplex(
            &ctx.duplex_layers[1],
            &mut ctx.fat_storage,
            ctx.header.layout.fat_offset,
        );
    } else {
        ctx.fat_ivfc_storage.init(
            ctx.header.layout.fat_ivfc_master_hash_a,
            &ctx.header.fat_ivfc_header,
        );
        ctx.fat_storage = vec![0u8; ctx.fat_ivfc_storage.length as usize];
        let fat_log_off = ctx.header.fat_ivfc_header.level_headers
            [ctx.header.fat_ivfc_header.num_levels as usize - 2]
            .logical_offset;
        ctx.meta_remap_storage.read_duplex(
            &ctx.duplex_layers[1],
            &mut ctx.fat_storage,
            fat_log_off,
        );
    }

    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        save_filesystem_verify(ctx);
    }

    ctx.dir_table_block = ctx.header.fat_header.directory_table_block;
    ctx.file_table_block = ctx.header.fat_header.file_table_block;
    ctx.block_size = ctx.header.save_header.block_size as u32;

    if (tool_ctx.action & ACTION_INFO) != 0 {
        save_print(ctx, tool_ctx);
    }

    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        save_save(ctx, tool_ctx);
    }
}

pub fn save_save_file(
    ctx: &mut SaveCtx,
    mut ofs: u64,
    total_size: u64,
    start_block: u32,
    filepath: &Filepath,
    verify: bool,
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
    with_worker_scratch(total_size.min(SCRATCH_BUF_SIZE as u64) as usize, |buf| {
        while ofs < end_ofs {
            let read_size = ((end_ofs - ofs) as usize).min(buf.len());
            ctx.fat_storage_read(start_block, &mut buf[..read_size], ofs, verify);
            if f_out.write_all(&buf[..read_size]).is_err() {
                eprintln!("Failed to write file!");
                process::exit(1);
            }
            ofs += read_size as u64;
        }
    });
}

fn save_visit_save_file(
    ctx: &mut SaveCtx,
    file_index: u32,
    dir_path: &Filepath,
    tool_ctx: &HactoolCtx,
) -> bool {
    let verify = (tool_ctx.action & ACTION_VERIFY) != 0;
    let file_table_blk = ctx.file_table_block;
    let entry = match ctx.fs_list_get_value(file_table_blk, file_index, verify) {
        Some(e) => e,
        None => return false,
    };

    let mut cur_path = dir_path.clone();
    if !entry.name.is_empty() {
        cur_path.append(&entry.name);
    }

    let mut found_file = true;

    if (tool_ctx.action & ACTION_LISTFILES) == 0 {
        if !tool_ctx.settings.quiet {
            println!("Saving {}...", cur_path.char_path);
        }
        save_save_file(
            ctx,
            0,
            entry.file_info.length,
            entry.file_info.start_block,
            &cur_path,
            verify,
        );
    } else {
        println!("save:{}", cur_path.char_path);
    }

    if entry.next_sibling != 0 {
        found_file |= save_visit_save_file(ctx, entry.next_sibling, dir_path, tool_ctx);
    }

    found_file
}

fn save_visit_save_dir(
    ctx: &mut SaveCtx,
    dir_index: u32,
    parent_path: &Filepath,
    tool_ctx: &HactoolCtx,
) -> bool {
    let verify = (tool_ctx.action & ACTION_VERIFY) != 0;
    let dir_table_blk = ctx.dir_table_block;
    let entry = match ctx.fs_list_get_value(dir_table_blk, dir_index, verify) {
        Some(e) => e,
        None => return false,
    };

    let mut cur_path = parent_path.clone();
    if !entry.name.is_empty() {
        cur_path.append(&entry.name);
    }

    if (tool_ctx.action & ACTION_LISTROMFS) == 0 {
        let _ = os_makedir(&cur_path.char_path);
    }

    let mut any_files = false;

    if entry.next_sibling != 0 {
        any_files |= save_visit_save_dir(ctx, entry.next_sibling, parent_path, tool_ctx);
    }
    if entry.find_position.next_directory != 0 {
        any_files |=
            save_visit_save_dir(ctx, entry.find_position.next_directory, &cur_path, tool_ctx);
    }
    if entry.find_position.next_file != 0 {
        any_files |=
            save_visit_save_file(ctx, entry.find_position.next_file, &cur_path, tool_ctx);
    }

    any_files
}

pub fn save_save(ctx: &mut SaveCtx, tool_ctx: &HactoolCtx) {
    let verify = (tool_ctx.action & ACTION_VERIFY) != 0;
    let dir_table_blk = ctx.dir_table_block;
    let idx = ctx.fs_get_index_from_key(dir_table_blk, 0, "", verify);
    if idx == 0xFFFF_FFFF {
        eprint!("Failed to locate root directory!");
        return;
    }
    if ctx.fs_list_get_value(dir_table_blk, idx, verify).is_none() {
        eprint!("Failed to get filesystem list entry for root directory!");
        return;
    }

    if (tool_ctx.action & ACTION_LISTFILES) != 0 {
        let mut fakepath = Filepath::new();
        fakepath.set("");
        save_visit_save_dir(ctx, idx, &fakepath, tool_ctx);
    } else if tool_ctx.settings.out_dir_path.enabled
        && tool_ctx.settings.out_dir_path.path.valid == Validity::Valid
    {
        let dirpath = &tool_ctx.settings.out_dir_path.path;
        let _ = os_makedir(&dirpath.char_path);
        save_visit_save_dir(ctx, idx, dirpath, tool_ctx);
    }
}

fn save_print_ivfc_section(ctx: &SaveCtx, tool_ctx: &HactoolCtx) {
    print_magic(
        "    Magic:                          ",
        ctx.header.data_ivfc_header.magic,
    );
    println!(
        "    ID:                             {:08x}",
        ctx.header.data_ivfc_header.id
    );
    memdump_stdout(
        "    Salt Seed:                      ",
        &ctx.header.data_ivfc_header.salt_source,
    );
    for i in 0..(ctx.header.data_ivfc_header.num_levels as usize - 1) {
        if (tool_ctx.action & ACTION_VERIFY) != 0 {
            println!(
                "    Level {} ({}):",
                i,
                ctx.core_data_ivfc_storage.levels[i].hash_validity.as_str()
            );
        } else {
            println!("    Level {}:", i);
        }
        println!(
            "        Data Offset:                0x{:016x}",
            ctx.header.data_ivfc_header.level_headers[i].logical_offset
        );
        println!(
            "        Data Size:                  0x{:016x}",
            ctx.header.data_ivfc_header.level_headers[i].hash_data_size
        );
        if i != 0 {
            println!(
                "        Hash Offset:                0x{:016x}",
                ctx.header.data_ivfc_header.level_headers[i - 1].logical_offset
            );
        } else {
            println!("        Hash Offset:                0x0");
        }
        println!(
            "        Hash Block Size:            0x{:08x}",
            1u32 << ctx.header.data_ivfc_header.level_headers[i].block_size
        );
    }
}

fn save_get_save_type(save_data_type: u8) -> &'static str {
    match save_data_type {
        0 => "SystemSaveData",
        1 => "SaveData",
        2 => "BcatDeliveryCacheStorage",
        3 => "DeviceSaveData",
        4 => "TemporaryStorage",
        5 => "CacheStorage",
        _ => "Unknown",
    }
}

fn format_utc_timestamp(ts: u64) -> String {
    // Convert Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) to "%Y-%m-%d %H:%M:%S UTC"
    let secs = ts as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // Howard Hinnant civil_from_days algorithm
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, m, d, hour, min, sec
    )
}

pub fn save_print(ctx: &SaveCtx, tool_ctx: &HactoolCtx) {
    println!("\nSave:");

    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        if ctx.header_cmac_validity == Validity::Valid {
            memdump_stdout(
                "Header CMAC (GOOD):                 ",
                &ctx.header.cmac,
            );
        } else {
            memdump_stdout(
                "Header CMAC (FAIL):                 ",
                &ctx.header.cmac,
            );
        }
    } else {
        memdump_stdout(
            "Header CMAC:                        ",
            &ctx.header.cmac,
        );
    }

    println!(
        "Title ID:                           {:016x}",
        ctx.header.extra_data.title_id
    );
    memdump_stdout(
        "User ID:                            ",
        &ctx.header.extra_data.user_id,
    );
    println!(
        "Save ID:                            {:016x}",
        ctx.header.extra_data.save_id
    );
    println!(
        "Save Type:                          {}",
        save_get_save_type(ctx.header.extra_data.save_data_type)
    );
    println!(
        "Owner ID:                           {:016x}",
        ctx.header.extra_data.save_owner_id
    );
    println!(
        "Timestamp:                          {}",
        format_utc_timestamp(ctx.header.extra_data.timestamp)
    );
    println!(
        "Save Data Size:                     0x{:016x}",
        ctx.header.extra_data.data_size
    );
    println!(
        "Journal Size:                       0x{:016x}",
        ctx.header.extra_data.journal_size
    );
    println!(
        "Free Space:                         0x{:016x}",
        save_allocation_table_get_free_space_size(
            &ctx.fat_storage,
            &ctx.header.fat_header,
            &ctx.header.save_header
        )
    );

    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        if ctx.header_hash_validity == Validity::Valid {
            memdump_stdout(
                "Header Hash (GOOD):                 ",
                &ctx.header.layout.hash,
            );
        } else {
            memdump_stdout(
                "Header Hash (FAIL):                 ",
                &ctx.header.layout.hash,
            );
        }
    } else {
        memdump_stdout(
            "Header Hash:                        ",
            &ctx.header.layout.hash,
        );
    }

    save_print_ivfc_section(ctx, tool_ctx);

    println!();
}

