#![allow(dead_code)]

use crate::types::{BaseFileType, FileType, Filepath, OverrideFilepath, SharedFile};

#[derive(Clone)]
pub struct NcaKeyset {
    pub secure_boot_key: [u8; 0x10],
    pub tsec_key: [u8; 0x10],
    pub device_key: [u8; 0x10],
    pub keyblob_keys: [[u8; 0x10]; 0x20],
    pub keyblob_mac_keys: [[u8; 0x10]; 0x20],
    pub encrypted_keyblobs: [[u8; 0xB0]; 0x20],
    pub mariko_aes_class_keys: [[u8; 0x10]; 0xC],
    pub mariko_kek: [u8; 0x10],
    pub mariko_bek: [u8; 0x10],
    pub keyblobs: [[u8; 0x90]; 0x20],
    pub keyblob_key_sources: [[u8; 0x10]; 0x20],
    pub keyblob_mac_key_source: [u8; 0x10],
    pub tsec_root_kek: [u8; 0x10],
    pub package1_mac_kek: [u8; 0x10],
    pub package1_kek: [u8; 0x10],
    pub tsec_auth_signatures: [[u8; 0x10]; 0x20],
    pub tsec_root_keys: [[u8; 0x10]; 0x20],
    pub master_kek_sources: [[u8; 0x10]; 0x20],
    pub mariko_master_kek_sources: [[u8; 0x10]; 0x20],
    pub master_keks: [[u8; 0x10]; 0x20],
    pub master_key_source: [u8; 0x10],
    pub master_keys: [[u8; 0x10]; 0x20],
    pub package1_mac_keys: [[u8; 0x10]; 0x20],
    pub package1_keys: [[u8; 0x10]; 0x20],
    pub package2_keys: [[u8; 0x10]; 0x20],
    pub package2_key_source: [u8; 0x10],
    pub per_console_key_source: [u8; 0x10],
    pub aes_kek_generation_source: [u8; 0x10],
    pub aes_key_generation_source: [u8; 0x10],
    pub key_area_key_application_source: [u8; 0x10],
    pub key_area_key_ocean_source: [u8; 0x10],
    pub key_area_key_system_source: [u8; 0x10],
    pub titlekek_source: [u8; 0x10],
    pub header_kek_source: [u8; 0x10],
    pub sd_card_kek_source: [u8; 0x10],
    pub sd_card_key_sources: [[u8; 0x20]; 2],
    pub save_mac_kek_source: [u8; 0x10],
    pub save_mac_key_source: [u8; 0x10],
    pub header_key_source: [u8; 0x20],
    pub header_key: [u8; 0x20],
    pub titlekeks: [[u8; 0x10]; 0x20],
    pub key_area_keys: [[[u8; 0x10]; 3]; 0x20],
    pub xci_header_key: [u8; 0x10],
    pub save_mac_key: [u8; 0x10],
    pub sd_card_keys: [[u8; 0x20]; 2],
    pub nca_hdr_fixed_key_moduli: [[u8; 0x100]; 2],
    pub acid_fixed_key_moduli: [[u8; 0x100]; 2],
    pub package2_fixed_key_modulus: [u8; 0x100],
}

impl Default for NcaKeyset {
    fn default() -> Self {
        Self {
            secure_boot_key: [0; 0x10],
            tsec_key: [0; 0x10],
            device_key: [0; 0x10],
            keyblob_keys: [[0; 0x10]; 0x20],
            keyblob_mac_keys: [[0; 0x10]; 0x20],
            encrypted_keyblobs: [[0; 0xB0]; 0x20],
            mariko_aes_class_keys: [[0; 0x10]; 0xC],
            mariko_kek: [0; 0x10],
            mariko_bek: [0; 0x10],
            keyblobs: [[0; 0x90]; 0x20],
            keyblob_key_sources: [[0; 0x10]; 0x20],
            keyblob_mac_key_source: [0; 0x10],
            tsec_root_kek: [0; 0x10],
            package1_mac_kek: [0; 0x10],
            package1_kek: [0; 0x10],
            tsec_auth_signatures: [[0; 0x10]; 0x20],
            tsec_root_keys: [[0; 0x10]; 0x20],
            master_kek_sources: [[0; 0x10]; 0x20],
            mariko_master_kek_sources: [[0; 0x10]; 0x20],
            master_keks: [[0; 0x10]; 0x20],
            master_key_source: [0; 0x10],
            master_keys: [[0; 0x10]; 0x20],
            package1_mac_keys: [[0; 0x10]; 0x20],
            package1_keys: [[0; 0x10]; 0x20],
            package2_keys: [[0; 0x10]; 0x20],
            package2_key_source: [0; 0x10],
            per_console_key_source: [0; 0x10],
            aes_kek_generation_source: [0; 0x10],
            aes_key_generation_source: [0; 0x10],
            key_area_key_application_source: [0; 0x10],
            key_area_key_ocean_source: [0; 0x10],
            key_area_key_system_source: [0; 0x10],
            titlekek_source: [0; 0x10],
            header_kek_source: [0; 0x10],
            sd_card_kek_source: [0; 0x10],
            sd_card_key_sources: [[0; 0x20]; 2],
            save_mac_kek_source: [0; 0x10],
            save_mac_key_source: [0; 0x10],
            header_key_source: [0; 0x20],
            header_key: [0; 0x20],
            titlekeks: [[0; 0x10]; 0x20],
            key_area_keys: [[[0; 0x10]; 3]; 0x20],
            xci_header_key: [0; 0x10],
            save_mac_key: [0; 0x10],
            sd_card_keys: [[0; 0x20]; 2],
            nca_hdr_fixed_key_moduli: [[0; 0x100]; 2],
            acid_fixed_key_moduli: [[0; 0x100]; 2],
            package2_fixed_key_modulus: [0; 0x100],
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct TitlekeyEntry {
    pub rights_id: [u8; 0x10],
    pub titlekey: [u8; 0x10],
    pub dec_titlekey: [u8; 0x10],
}

#[derive(Clone, Default)]
pub struct KnownTitlekeys {
    pub titlekeys: Vec<TitlekeyEntry>,
}

#[derive(Clone, Default)]
pub struct HactoolSettings {
    pub keyset: NcaKeyset,
    pub skip_key_warnings: bool,
    pub quiet: bool,
    pub has_expected_content_type: bool,
    pub expected_content_type: u32,
    pub append_section_types: bool,
    pub suppress_keydata_output: bool,
    pub has_cli_titlekey: bool,
    pub cli_titlekey: [u8; 0x10],
    pub dec_cli_titlekey: [u8; 0x10],
    pub known_titlekeys: KnownTitlekeys,
    pub has_cli_contentkey: bool,
    pub cli_contentkey: [u8; 0x10],
    pub has_sdseed: bool,
    pub sdseed: [u8; 0x10],
    pub keygen_sbk: [u8; 0x10],
    pub keygen_tsec: [u8; 0x10],
    pub section_paths: [Filepath; 4],
    pub section_dir_paths: [Filepath; 4],
    pub exefs_path: OverrideFilepath,
    pub exefs_dir_path: OverrideFilepath,
    pub romfs_path: OverrideFilepath,
    pub romfs_dir_path: OverrideFilepath,
    pub out_dir_path: OverrideFilepath,
    pub pfs0_dir_path: Filepath,
    pub hfs0_dir_path: Filepath,
    pub pk11_dir_path: Filepath,
    pub pk21_dir_path: Filepath,
    pub ini1_dir_path: Filepath,
    pub plaintext_path: Filepath,
    pub uncompressed_path: Filepath,
    pub rootpt_dir_path: Filepath,
    pub update_dir_path: Filepath,
    pub normal_dir_path: Filepath,
    pub secure_dir_path: Filepath,
    pub logo_dir_path: Filepath,
    pub header_path: Filepath,
    pub nax0_path: Filepath,
    pub nax0_sd_path: Filepath,
    pub npdm_json_path: Filepath,
}

#[derive(Default)]
pub struct HactoolCtx {
    pub file_type: FileType,
    pub file: Option<SharedFile>,
    pub base_file: Option<SharedFile>,
    pub base_file_type: BaseFileType,
    pub base_nca_ctx: Option<Box<crate::nca::NcaCtx>>,
    pub settings: HactoolSettings,
    pub action: u32,
}

impl HactoolCtx {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has_base_file(&self) -> bool {
        self.base_file.is_some() || self.base_file_type == BaseFileType::Fake
    }
}

