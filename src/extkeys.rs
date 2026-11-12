#![allow(dead_code)]

//! External keyfile (`prod.keys`, `dev.keys`, `title.keys`) parser matching `extkeys.c`.

use crate::pki::pki_set_beta_nca0_exponent;
use crate::settings::{HactoolSettings, TitlekeyEntry};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process;

#[inline]
fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

#[inline]
fn hex_to_u8(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

pub fn parse_hex_key(key: &mut [u8], hex: &str) {
    let len = key.len();
    if hex.len() != 2 * len || !hex.bytes().all(is_hex) {
        eprintln!("Key ({}) must be {} hex digits!", hex, 2 * len);
        process::exit(1);
    }

    key.fill(0);
    for (i, b) in hex.bytes().enumerate() {
        let mut val = hex_to_u8(b);
        if (i & 1) == 0 {
            val <<= 4;
        }
        key[i >> 1] |= val;
    }
}

/// Parses a single line according to `get_kv` in `extkeys.c`:
/// - Returns `Ok(Some((key, value)))` on valid key=value or key,value
/// - Returns `Ok(None)` on empty line
/// - Returns `Err(())` on malformed line
fn parse_kv_line(raw_line: &str) -> Result<Option<(String, String)>, ()> {
    let line = raw_line.trim_end_matches(&['\r', '\n'][..]);
    if line.is_empty() {
        return Ok(None);
    }

    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }

    let key_start = i;
    let mut key = String::new();
    while i < bytes.len()
        && bytes[i] != b' '
        && bytes[i] != b','
        && bytes[i] != b'\t'
        && bytes[i] != b'='
    {
        let c = bytes[i];
        if c.is_ascii_uppercase() {
            key.push((c + 32) as char);
        } else if c == b'_' || c.is_ascii_digit() || c.is_ascii_lowercase() {
            key.push(c as char);
        } else {
            return Err(());
        }
        i += 1;
    }

    if i >= bytes.len() || key.is_empty() || i == key_start {
        return Err(());
    }

    if bytes[i] == b'=' || bytes[i] == b',' {
        i += 1;
    } else {
        i += 1;
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() || (bytes[i] != b'=' && bytes[i] != b',') {
            return Err(());
        }
        i += 1;
    }

    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }

    let mut end = bytes.len();
    while end > i && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }

    let value = String::from_utf8_lossy(&bytes[i..end]).into_owned();
    Ok(Some((key, value)))
}

pub fn extkeys_parse_titlekeys(settings: &mut HactoolSettings, file: File) {
    let reader = BufReader::new(file);
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => break,
        };
        if let Ok(Some((key, value))) = parse_kv_line(&line) {
            let mut should_ignore = false;
            if key.len() != 0x20 || !key.bytes().all(is_hex) {
                should_ignore = true;
            }
            if should_ignore {
                if !settings.skip_key_warnings {
                    eprintln!(
                        "[WARN]: Invalid title.keys content: \"{}\", (value \"{}\")",
                        key, value
                    );
                }
            } else {
                let mut rights_id = [0u8; 0x10];
                let mut titlekey = [0u8; 0x10];
                parse_hex_key(&mut rights_id, &key);
                parse_hex_key(&mut titlekey, &value);
                settings_add_titlekey(settings, &rights_id, &titlekey);
            }
        }
    }
}

pub fn extkeys_initialize_settings(settings: &mut HactoolSettings, file: File) {
    let reader = BufReader::new(file);
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => break,
        };
        if let Ok(Some((key, value))) = parse_kv_line(&line) {
            let keyset = &mut settings.keyset;
            let mut matched = true;

            match key.as_str() {
                "aes_kek_generation_source" => {
                    parse_hex_key(&mut keyset.aes_kek_generation_source, &value)
                }
                "aes_key_generation_source" => {
                    parse_hex_key(&mut keyset.aes_key_generation_source, &value)
                }
                "key_area_key_application_source" => {
                    parse_hex_key(&mut keyset.key_area_key_application_source, &value)
                }
                "key_area_key_ocean_source" => {
                    parse_hex_key(&mut keyset.key_area_key_ocean_source, &value)
                }
                "key_area_key_system_source" => {
                    parse_hex_key(&mut keyset.key_area_key_system_source, &value)
                }
                "titlekek_source" => parse_hex_key(&mut keyset.titlekek_source, &value),
                "header_kek_source" => parse_hex_key(&mut keyset.header_kek_source, &value),
                "header_key_source" => parse_hex_key(&mut keyset.header_key_source, &value),
                "header_key" => parse_hex_key(&mut keyset.header_key, &value),
                "package2_key_source" => parse_hex_key(&mut keyset.package2_key_source, &value),
                "per_console_key_source" => {
                    parse_hex_key(&mut keyset.per_console_key_source, &value)
                }
                "xci_header_key" => parse_hex_key(&mut keyset.xci_header_key, &value),
                "sd_card_kek_source" => parse_hex_key(&mut keyset.sd_card_kek_source, &value),
                "sd_card_nca_key_source" => {
                    parse_hex_key(&mut keyset.sd_card_key_sources[1], &value)
                }
                "sd_card_save_key_source" => {
                    parse_hex_key(&mut keyset.sd_card_key_sources[0], &value)
                }
                "save_mac_kek_source" => parse_hex_key(&mut keyset.save_mac_kek_source, &value),
                "save_mac_key_source" => parse_hex_key(&mut keyset.save_mac_key_source, &value),
                "master_key_source" => parse_hex_key(&mut keyset.master_key_source, &value),
                "keyblob_mac_key_source" => {
                    parse_hex_key(&mut keyset.keyblob_mac_key_source, &value)
                }
                "secure_boot_key" => parse_hex_key(&mut keyset.secure_boot_key, &value),
                "tsec_key" => parse_hex_key(&mut keyset.tsec_key, &value),
                "mariko_kek" => parse_hex_key(&mut keyset.mariko_kek, &value),
                "mariko_bek" => parse_hex_key(&mut keyset.mariko_bek, &value),
                "tsec_root_kek" => parse_hex_key(&mut keyset.tsec_root_kek, &value),
                "package1_mac_kek" => parse_hex_key(&mut keyset.package1_mac_kek, &value),
                "package1_kek" => parse_hex_key(&mut keyset.package1_kek, &value),
                "beta_nca0_exponent" => {
                    let mut exponent = [0u8; 0x100];
                    parse_hex_key(&mut exponent, &value);
                    pki_set_beta_nca0_exponent(&exponent);
                }
                "xci_t1_titlekey_kek_00" => {}
                _ => {
                    matched = false;
                    for i in 0..0x6 {
                        if key == format!("keyblob_key_source_{:02x}", i) {
                            parse_hex_key(&mut keyset.keyblob_key_sources[i], &value);
                            matched = true;
                            break;
                        } else if key == format!("keyblob_key_{:02x}", i) {
                            parse_hex_key(&mut keyset.keyblob_keys[i], &value);
                            matched = true;
                            break;
                        } else if key == format!("keyblob_mac_key_{:02x}", i) {
                            parse_hex_key(&mut keyset.keyblob_mac_keys[i], &value);
                            matched = true;
                            break;
                        } else if key == format!("encrypted_keyblob_{:02x}", i) {
                            parse_hex_key(&mut keyset.encrypted_keyblobs[i], &value);
                            matched = true;
                            break;
                        } else if key == format!("mariko_master_kek_source_{:02x}", i) {
                            parse_hex_key(&mut keyset.mariko_master_kek_sources[i], &value);
                            matched = true;
                            break;
                        } else if key == format!("keyblob_{:02x}", i) {
                            parse_hex_key(&mut keyset.keyblobs[i], &value);
                            matched = true;
                            break;
                        }
                    }

                    if !matched {
                        for i in 0x6..0x20 {
                            if key == format!("tsec_auth_signature_{:02x}", i - 6) {
                                parse_hex_key(&mut keyset.tsec_auth_signatures[i - 6], &value);
                                matched = true;
                                break;
                            } else if key == format!("tsec_root_key_{:02x}", i - 6) {
                                parse_hex_key(&mut keyset.tsec_root_keys[i - 6], &value);
                                matched = true;
                                break;
                            } else if key == format!("master_kek_source_{:02x}", i) {
                                parse_hex_key(&mut keyset.master_kek_sources[i], &value);
                                matched = true;
                                break;
                            } else if key == format!("mariko_master_kek_source_{:02x}", i) {
                                parse_hex_key(&mut keyset.mariko_master_kek_sources[i], &value);
                                matched = true;
                                break;
                            } else if key == format!("package1_mac_key_{:02x}", i) {
                                parse_hex_key(&mut keyset.package1_mac_keys[i], &value);
                                matched = true;
                                break;
                            }
                        }
                    }

                    if !matched {
                        for i in 0..0xC {
                            if key == format!("mariko_aes_class_key_{:02x}", i) {
                                parse_hex_key(&mut keyset.mariko_aes_class_keys[i], &value);
                                matched = true;
                                break;
                            }
                        }
                    }

                    if !matched {
                        for i in 0..0x20 {
                            if key == format!("master_kek_{:02x}", i) {
                                parse_hex_key(&mut keyset.master_keks[i], &value);
                                matched = true;
                                break;
                            } else if key == format!("master_key_{:02x}", i) {
                                parse_hex_key(&mut keyset.master_keys[i], &value);
                                matched = true;
                                break;
                            } else if key == format!("package1_key_{:02x}", i) {
                                parse_hex_key(&mut keyset.package1_keys[i], &value);
                                matched = true;
                                break;
                            } else if key == format!("package2_key_{:02x}", i) {
                                parse_hex_key(&mut keyset.package2_keys[i], &value);
                                matched = true;
                                break;
                            } else if key == format!("titlekek_{:02x}", i) {
                                parse_hex_key(&mut keyset.titlekeks[i], &value);
                                matched = true;
                                break;
                            } else if key == format!("key_area_key_application_{:02x}", i) {
                                parse_hex_key(&mut keyset.key_area_keys[i][0], &value);
                                matched = true;
                                break;
                            } else if key == format!("key_area_key_ocean_{:02x}", i) {
                                parse_hex_key(&mut keyset.key_area_keys[i][1], &value);
                                matched = true;
                                break;
                            } else if key == format!("key_area_key_system_{:02x}", i) {
                                parse_hex_key(&mut keyset.key_area_keys[i][2], &value);
                                matched = true;
                                break;
                            }
                        }
                    }
                }
            }

            if !matched && !settings.skip_key_warnings {
                eprintln!("[WARN]: Failed to match key \"{}\", (value \"{}\")", key, value);
            }
        }
    }
}

pub fn settings_has_titlekey(settings: &HactoolSettings, rights_id: &[u8; 0x10]) -> bool {
    settings_get_titlekey(settings, rights_id).is_some()
}

pub fn settings_add_titlekey(
    settings: &mut HactoolSettings,
    rights_id: &[u8; 0x10],
    titlekey: &[u8; 0x10],
) {
    if settings_has_titlekey(settings, rights_id) {
        eprint!("Error: Rights ID ");
        for &b in rights_id {
            eprint!("{:02X}", b);
        }
        eprintln!(" already has a corresponding titlekey!");
        process::exit(1);
    }

    settings.known_titlekeys.titlekeys.push(TitlekeyEntry {
        rights_id: *rights_id,
        titlekey: *titlekey,
        dec_titlekey: [0u8; 0x10],
    });
}

pub fn settings_get_titlekey<'a>(
    settings: &'a HactoolSettings,
    rights_id: &[u8; 0x10],
) -> Option<&'a TitlekeyEntry> {
    settings
        .known_titlekeys
        .titlekeys
        .iter()
        .find(|e| &e.rights_id == rights_id)
}

