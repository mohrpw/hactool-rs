use hactool::aes::{aes_calculate_cmac, AesCtx, AesMode};
use hactool::npdm::npdm_get_json;
use hactool::pfs0::{pfs0_process, Pfs0Ctx};
use hactool::pki::{pki_derive_keys, pki_initialize_keyset};
use hactool::romfs::{romfs_process, RomfsCtx, ROMFS_ENTRY_EMPTY, ROMFS_HEADER_SIZE};
use hactool::settings::HactoolCtx;
use hactool::sha::{par_verify_blocks_with_suffix, sha256_hash_buffer};
use hactool::types::{
    FileType, KeysetVariant, SharedFile, ACTION_EXTRACT, ACTION_INFO, ACTION_VERIFY, MAGIC_META,
    MAGIC_PFS0,
};
use hactool::utils::{create_uncompressed_file, os_makedir};
use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::time::Instant;

#[test]
fn test_aes_ecb_cbc_ctr_xts_cmac() {
    // NIST SP 800-38A AES-128 ECB test vector
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let pt: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    let expected_ct: [u8; 16] = [
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef,
        0x97,
    ];

    let mut enc_ctx = AesCtx::new(&key, 16, AesMode::Ecb);
    let mut ct = [0u8; 16];
    enc_ctx.encrypt(&pt, &mut ct);
    assert_eq!(ct, expected_ct);

    let mut pt_out = [0u8; 16];
    enc_ctx.decrypt(&ct, &mut pt_out);
    assert_eq!(pt_out, pt);

    // NIST SP 800-38B AES-128 CMAC test vector (16 bytes)
    let expected_cmac: [u8; 16] = [
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28,
        0x7c,
    ];
    let mut mac = [0u8; 16];
    aes_calculate_cmac(&mut mac, &pt, &key);
    assert_eq!(mac, expected_cmac);

    // CTR roundtrip (multi-block + parallel threshold)
    let mut ctr_ctx = AesCtx::new(&key, 16, AesMode::Ctr);
    let iv = [0x11u8; 16];
    let data = vec![0xA5u8; 2 * 1024 * 1024 + 37];
    let mut enc = vec![0u8; data.len()];
    let mut dec = vec![0u8; data.len()];
    ctr_ctx.set_iv(&iv);
    ctr_ctx.encrypt(&data, &mut enc);
    assert_ne!(data, enc);
    ctr_ctx.set_iv(&iv);
    ctr_ctx.decrypt(&enc, &mut dec);
    assert_eq!(data, dec);

    // XTS roundtrip (multi-sector + parallel threshold)
    let xts_key = [0x42u8; 32];
    let xts_ctx = AesCtx::new(&xts_key, 32, AesMode::Xts);
    let xts_pt = vec![0x5Au8; 2 * 1024 * 1024];
    let mut xts_ct = vec![0u8; xts_pt.len()];
    let mut xts_dec = vec![0u8; xts_pt.len()];
    xts_ctx.xts_encrypt(&xts_pt, &mut xts_ct, 0, 0x200);
    assert_ne!(xts_pt, xts_ct);
    xts_ctx.xts_decrypt(&xts_ct, &mut xts_dec, 0, 0x200);
    assert_eq!(xts_pt, xts_dec);
}

#[test]
fn test_sha256_and_parallel_verification() {
    // NIST SHA-256 test vector ("abc")
    let mut hash = [0u8; 32];
    sha256_hash_buffer(&mut hash, b"abc");
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(hash, expected);

    // Parallel block hash table verification
    let block_size = 0x1000usize;
    let num_blocks = 512usize; // 2 MB
    let mut data = vec![0u8; block_size * num_blocks];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i.wrapping_mul(31) ^ (i >> 8)) as u8;
    }
    let mut hash_table = vec![0u8; 32 * num_blocks];
    for i in 0..num_blocks {
        let mut h = [0u8; 32];
        sha256_hash_buffer(&mut h, &data[i * block_size..(i + 1) * block_size]);
        hash_table[i * 32..(i + 1) * 32].copy_from_slice(&h);
    }

    assert!(par_verify_blocks_with_suffix(
        &data,
        &hash_table,
        block_size,
        None
    ));

    // Corrupt a single byte and ensure Invalid
    data[block_size * 257 + 13] ^= 1;
    assert!(!par_verify_blocks_with_suffix(
        &data,
        &hash_table,
        block_size,
        None
    ));

    // Throughput benchmark of 64 MB AES-CTR, AES-XTS, and parallel SHA-256
    let bench_size = 64 * 1024 * 1024usize;
    let bench_in = vec![0x42u8; bench_size];
    let mut bench_out = vec![0u8; bench_size];

    let mut ctr_ctx = AesCtx::new(&[0x11u8; 16], 16, AesMode::Ctr);
    ctr_ctx.set_iv(&[0x22u8; 16]);
    let t0 = Instant::now();
    ctr_ctx.decrypt(&bench_in, &mut bench_out);
    let ctr_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let xts_ctx = AesCtx::new(&[0x33u8; 32], 32, AesMode::Xts);
    let t1 = Instant::now();
    xts_ctx.xts_decrypt(&bench_in, &mut bench_out, 0, 0x200);
    let xts_ms = t1.elapsed().as_secs_f64() * 1000.0;

    // Benchmark parallel SHA-256 block verification on 64 MiB (16384 blocks of 4 KiB)
    let mut single_block_hash = [0u8; 32];
    sha256_hash_buffer(&mut single_block_hash, &bench_in[..0x1000]);
    let mut bench_hashes = vec![0u8; (bench_size / 0x1000) * 32];
    for chunk in bench_hashes.chunks_exact_mut(32) {
        chunk.copy_from_slice(&single_block_hash);
    }
    let t2 = Instant::now();
    let ok = par_verify_blocks_with_suffix(&bench_in, &bench_hashes, 0x1000, None);
    let sha_ms = t2.elapsed().as_secs_f64() * 1000.0;
    assert!(ok);

    println!(
        "BENCHMARK (64 MiB): AES-128-CTR = {:.2} ms ({:.2} GiB/s), AES-128-XTS = {:.2} ms ({:.2} GiB/s), SHA-256 (par) = {:.2} ms ({:.2} GiB/s)",
        ctr_ms,
        (64.0 / 1024.0) / (ctr_ms / 1000.0),
        xts_ms,
        (64.0 / 1024.0) / (xts_ms / 1000.0),
        sha_ms,
        (64.0 / 1024.0) / (sha_ms / 1000.0),
    );
}

#[test]
fn test_pki_key_derivation() {
    let mut tool_ctx = HactoolCtx::new();
    pki_initialize_keyset(&mut tool_ctx.settings.keyset, KeysetVariant::Dev);
    pki_derive_keys(&mut tool_ctx.settings.keyset);
    // Ensure key derivation executes cleanly and populates derived slots deterministically
    let mut tool_ctx2 = HactoolCtx::new();
    pki_initialize_keyset(&mut tool_ctx2.settings.keyset, KeysetVariant::Dev);
    pki_derive_keys(&mut tool_ctx2.settings.keyset);
    assert_eq!(
        tool_ctx.settings.keyset.key_area_keys,
        tool_ctx2.settings.keyset.key_area_keys
    );
}

#[test]
fn test_pfs0_hfs0_npdm_nso0_kip1_synthetic_containers() {
    let temp_dir = std::env::temp_dir().join("hactool_rust_tests");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    // 1. Construct a valid synthetic NPDM (with ACI0 + ACID, FSA, Service Access, Kernel Capabilities including 0x7F quirk)
    let mut npdm = vec![0u8; 0x500];
    npdm[0..4].copy_from_slice(&MAGIC_META.to_le_bytes());
    npdm[0x0C] = 1; // flags: 64-bit
    npdm[0x0E] = 44; // main_thread_prio
    npdm[0x0F] = 0; // default_cpuid
    npdm[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // version
    npdm[0x18..0x1C].copy_from_slice(&0x1000u32.to_le_bytes()); // main_stack_size
    npdm[0x20..0x2B].copy_from_slice(b"TestProgram");
    // ACI0 at 0x80, size 0x200; ACID at 0x280, size 0x240
    npdm[0x70..0x74].copy_from_slice(&0x80u32.to_le_bytes());
    npdm[0x74..0x78].copy_from_slice(&0x200u32.to_le_bytes());
    npdm[0x78..0x7C].copy_from_slice(&0x280u32.to_le_bytes());
    npdm[0x7C..0x80].copy_from_slice(&0x240u32.to_le_bytes());

    // ACI0 header at 0x80
    npdm[0x80..0x84].copy_from_slice(&0x30494341u32.to_le_bytes()); // "ACI0"
    npdm[0x90..0x98].copy_from_slice(&0x0100000000001234u64.to_le_bytes()); // title_id
    // FSA at 0x80 + 0x40 = 0xC0, size 0x1C
    npdm[0xA0..0xA4].copy_from_slice(&0x40u32.to_le_bytes());
    npdm[0xA4..0xA8].copy_from_slice(&0x1Cu32.to_le_bytes());
    // SAC at 0x80 + 0x60 = 0xE0, size 0x10
    npdm[0xA8..0xAC].copy_from_slice(&0x60u32.to_le_bytes());
    npdm[0xAC..0xB0].copy_from_slice(&0x10u32.to_le_bytes());
    // KAC at 0x80 + 0x70 = 0xF0, size 0x8
    npdm[0xB0..0xB4].copy_from_slice(&0x70u32.to_le_bytes());
    npdm[0xB4..0xB8].copy_from_slice(&0x08u32.to_le_bytes());

    // FSA permissions at 0xC4: bit 0 = 1
    npdm[0xC0] = 1;
    npdm[0xC4..0xCC].copy_from_slice(&1u64.to_le_bytes());
    // SAC at 0xE0: host service "sm:" (0x80 | 3)
    npdm[0xE0] = 0x83;
    npdm[0xE1..0xE4].copy_from_slice(b"sm:");
    // KAC at 0xF0: syscall mask for bank 5 (5 << 29) with bit 7 set (syscall 0x78 + 7 = 0x7F!)
    let kac_desc: u32 = 0x0F | (5 << 29) | (1 << (5 + 7));
    npdm[0xF0..0xF4].copy_from_slice(&kac_desc.to_le_bytes());
    // Kernel version descriptor: (15 << 15) - 1 = 0x77FFF, major=5, minor=0
    let kv_desc: u32 = 0x3FFF | (5 << 19);
    npdm[0xF4..0xF8].copy_from_slice(&kv_desc.to_le_bytes());

    // ACID header at 0x280
    npdm[0x280 + 0x200..0x280 + 0x204].copy_from_slice(&0x44494341u32.to_le_bytes()); // "ACID"
    npdm[0x280 + 0x210..0x280 + 0x218].copy_from_slice(&0x0100000000000000u64.to_le_bytes());
    npdm[0x280 + 0x218..0x280 + 0x220].copy_from_slice(&0x01FFFFFFFFFFFFFFu64.to_le_bytes());
    npdm[0x280 + 0x220..0x280 + 0x224].copy_from_slice(&0x240u32.to_le_bytes());
    npdm[0x280 + 0x224..0x280 + 0x228].copy_from_slice(&0u32.to_le_bytes());

    let json = npdm_get_json(&npdm);
    assert!(json.contains("\"name\":\t\"TestProgram\""));
    assert!(json.contains("\"svcCallSecureMonitorsvcUnknown\":\t\"0x7f\""));

    // 2. Construct a valid synthetic PFS0 with 2 files ("main.npdm" and "hello.txt")
    let file2_data = b"Hello from Rust hactool port!";
    let mut pfs0_bytes = Vec::new();
    pfs0_bytes.extend_from_slice(&MAGIC_PFS0.to_le_bytes());
    pfs0_bytes.extend_from_slice(&2u32.to_le_bytes()); // num_files = 2
    pfs0_bytes.extend_from_slice(&0x20u32.to_le_bytes()); // strtab_size = 0x20
    pfs0_bytes.extend_from_slice(&0u32.to_le_bytes()); // reserved
    // Entry 0: main.npdm
    pfs0_bytes.extend_from_slice(&0u64.to_le_bytes()); // offset
    pfs0_bytes.extend_from_slice(&(npdm.len() as u64).to_le_bytes()); // size
    pfs0_bytes.extend_from_slice(&0u32.to_le_bytes()); // strtab_ofs
    pfs0_bytes.extend_from_slice(&0u32.to_le_bytes()); // reserved
    // Entry 1: hello.txt
    pfs0_bytes.extend_from_slice(&(npdm.len() as u64).to_le_bytes()); // offset
    pfs0_bytes.extend_from_slice(&(file2_data.len() as u64).to_le_bytes()); // size
    pfs0_bytes.extend_from_slice(&10u32.to_le_bytes()); // strtab_ofs
    pfs0_bytes.extend_from_slice(&0u32.to_le_bytes()); // reserved
    // String table (0x20 bytes)
    let mut strtab = [0u8; 0x20];
    strtab[0..9].copy_from_slice(b"main.npdm");
    strtab[10..19].copy_from_slice(b"hello.txt");
    pfs0_bytes.extend_from_slice(&strtab);
    // Payloads
    pfs0_bytes.extend_from_slice(&npdm);
    pfs0_bytes.extend_from_slice(file2_data);

    let pfs0_path = temp_dir.join("test.pfs0");
    let pfs0_out = temp_dir.join("pfs0_out");
    File::create(&pfs0_path).unwrap().write_all(&pfs0_bytes).unwrap();

    let mut tool_ctx = HactoolCtx::new();
    tool_ctx.file_type = FileType::Pfs0;
    tool_ctx.action = ACTION_INFO | ACTION_EXTRACT | ACTION_VERIFY;
    tool_ctx.settings.pfs0_dir_path.set(pfs0_out.to_str().unwrap());
    let sf = SharedFile::new(File::open(&pfs0_path).unwrap());
    let mut pfs0_ctx = Pfs0Ctx::new();
    pfs0_ctx.file = Some(sf);
    pfs0_process(&mut pfs0_ctx, &mut tool_ctx);

    let extracted_hello = std::fs::read(pfs0_out.join("hello.txt")).unwrap();
    assert_eq!(extracted_hello, file2_data);
    let extracted_npdm = std::fs::read(pfs0_out.join("main.npdm")).unwrap();
    assert_eq!(extracted_npdm, npdm);
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_stateless_ctr_at_unaligned_and_carry() {
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let iv: [u8; 16] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFD,
    ];

    let total_len = 1_300_000usize;
    let plaintext: Vec<u8> = (0..total_len)
        .map(|i| (i.wrapping_mul(131) ^ (i >> 7)) as u8)
        .collect();
    let mut ciphertext = vec![0u8; total_len];
    let mut enc_ctx = AesCtx::new(&key, 16, AesMode::Ctr);
    enc_ctx.set_iv(&iv);
    enc_ctx.encrypt(&plaintext, &mut ciphertext);

    let dec_ctx = AesCtx::new(&key, 16, AesMode::Ctr);

    // Exhaustive unaligned offsets & sizes including tiny <16B, cross-block, counter carry (~64B), and >= PAR_THRESHOLD
    let cases: &[(u64, usize)] = &[
        (0, 0),
        (1, 1),
        (7, 5),
        (15, 1),
        (15, 2),
        (13, 19),
        (37, 0x45),
        (0x1FF, 0x203),
        (19, 1_100_003),
        (0x20001, 700_000),
    ];

    for &(ofs, len) in cases {
        let start = ofs as usize;
        let end = start + len;
        let iv_at = u128::from_be_bytes(iv)
            .wrapping_add((ofs >> 4) as u128)
            .to_be_bytes();
        let block_ofs = (ofs & 0xF) as usize;
        let mut out = vec![0xAAu8; len];
        dec_ctx.ctr_decrypt_at(&iv_at, block_ofs, &ciphertext[start..end], &mut out);
        assert_eq!(out, plaintext[start..end], "ctr_decrypt_at mismatch at ofs={ofs} len={len}");

        let mut in_place = ciphertext[start..end].to_vec();
        dec_ctx.ctr_decrypt_in_place_at(&iv_at, block_ofs, &mut in_place);
        assert_eq!(
            in_place,
            plaintext[start..end],
            "ctr_decrypt_in_place_at mismatch at ofs={ofs} len={len}"
        );
    }
}

fn push_romfs_dir(
    buf: &mut Vec<u8>,
    parent: u32,
    sibling: u32,
    child: u32,
    file: u32,
    name: &[u8],
) -> u32 {
    let ofs = buf.len() as u32;
    buf.extend_from_slice(&parent.to_le_bytes());
    buf.extend_from_slice(&sibling.to_le_bytes());
    buf.extend_from_slice(&child.to_le_bytes());
    buf.extend_from_slice(&file.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // hash
    buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buf.extend_from_slice(name);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    ofs
}

fn push_romfs_file(
    buf: &mut Vec<u8>,
    parent: u32,
    sibling: u32,
    offset: u64,
    size: u64,
    name: &[u8],
) -> u32 {
    let ofs = buf.len() as u32;
    buf.extend_from_slice(&parent.to_le_bytes());
    buf.extend_from_slice(&sibling.to_le_bytes());
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // hash
    buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buf.extend_from_slice(name);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    ofs
}

#[test]
fn test_romfs_parallel_extraction_and_cli_quiet() {
    let temp_dir = std::env::temp_dir().join("hactool_rust_romfs_cli_tests");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    // Build synthetic RomFS:
    // /root.bin (13 bytes)
    // /empty_dir/ (empty dir)
    // /sub/deep/zero.bin (0 bytes)
    // /sub/deep/payload.bin (1 MiB)
    let root_data = b"root_payload!".to_vec();
    let payload_data: Vec<u8> = (0usize..1024 * 1024).map(|i| i.wrapping_mul(17) as u8).collect();

    let mut files = Vec::new();
    let f_root_ofs = push_romfs_file(&mut files, 0, ROMFS_ENTRY_EMPTY, 0, root_data.len() as u64, b"root.bin");
    let f_payload_ofs = push_romfs_file(
        &mut files,
        0, // patched below
        ROMFS_ENTRY_EMPTY,
        root_data.len() as u64,
        payload_data.len() as u64,
        b"payload.bin",
    );
    let f_zero_ofs = push_romfs_file(
        &mut files,
        0,
        f_payload_ofs,
        root_data.len() as u64 + payload_data.len() as u64,
        0,
        b"zero.bin",
    );

    // Precompute dir offsets cleanly: root at 0 (name=""), empty_dir, sub, deep
    let mut dirs = Vec::new();
    let d_root = push_romfs_dir(&mut dirs, 0, ROMFS_ENTRY_EMPTY, 0, f_root_ofs, b"");
    let d_empty = push_romfs_dir(&mut dirs, d_root, 0, ROMFS_ENTRY_EMPTY, ROMFS_ENTRY_EMPTY, b"empty_dir");
    let d_sub = push_romfs_dir(&mut dirs, d_root, ROMFS_ENTRY_EMPTY, 0, ROMFS_ENTRY_EMPTY, b"sub");
    let d_deep = push_romfs_dir(&mut dirs, d_sub, ROMFS_ENTRY_EMPTY, ROMFS_ENTRY_EMPTY, f_zero_ofs, b"deep");

    // Patch root.child = d_empty, empty_dir.sibling = d_sub, sub.child = d_deep
    dirs[d_root as usize + 8..d_root as usize + 12].copy_from_slice(&d_empty.to_le_bytes());
    dirs[d_empty as usize + 4..d_empty as usize + 8].copy_from_slice(&d_sub.to_le_bytes());
    dirs[d_sub as usize + 8..d_sub as usize + 12].copy_from_slice(&d_deep.to_le_bytes());
    // Patch file parents for deep dir files
    files[f_zero_ofs as usize..f_zero_ofs as usize + 4].copy_from_slice(&d_deep.to_le_bytes());
    files[f_payload_ofs as usize..f_payload_ofs as usize + 4].copy_from_slice(&d_deep.to_le_bytes());

    let dir_meta_ofs = ROMFS_HEADER_SIZE;
    let file_meta_ofs = dir_meta_ofs + dirs.len() as u64;
    let data_ofs = file_meta_ofs + files.len() as u64;

    let mut romfs_img = Vec::new();
    romfs_img.extend_from_slice(&ROMFS_HEADER_SIZE.to_le_bytes()); // header_size
    romfs_img.extend_from_slice(&ROMFS_HEADER_SIZE.to_le_bytes()); // dir_hash_table_offset
    romfs_img.extend_from_slice(&0u64.to_le_bytes()); // dir_hash_table_size
    romfs_img.extend_from_slice(&dir_meta_ofs.to_le_bytes()); // dir_meta_table_offset
    romfs_img.extend_from_slice(&(dirs.len() as u64).to_le_bytes()); // dir_meta_table_size
    romfs_img.extend_from_slice(&file_meta_ofs.to_le_bytes()); // file_hash_table_offset
    romfs_img.extend_from_slice(&0u64.to_le_bytes()); // file_hash_table_size
    romfs_img.extend_from_slice(&file_meta_ofs.to_le_bytes()); // file_meta_table_offset
    romfs_img.extend_from_slice(&(files.len() as u64).to_le_bytes()); // file_meta_table_size
    romfs_img.extend_from_slice(&data_ofs.to_le_bytes()); // data_offset
    romfs_img.extend_from_slice(&dirs);
    romfs_img.extend_from_slice(&files);
    romfs_img.extend_from_slice(&root_data);
    romfs_img.extend_from_slice(&payload_data);

    let romfs_path = temp_dir.join("test.romfs");
    let romfs_out = temp_dir.join("romfs_out");
    File::create(&romfs_path).unwrap().write_all(&romfs_img).unwrap();

    let mut tool_ctx = HactoolCtx::new();
    tool_ctx.file_type = FileType::Romfs;
    tool_ctx.action = ACTION_EXTRACT;
    tool_ctx.settings.quiet = true;
    tool_ctx.settings.romfs_dir_path.enabled = true;
    tool_ctx.settings.romfs_dir_path.path.set(romfs_out.to_str().unwrap());
    let mut romfs_ctx = RomfsCtx::default();
    romfs_ctx.file = Some(SharedFile::open(&romfs_path).unwrap());
    romfs_process(&mut romfs_ctx, &mut tool_ctx);

    assert!(romfs_out.join("empty_dir").is_dir());
    assert_eq!(std::fs::read(romfs_out.join("root.bin")).unwrap(), root_data);
    assert_eq!(std::fs::read(romfs_out.join("sub").join("deep").join("zero.bin")).unwrap().len(), 0);
    assert_eq!(std::fs::read(romfs_out.join("sub").join("deep").join("payload.bin")).unwrap(), payload_data);

    // 2. Test compiled binary CLI `-q` / `--quiet` + parallel PFS0 extraction
    let bin = env!("CARGO_BIN_EXE_hactool");
    let pfs0_file = temp_dir.join("cli.pfs0");
    let cli_data1 = b"alpha_file".to_vec();
    let cli_data2 = b"beta_file_contents".to_vec();
    let mut pfs0_bytes = Vec::new();
    pfs0_bytes.extend_from_slice(&MAGIC_PFS0.to_le_bytes());
    pfs0_bytes.extend_from_slice(&2u32.to_le_bytes());
    pfs0_bytes.extend_from_slice(&0x10u32.to_le_bytes());
    pfs0_bytes.extend_from_slice(&0u32.to_le_bytes());
    // Entry 0: a.bin
    pfs0_bytes.extend_from_slice(&0u64.to_le_bytes());
    pfs0_bytes.extend_from_slice(&(cli_data1.len() as u64).to_le_bytes());
    pfs0_bytes.extend_from_slice(&0u32.to_le_bytes());
    pfs0_bytes.extend_from_slice(&0u32.to_le_bytes());
    // Entry 1: b.bin
    pfs0_bytes.extend_from_slice(&(cli_data1.len() as u64).to_le_bytes());
    pfs0_bytes.extend_from_slice(&(cli_data2.len() as u64).to_le_bytes());
    pfs0_bytes.extend_from_slice(&6u32.to_le_bytes());
    pfs0_bytes.extend_from_slice(&0u32.to_le_bytes());
    let mut strtab = [0u8; 0x10];
    strtab[0..5].copy_from_slice(b"a.bin");
    strtab[6..11].copy_from_slice(b"b.bin");
    pfs0_bytes.extend_from_slice(&strtab);
    pfs0_bytes.extend_from_slice(&cli_data1);
    pfs0_bytes.extend_from_slice(&cli_data2);
    File::create(&pfs0_file).unwrap().write_all(&pfs0_bytes).unwrap();

    let out_verbose = temp_dir.join("cli_verbose");
    let res_v = Command::new(bin)
        .args(["-t", "pfs0", "--disablekeywarns", "--pfs0dir", out_verbose.to_str().unwrap(), pfs0_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(res_v.status.success());
    let stdout_v = String::from_utf8_lossy(&res_v.stdout);
    assert!(stdout_v.contains("Saving a.bin to"));
    assert!(stdout_v.contains("Saving b.bin to"));
    assert!(stdout_v.contains("Done!"));

    let out_quiet = temp_dir.join("cli_quiet");
    let res_q = Command::new(bin)
        .args(["-q", "-t", "pfs0", "--disablekeywarns", "--pfs0dir", out_quiet.to_str().unwrap(), pfs0_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(res_q.status.success());
    let stdout_q = String::from_utf8_lossy(&res_q.stdout);
    assert!(!stdout_q.contains("Saving "), "Expected no Saving lines in -q output, got: {stdout_q}");
    assert!(stdout_q.contains("Done!"));
    assert_eq!(std::fs::read(out_quiet.join("a.bin")).unwrap(), cli_data1);
    assert_eq!(std::fs::read(out_quiet.join("b.bin")).unwrap(), cli_data2);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_create_uncompressed_file_basic_and_windows_ntfs() {
    let temp_dir = std::env::temp_dir().join(format!(
        "hactool_uncompressed_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let plain_path = temp_dir.join("plain.bin");
    {
        let mut f = create_uncompressed_file(&plain_path).unwrap();
        f.write_all(b"hactool-rs payload").unwrap();
    }
    assert_eq!(std::fs::read(&plain_path).unwrap(), b"hactool-rs payload");

    #[cfg(windows)]
    {
        use std::ffi::c_void;
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use std::os::windows::io::AsRawHandle;

        const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x0800;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FSCTL_SET_COMPRESSION: u32 = 0x0009_C040;
        const COMPRESSION_FORMAT_DEFAULT: u16 = 1;

        #[link(name = "kernel32")]
        extern "system" {
            fn DeviceIoControl(
                h_device: *mut c_void,
                dw_io_control_code: u32,
                lp_in_buffer: *mut c_void,
                n_in_buffer_size: u32,
                lp_out_buffer: *mut c_void,
                n_out_buffer_size: u32,
                lp_bytes_returned: *mut u32,
                lp_overlapped: *mut c_void,
            ) -> i32;
        }

        let comp_dir = temp_dir.join("compressed_parent");
        std::fs::create_dir_all(&comp_dir).unwrap();
        if let Ok(dir_handle) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&comp_dir)
        {
            let mut fmt = COMPRESSION_FORMAT_DEFAULT;
            let mut ret: u32 = 0;
            let ok = unsafe {
                DeviceIoControl(
                    dir_handle.as_raw_handle(),
                    FSCTL_SET_COMPRESSION,
                    (&mut fmt as *mut u16).cast(),
                    2,
                    std::ptr::null_mut(),
                    0,
                    &mut ret,
                    std::ptr::null_mut(),
                )
            };
            if ok != 0
                && (std::fs::metadata(&comp_dir).unwrap().file_attributes()
                    & FILE_ATTRIBUTE_COMPRESSED)
                    != 0
            {
                let out_file = comp_dir.join("extracted.nca");
                {
                    let mut f = create_uncompressed_file(&out_file).unwrap();
                    f.write_all(&[0x5Au8; 64 * 1024]).unwrap();
                }
                let attrs = std::fs::metadata(&out_file).unwrap().file_attributes();
                assert_eq!(
                    attrs & FILE_ATTRIBUTE_COMPRESSED,
                    0,
                    "Expected FILE_ATTRIBUTE_COMPRESSED to be cleared on new output file"
                );

                let nested_dir = comp_dir.join("nested").join("romfs");
                os_makedir(&nested_dir);
                let dir_attrs = std::fs::metadata(&nested_dir).unwrap().file_attributes();
                assert_eq!(
                    dir_attrs & FILE_ATTRIBUTE_COMPRESSED,
                    0,
                    "Expected FILE_ATTRIBUTE_COMPRESSED to be cleared on os_makedir output directory"
                );
            }
        }
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}
