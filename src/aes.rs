#![allow(dead_code)]

//! High-performance AES-128 implementation with x86_64 AES-NI hardware acceleration,
//! 8-block pipelined CTR mode, Rayon-parallelized CTR/XTS, CBC, ECB, and CMAC.

use rayon::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AesMode {
    Ecb,
    Ctr,
    Xts,
    CbcEnc,
    CbcDec,
}

/// Expanded AES-128 key schedule (11 round keys of 16 bytes each)
#[derive(Clone, Copy)]
pub struct Aes128Key {
    pub enc_keys: [[u8; 16]; 11],
    pub dec_keys: [[u8; 16]; 11],
    pub use_aesni: bool,
}

// Standard AES S-Box and Inverse S-Box for key expansion and portable fallback
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

#[inline(always)]
fn gmul2(x: u8) -> u8 {
    (x << 1) ^ (if (x & 0x80) != 0 { 0x1b } else { 0 })
}

#[inline(always)]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

#[inline(always)]
fn inv_mix_column(col: &mut [u8; 4]) {
    let a = col[0];
    let b = col[1];
    let c = col[2];
    let d = col[3];
    col[0] = gmul(a, 0x0e) ^ gmul(b, 0x0b) ^ gmul(c, 0x0d) ^ gmul(d, 0x09);
    col[1] = gmul(a, 0x09) ^ gmul(b, 0x0e) ^ gmul(c, 0x0b) ^ gmul(d, 0x0d);
    col[2] = gmul(a, 0x0d) ^ gmul(b, 0x09) ^ gmul(c, 0x0e) ^ gmul(d, 0x0b);
    col[3] = gmul(a, 0x0b) ^ gmul(b, 0x0d) ^ gmul(c, 0x09) ^ gmul(d, 0x0e);
}

impl Aes128Key {
    pub fn new(key: &[u8]) -> Self {
        let mut enc_keys = [[0u8; 16]; 11];
        enc_keys[0].copy_from_slice(&key[0..16]);

        for r in 1..11 {
            let prev = enc_keys[r - 1];
            let mut cur = [0u8; 16];
            // RotWord + SubWord + Rcon
            cur[0] = prev[0] ^ SBOX[prev[13] as usize] ^ RCON[r - 1];
            cur[1] = prev[1] ^ SBOX[prev[14] as usize];
            cur[2] = prev[2] ^ SBOX[prev[15] as usize];
            cur[3] = prev[3] ^ SBOX[prev[12] as usize];

            for i in 4..16 {
                cur[i] = prev[i] ^ cur[i - 4];
            }
            enc_keys[r] = cur;
        }

        let mut dec_keys = [[0u8; 16]; 11];
        dec_keys[0] = enc_keys[10];
        dec_keys[10] = enc_keys[0];

        #[cfg(target_arch = "x86_64")]
        let use_aesni = std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("sse2")
            && std::is_x86_feature_detected!("ssse3");
        #[cfg(not(target_arch = "x86_64"))]
        let use_aesni = false;

        for r in 1..10 {
            let mut k = enc_keys[10 - r];
            for c in 0..4 {
                let mut col = [k[c * 4], k[c * 4 + 1], k[c * 4 + 2], k[c * 4 + 3]];
                inv_mix_column(&mut col);
                k[c * 4] = col[0];
                k[c * 4 + 1] = col[1];
                k[c * 4 + 2] = col[2];
                k[c * 4 + 3] = col[3];
            }
            dec_keys[r] = k;
        }

        Self {
            enc_keys,
            dec_keys,
            use_aesni,
        }
    }

    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        #[cfg(target_arch = "x86_64")]
        if self.use_aesni {
            unsafe {
                self.encrypt_block_aesni(block);
            }
            return;
        }
        self.encrypt_block_soft(block);
    }

    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        #[cfg(target_arch = "x86_64")]
        if self.use_aesni {
            unsafe {
                self.decrypt_block_aesni(block);
            }
            return;
        }
        self.decrypt_block_soft(block);
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes,sse2")]
    unsafe fn encrypt_block_aesni(&self, block: &mut [u8; 16]) {
        use core::arch::x86_64::*;
        unsafe {
            let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            state = _mm_xor_si128(state, _mm_loadu_si128(self.enc_keys[0].as_ptr() as *const __m128i));
            for r in 1..10 {
                state = _mm_aesenc_si128(state, _mm_loadu_si128(self.enc_keys[r].as_ptr() as *const __m128i));
            }
            state = _mm_aesenclast_si128(state, _mm_loadu_si128(self.enc_keys[10].as_ptr() as *const __m128i));
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes,sse2")]
    unsafe fn decrypt_block_aesni(&self, block: &mut [u8; 16]) {
        use core::arch::x86_64::*;
        unsafe {
            let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            state = _mm_xor_si128(state, _mm_loadu_si128(self.dec_keys[0].as_ptr() as *const __m128i));
            for r in 1..10 {
                state = _mm_aesdec_si128(state, _mm_loadu_si128(self.dec_keys[r].as_ptr() as *const __m128i));
            }
            state = _mm_aesdeclast_si128(state, _mm_loadu_si128(self.dec_keys[10].as_ptr() as *const __m128i));
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
        }
    }

    fn encrypt_block_soft(&self, block: &mut [u8; 16]) {
        for i in 0..16 {
            block[i] ^= self.enc_keys[0][i];
        }
        for r in 1..10 {
            // SubBytes + ShiftRows
            let mut s = [0u8; 16];
            s[0] = SBOX[block[0] as usize];
            s[1] = SBOX[block[5] as usize];
            s[2] = SBOX[block[10] as usize];
            s[3] = SBOX[block[15] as usize];
            s[4] = SBOX[block[4] as usize];
            s[5] = SBOX[block[9] as usize];
            s[6] = SBOX[block[14] as usize];
            s[7] = SBOX[block[3] as usize];
            s[8] = SBOX[block[8] as usize];
            s[9] = SBOX[block[13] as usize];
            s[10] = SBOX[block[2] as usize];
            s[11] = SBOX[block[7] as usize];
            s[12] = SBOX[block[12] as usize];
            s[13] = SBOX[block[1] as usize];
            s[14] = SBOX[block[6] as usize];
            s[15] = SBOX[block[11] as usize];

            // MixColumns + AddRoundKey
            for c in 0..4 {
                let i = c * 4;
                let a0 = s[i];
                let a1 = s[i + 1];
                let a2 = s[i + 2];
                let a3 = s[i + 3];
                let t = a0 ^ a1 ^ a2 ^ a3;
                block[i] = a0 ^ t ^ gmul2(a0 ^ a1) ^ self.enc_keys[r][i];
                block[i + 1] = a1 ^ t ^ gmul2(a1 ^ a2) ^ self.enc_keys[r][i + 1];
                block[i + 2] = a2 ^ t ^ gmul2(a2 ^ a3) ^ self.enc_keys[r][i + 2];
                block[i + 3] = a3 ^ t ^ gmul2(a3 ^ a0) ^ self.enc_keys[r][i + 3];
            }
        }
        // Final round
        let mut s = [0u8; 16];
        s[0] = SBOX[block[0] as usize] ^ self.enc_keys[10][0];
        s[1] = SBOX[block[5] as usize] ^ self.enc_keys[10][1];
        s[2] = SBOX[block[10] as usize] ^ self.enc_keys[10][2];
        s[3] = SBOX[block[15] as usize] ^ self.enc_keys[10][3];
        s[4] = SBOX[block[4] as usize] ^ self.enc_keys[10][4];
        s[5] = SBOX[block[9] as usize] ^ self.enc_keys[10][5];
        s[6] = SBOX[block[14] as usize] ^ self.enc_keys[10][6];
        s[7] = SBOX[block[3] as usize] ^ self.enc_keys[10][7];
        s[8] = SBOX[block[8] as usize] ^ self.enc_keys[10][8];
        s[9] = SBOX[block[13] as usize] ^ self.enc_keys[10][9];
        s[10] = SBOX[block[2] as usize] ^ self.enc_keys[10][10];
        s[11] = SBOX[block[7] as usize] ^ self.enc_keys[10][11];
        s[12] = SBOX[block[12] as usize] ^ self.enc_keys[10][12];
        s[13] = SBOX[block[1] as usize] ^ self.enc_keys[10][13];
        s[14] = SBOX[block[6] as usize] ^ self.enc_keys[10][14];
        s[15] = SBOX[block[11] as usize] ^ self.enc_keys[10][15];
        *block = s;
    }

    fn decrypt_block_soft(&self, block: &mut [u8; 16]) {
        for i in 0..16 {
            block[i] ^= self.enc_keys[10][i];
        }
        for r in (1..10).rev() {
            // InvShiftRows + InvSubBytes + AddRoundKey
            let mut s = [0u8; 16];
            s[0] = INV_SBOX[block[0] as usize] ^ self.enc_keys[r][0];
            s[1] = INV_SBOX[block[13] as usize] ^ self.enc_keys[r][1];
            s[2] = INV_SBOX[block[10] as usize] ^ self.enc_keys[r][2];
            s[3] = INV_SBOX[block[7] as usize] ^ self.enc_keys[r][3];
            s[4] = INV_SBOX[block[4] as usize] ^ self.enc_keys[r][4];
            s[5] = INV_SBOX[block[1] as usize] ^ self.enc_keys[r][5];
            s[6] = INV_SBOX[block[14] as usize] ^ self.enc_keys[r][6];
            s[7] = INV_SBOX[block[11] as usize] ^ self.enc_keys[r][7];
            s[8] = INV_SBOX[block[8] as usize] ^ self.enc_keys[r][8];
            s[9] = INV_SBOX[block[5] as usize] ^ self.enc_keys[r][9];
            s[10] = INV_SBOX[block[2] as usize] ^ self.enc_keys[r][10];
            s[11] = INV_SBOX[block[15] as usize] ^ self.enc_keys[r][11];
            s[12] = INV_SBOX[block[12] as usize] ^ self.enc_keys[r][12];
            s[13] = INV_SBOX[block[9] as usize] ^ self.enc_keys[r][13];
            s[14] = INV_SBOX[block[6] as usize] ^ self.enc_keys[r][14];
            s[15] = INV_SBOX[block[3] as usize] ^ self.enc_keys[r][15];

            // InvMixColumns
            for c in 0..4 {
                let mut col = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
                inv_mix_column(&mut col);
                block[c * 4] = col[0];
                block[c * 4 + 1] = col[1];
                block[c * 4 + 2] = col[2];
                block[c * 4 + 3] = col[3];
            }
        }
        // Final round
        let mut s = [0u8; 16];
        s[0] = INV_SBOX[block[0] as usize] ^ self.enc_keys[0][0];
        s[1] = INV_SBOX[block[13] as usize] ^ self.enc_keys[0][1];
        s[2] = INV_SBOX[block[10] as usize] ^ self.enc_keys[0][2];
        s[3] = INV_SBOX[block[7] as usize] ^ self.enc_keys[0][3];
        s[4] = INV_SBOX[block[4] as usize] ^ self.enc_keys[0][4];
        s[5] = INV_SBOX[block[1] as usize] ^ self.enc_keys[0][5];
        s[6] = INV_SBOX[block[14] as usize] ^ self.enc_keys[0][6];
        s[7] = INV_SBOX[block[11] as usize] ^ self.enc_keys[0][7];
        s[8] = INV_SBOX[block[8] as usize] ^ self.enc_keys[0][8];
        s[9] = INV_SBOX[block[5] as usize] ^ self.enc_keys[0][9];
        s[10] = INV_SBOX[block[2] as usize] ^ self.enc_keys[0][10];
        s[11] = INV_SBOX[block[15] as usize] ^ self.enc_keys[0][11];
        s[12] = INV_SBOX[block[12] as usize] ^ self.enc_keys[0][12];
        s[13] = INV_SBOX[block[9] as usize] ^ self.enc_keys[0][13];
        s[14] = INV_SBOX[block[6] as usize] ^ self.enc_keys[0][14];
        s[15] = INV_SBOX[block[3] as usize] ^ self.enc_keys[0][15];
        *block = s;
    }

    /// Pipelined 8-block CTR encryption/decryption using AES-NI (in-place)
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes,sse2,ssse3")]
    unsafe fn ctr_crypt_aesni(&self, buf: &mut [u8], ctr: &mut [u8; 16]) {
        use core::arch::x86_64::*;
        unsafe {
            let rk0 = _mm_loadu_si128(self.enc_keys[0].as_ptr() as *const __m128i);
            let rk1 = _mm_loadu_si128(self.enc_keys[1].as_ptr() as *const __m128i);
            let rk2 = _mm_loadu_si128(self.enc_keys[2].as_ptr() as *const __m128i);
            let rk3 = _mm_loadu_si128(self.enc_keys[3].as_ptr() as *const __m128i);
            let rk4 = _mm_loadu_si128(self.enc_keys[4].as_ptr() as *const __m128i);
            let rk5 = _mm_loadu_si128(self.enc_keys[5].as_ptr() as *const __m128i);
            let rk6 = _mm_loadu_si128(self.enc_keys[6].as_ptr() as *const __m128i);
            let rk7 = _mm_loadu_si128(self.enc_keys[7].as_ptr() as *const __m128i);
            let rk8 = _mm_loadu_si128(self.enc_keys[8].as_ptr() as *const __m128i);
            let rk9 = _mm_loadu_si128(self.enc_keys[9].as_ptr() as *const __m128i);
            let rk10 = _mm_loadu_si128(self.enc_keys[10].as_ptr() as *const __m128i);

            let mut hi = u64::from_be_bytes(ctr[0..8].try_into().unwrap());
            let mut lo = u64::from_be_bytes(ctr[8..16].try_into().unwrap());

            let mut offset = 0usize;
            let len = buf.len();

            macro_rules! next_ctr_xmm {
                () => {{
                    let v = _mm_set_epi64x(lo.swap_bytes() as i64, hi.swap_bytes() as i64);
                    let (nlo, carry) = lo.overflowing_add(1);
                    lo = nlo;
                    if carry {
                        hi = hi.wrapping_add(1);
                    }
                    v
                }};
            }

            // Process 8 blocks (128 bytes) per iteration to saturate AES-NI pipeline
            while offset + 128 <= len {
                let mut s0 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s1 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s2 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s3 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s4 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s5 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s6 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s7 = _mm_xor_si128(next_ctr_xmm!(), rk0);

                macro_rules! round {
                    ($rk:expr) => {
                        s0 = _mm_aesenc_si128(s0, $rk);
                        s1 = _mm_aesenc_si128(s1, $rk);
                        s2 = _mm_aesenc_si128(s2, $rk);
                        s3 = _mm_aesenc_si128(s3, $rk);
                        s4 = _mm_aesenc_si128(s4, $rk);
                        s5 = _mm_aesenc_si128(s5, $rk);
                        s6 = _mm_aesenc_si128(s6, $rk);
                        s7 = _mm_aesenc_si128(s7, $rk);
                    };
                }

                round!(rk1);
                round!(rk2);
                round!(rk3);
                round!(rk4);
                round!(rk5);
                round!(rk6);
                round!(rk7);
                round!(rk8);
                round!(rk9);

                s0 = _mm_aesenclast_si128(s0, rk10);
                s1 = _mm_aesenclast_si128(s1, rk10);
                s2 = _mm_aesenclast_si128(s2, rk10);
                s3 = _mm_aesenclast_si128(s3, rk10);
                s4 = _mm_aesenclast_si128(s4, rk10);
                s5 = _mm_aesenclast_si128(s5, rk10);
                s6 = _mm_aesenclast_si128(s6, rk10);
                s7 = _mm_aesenclast_si128(s7, rk10);

                let ptr = buf.as_mut_ptr().add(offset) as *mut __m128i;
                _mm_storeu_si128(ptr.add(0), _mm_xor_si128(_mm_loadu_si128(ptr.add(0)), s0));
                _mm_storeu_si128(ptr.add(1), _mm_xor_si128(_mm_loadu_si128(ptr.add(1)), s1));
                _mm_storeu_si128(ptr.add(2), _mm_xor_si128(_mm_loadu_si128(ptr.add(2)), s2));
                _mm_storeu_si128(ptr.add(3), _mm_xor_si128(_mm_loadu_si128(ptr.add(3)), s3));
                _mm_storeu_si128(ptr.add(4), _mm_xor_si128(_mm_loadu_si128(ptr.add(4)), s4));
                _mm_storeu_si128(ptr.add(5), _mm_xor_si128(_mm_loadu_si128(ptr.add(5)), s5));
                _mm_storeu_si128(ptr.add(6), _mm_xor_si128(_mm_loadu_si128(ptr.add(6)), s6));
                _mm_storeu_si128(ptr.add(7), _mm_xor_si128(_mm_loadu_si128(ptr.add(7)), s7));

                offset += 128;
            }

            // Remaining blocks
            while offset < len {
                let mut block = [0u8; 16];
                let mut state = _mm_xor_si128(next_ctr_xmm!(), rk0);
                state = _mm_aesenc_si128(state, rk1);
                state = _mm_aesenc_si128(state, rk2);
                state = _mm_aesenc_si128(state, rk3);
                state = _mm_aesenc_si128(state, rk4);
                state = _mm_aesenc_si128(state, rk5);
                state = _mm_aesenc_si128(state, rk6);
                state = _mm_aesenc_si128(state, rk7);
                state = _mm_aesenc_si128(state, rk8);
                state = _mm_aesenc_si128(state, rk9);
                state = _mm_aesenclast_si128(state, rk10);
                _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);

                let rem = (len - offset).min(16);
                for i in 0..rem {
                    buf[offset + i] ^= block[i];
                }
                offset += rem;
            }

            ctr[0..8].copy_from_slice(&hi.to_be_bytes());
            ctr[8..16].copy_from_slice(&lo.to_be_bytes());
        }
    }

    /// Pipelined 8-block CTR encryption/decryption using AES-NI (single-pass src -> dst)
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes,sse2,ssse3")]
    unsafe fn ctr_crypt_src_to_dst_aesni(
        &self,
        src: &[u8],
        dst: &mut [u8],
        ctr: &mut [u8; 16],
    ) {
        use core::arch::x86_64::*;
        unsafe {
            let rk0 = _mm_loadu_si128(self.enc_keys[0].as_ptr() as *const __m128i);
            let rk1 = _mm_loadu_si128(self.enc_keys[1].as_ptr() as *const __m128i);
            let rk2 = _mm_loadu_si128(self.enc_keys[2].as_ptr() as *const __m128i);
            let rk3 = _mm_loadu_si128(self.enc_keys[3].as_ptr() as *const __m128i);
            let rk4 = _mm_loadu_si128(self.enc_keys[4].as_ptr() as *const __m128i);
            let rk5 = _mm_loadu_si128(self.enc_keys[5].as_ptr() as *const __m128i);
            let rk6 = _mm_loadu_si128(self.enc_keys[6].as_ptr() as *const __m128i);
            let rk7 = _mm_loadu_si128(self.enc_keys[7].as_ptr() as *const __m128i);
            let rk8 = _mm_loadu_si128(self.enc_keys[8].as_ptr() as *const __m128i);
            let rk9 = _mm_loadu_si128(self.enc_keys[9].as_ptr() as *const __m128i);
            let rk10 = _mm_loadu_si128(self.enc_keys[10].as_ptr() as *const __m128i);

            let mut hi = u64::from_be_bytes(ctr[0..8].try_into().unwrap());
            let mut lo = u64::from_be_bytes(ctr[8..16].try_into().unwrap());

            let mut offset = 0usize;
            let len = src.len().min(dst.len());

            macro_rules! next_ctr_xmm {
                () => {{
                    let v = _mm_set_epi64x(lo.swap_bytes() as i64, hi.swap_bytes() as i64);
                    let (nlo, carry) = lo.overflowing_add(1);
                    lo = nlo;
                    if carry {
                        hi = hi.wrapping_add(1);
                    }
                    v
                }};
            }

            while offset + 128 <= len {
                let mut s0 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s1 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s2 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s3 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s4 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s5 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s6 = _mm_xor_si128(next_ctr_xmm!(), rk0);
                let mut s7 = _mm_xor_si128(next_ctr_xmm!(), rk0);

                macro_rules! round {
                    ($rk:expr) => {
                        s0 = _mm_aesenc_si128(s0, $rk);
                        s1 = _mm_aesenc_si128(s1, $rk);
                        s2 = _mm_aesenc_si128(s2, $rk);
                        s3 = _mm_aesenc_si128(s3, $rk);
                        s4 = _mm_aesenc_si128(s4, $rk);
                        s5 = _mm_aesenc_si128(s5, $rk);
                        s6 = _mm_aesenc_si128(s6, $rk);
                        s7 = _mm_aesenc_si128(s7, $rk);
                    };
                }

                round!(rk1);
                round!(rk2);
                round!(rk3);
                round!(rk4);
                round!(rk5);
                round!(rk6);
                round!(rk7);
                round!(rk8);
                round!(rk9);

                s0 = _mm_aesenclast_si128(s0, rk10);
                s1 = _mm_aesenclast_si128(s1, rk10);
                s2 = _mm_aesenclast_si128(s2, rk10);
                s3 = _mm_aesenclast_si128(s3, rk10);
                s4 = _mm_aesenclast_si128(s4, rk10);
                s5 = _mm_aesenclast_si128(s5, rk10);
                s6 = _mm_aesenclast_si128(s6, rk10);
                s7 = _mm_aesenclast_si128(s7, rk10);

                let s_ptr = src.as_ptr().add(offset) as *const __m128i;
                let d_ptr = dst.as_mut_ptr().add(offset) as *mut __m128i;
                _mm_storeu_si128(d_ptr.add(0), _mm_xor_si128(_mm_loadu_si128(s_ptr.add(0)), s0));
                _mm_storeu_si128(d_ptr.add(1), _mm_xor_si128(_mm_loadu_si128(s_ptr.add(1)), s1));
                _mm_storeu_si128(d_ptr.add(2), _mm_xor_si128(_mm_loadu_si128(s_ptr.add(2)), s2));
                _mm_storeu_si128(d_ptr.add(3), _mm_xor_si128(_mm_loadu_si128(s_ptr.add(3)), s3));
                _mm_storeu_si128(d_ptr.add(4), _mm_xor_si128(_mm_loadu_si128(s_ptr.add(4)), s4));
                _mm_storeu_si128(d_ptr.add(5), _mm_xor_si128(_mm_loadu_si128(s_ptr.add(5)), s5));
                _mm_storeu_si128(d_ptr.add(6), _mm_xor_si128(_mm_loadu_si128(s_ptr.add(6)), s6));
                _mm_storeu_si128(d_ptr.add(7), _mm_xor_si128(_mm_loadu_si128(s_ptr.add(7)), s7));

                offset += 128;
            }

            while offset < len {
                let mut block = [0u8; 16];
                let mut state = _mm_xor_si128(next_ctr_xmm!(), rk0);
                state = _mm_aesenc_si128(state, rk1);
                state = _mm_aesenc_si128(state, rk2);
                state = _mm_aesenc_si128(state, rk3);
                state = _mm_aesenc_si128(state, rk4);
                state = _mm_aesenc_si128(state, rk5);
                state = _mm_aesenc_si128(state, rk6);
                state = _mm_aesenc_si128(state, rk7);
                state = _mm_aesenc_si128(state, rk8);
                state = _mm_aesenc_si128(state, rk9);
                state = _mm_aesenclast_si128(state, rk10);
                _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);

                let rem = (len - offset).min(16);
                for i in 0..rem {
                    dst[offset + i] = src[offset + i] ^ block[i];
                }
                offset += rem;
            }

            ctr[0..8].copy_from_slice(&hi.to_be_bytes());
            ctr[8..16].copy_from_slice(&lo.to_be_bytes());
        }
    }

    pub fn ctr_crypt_chunk(&self, buf: &mut [u8], ctr: &mut [u8; 16]) {
        #[cfg(target_arch = "x86_64")]
        if self.use_aesni {
            unsafe {
                self.ctr_crypt_aesni(buf, ctr);
            }
            return;
        }

        let mut hi = u64::from_be_bytes(ctr[0..8].try_into().unwrap());
        let mut lo = u64::from_be_bytes(ctr[8..16].try_into().unwrap());

        for chunk in buf.chunks_mut(16) {
            let mut block = [0u8; 16];
            block[0..8].copy_from_slice(&hi.to_be_bytes());
            block[8..16].copy_from_slice(&lo.to_be_bytes());
            let (nlo, carry) = lo.overflowing_add(1);
            lo = nlo;
            if carry {
                hi = hi.wrapping_add(1);
            }

            self.encrypt_block_soft(&mut block);
            for (b, k) in chunk.iter_mut().zip(block.iter()) {
                *b ^= *k;
            }
        }

        ctr[0..8].copy_from_slice(&hi.to_be_bytes());
        ctr[8..16].copy_from_slice(&lo.to_be_bytes());
    }

    pub fn ctr_crypt_chunk_src_to_dst(
        &self,
        src: &[u8],
        dst: &mut [u8],
        ctr: &mut [u8; 16],
    ) {
        let len = src.len().min(dst.len());
        let src = &src[..len];
        let dst = &mut dst[..len];

        #[cfg(target_arch = "x86_64")]
        if self.use_aesni {
            unsafe {
                self.ctr_crypt_src_to_dst_aesni(src, dst, ctr);
            }
            return;
        }

        let mut hi = u64::from_be_bytes(ctr[0..8].try_into().unwrap());
        let mut lo = u64::from_be_bytes(ctr[8..16].try_into().unwrap());

        for (s_chunk, d_chunk) in src.chunks(16).zip(dst.chunks_mut(16)) {
            let mut block = [0u8; 16];
            block[0..8].copy_from_slice(&hi.to_be_bytes());
            block[8..16].copy_from_slice(&lo.to_be_bytes());
            let (nlo, carry) = lo.overflowing_add(1);
            lo = nlo;
            if carry {
                hi = hi.wrapping_add(1);
            }

            self.encrypt_block_soft(&mut block);
            for i in 0..s_chunk.len() {
                d_chunk[i] = s_chunk[i] ^ block[i];
            }
        }

        ctr[0..8].copy_from_slice(&hi.to_be_bytes());
        ctr[8..16].copy_from_slice(&lo.to_be_bytes());
    }
}

#[inline(always)]
fn add_ctr_blocks(ctr: &[u8; 16], blocks: u64) -> [u8; 16] {
    let hi = u64::from_be_bytes(ctr[0..8].try_into().unwrap());
    let lo = u64::from_be_bytes(ctr[8..16].try_into().unwrap());
    let (nlo, carry) = lo.overflowing_add(blocks);
    let nhi = hi.wrapping_add(if carry { 1 } else { 0 });
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&nhi.to_be_bytes());
    out[8..16].copy_from_slice(&nlo.to_be_bytes());
    out
}

/// GF(2^128) multiplication by x in little-endian polynomial representation (used by AES-XTS)
#[inline(always)]
fn gf128mul_x_ble(tweak: &mut [u8; 16]) {
    let mut lo = u64::from_le_bytes(tweak[0..8].try_into().unwrap());
    let mut hi = u64::from_le_bytes(tweak[8..16].try_into().unwrap());
    let carry = (hi >> 63) != 0;
    hi = (hi << 1) | (lo >> 63);
    lo <<= 1;
    if carry {
        lo ^= 0x87;
    }
    tweak[0..8].copy_from_slice(&lo.to_le_bytes());
    tweak[8..16].copy_from_slice(&hi.to_le_bytes());
}

/// Compute Nintendo's Big-Endian 16-byte sector tweak value
#[inline(always)]
fn get_nintendo_tweak( mut sector: usize) -> [u8; 16] {
    let mut tweak = [0u8; 16];
    for i in (0..16).rev() {
        tweak[i] = (sector & 0xFF) as u8;
        sector >>= 8;
    }
    tweak
}

/// AES context matching hactool's `aes_ctx_t`
#[derive(Clone)]
pub struct AesCtx {
    pub mode: AesMode,
    pub key1: Aes128Key,
    pub key2: Option<Aes128Key>, // Used for XTS tweak key (`key[16..32]`)
    pub iv: [u8; 16],
}

impl AesCtx {
    pub fn new(key: &[u8], key_bytes: usize, mode: AesMode) -> Self {
        let key1 = Aes128Key::new(&key[0..16]);
        let key2 = if mode == AesMode::Xts && key_bytes >= 32 {
            Some(Aes128Key::new(&key[16..32]))
        } else {
            None
        };
        Self {
            mode,
            key1,
            key2,
            iv: [0u8; 16],
        }
    }

    pub fn set_iv(&mut self, iv: &[u8]) {
        self.iv.copy_from_slice(&iv[0..16]);
    }

    /// Decrypt AES-CTR from `src` to `dst` statelessly starting at `base_iv` and intra-block offset `block_ofs` (0..16).
    /// Handles unaligned starts without extra reads and parallelizes payloads >= 512 KiB across rayon.
    pub fn ctr_decrypt_at(
        &self,
        base_iv: &[u8; 16],
        block_ofs: usize,
        src: &[u8],
        dst: &mut [u8],
    ) {
        debug_assert_eq!(self.mode, AesMode::Ctr);
        let len = src.len().min(dst.len());
        if len == 0 {
            return;
        }
        let src = &src[..len];
        let dst = &mut dst[..len];
        let block_ofs = block_ofs & 0xF;

        let mut ctr = *base_iv;
        let head_len = if block_ofs != 0 {
            let mut keystream = ctr;
            self.key1.encrypt_block(&mut keystream);
            ctr = add_ctr_blocks(&ctr, 1);
            let n = (16 - block_ofs).min(len);
            for i in 0..n {
                dst[i] = src[i] ^ keystream[block_ofs + i];
            }
            n
        } else {
            0
        };

        let s_rem = &src[head_len..];
        let d_rem = &mut dst[head_len..];
        if s_rem.is_empty() {
            return;
        }

        const PAR_THRESHOLD: usize = 512 * 1024;
        const CHUNK_BYTES: usize = 256 * 1024;
        if s_rem.len() >= PAR_THRESHOLD {
            let key = &self.key1;
            s_rem
                .par_chunks(CHUNK_BYTES)
                .zip(d_rem.par_chunks_mut(CHUNK_BYTES))
                .enumerate()
                .for_each(|(idx, (s_chunk, d_chunk))| {
                    let blocks_before = (idx as u64) * ((CHUNK_BYTES / 16) as u64);
                    let mut chunk_ctr = add_ctr_blocks(&ctr, blocks_before);
                    key.ctr_crypt_chunk_src_to_dst(s_chunk, d_chunk, &mut chunk_ctr);
                });
        } else {
            self.key1.ctr_crypt_chunk_src_to_dst(s_rem, d_rem, &mut ctr);
        }
    }

    /// Decrypt AES-CTR in place statelessly starting at `base_iv` and intra-block offset `block_ofs` (0..16).
    pub fn ctr_decrypt_in_place_at(&self, base_iv: &[u8; 16], block_ofs: usize, buf: &mut [u8]) {
        debug_assert_eq!(self.mode, AesMode::Ctr);
        if buf.is_empty() {
            return;
        }
        let block_ofs = block_ofs & 0xF;

        let mut ctr = *base_iv;
        let head_len = if block_ofs != 0 {
            let mut keystream = ctr;
            self.key1.encrypt_block(&mut keystream);
            ctr = add_ctr_blocks(&ctr, 1);
            let n = (16 - block_ofs).min(buf.len());
            for i in 0..n {
                buf[i] ^= keystream[block_ofs + i];
            }
            n
        } else {
            0
        };

        let rem = &mut buf[head_len..];
        if rem.is_empty() {
            return;
        }

        const PAR_THRESHOLD: usize = 512 * 1024;
        const CHUNK_BYTES: usize = 256 * 1024;
        if rem.len() >= PAR_THRESHOLD {
            let key = &self.key1;
            rem.par_chunks_mut(CHUNK_BYTES)
                .enumerate()
                .for_each(|(idx, chunk)| {
                    let blocks_before = (idx as u64) * ((CHUNK_BYTES / 16) as u64);
                    let mut chunk_ctr = add_ctr_blocks(&ctr, blocks_before);
                    key.ctr_crypt_chunk(chunk, &mut chunk_ctr);
                });
        } else {
            self.key1.ctr_crypt_chunk(rem, &mut ctr);
        }
    }

    /// In-place encryption/decryption for CTR, ECB, CBC
    pub fn crypt_in_place(&mut self, buf: &mut [u8], is_encrypt: bool) {
        match self.mode {
            AesMode::Ctr => {
                // Multi-thread large CTR buffers (>= 512 KB) via rayon work-stealing pool
                const PAR_THRESHOLD: usize = 512 * 1024;
                const CHUNK_BYTES: usize = 256 * 1024;
                if buf.len() >= PAR_THRESHOLD {
                    let base_iv = self.iv;
                    let key = &self.key1;
                    buf.par_chunks_mut(CHUNK_BYTES)
                        .enumerate()
                        .for_each(|(idx, slice)| {
                            let blocks_before = (idx as u64) * ((CHUNK_BYTES / 16) as u64);
                            let mut chunk_ctr = add_ctr_blocks(&base_iv, blocks_before);
                            key.ctr_crypt_chunk(slice, &mut chunk_ctr);
                        });
                    let total_blocks = buf.len().div_ceil(16) as u64;
                    self.iv = add_ctr_blocks(&base_iv, total_blocks);
                } else {
                    self.key1.ctr_crypt_chunk(buf, &mut self.iv);
                }
            }
            AesMode::Ecb => {
                if is_encrypt {
                    for chunk in buf.chunks_exact_mut(16) {
                        let block: &mut [u8; 16] = chunk.try_into().unwrap();
                        self.key1.encrypt_block(block);
                    }
                } else {
                    for chunk in buf.chunks_exact_mut(16) {
                        let block: &mut [u8; 16] = chunk.try_into().unwrap();
                        self.key1.decrypt_block(block);
                    }
                }
            }
            AesMode::CbcEnc => {
                for chunk in buf.chunks_exact_mut(16) {
                    let block: &mut [u8; 16] = chunk.try_into().unwrap();
                    for i in 0..16 {
                        block[i] ^= self.iv[i];
                    }
                    self.key1.encrypt_block(block);
                    self.iv = *block;
                }
            }
            AesMode::CbcDec => {
                for chunk in buf.chunks_exact_mut(16) {
                    let block: &mut [u8; 16] = chunk.try_into().unwrap();
                    let next_iv = *block;
                    self.key1.decrypt_block(block);
                    for i in 0..16 {
                        block[i] ^= self.iv[i];
                    }
                    self.iv = next_iv;
                }
            }
            AesMode::Xts => {
                panic!("Use xts_encrypt / xts_decrypt for XTS mode");
            }
        }
    }

    pub fn encrypt(&mut self, src: &[u8], dst: &mut [u8]) {
        dst[..src.len()].copy_from_slice(src);
        self.crypt_in_place(&mut dst[..src.len()], true);
    }

    pub fn decrypt(&mut self, src: &[u8], dst: &mut [u8]) {
        dst[..src.len()].copy_from_slice(src);
        self.crypt_in_place(&mut dst[..src.len()], false);
    }

    pub fn decrypt_in_place(&mut self, buf: &mut [u8]) {
        self.crypt_in_place(buf, false);
    }

    pub fn encrypt_in_place(&mut self, buf: &mut [u8]) {
        self.crypt_in_place(buf, true);
    }

    fn xts_crypt_sector(&self, sector_buf: &mut [u8], sector_idx: usize, is_encrypt: bool) {
        let tweak_key = self.key2.as_ref().expect("XTS requires 32-byte key");
        let mut tweak = get_nintendo_tweak(sector_idx);
        tweak_key.encrypt_block(&mut tweak);

        for chunk in sector_buf.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = chunk.try_into().unwrap();
            for i in 0..16 {
                block[i] ^= tweak[i];
            }
            if is_encrypt {
                self.key1.encrypt_block(block);
            } else {
                self.key1.decrypt_block(block);
            }
            for i in 0..16 {
                block[i] ^= tweak[i];
            }
            gf128mul_x_ble(&mut tweak);
        }
    }

    pub fn xts_crypt_in_place(
        &self,
        buf: &mut [u8],
        sector: usize,
        sector_size: usize,
        is_encrypt: bool,
    ) {
        assert!(buf.len() % sector_size == 0);
        let num_sectors = buf.len() / sector_size;
        if num_sectors == 0 {
            return;
        }

        // Parallelize across CPU cores when buffer is large (>= 256 KB and multiple sectors)
        if buf.len() >= 256 * 1024 && num_sectors >= 8 {
            let sectors_per_chunk = ((256 * 1024) / sector_size).max(1);
            let bytes_per_chunk = sectors_per_chunk * sector_size;
            buf.par_chunks_mut(bytes_per_chunk)
                .enumerate()
                .for_each(|(c_idx, chunk)| {
                    let base_sector = sector + c_idx * sectors_per_chunk;
                    for (s_idx, sec_buf) in chunk.chunks_exact_mut(sector_size).enumerate() {
                        self.xts_crypt_sector(sec_buf, base_sector + s_idx, is_encrypt);
                    }
                });
        } else {
            for (s_idx, sec_buf) in buf.chunks_exact_mut(sector_size).enumerate() {
                self.xts_crypt_sector(sec_buf, sector + s_idx, is_encrypt);
            }
        }
    }

    pub fn xts_decrypt(
        &self,
        src: &[u8],
        dst: &mut [u8],
        sector: usize,
        sector_size: usize,
    ) {
        dst[..src.len()].copy_from_slice(src);
        self.xts_crypt_in_place(&mut dst[..src.len()], sector, sector_size, false);
    }

    pub fn xts_encrypt(
        &self,
        src: &[u8],
        dst: &mut [u8],
        sector: usize,
        sector_size: usize,
    ) {
        dst[..src.len()].copy_from_slice(src);
        self.xts_crypt_in_place(&mut dst[..src.len()], sector, sector_size, true);
    }
}

/// Multiply a 16-byte Big-Endian value by 2 in GF(2^128) for AES-CMAC subkey generation
#[inline]
fn cmac_leftshift_onebit(input: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut overflow = 0u8;
    for i in (0..16).rev() {
        out[i] = (input[i] << 1) | overflow;
        overflow = (input[i] >> 7) & 1;
    }
    if (input[0] & 0x80) != 0 {
        out[15] ^= 0x87;
    }
    out
}

/// Calculate 16-byte AES-128-CMAC matching `aes_calculate_cmac` in `aes.c`
pub fn aes_calculate_cmac(mac: &mut [u8; 16], src: &[u8], key: &[u8; 16]) {
    let aes = Aes128Key::new(key);
    let mut l = [0u8; 16];
    aes.encrypt_block(&mut l);

    let k1 = cmac_leftshift_onebit(&l);
    let k2 = cmac_leftshift_onebit(&k1);

    let len = src.len();
    let n = if len == 0 { 1 } else { (len + 15) / 16 };
    let complete = len != 0 && (len % 16 == 0);

    let mut x = [0u8; 16];
    for i in 0..(n - 1) {
        let block = &src[i * 16..(i + 1) * 16];
        for j in 0..16 {
            x[j] ^= block[j];
        }
        aes.encrypt_block(&mut x);
    }

    let mut m_last = [0u8; 16];
    let last_start = (n - 1) * 16;
    if complete {
        let block = &src[last_start..last_start + 16];
        for j in 0..16 {
            m_last[j] = block[j] ^ k1[j];
        }
    } else {
        let rem = len.saturating_sub(last_start);
        for j in 0..rem {
            m_last[j] = src[last_start + j];
        }
        m_last[rem] = 0x80;
        for j in 0..16 {
            m_last[j] ^= k2[j];
        }
    }

    for j in 0..16 {
        x[j] ^= m_last[j];
    }
    aes.encrypt_block(&mut x);
    *mac = x;
}

