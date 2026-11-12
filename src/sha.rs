#![allow(dead_code)]

//! High-performance SHA-256 implementation with x86_64 SHA-NI hardware acceleration,
//! HMAC-SHA256, and parallel block-hash table verification across CPU cores.

use rayon::prelude::*;

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub type Sha256 = Sha256Ctx;

#[derive(Clone)]
pub struct Sha256Ctx {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
    use_shani: bool,
}

impl Sha256Ctx {
    pub fn new() -> Self {
        #[cfg(target_arch = "x86_64")]
        let use_shani = std::is_x86_feature_detected!("sha")
            && std::is_x86_feature_detected!("sse4.1")
            && std::is_x86_feature_detected!("ssse3");
        #[cfg(not(target_arch = "x86_64"))]
        let use_shani = false;

        Self {
            state: H0,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
            use_shani,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;

        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..64].copy_from_slice(&data[..need]);
            let block = self.buf;
            self.compress_blocks(&block);
            self.buf_len = 0;
            data = &data[need..];
        }

        let full_len = data.len() & !63;
        if full_len > 0 {
            self.compress_blocks(&data[..full_len]);
            data = &data[full_len..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            let block = self.buf;
            self.compress_blocks(&block);
            self.buf_len = 0;
        }

        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.compress_blocks(&block);

        let mut out = [0u8; 32];
        for (i, &w) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    #[inline]
    fn compress_blocks(&mut self, blocks: &[u8]) {
        #[cfg(target_arch = "x86_64")]
        if self.use_shani {
            unsafe {
                compress_blocks_shani(&mut self.state, blocks);
            }
            return;
        }
        compress_blocks_soft(&mut self.state, blocks);
    }
}

fn compress_blocks_soft(state: &mut [u32; 8], blocks: &[u8]) {
    for chunk in blocks.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse4.1,ssse3")]
unsafe fn compress_blocks_shani(state: &mut [u32; 8], blocks: &[u8]) {
    use core::arch::x86_64::*;
    unsafe {
        let mask = _mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203);

        // Load initial state:
        // state[0..4] = [a, b, c, d], state[4..8] = [e, f, g, h]
        // Target layout:
        // state0 (lanes 0..3) = [f, e, b, a]
        // state1 (lanes 0..3) = [h, g, d, c]
        let tmp = _mm_loadu_si128(state.as_ptr() as *const __m128i);
        let mut state1 = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i);
        let tmp = _mm_shuffle_epi32(tmp, 0xB1); // [b, a, d, c]
        state1 = _mm_shuffle_epi32(state1, 0x1B); // [h, g, f, e]
        let mut state0 = _mm_alignr_epi8(tmp, state1, 8); // [f, e, b, a]
        state1 = _mm_blend_epi16(state1, tmp, 0xF0); // [h, g, d, c]

        for chunk in blocks.chunks_exact(64) {
            let abef_save = state0;
            let cdgh_save = state1;

            let ptr = chunk.as_ptr() as *const __m128i;
            let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(0)), mask);
            let mut msg1 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(1)), mask);
            let mut msg2 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(2)), mask);
            let mut msg3 = _mm_shuffle_epi8(_mm_loadu_si128(ptr.add(3)), mask);

            macro_rules! k_vec {
                ($idx:expr) => {
                    _mm_loadu_si128(K256.as_ptr().add($idx) as *const __m128i)
                };
            }

            // Rounds 0..3
            let mut msg = _mm_add_epi32(msg0, k_vec!(0));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 4..7
            msg = _mm_add_epi32(msg1, k_vec!(4));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg0 = _mm_sha256msg1_epu32(msg0, msg1);

            // Rounds 8..11
            msg = _mm_add_epi32(msg2, k_vec!(8));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            // Rounds 12..15
            msg = _mm_add_epi32(msg3, k_vec!(12));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg3, msg2, 4);
            msg0 = _mm_add_epi32(msg0, tmp_m);
            msg0 = _mm_sha256msg2_epu32(msg0, msg3);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            // Rounds 16..19
            msg = _mm_add_epi32(msg0, k_vec!(16));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg0, msg3, 4);
            msg1 = _mm_add_epi32(msg1, tmp_m);
            msg1 = _mm_sha256msg2_epu32(msg1, msg0);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msg0);

            // Rounds 20..23
            msg = _mm_add_epi32(msg1, k_vec!(20));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg1, msg0, 4);
            msg2 = _mm_add_epi32(msg2, tmp_m);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg0 = _mm_sha256msg1_epu32(msg0, msg1);

            // Rounds 24..27
            msg = _mm_add_epi32(msg2, k_vec!(24));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg2, msg1, 4);
            msg3 = _mm_add_epi32(msg3, tmp_m);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            // Rounds 28..31
            msg = _mm_add_epi32(msg3, k_vec!(28));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg3, msg2, 4);
            msg0 = _mm_add_epi32(msg0, tmp_m);
            msg0 = _mm_sha256msg2_epu32(msg0, msg3);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            // Rounds 32..35
            msg = _mm_add_epi32(msg0, k_vec!(32));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg0, msg3, 4);
            msg1 = _mm_add_epi32(msg1, tmp_m);
            msg1 = _mm_sha256msg2_epu32(msg1, msg0);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msg0);

            // Rounds 36..39
            msg = _mm_add_epi32(msg1, k_vec!(36));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg1, msg0, 4);
            msg2 = _mm_add_epi32(msg2, tmp_m);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg0 = _mm_sha256msg1_epu32(msg0, msg1);

            // Rounds 40..43
            msg = _mm_add_epi32(msg2, k_vec!(40));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg2, msg1, 4);
            msg3 = _mm_add_epi32(msg3, tmp_m);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg1 = _mm_sha256msg1_epu32(msg1, msg2);

            // Rounds 44..47
            msg = _mm_add_epi32(msg3, k_vec!(44));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg3, msg2, 4);
            msg0 = _mm_add_epi32(msg0, tmp_m);
            msg0 = _mm_sha256msg2_epu32(msg0, msg3);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg2 = _mm_sha256msg1_epu32(msg2, msg3);

            // Rounds 48..51
            msg = _mm_add_epi32(msg0, k_vec!(48));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg0, msg3, 4);
            msg1 = _mm_add_epi32(msg1, tmp_m);
            msg1 = _mm_sha256msg2_epu32(msg1, msg0);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
            msg3 = _mm_sha256msg1_epu32(msg3, msg0);

            // Rounds 52..55
            msg = _mm_add_epi32(msg1, k_vec!(52));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg1, msg0, 4);
            msg2 = _mm_add_epi32(msg2, tmp_m);
            msg2 = _mm_sha256msg2_epu32(msg2, msg1);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 56..59
            msg = _mm_add_epi32(msg2, k_vec!(56));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            let tmp_m = _mm_alignr_epi8(msg2, msg1, 4);
            msg3 = _mm_add_epi32(msg3, tmp_m);
            msg3 = _mm_sha256msg2_epu32(msg3, msg2);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            // Rounds 60..63
            msg = _mm_add_epi32(msg3, k_vec!(60));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

            state0 = _mm_add_epi32(state0, abef_save);
            state1 = _mm_add_epi32(state1, cdgh_save);
        }

        let tmp = _mm_shuffle_epi32(state0, 0x1B); // [a, b, e, f]
        state1 = _mm_shuffle_epi32(state1, 0xB1); // [g, h, c, d]
        let out0 = _mm_blend_epi16(tmp, state1, 0xF0); // [a, b, c, d]
        let out1 = _mm_alignr_epi8(state1, tmp, 8); // [e, f, g, h]

        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, out0);
        _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, out1);
    }
}

/// Hash buffer with SHA-256 into `digest`
pub fn sha256_hash_buffer(digest: &mut [u8; 32], data: &[u8]) {
    let mut ctx = Sha256Ctx::new();
    ctx.update(data);
    *digest = ctx.finalize();
}

/// Compute HMAC-SHA256 matching `sha256_get_buffer_hmac` in `sha.c`
pub fn sha256_get_buffer_hmac(mac: &mut [u8; 32], data: &[u8], key: &[u8]) {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let mut kh = [0u8; 32];
        sha256_hash_buffer(&mut kh, key);
        k_block[..32].copy_from_slice(&kh);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }

    let mut inner = Sha256Ctx::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256Ctx::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    *mac = outer.finalize();
}

/// Multi-threaded block hash verification across CPU cores
pub fn par_verify_blocks(data: &[u8], hash_table: &[u8], block_size: usize) -> bool {
    par_verify_blocks_with_suffix(data, hash_table, block_size, None)
}

/// Multi-threaded block hash verification with an optional suffix per block (e.g. XCI HFS0 compatibility)
pub fn par_verify_blocks_with_suffix(
    data: &[u8],
    hash_table: &[u8],
    block_size: usize,
    suffix: Option<&[u8]>,
) -> bool {
    if block_size == 0 || data.is_empty() {
        return true;
    }

    let num_blocks = (data.len() + block_size - 1) / block_size;
    if hash_table.len() < num_blocks * 0x20 {
        return false;
    }

    // For small payloads (< 512 KB or <= 4 blocks), verify directly on current thread
    if data.len() < 512 * 1024 || num_blocks <= 4 {
        for i in 0..num_blocks {
            let start = i * block_size;
            let end = (start + block_size).min(data.len());
            let expected = &hash_table[i * 0x20..(i + 1) * 0x20];
            let mut ctx = Sha256Ctx::new();
            ctx.update(&data[start..end]);
            if let Some(sfx) = suffix {
                ctx.update(sfx);
            }
            let actual = ctx.finalize();
            if actual != expected {
                return false;
            }
        }
        return true;
    }

    let res: Result<(), ()> = (0..num_blocks).into_par_iter().try_for_each(|i| {
        let start = i * block_size;
        let end = (start + block_size).min(data.len());
        let expected = &hash_table[i * 0x20..(i + 1) * 0x20];
        let mut ctx = Sha256Ctx::new();
        ctx.update(&data[start..end]);
        if let Some(sfx) = suffix {
            ctx.update(sfx);
        }
        let actual = ctx.finalize();
        if actual != expected {
            Err(())
        } else {
            Ok(())
        }
    });

    res.is_ok()
}

