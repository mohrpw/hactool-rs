#![allow(dead_code)]

//! 2048-bit RSA signature verification (RSA-PSS, RSA-PKCS#1 v1.5) and RSA-OAEP decryption
//! matching `rsa.c` in hactool.

use crate::sha::{sha256_hash_buffer, Sha256Ctx};

/// 2048-bit unsigned integer stored as 32 little-endian 64-bit limbs
#[derive(Clone, Copy, PartialEq, Eq)]
struct U2048([u64; 32]);

/// 4096-bit unsigned integer stored as 64 little-endian 64-bit limbs
#[derive(Clone, Copy)]
struct U4096([u64; 64]);

impl U2048 {
    const ZERO: Self = Self([0u64; 32]);

    fn from_be_bytes(bytes: &[u8; 256]) -> Self {
        let mut limbs = [0u64; 32];
        for i in 0..32 {
            let src_idx = 256 - (i + 1) * 8;
            limbs[i] = u64::from_be_bytes(bytes[src_idx..src_idx + 8].try_into().unwrap());
        }
        Self(limbs)
    }

    fn to_be_bytes(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        for i in 0..32 {
            let dst_idx = 256 - (i + 1) * 8;
            out[dst_idx..dst_idx + 8].copy_from_slice(&self.0[i].to_be_bytes());
        }
        out
    }

    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        for i in (0..32).rev() {
            if self.0[i] != other.0[i] {
                return self.0[i].cmp(&other.0[i]);
            }
        }
        core::cmp::Ordering::Equal
    }

    /// Square into U4096 (`self * self`)
    fn mul(&self, rhs: &Self) -> U4096 {
        let mut res = [0u64; 64];
        for i in 0..32 {
            let mut carry = 0u128;
            let a = self.0[i] as u128;
            for j in 0..32 {
                let prod = a * (rhs.0[j] as u128) + (res[i + j] as u128) + carry;
                res[i + j] = prod as u64;
                carry = prod >> 64;
            }
            res[i + 32] = carry as u64;
        }
        U4096(res)
    }
}

impl U4096 {
    fn get_bit(&self, bit_idx: usize) -> u64 {
        let limb = bit_idx / 64;
        let bit = bit_idx % 64;
        (self.0[limb] >> bit) & 1
    }

    /// Modulo reduction by a 2048-bit modulus `m` using bitwise shift-and-subtract
    fn rem(&self, m: &U2048) -> U2048 {
        let mut r = [0u64; 33]; // 33 limbs to hold shifted value with possible 2049th bit

        for bit in (0..4096).rev() {
            // Left shift `r` by 1 bit and insert `self.get_bit(bit)`
            let mut carry = self.get_bit(bit);
            for i in 0..33 {
                let next_carry = r[i] >> 63;
                r[i] = (r[i] << 1) | carry;
                carry = next_carry;
            }

            // Check if r >= m
            let ge = if r[32] > 0 {
                true
            } else {
                let mut g = false;
                for i in (0..32).rev() {
                    if r[i] > m.0[i] {
                        g = true;
                        break;
                    } else if r[i] < m.0[i] {
                        g = false;
                        break;
                    }
                    if i == 0 {
                        g = true; // equal
                    }
                }
                g
            };

            if ge {
                let mut borrow = 0u128;
                for i in 0..32 {
                    let sub = (m.0[i] as u128) + borrow;
                    if (r[i] as u128) >= sub {
                        r[i] -= sub as u64;
                        borrow = 0;
                    } else {
                        r[i] = ((1u128 << 64) + (r[i] as u128) - sub) as u64;
                        borrow = 1;
                    }
                }
                r[32] = r[32].wrapping_sub(borrow as u64);
            }
        }

        let mut out = [0u64; 32];
        out.copy_from_slice(&r[0..32]);
        U2048(out)
    }
}

/// Compute `base^exp mod modulus` where `base` and `modulus` are 256-byte big-endian integers
fn rsa2048_public_op(sig: &[u8; 256], modulus: &[u8; 256], exp_bytes: &[u8]) -> Option<[u8; 256]> {
    if (modulus[255] & 1) == 0 {
        return None;
    }
    let m = U2048::from_be_bytes(modulus);
    let s = U2048::from_be_bytes(sig);
    if s.cmp(&m) != core::cmp::Ordering::Less {
        return None;
    }

    let mut result = U2048::ZERO;
    result.0[0] = 1;
    let mut started = false;

    for &byte in exp_bytes {
        for bit in (0..8).rev() {
            let b = (byte >> bit) & 1;
            if !started {
                if b == 0 {
                    continue;
                }
                started = true;
                result = s;
                continue;
            }
            result = result.mul(&result).rem(&m);
            if b == 1 {
                result = result.mul(&s).rem(&m);
            }
        }
    }

    Some(result.to_be_bytes())
}

/// MGF1 mask generation with SHA-256 (`mgf_mask` in `rsa.c`)
fn mgf1_sha256(dst: &mut [u8], src: &[u8]) {
    let mut counter = 0u32;
    for chunk in dst.chunks_mut(32) {
        let mut ctx = Sha256Ctx::new();
        ctx.update(src);
        ctx.update(&counter.to_be_bytes());
        let mask = ctx.finalize();
        for (d, m) in chunk.iter_mut().zip(mask.iter()) {
            *d ^= *m;
        }
        counter += 1;
    }
}

/// Verify RSA-2048 PSS with SHA-256 (`rsa2048_pss_verify` in `rsa.c`)
pub fn rsa2048_pss_verify(data: &[u8], signature: &[u8; 256], modulus: &[u8; 256]) -> bool {
    let exp = [0x01u8, 0x00, 0x01]; // 65537
    let mut em = match rsa2048_public_op(signature, modulus, &exp) {
        Some(buf) => buf,
        None => return false,
    };

    // In mbedtls_rsa_rsassa_pss_verify_ext for 2048-bit RSA:
    if em[255] != 0xBC {
        return false;
    }
    if (em[0] & 0x80) != 0 {
        return false;
    }

    let mut mhash = [0u8; 32];
    sha256_hash_buffer(&mut mhash, data);

    // maskedDB is em[0..223], H is em[223..255]
    let (masked_db, h) = em[..255].split_at_mut(223);
    mgf1_sha256(masked_db, h);
    masked_db[0] &= 0x7F;

    // Skip 0x00 padding in DB until 0x01
    let mut idx = 0;
    while idx < masked_db.len() && masked_db[idx] == 0 {
        idx += 1;
    }
    if idx >= masked_db.len() || masked_db[idx] != 0x01 {
        return false;
    }
    idx += 1;
    let salt = &masked_db[idx..];

    let mut ctx = Sha256Ctx::new();
    ctx.update(&[0u8; 8]);
    ctx.update(&mhash);
    ctx.update(salt);
    let h_prime = ctx.finalize();

    h_prime == h
}

/// Verify RSA-2048 PKCS#1 v1.5 with SHA-256 (`rsa2048_pkcs1_verify` in `rsa.c`)
pub fn rsa2048_pkcs1_verify(data: &[u8], signature: &[u8; 256], modulus: &[u8; 256]) -> bool {
    let exp = [0x01u8, 0x00, 0x01]; // 65537
    let em = match rsa2048_public_op(signature, modulus, &exp) {
        Some(buf) => buf,
        None => return false,
    };

    let mut mhash = [0u8; 32];
    sha256_hash_buffer(&mut mhash, data);

    // PKCS#1 v1.5 DigestInfo prefix for SHA-256 (19 bytes)
    const ASN1_SHA256: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    // Expected structure: 0x00 || 0x01 || 0xFF (202 bytes) || 0x00 || ASN1_SHA256 (19 bytes) || mhash (32 bytes)
    if em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }
    for i in 2..204 {
        if em[i] != 0xFF {
            return false;
        }
    }
    if em[204] != 0x00 {
        return false;
    }
    if em[205..224] != ASN1_SHA256 {
        return false;
    }
    em[224..256] == mhash
}

/// RSA-OAEP unwrap (`rsa2048_oaep_decrypt_verify` in `rsa.c`, used for beta NCA0 header keys)
pub fn rsa2048_oaep_decrypt_verify(
    out: &mut [u8],
    signature: &[u8; 256],
    modulus: &[u8; 256],
    exponent: &[u8],
    label_hash: &[u8; 32],
) -> usize {
    let mut buf = match rsa2048_public_op(signature, modulus, exponent) {
        Some(b) => b,
        None => return 0,
    };

    if buf[0] != 0 {
        return 0;
    }

    // buf[1..33] is maskedSeed, buf[33..256] is maskedDB
    let (head, masked_db) = buf.split_at_mut(33);
    let seed = &mut head[1..33];
    mgf1_sha256(seed, masked_db);
    mgf1_sha256(masked_db, seed);

    // Verify lHash' == label_hash
    if &masked_db[0..32] != label_hash {
        return 0;
    }

    let mut pos = 32;
    while pos < masked_db.len() && masked_db[pos] == 0 {
        pos += 1;
    }
    if pos >= masked_db.len() || masked_db[pos] != 0x01 {
        return 0;
    }
    pos += 1;

    let msg = &masked_db[pos..];
    let copy_len = msg.len().min(out.len());
    out[..copy_len].copy_from_slice(&msg[..copy_len]);
    copy_len
}

