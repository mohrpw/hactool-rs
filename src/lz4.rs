#![allow(dead_code)]

//! Safe, fast LZ4 block decompression matching `LZ4_decompress_safe` in `lz4.c`.

/// Decompresses an LZ4 raw block into `dst`.
/// Returns `Ok(decompressed_bytes)` or `Err(())` if malformed/corrupted.
pub fn lz4_decompress_safe(src: &[u8], dst: &mut [u8]) -> Result<usize, ()> {
    let mut ip = 0usize;
    let mut op = 0usize;
    let src_len = src.len();
    let dst_len = dst.len();

    while ip < src_len {
        let token = src[ip] as usize;
        ip += 1;

        // Literal length
        let mut lit_len = token >> 4;
        if lit_len == 15 {
            loop {
                if ip >= src_len {
                    return Err(());
                }
                let s = src[ip] as usize;
                ip += 1;
                lit_len = lit_len.checked_add(s).ok_or(())?;
                if s != 255 {
                    break;
                }
            }
        }

        // Copy literals
        if ip.checked_add(lit_len).ok_or(())? > src_len
            || op.checked_add(lit_len).ok_or(())? > dst_len
        {
            return Err(());
        }
        dst[op..op + lit_len].copy_from_slice(&src[ip..ip + lit_len]);
        ip += lit_len;
        op += lit_len;

        // Check for end of block (last sequence has only literals)
        if ip == src_len {
            break;
        }

        // Match offset (16-bit little-endian)
        if ip + 2 > src_len {
            return Err(());
        }
        let offset = (src[ip] as usize) | ((src[ip + 1] as usize) << 8);
        ip += 2;
        if offset == 0 || offset > op {
            return Err(());
        }

        // Match length
        let mut match_len = (token & 0x0F) + 4;
        if match_len == 19 {
            loop {
                if ip >= src_len {
                    return Err(());
                }
                let s = src[ip] as usize;
                ip += 1;
                match_len = match_len.checked_add(s).ok_or(())?;
                if s != 255 {
                    break;
                }
            }
        }

        if op.checked_add(match_len).ok_or(())? > dst_len {
            return Err(());
        }

        let match_pos = op - offset;
        if offset >= match_len {
            // Non-overlapping match: fast slice copy
            dst.copy_within(match_pos..match_pos + match_len, op);
            op += match_len;
        } else if offset == 1 {
            // RLE repeat single byte
            let b = dst[match_pos];
            dst[op..op + match_len].fill(b);
            op += match_len;
        } else {
            // Overlapping match copy
            for i in 0..match_len {
                dst[op + i] = dst[match_pos + i];
            }
            op += match_len;
        }
    }

    Ok(op)
}

