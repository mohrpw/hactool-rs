# hactool-rs

A high-performance parallel Rust port of [SciresM/hactool](https://github.com/SciresM/hactool) for inspecting, decrypting, verifying, and extracting Nintendo Switch file formats (`NCA`, `NSP`/`PFS0`, `XCI`, `HFS0`, `RomFS`, `Save`, `KIP1`, `INI1`, `NSO0`, `NPDM`, `PK11`, `PK21`, `NAX0`).

> **Attribution:** `hactool-rs` is a Rust port of SciresM's original C implementation (`hactool`, upstream `1.4.0`), licensed under the same [ISC License](LICENSE). Only a single external crate (`rayon`) is used alongside the Rust standard library.

---

## Key Improvements over C `hactool`

- **Work-Stealing Parallel Extraction (`rayon`):** `pfs0`, `hfs0`, `xci`, `nca`, `romfs`, and `nca0_romfs` extract files concurrently via `rayon::par_iter()` using Longest-Processing-Time-first (LPT) scheduling to eliminate tail latency on large assets.
- **2-Pass NTFS/Filesystem Friendly Directory Creation:** Target directories are created sequentially upfront before parallel file extraction begins, preventing MFT/directory-lock contention when unpacking thousands of files.
- **Lock-Free Positioned Reads (`RandomAccessReader` / `SharedFile`):** Uses `FileExt::seek_read` on Windows and `FileExt::read_at` (`pread`) on Unix so worker threads read concurrently from shared container handles without global cursor locks.
- **Hardware-Accelerated Crypto & Parallel Hashing:**
  - Runtime-detected `x86_64` AES-NI with **8-block pipelining** (`128 B/iter`), stateless `ctr_decrypt_at` for unaligned offsets without double reads, and `rayon`-parallelized AES-CTR / AES-XTS on large buffers.
  - Runtime-detected `x86_64` SHA-NI + parallel multi-block SHA-256 verification (`par_verify_blocks_with_suffix`), with clean portable software fallbacks on non-`x86_64` targets (e.g. Apple Silicon `aarch64`).
- **Thread-Local Reusable Scratch Buffers:** Reuses a per-worker `4 MiB` buffer (`with_worker_scratch`) instead of allocating and zero-filling (`memset(0xCC)`) `4 MiB` per extracted file.
- **Buffered Progress Output & `-q, --quiet`:** Synchronized `64 KiB`-buffered progress writer (`BufferedLineWriter`) plus a `-q` / `--quiet` flag to avoid Windows console I/O stalls on thousands of files.
- **Zero-Dependency Windows NTFS Compression Guard:** When creating output files on Windows inside directories with inherited `FILE_ATTRIBUTE_COMPRESSED` (LZNT1), `create_uncompressed_file` disables compression via `FSCTL_SET_COMPRESSION` (`COMPRESSION_FORMAT_NONE`) before writing encrypted/high-entropy payloads — with **0 extra syscalls** on normal uncompressed folders. *(To inspect or clean existing compressed folders/source files under Windows, use `ntfs-unthrottle` or `compact /u`.)*

---

## Performance Benchmarks

Measured on Windows 11 (`WDC` NVMe SSD, uncompressed NTFS) using a `6.27 GB` (`6,274,834,880` bytes) NSP container in a 2-step unpack pipeline (`pfs0` → `nca` extracting `6` ExeFS + `3,836` RomFS files across `169` directories, `100%` SHA-256 verified identical output to C `hactool`):

| Implementation | Step 1 (`pfs0`) | Step 2 (`nca`) | Total |
|---|---:|---:|---:|
| C `hactool` (reference) | `9.52–11.83 s` | `28.70–35.41 s` | `38.32–45.60 s` |
| `hactool-rs` (default output) | `9.82–19.37 s` | `11.73–12.60 s` | `22.43–31.09 s` |
| `hactool-rs` (`-q` quiet) | `13.46 s` | `12.76 s` | `26.22 s` |

In-memory `64 MiB` release crypto microbenchmark (`cargo test --release -- --nocapture`):
- `AES-128-CTR`: `27.93 ms` (`2.24 GiB/s`)
- `AES-128-XTS`: `22.67 ms` (`2.76 GiB/s`)
- `SHA-256` (parallel): `6.33 ms` (`9.88 GiB/s`)

---

## Building & Testing

The package name is `hactool-rs` and builds a drop-in compatible `hactool` (`hactool.exe` on Windows) binary:

```bash
cargo build --release
cargo test --release -- --nocapture
```

The compiled executable will be at `target/release/hactool` (`target\release\hactool.exe` on Windows).

---

## Usage

```text
Usage: hactool [options...] <file>
Options:
-i, --info        Show file info.
                      This is the default action.
-x, --extract     Extract data from file.
                      This is also the default action.
  -r, --raw          Keep raw data, don't unpack.
  -y, --verify       Verify hashes and signatures.
  -q, --quiet        Suppress per-file extraction progress lines.
  -d, --dev          Decrypt with development keys instead of retail.
  -k, --keyset       Load keys from an external file.
  -t, --intype=type  Specify input file type [nca, xci, pfs0, romfs, hfs0, npdm, pk11, pk21, ini1, kip1, nax0, save, keygen]
  --titlekey=key     Set title key for Rights ID crypto titles.
  --contentkey=key   Set raw key for NCA body decryption.
  --disablekeywarns  Disables warning output when loading external keys.
```

All format-specific flags (`--romfsdir`, `--exefsdir`, `--pfs0dir`, `--outdir`, `--plaintext`, `--header`, `--sdseed`, `--sdpath`, `--sbk`, `--tseckey`, etc.) match upstream `hactool`.

### External Keys

Provide a keyset via `-k` / `--keyset`, or place it at `$HOME/.switch/prod.keys` (`%USERPROFILE%\.switch\prod.keys` on Windows, or `$HOME/.switch/dev.keys` with `-d`/`--dev`). See [KEYS.md](KEYS.md) for recognized key names.

---

## Licensing

This software is licensed under the **ISC License** — see [LICENSE](LICENSE).  
Original C implementation copyright (c) 2018, SciresM.
