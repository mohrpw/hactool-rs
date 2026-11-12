#![allow(dead_code)]

//! NPDM (META / ACID / ACI0) parsing, printing, and cJSON-compatible JSON serialization
//! matching `npdm.c` in hactool.

use crate::rsa::rsa2048_pss_verify;
use crate::settings::HactoolCtx;
use crate::types::{read_u32_le, read_u64_le, Validity, ACTION_EXTRACT, ACTION_INFO, ACTION_VERIFY};
use crate::utils::{create_uncompressed_file, memdump_stdout, print_magic};
use std::io::Write;
use std::process;

pub const MAGIC_META: u32 = 0x4154454D;
pub const MAGIC_ACID: u32 = 0x44494341;
pub const MAGIC_ACI0: u32 = 0x30494341;
pub const NPDM_HEADER_SIZE: usize = 0x80;

#[derive(Clone, Copy, Debug, Default)]
pub struct NpdmHeader {
    pub magic: u32,
    pub aci0_offset: u32,
    pub aci0_size: u32,
    pub acid_offset: u32,
    pub acid_size: u32,
}

impl NpdmHeader {
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < NPDM_HEADER_SIZE {
            return Self::default();
        }
        Self {
            magic: read_u32_le(data, 0x00),
            aci0_offset: read_u32_le(data, 0x70),
            aci0_size: read_u32_le(data, 0x74),
            acid_offset: read_u32_le(data, 0x78),
            acid_size: read_u32_le(data, 0x7C),
        }
    }
}

// Notice in npdm.c line 137: `"svcCallSecureMonitor" "svcUnknown",` has a missing comma in C,
// causing string concatenation `"svcCallSecureMonitorsvcUnknown"` at index 0x7F!
// We replicate the exact 0xC0 array as compiled in C.
pub const SVC_NAMES: [&str; 0xC0] = [
    "svcUnknown",
    "svcSetHeapSize",
    "svcSetMemoryPermission",
    "svcSetMemoryAttribute",
    "svcMapMemory",
    "svcUnmapMemory",
    "svcQueryMemory",
    "svcExitProcess",
    "svcCreateThread",
    "svcStartThread",
    "svcExitThread",
    "svcSleepThread",
    "svcGetThreadPriority",
    "svcSetThreadPriority",
    "svcGetThreadCoreMask",
    "svcSetThreadCoreMask",
    "svcGetCurrentProcessorNumber",
    "svcSignalEvent",
    "svcClearEvent",
    "svcMapSharedMemory",
    "svcUnmapSharedMemory",
    "svcCreateTransferMemory",
    "svcCloseHandle",
    "svcResetSignal",
    "svcWaitSynchronization",
    "svcCancelSynchronization",
    "svcArbitrateLock",
    "svcArbitrateUnlock",
    "svcWaitProcessWideKeyAtomic",
    "svcSignalProcessWideKey",
    "svcGetSystemTick",
    "svcConnectToNamedPort",
    "svcSendSyncRequestLight",
    "svcSendSyncRequest",
    "svcSendSyncRequestWithUserBuffer",
    "svcSendAsyncRequestWithUserBuffer",
    "svcGetProcessId",
    "svcGetThreadId",
    "svcBreak",
    "svcOutputDebugString",
    "svcReturnFromException",
    "svcGetInfo",
    "svcFlushEntireDataCache",
    "svcFlushDataCache",
    "svcMapPhysicalMemory",
    "svcUnmapPhysicalMemory",
    "svcGetDebugFutureThreadInfo",
    "svcGetLastThreadInfo",
    "svcGetResourceLimitLimitValue",
    "svcGetResourceLimitCurrentValue",
    "svcSetThreadActivity",
    "svcGetThreadContext3",
    "svcWaitForAddress",
    "svcSignalToAddress",
    "svcSynchronizePreemptionState",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcKernelDebug",
    "svcChangeKernelTraceState",
    "svcUnknown",
    "svcUnknown",
    "svcCreateSession",
    "svcAcceptSession",
    "svcReplyAndReceiveLight",
    "svcReplyAndReceive",
    "svcReplyAndReceiveWithUserBuffer",
    "svcCreateEvent",
    "svcUnknown",
    "svcUnknown",
    "svcMapPhysicalMemoryUnsafe",
    "svcUnmapPhysicalMemoryUnsafe",
    "svcSetUnsafeLimit",
    "svcCreateCodeMemory",
    "svcControlCodeMemory",
    "svcSleepSystem",
    "svcReadWriteRegister",
    "svcSetProcessActivity",
    "svcCreateSharedMemory",
    "svcMapTransferMemory",
    "svcUnmapTransferMemory",
    "svcCreateInterruptEvent",
    "svcQueryPhysicalAddress",
    "svcQueryIoMapping",
    "svcCreateDeviceAddressSpace",
    "svcAttachDeviceAddressSpace",
    "svcDetachDeviceAddressSpace",
    "svcMapDeviceAddressSpaceByForce",
    "svcMapDeviceAddressSpaceAligned",
    "svcMapDeviceAddressSpace",
    "svcUnmapDeviceAddressSpace",
    "svcInvalidateProcessDataCache",
    "svcStoreProcessDataCache",
    "svcFlushProcessDataCache",
    "svcDebugActiveProcess",
    "svcBreakDebugProcess",
    "svcTerminateDebugProcess",
    "svcGetDebugEvent",
    "svcContinueDebugEvent",
    "svcGetProcessList",
    "svcGetThreadList",
    "svcGetDebugThreadContext",
    "svcSetDebugThreadContext",
    "svcQueryDebugProcessMemory",
    "svcReadDebugProcessMemory",
    "svcWriteDebugProcessMemory",
    "svcSetHardwareBreakPoint",
    "svcGetDebugThreadParam",
    "svcUnknown",
    "svcGetSystemInfo",
    "svcCreatePort",
    "svcManageNamedPort",
    "svcConnectToPort",
    "svcSetProcessMemoryPermission",
    "svcMapProcessMemory",
    "svcUnmapProcessMemory",
    "svcQueryProcessMemory",
    "svcMapProcessCodeMemory",
    "svcUnmapProcessCodeMemory",
    "svcCreateProcess",
    "svcStartProcess",
    "svcTerminateProcess",
    "svcGetProcessInfo",
    "svcCreateResourceLimit",
    "svcSetResourceLimitLimitValue",
    "svcCallSecureMonitorsvcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "svcUnknown",
    "",
];

const FS_PERM_MASK_NODEBUG: u64 = 0xBFFFFFFFFFFFFFFF;

const FS_PERMISSIONS_RW: [(&str, u64); 0x27] = [
    ("MountContentType2", 0x8000000000000801),
    ("MountContentType5", 0x8000000000000801),
    ("MountContentType3", 0x8000000000000801),
    ("MountContentType4", 0x8000000000000801),
    ("MountContentType6", 0x8000000000000801),
    ("MountContentType7", 0x8000000000000801),
    ("Unknown (0x6)", 0x8000000000000000),
    ("ContentStorageAccess", 0x8000000000000800),
    ("ImageDirectoryAccess", 0x8000000000001000),
    ("MountBisType28", 0x8000000000000084),
    ("MountBisType29", 0x8000000000000080),
    ("MountBisType30", 0x8000000000008080),
    ("MountBisType31", 0x8000000000008080),
    ("Unknown (0xD)", 0x8000000000000080),
    ("SdCardAccess", 0xC000000000200000),
    ("GameCardUser", 0x8000000000000010),
    ("SaveDataAccess0", 0x8000000000040020),
    ("SystemSaveDataAccess0", 0x8000000000000028),
    ("SaveDataAccess1", 0x8000000000000020),
    ("SystemSaveDataAccess1", 0x8000000000000020),
    ("BisPartition0", 0x8000000000010082),
    ("BisPartition10", 0x8000000000010080),
    ("BisPartition20", 0x8000000000010080),
    ("BisPartition21", 0x8000000000010080),
    ("BisPartition22", 0x8000000000010080),
    ("BisPartition23", 0x8000000000010080),
    ("BisPartition24", 0x8000000000010080),
    ("BisPartition25", 0x8000000000010080),
    ("BisPartition26", 0x8000000000000080),
    ("BisPartition27", 0x8000000000000084),
    ("BisPartition28", 0x8000000000000084),
    ("BisPartition29", 0x8000000000000080),
    ("BisPartition30", 0x8000000000000080),
    ("BisPartition31", 0x8000000000000080),
    ("BisPartition32", 0x8000000000000080),
    ("Unknown (0x23)", 0xC000000000200000),
    ("GameCard_System", 0x8000000000000100),
    ("MountContent_System", 0x8000000000100008),
    ("HostAccess", 0xC000000000400000),
];

const FS_PERMISSIONS_BOOL: [(&str, u64); 0x1B] = [
    ("BisCache", 0x8000000000000080),
    ("EraseMmc", 0x8000000000000080),
    ("GameCardCertificate", 0x8000000000000010),
    ("GameCardIdSet", 0x8000000000000010),
    ("GameCardDriver", 0x8000000000000200),
    ("GameCardAsic", 0x8000000000000200),
    ("SaveDataCreate", 0x8000000000002020),
    ("SaveDataDelete0", 0x8000000000000060),
    ("SystemSaveDataCreate0", 0x8000000000000028),
    ("SystemSaveDataCreate1", 0x8000000000000020),
    ("SaveDataDelete1", 0x8000000000004028),
    ("SaveDataIterators0", 0x8000000000000060),
    ("SaveDataIterators1", 0x8000000000004020),
    ("SaveThumbnails", 0x8000000000020000),
    ("PosixTime", 0x8000000000000400),
    ("SaveDataExtraData", 0x8000000000004060),
    ("GlobalMode", 0x8000000000080000),
    ("SpeedEmulation", 0x8000000000080000),
    ("(NULL)", 0),
    ("PaddingFiles", 0xC000000000800000),
    ("SaveData_Debug", 0xC000000001000000),
    ("SaveData_SystemManagement", 0xC000000002000000),
    ("Unknown (0x16)", 0x8000000004000000),
    ("Unknown (0x17)", 0x8000000008000000),
    ("Unknown (0x18)", 0x8000000010000000),
    ("Unknown (0x19)", 0x8000000000000800),
    ("Unknown (0x1A)", 0x8000000000004020),
];

pub fn npdm_get_proc_category(process_category: i32) -> &'static str {
    match process_category {
        0 => "Regular Title",
        1 => "Kernel Built-In",
        _ => "Unknown",
    }
}

fn kac_get_app_type(app_type: u32) -> &'static str {
    match app_type {
        0 => "System Module",
        1 => "Application",
        2 => "Applet",
        _ => "Unknown",
    }
}

#[derive(Clone, Debug)]
struct KacMmio {
    address: u64,
    size: u64,
    is_ro: bool,
    is_norm: bool,
}

pub fn kac_print(descriptors: &[u32]) {
    let mut has_kern_flags = false;
    let mut lowest_thread_prio = 0u32;
    let mut highest_thread_prio = 0u32;
    let mut lowest_cpu_id = 0u32;
    let mut highest_cpu_id = 0u32;
    let mut svcs_allowed = [false; 0xC0];
    let mut mmios: Vec<KacMmio> = Vec::new();
    let mut irqs: Vec<(u32, u32)> = Vec::new();
    let mut has_app_type = false;
    let mut application_type = 0u32;
    let mut has_kern_ver = false;
    let mut kernel_release_version = 0u32;
    let mut has_handle_table_size = false;
    let mut handle_table_size = 0u32;
    let mut has_debug_flags = false;
    let mut allow_debug = false;
    let mut force_debug = false;

    let mut i = 0;
    while i < descriptors.len() {
        let mut desc = descriptors[i];
        i += 1;
        if desc == 0xFFFFFFFF {
            continue;
        }
        let mut low_bits = 0u32;
        while (desc & 1) != 0 {
            desc >>= 1;
            low_bits += 1;
        }
        desc >>= 1;

        match low_bits {
            3 => {
                has_kern_flags = true;
                highest_thread_prio = desc & 0x3F;
                desc >>= 6;
                lowest_thread_prio = desc & 0x3F;
                desc >>= 6;
                lowest_cpu_id = desc & 0xFF;
                desc >>= 8;
                highest_cpu_id = desc & 0xFF;
            }
            4 => {
                let syscall_base = ((desc >> 24) as usize) * 0x18;
                for sc in 0..0x18 {
                    if syscall_base + sc < 0xC0 {
                        svcs_allowed[syscall_base + sc] = (desc & 1) != 0;
                        desc >>= 1;
                    }
                }
            }
            6 => {
                let address = ((desc & 0xFFFFFF) as u64) << 12;
                let is_ro = (desc >> 24) != 0;
                if i >= descriptors.len() {
                    eprintln!("Error: Invalid Kernel Access Control Descriptors!");
                    process::exit(1);
                }
                desc = descriptors[i];
                i += 1;
                if (desc & 0x7F) != 0x3F {
                    eprintln!("Error: Invalid Kernel Access Control Descriptors!");
                    process::exit(1);
                }
                desc >>= 7;
                let size = ((desc & 0xFFFFFF) as u64) << 12;
                let is_norm = (desc >> 24) != 0;
                // Ordered insertion matching kac_add_mmio
                let pos = mmios
                    .iter()
                    .position(|m| m.address > address)
                    .unwrap_or(mmios.len());
                mmios.insert(
                    pos,
                    KacMmio {
                        address,
                        size,
                        is_ro,
                        is_norm,
                    },
                );
            }
            7 => {
                let address = (desc << 12) as u64;
                let pos = mmios
                    .iter()
                    .position(|m| m.address > address)
                    .unwrap_or(mmios.len());
                mmios.insert(
                    pos,
                    KacMmio {
                        address,
                        size: 0x1000,
                        is_ro: false,
                        is_norm: false,
                    },
                );
            }
            11 => {
                let irq0 = desc & 0x3FF;
                let irq1 = (desc >> 10) & 0x3FF;
                irqs.push((irq0, irq1));
            }
            13 => {
                has_app_type = true;
                application_type = desc & 7;
            }
            14 => {
                has_kern_ver = true;
                kernel_release_version = desc;
            }
            15 => {
                has_handle_table_size = true;
                handle_table_size = desc;
            }
            16 => {
                has_debug_flags = true;
                allow_debug = (desc & 1) != 0;
                force_debug = ((desc >> 1) & 1) != 0;
            }
            _ => {}
        }
    }

    if has_kern_flags {
        println!(
            "        Lowest Allowed Priority:    {}",
            lowest_thread_prio as i32
        );
        println!(
            "        Highest Allowed Priority:   {}",
            highest_thread_prio as i32
        );
        println!(
            "        Lowest Allowed CPU ID:      {}",
            lowest_cpu_id as i32
        );
        println!(
            "        Highest Allowed CPU ID:     {}",
            highest_cpu_id as i32
        );
    }

    let mut first_svc = true;
    for i in 0..0xC0 {
        if svcs_allowed[i] {
            if first_svc {
                println!(
                    "        Allowed SVCs:               {:<35} (0x{:02x})",
                    SVC_NAMES[i], i
                );
                first_svc = false;
            } else {
                println!(
                    "                                    {:<35} (0x{:02x})",
                    SVC_NAMES[i], i
                );
            }
        }
    }

    let mut first_mmio = true;
    for m in &mmios {
        if first_mmio {
            print!("        Mapped IO:                  ");
            first_mmio = false;
        } else {
            print!("                                    ");
        }
        println!(
            "({:09x}-{:09x}, {}, {})",
            m.address,
            m.address + m.size,
            if m.is_ro { "RO" } else { "RW" },
            if m.is_norm { "Normal" } else { "IO" }
        );
    }

    if !irqs.is_empty() {
        print!("        Mapped Interrupts:          ");
        let mut num_irqs = 0;
        for &(irq0, irq1) in &irqs {
            for &irq in &[irq0, irq1] {
                if irq != 0x3FF {
                    if num_irqs % 8 == 0 {
                        if num_irqs != 0 {
                            print!("\n                                    ");
                        }
                    } else {
                        print!(", ");
                    }
                    print!("0x{:03x}", irq);
                    num_irqs += 1;
                }
            }
        }
        println!();
    }

    if has_app_type {
        println!(
            "        Application Type:           {}",
            kac_get_app_type(application_type)
        );
    }
    if has_handle_table_size {
        println!(
            "        Handle Table Size:          {}",
            handle_table_size as i32
        );
    }
    if has_kern_ver {
        println!("        Minimum Kernel Version:     {}", kernel_release_version);
    }
    if has_debug_flags {
        println!(
            "        Allow Debug:                {}",
            if allow_debug { "YES" } else { "NO" }
        );
        println!(
            "        Force Debug:                {}",
            if force_debug { "YES" } else { "NO" }
        );
    }
}

fn wildcard_match(pattern: &[u8], candidate: &[u8]) -> bool {
    if pattern.is_empty() {
        return candidate.is_empty();
    } else if pattern[0] == b'*' {
        for c in 0..candidate.len() {
            if wildcard_match(&pattern[1..], &candidate[c..]) {
                return true;
            }
        }
        wildcard_match(&pattern[1..], &[])
    } else if !candidate.is_empty() {
        // Notice in npdm.c line 527: C's `match` does not compare pattern[p] == candidate[c]
        // for non-'*' characters, it just advances both p+1 and c+1 until '\0'!
        wildcard_match(&pattern[1..], &candidate[1..])
    } else {
        false
    }
}

struct SacEntry {
    service: String,
    valid: bool,
}

fn sac_matches(list: &[SacEntry], service: &str) -> bool {
    list.iter()
        .any(|e| wildcard_match(e.service.as_bytes(), service.as_bytes()))
}

fn sac_parse(
    sac: &[u8],
    r_hosts: Option<&[SacEntry]>,
    r_accesses: Option<&[SacEntry]>,
) -> (Vec<SacEntry>, Vec<SacEntry>) {
    let mut hosts = Vec::new();
    let mut accesses = Vec::new();
    let mut ofs = 0usize;

    while ofs < sac.len() {
        let ctrl = sac[ofs];
        ofs += 1;
        let service_len = ((ctrl & 0xF) as usize) + 1;
        let end = (ofs + service_len).min(sac.len());
        let raw_bytes = &sac[ofs..end];
        let nul_pos = raw_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(raw_bytes.len());
        let service = String::from_utf8_lossy(&raw_bytes[..nul_pos]).into_owned();

        // Note: in npdm.c lines 553-557, `sac_matches` was called BEFORE `strncpy(cur_entry->service, ...)`
        // meaning `cur_entry->service` was empty `""` when matched against `r_host`/`r_accesses`!
        let valid = if (ctrl & 0x80) != 0 {
            match r_hosts {
                Some(rh) => sac_matches(rh, ""),
                None => true,
            }
        } else {
            match (r_hosts, r_accesses) {
                (Some(_), Some(ra)) => sac_matches(ra, ""),
                (Some(_), None) => false,
                (None, _) => true,
            }
        };

        if (ctrl & 0x80) != 0 {
            hosts.push(SacEntry { service, valid });
        } else {
            accesses.push(SacEntry { service, valid });
        }
        ofs += service_len;
    }

    (hosts, accesses)
}

fn sac_print(acid_sac: &[u8], aci0_sac: &[u8]) {
    let (acid_hosts, acid_accesses) = sac_parse(acid_sac, None, None);
    let (aci0_hosts, aci0_accesses) =
        sac_parse(aci0_sac, Some(&acid_hosts), Some(&acid_accesses));

    let mut first = true;
    for h in &aci0_hosts {
        let suffix = if h.valid { "" } else { "(Invalid)" };
        if first {
            println!("        Hosts:                      {:<16}{}", h.service, suffix);
            first = false;
        } else {
            println!("                                    {:<16}{}", h.service, suffix);
        }
    }

    first = true;
    for a in &aci0_accesses {
        let suffix = if a.valid { "" } else { "(Invalid)" };
        if first {
            println!(
                "        Accesses:                   {:<16}{}",
                a.service, suffix
            );
            first = false;
        } else {
            println!(
                "                                    {:<16}{}",
                a.service, suffix
            );
        }
    }
}

fn fac_print(fac_bytes: &[u8], fah_bytes: &[u8]) {
    if fac_bytes.len() < 12 || fah_bytes.len() < 12 {
        return;
    }
    let fac_ver = read_u32_le(fac_bytes, 0) as i32;
    let fac_perms = read_u64_le(fac_bytes, 4);
    let fah_ver = read_u32_le(fah_bytes, 0) as i32;
    let fah_perms = read_u64_le(fah_bytes, 4);

    if fac_ver == fah_ver {
        println!("        Version:                    {}", fac_ver);
    } else {
        println!("        Control Version:            {}", fac_ver);
        println!("        Header Version:             {}", fah_ver);
    }

    let perms = fac_perms & fah_perms;
    println!("        Raw Permissions:            0x{:016x}", perms);
    print!("        RW Permissions:             ");
    for &(name, mask) in &FS_PERMISSIONS_RW {
        if (mask & perms) != 0 {
            if (mask & (perms & FS_PERM_MASK_NODEBUG)) != 0 {
                print!("{}\n                                    ", name);
            } else {
                print!(
                    "{:<32} [DEBUG ONLY]\n                                    ",
                    name
                );
            }
        }
    }
    println!();
    print!("        Boolean Permissions:        ");
    for &(name, mask) in &FS_PERMISSIONS_BOOL {
        if (mask & perms) != 0 {
            if (mask & (perms & FS_PERM_MASK_NODEBUG)) != 0 {
                print!("{}\n                                    ", name);
            } else {
                print!(
                    "{:<32} [DEBUG ONLY]\n                                    ",
                    name
                );
            }
        }
    }
    println!();
}

pub fn npdm_process(npdm_bytes: &[u8], tool_ctx: &mut HactoolCtx) {
    if (tool_ctx.action & ACTION_INFO) != 0 {
        npdm_print(npdm_bytes, tool_ctx);
    }
    if (tool_ctx.action & ACTION_EXTRACT) != 0 {
        npdm_save(npdm_bytes, tool_ctx);
    }
}

fn read_u32_slice(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

pub fn npdm_print(npdm: &[u8], tool_ctx: &HactoolCtx) {
    if npdm.len() < 0x80 {
        return;
    }
    let magic = read_u32_le(npdm, 0);
    let acid_sign_key_index = read_u32_le(npdm, 4);
    let mmu_flags = npdm[0xC];
    let main_thread_prio = npdm[0xE] as i8;
    let default_cpuid = npdm[0xF];
    let version = read_u32_le(npdm, 0x18);
    let main_stack_size = read_u32_le(npdm, 0x1C);
    let title_name_raw = &npdm[0x20..0x70];
    let title_name_end = title_name_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(title_name_raw.len());
    let title_name = String::from_utf8_lossy(&title_name_raw[..title_name_end]);
    let aci0_offset = read_u32_le(npdm, 0x70) as usize;
    let acid_offset = read_u32_le(npdm, 0x78) as usize;

    println!("NPDM:");
    print_magic("    Magic:                          ", magic);
    println!("    MMU Flags:                      {:x}", mmu_flags);
    println!("    Main Thread Priority:           {}", main_thread_prio);
    println!("    Default CPU ID:                 {:x}", default_cpuid);
    println!(
        "    Version:                        {}.{}.{}-{} ({})",
        (version >> 26) & 0x3F,
        (version >> 20) & 0x3F,
        (version >> 16) & 0xF,
        version & 0xFFFF,
        version
    );
    println!("    Main Thread Stack Size:         0x{:x}", main_stack_size);
    println!("    Title Name:                     {}", title_name);

    if acid_offset + 0x240 > npdm.len() || aci0_offset + 0x40 > npdm.len() {
        return;
    }
    let acid = &npdm[acid_offset..];
    let aci0 = &npdm[aci0_offset..];

    let acid_sig: &[u8; 0x100] = acid[0..0x100].try_into().unwrap();
    let acid_mod: &[u8; 0x100] = acid[0x100..0x200].try_into().unwrap();
    let acid_magic = read_u32_le(acid, 0x200);
    let acid_size = read_u32_le(acid, 0x204) as usize;
    let acid_flags = read_u32_le(acid, 0x20C);
    let title_id_range_min = read_u64_le(acid, 0x210);
    let title_id_range_max = read_u64_le(acid, 0x218);
    let fac_offset = read_u32_le(acid, 0x220) as usize;
    let acid_sac_offset = read_u32_le(acid, 0x228) as usize;
    let acid_sac_size = read_u32_le(acid, 0x22C) as usize;
    let acid_kac_offset = read_u32_le(acid, 0x230) as usize;
    let acid_kac_size = read_u32_le(acid, 0x234) as usize;

    let aci0_magic = read_u32_le(aci0, 0x0);
    let aci0_title_id = read_u64_le(aci0, 0x10);
    let fah_offset = read_u32_le(aci0, 0x20) as usize;
    let aci0_sac_offset = read_u32_le(aci0, 0x28) as usize;
    let aci0_sac_size = read_u32_le(aci0, 0x2C) as usize;
    let aci0_kac_offset = read_u32_le(aci0, 0x30) as usize;
    let aci0_kac_size = read_u32_le(aci0, 0x34) as usize;

    println!("    ACID:");
    print_magic("        Magic:                      ", acid_magic);
    if (tool_ctx.action & ACTION_VERIFY) != 0 {
        let moduli = &tool_ctx.settings.keyset.acid_fixed_key_moduli;
        if (acid_sign_key_index as usize) < moduli.len() {
            println!("        Signature Key (GOOD):       {}", acid_sign_key_index);
            let verify_end = (0x100 + acid_size).min(acid.len());
            if rsa2048_pss_verify(
                &acid[0x100..verify_end],
                acid_sig,
                &moduli[acid_sign_key_index as usize],
            ) {
                memdump_stdout("        Signature (GOOD):           ", acid_sig);
            } else {
                memdump_stdout("        Signature (FAIL):           ", acid_sig);
            }
        } else {
            println!("        Signature Key (FAIL):       {}", acid_sign_key_index);
            memdump_stdout("        Signature (FAIL):           ", acid_sig);
        }
    } else {
        println!("        Signature Key:              {}", acid_sign_key_index);
        memdump_stdout("        Signature:                  ", acid_sig);
    }
    memdump_stdout("        Header Modulus:             ", acid_mod);
    println!("        Is Retail:                  {}", (acid_flags & 1) as i32);
    println!(
        "        Pool Partition:             {}",
        ((acid_flags >> 2) & 3) as i32
    );
    println!(
        "        Title ID Range:             {:016x}-{:016x}",
        title_id_range_min, title_id_range_max
    );

    println!("    ACI0:");
    print_magic("        Magic:                      ", aci0_magic);
    println!("        Title ID:                   {:016x}", aci0_title_id);

    let acid_kac_bytes = &acid[acid_kac_offset..(acid_kac_offset + acid_kac_size).min(acid.len())];
    let aci0_kac_bytes = &aci0[aci0_kac_offset..(aci0_kac_offset + aci0_kac_size).min(aci0.len())];
    let acid_kac = read_u32_slice(acid_kac_bytes);
    let aci0_kac = read_u32_slice(aci0_kac_bytes);

    if acid_kac_bytes == aci0_kac_bytes {
        println!("    Kernel Access Control:");
        kac_print(&acid_kac);
    } else {
        println!("    ACID Kernel Access Control:");
        kac_print(&acid_kac);
        println!("    ACI0 Kernel Access Control:");
        kac_print(&aci0_kac);
    }

    let acid_sac = &acid[acid_sac_offset..(acid_sac_offset + acid_sac_size).min(acid.len())];
    let aci0_sac = &aci0[aci0_sac_offset..(aci0_sac_offset + aci0_sac_size).min(aci0.len())];
    println!("    Service Access Control:");
    sac_print(acid_sac, aci0_sac);

    let fac = &acid[fac_offset..];
    let fah = &aci0[fah_offset..];
    println!("    Filesystem Access Control:");
    fac_print(fac, fah);
}

// ============================================================================
// cJSON-compatible JSON builder for NPDM and KIP1
// ============================================================================

#[derive(Clone, Debug)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    pub fn format_cjson(&self) -> String {
        let mut out = String::new();
        self.fmt_inner(&mut out, 0);
        out
    }

    fn fmt_inner(&self, out: &mut String, depth: usize) {
        match self {
            JsonValue::Null => out.push_str("null"),
            JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            JsonValue::Number(n) => out.push_str(&n.to_string()),
            JsonValue::String(s) => {
                out.push('"');
                for ch in s.chars() {
                    match ch {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\x08' => out.push_str("\\b"),
                        '\x0c' => out.push_str("\\f"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 32 => {
                            out.push_str(&format!("\\u{:04x}", c as u32));
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            // In cJSON.c `print_array`:
            // arrays increment depth by 1, format on a single line `[elem1, elem2]`
            JsonValue::Array(items) => {
                out.push('[');
                for (idx, item) in items.iter().enumerate() {
                    item.fmt_inner(out, depth + 1);
                    if idx + 1 < items.len() {
                        out.push_str(", ");
                    }
                }
                out.push(']');
            }
            // In cJSON.c `print_object`:
            // objects increment depth by 1, use `\n` and `\t` indentation, and `:\t` after key
            JsonValue::Object(fields) => {
                if fields.is_empty() {
                    out.push_str("{\n");
                    for _ in 0..depth {
                        out.push('\t');
                    }
                    out.push('}');
                    return;
                }
                out.push_str("{\n");
                let child_depth = depth + 1;
                for (idx, (k, v)) in fields.iter().enumerate() {
                    for _ in 0..child_depth {
                        out.push('\t');
                    }
                    JsonValue::String(k.clone()).fmt_inner(out, child_depth);
                    out.push_str(":\t");
                    v.fmt_inner(out, child_depth);
                    if idx + 1 < fields.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                for _ in 0..depth {
                    out.push('\t');
                }
                out.push('}');
            }
        }
    }
}

fn kac_create_obj(type_str: &str, val: JsonValue) -> JsonValue {
    JsonValue::Object(vec![
        ("type".to_string(), JsonValue::String(type_str.to_string())),
        ("value".to_string(), val),
    ])
}

pub fn kac_get_json(descriptors: &[u32]) -> JsonValue {
    let mut items: Vec<JsonValue> = Vec::new();
    let mut syscall_obj_idx: Option<usize> = None;

    let mut i = 0;
    while i < descriptors.len() {
        let mut desc = descriptors[i];
        i += 1;
        if desc == 0xFFFFFFFF {
            continue;
        }
        let mut low_bits = 0u32;
        while (desc & 1) != 0 {
            desc >>= 1;
            low_bits += 1;
        }
        desc >>= 1;

        match low_bits {
            3 => {
                let mut fields = Vec::new();
                fields.push((
                    "highest_thread_priority".to_string(),
                    JsonValue::Number((desc & 0x3F) as i64),
                ));
                desc >>= 6;
                fields.push((
                    "lowest_thread_priority".to_string(),
                    JsonValue::Number((desc & 0x3F) as i64),
                ));
                desc >>= 6;
                fields.push((
                    "lowest_cpu_id".to_string(),
                    JsonValue::Number((desc & 0xFF) as i64),
                ));
                desc >>= 8;
                fields.push((
                    "highest_cpu_id".to_string(),
                    JsonValue::Number((desc & 0xFF) as i64),
                ));
                items.push(kac_create_obj("kernel_flags", JsonValue::Object(fields)));
            }
            4 => {
                let idx = match syscall_obj_idx {
                    Some(idx) => idx,
                    None => {
                        let new_idx = items.len();
                        items.push(kac_create_obj("syscalls", JsonValue::Object(Vec::new())));
                        syscall_obj_idx = Some(new_idx);
                        new_idx
                    }
                };
                let syscall_base = ((desc >> 24) as usize) * 0x18;
                if let JsonValue::Object(ref mut obj_fields) = items[idx] {
                    if let Some((_, JsonValue::Object(ref mut sc_fields))) = obj_fields.get_mut(1)
                    {
                        for sc in 0..0x18 {
                            if syscall_base + sc < 0xC0 {
                                if (desc & 1) != 0 {
                                    let id = syscall_base + sc;
                                    sc_fields.push((
                                        SVC_NAMES[id].to_string(),
                                        JsonValue::String(format!("0x{:02x}", id as u8)),
                                    ));
                                }
                                desc >>= 1;
                            }
                        }
                    }
                }
            }
            6 => {
                let address = (desc & 0xFFFFFF) << 12;
                let is_ro = ((desc >> 24) & 1) != 0;
                if i >= descriptors.len() {
                    eprintln!("Error: Invalid Kernel Access Control Descriptors!");
                    process::exit(1);
                }
                desc = descriptors[i];
                i += 1;
                if (desc & 0x7F) != 0x3F {
                    eprintln!("Error: Invalid Kernel Access Control Descriptors!");
                    process::exit(1);
                }
                desc >>= 7;
                let size = (desc & 0xFFFFFF) << 12;
                let is_io = ((desc >> 24) & 1) == 0;
                let fields = vec![
                    (
                        "address".to_string(),
                        JsonValue::String(format!("0x{:08x}", address)),
                    ),
                    ("is_ro".to_string(), JsonValue::Bool(is_ro)),
                    (
                        "size".to_string(),
                        JsonValue::String(format!("0x{:08x}", size)),
                    ),
                    ("is_io".to_string(), JsonValue::Bool(is_io)),
                ];
                items.push(kac_create_obj("map", JsonValue::Object(fields)));
            }
            7 => {
                let page = desc << 12;
                items.push(kac_create_obj(
                    "map_page",
                    JsonValue::String(format!("0x{:08x}", page)),
                ));
            }
            11 => {
                let irq0 = if (desc & 0x3FF) == 0x3FF {
                    JsonValue::Null
                } else {
                    JsonValue::Number((desc & 0x3FF) as i64)
                };
                desc >>= 10;
                let irq1 = if (desc & 0x3FF) == 0x3FF {
                    JsonValue::Null
                } else {
                    JsonValue::Number((desc & 0x3FF) as i64)
                };
                items.push(kac_create_obj("irq_pair", JsonValue::Array(vec![irq0, irq1])));
            }
            13 => {
                items.push(kac_create_obj(
                    "application_type",
                    JsonValue::Number((desc & 7) as i64),
                ));
            }
            14 => {
                items.push(kac_create_obj(
                    "min_kernel_version",
                    JsonValue::String(format!("0x{:04x}", (desc & 0xFFFF) as u16)),
                ));
            }
            15 => {
                items.push(kac_create_obj(
                    "handle_table_size",
                    JsonValue::Number(desc as i64),
                ));
            }
            16 => {
                let fields = vec![
                    ("allow_debug".to_string(), JsonValue::Bool((desc & 1) != 0)),
                    (
                        "force_debug".to_string(),
                        JsonValue::Bool(((desc >> 1) & 1) != 0),
                    ),
                ];
                items.push(kac_create_obj("debug_flags", JsonValue::Object(fields)));
            }
            _ => {}
        }
    }

    JsonValue::Array(items)
}

fn sac_get_json_filtered(sac: &[u8], want_host: bool) -> JsonValue {
    let mut items = Vec::new();
    let mut ofs = 0usize;
    while ofs < sac.len() {
        let ctrl = sac[ofs];
        ofs += 1;
        let service_len = ((ctrl & 0x7) as usize) + 1;
        let is_host = (ctrl & 0x80) != 0;
        if is_host == want_host {
            let end = (ofs + service_len).min(sac.len());
            let raw = &sac[ofs..end];
            let nul_pos = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let s = String::from_utf8_lossy(&raw[..nul_pos]).into_owned();
            items.push(JsonValue::String(s));
        }
        ofs += service_len;
    }
    JsonValue::Array(items)
}

pub fn npdm_get_json(npdm: &[u8]) -> String {
    let mmu_flags = npdm[0xC];
    let main_thread_prio = npdm[0xE];
    let default_cpuid = npdm[0xF];
    let version = read_u32_le(npdm, 0x18);
    let main_stack_size = read_u32_le(npdm, 0x1C);
    let title_name_raw = &npdm[0x20..0x70];
    let title_name_end = title_name_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(title_name_raw.len());
    let title_name = String::from_utf8_lossy(&title_name_raw[..title_name_end]).into_owned();
    let aci0_offset = read_u32_le(npdm, 0x70) as usize;
    let acid_offset = read_u32_le(npdm, 0x78) as usize;

    let acid = &npdm[acid_offset..];
    let aci0 = &npdm[aci0_offset..];

    let acid_flags = read_u32_le(acid, 0x20C);
    let title_id_range_min = read_u64_le(acid, 0x210);
    let title_id_range_max = read_u64_le(acid, 0x218);
    let fac_offset = read_u32_le(acid, 0x220) as usize;

    let aci0_title_id = read_u64_le(aci0, 0x10);
    let fah_offset = read_u32_le(aci0, 0x20) as usize;
    let aci0_sac_offset = read_u32_le(aci0, 0x28) as usize;
    let aci0_sac_size = read_u32_le(aci0, 0x2C) as usize;
    let aci0_kac_offset = read_u32_le(aci0, 0x30) as usize;
    let aci0_kac_size = read_u32_le(aci0, 0x34) as usize;

    let fac_perms = read_u64_le(&acid[fac_offset..], 4);
    let fah_perms = read_u64_le(&aci0[fah_offset..], 4);
    let perms = fac_perms & fah_perms;

    let aci0_sac = &aci0[aci0_sac_offset..(aci0_sac_offset + aci0_sac_size).min(aci0.len())];
    let aci0_kac_bytes = &aci0[aci0_kac_offset..(aci0_kac_offset + aci0_kac_size).min(aci0.len())];
    let aci0_kac = read_u32_slice(aci0_kac_bytes);

    let root = JsonValue::Object(vec![
        ("name".to_string(), JsonValue::String(title_name)),
        (
            "title_id".to_string(),
            JsonValue::String(format!("0x{:016x}", aci0_title_id)),
        ),
        (
            "title_id_range_min".to_string(),
            JsonValue::String(format!("0x{:016x}", title_id_range_min)),
        ),
        (
            "title_id_range_max".to_string(),
            JsonValue::String(format!("0x{:016x}", title_id_range_max)),
        ),
        (
            "main_thread_stack_size".to_string(),
            JsonValue::String(format!("0x{:08x}", main_stack_size)),
        ),
        (
            "main_thread_priority".to_string(),
            JsonValue::Number(main_thread_prio as i64),
        ),
        (
            "default_cpu_id".to_string(),
            JsonValue::Number(default_cpuid as i64),
        ),
        (
            "version".to_string(),
            JsonValue::String(format!("0x{:08x}", version)),
        ),
        ("is_retail".to_string(), JsonValue::Bool((acid_flags & 1) != 0)),
        (
            "pool_partition".to_string(),
            JsonValue::Number(((acid_flags >> 2) & 3) as i64),
        ),
        ("is_64_bit".to_string(), JsonValue::Bool((mmu_flags & 1) != 0)),
        (
            "address_space_type".to_string(),
            JsonValue::Number(((mmu_flags >> 1) & 7) as i64),
        ),
        (
            "filesystem_access".to_string(),
            JsonValue::Object(vec![(
                "permissions".to_string(),
                JsonValue::String(format!("0x{:016x}", perms)),
            )]),
        ),
        (
            "service_access".to_string(),
            sac_get_json_filtered(aci0_sac, false),
        ),
        (
            "service_host".to_string(),
            sac_get_json_filtered(aci0_sac, true),
        ),
        ("kernel_capabilities".to_string(), kac_get_json(&aci0_kac)),
    ]);

    root.format_cjson()
}

pub fn npdm_save(npdm: &[u8], tool_ctx: &HactoolCtx) {
    let json_path = &tool_ctx.settings.npdm_json_path;
    if json_path.valid != Validity::Valid {
        return;
    }

    let mut f_json = match create_uncompressed_file(&json_path.char_path) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("Failed to open {}!", json_path.char_path);
            return;
        }
    };

    let json = npdm_get_json(npdm);
    if f_json.write_all(json.as_bytes()).is_err() {
        eprintln!("Failed to write JSON file!");
        process::exit(1);
    }
}

