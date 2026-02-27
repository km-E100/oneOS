#![cfg(target_os = "none")]

extern crate alloc;

use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;

use crate::drivers::serial;

use crate::goes;
use crate::goes::records as goes_records;

mod abi;
mod console;
mod elf;

pub use abi::{api_v1_ptr, AppApiV1};
pub use abi::{debug_last_call, DebugLastAbiCall};
pub use console::{
    read_line as console_read_line, write_line as console_write_line,
    write_line_args as console_write_line_args, write_str as console_write_str, ConsoleError,
};

static RUNNING: Mutex<BTreeMap<String, u32>> = Mutex::new(BTreeMap::new());

#[derive(Clone)]
struct CachedAppBinary {
    name: String,
    arch: u32,
    seq: u64,
    bytes: Vec<u8>,
    last_use: u64,
}

static CACHE_TICK: AtomicU64 = AtomicU64::new(1);
static APP_BINARY_CACHE: Mutex<Vec<CachedAppBinary>> = Mutex::new(Vec::new());
const APP_BINARY_CACHE_MAX_BYTES: usize = 8 * 1024 * 1024; // 8MiB

// Cached bytes format (in-boot only): a compact “segment image” to avoid re-reading ELF from disk.
// This intentionally avoids any path semantics; it’s purely a performance cache.
const APP_IMAGE_MAGIC: [u8; 4] = *b"OAPP";
const APP_IMAGE_VERSION_V1: u32 = 1;
const APP_IMAGE_VERSION_V2: u32 = 2;
const APP_IMAGE_VERSION_CURRENT: u32 = APP_IMAGE_VERSION_V2;
const APP_IMAGE_SEG_ENTRY_V1_SIZE: usize = 16;
const APP_IMAGE_SEG_ENTRY_V2_SIZE: usize = 24;

pub const CAP_CONSOLE: u64 = 1 << 0;
pub const CAP_GPU: u64 = 1 << 1;
pub const CAP_GOES_READ_USER: u64 = 1 << 2;
pub const CAP_GOES_WRITE_USER: u64 = 1 << 3;
pub const CAP_IPC: u64 = 1 << 4;

// When a timer IRQ times out an AppDomain, the interrupt handler redirects execution
// to this saved address so `call_app_entry` can restore the kernel stack and return.
#[no_mangle]
pub static mut ONEOS_APP_ABORT_JMP: u64 = 0;

// aarch64: `call_app_entry` must not rely on call-clobbered registers after `blr entry`.
// Keep the saved kernel SP in a global slot and reference it via PC-relative addressing.
#[no_mangle]
pub static mut ONEOS_APP_SAVED_SP: u64 = 0;

// Best-effort debug breadcrumbs for App entry handoff on aarch64.
// These are used by the aarch64 trap logger to diagnose failures before/inside the first ABI call.
#[no_mangle]
pub static mut ONEOS_APP_DEBUG_ENTRY: u64 = 0;
#[no_mangle]
pub static mut ONEOS_APP_DEBUG_API: u64 = 0;
#[no_mangle]
pub static mut ONEOS_APP_DEBUG_STACK_TOP: u64 = 0;
#[no_mangle]
pub static mut ONEOS_APP_DEBUG_SP_BEFORE: u64 = 0;
#[no_mangle]
pub static mut ONEOS_APP_DEBUG_SP_AFTER_SET: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppError {
    GoesUnavailable,
    NotFound,
    Removed,
    AlreadyRunning,
    NotRunning,
    PermissionDenied,
    InvalidBinary,
    WriteFailed,
    MmuBuildFailed,
    MmuSwitchFailed,
}

#[cfg(target_arch = "aarch64")]
const APP_LOAD_BASE: u64 = 0x4100_0000;
#[cfg(target_arch = "aarch64")]
const APP_LOAD_LIMIT: u64 = 0x0200_0000; // 32 MiB

#[cfg(target_arch = "x86_64")]
const APP_LOAD_BASE: u64 = 0x3000_0000;
#[cfg(target_arch = "x86_64")]
const APP_LOAD_LIMIT: u64 = 0x0200_0000; // 32 MiB

const APP_STACK_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
struct LoadedSeg {
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    flags: u32, // ELF p_flags (PF_X=1, PF_W=2, PF_R=4); 0 if unknown (OAPP v1)
}

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __data_end: u8;
    static __bss_start: u8;
    static __bss_end: u8;
}

fn align_down_4k(x: u64) -> u64 {
    x & !0xfffu64
}

fn align_up_4k(x: u64) -> u64 {
    (x + 0xfff) & !0xfffu64
}

fn push_map_wx_checked(
    layout: &mut crate::mmu::addrspace::AppSpaceLayout,
    map: crate::mmu::addrspace::AppMap,
) {
    if map.exec && map.writable {
        // Hard rule (Stage 5/M3): never allow RWX pages in an App address space.
        serial::log_line_args(format_args!(
            "mmu-appspace: reject RWX map va=0x{:x} len=0x{:x} (device={})",
            map.va, map.len, map.device
        ));
        return;
    }
    layout.push(map);
}

fn locator_binary_len(loc: &goes::replay::AppBinaryLocator) -> u32 {
    goes::replay::binary_payload_len(loc)
}

fn load_app_image_from_disk(
    name: &str,
    loc: &goes::replay::AppBinaryLocator,
    want_cache: bool,
) -> Result<(u64, Option<u32>, u32, Option<Vec<u8>>, Vec<LoadedSeg>), AppError> {
    // payload: v1 meta(56) + OAPP segment image bytes
    if loc.payload_len < 56 {
        return Err(AppError::InvalidBinary);
    }
    let image_len = locator_binary_len(loc) as usize;
    if image_len < 24 {
        return Err(AppError::InvalidBinary);
    }

    let base = loc.record_off + goes_records::HEADER_SIZE as u64 + 56;

    // OAPP header (24 bytes)
    let mut hdr = [0u8; 24];
    crate::virtio::blk::read_at_res(base, &mut hdr).map_err(|_| AppError::GoesUnavailable)?;
    if &hdr[0..4] != b"OAPP" {
        serial::log_line_args(format_args!(
            "app: image magic mismatch for {} (got {:02x} {:02x} {:02x} {:02x})",
            name, hdr[0], hdr[1], hdr[2], hdr[3]
        ));
        return Err(AppError::InvalidBinary);
    }
    let ver = u32::from_le_bytes(hdr[4..8].try_into().unwrap_or([0; 4]));
    if ver != APP_IMAGE_VERSION_V1 && ver != APP_IMAGE_VERSION_V2 {
        serial::log_line_args(format_args!(
            "app: unsupported OAPP version {} for {}",
            ver, name
        ));
        return Err(AppError::InvalidBinary);
    }
    let entry = u64::from_le_bytes(hdr[8..16].try_into().unwrap_or([0; 8]));
    let seg_count = u32::from_le_bytes(hdr[16..20].try_into().unwrap_or([0; 4])) as usize;
    let entry_size_hdr = u32::from_le_bytes(hdr[20..24].try_into().unwrap_or([0; 4])) as usize;
    let entry_size = if entry_size_hdr != 0 {
        entry_size_hdr
    } else if ver == APP_IMAGE_VERSION_V1 {
        APP_IMAGE_SEG_ENTRY_V1_SIZE
    } else {
        APP_IMAGE_SEG_ENTRY_V2_SIZE
    };
    if entry_size != APP_IMAGE_SEG_ENTRY_V1_SIZE && entry_size != APP_IMAGE_SEG_ENTRY_V2_SIZE {
        serial::log_line_args(format_args!(
            "app: invalid OAPP entry_size={} ver={} for {}",
            entry_size, ver, name
        ));
        return Err(AppError::InvalidBinary);
    }
    let table_len = seg_count.saturating_mul(entry_size);
    if seg_count == 0 || table_len > 64 * 1024 {
        return Err(AppError::InvalidBinary);
    }
    let header_len = 24usize;
    let data_base = header_len + table_len;
    if data_base > image_len {
        return Err(AppError::InvalidBinary);
    }

    let mut table = Vec::new();
    table.resize(table_len, 0u8);
    crate::virtio::blk::read_at_res(base + header_len as u64, &mut table)
        .map_err(|_| AppError::GoesUnavailable)?;

    let mut cache_img = if want_cache {
        let mut buf = Vec::new();
        buf.resize(image_len, 0u8);
        buf[0..24].copy_from_slice(&hdr);
        buf[24..24 + table_len].copy_from_slice(&table);
        Some(buf)
    } else {
        None
    };

    let mut data_off = 0usize;
    let mut segs_out: Vec<LoadedSeg> = Vec::new();
    for i in 0..seg_count {
        let t = i * entry_size;
        let vaddr = u64::from_le_bytes(table[t..t + 8].try_into().unwrap_or([0; 8]));
        let filesz = u32::from_le_bytes(table[t + 8..t + 12].try_into().unwrap_or([0; 4])) as usize;
        let memsz = u32::from_le_bytes(table[t + 12..t + 16].try_into().unwrap_or([0; 4])) as usize;
        let flags = if entry_size >= 20 {
            u32::from_le_bytes(table[t + 16..t + 20].try_into().unwrap_or([0; 4]))
        } else {
            0
        };
        if memsz == 0 {
            continue;
        }
        segs_out.push(LoadedSeg {
            vaddr,
            filesz: filesz as u64,
            memsz: memsz as u64,
            flags,
        });
        let end = vaddr
            .checked_add(memsz as u64)
            .ok_or(AppError::InvalidBinary)?;
        let allowed_end = APP_LOAD_BASE
            .checked_add(APP_LOAD_LIMIT)
            .ok_or(AppError::InvalidBinary)?;
        if vaddr < APP_LOAD_BASE || end > allowed_end {
            serial::log_line_args(format_args!(
                "app: image segment vaddr out of range: name={} vaddr=0x{:x} end=0x{:x} allowed=[0x{:x},0x{:x})",
                name, vaddr, end, APP_LOAD_BASE, allowed_end
            ));
            return Err(AppError::InvalidBinary);
        }
        if data_base
            .checked_add(data_off)
            .and_then(|o| o.checked_add(filesz))
            .ok_or(AppError::InvalidBinary)?
            > image_len
        {
            return Err(AppError::InvalidBinary);
        }

        // Only clear BSS region; file bytes will overwrite the rest.
        unsafe {
            let dst = core::slice::from_raw_parts_mut(vaddr as *mut u8, memsz);
            if filesz < memsz {
                dst[filesz..].fill(0);
            } else if filesz == 0 {
                dst[..].fill(0);
            }
        }

        // Larger I/O reduces virtio-blk requests and host overhead.
        // Keep this aligned with the host-side bulk buffer (256KiB).
        const CHUNK: usize = 256 * 1024;
        let mut done = 0usize;
        while done < filesz {
            let take = core::cmp::min(CHUNK, filesz - done);
            unsafe {
                let dst = core::slice::from_raw_parts_mut((vaddr as usize + done) as *mut u8, take);
                crate::virtio::blk::read_at_res(base + (data_base + data_off + done) as u64, dst)
                    .map_err(|_| AppError::GoesUnavailable)?;
                if let Some(img) = cache_img.as_mut() {
                    let start = data_base + data_off + done;
                    let end = start + take;
                    img[start..end].copy_from_slice(dst);
                }
            }
            done += take;
        }

        data_off += filesz;
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "dsb ish",
            "ic iallu",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }

    Ok((
        entry,
        None,
        image_len.min(u32::MAX as usize) as u32,
        cache_img,
        segs_out,
    ))
}

pub fn install(name: &str, entry: &str, version: &str, caps_mask: u64) -> Result<u64, AppError> {
    // Applications workspace is a registry only; all package objects live in App:<name>.
    let ws_registry = "Applications";
    let app_ws = alloc::format!("App:{}", name);
    let app_data_ws = alloc::format!("LAD:{}", name);
    if app_ws.as_bytes().len() > 32 {
        return Err(AppError::WriteFailed);
    }
    if app_data_ws.as_bytes().len() > 32 {
        return Err(AppError::WriteFailed);
    }

    // Ensure App workspace exists (recorded under Applications).
    let mut ws_payload = [0u8; 40];
    goes::replay::encode_create_workspace_payload_v1(&app_ws, 0, &mut ws_payload);
    let _ = goes::writer::append_record(
        ws_registry,
        goes::records::RECORD_CREATE_WORKSPACE_V1,
        &ws_payload,
    );
    // Ensure per-app private data workspace exists (Library/AppData/<app> semantic; `LAD:<app>` encoding).
    goes::replay::encode_create_workspace_payload_v1(&app_data_ws, 0, &mut ws_payload);
    let _ = goes::writer::append_record(
        ws_registry,
        goes::records::RECORD_CREATE_WORKSPACE_V1,
        &ws_payload,
    );

    let mut payload = [0u8; 104];
    goes::replay::encode_app_manifest_payload_v2(name, entry, version, &mut payload);
    let seq = goes::writer::append_record(&app_ws, goes::records::RECORD_APP_MANIFEST_V2, &payload)
        .map_err(|e| {
            serial::log_line_args(format_args!("app: install manifest failed: {:?}", e));
            match e {
                goes::writer::WriteError::PermissionDenied => AppError::PermissionDenied,
                goes::writer::WriteError::GoesUnavailable => AppError::GoesUnavailable,
                _ => AppError::WriteFailed,
            }
        })?;

    // Applications registry: name -> App workspace mapping.
    let mut reg_payload = [0u8; 72];
    reg_payload[0..4].copy_from_slice(&1u32.to_le_bytes());
    reg_payload[4..8].copy_from_slice(&0u32.to_le_bytes());
    reg_payload[8..40].copy_from_slice(&goes::records::encode_name32(name));
    reg_payload[40..72].copy_from_slice(&goes::records::encode_name32(&app_ws));
    let _ = goes::writer::append_record(
        ws_registry,
        goes::records::RECORD_APP_REGISTRY_V1,
        &reg_payload,
    );

    // AppConfig: create an empty config by default; host installer may overwrite with actual bytes.
    let mut cfg_payload = Vec::with_capacity(4 + 4 + 32 + 32 + 4);
    cfg_payload.extend_from_slice(&1u32.to_le_bytes());
    cfg_payload.extend_from_slice(&0u32.to_le_bytes());
    cfg_payload.extend_from_slice(&goes::records::encode_name32(name));
    cfg_payload.extend_from_slice(&goes::records::encode_name32(&app_ws));
    cfg_payload.extend_from_slice(&0u32.to_le_bytes());
    let _ = goes::writer::append_record(
        &app_ws,
        goes::records::RECORD_APP_CONFIG_TEXT_V1,
        &cfg_payload,
    );

    // AppBinary placeholder (v2, no bytes yet; host installer may write bytes).
    let mut bin_payload = [0u8; 48];
    goes::replay::encode_app_binary_payload_v2_header(name, 0, &mut bin_payload);
    let _ = goes::writer::append_record(&app_ws, goes::records::RECORD_APP_BINARY_V2, &bin_payload);

    // AppCapabilities (v2).
    let mut caps_payload = [0u8; 48];
    goes::replay::encode_app_caps_payload_v2(name, caps_mask, &mut caps_payload);
    let _ = goes::writer::append_record(&app_ws, goes::records::RECORD_APP_CAPS_V2, &caps_payload);

    crate::audit::emit(
        crate::audit::EVENT_APP_INSTALL,
        "Applications",
        name,
        caps_mask,
        seq,
    );
    Ok(seq)
}

fn load_elf_segments(bytes: &[u8]) -> Result<u64, AppError> {
    let (info, phdrs) = elf::parse_elf64_le(bytes).map_err(|_| AppError::InvalidBinary)?;
    // PT_LOAD = 1
    for ph in phdrs.iter() {
        if ph.p_type != 1 {
            continue;
        }
        if ph.memsz == 0 {
            continue;
        }
        let vaddr = ph.vaddr;
        let end = vaddr.checked_add(ph.memsz).ok_or(AppError::InvalidBinary)?;
        let allowed_end = APP_LOAD_BASE
            .checked_add(APP_LOAD_LIMIT)
            .ok_or(AppError::InvalidBinary)?;
        if vaddr < APP_LOAD_BASE || end > allowed_end {
            serial::log_line_args(format_args!(
                "app: segment vaddr out of range: vaddr=0x{:x} end=0x{:x} allowed=[0x{:x},0x{:x})",
                vaddr, end, APP_LOAD_BASE, allowed_end
            ));
            return Err(AppError::InvalidBinary);
        }

        let off = ph.offset as usize;
        let filesz = ph.filesz as usize;
        let memsz = ph.memsz as usize;
        if off.checked_add(filesz).ok_or(AppError::InvalidBinary)? > bytes.len() {
            return Err(AppError::InvalidBinary);
        }

        unsafe {
            let dst = core::slice::from_raw_parts_mut(vaddr as *mut u8, memsz);
            if filesz < memsz {
                dst[filesz..].fill(0);
            } else if filesz == 0 {
                dst[..].fill(0);
            }
            if filesz != 0 {
                dst[..filesz].copy_from_slice(&bytes[off..off + filesz]);
            }
        }
    }

    // Ensure instruction cache coherency after loading executable code.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "dsb ish",
            "ic iallu",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }

    Ok(info.entry)
}

#[cfg(target_arch = "aarch64")]
unsafe fn call_app_entry(entry: u64, api: *const AppApiV1, stack_top: *mut u8) -> i32 {
    let mut ret: i32;
    core::arch::asm!(
        // Record handoff parameters for debugging.
        "str {func}, [{dbg_entry}]",
        "str x0, [{dbg_api}]",
        "str {stack}, [{dbg_stack}]",
        "mov x15, sp",
        "str x15, [{dbg_sp_before}]",
        // Save abort target (label 2) into a global (PC-relative).
        "adr x17, 2f",
        "adrp x16, ONEOS_APP_ABORT_JMP",
        "add x16, x16, :lo12:ONEOS_APP_ABORT_JMP",
        "str x17, [x16]",
        // Save kernel SP into a global slot (PC-relative).
        //
        "mov x16, sp",
        "adrp x17, ONEOS_APP_SAVED_SP",
        "add x17, x17, :lo12:ONEOS_APP_SAVED_SP",
        "str x16, [x17]",
        // Switch to app stack.
        "mov sp, {stack}",
        "mov x15, sp",
        "str x15, [{dbg_sp_after}]",
        "blr {func}",
        "2:",
        // Restore kernel SP (PC-relative). This must not depend on any app-preserved registers.
        "adrp x16, ONEOS_APP_SAVED_SP",
        "add x16, x16, :lo12:ONEOS_APP_SAVED_SP",
        "ldr x17, [x16]",
        "mov sp, x17",
        func = in(reg) entry,
        stack = in(reg) stack_top,
        dbg_entry = in(reg) (&raw mut ONEOS_APP_DEBUG_ENTRY as *mut u64),
        dbg_api = in(reg) (&raw mut ONEOS_APP_DEBUG_API as *mut u64),
        dbg_stack = in(reg) (&raw mut ONEOS_APP_DEBUG_STACK_TOP as *mut u64),
        dbg_sp_before = in(reg) (&raw mut ONEOS_APP_DEBUG_SP_BEFORE as *mut u64),
        dbg_sp_after = in(reg) (&raw mut ONEOS_APP_DEBUG_SP_AFTER_SET as *mut u64),
        in("x0") api,
        lateout("w0") ret,
        // Inform the compiler that all C-ABI call-clobbered registers may be clobbered by `blr`.
        clobber_abi("C"),
        out("x15") _,
        options(preserves_flags)
    );
    ret
}

#[cfg(target_arch = "x86_64")]
unsafe fn call_app_entry(entry: u64, api: *const AppApiV1, stack_top: *mut u8) -> i32 {
    let mut ret: i32;
    core::arch::asm!(
        // Save abort target (label 2) into global (RIP-relative to avoid relocations).
        "lea r15, [rip + {abort_sym}]",
        "lea r14, [rip + 2f]",
        "mov qword ptr [r15], r14",
        // Save kernel RSP into global (RIP-relative to avoid relocations).
        "lea r15, [rip + {saved_sp_sym}]",
        "mov qword ptr [r15], rsp",
        // Switch to app stack, call app entry.
        "mov rsp, {stack}",
        "call {func}",
        "2:",
        // Restore kernel RSP from global (do not depend on app-preserved registers).
        "lea r15, [rip + {saved_sp_sym}]",
        "mov rsp, qword ptr [r15]",
        func = in(reg) entry,
        stack = in(reg) stack_top,
        abort_sym = sym ONEOS_APP_ABORT_JMP,
        saved_sp_sym = sym ONEOS_APP_SAVED_SP,
        in("rdi") api,
        lateout("eax") ret,
        out("r14") _,
        out("r15") _,
        // Tell the compiler that the CALL may clobber all C ABI call-clobbered registers.
        clobber_abi("C"),
        options(preserves_flags)
    );
    ret
}

pub fn remove(name: &str) -> Result<u64, AppError> {
    // If the app is running, stop it first for deterministic behavior.
    // This must not panic; failure to stop just yields a regular error.
    if RUNNING.lock().contains_key(name) {
        let _ = stop(name);
    }
    let ws = "Applications";
    let mut payload = [0u8; 40];
    goes::replay::encode_app_remove_payload_v2(name, &mut payload);
    let seq = goes::writer::append_record(ws, goes::records::RECORD_APP_REMOVE_V2, &payload)
        .map_err(|e| match e {
            goes::writer::WriteError::PermissionDenied => AppError::PermissionDenied,
            goes::writer::WriteError::GoesUnavailable => AppError::GoesUnavailable,
            _ => AppError::WriteFailed,
        })?;
    crate::audit::emit(crate::audit::EVENT_APP_REMOVE, "Applications", name, 0, seq);
    Ok(seq)
}

fn ensure_app_workspace(
    user: &str,
    app: &str,
    idx: &goes::replay::Index,
) -> Result<String, AppError> {
    let mut ws = String::from("User:");
    ws.push_str(user);
    ws.push_str("/Apps/");
    ws.push_str(app);
    if idx.workspaces.contains_key(&ws) {
        return Ok(ws);
    }
    let mut payload = [0u8; 40];
    goes::replay::encode_create_workspace_payload_v1(&ws, 0, &mut payload);
    let mut user_root = String::from("User:");
    user_root.push_str(user);
    goes::writer::append_record(
        &user_root,
        goes::records::RECORD_CREATE_WORKSPACE_V1,
        &payload,
    )
    .map_err(|e| match e {
        goes::writer::WriteError::PermissionDenied => AppError::PermissionDenied,
        goes::writer::WriteError::GoesUnavailable => AppError::GoesUnavailable,
        _ => AppError::WriteFailed,
    })?;
    Ok(ws)
}

fn cache_total_bytes(entries: &[CachedAppBinary]) -> usize {
    entries.iter().map(|e| e.bytes.len()).sum()
}

fn cache_get(name: &str, arch: u32, seq: u64) -> Option<Vec<u8>> {
    let mut cache = APP_BINARY_CACHE.lock();
    let now = CACHE_TICK.fetch_add(1, Ordering::Relaxed);
    if let Some(entry) = cache
        .iter_mut()
        .find(|e| e.seq == seq && e.arch == arch && e.name.eq_ignore_ascii_case(name))
    {
        entry.last_use = now;
        return Some(entry.bytes.clone());
    }
    None
}

fn cache_put(name: &str, arch: u32, seq: u64, bytes: Vec<u8>) {
    // Keep cache bounded; this is a performance optimization only.
    if bytes.is_empty() || bytes.len() > APP_BINARY_CACHE_MAX_BYTES {
        return;
    }
    let mut cache = APP_BINARY_CACHE.lock();
    let now = CACHE_TICK.fetch_add(1, Ordering::Relaxed);

    if let Some(entry) = cache
        .iter_mut()
        .find(|e| e.seq == seq && e.arch == arch && e.name.eq_ignore_ascii_case(name))
    {
        entry.bytes = bytes;
        entry.last_use = now;
        return;
    }

    cache.push(CachedAppBinary {
        name: name.to_string(),
        arch,
        seq,
        bytes,
        last_use: now,
    });

    // Evict LRU until within limit.
    while cache_total_bytes(&cache) > APP_BINARY_CACHE_MAX_BYTES {
        if let Some((idx, _)) = cache.iter().enumerate().min_by_key(|(_, e)| e.last_use) {
            cache.remove(idx);
        } else {
            break;
        }
    }
}

fn load_elf_segments_from_disk(
    name: &str,
    loc: &goes::replay::AppBinaryLocator,
    verify_crc: bool,
    want_cache: bool,
) -> Result<(u64, Option<u32>, u32, Option<Vec<u8>>, Vec<LoadedSeg>), AppError> {
    let file_len = (loc.payload_len as usize).saturating_sub(48);
    if file_len < 0x40 {
        return Err(AppError::InvalidBinary);
    }
    let bin_base = loc.record_off + goes_records::HEADER_SIZE as u64 + 48;

    // Read ELF header first.
    let mut hdr64 = [0u8; 0x40];
    crate::virtio::blk::read_at_res(bin_base, &mut hdr64).map_err(|_| AppError::GoesUnavailable)?;

    // Read enough bytes to include the program header table.
    let phoff = u64::from_le_bytes(hdr64[0x20..0x28].try_into().unwrap_or([0; 8])) as usize;
    let phentsize = u16::from_le_bytes(hdr64[0x36..0x38].try_into().unwrap_or([0; 2])) as usize;
    let phnum = u16::from_le_bytes(hdr64[0x38..0x3a].try_into().unwrap_or([0; 2])) as usize;
    let ph_table_end = phoff
        .saturating_add(phentsize.saturating_mul(phnum))
        .max(0x40);
    if ph_table_end > file_len || ph_table_end == 0 {
        return Err(AppError::InvalidBinary);
    }
    // Cap the header+phdr buffer to avoid pathological allocations.
    if ph_table_end > (64 * 1024) {
        return Err(AppError::InvalidBinary);
    }

    let mut head = Vec::new();
    head.resize(ph_table_end, 0u8);
    crate::virtio::blk::read_at_res(bin_base, &mut head).map_err(|_| AppError::GoesUnavailable)?;
    let (info, phdrs) = elf::parse_elf64_le(&head).map_err(|_| AppError::InvalidBinary)?;

    let mut crc = if verify_crc {
        let mut c = goes::crc32::init();
        c = goes::crc32::update(c, &head);
        Some(c)
    } else {
        None
    };

    // Precompute PT_LOAD segments for optional caching.
    #[derive(Clone, Copy)]
    struct Seg {
        vaddr: u64,
        filesz: u32,
        memsz: u32,
        flags: u32,
    }
    let mut segs: Vec<Seg> = Vec::new();
    let mut total_filesz: usize = 0;
    if want_cache {
        for ph in phdrs.iter() {
            if ph.p_type != 1 || ph.memsz == 0 {
                continue;
            }
            let off = ph.offset as usize;
            let filesz = ph.filesz as usize;
            let memsz = ph.memsz as usize;
            if off.checked_add(filesz).ok_or(AppError::InvalidBinary)? > file_len {
                return Err(AppError::InvalidBinary);
            }
            total_filesz = total_filesz.saturating_add(filesz);
            segs.push(Seg {
                vaddr: ph.vaddr,
                filesz: ph.filesz as u32,
                memsz: ph.memsz as u32,
                flags: ph.flags,
            });
        }
    }

    // If caller wants caching (handled by caller based on shipped/verified policy),
    // build a compact segment image while we stream-load.
    let mut cache_img: Option<Vec<u8>> = None;
    if want_cache && !segs.is_empty() {
        // Header: magic[4], ver(u32), entry(u64), seg_count(u32), entry_size(u32)
        let header_len = 24usize;
        let entry_size = APP_IMAGE_SEG_ENTRY_V2_SIZE;
        let table_len = segs.len() * entry_size; // v2: + flags + reserved
        let mut buf = Vec::new();
        buf.resize(header_len + table_len + total_filesz, 0u8);
        buf[0..4].copy_from_slice(&APP_IMAGE_MAGIC);
        buf[4..8].copy_from_slice(&APP_IMAGE_VERSION_CURRENT.to_le_bytes());
        buf[8..16].copy_from_slice(&info.entry.to_le_bytes());
        buf[16..20].copy_from_slice(&(segs.len() as u32).to_le_bytes());
        buf[20..24].copy_from_slice(&(entry_size as u32).to_le_bytes());
        let mut t = header_len;
        for seg in segs.iter() {
            buf[t..t + 8].copy_from_slice(&seg.vaddr.to_le_bytes());
            buf[t + 8..t + 12].copy_from_slice(&seg.filesz.to_le_bytes());
            buf[t + 12..t + 16].copy_from_slice(&seg.memsz.to_le_bytes());
            buf[t + 16..t + 20].copy_from_slice(&seg.flags.to_le_bytes());
            buf[t + 20..t + 24].copy_from_slice(&0u32.to_le_bytes());
            t += entry_size;
        }
        cache_img = Some(buf);
    }

    let cache_data_base = 24usize + segs.len() * APP_IMAGE_SEG_ENTRY_V2_SIZE;
    let mut cache_write_off = 0usize;

    let mut segs_out: Vec<LoadedSeg> = Vec::new();

    // PT_LOAD = 1
    for ph in phdrs.iter() {
        if ph.p_type != 1 {
            continue;
        }
        if ph.memsz == 0 {
            continue;
        }
        segs_out.push(LoadedSeg {
            vaddr: ph.vaddr,
            filesz: ph.filesz,
            memsz: ph.memsz,
            flags: ph.flags,
        });
        let vaddr = ph.vaddr;
        let end = vaddr.checked_add(ph.memsz).ok_or(AppError::InvalidBinary)?;
        let allowed_end = APP_LOAD_BASE
            .checked_add(APP_LOAD_LIMIT)
            .ok_or(AppError::InvalidBinary)?;
        if vaddr < APP_LOAD_BASE || end > allowed_end {
            serial::log_line_args(format_args!(
                "app: segment vaddr out of range: name={} vaddr=0x{:x} end=0x{:x} allowed=[0x{:x},0x{:x})",
                name, vaddr, end, APP_LOAD_BASE, allowed_end
            ));
            return Err(AppError::InvalidBinary);
        }
        let off = ph.offset as usize;
        let filesz = ph.filesz as usize;
        let memsz = ph.memsz as usize;
        if off.checked_add(filesz).ok_or(AppError::InvalidBinary)? > file_len {
            return Err(AppError::InvalidBinary);
        }

        // Only clear BSS region; file bytes will overwrite the rest.
        unsafe {
            let dst = core::slice::from_raw_parts_mut(vaddr as *mut u8, memsz);
            if filesz < memsz {
                dst[filesz..].fill(0);
            } else if filesz == 0 {
                dst[..].fill(0);
            }
        }

        // Read file bytes directly into destination memory in large chunks.
        // Larger I/O reduces virtio-blk requests and host overhead.
        // Keep this aligned with the host-side bulk buffer (256KiB).
        const CHUNK: usize = 256 * 1024;
        let mut done = 0usize;
        while done < filesz {
            let take = core::cmp::min(CHUNK, filesz - done);
            unsafe {
                let dst = core::slice::from_raw_parts_mut((vaddr as usize + done) as *mut u8, take);
                crate::virtio::blk::read_at_res(bin_base + off as u64 + done as u64, dst)
                    .map_err(|_| AppError::GoesUnavailable)?;
                if let Some(c) = crc.as_mut() {
                    *c = goes::crc32::update(*c, dst);
                }
                if let Some(img) = cache_img.as_mut() {
                    let start = cache_data_base + cache_write_off + done;
                    let end = start + take;
                    if end <= img.len() {
                        img[start..end].copy_from_slice(dst);
                    }
                }
            }
            done += take;
        }
        if cache_img.is_some() {
            cache_write_off += filesz;
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "dsb ish",
            "ic iallu",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }

    let exec_crc32 = crc.map(goes::crc32::finalize);
    Ok((info.entry, exec_crc32, file_len as u32, cache_img, segs_out))
}

fn load_app_image_from_cached_bytes(
    name: &str,
    bytes: &[u8],
) -> Result<(u64, u32, Vec<LoadedSeg>), AppError> {
    if bytes.len() < 24 {
        return Err(AppError::InvalidBinary);
    }
    if bytes[0..4] != APP_IMAGE_MAGIC {
        serial::log_line_args(format_args!("app: cache magic mismatch for {}", name));
        return Err(AppError::InvalidBinary);
    }
    let ver = u32::from_le_bytes(bytes[4..8].try_into().unwrap_or([0; 4]));
    if ver != APP_IMAGE_VERSION_V1 && ver != APP_IMAGE_VERSION_V2 {
        serial::log_line_args(format_args!(
            "app: cache unsupported version {} for {}",
            ver, name
        ));
        return Err(AppError::InvalidBinary);
    }
    let entry = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
    let seg_count = u32::from_le_bytes(bytes[16..20].try_into().unwrap_or([0; 4])) as usize;
    let entry_size_hdr = u32::from_le_bytes(bytes[20..24].try_into().unwrap_or([0; 4])) as usize;
    let header_len = 24usize;
    let entry_size = if entry_size_hdr != 0 {
        entry_size_hdr
    } else if ver == APP_IMAGE_VERSION_V1 {
        APP_IMAGE_SEG_ENTRY_V1_SIZE
    } else {
        APP_IMAGE_SEG_ENTRY_V2_SIZE
    };
    if entry_size != APP_IMAGE_SEG_ENTRY_V1_SIZE && entry_size != APP_IMAGE_SEG_ENTRY_V2_SIZE {
        serial::log_line_args(format_args!(
            "app: cache invalid entry_size={} ver={} for {}",
            entry_size, ver, name
        ));
        return Err(AppError::InvalidBinary);
    }
    let table_len = seg_count.saturating_mul(entry_size);
    let data_base = header_len.saturating_add(table_len);
    if seg_count == 0 || data_base > bytes.len() {
        return Err(AppError::InvalidBinary);
    }
    let mut segs_out: Vec<LoadedSeg> = Vec::new();
    let mut data_off = data_base;
    for i in 0..seg_count {
        let t = header_len + i * entry_size;
        let vaddr = u64::from_le_bytes(bytes[t..t + 8].try_into().unwrap_or([0; 8]));
        let filesz = u32::from_le_bytes(bytes[t + 8..t + 12].try_into().unwrap_or([0; 4])) as usize;
        let memsz = u32::from_le_bytes(bytes[t + 12..t + 16].try_into().unwrap_or([0; 4])) as usize;
        let flags = if entry_size >= 20 {
            u32::from_le_bytes(bytes[t + 16..t + 20].try_into().unwrap_or([0; 4]))
        } else {
            0
        };
        if memsz == 0 {
            continue;
        }
        segs_out.push(LoadedSeg {
            vaddr,
            filesz: filesz as u64,
            memsz: memsz as u64,
            flags,
        });
        let end = vaddr
            .checked_add(memsz as u64)
            .ok_or(AppError::InvalidBinary)?;
        let allowed_end = APP_LOAD_BASE
            .checked_add(APP_LOAD_LIMIT)
            .ok_or(AppError::InvalidBinary)?;
        if vaddr < APP_LOAD_BASE || end > allowed_end {
            serial::log_line_args(format_args!(
                "app: segment vaddr out of range (cache): name={} vaddr=0x{:x} end=0x{:x} allowed=[0x{:x},0x{:x})",
                name, vaddr, end, APP_LOAD_BASE, allowed_end
            ));
            return Err(AppError::InvalidBinary);
        }
        if data_off
            .checked_add(filesz)
            .ok_or(AppError::InvalidBinary)?
            > bytes.len()
        {
            return Err(AppError::InvalidBinary);
        }
        unsafe {
            let dst = core::slice::from_raw_parts_mut(vaddr as *mut u8, memsz);
            if filesz < memsz {
                dst[filesz..].fill(0);
            } else if filesz == 0 {
                dst[..].fill(0);
            }
            if filesz != 0 {
                dst[..filesz].copy_from_slice(&bytes[data_off..data_off + filesz]);
            }
        }
        data_off += filesz;
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "dsb ish",
            "ic iallu",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }

    Ok((entry, bytes.len().min(u32::MAX as usize) as u32, segs_out))
}

pub fn run(name: &str, user: &str) -> Result<u32, AppError> {
    let Some(idx) = goes::replay::snapshot() else {
        return Err(AppError::GoesUnavailable);
    };
    let app = if let Some(app) = idx.apps.get(name) {
        app
    } else {
        // v1: accept case-insensitive lookup for convenience.
        let Some((_, app)) = idx.apps.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)) else {
            return Err(AppError::NotFound);
        };
        app
    };
    if app.removed {
        return Err(AppError::Removed);
    }
    if app.workspace.is_empty() {
        serial::log_line_args(format_args!("app: no registry mapping for {}", name));
        return Err(AppError::NotFound);
    }
    // Must "enter App:<name> scope" conceptually: validate that the current domain
    // is allowed to read this App workspace (capability+policy).
    if !crate::sandbox::can_goes_read_quiet(&app.workspace) {
        serial::log_line_args(format_args!(
            "app: denied reading app workspace {}",
            app.workspace
        ));
        return Err(AppError::PermissionDenied);
    }
    // Load package manifest/config from App workspace (no path semantics).
    serial::log_line_args(format_args!(
        "app: load package from workspace {}",
        app.workspace
    ));
    match goes::replay::app_config_bytes_for_user(&idx, &app.name, user) {
        Some(bytes) => {
            serial::log_line_args(format_args!(
                "app: config loaded (name={}, bytes={})",
                app.name,
                bytes.len()
            ));
            if let Ok(s) = core::str::from_utf8(bytes) {
                let preview = s.trim();
                if !preview.is_empty() {
                    // Keep serial logs compact.
                    let mut one_line = preview;
                    if let Some(p) = preview.find('\n') {
                        one_line = &preview[..p];
                    }
                    serial::log_line_args(format_args!("app: config preview: {}", one_line));
                }
            }
        }
        None => serial::log_line_args(format_args!(
            "app: config missing (workspace={})",
            app.workspace
        )),
    }
    let persistent = (app.caps_mask & CAP_GOES_WRITE_USER) != 0;
    if persistent {
        let _app_ws = ensure_app_workspace(user, name, &idx)?;
    }
    {
        let running = RUNNING.lock();
        if running.contains_key(name) {
            return Err(AppError::AlreadyRunning);
        }
    }

    // v2: create an AppDomain stub (single-task model, no real execution yet).
    let domain_id = crate::sandbox::spawn_app_domain(name, user, &app.workspace, app.caps_mask)
        .map_err(|_| AppError::PermissionDenied)? as u32;
    let _ = crate::sandbox::start_domain(domain_id as crate::sandbox::DomainId);
    RUNNING.lock().insert(name.to_string(), domain_id);

    // Persistable user-context trace is only written when the app requests user GOES write.
    if persistent {
        let from = crate::shell::user_scope_id(user);
        let to = app.seq;
        let edge_type = 0x0001u32; // uses
        let mut edge_payload = [0u8; 24];
        goes::replay::encode_edge_payload_v1(from, to, edge_type, &mut edge_payload);
        let mut user_ws = String::from("User:");
        user_ws.push_str(user);
        let _ =
            goes::writer::append_record(&user_ws, goes::records::RECORD_ADD_EDGE_V1, &edge_payload);
    }

    // v2: execute the app in AppDomain (still single-task/synchronous).
    if app.entry.starts_with("elf:") {
        let Some(loc) = goes::replay::select_app_binary_locator(&idx, &app.name) else {
            serial::log_line_args(format_args!("app: missing binary locator for {}", name));
            return Err(AppError::InvalidBinary);
        };
        // Verify/caching (best-effort):
        // Only compute CRC32 on first run or when the binary record seq changes.
        let cached = idx
            .app_verify_cache
            .get(&(user.to_string(), app.name.clone()))
            .map(|e| e.binary_seq == loc.seq && e.binary_len == locator_binary_len(&loc))
            .unwrap_or(false);
        let bin_len_hint = locator_binary_len(&loc);
        // C3: system-shipped apps can skip runtime CRC as long as the installer marker
        // matches the current binary record (seq + len). External apps still validate.
        let shipped_ok =
            goes::replay::is_system_shipped_app(&idx, &app.name, loc.arch, loc.seq, bin_len_hint);
        let need_crc = !shipped_ok && !cached;

        // E: In-boot cache: if we have already loaded this exact binary (seq+arch), reuse bytes to
        // avoid disk I/O on subsequent runs. External apps only get cached after first successful verify.
        let can_cache = shipped_ok || cached;
        let mut used_cache = false;
        let (entry, exec_crc, bin_len, segs_loaded) =
            if let Some(bytes) = cache_get(&app.name, loc.arch, loc.seq) {
                used_cache = true;
                if need_crc {
                    // Should be unreachable: we only cache after shipped_ok or verified run.
                    return Err(AppError::InvalidBinary);
                }
                let (entry, blen, segs) = load_app_image_from_cached_bytes(&app.name, &bytes)?;
                (entry, None, blen, segs)
            } else {
                // Stream-load segments directly from disk (no full ELF read).
                let (entry, exec_crc, bin_len, cache_img, segs) =
                    if loc.record_type == goes::records::RECORD_APP_IMAGE_V1 {
                        load_app_image_from_disk(&app.name, &loc, can_cache)?
                    } else {
                        load_elf_segments_from_disk(&app.name, &loc, need_crc, can_cache)?
                    };
                if can_cache {
                    if let Some(img) = cache_img {
                        cache_put(&app.name, loc.arch, loc.seq, img);
                    }
                }
                (entry, exec_crc, bin_len, segs)
            };
        if used_cache {
            serial::log_line_args(format_args!(
                "app: binary cache hit {} arch={} seq={}",
                name, loc.arch, loc.seq
            ));
        }

        serial::log_line_args(format_args!(
            "app: layout {} segments (va==pa assumption for v2)",
            segs_loaded.len()
        ));
        for (i, s) in segs_loaded.iter().enumerate() {
            if s.flags == 0 {
                serial::log_line_args(format_args!(
                    "app:  seg#{:02} va=0x{:x} pa=0x{:x} file=0x{:x} mem=0x{:x} flags=unknown",
                    i, s.vaddr, s.vaddr, s.filesz, s.memsz
                ));
            } else {
                let r = (s.flags & PF_R) != 0;
                let w = (s.flags & PF_W) != 0;
                let x = (s.flags & PF_X) != 0;
                serial::log_line_args(format_args!(
                    "app:  seg#{:02} va=0x{:x} pa=0x{:x} file=0x{:x} mem=0x{:x} flags={}{}{} (0x{:x})",
                    i,
                    s.vaddr,
                    s.vaddr,
                    s.filesz,
                    s.memsz,
                    if r { 'R' } else { '-' },
                    if w { 'W' } else { '-' },
                    if x { 'X' } else { '-' },
                    s.flags
                ));
            }
        }

        if let Some(crc) = exec_crc {
            let mut payload = [0u8; 88];
            payload[0..4].copy_from_slice(&1u32.to_le_bytes());
            payload[4..8].copy_from_slice(&0u32.to_le_bytes());
            payload[8..40].copy_from_slice(&goes::records::encode_name32(user));
            payload[40..72].copy_from_slice(&goes::records::encode_name32(&app.name));
            payload[72..80].copy_from_slice(&loc.seq.to_le_bytes());
            payload[80..84].copy_from_slice(&crc.to_le_bytes());
            payload[84..88].copy_from_slice(&bin_len.to_le_bytes());
            let mut user_ws = String::from("User:");
            user_ws.push_str(user);
            let _ = goes::writer::append_record(
                &user_ws,
                goes::records::RECORD_APP_VERIFY_CACHE_V1,
                &payload,
            );
        }

        // Prepare stack.
        struct AlignedStack {
            ptr: NonNull<u8>,
            len: usize,
        }
        impl AlignedStack {
            fn new(len: usize) -> Result<Self, AppError> {
                let layout =
                    Layout::from_size_align(len, 4096).map_err(|_| AppError::MmuBuildFailed)?;
                let ptr = unsafe { alloc_zeroed(layout) };
                let ptr = NonNull::new(ptr).ok_or(AppError::MmuBuildFailed)?;
                Ok(Self { ptr, len })
            }
            fn as_ptr(&self) -> *const u8 {
                self.ptr.as_ptr()
            }
            fn as_mut_ptr(&mut self) -> *mut u8 {
                self.ptr.as_ptr()
            }
        }
        impl Drop for AlignedStack {
            fn drop(&mut self) {
                if self.len == 0 {
                    return;
                }
                if let Ok(layout) = Layout::from_size_align(self.len, 4096) {
                    unsafe { dealloc(self.ptr.as_ptr(), layout) };
                }
            }
        }

        let mut stack = AlignedStack::new(APP_STACK_SIZE)?;
        let stack_top = unsafe {
            let top = stack.as_mut_ptr().add(stack.len);
            // 16-byte align.
            (top as usize & !0xFu64 as usize) as *mut u8
        };

        // v2: software-enforced region set (shared address space).
        // App pointers are constrained to:
        // - the actual loaded segment ranges (not the whole APP_LOAD window)
        // - the per-run stack buffer
        //
        // This does NOT provide hard isolation (no MMU), but it prevents accidental
        // kernel pointer usage through AppApi and stabilizes future MMU-backed mapping.
        let mut regions: Vec<crate::sandbox::MemRegion> = Vec::new();
        for s in segs_loaded.iter().copied() {
            let start = s.vaddr as usize;
            let end = (s.vaddr.saturating_add(s.memsz)) as usize;
            if start >= end {
                continue;
            }
            let writable = if s.flags == 0 {
                true
            } else {
                (s.flags & PF_W) != 0
            };
            let rights = if writable {
                crate::sandbox::MEM_RIGHT_READ | crate::sandbox::MEM_RIGHT_WRITE
            } else {
                crate::sandbox::MEM_RIGHT_READ
            };
            regions.push(crate::sandbox::MemRegion { start, end, rights });
        }
        regions.push(crate::sandbox::MemRegion {
            start: stack.as_ptr() as usize,
            end: stack.as_ptr() as usize + stack.len,
            rights: crate::sandbox::MEM_RIGHT_READ | crate::sandbox::MEM_RIGHT_WRITE,
        });
        regions.sort_by_key(|r| r.start);
        // Merge overlapping/adjacent ranges when rights match, to keep checks fast.
        let mut merged: Vec<crate::sandbox::MemRegion> = Vec::new();
        for r in regions.into_iter() {
            if let Some(last) = merged.last_mut() {
                if r.start <= last.end && r.rights == last.rights {
                    last.end = last.end.max(r.end);
                    continue;
                }
            }
            merged.push(r);
        }
        let _ = crate::sandbox::set_domain_regions(domain_id as crate::sandbox::DomainId, merged);

        // v2/M2: build an AppDomain page-table root for MMU-backed AddressSpace switching.
        //
        // Note: oneOS runs in a “pure kernel mode + Sandbox Domain” model. Apps still execute
        // at EL1/ring0, but we use per-domain page tables to constrain address visibility and
        // to reliably trap illegal memory access into a Domain fault (instead of panicking).
        //
        // For now we include the minimal kernel/driver mappings required for:
        // - the entry/abort trampoline (`call_app_entry`)
        // - console I/O backends (framebuffer + virtio-keyboard MMIO)
        // - GOES/virtio-blk (read config for app package/config)
        //
        // v3+: we will split these shared mappings into a dedicated kernel region and shrink
        // the exposed surface further.
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if crate::mmu::switch::app_address_space_switch_enabled()
            && crate::mmu::addrspace::current_mmu_enabled()
        {
            if let Some(asid) =
                crate::sandbox::domain_address_space(domain_id as crate::sandbox::DomainId)
            {
                let mut layout = crate::mmu::addrspace::AppSpaceLayout::new();

                // -------------------------------------------------------------------------
                // Shared kernel mappings (identity-mapped) required while the AppDomain runs.
                //
                // Important: every App address space must include the kernel text/trampoline,
                // otherwise the handoff (`call_app_entry`) and abort path cannot execute once
                // we switch TTBR0/CR3.
                // Map kernel sections with W^X:
                // - .text: RX
                // - .rodata: RO (NX)
                // - .data+.bss: RW (NX)
                unsafe {
                    let text_start = &raw const __text_start as *const u8 as u64;
                    let text_end = &raw const __text_end as *const u8 as u64;
                    let ro_start = &raw const __rodata_start as *const u8 as u64;
                    let ro_end = &raw const __rodata_end as *const u8 as u64;
                    let data_start = &raw const __data_start as *const u8 as u64;
                    let data_end = &raw const __data_end as *const u8 as u64;
                    let bss_start = &raw const __bss_start as *const u8 as u64;
                    let bss_end = &raw const __bss_end as *const u8 as u64;

                    if text_end > text_start {
                        let s = align_down_4k(text_start);
                        let e = align_up_4k(text_end);
                        push_map_wx_checked(
                            &mut layout,
                            crate::mmu::addrspace::AppMap {
                                va: s,
                                pa: s,
                                len: e - s,
                                exec: true,
                                writable: false,
                                device: false,
                            },
                        );
                    }
                    if ro_end > ro_start {
                        let s = align_down_4k(ro_start);
                        let e = align_up_4k(ro_end);
                        push_map_wx_checked(
                            &mut layout,
                            crate::mmu::addrspace::AppMap {
                                va: s,
                                pa: s,
                                len: e - s,
                                exec: false,
                                writable: false,
                                device: false,
                            },
                        );
                    }
                    let rw_start = core::cmp::min(data_start, bss_start);
                    let rw_end = core::cmp::max(data_end, bss_end);
                    if rw_end > rw_start {
                        let s = align_down_4k(rw_start);
                        let e = align_up_4k(rw_end);
                        push_map_wx_checked(
                            &mut layout,
                            crate::mmu::addrspace::AppMap {
                                va: s,
                                pa: s,
                                len: e - s,
                                exec: false,
                                writable: true,
                                device: false,
                            },
                        );
                    }
                }

                // Kernel stack window around current SP (RW, NX).
                let sp_now: u64;
                unsafe {
                    #[cfg(target_arch = "aarch64")]
                    core::arch::asm!("mov {0}, sp", out(reg) sp_now, options(nomem, nostack, preserves_flags));
                    #[cfg(target_arch = "x86_64")]
                    core::arch::asm!("mov {0}, rsp", out(reg) sp_now, options(nomem, nostack, preserves_flags));
                }
                let stack_start = sp_now.saturating_sub(0x40000) & !0xfff;
                let stack_end = (sp_now.saturating_add(0x20000) + 0xfff) & !0xfff;
                if stack_end > stack_start {
                    push_map_wx_checked(
                        &mut layout,
                        crate::mmu::addrspace::AppMap {
                            va: stack_start,
                            pa: stack_start,
                            len: stack_end - stack_start,
                            exec: false,
                            writable: true,
                            device: false,
                        },
                    );
                }

                // x86_64: firmware-provided GDT must remain mapped after CR3 switch.
                //
                // We intentionally do not install our own GDT/TSS yet (v3+). UEFI/QEMU often
                // runs with CS=0x38 and a GDT allocated in firmware memory. After switching to
                // an AppDomain CR3, interrupts and far control transfers may still need to
                // fetch descriptors from the current GDT. If the GDT page is not mapped, the
                // CPU will fault and can triple-fault reboot without panic output.
                #[cfg(target_arch = "x86_64")]
                {
                    #[repr(C, packed)]
                    struct DtReg {
                        limit: u16,
                        base: u64,
                    }
                    let mut gdtr = DtReg { limit: 0, base: 0 };
                    unsafe {
                        core::arch::asm!(
                            "sgdt [{}]",
                            in(reg) (&mut gdtr as *mut DtReg),
                            options(nostack, preserves_flags)
                        );
                    }
                    let gdt_base = unsafe { core::ptr::addr_of!(gdtr.base).read_unaligned() };
                    let gdt_limit = unsafe { core::ptr::addr_of!(gdtr.limit).read_unaligned() };
                    let gdt_len = (gdt_limit as u64).saturating_add(1);
                    let gdt_start = align_down_4k(gdt_base);
                    let gdt_end = align_up_4k(gdt_base.saturating_add(gdt_len));
                    if gdt_end > gdt_start {
                        serial::log_line_args(format_args!(
                            "mmu-appspace: map current GDT base=0x{:x} limit=0x{:x} -> [0x{:x}..0x{:x})",
                            gdt_base, gdt_limit, gdt_start, gdt_end
                        ));
                        push_map_wx_checked(
                            &mut layout,
                            crate::mmu::addrspace::AppMap {
                                va: gdt_start,
                                pa: gdt_start,
                                len: gdt_end - gdt_start,
                                exec: false,
                                writable: false,
                                device: false,
                            },
                        );
                    } else {
                        serial::log_line_args(format_args!(
                            "mmu-appspace: WARN: sgdt returned empty/invalid (base=0x{:x} limit=0x{:x})",
                            gdt_base, gdt_limit
                        ));
                    }
                }

                // Kernel heap (RW, NX).
                let (heap_start, heap_end, _heap_used) = crate::heap::stats();
                if heap_end > heap_start {
                    push_map_wx_checked(
                        &mut layout,
                        crate::mmu::addrspace::AppMap {
                            va: heap_start as u64,
                            pa: heap_start as u64,
                            len: (heap_end - heap_start) as u64,
                            exec: false,
                            writable: true,
                            device: false,
                        },
                    );
                }

                // Framebuffer mapping policy (Stage 1):
                // - Default: do NOT map framebuffer into AppDomain address space.
                // - Only map when the app explicitly requests GPU capability (for now).
                if (app.caps_mask & CAP_GPU) != 0 {
                    if let Some(info) = crate::boot_info::get().and_then(|b| b.framebuffer()) {
                        if info.base != 0 && info.size != 0 {
                            push_map_wx_checked(
                                &mut layout,
                                crate::mmu::addrspace::AppMap {
                                    va: info.base,
                                    pa: info.base,
                                    len: info.size,
                                    exec: false,
                                    writable: true,
                                    device: false,
                                },
                            );
                        }
                    }
                }

                #[cfg(target_arch = "aarch64")]
                {
                    // QEMU virt GIC (needed for timer IRQ while app timeout is armed).
                    push_map_wx_checked(
                        &mut layout,
                        crate::mmu::addrspace::AppMap {
                            va: 0x0800_0000,
                            pa: 0x0800_0000,
                            len: 0x20_000,
                            exec: false,
                            writable: true,
                            device: true,
                        },
                    );

                    // PL011 UART (serial log on virt).
                    push_map_wx_checked(
                        &mut layout,
                        crate::mmu::addrspace::AppMap {
                            va: 0x0900_0000,
                            pa: 0x0900_0000,
                            len: 0x1000,
                            exec: false,
                            writable: true,
                            device: true,
                        },
                    );

                    // PCIe BAR fallback window (device).
                    push_map_wx_checked(
                        &mut layout,
                        crate::mmu::addrspace::AppMap {
                            va: 0x1000_0000,
                            pa: 0x1000_0000,
                            len: 0x0100_0000,
                            exec: false,
                            writable: true,
                            device: true,
                        },
                    );
                }

                if let Some((base, len)) = crate::virtio::keyboard::mmu_required_mmio_window() {
                    push_map_wx_checked(
                        &mut layout,
                        crate::mmu::addrspace::AppMap {
                            va: base,
                            pa: base,
                            len,
                            exec: false,
                            writable: true,
                            device: true,
                        },
                    );
                }
                // Stage 1: do not expose GOES block device MMIO to apps by default.
                // Future: goesd/driver services will own these mappings under capability+policy.

                // PCI ECAM (device) – aarch64 virt only (x86_64 uses legacy PCI config I/O).
                #[cfg(target_arch = "aarch64")]
                push_map_wx_checked(
                    &mut layout,
                    crate::mmu::addrspace::AppMap {
                        va: 0x4010_0000_00,
                        pa: 0x4010_0000_00,
                        len: 0x10_0000,
                        exec: false,
                        writable: true,
                        device: true,
                    },
                );

                // Minimal shared read-only page (v2): stable VA in every AppDomain.
                // This page must never contain writable pointers.
                let shared_va = crate::mmu::addrspace::app_shared_ro_va();
                let shared_pa = crate::mmu::addrspace::app_shared_ro_pa();
                push_map_wx_checked(
                    &mut layout,
                    crate::mmu::addrspace::AppMap {
                        va: shared_va,
                        pa: shared_pa,
                        len: 0x1000,
                        exec: false,
                        writable: false,
                        device: false,
                    },
                );

                // -------------------------------------------------------------------------
                // App segments + app stack.
                //
                // Use per-segment flags when available (ELF/OAPP v2).
                // For legacy OAPP v1 (flags=0), use a conservative heuristic:
                // - seg#0: RX (code)
                // - seg#1+: RW NX (data)
                //
                // Important: ELF PT_LOAD segments are not guaranteed to be 4K aligned. If we
                // naively align each segment to pages and map them in order, later segments can
                // overwrite permissions of earlier ones on the same page (e.g. rodata starting
                // at +0x30 into the first text page). That leads to NX being set on the entry
                // page and causes an immediate fault/triple-fault after CR3 switch on x86_64.
                //
                // Fix: build a minimal set of non-overlapping, page-aligned intervals by
                // splitting at segment page boundaries and OR-ing permissions (exec/write) for
                // segments that cover each interval. If an interval becomes RWX, refuse it.
                {
                    #[derive(Clone, Copy)]
                    struct SegPerm {
                        start: u64,
                        end: u64,
                        exec: bool,
                        writable: bool,
                    }

                    let mut seg_perms: [Option<SegPerm>; 16] = [None; 16];
                    let mut seg_n = 0usize;
                    let mut bounds: [u64; 32] = [0; 32];
                    let mut bound_n = 0usize;

                    for (idx, s) in segs_loaded.iter().copied().enumerate() {
                        let (mut exec, mut writable) = if s.flags != 0 {
                            ((s.flags & PF_X) != 0, (s.flags & PF_W) != 0)
                        } else {
                            (idx == 0, idx != 0)
                        };
                        if exec && writable {
                            serial::log_line_args(format_args!(
                                "mmu-appspace: segment has W|X (forcing NX): seg#{} va=0x{:x} flags=0x{:x}",
                                idx, s.vaddr, s.flags
                            ));
                            exec = false;
                        }

                        let start = align_down_4k(s.vaddr);
                        let end = align_up_4k(s.vaddr.saturating_add(s.memsz));
                        if start == end {
                            continue;
                        }
                        if seg_n < seg_perms.len() {
                            seg_perms[seg_n] = Some(SegPerm {
                                start,
                                end,
                                exec,
                                writable,
                            });
                            seg_n += 1;
                        } else {
                            serial::log_line("mmu-appspace: too many segments; truncating perms");
                            break;
                        }
                        if bound_n + 2 <= bounds.len() {
                            bounds[bound_n] = start;
                            bounds[bound_n + 1] = end;
                            bound_n += 2;
                        }
                    }

                    // Sort bounds (small fixed array) and unique.
                    let mut i = 0usize;
                    while i < bound_n {
                        let mut j = i + 1;
                        while j < bound_n {
                            if bounds[j] < bounds[i] {
                                bounds.swap(i, j);
                            }
                            j += 1;
                        }
                        i += 1;
                    }
                    let mut uniq_n = 0usize;
                    for k in 0..bound_n {
                        if k == 0 || bounds[k] != bounds[k - 1] {
                            bounds[uniq_n] = bounds[k];
                            uniq_n += 1;
                        }
                    }

                    let mut k = 0usize;
                    while k + 1 < uniq_n {
                        let a = bounds[k];
                        let b = bounds[k + 1];
                        if a >= b {
                            k += 1;
                            continue;
                        }
                        let mut exec = false;
                        let mut writable = false;
                        for s in seg_perms.iter().copied().flatten() {
                            if a >= s.start && a < s.end {
                                exec |= s.exec;
                                writable |= s.writable;
                            }
                        }
                        if exec && writable {
                            serial::log_line_args(format_args!(
                                "mmu-appspace: reject RWX interval va=0x{:x}..0x{:x}",
                                a, b
                            ));
                            // Keep running without this map; the page-table selfcheck will fail
                            // and the app run will be rejected when switching is enabled.
                        } else {
                            push_map_wx_checked(
                                &mut layout,
                                crate::mmu::addrspace::AppMap {
                                    va: a,
                                    pa: a,
                                    len: b - a,
                                    exec,
                                    writable,
                                    device: false,
                                },
                            );
                        }
                        k += 1;
                    }
                }
                push_map_wx_checked(
                    &mut layout,
                    crate::mmu::addrspace::AppMap {
                        va: stack.as_ptr() as u64,
                        pa: stack.as_ptr() as u64,
                        len: stack.len as u64,
                        exec: false,
                        writable: true,
                        device: false,
                    },
                );
                serial::log_line_args(format_args!(
                    "mmu-appspace: build app space dom={} asid={} maps={}",
                    domain_id,
                    asid,
                    layout.maps.len()
                ));
                for (i, m) in layout.maps.iter().enumerate() {
                    serial::log_line_args(format_args!(
                        "mmu-appspace:  map#{} va=0x{:x} pa=0x{:x} len=0x{:x} exec={} w={} dev={}",
                        i, m.va, m.pa, m.len, m.exec, m.writable, m.device
                    ));
                }
                let mut built_root: Option<u64> = None;
                match crate::mmu::addrspace::build_app_space_with_stats_and_pages(&layout) {
                    Ok((root, tables, pages, pt_pages)) => {
                        crate::mmu::addrspace::set_pt_root_with_pages(asid, root, pt_pages);
                        let ok = crate::mmu::addrspace::selfcheck_app_space(root, &layout);
                        serial::log_line_args(format_args!(
                            "mmu-appspace: built root=0x{:x} tables={} pages={} selfcheck_ok={}",
                            root, tables, pages, ok
                        ));
                        built_root = Some(root);
                    }
                    Err(e) => {
                        serial::log_line_args(format_args!("mmu-appspace: build failed: {:?}", e));
                    }
                }

                // Stage 6/M4: if address-space switching is enabled, treat page-table build
                // failures as a hard error for this app run. This avoids silently executing
                // an AppDomain without isolation (which can lead to confusing faults).
                if crate::mmu::switch::app_address_space_switch_enabled()
                    && crate::mmu::addrspace::current_mmu_enabled()
                    && built_root.is_none()
                {
                    // Cleanup the partially created domain before returning.
                    RUNNING.lock().remove(name);
                    let _ = crate::sandbox::stop_domain(domain_id as crate::sandbox::DomainId);
                    crate::sandbox::kill_domain(domain_id as crate::sandbox::DomainId);
                    return Err(AppError::MmuBuildFailed);
                }
            }
        }

        let prev = crate::sandbox::current_domain();
        let prev_fg = crate::console::mgr::foreground();
        // Create a dedicated console session for this AppDomain and take foreground.
        let app_session = crate::console::mgr::create_session(domain_id as crate::sandbox::DomainId);
        crate::console::mgr::bind_domain_session(domain_id as crate::sandbox::DomainId, app_session);
        crate::console::mgr::set_foreground(app_session);

        crate::sandbox::set_current_domain(domain_id as crate::sandbox::DomainId);
        let api = api_v1_ptr();
        // v2: watchdog to prevent app deadloops from hanging the system.
        crate::timer::arm_app_timeout(domain_id as u32, 5_000);
        serial::log_line_args(format_args!("app: executing {} entry=0x{:x}", name, entry));
        serial::log_line_args(format_args!(
            "app: call_app_entry prep dom={} api=0x{:x} stack_buf=[0x{:x}..0x{:x}) stack_top=0x{:x} top_align={}",
            domain_id,
            api as usize,
            stack.as_ptr() as usize,
            stack.as_ptr() as usize + stack.len,
            stack_top as usize,
            (stack_top as usize) & 0xf
        ));

        // Stage 3 scaffold (default disabled): if this AppDomain has a built page-table root,
        // we can switch TTBR0/CR3 before entering the app and restore on return.
        let mut saved_space: Option<crate::mmu::switch::SavedSpace> = None;
        if crate::mmu::switch::app_address_space_switch_enabled() {
            if let Some(asid) =
                crate::sandbox::domain_address_space(domain_id as crate::sandbox::DomainId)
            {
                if let Some(root) = crate::mmu::addrspace::pt_root(asid) {
                    match crate::mmu::switch::enter_app_space(root) {
                        Ok(s) => saved_space = Some(s),
                        Err(e) => {
                            serial::log_line_args(format_args!(
                                "mmu-switch: enter failed (dom={} asid={} root=0x{:x}): {:?}",
                                domain_id, asid, root, e
                            ));
                            crate::timer::disarm_app_timeout(domain_id as u32);
                            crate::sandbox::set_current_domain(prev);
                            RUNNING.lock().remove(name);
                            let _ =
                                crate::sandbox::stop_domain(domain_id as crate::sandbox::DomainId);
                            crate::sandbox::kill_domain(domain_id as crate::sandbox::DomainId);
                            return Err(AppError::MmuSwitchFailed);
                        }
                    }
                }
            }
        }
        let code = unsafe { call_app_entry(entry, api, stack_top) };
        if let Some(s) = saved_space {
            let _ = crate::mmu::switch::leave_app_space(s);
        }
        serial::log_line_args(format_args!(
            "app: returned from call_app_entry dom={} code={} abort_jmp=0x{:x}",
            domain_id,
            code,
            unsafe { core::ptr::read_volatile(&raw const ONEOS_APP_ABORT_JMP) }
        ));
        crate::timer::disarm_app_timeout(domain_id as u32);
        if code == crate::timer::TIMEOUT_RETURN_CODE {
            if crate::timer::take_timeout_pending_domain() == Some(domain_id as u32) {
                serial::log_line_args(format_args!("app: timeout kill domain={}", domain_id));
                crate::sandbox::fault(crate::sandbox::FaultKind::PolicyViolation, "app timeout");
            }
        }
        if code == crate::timer::APP_FAULT_RETURN_CODE {
            serial::log_line_args(format_args!(
                "app: fault kill domain={} (sync exception/#PF/#GP)",
                domain_id
            ));
            if let Some(f) = crate::timer::take_pending_fault_info() {
                serial::log_line_args(format_args!(
                    "app: pending fault domain={} vector={} rip=0x{:x} addr=0x{:x} err=0x{:x}",
                    f.domain, f.vector, f.rip, f.addr, f.err
                ));
            }
            crate::sandbox::fault(
                crate::sandbox::FaultKind::InvalidMemoryAccess,
                "app hardware fault",
            );
        }
        // IMPORTANT: restore the caller domain *before* printing any status to the console.
        //
        // Rationale:
        // - Console writes are capability-checked against the current domain.
        // - In the single-task model, `app::run()` may execute inside the shell task; if we keep
        //   the AppDomain selected while printing, the sandbox can fault/kill the domain and
        //   indirectly kill the shell task.
        crate::sandbox::set_current_domain(prev);
        // Ensure all app output is rendered before returning foreground to shell.
        crate::console::mgr::flush(crate::console::mgr::last_seq_for_session(app_session));
        crate::console::mgr::set_foreground(prev_fg);
        crate::console::mgr::close_session(app_session);
        let _ = console_write_line_args(format_args!("app: exit code {}", code));
        serial::log_line_args(format_args!("app: exit code {}", code));
    } else if app.entry.starts_with("script:") {
        // oneOS apps are Rust-only; scripts were removed.
        let _ =
            console_write_line("app: script apps are not supported (Rust-only); use entry=elf:v1");
        serial::log_line_args(format_args!(
            "app: refused to execute script entry (name={}, entry={})",
            name, app.entry
        ));
        return Err(AppError::InvalidBinary);
    } else {
        serial::log_line_args(format_args!(
            "app: unsupported entry (name={}, entry={})",
            name, app.entry
        ));
        return Err(AppError::InvalidBinary);
    }

    crate::audit::emit(
        crate::audit::EVENT_APP_RUN,
        "Applications",
        name,
        domain_id as u64,
        app.seq,
    );

    // v2: synchronous execution; cleanup immediately.
    RUNNING.lock().remove(name);
    let _ = crate::sandbox::stop_domain(domain_id as crate::sandbox::DomainId);
    crate::sandbox::kill_domain(domain_id as crate::sandbox::DomainId);
    crate::audit::emit(
        crate::audit::EVENT_APP_STOP,
        "Applications",
        name,
        domain_id as u64,
        0,
    );
    Ok(domain_id)
}

pub fn stop(name: &str) -> Result<(), AppError> {
    let mut running = RUNNING.lock();
    let Some(domain) = running.remove(name) else {
        return Err(AppError::NotRunning);
    };
    let _ = crate::sandbox::stop_domain(domain as crate::sandbox::DomainId);
    crate::sandbox::kill_domain(domain as crate::sandbox::DomainId);
    crate::audit::emit(
        crate::audit::EVENT_APP_STOP,
        "Applications",
        name,
        domain as u64,
        0,
    );
    Ok(())
}

pub fn running_list() -> BTreeMap<String, u32> {
    RUNNING.lock().clone()
}
