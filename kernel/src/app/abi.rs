#![cfg(target_os = "none")]

extern crate alloc;

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use alloc::vec::Vec;

use crate::sandbox;
use crate::timer;

#[repr(C)]
pub struct AppApiV1 {
    pub version: u32,
    pub _reserved: u32,
    pub console_write: extern "C" fn(ptr: *const u8, len: usize) -> isize,
    pub console_read: extern "C" fn(ptr: *mut u8, len: usize) -> isize,
    // v2: watchdog feed to keep interactive apps alive under timeout policy.
    pub watchdog_feed: extern "C" fn() -> isize,
    pub _reserved2: *const c_void,
    // v3: IPC primitives (Stage 3).
    pub ipc_send: extern "C" fn(
        service_ptr: *const u8,
        service_len: usize,
        opcode: u32,
        ptr: *const u8,
        len: usize,
    ) -> isize,
    pub ipc_recv: extern "C" fn(
        hdr: *mut IpcMsgHeader,
        ptr: *mut u8,
        cap: usize,
        blocking: u32,
        timeout_ticks: u64,
    ) -> isize,
}

#[repr(C)]
pub struct IpcMsgHeader {
    pub from_domain: u32,
    pub opcode: u32,
    pub len: u32,
    pub _reserved: u32,
}

const API_V1: AppApiV1 = AppApiV1 {
    version: 3,
    _reserved: 0,
    console_write: console_write_v1,
    console_read: console_read_v1,
    watchdog_feed: watchdog_feed_v1,
    _reserved2: ptr::null(),
    ipc_send: ipc_send_v1,
    ipc_recv: ipc_recv_v1,
};

pub fn api_v1_ptr() -> *const AppApiV1 {
    &API_V1 as *const AppApiV1
}

// Debug-only breadcrumbs to correlate traps with the last App->Kernel ABI call.
// This is intentionally lock-free and best-effort; overwrites are fine.
const LAST_OP_NONE: u32 = 0;
const LAST_OP_CONSOLE_WRITE: u32 = 1;
const LAST_OP_CONSOLE_READ: u32 = 2;
const LAST_OP_WATCHDOG_FEED: u32 = 3;
const LAST_OP_IPC_SEND: u32 = 4;
const LAST_OP_IPC_RECV: u32 = 5;

static LAST_OP: AtomicU32 = AtomicU32::new(LAST_OP_NONE);
static LAST_DOMAIN: AtomicU32 = AtomicU32::new(0);
static LAST_PTR: AtomicU64 = AtomicU64::new(0);
static LAST_LEN: AtomicU64 = AtomicU64::new(0);
static LAST_LR: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub struct DebugLastAbiCall {
    pub op: u32,
    pub domain: u32,
    pub ptr: u64,
    pub len: u64,
    pub lr: u64,
}

#[inline(always)]
fn record_last_call(op: u32, ptr: u64, len: u64) {
    let domain = sandbox::current_domain();
    let mut lr: u64 = 0;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mov {0}, x30", out(reg) lr, options(nomem, nostack, preserves_flags));
    }
    // x86_64: omit LR capture (stack layout depends on prologue); aarch64 is the primary target.
    // Store payload first, then mark op last so readers won't see op!=0 with zeroed fields.
    LAST_DOMAIN.store(domain, Ordering::Relaxed);
    LAST_PTR.store(ptr, Ordering::Relaxed);
    LAST_LEN.store(len, Ordering::Relaxed);
    LAST_LR.store(lr, Ordering::Relaxed);
    LAST_OP.store(op, Ordering::Relaxed);
}

pub fn debug_last_call() -> DebugLastAbiCall {
    DebugLastAbiCall {
        op: LAST_OP.load(Ordering::Relaxed),
        domain: LAST_DOMAIN.load(Ordering::Relaxed),
        ptr: LAST_PTR.load(Ordering::Relaxed),
        len: LAST_LEN.load(Ordering::Relaxed),
        lr: LAST_LR.load(Ordering::Relaxed),
    }
}

extern "C" fn console_write_v1(ptr: *const u8, len: usize) -> isize {
    record_last_call(LAST_OP_CONSOLE_WRITE, ptr as u64, len as u64);
    if sandbox::require_console_write().is_err() {
        return -1;
    }
    if ptr.is_null() || len == 0 {
        return 0;
    }
    if (ptr as usize) < 0x1000 {
        crate::drivers::serial::log_line_args(format_args!(
            "app-abi: suspicious console_write ptr=0x{:x} len={} domain={}",
            ptr as usize,
            len,
            sandbox::current_domain()
        ));
    }

    // Unified address space pointer validation entry (Domain fault on violation).
    if !sandbox::validate_domain_ptr(ptr, len, false) {
        return -1;
    }
    // IMPORTANT (aarch64): avoid potential compiler-generated wide unaligned loads when
    // reading App memory by forcing byte-wise volatile reads.
    //
    // Also, App page tables may intentionally omit kernel-only MMIO (e.g. framebuffer).
    // So we must read bytes while still in the App TTBR0/CR3, then switch to the kernel
    // AddressSpace for the actual framebuffer writes.
    //
    // Route through ConsoleManager session output (ordered + backend-rendered).
    let session = crate::console::mgr::ensure_session_for_current_domain();
    let mut offset = 0usize;
    let mut scratch = [0u8; 128];
    while offset < len {
        let n = core::cmp::min(len - offset, scratch.len());
        for i in 0..n {
            scratch[i] = unsafe { ptr.add(offset + i).read_volatile() };
        }
        for i in 0..n {
            scratch[i] = match scratch[i] {
                b'\n' => b'\n',
                b'\t' => b'\t',
                b if (0x20..=0x7e).contains(&b) => b,
                _ => b'?',
            };
        }
        let _ =
            crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, &scratch[..n]);
        offset += n;
    }
    len as isize
}

extern "C" fn console_read_v1(ptr: *mut u8, len: usize) -> isize {
    record_last_call(LAST_OP_CONSOLE_READ, ptr as u64, len as u64);
    if sandbox::require_console_read().is_err() {
        return -1;
    }
    if ptr.is_null() || len == 0 {
        return 0;
    }
    if (ptr as usize) < 0x1000 {
        crate::drivers::serial::log_line_args(format_args!(
            "app-abi: suspicious console_read ptr=0x{:x} len={} domain={}",
            ptr as usize,
            len,
            sandbox::current_domain()
        ));
    }

    if !sandbox::validate_domain_ptr(ptr as *const u8, len, true) {
        return -1;
    }
    let session = crate::console::mgr::ensure_session_for_current_domain();
    // Ensure any prompt/output preceding the read is visible before we wait for input.
    crate::console::mgr::flush(crate::console::mgr::last_seq_for_session(session));
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, len) };

    let mut n = 0usize;
    loop {
        // Keep the app domain alive while blocked on console input.
        timer::feed_current_app_timeout();
        let Some(evt) = crate::console::mgr::read_key(session, true) else {
            continue;
        };
        match evt {
            crate::console::KeyEvent::Char(ch) => {
                if ch == '\n' || ch == '\r' {
                    let _ =
                        crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, b"\n");
                    crate::console::mgr::flush(crate::console::mgr::last_seq_for_session(session));
                    break;
                }
                if n < buf.len() && ch.is_ascii() {
                    buf[n] = ch as u8;
                    n += 1;
                    let one = [ch as u8];
                    let _ = crate::console::mgr::write(
                        session,
                        crate::console::mgr::STREAM_STDOUT,
                        &one,
                    );
                }
            }
            crate::console::KeyEvent::Backspace => {
                if n > 0 {
                    n -= 1;
                    let _ = crate::console::mgr::backspace(session, 1);
                }
            }
            crate::console::KeyEvent::Enter => {
                let _ =
                    crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, b"\n");
                crate::console::mgr::flush(crate::console::mgr::last_seq_for_session(session));
                break;
            }
            crate::console::KeyEvent::Tab => {
                if n < buf.len() {
                    buf[n] = b'\t';
                    n += 1;
                    let _ =
                        crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, b"\t");
                }
            }
        }
    }
    n as isize
}

extern "C" fn watchdog_feed_v1() -> isize {
    record_last_call(LAST_OP_WATCHDOG_FEED, 0, 0);
    // Watchdog feed is only meaningful for sandboxed app domains; refuse otherwise.
    if sandbox::current_domain() <= 1 {
        return -1;
    }
    timer::feed_current_app_timeout();
    0
}

extern "C" fn ipc_send_v1(
    service_ptr: *const u8,
    service_len: usize,
    opcode: u32,
    ptr: *const u8,
    len: usize,
) -> isize {
    record_last_call(LAST_OP_IPC_SEND, service_ptr as u64, service_len as u64);
    if sandbox::require_ipc_send().is_err() {
        return -1;
    }
    if service_ptr.is_null() || service_len == 0 || service_len > 32 {
        return -1;
    }
    if len > 512 {
        return -1;
    }
    if !sandbox::validate_domain_ptr(service_ptr, service_len, false) {
        return -1;
    }
    if len != 0 {
        if ptr.is_null() {
            return -1;
        }
        if !sandbox::validate_domain_ptr(ptr, len, false) {
            return -1;
        }
    }

    let mut svc_buf = [0u8; 32];
    for i in 0..service_len {
        svc_buf[i] = unsafe { service_ptr.add(i).read_volatile() };
    }
    let svc = match core::str::from_utf8(&svc_buf[..service_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let mut payload: Vec<u8> = Vec::new();
    if len != 0 {
        payload.reserve_exact(len);
        let mut off = 0usize;
        let mut scratch = [0u8; 128];
        while off < len {
            let n = core::cmp::min(len - off, scratch.len());
            for i in 0..n {
                scratch[i] = unsafe { ptr.add(off + i).read_volatile() };
            }
            payload.extend_from_slice(&scratch[..n]);
            off += n;
        }
    }

    let ok = crate::mmu::switch::with_kernel_space(|| {
        crate::ipc::send_to_service(svc, opcode, &payload).is_ok()
    });
    if ok {
        0
    } else {
        -1
    }
}

extern "C" fn ipc_recv_v1(
    hdr: *mut IpcMsgHeader,
    ptr: *mut u8,
    cap: usize,
    blocking: u32,
    timeout_ticks: u64,
) -> isize {
    record_last_call(LAST_OP_IPC_RECV, hdr as u64, cap as u64);
    if sandbox::require_ipc_recv().is_err() {
        return -1;
    }
    if hdr.is_null() {
        return -1;
    }
    if !sandbox::validate_domain_ptr(hdr as *const u8, core::mem::size_of::<IpcMsgHeader>(), true) {
        return -1;
    }
    if cap != 0 {
        if ptr.is_null() {
            return -1;
        }
        if !sandbox::validate_domain_ptr(ptr as *const u8, cap, true) {
            return -1;
        }
    }

    let res = crate::mmu::switch::with_kernel_space(|| {
        crate::ipc::recv(blocking != 0, (timeout_ticks != 0).then_some(timeout_ticks))
    });
    let msg = match res {
        Ok(m) => m,
        Err(crate::ipc::IpcError::WouldBlock) => return -2,
        Err(crate::ipc::IpcError::Timeout) => return -3,
        Err(_) => return -1,
    };

    let n = core::cmp::min(msg.payload.len(), cap);
    unsafe {
        hdr.write_volatile(IpcMsgHeader {
            from_domain: msg.header.src_domain,
            opcode: msg.header.opcode,
            len: msg.payload.len().min(u32::MAX as usize) as u32,
            _reserved: 0,
        });
    }
    for i in 0..n {
        unsafe { ptr.add(i).write_volatile(msg.payload[i]) };
    }
    n as isize
}
