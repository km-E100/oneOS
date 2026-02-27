#![cfg(target_os = "none")]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

pub use oneos_service::{IpcMsgHeader, ServiceApi};

use crate::sandbox;

pub const SERVICE_API: ServiceApi = ServiceApi {
    version: 2,
    _reserved: 0,
    console_write: console_write,
    ipc_send: ipc_send,
    ipc_send_domain: ipc_send_domain,
    ipc_recv: ipc_recv,
    ticks: ticks,
    log_write: log_write,
    cap_query: cap_query,
    console_backend_recv: console_backend_recv,
    console_backend_ack: console_backend_ack,
    ui_write: ui_write,
    ui_backspace: ui_backspace,
    ui_clear: ui_clear,
    _reserved2: core::ptr::null(),
};

extern "C" fn ticks() -> u64 {
    crate::timer::ticks()
}

extern "C" fn cap_query() -> u64 {
    crate::sandbox::caps_mask_for_current_domain()
}

extern "C" fn console_write(ptr: *const u8, len: usize) -> isize {
    if sandbox::require_console_write_service().is_err() {
        return -1;
    }
    if ptr.is_null() || len == 0 {
        return 0;
    }
    if !sandbox::validate_domain_ptr(ptr, len, false) {
        return -1;
    }
    let mut offset = 0usize;
    let mut scratch = [0u8; 128];
    while offset < len {
        let n = core::cmp::min(len - offset, scratch.len());
        for i in 0..n {
            scratch[i] = unsafe { ptr.add(offset + i).read_volatile() };
        }
        let session = crate::console::mgr::ensure_session_for_current_domain();
        let _ = crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, &scratch[..n]);
        offset += n;
    }
    len as isize
}

extern "C" fn console_backend_recv(
    hdr: *mut oneos_service::ConsoleOutHeader,
    ptr: *mut u8,
    cap: usize,
    blocking: u32,
    timeout_ticks: u64,
) -> isize {
    if hdr.is_null() || ptr.is_null() || cap == 0 {
        return -1;
    }
    // Only the registered backend domain may pull console output.
    if !crate::console::mgr::is_backend_current_domain() {
        return -1;
    }
    let hdr = unsafe { &mut *hdr };
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, cap) };
    crate::console::mgr::backend_recv(hdr, buf, blocking != 0, timeout_ticks)
}

extern "C" fn console_backend_ack(seq: u64) -> isize {
    crate::console::mgr::backend_ack(seq)
}

extern "C" fn ui_write(ptr: *const u8, len: usize) -> isize {
    if !crate::console::mgr::is_backend_current_domain() {
        return -1;
    }
    if ptr.is_null() || len == 0 {
        return 0;
    }
    if !sandbox::validate_domain_ptr(ptr, len, false) {
        return -1;
    }
    let mut offset = 0usize;
    let mut scratch = [0u8; 256];
    while offset < len {
        let n = core::cmp::min(len - offset, scratch.len());
        for i in 0..n {
            scratch[i] = unsafe { ptr.add(offset + i).read_volatile() };
        }
        crate::mmu::switch::with_kernel_space(|| {
            // Temporary: render bytes through the kernel's display console.
            for &b in &scratch[..n] {
                crate::display::write_char(match b {
                    b'\n' => '\n',
                    b'\t' => '\t',
                    0x20..=0x7e => b as char,
                    _ => '?',
                });
            }
        });
        offset += n;
    }
    len as isize
}

extern "C" fn ui_backspace(count: u32) -> isize {
    if !crate::console::mgr::is_backend_current_domain() {
        return -1;
    }
    crate::mmu::switch::with_kernel_space(|| {
        for _ in 0..count {
            crate::display::backspace();
        }
    });
    0
}

extern "C" fn ui_clear() -> isize {
    if !crate::console::mgr::is_backend_current_domain() {
        return -1;
    }
    crate::mmu::switch::with_kernel_space(|| {
        crate::display::clear();
    });
    0
}

fn read_name32(ptr: *const u8, len: usize) -> Option<[u8; 32]> {
    if ptr.is_null() || len == 0 || len > 32 {
        return None;
    }
    if !sandbox::validate_domain_ptr(ptr, len, false) {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..len {
        out[i] = unsafe { ptr.add(i).read_volatile() };
    }
    Some(out)
}

fn name32_to_str(name: &[u8; 32], len: usize) -> Option<&'static str> {
    let bytes = &name[..len];
    let s = core::str::from_utf8(bytes).ok()?;
    let mut owned = String::new();
    owned.push_str(s);
    Some(Box::leak(owned.into_boxed_str()))
}

extern "C" fn ipc_send(
    service_ptr: *const u8,
    service_len: usize,
    opcode: u32,
    ptr: *const u8,
    len: usize,
) -> isize {
    if sandbox::require_ipc_send().is_err() {
        return -1;
    }
    let name32 = match read_name32(service_ptr, service_len) {
        Some(v) => v,
        None => return -1,
    };
    if len > 512 {
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
    let svc = match name32_to_str(&name32, service_len) {
        Some(s) => s,
        None => return -1,
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

extern "C" fn ipc_send_domain(domain_id: u32, opcode: u32, ptr: *const u8, len: usize) -> isize {
    if sandbox::require_ipc_send().is_err() {
        return -1;
    }
    if len > 512 {
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
        crate::ipc::send_to_domain(domain_id, opcode, &payload).is_ok()
    });
    if ok {
        0
    } else {
        -1
    }
}

extern "C" fn ipc_recv(
    hdr: *mut IpcMsgHeader,
    ptr: *mut u8,
    cap: usize,
    blocking: u32,
    timeout_ticks: u64,
) -> isize {
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
            src_domain: msg.header.src_domain,
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

extern "C" fn log_write(ptr: *const u8, len: usize) -> isize {
    if ptr.is_null() || len == 0 {
        return 0;
    }
    if !sandbox::validate_domain_ptr(ptr, len, false) {
        return -1;
    }
    let mut offset = 0usize;
    let mut scratch = [0u8; 128];
    while offset < len {
        let n = core::cmp::min(len - offset, scratch.len());
        for i in 0..n {
            scratch[i] = unsafe { ptr.add(offset + i).read_volatile() };
        }
        let _ = crate::ipc::send_to_service("svc_logger", 10, &scratch[..n]);
        offset += n;
    }
    len as isize
}
