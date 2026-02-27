#![no_std]

use core::ffi::c_void;

#[repr(C)]
pub struct ServiceApi {
    pub version: u32,
    pub _reserved: u32,
    pub console_write: extern "C" fn(ptr: *const u8, len: usize) -> isize,
    pub ipc_send: extern "C" fn(
        service_ptr: *const u8,
        service_len: usize,
        opcode: u32,
        ptr: *const u8,
        len: usize,
    ) -> isize,
    pub ipc_send_domain:
        extern "C" fn(domain_id: u32, opcode: u32, ptr: *const u8, len: usize) -> isize,
    pub ipc_recv: extern "C" fn(
        hdr: *mut IpcMsgHeader,
        ptr: *mut u8,
        cap: usize,
        blocking: u32,
        timeout_ticks: u64,
    ) -> isize,
    pub ticks: extern "C" fn() -> u64,
    pub log_write: extern "C" fn(ptr: *const u8, len: usize) -> isize,
    pub cap_query: extern "C" fn() -> u64,
    // v2: Console backend I/O (polled by UI service).
    pub console_backend_recv: extern "C" fn(
        hdr: *mut ConsoleOutHeader,
        ptr: *mut u8,
        cap: usize,
        blocking: u32,
        timeout_ticks: u64,
    ) -> isize,
    pub console_backend_ack: extern "C" fn(seq: u64) -> isize,
    // v2: Minimal UI primitives for the backend (temporary; will evolve to framebuffer/window APIs).
    pub ui_write: extern "C" fn(ptr: *const u8, len: usize) -> isize,
    pub ui_backspace: extern "C" fn(count: u32) -> isize,
    pub ui_clear: extern "C" fn() -> isize,
    pub _reserved2: *const c_void,
}

#[repr(C)]
pub struct IpcMsgHeader {
    pub src_domain: u32,
    pub opcode: u32,
    pub len: u32,
    pub _reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConsoleOutHeader {
    pub session: u32,
    pub stream: u32,
    pub op: u32,
    pub len: u32,
    pub seq: u64,
}

#[inline]
pub unsafe fn console_write_str(api: *const ServiceApi, s: &str) -> isize {
    let api = &*api;
    (api.console_write)(s.as_ptr(), s.len())
}

#[inline]
pub unsafe fn console_backend_recv(
    api: *const ServiceApi,
    hdr: &mut ConsoleOutHeader,
    buf: &mut [u8],
    blocking: bool,
    timeout_ticks: u64,
) -> isize {
    let api = &*api;
    (api.console_backend_recv)(
        hdr as *mut ConsoleOutHeader,
        buf.as_mut_ptr(),
        buf.len(),
        if blocking { 1 } else { 0 },
        timeout_ticks,
    )
}

#[inline]
pub unsafe fn console_backend_ack(api: *const ServiceApi, seq: u64) -> isize {
    let api = &*api;
    (api.console_backend_ack)(seq)
}

#[inline]
pub unsafe fn ui_write_bytes(api: *const ServiceApi, bytes: &[u8]) -> isize {
    let api = &*api;
    (api.ui_write)(bytes.as_ptr(), bytes.len())
}

#[inline]
pub unsafe fn ui_backspace(api: *const ServiceApi, count: u32) -> isize {
    let api = &*api;
    (api.ui_backspace)(count)
}

#[inline]
pub unsafe fn ui_clear(api: *const ServiceApi) -> isize {
    let api = &*api;
    (api.ui_clear)()
}

#[inline]
pub unsafe fn ipc_send(
    api: *const ServiceApi,
    service: &str,
    opcode: u32,
    payload: &[u8],
) -> isize {
    let api = &*api;
    (api.ipc_send)(
        service.as_ptr(),
        service.len(),
        opcode,
        payload.as_ptr(),
        payload.len(),
    )
}

#[inline]
pub unsafe fn ipc_send_domain(
    api: *const ServiceApi,
    domain_id: u32,
    opcode: u32,
    payload: &[u8],
) -> isize {
    let api = &*api;
    (api.ipc_send_domain)(domain_id, opcode, payload.as_ptr(), payload.len())
}

#[inline]
pub unsafe fn ipc_recv(
    api: *const ServiceApi,
    hdr: &mut IpcMsgHeader,
    buf: &mut [u8],
    blocking: bool,
    timeout_ticks: u64,
) -> isize {
    let api = &*api;
    (api.ipc_recv)(
        hdr as *mut IpcMsgHeader,
        buf.as_mut_ptr(),
        buf.len(),
        if blocking { 1 } else { 0 },
        timeout_ticks,
    )
}

#[inline]
pub unsafe fn ticks(api: *const ServiceApi) -> u64 {
    let api = &*api;
    (api.ticks)()
}

#[inline]
pub unsafe fn log_write_str(api: *const ServiceApi, s: &str) -> isize {
    let api = &*api;
    (api.log_write)(s.as_ptr(), s.len())
}

#[inline]
pub unsafe fn cap_query(api: *const ServiceApi) -> u64 {
    let api = &*api;
    (api.cap_query)()
}
