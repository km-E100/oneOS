#![no_std]

use core::ffi::c_void;

#[repr(C)]
pub struct AppApiV1 {
    pub version: u32,
    pub _reserved: u32,
    pub console_write: extern "C" fn(ptr: *const u8, len: usize) -> isize,
    pub console_read: extern "C" fn(ptr: *mut u8, len: usize) -> isize,
    // v2: watchdog feed to refresh AppDomain timeout.
    pub watchdog_feed: extern "C" fn() -> isize,
    pub _reserved2: *const c_void,
    // v3: IPC primitives (Stage 3).
    pub ipc_send: extern "C" fn(service_ptr: *const u8, service_len: usize, opcode: u32, ptr: *const u8, len: usize) -> isize,
    pub ipc_recv: extern "C" fn(hdr: *mut IpcMsgHeader, ptr: *mut u8, cap: usize, blocking: u32, timeout_ticks: u64) -> isize,
}

#[repr(C)]
pub struct IpcMsgHeader {
    pub from_domain: u32,
    pub opcode: u32,
    pub len: u32,
    pub _reserved: u32,
}

pub mod oneconsole_ipc {
    pub const OPCODE_NOTIFY_TEXT: u32 = 3;
    pub const OPCODE_NOTIFY_TEXT_SYNC: u32 = 4;
    pub const OPCODE_NOTIFY_TEXT_ACK: u32 = 5;
}

#[inline]
pub unsafe fn watchdog_feed(api: *const AppApiV1) {
    let api = &*api;
    let _ = (api.watchdog_feed)();
}

#[inline]
pub unsafe fn console_write_str(api: *const AppApiV1, s: &str) {
    watchdog_feed(api);
    let api = &*api;
    (api.console_write)(s.as_ptr(), s.len());
}

#[inline]
pub unsafe fn console_write_line(api: *const AppApiV1, s: &str) {
    console_write_str(api, s);
    console_write_str(api, "\n");
}

#[inline]
pub unsafe fn console_read(api: *const AppApiV1, buf: &mut [u8]) -> isize {
    // Feed once before entering a potentially long wait.
    watchdog_feed(api);
    let api = &*api;
    (api.console_read)(buf.as_mut_ptr(), buf.len())
}

#[inline]
pub unsafe fn ipc_send(api: *const AppApiV1, service: &str, opcode: u32, payload: &[u8]) -> isize {
    watchdog_feed(api);
    let api = &*api;
    (api.ipc_send)(service.as_ptr(), service.len(), opcode, payload.as_ptr(), payload.len())
}

#[inline]
pub unsafe fn ipc_notify_line(api: *const AppApiV1, msg: &str) -> isize {
    let mut buf = [0u8; 256];
    let bytes = msg.as_bytes();
    let n = core::cmp::min(bytes.len(), buf.len().saturating_sub(1));
    buf[..n].copy_from_slice(&bytes[..n]);
    buf[n] = b'\n';
    let rc = ipc_send(api, "oneconsole", oneconsole_ipc::OPCODE_NOTIFY_TEXT_SYNC, &buf[..n + 1]);
    if rc < 0 {
        return rc;
    }

    // Block until oneconsole acks that it has consumed the message. This makes app output a part of
    // "foreground completion" semantics: the app won't exit before its last line is visible.
    let mut hdr = IpcMsgHeader {
        from_domain: 0,
        opcode: 0,
        len: 0,
        _reserved: 0,
    };
    let mut scratch = [0u8; 8];
    loop {
        let n = ipc_recv(api, &mut hdr, &mut scratch, true, 500);
        if n < 0 {
            return n;
        }
        if hdr.opcode == oneconsole_ipc::OPCODE_NOTIFY_TEXT_ACK {
            return 0;
        }
        // Ignore unrelated messages.
    }
}

#[inline]
pub unsafe fn ipc_recv(api: *const AppApiV1, hdr: &mut IpcMsgHeader, buf: &mut [u8], blocking: bool, timeout_ticks: u64) -> isize {
    watchdog_feed(api);
    let api = &*api;
    (api.ipc_recv)(
        hdr as *mut IpcMsgHeader,
        buf.as_mut_ptr(),
        buf.len(),
        if blocking { 1 } else { 0 },
        timeout_ticks,
    )
}
