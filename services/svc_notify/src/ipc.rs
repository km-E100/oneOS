use oneos_service::{IpcMsgHeader, ServiceApi};

pub const OPCODE_NOTIFY_TEXT: u32 = 3;

pub fn recv(api: *const ServiceApi, hdr: &mut IpcMsgHeader, buf: &mut [u8]) -> isize {
    unsafe { oneos_service::ipc_recv(api, hdr, buf, true, 0) }
}

pub fn send(api: *const ServiceApi, service: &str, opcode: u32, payload: &[u8]) -> isize {
    unsafe { oneos_service::ipc_send(api, service, opcode, payload) }
}
