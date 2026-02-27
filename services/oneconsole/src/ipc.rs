use oneos_service::{IpcMsgHeader, ServiceApi};

pub const OPCODE_PING: u32 = 1;
pub const OPCODE_PONG: u32 = 2;
pub const OPCODE_NOTIFY_TEXT: u32 = 3;
pub const OPCODE_NOTIFY_TEXT_SYNC: u32 = 4;
pub const OPCODE_NOTIFY_TEXT_ACK: u32 = 5;

pub fn recv(api: *const ServiceApi, hdr: &mut IpcMsgHeader, buf: &mut [u8]) -> isize {
    unsafe { oneos_service::ipc_recv(api, hdr, buf, true, 0) }
}

pub fn send(api: *const ServiceApi, service: &str, opcode: u32, payload: &[u8]) -> isize {
    unsafe { oneos_service::ipc_send(api, service, opcode, payload) }
}

pub fn send_domain(api: *const ServiceApi, domain_id: u32, opcode: u32, payload: &[u8]) -> isize {
    unsafe { oneos_service::ipc_send_domain(api, domain_id, opcode, payload) }
}
