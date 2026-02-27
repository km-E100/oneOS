use oneos_service::{IpcMsgHeader, ServiceApi};

pub const OPCODE_TIME_REQ: u32 = 11;
pub const OPCODE_TIME_RESP: u32 = 12;

pub fn recv(api: *const ServiceApi, hdr: &mut IpcMsgHeader, buf: &mut [u8]) -> isize {
    unsafe { oneos_service::ipc_recv(api, hdr, buf, true, 0) }
}

pub fn send(api: *const ServiceApi, service: &str, opcode: u32, payload: &[u8]) -> isize {
    unsafe { oneos_service::ipc_send(api, service, opcode, payload) }
}

pub fn send_domain(api: *const ServiceApi, domain_id: u32, opcode: u32, payload: &[u8]) -> isize {
    unsafe { oneos_service::ipc_send_domain(api, domain_id, opcode, payload) }
}
