use oneos_service::{IpcMsgHeader, ServiceApi};

pub const OPCODE_LOG_LINE: u32 = 10;

pub fn recv(api: *const ServiceApi, hdr: &mut IpcMsgHeader, buf: &mut [u8]) -> isize {
    unsafe { oneos_service::ipc_recv(api, hdr, buf, true, 0) }
}
