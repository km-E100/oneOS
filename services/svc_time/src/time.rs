use oneos_service::{IpcMsgHeader, ServiceApi};

use crate::ipc;

pub fn run(api: *const ServiceApi) -> i32 {
    unsafe {
        let _ = oneos_service::console_write_str(api, "svc_time: started\n");
    }

    let mut hdr = IpcMsgHeader {
        src_domain: 0,
        opcode: 0,
        len: 0,
        _reserved: 0,
    };
    let mut buf = [0u8; 64];
    loop {
        let n = ipc::recv(api, &mut hdr, &mut buf);
        if n < 0 {
            continue;
        }
        if hdr.opcode != ipc::OPCODE_TIME_REQ {
            continue;
        }
        let now = unsafe { oneos_service::ticks(api) };
        let payload = now.to_le_bytes();
        let _ = ipc::send_domain(api, hdr.src_domain, ipc::OPCODE_TIME_RESP, &payload);
    }
}
