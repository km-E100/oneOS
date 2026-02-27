use oneos_service::{IpcMsgHeader, ServiceApi};

use crate::ipc;

pub fn run(api: *const ServiceApi) -> i32 {
    unsafe {
        let _ = oneos_service::console_write_str(api, "svc_notify: started\n");
    }

    let mut hdr = IpcMsgHeader {
        src_domain: 0,
        opcode: 0,
        len: 0,
        _reserved: 0,
    };
    let mut buf = [0u8; 512];
    loop {
        let n = ipc::recv(api, &mut hdr, &mut buf);
        if n < 0 {
            continue;
        }
        if hdr.opcode != ipc::OPCODE_NOTIFY_TEXT {
            continue;
        }
        let payload = &buf[..(hdr.len as usize).min(buf.len())];
        let _ = ipc::send(api, "oneconsole", ipc::OPCODE_NOTIFY_TEXT, payload);
    }
}
