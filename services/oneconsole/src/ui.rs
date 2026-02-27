use oneos_service::ServiceApi;

pub fn run(api: *const ServiceApi) -> i32 {
    // Backend loop: pull ordered output records from the kernel ConsoleManager and render them.
    // Note: rendering primitives are intentionally minimal for now (text + backspace + clear).
    const OP_WRITE: u32 = 0;
    const OP_BACKSPACE: u32 = 1;
    const OP_CLEAR: u32 = 2;

    let mut hdr = oneos_service::ConsoleOutHeader {
        session: 0,
        stream: 0,
        op: 0,
        len: 0,
        seq: 0,
    };
    let mut buf = [0u8; 512];
    loop {
        let r = unsafe { oneos_service::console_backend_recv(api, &mut hdr, &mut buf, true, 0) };
        if r < 0 {
            continue;
        }
        match hdr.op {
            OP_WRITE => {
                let n = (hdr.len as usize).min(buf.len());
                let _ = unsafe { oneos_service::ui_write_bytes(api, &buf[..n]) };
            }
            OP_BACKSPACE => {
                let _ = unsafe { oneos_service::ui_backspace(api, hdr.len) };
            }
            OP_CLEAR => {
                let _ = unsafe { oneos_service::ui_clear(api) };
            }
            _ => {}
        }
        let _ = unsafe { oneos_service::console_backend_ack(api, hdr.seq) };
    }
}
