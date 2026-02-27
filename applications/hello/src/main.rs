#![no_std]
#![no_main]

use core::panic::PanicInfo;
use oneos_app::{console_write_line, ipc_recv, ipc_send, IpcMsgHeader, watchdog_feed, AppApiV1};

const OPCODE_TIME_REQ: u32 = 11;
const OPCODE_TIME_RESP: u32 = 12;

fn u64_to_dec(mut v: u64, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    while v != 0 && n < tmp.len() {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut w = 0usize;
    while w < n && w < out.len() {
        out[w] = tmp[n - 1 - w];
        w += 1;
    }
    w
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn oneos_app_main(api: *const AppApiV1) -> i32 {
    unsafe { watchdog_feed(api) };
    unsafe {
        let _ = ipc_send(api, "svc_time", OPCODE_TIME_REQ, &[]);
        let mut hdr = IpcMsgHeader {
            from_domain: 0,
            opcode: 0,
            len: 0,
            _reserved: 0,
        };
        let mut buf = [0u8; 16];
        let mut ok = false;
        for _ in 0..10 {
            let n = ipc_recv(api, &mut hdr, &mut buf, true, 50);
            if n <= 0 {
                continue;
            }
            if hdr.opcode != OPCODE_TIME_RESP {
                continue;
            }
            if (hdr.len as usize) < 8 {
                continue;
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&buf[..8]);
            let t = u64::from_le_bytes(arr);
            let mut msg = [0u8; 64];
            let prefix = b"hello from oneOS, ticks=";
            let mut p = 0usize;
            for &b in prefix {
                if p < msg.len() {
                    msg[p] = b;
                    p += 1;
                }
            }
            p += u64_to_dec(t, &mut msg[p..]);
            if p + 1 < msg.len() {
                msg[p] = b'\n';
                p += 1;
            }
            if let Ok(s) = core::str::from_utf8(&msg[..p]) {
                console_write_line(api, s);
            } else {
                console_write_line(api, "hello from oneOS (ticks decode failed)");
            }
            ok = true;
            break;
        }
        if !ok {
            console_write_line(api, "hello from oneOS (svc_time timeout)");
        }
    }
    0
}
