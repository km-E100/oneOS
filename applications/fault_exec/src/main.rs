#![no_std]
#![no_main]

use core::panic::PanicInfo;
use oneos_app::{console_write_line, watchdog_feed, AppApiV1};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn oneos_app_main(api: *const AppApiV1) -> i32 {
    unsafe { watchdog_feed(api) };
    unsafe {
        console_write_line(api, "fault_exec: about to execute from stack (expect NX fault)");
    }
    let buf = [0u8; 16];
    let ptr = core::hint::black_box(buf.as_ptr());
    let f: extern "C" fn() -> i32 = unsafe { core::mem::transmute(ptr) };
    let _ = unsafe { f() };
    0
}

