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
        console_write_line(api, "fault_text: about to write into .text (expect fault)");
    }
    let p = oneos_app_main as usize as *mut u8;
    unsafe { core::ptr::write_volatile(p, 0xCC) };
    0
}

