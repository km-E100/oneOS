#![no_std]
#![no_main]

use core::panic::PanicInfo;
use oneos_app::{console_read, console_write_line, console_write_str, watchdog_feed, AppApiV1};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn oneos_app_main(api: *const AppApiV1) -> i32 {
    unsafe {
        console_write_line(api, "GuessNumber (oneOS app)");
        console_write_line(api, "I picked a number between 1 and 100.");
    }

    let mut seed = (api as usize as u64) ^ 0x9e37_79b9_7f4a_7c15u64;
    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    let target = ((seed >> 32) % 100 + 1) as u32;

    let mut attempts: u32 = 0;
    let mut buf = [0u8; 32];
    loop {
        // Keep the domain alive under the kernel timeout policy.
        unsafe { watchdog_feed(api) };
        unsafe {
            console_write_str(api, "guess> ");
        }
        let n = unsafe { console_read(api, &mut buf) };
        if n <= 0 {
            continue;
        }
        let n = n as usize;
        let s = core::str::from_utf8(&buf[..n]).unwrap_or("").trim();
        if s.is_empty() {
            continue;
        }
        let mut value: u32 = 0;
        let mut ok = true;
        for b in s.as_bytes() {
            if !b.is_ascii_digit() {
                ok = false;
                break;
            }
            value = value.saturating_mul(10).saturating_add((b - b'0') as u32);
        }
        if !ok || value < 1 || value > 100 {
            unsafe {
                console_write_line(api, "invalid input (enter 1..100)");
            }
            continue;
        }

        attempts = attempts.saturating_add(1);
        if value < target {
            unsafe { console_write_line(api, "too small"); }
        } else if value > target {
            unsafe { console_write_line(api, "too big"); }
        } else {
            unsafe {
                console_write_line(api, "correct!");
                console_write_str(api, "attempts: ");
                write_u32(api, attempts);
                console_write_str(api, "\n");
            }
            break;
        }
    }

    0
}

unsafe fn write_u32(api: *const AppApiV1, mut v: u32) {
    let mut tmp = [0u8; 10];
    let mut i = 0usize;
    if v == 0 {
        tmp[0] = b'0';
        i = 1;
    } else {
        while v != 0 && i < tmp.len() {
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            i += 1;
        }
    }
    for ch in tmp[..i].iter().rev() {
        let s = core::str::from_utf8_unchecked(core::slice::from_ref(ch));
        console_write_str(api, s);
    }
}
