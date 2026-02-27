use crate::{arch, text};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(1);
static IN_PANIC: AtomicBool = AtomicBool::new(false);

fn pick(choices: &'static [&'static str], s: u64) -> &'static str {
    if choices.is_empty() {
        return "";
    }
    let idx = (s as usize) % choices.len();
    choices[idx]
}

fn time_noise() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // x86: TSC
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // ARM: virtual counter
        let cnt: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, cntvct_el0",
                out(reg) cnt,
                options(nomem, nostack, preserves_flags)
            );
        }
        cnt
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

fn mix(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    x
}

fn panic_seed(info: &PanicInfo) -> u64 {
    let mut s = COUNTER.fetch_add(1, Ordering::SeqCst);

    if let Some(loc) = info.location() {
        s ^= loc.line() as u64;
        s = s.rotate_left(17) ^ (loc.column() as u64);
    }

    // 时间扰动：同一行 panic，不同时间 → 不同 seed
    s ^= time_noise();

    mix(s)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if IN_PANIC.swap(true, Ordering::SeqCst) {
        text::write_line("ONEOS_PANIC");
        text::write_line("(x_x) double panic");
        return arch::halt();
    }

    let seed = panic_seed(info);

    const PREFIX: &[&str] = &[
        "(>_<) oneOS kernel panic",
        "(x_x) oneOS kernel panic",
        "(o_o) oneOS kernel panic",
        "(T_T) oneOS kernel panic",
        "(;_;) oneOS kernel panic",
        "(^_^) oneOS kernel panic",
        "(-_-) oneOS kernel panic",
        "(o_O) oneOS kernel panic",
        "(O_o) oneOS kernel panic",
        "(@_@) oneOS kernel panic",
    ];

    const FEELING: &[&str] = &[
        "something went wrong inside the system...",
        "the world just cracked a little.",
        "a subsystem stopped responding.",
        "an invariant has been violated.",
        "this was not supposed to happen.",
        "the kernel lost its balance.",
        "a quiet failure echoed through the system.",
        "execution reached an impossible state.",
        "the machine hesitated, then stopped.",
        "consistency could not be preserved.",
    ];

    const FOOTER: &[&str] = &[
        "please restart the system",
        "reboot and try again",
        "panic is a state, not a surprise",
        "the system has halted safely",
        "nothing more can be done from here",
        "power cycle required",
        "recovery may be possible",
        "the kernel chose to stop",
        "halted to prevent further damage",
        "this stop was intentional",
    ];

    let prefix = pick(PREFIX, seed);
    let feeling = pick(FEELING, mix(seed ^ 0x9e3779b97f4a7c15));
    let footer = pick(FOOTER, mix(seed ^ 0xbf58476d1ce4e5b9));

    text::write_line("ONEOS_PANIC");

    text::write_line(prefix);
    text::write_line(feeling);

    let _ = text::write_line_args(format_args!("panic: {}", info));

    if let Some(loc) = info.location() {
        let _ = text::write_line_args(format_args!("at {}:{}", loc.file(), loc.line()));
    }

    text::write_line(footer);
    arch::halt()
}
