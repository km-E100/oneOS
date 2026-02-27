#![allow(dead_code)]

/// aarch64 上用 WFI 循环停机。
#[cfg(target_arch = "aarch64")]
pub fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

/// raw-kernel (no_std) 阶段：关闭 UEFI 遗留的 MMU/缓存/执行权限策略。
///
/// 现象：App 入口执行触发 Instruction Abort（permission fault），常见原因是 UEFI 页表
/// 将普通 RAM 标记为 PXN/UXN（不可执行）。在我们还没建立自己的页表前，最小可行方案是
/// 将系统切回 MMU=off 的物理地址执行模式。
///
/// 注意：该函数仅用于 raw kernel（target_os=none）早期阶段。
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub fn early_disable_mmu_for_raw_kernel() {
    use crate::drivers::serial;

    let mut current_el: u64 = 0;
    let mut sctlr: u64 = 0;
    unsafe {
        core::arch::asm!("mrs {0}, CurrentEL", out(reg) current_el, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mrs {0}, sctlr_el1", out(reg) sctlr, options(nomem, nostack, preserves_flags));
    }
    serial::log_line_args(format_args!(
        "aarch64: early mmu state CurrentEL=0x{:x} sctlr_el1=0x{:x}",
        current_el, sctlr
    ));

    // Only meaningful at EL1.
    if (current_el >> 2) & 0x3 != 1 {
        serial::log_line("aarch64: early_disable_mmu_for_raw_kernel skipped (not EL1)");
        return;
    }

    // SCTLR_EL1 bits:
    // M (0) = MMU enable
    // C (2) = data cache enable
    // I (12)= instruction cache enable
    // WXN (19)= write implies execute-never
    let mut new_sctlr = sctlr;
    new_sctlr &= !(1 << 0); // M
    new_sctlr &= !(1 << 2); // C
    new_sctlr &= !(1 << 12); // I
    new_sctlr &= !(1 << 19); // WXN

    if new_sctlr == sctlr {
        serial::log_line("aarch64: early mmu state unchanged");
        return;
    }

    unsafe {
        core::arch::asm!("dsb sy", "isb", options(nomem, nostack, preserves_flags));
        core::arch::asm!("msr sctlr_el1, {0}", in(reg) new_sctlr, options(nomem, nostack, preserves_flags));
        core::arch::asm!("isb", options(nomem, nostack, preserves_flags));
    }

    let mut after: u64 = 0;
    unsafe {
        core::arch::asm!("mrs {0}, sctlr_el1", out(reg) after, options(nomem, nostack, preserves_flags))
    };
    serial::log_line_args(format_args!(
        "aarch64: early mmu disabled sctlr_el1=0x{:x}",
        after
    ));
}

/// 非 aarch64 架构下的占位实现，避免交叉编译报错。
#[cfg(not(target_arch = "aarch64"))]
pub fn halt() -> ! {
    loop {}
}
