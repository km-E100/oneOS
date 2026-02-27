#![cfg(target_os = "none")]

use core::ops::Drop;

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn irq_save_disable_inner() -> u64 {
    let daif: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, daif",
            "msr daifset, #2",
            out(reg) daif,
            options(nomem, nostack, preserves_flags)
        );
    }
    daif
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn irq_restore_inner(daif: u64) {
    unsafe {
        core::arch::asm!(
            "msr daif, {0}",
            in(reg) daif,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn irq_save_disable_inner() -> bool {
    let rflags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {0}",
            out(reg) rflags,
            options(nomem, preserves_flags)
        );
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
    (rflags & (1 << 9)) != 0
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn irq_restore_inner(was_enabled: bool) {
    if was_enabled {
        unsafe { core::arch::asm!("sti", options(nomem, nostack, preserves_flags)) };
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
#[inline(always)]
fn irq_save_disable_inner() -> u8 {
    0
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
#[inline(always)]
fn irq_restore_inner(_: u8) {}

#[cfg(target_arch = "aarch64")]
pub type IrqState = u64;
#[cfg(target_arch = "x86_64")]
pub type IrqState = bool;
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub type IrqState = u8;

pub struct IrqGuard {
    state: IrqState,
}

impl IrqGuard {
    #[inline(always)]
    pub fn new() -> Self {
        let state = irq_save_disable_inner();
        Self { state }
    }

    #[inline(always)]
    pub fn state(&self) -> IrqState {
        self.state
    }
}

impl Drop for IrqGuard {
    #[inline(always)]
    fn drop(&mut self) {
        irq_restore_inner(self.state);
    }
}
