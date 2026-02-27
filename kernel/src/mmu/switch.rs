#![cfg(target_os = "none")]

use crate::drivers::serial;
use crate::sync::irq::IrqGuard;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU64, Ordering};

/// Stage 3 (M2/X1): AddressSpace switch glue.
///
/// Hard rule for current stage:
/// - aarch64: enabled once the raw kernel installs its own MMU mappings.
/// - Even when enabled, aarch64 will no-op if MMU is off.
/// - x86_64 switching remains risky until we guarantee kernel mappings are shared in every App CR3.
///
/// Stage 1 (Post-MMU): controlled by bootflag `mmu_strict=on/off` (default on).
const DEFAULT_APP_ADDRESS_SPACE_SWITCH: bool = true;

static APP_ADDRESS_SPACE_SWITCH_ENABLED: AtomicBool =
    AtomicBool::new(DEFAULT_APP_ADDRESS_SPACE_SWITCH);

pub fn set_app_address_space_switch_enabled(enabled: bool) {
    APP_ADDRESS_SPACE_SWITCH_ENABLED.store(enabled, Ordering::SeqCst);
}

pub fn app_address_space_switch_enabled() -> bool {
    APP_ADDRESS_SPACE_SWITCH_ENABLED.load(Ordering::SeqCst)
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn aarch64_effective_kernel_ttbr0() -> u64 {
    // IMPORTANT: The scheduler's `KERNEL_MMU_ROOT` is intended to represent the kernel TTBR0,
    // but some execution paths (or memory corruption during early bring-up) can accidentally
    // leave it equal to the currently-installed App TTBR0. When we are actively running an app
    // (`LAST_APP_TTBR0 != 0`), prefer the snapshot captured at the moment we entered the app
    // address space (`LAST_KERNEL_TTBR0_FOR_APP`) because it is the only reliable kernel root
    // for switching back.
    let last_app = LAST_APP_TTBR0.load(Ordering::SeqCst);
    let last_kernel = LAST_KERNEL_TTBR0_FOR_APP.load(Ordering::SeqCst);
    if last_app != 0 && last_kernel != 0 {
        return last_kernel;
    }
    let sched_kernel = crate::sched::kernel_mmu_root();
    if sched_kernel != 0 {
        return sched_kernel;
    }
    last_kernel
}

/// Run `f` with the kernel AddressSpace installed (best-effort).
///
/// Why: when an AppDomain runs under its own TTBR0/CR3, some kernel-only mappings
/// (e.g. framebuffer) may intentionally be absent from the App page table. Kernel
/// code servicing App ABI calls must temporarily switch back to the kernel root
/// before touching such mappings.
pub fn with_kernel_space<R>(f: impl FnOnce() -> R) -> R {
    if !app_address_space_switch_enabled() {
        return f();
    }

    #[cfg(target_arch = "aarch64")]
    {
        if !crate::mmu::aarch64::is_enabled() {
            return f();
        }
        let kernel = aarch64_effective_kernel_ttbr0();
        if kernel == 0 {
            return f();
        }
        let cur = crate::mmu::aarch64::read_ttbr0_el1();
        if cur == kernel {
            return f();
        }
        // Prevent preemption/interrupt handlers from observing a transient TTBR0 value.
        // This avoids restoring TTBR0 to the wrong value if a context switch happens inside `f`.
        let _irq = IrqGuard::new();
        let cur = crate::mmu::aarch64::read_ttbr0_el1();
        if cur == kernel {
            return f();
        }
        crate::mmu::aarch64::enter_ttbr0(kernel);
        let out = f();
        crate::mmu::aarch64::enter_ttbr0(cur);
        return out;
    }

    #[cfg(target_arch = "x86_64")]
    {
        if !crate::mmu::x86_64::is_paging_enabled() {
            return f();
        }
        let kernel = LAST_KERNEL_CR3_FOR_APP.load(Ordering::SeqCst);
        if kernel == 0 {
            return f();
        }
        let cur = crate::mmu::x86_64::current_cr3();
        if cur == kernel {
            return f();
        }
        let _irq = IrqGuard::new();
        let cur = crate::mmu::x86_64::current_cr3();
        if cur == kernel {
            return f();
        }
        unsafe { crate::mmu::x86_64::write_cr3(kernel) };
        let out = f();
        unsafe { crate::mmu::x86_64::write_cr3(cur) };
        return out;
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        f()
    }
}

static SWITCH_ENTER_COUNT: AtomicU64 = AtomicU64::new(0);
static SWITCH_LEAVE_COUNT: AtomicU64 = AtomicU64::new(0);
static TRAP_RESTORE_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn switch_stats() -> (u64, u64, u64) {
    (
        SWITCH_ENTER_COUNT.load(Ordering::Relaxed),
        SWITCH_LEAVE_COUNT.load(Ordering::Relaxed),
        TRAP_RESTORE_COUNT.load(Ordering::Relaxed),
    )
}

// When running an AppDomain we may switch TTBR0/CR3 to the App's AddressSpace.
// If a hardware exception occurs inside the app, the trap handler must be able to
// restore the kernel AddressSpace before returning to the abort trampoline.
//
// This is single-app-at-a-time in v2, so one global slot is sufficient.
#[cfg(target_arch = "aarch64")]
static LAST_KERNEL_TTBR0_FOR_APP: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static LAST_APP_TTBR0: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "x86_64")]
static LAST_KERNEL_CR3_FOR_APP: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static LAST_APP_CR3: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchError {
    UnsupportedArch,
    MmuDisabled,
}

#[derive(Clone, Copy, Debug)]
pub struct SavedSpace {
    #[cfg(target_arch = "aarch64")]
    ttbr0: u64,
    #[cfg(target_arch = "x86_64")]
    cr3: u64,
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_restore_kernel_space_for_trap() -> Option<u64> {
    if !crate::mmu::aarch64::is_enabled() {
        return None;
    }
    let kernel = aarch64_effective_kernel_ttbr0();
    if kernel == 0 {
        return None;
    }
    let cur = crate::mmu::aarch64::read_ttbr0_el1();
    if cur != kernel {
        crate::mmu::aarch64::enter_ttbr0(kernel);
        crate::sched::notify_mmu_root_changed(kernel);
        TRAP_RESTORE_COUNT.fetch_add(1, Ordering::Relaxed);
        serial::log_line_args(format_args!(
            "mmu-switch: trap restore aarch64 ttbr0 0x{:x} -> 0x{:x}",
            cur, kernel
        ));
    }
    Some(kernel)
}

#[cfg(target_arch = "x86_64")]
pub fn x86_64_restore_kernel_space_for_trap() -> Option<u64> {
    if !crate::mmu::x86_64::is_paging_enabled() {
        return None;
    }
    let kernel = LAST_KERNEL_CR3_FOR_APP.load(Ordering::SeqCst);
    if kernel == 0 {
        return None;
    }
    let cur = crate::mmu::x86_64::current_cr3();
    if cur != kernel {
        unsafe { crate::mmu::x86_64::write_cr3(kernel) };
        crate::sched::notify_mmu_root_changed(kernel);
        TRAP_RESTORE_COUNT.fetch_add(1, Ordering::Relaxed);
        serial::log_line_args(format_args!(
            "mmu-switch: trap restore x86_64 cr3 0x{:x} -> 0x{:x}",
            cur, kernel
        ));
    }
    Some(kernel)
}

/// Best-effort: enter App address space rooted at `pt_root`.
///
/// On aarch64: this will only do anything if MMU is already enabled.
/// On x86_64: currently returns an error unless the switch is explicitly enabled.
pub fn enter_app_space(pt_root: u64) -> Result<SavedSpace, SwitchError> {
    if !app_address_space_switch_enabled() {
        return Err(SwitchError::UnsupportedArch);
    }
    let _ = pt_root;

    #[cfg(target_arch = "aarch64")]
    {
        if !crate::mmu::aarch64::is_enabled() {
            serial::log_line_args(format_args!("mmu-switch: skip (aarch64 mmu disabled)"));
            return Err(SwitchError::MmuDisabled);
        }

        let old = crate::mmu::aarch64::read_ttbr0_el1();
        crate::mmu::aarch64::enter_ttbr0(pt_root);
        LAST_KERNEL_TTBR0_FOR_APP.store(old, Ordering::SeqCst);
        LAST_APP_TTBR0.store(pt_root, Ordering::SeqCst);
        // Route B scaffold: expose roots to the TTBR1 trampoline state page (kernel/app).
        crate::mmu::addrspace::ttbr1_tramp_state_set(old, pt_root);
        crate::sched::notify_mmu_root_changed(pt_root);
        SWITCH_ENTER_COUNT.fetch_add(1, Ordering::Relaxed);
        serial::log_line_args(format_args!(
            "mmu-switch: enter aarch64 ttbr0 0x{:x} -> 0x{:x}",
            old, pt_root
        ));
        return Ok(SavedSpace { ttbr0: old });
    }

    #[cfg(target_arch = "x86_64")]
    {
        // v3+ (planned): switch CR3 for AppDomain address spaces.
        //
        // SAFETY/SEMANTICS:
        // - This is still “pure kernel mode”; we do not switch privilege levels.
        // - Switching CR3 without shared kernel mappings can brick the system; keep behind flag.
        if !crate::mmu::x86_64::is_paging_enabled() {
            serial::log_line("mmu-switch: skip (x86_64 paging disabled)");
            return Err(SwitchError::MmuDisabled);
        }

        // DEBUG: before switching CR3, verify that critical kernel addresses remain mapped
        // under the target App CR3. If not, the very next instruction fetch or interrupt
        // can triple-fault and reboot (no panic output).
        #[repr(C, packed)]
        struct DtReg {
            limit: u16,
            base: u64,
        }
        let rsp: u64;
        let rip: u64;
        let mut idtr = DtReg { limit: 0, base: 0 };
        let mut gdtr = DtReg { limit: 0, base: 0 };
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, preserves_flags));
            core::arch::asm!("lea {}, [rip + 0]", out(reg) rip, options(nomem, preserves_flags));
            core::arch::asm!("sidt [{}]", in(reg) (&mut idtr as *mut DtReg), options(nostack, preserves_flags));
            core::arch::asm!("sgdt [{}]", in(reg) (&mut gdtr as *mut DtReg), options(nostack, preserves_flags));
        }
        let idt_base = unsafe { core::ptr::addr_of!(idtr.base).read_unaligned() };
        let gdt_base = unsafe { core::ptr::addr_of!(gdtr.base).read_unaligned() };

        // Page-table walk is best-effort and assumes the page tables are identity-accessible
        // in the current kernel mapping (v2/v3 transition scaffolding).
        unsafe {
            let p_rsp = crate::mmu::x86_64::walk_l1(pt_root, rsp);
            let p_rip = crate::mmu::x86_64::walk_l1(pt_root, rip);
            let p_idt = crate::mmu::x86_64::walk_l1(pt_root, idt_base);
            let p_gdt = crate::mmu::x86_64::walk_l1(pt_root, gdt_base);
            serial::log_line_args(format_args!(
                "mmu-switch: x86_64 preflight rsp=0x{:x} rip=0x{:x} idt=0x{:x} gdt=0x{:x}",
                rsp, rip, idt_base, gdt_base
            ));
            serial::log_line_args(format_args!(
                "mmu-switch: x86_64 preflight pte rsp(kind={:?} desc=0x{:x}) rip(kind={:?} desc=0x{:x})",
                p_rsp.kind, p_rsp.desc, p_rip.kind, p_rip.desc
            ));
            serial::log_line_args(format_args!(
                "mmu-switch: x86_64 preflight pte idt(kind={:?} desc=0x{:x}) gdt(kind={:?} desc=0x{:x})",
                p_idt.kind, p_idt.desc, p_gdt.kind, p_gdt.desc
            ));
        }

        let old = crate::mmu::x86_64::current_cr3();
        unsafe { crate::mmu::x86_64::write_cr3(pt_root) };
        LAST_KERNEL_CR3_FOR_APP.store(old, Ordering::SeqCst);
        LAST_APP_CR3.store(pt_root, Ordering::SeqCst);
        crate::sched::notify_mmu_root_changed(pt_root);
        SWITCH_ENTER_COUNT.fetch_add(1, Ordering::Relaxed);
        serial::log_line_args(format_args!(
            "mmu-switch: enter x86_64 cr3 0x{:x} -> 0x{:x}",
            old, pt_root
        ));
        return Ok(SavedSpace { cr3: old });
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        Err(SwitchError::UnsupportedArch)
    }
}

pub fn leave_app_space(saved: SavedSpace) -> Result<(), SwitchError> {
    if !app_address_space_switch_enabled() {
        return Err(SwitchError::UnsupportedArch);
    }
    let _ = saved;

    #[cfg(target_arch = "aarch64")]
    {
        if !crate::mmu::aarch64::is_enabled() {
            serial::log_line_args(format_args!("mmu-switch: leave skip (mmu disabled)"));
            return Err(SwitchError::MmuDisabled);
        }
        crate::mmu::aarch64::enter_ttbr0(saved.ttbr0);
        LAST_APP_TTBR0.store(0, Ordering::SeqCst);
        LAST_KERNEL_TTBR0_FOR_APP.store(0, Ordering::SeqCst);
        crate::mmu::addrspace::ttbr1_tramp_state_set(saved.ttbr0, 0);
        crate::sched::notify_mmu_root_changed(saved.ttbr0);
        SWITCH_LEAVE_COUNT.fetch_add(1, Ordering::Relaxed);
        serial::log_line_args(format_args!(
            "mmu-switch: leave aarch64 ttbr0 -> 0x{:x}",
            saved.ttbr0
        ));
        return Ok(());
    }

    #[cfg(target_arch = "x86_64")]
    {
        if !crate::mmu::x86_64::is_paging_enabled() {
            serial::log_line("mmu-switch: leave skip (x86_64 paging disabled)");
            return Err(SwitchError::MmuDisabled);
        }
        unsafe { crate::mmu::x86_64::write_cr3(saved.cr3) };
        LAST_APP_CR3.store(0, Ordering::SeqCst);
        LAST_KERNEL_CR3_FOR_APP.store(0, Ordering::SeqCst);
        crate::sched::notify_mmu_root_changed(saved.cr3);
        SWITCH_LEAVE_COUNT.fetch_add(1, Ordering::Relaxed);
        serial::log_line_args(format_args!(
            "mmu-switch: leave x86_64 cr3 -> 0x{:x}",
            saved.cr3
        ));
        Ok(())
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = saved;
        Err(SwitchError::UnsupportedArch)
    }
}
