#![cfg(target_os = "none")]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::drivers::serial;

pub const TIMEOUT_RETURN_CODE: i32 = -2;
pub const APP_FAULT_RETURN_CODE: i32 = -3;

static TICK_HZ: AtomicU64 = AtomicU64::new(100);
static TICKS: AtomicU64 = AtomicU64::new(0);

static ACTIVE_APP_DOMAIN: AtomicU32 = AtomicU32::new(0);
static ACTIVE_DEADLINE_TICK: AtomicU64 = AtomicU64::new(0);
static ACTIVE_ADD_TICKS: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_PENDING_DOMAIN: AtomicU32 = AtomicU32::new(0);

pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::init();
        return;
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::init();
        return;
    }
    serial::log_line("timer: init skipped (unsupported arch)");
}

pub fn hz() -> u64 {
    TICK_HZ.load(Ordering::Relaxed)
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

pub fn arm_app_timeout(domain_id: u32, timeout_ms: u64) {
    if timeout_ms == 0 {
        disarm_app_timeout(domain_id);
        return;
    }
    let hz = hz().max(1);
    let add = timeout_ms.saturating_mul(hz) / 1000;
    let now = ticks();
    serial::log_line_args(format_args!(
        "timer: arm_app_timeout domain={} now_tick={} timeout_ms={} hz={} add_ticks={}",
        domain_id,
        now,
        timeout_ms,
        hz,
        add.max(1)
    ));
    ACTIVE_APP_DOMAIN.store(domain_id, Ordering::SeqCst);
    let add = add.max(1);
    ACTIVE_ADD_TICKS.store(add, Ordering::SeqCst);
    // Stage 2: count down CPU ticks for this domain (preemptive scheduler may run others).
    ACTIVE_DEADLINE_TICK.store(add, Ordering::SeqCst);
    serial::log_line_args(format_args!(
        "timer: armed domain={} budget_ticks={}",
        domain_id, add
    ));
}

pub fn disarm_app_timeout(domain_id: u32) {
    let cur = ACTIVE_APP_DOMAIN.load(Ordering::SeqCst);
    if cur == domain_id {
        ACTIVE_APP_DOMAIN.store(0, Ordering::SeqCst);
        ACTIVE_DEADLINE_TICK.store(0, Ordering::SeqCst);
        ACTIVE_ADD_TICKS.store(0, Ordering::SeqCst);
        serial::log_line_args(format_args!(
            "timer: disarm_app_timeout domain={}",
            domain_id
        ));
    }
}

/// Refresh the currently armed app timeout deadline without logging.
///
/// Used by interactive console I/O and by apps via AppApi watchdog_feed.
pub fn feed_current_app_timeout() {
    let app = ACTIVE_APP_DOMAIN.load(Ordering::SeqCst);
    if app == 0 {
        return;
    }
    if crate::sandbox::current_domain() != app {
        return;
    }
    let add = ACTIVE_ADD_TICKS.load(Ordering::SeqCst);
    if add == 0 {
        return;
    }
    ACTIVE_DEADLINE_TICK.store(add, Ordering::SeqCst);
}

pub fn take_timeout_pending_domain() -> Option<u32> {
    let id = TIMEOUT_PENDING_DOMAIN.swap(0, Ordering::SeqCst);
    (id != 0).then_some(id)
}

#[derive(Clone, Copy, Debug)]
pub struct PendingFaultInfo {
    pub domain: u32,
    pub vector: u32,
    pub rip: u64,
    pub addr: u64,
    pub err: u64,
}

pub fn take_pending_fault_info() -> Option<PendingFaultInfo> {
    #[cfg(target_arch = "x86_64")]
    {
        return x86_64::take_pending_fault_info();
    }
    #[cfg(target_arch = "aarch64")]
    {
        return None;
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        None
    }
}

fn on_tick() -> bool {
    let t = TICKS.fetch_add(1, Ordering::SeqCst).saturating_add(1);
    let app = ACTIVE_APP_DOMAIN.load(Ordering::SeqCst);
    if app == 0 {
        return false;
    }
    // Stage 2: CPU-time budget (only count ticks while the domain is currently running).
    if crate::sandbox::current_domain() != app {
        return false;
    }
    let left = ACTIVE_DEADLINE_TICK.load(Ordering::SeqCst);
    if left == 0 {
        return false;
    }
    let left = left.saturating_sub(1);
    ACTIVE_DEADLINE_TICK.store(left, Ordering::SeqCst);
    if left != 0 {
        return false;
    }
    // Mark pending timeout and request abort.
    TIMEOUT_PENDING_DOMAIN.store(app, Ordering::SeqCst);
    serial::log_line_args(format_args!(
        "timer: timeout reached domain={} tick={}",
        app, t
    ));
    // Prevent repeated abort re-entry storm.
    ACTIVE_APP_DOMAIN.store(0, Ordering::SeqCst);
    ACTIVE_DEADLINE_TICK.store(0, Ordering::SeqCst);
    ACTIVE_ADD_TICKS.store(0, Ordering::SeqCst);
    true
}

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use super::{on_tick, TICK_HZ};
    use core::arch::global_asm;
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    use crate::drivers::serial;
    use crate::sandbox::DomainKind;

    static PENDING_FAULT_DOMAIN: AtomicU32 = AtomicU32::new(0);
    static PENDING_FAULT_VECTOR: AtomicU32 = AtomicU32::new(0);
    static PENDING_FAULT_RIP: AtomicU64 = AtomicU64::new(0);
    static PENDING_FAULT_ADDR: AtomicU64 = AtomicU64::new(0);
    static PENDING_FAULT_ERR: AtomicU64 = AtomicU64::new(0);

    fn record_pending_fault(vector: u32, rip: u64, addr: u64, err: u64) {
        // Stage 1 rule: ISR must not allocate / write disk / stop domains.
        let domain = crate::sandbox::current_domain();
        PENDING_FAULT_DOMAIN.store(domain, Ordering::Relaxed);
        PENDING_FAULT_VECTOR.store(vector, Ordering::Relaxed);
        PENDING_FAULT_RIP.store(rip, Ordering::Relaxed);
        PENDING_FAULT_ADDR.store(addr, Ordering::Relaxed);
        PENDING_FAULT_ERR.store(err, Ordering::Relaxed);
    }

    pub fn take_pending_fault_info() -> Option<super::PendingFaultInfo> {
        let domain = PENDING_FAULT_DOMAIN.swap(0, Ordering::SeqCst);
        if domain == 0 {
            return None;
        }
        Some(super::PendingFaultInfo {
            domain,
            vector: PENDING_FAULT_VECTOR.swap(0, Ordering::SeqCst),
            rip: PENDING_FAULT_RIP.swap(0, Ordering::SeqCst),
            addr: PENDING_FAULT_ADDR.swap(0, Ordering::SeqCst),
            err: PENDING_FAULT_ERR.swap(0, Ordering::SeqCst),
        })
    }

    const PIC1: u16 = 0x20;
    const PIC2: u16 = 0xA0;
    const PIC1_COMMAND: u16 = PIC1;
    const PIC1_DATA: u16 = PIC1 + 1;
    const PIC2_COMMAND: u16 = PIC2;
    const PIC2_DATA: u16 = PIC2 + 1;
    const PIC_EOI: u8 = 0x20;

    const PIT_COMMAND: u16 = 0x43;
    const PIT_CHANNEL0: u16 = 0x40;
    const PIT_BASE_HZ: u32 = 1_193_182;

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    struct IdtEntry {
        off_low: u16,
        sel: u16,
        ist: u8,
        attrs: u8,
        off_mid: u16,
        off_high: u32,
        zero: u32,
    }

    #[repr(C, packed)]
    struct Idtr {
        limit: u16,
        base: u64,
    }

    static mut IDT: [IdtEntry; 256] = [IdtEntry {
        off_low: 0,
        sel: 0,
        ist: 0,
        attrs: 0,
        off_mid: 0,
        off_high: 0,
        zero: 0,
    }; 256];

    extern "C" {
        fn oneos_x86_timer_isr();
        fn oneos_x86_isr_ud();
        fn oneos_x86_isr_df();
        fn oneos_x86_isr_gp();
        fn oneos_x86_isr_pf();
        fn oneos_x86_isr_spurious();
    }

    global_asm!(
        r#"
        .intel_syntax noprefix
        .section .text
        .global oneos_x86_timer_isr
    oneos_x86_timer_isr:
        push rax
        push rcx
        push rdx
        push rbx
        push rbp
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15

        // SysV ABI: ensure stack is 16-byte aligned *inside* the Rust callee.
        // Interrupt frame pushes 24 bytes, so after 15 pushes (120) we are 0 mod 16.
        // Make it 8 mod 16 before CALL so callee sees 0 mod 16.
        sub rsp, 8
        call oneos_timer_tick_x86
        add rsp, 8
        // eax: bit0=abort, bit1=preempt
        test eax, 1
        jz 2f

        // saved rax is at [rsp + 14*8] (because we pushed rax first).
        mov qword ptr [rsp + 112], -2
        mov rdx, qword ptr [rip + ONEOS_APP_ABORT_JMP]
        // interrupt frame rip is at [rsp + 15*8].
        mov qword ptr [rsp + 120], rdx
        jmp 1f
    2:
        test eax, 2
        jz 1f
        // Preempt: store original RIP and redirect to scheduler preempt trampoline.
        mov rdx, qword ptr [rsp + 120]
        mov qword ptr [rip + ONEOS_SCHED_PREEMPT_PC], rdx
        lea rdx, [rip + oneos_x86_sched_preempt]
        mov qword ptr [rsp + 120], rdx
    1:
        // EOI for PIC
        mov al, 0x20
        out 0x20, al

        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        pop rdx
        pop rcx
        pop rax
        iretq
        "#
    );

    // Minimal diagnostic ISRs to avoid triple-fault reboot loops during early bring-up.
    // For AppDomain faults (#PF/#GP), we redirect to the app abort trampoline so the shell survives.
    global_asm!(
        r#"
        .intel_syntax noprefix
        .section .text

        .global oneos_x86_isr_ud
    oneos_x86_isr_ud:
        // no error code: stack starts with RIP
        push rax
        push rcx
        push rdx
        push rbx
        push rbp
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15

        // Align stack for Rust call (same reasoning as timer ISR above).
        sub rsp, 8
        mov rdi, qword ptr [rsp + 128] // rip
        mov rsi, qword ptr [rsp + 136] // cs
        mov rdx, qword ptr [rsp + 144] // rflags
        call oneos_x86_ud_fault
        add rsp, 8
        test eax, eax
        jz 0f
        // saved rax is at [rsp + 14*8] = 112
        mov qword ptr [rsp + 112], -3
        mov rdx, qword ptr [rip + ONEOS_APP_ABORT_JMP]
        // interrupt frame rip is at [rsp + 15*8] = 120
        mov qword ptr [rsp + 120], rdx
    0:
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        pop rdx
        pop rcx
        pop rax
        iretq

        .global oneos_x86_isr_df
    oneos_x86_isr_df:
        // error code is at [rsp + 0]
        mov rdi, qword ptr [rsp + 0]   // err
        mov rsi, qword ptr [rsp + 8]   // rip
        mov rdx, qword ptr [rsp + 16]  // cs
        mov rcx, qword ptr [rsp + 24]  // rflags
        // Ensure stack alignment for Rust call (callee requires 16-byte aligned RSP).
        sub rsp, 8
        call oneos_x86_df_fault
        add rsp, 8
    9:
        cli
        hlt
        jmp 9b

        .global oneos_x86_isr_gp
    oneos_x86_isr_gp:
        // error code is at [rsp + 0]
        push rax
        push rcx
        push rdx
        push rbx
        push rbp
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15

        // Align stack for Rust call (same reasoning as timer ISR above).
        sub rsp, 8
        mov rdi, qword ptr [rsp + 128] // err
        mov rsi, qword ptr [rsp + 136] // rip
        mov rdx, qword ptr [rsp + 144] // cs
        mov rcx, qword ptr [rsp + 152] // rflags
        call oneos_x86_gp_fault
        add rsp, 8
        test eax, eax
        jz 1f
        // saved rax is at [rsp + 14*8] = 112
        mov qword ptr [rsp + 112], -3
        mov rdx, qword ptr [rip + ONEOS_APP_ABORT_JMP]
        // interrupt frame rip (after error code) is at [rsp + 16*8] = 128
        mov qword ptr [rsp + 128], rdx
    1:
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        pop rdx
        pop rcx
        pop rax
        add rsp, 8 // drop error code
        iretq

        .global oneos_x86_isr_pf
    oneos_x86_isr_pf:
        // error code is at [rsp + 0]
        push rax
        push rcx
        push rdx
        push rbx
        push rbp
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15

        // Align stack for Rust call (same reasoning as timer ISR above).
        sub rsp, 8
        mov rdi, qword ptr [rsp + 128] // err
        mov rsi, qword ptr [rsp + 136] // rip
        mov rdx, qword ptr [rsp + 144] // cs
        mov rcx, qword ptr [rsp + 152] // rflags
        call oneos_x86_pf_fault
        add rsp, 8
        test eax, eax
        jz 2f
        // saved rax is at [rsp + 14*8] = 112
        mov qword ptr [rsp + 112], -3
        mov rdx, qword ptr [rip + ONEOS_APP_ABORT_JMP]
        // interrupt frame rip (after error code) is at [rsp + 16*8] = 128
        mov qword ptr [rsp + 128], rdx
    2:
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        pop rdx
        pop rcx
        pop rax
        add rsp, 8 // drop error code
        iretq

        .global oneos_x86_isr_spurious
    oneos_x86_isr_spurious:
        // no error code: stack starts with RIP
        push rax
        push rcx
        push rdx
        push rbx
        push rbp
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15

        // Align stack for Rust call (same reasoning as timer ISR above).
        sub rsp, 8
        mov rdi, qword ptr [rsp + 128] // rip
        mov rsi, qword ptr [rsp + 136] // cs
        mov rdx, qword ptr [rsp + 144] // rflags
        call oneos_x86_spurious_irq
        add rsp, 8

        // EOI for PIC.
        mov al, 0x20
        out 0x20, al
        out 0xA0, al

        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        pop rdx
        pop rcx
        pop rax
        iretq
        "#
    );

    #[no_mangle]
    extern "C" fn oneos_x86_ud_fault(rip: u64, cs: u64, rflags: u64) -> u32 {
        serial::log_line_args(format_args!(
            "x86_64: #UD rip=0x{:x} cs=0x{:x} rflags=0x{:x}",
            rip, cs, rflags
        ));
        if crate::sandbox::current_domain_kind_or_kernel() == DomainKind::App
            && unsafe { core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_ABORT_JMP) } != 0
        {
            // If we ever switch CR3 for apps, restore the kernel CR3 before returning to the abort trampoline.
            let _ = crate::mmu::switch::x86_64_restore_kernel_space_for_trap();
            record_pending_fault(6, rip, 0, 0);
            return 1;
        }
        panic!(
            "x86_64: #UD in non-app domain (rip=0x{:x} cs=0x{:x} rflags=0x{:x})",
            rip, cs, rflags
        );
    }

    #[no_mangle]
    extern "C" fn oneos_x86_df_fault(err: u64, rip: u64, cs: u64, rflags: u64) {
        serial::log_line_args(format_args!(
            "x86_64: #DF err=0x{:x} rip=0x{:x} cs=0x{:x} rflags=0x{:x}",
            err, rip, cs, rflags
        ));
    }

    #[no_mangle]
    extern "C" fn oneos_timer_tick_x86() -> u32 {
        // Very small diagnostic to confirm PIT IRQ0 is actually firing before early reboots.
        // Keep it bounded to avoid flooding the serial console.
        static IRQ0_SEEN: AtomicU32 = AtomicU32::new(0);
        let n = IRQ0_SEEN.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if n <= 3 {
            serial::log_line_args(format_args!("x86_64: irq0 fired (n={})", n));
        }
        let should_abort = on_tick();
        let should_preempt = crate::sched::on_tick();
        if should_abort
            && crate::sandbox::current_domain_kind_or_kernel() == DomainKind::App
            && unsafe { core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_ABORT_JMP) } != 0
        {
            // Ensure the abort trampoline runs under the kernel CR3 if we ever switched CR3 for apps.
            let _ = crate::mmu::switch::x86_64_restore_kernel_space_for_trap();
        }
        (should_abort as u32) | ((should_preempt as u32) << 1)
    }

    #[no_mangle]
    extern "C" fn oneos_x86_gp_fault(err: u64, rip: u64, cs: u64, rflags: u64) -> u32 {
        serial::log_line_args(format_args!(
            "x86_64: #GP err=0x{:x} rip=0x{:x} cs=0x{:x} rflags=0x{:x}",
            err, rip, cs, rflags
        ));
        if crate::sandbox::current_domain_kind_or_kernel() == DomainKind::App
            && unsafe { core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_ABORT_JMP) } != 0
        {
            let _ = crate::mmu::switch::x86_64_restore_kernel_space_for_trap();
            record_pending_fault(13, rip, 0, err);
            return 1;
        }
        panic!(
            "x86_64: #GP in non-app domain (err=0x{:x} rip=0x{:x} cs=0x{:x} rflags=0x{:x})",
            err, rip, cs, rflags
        );
    }

    #[no_mangle]
    extern "C" fn oneos_x86_pf_fault(err: u64, rip: u64, cs: u64, rflags: u64) -> u32 {
        let mut cr2: u64 = 0;
        unsafe {
            core::arch::asm!(
                "mov {}, cr2",
                out(reg) cr2,
                options(nomem, nostack, preserves_flags)
            )
        };
        serial::log_line_args(format_args!(
            "x86_64: #PF err=0x{:x} rip=0x{:x} cr2=0x{:x} cs=0x{:x} rflags=0x{:x}",
            err, rip, cr2, cs, rflags
        ));
        if crate::sandbox::current_domain_kind_or_kernel() == DomainKind::App
            && unsafe { core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_ABORT_JMP) } != 0
        {
            let _ = crate::mmu::switch::x86_64_restore_kernel_space_for_trap();
            record_pending_fault(14, rip, cr2, err);
            return 1;
        }
        panic!(
            "x86_64: #PF in non-app domain (err=0x{:x} rip=0x{:x} cr2=0x{:x} cs=0x{:x} rflags=0x{:x})",
            err, rip, cr2, cs, rflags
        );
    }

    #[inline(always)]
    unsafe fn pic_read_isr(pic_cmd: u16) -> u8 {
        outb(pic_cmd, 0x0B); // OCW3: read ISR
        inb(pic_cmd)
    }

    #[inline(always)]
    unsafe fn pic_read_irr(pic_cmd: u16) -> u8 {
        outb(pic_cmd, 0x0A); // OCW3: read IRR
        inb(pic_cmd)
    }

    #[no_mangle]
    extern "C" fn oneos_x86_spurious_irq(rip: u64, cs: u64, rflags: u64) {
        let (isr1, irr1, isr2, irr2) = unsafe {
            (
                pic_read_isr(PIC1_COMMAND),
                pic_read_irr(PIC1_COMMAND),
                pic_read_isr(PIC2_COMMAND),
                pic_read_irr(PIC2_COMMAND),
            )
        };
        serial::log_line_args(format_args!(
            "x86_64: unexpected irq/exception rip=0x{:x} cs=0x{:x} rflags=0x{:x} PIC1(isr=0x{:02x} irr=0x{:02x}) PIC2(isr=0x{:02x} irr=0x{:02x})",
            rip, cs, rflags, isr1, irr1, isr2, irr2
        ));
    }

    #[inline(always)]
    unsafe fn outb(port: u16, val: u8) {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
    }

    #[inline(always)]
    unsafe fn inb(port: u16) -> u8 {
        let mut v: u8;
        core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags));
        v
    }

    unsafe fn pic_remap(offset1: u8, offset2: u8) {
        let a1 = inb(PIC1_DATA);
        let a2 = inb(PIC2_DATA);

        outb(PIC1_COMMAND, 0x11);
        outb(PIC2_COMMAND, 0x11);
        outb(PIC1_DATA, offset1);
        outb(PIC2_DATA, offset2);
        outb(PIC1_DATA, 4);
        outb(PIC2_DATA, 2);
        outb(PIC1_DATA, 0x01);
        outb(PIC2_DATA, 0x01);

        outb(PIC1_DATA, a1);
        outb(PIC2_DATA, a2);
    }

    unsafe fn pic_unmask_irq0() {
        let mut mask = inb(PIC1_DATA);
        mask &= !0x01;
        outb(PIC1_DATA, mask);
        // Ensure cascade line is enabled too.
        let mut mask2 = inb(PIC2_DATA);
        mask2 &= !0x04;
        outb(PIC2_DATA, mask2);
    }

    unsafe fn pit_set_hz(hz: u32) {
        let hz = hz.max(1);
        let divisor = (PIT_BASE_HZ / hz).max(1).min(0xFFFF) as u16;
        // Channel 0, lobyte/hibyte, mode 2 (rate generator), binary.
        outb(PIT_COMMAND, 0x34);
        outb(PIT_CHANNEL0, (divisor & 0xFF) as u8);
        outb(PIT_CHANNEL0, (divisor >> 8) as u8);
    }

    unsafe fn idt_set_gate(vec: usize, handler: u64, sel: u16) {
        let entry = &mut IDT[vec];
        entry.off_low = handler as u16;
        // We run in firmware-provided GDT/CS (e.g. UEFI uses CS=0x38 on QEMU).
        // Use the *current* CS selector to avoid triple-fault resets on the first IRQ.
        entry.sel = sel;
        entry.ist = 0;
        entry.attrs = 0x8E; // present, DPL=0, interrupt gate
        entry.off_mid = (handler >> 16) as u16;
        entry.off_high = (handler >> 32) as u32;
        entry.zero = 0;
    }

    unsafe fn lidt() {
        let idtr = Idtr {
            limit: (core::mem::size_of::<IdtEntry>() * IDT.len() - 1) as u16,
            base: IDT.as_ptr() as u64,
        };
        core::arch::asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }

    pub fn init() {
        // 100Hz tick by default (good enough for watchdog).
        let hz = 100u32;
        TICK_HZ.store(hz as u64, Ordering::Relaxed);

        unsafe {
            let cs: u16;
            core::arch::asm!("mov ax, cs", out("ax") cs, options(nomem, nostack, preserves_flags));
            serial::log_line_args(format_args!(
                "timer: x86_64 using CS=0x{:x} for IDT gates",
                cs
            ));

            // Trap handlers to avoid triple-fault reboot loops while still giving logs.
            idt_set_gate(6, oneos_x86_isr_ud as *const () as u64, cs);
            idt_set_gate(8, oneos_x86_isr_df as *const () as u64, cs);
            idt_set_gate(13, oneos_x86_isr_gp as *const () as u64, cs);
            idt_set_gate(14, oneos_x86_isr_pf as *const () as u64, cs);
            // Common spurious vectors (IRQ7=0x27, IRQ15=0x2F after remap).
            idt_set_gate(0x27, oneos_x86_isr_spurious as *const () as u64, cs);
            idt_set_gate(0x2F, oneos_x86_isr_spurious as *const () as u64, cs);
            idt_set_gate(32, oneos_x86_timer_isr as *const () as u64, cs);
            lidt();
            pic_remap(0x20, 0x28);
            pic_unmask_irq0();
            pit_set_hz(hz);
            // enable interrupts
            core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
        }
        serial::log_line("timer: x86_64 PIT tick enabled (100Hz)");
    }
}

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use super::{on_tick, APP_FAULT_RETURN_CODE, TICK_HZ, TIMEOUT_RETURN_CODE};
    use core::arch::global_asm;
    use core::sync::atomic::Ordering;
    use core::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

    use crate::drivers::serial;

    const EXC_STACK_SIZE: usize = 16 * 1024; // 16 KiB

    #[repr(align(16))]
    struct ExcStack([u8; EXC_STACK_SIZE]);

    // Dedicated exception stack for AArch64 (SP_EL0).
    // The vector entry stubs switch SPSel to 0 before saving registers so that a corrupted
    // SP_EL1 cannot cause a cascade of faults while trying to save the trap frame.
    #[no_mangle]
    static mut ONEOS_AARCH64_EXC_STACK: ExcStack = ExcStack([0u8; EXC_STACK_SIZE]);

    // Route B scaffold (Stage 1): TTBR1-fixed exception vector trampoline.
    // The raw aarch64 kernel may map this page at a fixed high VA (TTBR1) and point VBAR_EL1 to it.
    global_asm!(
        r#"
        .section .text.ttbr1_tramp,"ax"
        .align 12
        .global oneos_aarch64_ttbr1_vector_table
    oneos_aarch64_ttbr1_vector_table:
        // Current EL with SP0
        b oneos_aarch64_ttbr1_sync
        .space 0x7c
        b oneos_aarch64_ttbr1_irq
        .space 0x7c
        b oneos_aarch64_ttbr1_irq
        .space 0x7c
        b oneos_aarch64_ttbr1_sync
        .space 0x7c

        // Current EL with SPx
        b oneos_aarch64_ttbr1_sync
        .space 0x7c
        b oneos_aarch64_ttbr1_irq
        .space 0x7c
        b oneos_aarch64_ttbr1_irq
        .space 0x7c
        b oneos_aarch64_ttbr1_sync
        .space 0x7c

        // Lower EL: treat as bad (we do not run EL0/EL2)
        b oneos_aarch64_ttbr1_sync
        .space 0x7c
        b oneos_aarch64_ttbr1_sync
        .space 0x7c
        b oneos_aarch64_ttbr1_sync
        .space 0x7c
        b oneos_aarch64_ttbr1_sync
        .space 0x7c

        b oneos_aarch64_ttbr1_sync
        .space 0x7c
        b oneos_aarch64_ttbr1_sync
        .space 0x7c
        b oneos_aarch64_ttbr1_sync
        .space 0x7c
        b oneos_aarch64_ttbr1_sync
        .space 0x7c

    // x16/x17 are scratch; full handler saves them.
    oneos_aarch64_ttbr1_sync:
        // Restore kernel TTBR0 from TTBR1 trampoline state page: [kernel_ttbr0, app_ttbr0]
        ldr x16, =0xffff000000001000
        ldr x17, [x16]
        msr ttbr0_el1, x17
        dsb ish
        tlbi vmalle1
        dsb ish
        isb
        // Jump to the regular low-VA vector entry which saves regs and calls Rust.
        ldr x16, =oneos_aarch64_sync_entry
        br x16

    oneos_aarch64_ttbr1_irq:
        ldr x16, =0xffff000000001000
        ldr x17, [x16]
        msr ttbr0_el1, x17
        dsb ish
        tlbi vmalle1
        dsb ish
        isb
        ldr x16, =oneos_aarch64_irq_entry
        br x16
        "#
    );

    // QEMU virt (GICv2) default physical addresses.
    const GICD_BASE: usize = 0x0800_0000;
    const GICC_BASE: usize = 0x0801_0000;

    const GICD_CTLR: usize = 0x000;
    const GICD_ISENABLER0: usize = 0x100;
    const GICC_CTLR: usize = 0x000;
    const GICC_PMR: usize = 0x004;
    const GICC_IAR: usize = 0x00C;
    const GICC_EOIR: usize = 0x010;

    const INTID_CNTP: u32 = 30; // physical timer PPI

    global_asm!(
        r#"
        .section .text
	        .align 11
	        .global oneos_aarch64_vector_table
	    oneos_aarch64_vector_table:
        // Current EL with SP0 (rare for our code, but handle like SPx so App faults don't brick the system)
        b oneos_aarch64_sync
        .space 0x7c
        b oneos_aarch64_irq
        .space 0x7c
        // FIQ: treat as IRQ for now (no dedicated handler yet)
        b oneos_aarch64_irq
        .space 0x7c
        // SError: route through sync trap (fatal for Kernel, abort for App)
        b oneos_aarch64_sync
        .space 0x7c

        // Current EL with SPx
        b oneos_aarch64_sync
        .space 0x7c
        b oneos_aarch64_irq
        .space 0x7c
        // FIQ: treat as IRQ for now (no dedicated handler yet)
        b oneos_aarch64_irq
        .space 0x7c
        // SError: route through sync trap (fatal for Kernel, abort for App)
        b oneos_aarch64_sync
        .space 0x7c

        // Lower EL AArch64
        b oneos_aarch64_bad
        .space 0x7c
        b oneos_aarch64_bad
        .space 0x7c
        b oneos_aarch64_bad
        .space 0x7c
        b oneos_aarch64_bad
        .space 0x7c

        // Lower EL AArch32
        b oneos_aarch64_bad
        .space 0x7c
        b oneos_aarch64_bad
        .space 0x7c
        b oneos_aarch64_bad
        .space 0x7c
        b oneos_aarch64_bad
        .space 0x7c

	    oneos_aarch64_bad:
	        bl oneos_aarch64_bad_trap
	        b oneos_aarch64_bad

	        // Backward-compatible entry symbols referenced by the vector table.
	        .global oneos_aarch64_sync
	    oneos_aarch64_sync:
	        b oneos_aarch64_sync_entry

	        .global oneos_aarch64_irq
	    oneos_aarch64_irq:
	        b oneos_aarch64_irq_entry

	        .global oneos_aarch64_sync_entry
	    oneos_aarch64_sync_entry:
	        // Use SP_EL0 as dedicated exception stack (initialized in timer::init).
	        msr spsel, #0
	        // Save x0-x30 (x30=lr).
	        sub sp, sp, #(31*16)
	        stp x0, x1, [sp, #(0*16)]
	        stp x2, x3, [sp, #(1*16)]
        stp x4, x5, [sp, #(2*16)]
        stp x6, x7, [sp, #(3*16)]
        stp x8, x9, [sp, #(4*16)]
        stp x10, x11, [sp, #(5*16)]
        stp x12, x13, [sp, #(6*16)]
        stp x14, x15, [sp, #(7*16)]
        stp x16, x17, [sp, #(8*16)]
        stp x18, x19, [sp, #(9*16)]
        stp x20, x21, [sp, #(10*16)]
        stp x22, x23, [sp, #(11*16)]
        stp x24, x25, [sp, #(12*16)]
        stp x26, x27, [sp, #(13*16)]
        stp x28, x29, [sp, #(14*16)]
        str x30, [sp, #(15*16)]

        // Pass saved frame base to Rust handler.
        mov x0, sp
        bl oneos_aarch64_sync_trap

        // Restore regs.
        ldp x0, x1, [sp, #(0*16)]
        ldp x2, x3, [sp, #(1*16)]
        ldp x4, x5, [sp, #(2*16)]
        ldp x6, x7, [sp, #(3*16)]
        ldp x8, x9, [sp, #(4*16)]
        ldp x10, x11, [sp, #(5*16)]
        ldp x12, x13, [sp, #(6*16)]
        ldp x14, x15, [sp, #(7*16)]
        ldp x16, x17, [sp, #(8*16)]
        ldp x18, x19, [sp, #(9*16)]
        ldp x20, x21, [sp, #(10*16)]
        ldp x22, x23, [sp, #(11*16)]
        ldp x24, x25, [sp, #(12*16)]
        ldp x26, x27, [sp, #(13*16)]
        ldp x28, x29, [sp, #(14*16)]
        ldr x30, [sp, #(15*16)]
        add sp, sp, #(31*16)
        eret

	        .global oneos_aarch64_irq_entry
	    oneos_aarch64_irq_entry:
	        // Use SP_EL0 as dedicated exception stack (initialized in timer::init).
	        msr spsel, #0
	        // Save x0-x30 (x30=lr).
	        sub sp, sp, #(31*16)
	        stp x0, x1, [sp, #(0*16)]
	        stp x2, x3, [sp, #(1*16)]
        stp x4, x5, [sp, #(2*16)]
        stp x6, x7, [sp, #(3*16)]
        stp x8, x9, [sp, #(4*16)]
        stp x10, x11, [sp, #(5*16)]
        stp x12, x13, [sp, #(6*16)]
        stp x14, x15, [sp, #(7*16)]
        stp x16, x17, [sp, #(8*16)]
        stp x18, x19, [sp, #(9*16)]
        stp x20, x21, [sp, #(10*16)]
        stp x22, x23, [sp, #(11*16)]
        stp x24, x25, [sp, #(12*16)]
        stp x26, x27, [sp, #(13*16)]
        stp x28, x29, [sp, #(14*16)]
        str x30, [sp, #(15*16)]

        bl oneos_aarch64_timer_irq

        // Restore regs.
        ldp x0, x1, [sp, #(0*16)]
        ldp x2, x3, [sp, #(1*16)]
        ldp x4, x5, [sp, #(2*16)]
        ldp x6, x7, [sp, #(3*16)]
        ldp x8, x9, [sp, #(4*16)]
        ldp x10, x11, [sp, #(5*16)]
        ldp x12, x13, [sp, #(6*16)]
        ldp x14, x15, [sp, #(7*16)]
        ldp x16, x17, [sp, #(8*16)]
        ldp x18, x19, [sp, #(9*16)]
        ldp x20, x21, [sp, #(10*16)]
        ldp x22, x23, [sp, #(11*16)]
        ldp x24, x25, [sp, #(12*16)]
        ldp x26, x27, [sp, #(13*16)]
        ldp x28, x29, [sp, #(14*16)]
        ldr x30, [sp, #(15*16)]
        add sp, sp, #(31*16)
        eret
        "#
    );

    #[no_mangle]
    extern "C" fn oneos_aarch64_sync_trap(frame_sp: u64) {
        let mut esr: u64 = 0;
        let mut elr: u64 = 0;
        let mut far: u64 = 0;
        let mut sctlr: u64 = 0;
        unsafe {
            core::arch::asm!("mrs {0}, esr_el1", out(reg) esr, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mrs {0}, elr_el1", out(reg) elr, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mrs {0}, far_el1", out(reg) far, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mrs {0}, sctlr_el1", out(reg) sctlr, options(nomem, nostack, preserves_flags));
        }
        let ec = (esr >> 26) & 0x3f;
        let iss = esr & 0x01ff_ffff;
        let dfsc = iss & 0x3f;
        let wnr = (iss >> 6) & 1;
        let insn = unsafe { (elr as *const u32).read_volatile() as u64 };
        let dom = crate::sandbox::current_domain();
        let kind = crate::sandbox::current_domain_kind_or_kernel();
        let abort_jmp =
            unsafe { core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_ABORT_JMP) };

        serial::log_line_args(format_args!(
            "aarch64: sync trap esr=0x{:x} (ec=0x{:x} iss=0x{:x} dfsc=0x{:x} wnr={}) elr=0x{:x} insn=0x{:08x} far=0x{:x} sctlr=0x{:x} domain={} kind={:?}",
            esr, ec, iss, dfsc, wnr, elr, insn, far, sctlr, dom, kind
        ));

        if kind == crate::sandbox::DomainKind::App && abort_jmp != 0 {
            // If the AppDomain runs under its own TTBR0, restore the kernel TTBR0 first.
            // This ensures the abort trampoline, logging, and GOES/audit paths can run
            // even when the app address space is missing a mapping.
            let _ = crate::mmu::switch::aarch64_restore_kernel_space_for_trap();
            // Patch saved x0 in the trap frame so the wrapper restores it.
            unsafe {
                let x0_slot = frame_sp as *mut u64;
                x0_slot.write_volatile(APP_FAULT_RETURN_CODE as i64 as u64);
            }
            unsafe {
                core::arch::asm!(
                    "msr elr_el1, {0}",
                    in(reg) abort_jmp,
                    options(nomem, nostack, preserves_flags)
                );
            }
            serial::log_line_args(format_args!(
                "aarch64: app sync fault -> abort_jmp=0x{:x} ret={}",
                abort_jmp, APP_FAULT_RETURN_CODE
            ));
        } else if kind == crate::sandbox::DomainKind::SystemService {
            // System services must not hard-halt the whole machine.
            // Restore the kernel TTBR0 first (best-effort), then divert execution to a
            // safe abort handler that records a domain fault and exits the task.
            let _ = crate::mmu::switch::aarch64_restore_kernel_space_for_trap();
            unsafe {
                core::arch::asm!(
                    "msr elr_el1, {0}",
                    in(reg) (oneos_aarch64_systemservice_abort as *const () as u64),
                    options(nomem, nostack, preserves_flags)
                );
            }
            serial::log_line_args(format_args!(
                "aarch64: systemservice sync fault -> abort handler"
            ));
        } else {
            // Kernel/Shell faults are considered fatal for now.
            serial::log_line("aarch64: non-app sync fault; system halt");
            loop {
                core::hint::spin_loop();
            }
        }
    }

    #[no_mangle]
    extern "C" fn oneos_aarch64_systemservice_abort(_: usize) -> ! {
        // Runs in normal task context after the trap handler restores kernel TTBR0.
        // Keep it simple: record a fault and exit the current task.
        crate::sandbox::fault(
            crate::sandbox::FaultKind::InvalidMemoryAccess,
            "aarch64 sync fault in SystemService domain",
        );
        crate::sched::exit_current();
    }

    #[no_mangle]
    extern "C" fn oneos_aarch64_bad_trap() {
        // Best-effort diagnostics for unexpected exceptions (e.g. jumping to invalid app entry).
        // Keep it minimal: just log registers and spin.
        let mut esr: u64 = 0;
        let mut elr: u64 = 0;
        let mut far: u64 = 0;
        let mut sctlr: u64 = 0;
        let mut sp: u64 = 0;
        unsafe {
            core::arch::asm!("mrs {0}, esr_el1", out(reg) esr, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mrs {0}, elr_el1", out(reg) elr, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mrs {0}, far_el1", out(reg) far, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mrs {0}, sctlr_el1", out(reg) sctlr, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mov {0}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        let ec = (esr >> 26) & 0x3f;
        let iss = esr & 0x01ff_ffff;
        let dfsc = iss & 0x3f;
        let wnr = (iss >> 6) & 1;
        let insn = unsafe { (elr as *const u32).read_volatile() as u64 };
        let dom = crate::sandbox::current_domain();
        let abort_jmp =
            unsafe { core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_ABORT_JMP) };
        let dbg_entry =
            unsafe { core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_DEBUG_ENTRY) };
        let dbg_api =
            unsafe { core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_DEBUG_API) };
        let dbg_stack =
            unsafe { core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_DEBUG_STACK_TOP) };
        let dbg_sp_before =
            unsafe { core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_DEBUG_SP_BEFORE) };
        let dbg_sp_after = unsafe {
            core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_DEBUG_SP_AFTER_SET)
        };
        let last = crate::app::debug_last_call();
        serial::log_line_args(format_args!(
            "aarch64: exception trap esr=0x{:x} (ec=0x{:x} iss=0x{:x} dfsc=0x{:x} wnr={}) elr=0x{:x} insn=0x{:08x} far=0x{:x} sp=0x{:x} sctlr=0x{:x} domain={}",
            esr, ec, iss, dfsc, wnr, elr, insn, far, sp, sctlr, dom
        ));
        serial::log_line_args(format_args!(
            "aarch64: trap context abort_jmp=0x{:x} dbg(entry=0x{:x} api=0x{:x} stack=0x{:x} sp_before=0x{:x} sp_after=0x{:x}) last_abi(op={} dom={} ptr=0x{:x} len={} lr=0x{:x})",
            abort_jmp,
            dbg_entry,
            dbg_api,
            dbg_stack,
            dbg_sp_before,
            dbg_sp_after,
            last.op,
            last.domain,
            last.ptr,
            last.len,
            last.lr
        ));
        // Avoid spamming the log if we re-enter.
        loop {
            core::hint::spin_loop();
        }
    }

    #[no_mangle]
    extern "C" fn oneos_aarch64_timer_irq() {
        static IRQ_LOG_N: AtomicU32 = AtomicU32::new(0);
        unsafe {
            // NOTE: oneos_aarch64_irq saves GPRs on the current SP before calling here.
            // This is used for diagnostics when timeout-abort doesn't return to the shell.
            let mut sp: u64 = 0;
            core::arch::asm!("mov {0}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
            let saved_x0 = (sp as *const u64).read_volatile();

            let iar = mmio_read32(GICC_BASE + GICC_IAR);
            let intid = iar & 0x3ff;
            if intid == INTID_CNTP {
                let log_n = IRQ_LOG_N
                    .fetch_add(1, AtomicOrdering::Relaxed)
                    .saturating_add(1);
                if log_n <= 10 {
                    serial::log_line_args(format_args!(
                        "timer: aarch64 irq tick#{} enter (dom={} sp=0x{:x})",
                        log_n,
                        crate::sandbox::current_domain(),
                        sp
                    ));
                }
                let should_abort = on_tick();
                if log_n <= 10 {
                    serial::log_line_args(format_args!(
                        "timer: aarch64 irq tick#{} after watchdog on_tick abort={}",
                        log_n, should_abort
                    ));
                }
                let should_preempt = crate::sched::on_tick();
                if log_n <= 10 {
                    serial::log_line_args(format_args!(
                        "timer: aarch64 irq tick#{} after sched on_tick preempt={}",
                        log_n, should_preempt
                    ));
                }
                // Re-arm timer.
                program_timer();
                if should_abort {
                    // Restore kernel TTBR0 before returning to the abort trampoline.
                    let _ = crate::mmu::switch::aarch64_restore_kernel_space_for_trap();
                    // Redirect return address to abort-jump label and set x0 return code.
                    let jmp = core::ptr::read_volatile(&raw const crate::app::ONEOS_APP_ABORT_JMP);
                    serial::log_line_args(format_args!(
                        "timer: aborting app via elr_el1=0x{:x} ret={}",
                        jmp, TIMEOUT_RETURN_CODE
                    ));
                    serial::log_line_args(format_args!(
                        "timer: aarch64 irq frame sp=0x{:x} saved_x0=0x{:x} (note: irq stub restores x0 from frame)",
                        sp, saved_x0
                    ));
                    // Patch saved x0 in the IRQ frame so the wrapper restores it.
                    (sp as *mut u64).write_volatile(TIMEOUT_RETURN_CODE as i64 as u64);
                    core::arch::asm!(
                        "msr elr_el1, {elr}",
                        elr = in(reg) (jmp as u64),
                        options(nostack, preserves_flags)
                    );
                } else {
                    if should_preempt {
                        // Save the interrupted PC and redirect to the scheduler preempt trampoline.
                        let mut elr: u64 = 0;
                        core::arch::asm!(
                            "mrs {0}, elr_el1",
                            out(reg) elr,
                            options(nomem, nostack, preserves_flags)
                        );
                        crate::sched::request_preempt(elr);
                        extern "C" {
                            fn oneos_aarch64_sched_preempt() -> !;
                        }
                        let tramp = oneos_aarch64_sched_preempt as *const () as usize as u64;
                        core::arch::asm!(
                            "msr elr_el1, {0}",
                            in(reg) tramp,
                            options(nomem, nostack, preserves_flags)
                        );
                    }
                    // Route B scaffold: if we entered via the TTBR1 trampoline (AppDomain),
                    // switch TTBR0 back to the App address space before returning to user code.
                    let (_k, app_ttbr0) = crate::mmu::addrspace::ttbr1_tramp_state_get();
                    if matches!(
                        crate::sandbox::current_domain_kind_or_kernel(),
                        crate::sandbox::DomainKind::App | crate::sandbox::DomainKind::SystemService
                    ) && app_ttbr0 != 0
                    {
                        crate::mmu::aarch64::enter_ttbr0(app_ttbr0);
                    }
                }
                // EOI.
                mmio_write32(GICC_BASE + GICC_EOIR, iar);
                if IRQ_LOG_N.load(AtomicOrdering::Relaxed) <= 10 {
                    serial::log_line_args(format_args!(
                        "timer: aarch64 irq exit (intid=CNTP) dom={}",
                        crate::sandbox::current_domain()
                    ));
                }
                return;
            }
            // EOI for other interrupts too.
            mmio_write32(GICC_BASE + GICC_EOIR, iar);
        }
    }

    #[inline(always)]
    unsafe fn mmio_read32(addr: usize) -> u32 {
        (addr as *const u32).read_volatile()
    }

    #[inline(always)]
    unsafe fn mmio_write32(addr: usize, val: u32) {
        (addr as *mut u32).write_volatile(val);
    }

    unsafe fn gicv2_init() {
        // Enable distributor and CPU interface.
        mmio_write32(GICD_BASE + GICD_CTLR, 1);
        mmio_write32(GICC_BASE + GICC_PMR, 0xFF);
        mmio_write32(GICC_BASE + GICC_CTLR, 1);

        // Enable PPI 30 in ISENABLER0 (SGI/PPI).
        mmio_write32(GICD_BASE + GICD_ISENABLER0, 1u32 << INTID_CNTP);
    }

    unsafe fn program_timer() {
        let mut freq: u64;
        core::arch::asm!("mrs {0}, cntfrq_el0", out(reg) freq, options(nomem, nostack, preserves_flags));
        let hz = TICK_HZ.load(Ordering::Relaxed).max(1);
        let tval = (freq / hz).max(1);
        core::arch::asm!(
            "msr cntp_tval_el0, {tval}",
            "mov x0, #1",
            "msr cntp_ctl_el0, x0",
            tval = in(reg) (tval as u64),
            out("x0") _,
            options(nostack, preserves_flags)
        );
    }

    pub fn init() {
        // Default 100Hz tick.
        let hz = 100u64;
        TICK_HZ.store(hz, Ordering::Relaxed);

        unsafe {
            // Set up SP_EL0 as a dedicated exception stack. The entry stubs switch SPSel to 0.
            let exc_base = &raw const ONEOS_AARCH64_EXC_STACK as *const u8 as u64;
            let exc_top = exc_base + (EXC_STACK_SIZE as u64);
            core::arch::asm!(
                "msr sp_el0, {0}",
                in(reg) exc_top,
                options(nomem, nostack, preserves_flags)
            );

            // Set vector base.
            let base = if crate::mmu::aarch64::current_ttbr1_el1() != 0 {
                crate::mmu::addrspace::ttbr1_tramp_vector_va()
            } else {
                extern "C" {
                    static oneos_aarch64_vector_table: u8;
                }
                &oneos_aarch64_vector_table as *const u8 as u64
            };
            core::arch::asm!("msr vbar_el1, {0}", in(reg) base, options(nomem, nostack, preserves_flags));
            core::arch::asm!("isb", options(nomem, nostack, preserves_flags));

            gicv2_init();
            program_timer();

            // Enable IRQs (clear I bit).
            core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags));
        }

        serial::log_line("timer: aarch64 generic timer tick enabled (100Hz)");
    }
}
