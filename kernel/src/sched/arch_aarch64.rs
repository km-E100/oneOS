#![cfg(all(target_os = "none", target_arch = "aarch64"))]

use core::arch::global_asm;

use super::TaskContext;

extern "C" {
    fn oneos_aarch64_sched_start_first(ctx: *const TaskContext) -> !;
    fn oneos_aarch64_sched_yield();
    fn oneos_aarch64_sched_preempt() -> !;
}

pub unsafe fn start_first(ctx: *const TaskContext) -> ! {
    oneos_aarch64_sched_start_first(ctx)
}

pub unsafe fn yield_now() {
    oneos_aarch64_sched_yield()
}

#[allow(dead_code)]
pub unsafe fn preempt_trampoline_addr() -> u64 {
    oneos_aarch64_sched_preempt as usize as u64
}

#[no_mangle]
pub extern "C" fn task_bootstrap(task_id: u64) -> ! {
    super::oneos_sched_task_bootstrap(task_id)
}

global_asm!(
    r#"
    .section .text
    .align 4

    // void oneos_aarch64_sched_start_first(const TaskContext* ctx) -> !
    .global oneos_aarch64_sched_start_first
oneos_aarch64_sched_start_first:
    // Disable IRQs during the switch.
    msr daifset, #2
    // Use x21 as the context base pointer (restored last).
    mov x21, x0

    // Install SP, ELR, and SPSR for the target task before restoring GPRs.
    ldr x22, [x21, #(31*8)]      // sp
    mov sp, x22
    ldr x22, [x21, #(32*8)]      // pc
    msr elr_el1, x22
    ldr x22, [x21, #(33*8)]      // spsr (PSTATE snapshot)
    msr spsr_el1, x22

    // Restore x0-x15
    ldp x0,  x1,  [x21, #(0*16)]
    ldp x2,  x3,  [x21, #(1*16)]
    ldp x4,  x5,  [x21, #(2*16)]
    ldp x6,  x7,  [x21, #(3*16)]
    ldp x8,  x9,  [x21, #(4*16)]
    ldp x10, x11, [x21, #(5*16)]
    ldp x12, x13, [x21, #(6*16)]
    ldp x14, x15, [x21, #(7*16)]

    // Restore x16-x20 and x23-x30. Keep x21/x22 as scratch until the end.
    ldp x16, x17, [x21, #(16*8)]
    ldp x18, x19, [x21, #(18*8)]
    ldr x20, [x21, #(20*8)]
    ldp x23, x24, [x21, #(23*8)]
    ldp x25, x26, [x21, #(25*8)]
    ldp x27, x28, [x21, #(27*8)]
    ldr x29, [x21, #(29*8)]
    ldr x30, [x21, #(30*8)]

    // Restore x22 and x21 last.
    ldr x22, [x21, #(22*8)]
    ldr x21, [x21, #(21*8)]
    eret

    // yield trampoline (called as a function; does not return directly)
    .global oneos_aarch64_sched_yield
oneos_aarch64_sched_yield:
    // Disable IRQs during the switch.
    msr daifset, #2

    // Save x16/x17 on stack so we can use them as scratch without losing task state.
    stp x16, x17, [sp, #-16]!
    // Load current ctx pointer into x16.
    adrp x16, ONEOS_SCHED_CURRENT_CTX
    add  x16, x16, :lo12:ONEOS_SCHED_CURRENT_CTX
    ldr  x16, [x16]
    // Save original SP (before pushing x16/x17).
    add x17, sp, #16
    str x17, [x16, #(31*8)]
    // Save resume PC as return address in x30 (LR).
    str x30, [x16, #(32*8)]

    // Save x0-x15
    stp x0,  x1,  [x16, #(0*16)]
    stp x2,  x3,  [x16, #(1*16)]
    stp x4,  x5,  [x16, #(2*16)]
    stp x6,  x7,  [x16, #(3*16)]
    stp x8,  x9,  [x16, #(4*16)]
    stp x10, x11, [x16, #(5*16)]
    stp x12, x13, [x16, #(6*16)]
    stp x14, x15, [x16, #(7*16)]

    // Save x16/x17 original values from the pushed pair.
    ldp x0, x1, [sp]             // x0=orig x16, x1=orig x17
    str x0, [x16, #(16*8)]
    str x1, [x16, #(17*8)]

    // Save x18-x30 (x30 already saved as pc too, but keep full register set).
    stp x18, x19, [x16, #(18*8)]
    stp x20, x21, [x16, #(20*8)]
    stp x22, x23, [x16, #(22*8)]
    stp x24, x25, [x16, #(24*8)]
    stp x26, x27, [x16, #(26*8)]
    stp x28, x29, [x16, #(28*8)]
    str x30, [x16, #(30*8)]

    // Save PSTATE snapshot (NZCV + EL1h mode).
    mrs x0, nzcv
    mov x1, #0x5
    orr x0, x0, x1
    str x0, [x16, #(33*8)]

    // Call Rust picker: returns next TaskContext* in x0.
    bl oneos_sched_pick_next
    mov x21, x0                  // base = next ctx (restored last)

    // Install SP, ELR, and SPSR for the target task.
    ldr x22, [x21, #(31*8)]
    mov sp, x22
    ldr x22, [x21, #(32*8)]
    msr elr_el1, x22
    ldr x22, [x21, #(33*8)]
    msr spsr_el1, x22

    // Restore x0-x15
    ldp x0,  x1,  [x21, #(0*16)]
    ldp x2,  x3,  [x21, #(1*16)]
    ldp x4,  x5,  [x21, #(2*16)]
    ldp x6,  x7,  [x21, #(3*16)]
    ldp x8,  x9,  [x21, #(4*16)]
    ldp x10, x11, [x21, #(5*16)]
    ldp x12, x13, [x21, #(6*16)]
    ldp x14, x15, [x21, #(7*16)]

    // Restore x16-x20 and x23-x30. Keep x21/x22 as scratch until the end.
    ldp x16, x17, [x21, #(16*8)]
    ldp x18, x19, [x21, #(18*8)]
    ldr x20, [x21, #(20*8)]
    ldp x23, x24, [x21, #(23*8)]
    ldp x25, x26, [x21, #(25*8)]
    ldp x27, x28, [x21, #(27*8)]
    ldr x29, [x21, #(29*8)]
    ldr x30, [x21, #(30*8)]

    // Restore x22 and x21 last.
    ldr x22, [x21, #(22*8)]
    ldr x21, [x21, #(21*8)]
    eret

    // preempt trampoline (entered by modifying ELR_EL1 to this address)
    .global oneos_aarch64_sched_preempt
oneos_aarch64_sched_preempt:
    msr daifset, #2
    // Preserve x16/x17.
    stp x16, x17, [sp, #-16]!
    adrp x16, ONEOS_SCHED_CURRENT_CTX
    add  x16, x16, :lo12:ONEOS_SCHED_CURRENT_CTX
    ldr  x16, [x16]
    add x17, sp, #16
    str x17, [x16, #(31*8)]
    // pc override is provided by ONEOS_SCHED_PREEMPT_PC (set by timer ISR).
    adrp x17, ONEOS_SCHED_PREEMPT_PC
    add  x17, x17, :lo12:ONEOS_SCHED_PREEMPT_PC
    ldr  x17, [x17]
    str x17, [x16, #(32*8)]

    // Save x0-x15
    stp x0,  x1,  [x16, #(0*16)]
    stp x2,  x3,  [x16, #(1*16)]
    stp x4,  x5,  [x16, #(2*16)]
    stp x6,  x7,  [x16, #(3*16)]
    stp x8,  x9,  [x16, #(4*16)]
    stp x10, x11, [x16, #(5*16)]
    stp x12, x13, [x16, #(6*16)]
    stp x14, x15, [x16, #(7*16)]

    // Save original x16/x17 from the pushed pair.
    ldp x0, x1, [sp]
    str x0, [x16, #(16*8)]
    str x1, [x16, #(17*8)]

    // Save x18-x30
    stp x18, x19, [x16, #(18*8)]
    stp x20, x21, [x16, #(20*8)]
    stp x22, x23, [x16, #(22*8)]
    stp x24, x25, [x16, #(24*8)]
    stp x26, x27, [x16, #(26*8)]
    stp x28, x29, [x16, #(28*8)]
    str x30, [x16, #(30*8)]

    // Save PSTATE snapshot (NZCV + EL1h mode).
    mrs x0, nzcv
    mov x1, #0x5
    orr x0, x0, x1
    str x0, [x16, #(33*8)]

    bl oneos_sched_pick_next
    mov x21, x0
    ldr x22, [x21, #(31*8)]
    mov sp, x22
    ldr x22, [x21, #(32*8)]
    msr elr_el1, x22
    ldr x22, [x21, #(33*8)]
    msr spsr_el1, x22

    ldp x0,  x1,  [x21, #(0*16)]
    ldp x2,  x3,  [x21, #(1*16)]
    ldp x4,  x5,  [x21, #(2*16)]
    ldp x6,  x7,  [x21, #(3*16)]
    ldp x8,  x9,  [x21, #(4*16)]
    ldp x10, x11, [x21, #(5*16)]
    ldp x12, x13, [x21, #(6*16)]
    ldp x14, x15, [x21, #(7*16)]

    ldp x16, x17, [x21, #(16*8)]
    ldp x18, x19, [x21, #(18*8)]
    ldr x20, [x21, #(20*8)]
    ldp x23, x24, [x21, #(23*8)]
    ldp x25, x26, [x21, #(25*8)]
    ldp x27, x28, [x21, #(27*8)]
    ldr x29, [x21, #(29*8)]
    ldr x30, [x21, #(30*8)]

    ldr x22, [x21, #(22*8)]
    ldr x21, [x21, #(21*8)]
    eret
    "#
);
