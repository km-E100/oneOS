#![cfg(all(target_os = "none", target_arch = "x86_64"))]

use core::arch::global_asm;

use super::TaskContext;

extern "C" {
    fn oneos_x86_sched_start_first(ctx: *const TaskContext) -> !;
    fn oneos_x86_sched_yield();
    fn oneos_x86_sched_preempt() -> !;
}

pub unsafe fn start_first(ctx: *const TaskContext) -> ! {
    oneos_x86_sched_start_first(ctx)
}

pub unsafe fn yield_now() {
    oneos_x86_sched_yield()
}

#[allow(dead_code)]
pub unsafe fn preempt_trampoline_addr() -> u64 {
    oneos_x86_sched_preempt as usize as u64
}

#[no_mangle]
pub extern "C" fn task_bootstrap(task_id: u64) -> ! {
    super::oneos_sched_task_bootstrap(task_id)
}

global_asm!(
    r#"
    .intel_syntax noprefix
    .section .text

    // void oneos_x86_sched_start_first(const TaskContext* ctx) -> !
    .global oneos_x86_sched_start_first
oneos_x86_sched_start_first:
    cli
    // rdi = ctx
    mov rbx, rdi
    mov rsp, qword ptr [rbx + 16*8]        // rsp
    // Restore regs; keep rbx base until the end.
    mov rax, qword ptr [rbx + 0*8]
    mov rcx, qword ptr [rbx + 1*8]
    mov rdx, qword ptr [rbx + 2*8]
    // rbx restored last
    mov rbp, qword ptr [rbx + 4*8]
    mov rsi, qword ptr [rbx + 5*8]
    mov rdi, qword ptr [rbx + 6*8]
    mov r8,  qword ptr [rbx + 7*8]
    mov r9,  qword ptr [rbx + 8*8]
    mov r10, qword ptr [rbx + 9*8]
    mov r11, qword ptr [rbx + 10*8]
    mov r12, qword ptr [rbx + 11*8]
    mov r13, qword ptr [rbx + 12*8]
    mov r14, qword ptr [rbx + 13*8]
    mov r15, qword ptr [rbx + 14*8]
    // rflags
    push qword ptr [rbx + 18*8]
    popfq
    // Push target RIP as a return address and "return" into it.
    push qword ptr [rbx + 17*8]
    mov rbx, qword ptr [rbx + 3*8]
    ret

    .global oneos_x86_sched_yield
oneos_x86_sched_yield:
    cli
    // Save r11 on stack so we can use it as a base pointer.
    push r11
    // Load current ctx pointer into r11.
    mov r11, qword ptr [rip + ONEOS_SCHED_CURRENT_CTX]
    // Save rax first before using it as scratch.
    mov qword ptr [r11 + 0*8], rax
    // Save rip as the return address and rsp as at entry.
    mov rax, qword ptr [rsp + 8]
    mov qword ptr [r11 + 17*8], rax         // rip
    lea rax, [rsp + 8]                      // original rsp (before push r11)
    mov qword ptr [r11 + 16*8], rax         // rsp
    // Save regs (including original r11 from the pushed slot).
    mov qword ptr [r11 + 1*8], rcx
    mov qword ptr [r11 + 2*8], rdx
    mov qword ptr [r11 + 3*8], rbx
    mov qword ptr [r11 + 4*8], rbp
    mov qword ptr [r11 + 5*8], rsi
    mov qword ptr [r11 + 6*8], rdi
    mov qword ptr [r11 + 7*8], r8
    mov qword ptr [r11 + 8*8], r9
    mov qword ptr [r11 + 9*8], r10
    mov rax, qword ptr [rsp]                // original r11
    mov qword ptr [r11 + 10*8], rax
    mov qword ptr [r11 + 11*8], r12
    mov qword ptr [r11 + 12*8], r13
    mov qword ptr [r11 + 13*8], r14
    mov qword ptr [r11 + 14*8], r15
    pushfq
    pop rax
    mov qword ptr [r11 + 18*8], rax

    // Keep SysV stack alignment for the Rust call: we have pushed 8 bytes, so rsp%16==8.
    call oneos_sched_pick_next
    mov rbx, rax                             // next ctx base
    mov rsp, qword ptr [rbx + 16*8]

    mov rax, qword ptr [rbx + 0*8]
    mov rcx, qword ptr [rbx + 1*8]
    mov rdx, qword ptr [rbx + 2*8]
    mov rbp, qword ptr [rbx + 4*8]
    mov rsi, qword ptr [rbx + 5*8]
    mov rdi, qword ptr [rbx + 6*8]
    mov r8,  qword ptr [rbx + 7*8]
    mov r9,  qword ptr [rbx + 8*8]
    mov r10, qword ptr [rbx + 9*8]
    mov r11, qword ptr [rbx + 10*8]
    mov r12, qword ptr [rbx + 11*8]
    mov r13, qword ptr [rbx + 12*8]
    mov r14, qword ptr [rbx + 13*8]
    mov r15, qword ptr [rbx + 14*8]
    push qword ptr [rbx + 18*8]
    popfq
    mov rbx, qword ptr [rbx + 3*8]
    ret

    .global oneos_x86_sched_preempt
oneos_x86_sched_preempt:
    cli
    // Save r11 so we can use it as a base pointer.
    push r11
    mov r11, qword ptr [rip + ONEOS_SCHED_CURRENT_CTX]
    // Save original rax/r10 early (we will clobber them below).
    mov qword ptr [r11 + 0*8], rax
    mov qword ptr [r11 + 9*8], r10
    // Save original r11 from the pushed slot.
    mov r10, qword ptr [rsp]
    mov qword ptr [r11 + 10*8], r10
    // pc override provided by ONEOS_SCHED_PREEMPT_PC
    mov rax, qword ptr [rip + ONEOS_SCHED_PREEMPT_PC]
    mov qword ptr [r11 + 17*8], rax

    // Remove the saved r11 from the task stack and install the resume RIP as a return address.
    pop r10                                 // discard saved r11
    push rax                                // resume RIP
    mov qword ptr [r11 + 16*8], rsp         // rsp points to resume RIP

    // Save regs.
    mov qword ptr [r11 + 1*8], rcx
    mov qword ptr [r11 + 2*8], rdx
    mov qword ptr [r11 + 3*8], rbx
    mov qword ptr [r11 + 4*8], rbp
    mov qword ptr [r11 + 5*8], rsi
    mov qword ptr [r11 + 6*8], rdi
    mov qword ptr [r11 + 7*8], r8
    mov qword ptr [r11 + 8*8], r9
    mov qword ptr [r11 + 11*8], r12
    mov qword ptr [r11 + 12*8], r13
    mov qword ptr [r11 + 13*8], r14
    mov qword ptr [r11 + 14*8], r15
    pushfq
    pop rax
    mov qword ptr [r11 + 18*8], rax

    call oneos_sched_pick_next
    mov rbx, rax
    mov rsp, qword ptr [rbx + 16*8]

    mov rax, qword ptr [rbx + 0*8]
    mov rcx, qword ptr [rbx + 1*8]
    mov rdx, qword ptr [rbx + 2*8]
    mov rbp, qword ptr [rbx + 4*8]
    mov rsi, qword ptr [rbx + 5*8]
    mov rdi, qword ptr [rbx + 6*8]
    mov r8,  qword ptr [rbx + 7*8]
    mov r9,  qword ptr [rbx + 8*8]
    mov r10, qword ptr [rbx + 9*8]
    mov r11, qword ptr [rbx + 10*8]
    mov r12, qword ptr [rbx + 11*8]
    mov r13, qword ptr [rbx + 12*8]
    mov r14, qword ptr [rbx + 13*8]
    mov r15, qword ptr [rbx + 14*8]
    push qword ptr [rbx + 18*8]
    popfq
    mov rbx, qword ptr [rbx + 3*8]
    ret
    "#
);
