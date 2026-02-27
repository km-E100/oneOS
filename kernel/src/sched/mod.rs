#![cfg(target_os = "none")]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::drivers::serial;
use crate::sync::spinlock::IrqSpinLock;
use spin::Once;

#[cfg(target_arch = "aarch64")]
mod arch_aarch64;
#[cfg(target_arch = "x86_64")]
mod arch_x86_64;

pub type TaskId = usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Sleeping,
    Blocked,
    Exited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    High = 0,
    Normal = 1,
}

#[repr(C)]
pub struct TaskContext {
    #[cfg(target_arch = "aarch64")]
    regs: [u64; 31], // x0..x30
    #[cfg(target_arch = "aarch64")]
    sp: u64,
    #[cfg(target_arch = "aarch64")]
    pc: u64,
    #[cfg(target_arch = "aarch64")]
    spsr: u64,

    #[cfg(target_arch = "x86_64")]
    regs: [u64; 16], // rax,rcx,rdx,rbx,rbp,rsi,rdi,r8..r15 (in this order)
    #[cfg(target_arch = "x86_64")]
    rsp: u64,
    #[cfg(target_arch = "x86_64")]
    rip: u64,
    #[cfg(target_arch = "x86_64")]
    rflags: u64,
}

impl TaskContext {
    const fn zeroed() -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            Self {
                regs: [0; 31],
                sp: 0,
                pc: 0,
                spsr: 0x5, // EL1h, interrupts enabled
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                regs: [0; 16],
                rsp: 0,
                rip: 0,
                rflags: 0x202, // IF=1 by default
            }
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            // Unsupported arch build should not include sched.
            Self {}
        }
    }
}

struct Task {
    id: TaskId,
    name: &'static str,
    priority: Priority,
    state: TaskState,
    domain_id: u32,
    domain_kind: crate::sandbox::DomainKind,
    // Scheduling
    slice_left: u32,
    // Sleep
    wake_tick: u64,
    // Execution
    entry: extern "C" fn(usize) -> !,
    arg: usize,
    ctx: TaskContext,
    mmu_root: u64,
    stack_ptr: *mut u8,
    stack_layout: Layout,
}

// Kernel-only scheduler data structures guarded by a spin lock.
// `Task` contains raw pointers into the kernel heap; moving it across cores/threads is safe
// in this single-core bring-up stage as long as access is synchronized.
unsafe impl Send for Task {}

const DEFAULT_STACK_SIZE: usize = 64 * 1024;
const TIME_SLICE_TICKS: u32 = 3;

static NEXT_TASK_ID: AtomicUsize = AtomicUsize::new(1);
static STARTED: AtomicBool = AtomicBool::new(false);

static PREEMPT_PENDING: AtomicBool = AtomicBool::new(false);
#[no_mangle]
pub static ONEOS_SCHED_PREEMPT_PC: AtomicU64 = AtomicU64::new(0);

// Global current task context pointer used by arch trampolines.
#[no_mangle]
pub static ONEOS_SCHED_CURRENT_CTX: AtomicU64 = AtomicU64::new(0);

// Prevent re-entrant scheduling.
static IN_SWITCH: AtomicBool = AtomicBool::new(false);

struct SchedState {
    tasks: Vec<Box<Task>>,
    runq: [VecDeque<TaskId>; 2],
    current: Option<TaskId>,
    high_credit: u8,
}

impl SchedState {
    fn new() -> Self {
        Self {
            tasks: Vec::new(),
            runq: [VecDeque::new(), VecDeque::new()],
            current: None,
            high_credit: HIGH_QUOTA,
        }
    }

    fn ensure_runq_capacity_locked(&mut self) {
        // NOTE: Scheduler tick + preemption runs in timer IRQ context, so queue growth must happen
        // from non-IRQ paths (spawn) while interrupts are disabled.
        let desired = self.tasks.len().saturating_add(8);
        for q in self.runq.iter_mut() {
            if q.capacity() < desired {
                q.reserve(desired.saturating_sub(q.capacity()));
            }
        }
    }

    fn pop_ready_from(&mut self, idx: usize) -> Option<TaskId> {
        let q = &mut self.runq[idx];
        while let Some(id) = q.pop_front() {
            let Some(t) = self.tasks.iter().find(|t| t.id == id) else {
                continue;
            };
            if t.state == TaskState::Ready {
                return Some(id);
            }
        }
        None
    }

    fn record_pick(&mut self, idx: usize) {
        if idx == Priority::High as usize {
            self.high_credit = self.high_credit.saturating_sub(1);
        } else {
            self.high_credit = HIGH_QUOTA;
        }
    }

    fn enqueue(&mut self, id: TaskId) {
        let Some(t) = self.tasks.iter().find(|t| t.id == id) else {
            return;
        };
        let idx = t.priority as usize;
        if !self.runq[idx].iter().any(|x| *x == id) {
            if self.runq[idx].len() >= self.runq[idx].capacity() {
                serial::log_line_args(format_args!(
                    "sched: runq overflow (prio={:?} len={} cap={} tasks={})",
                    t.priority,
                    self.runq[idx].len(),
                    self.runq[idx].capacity(),
                    self.tasks.len()
                ));
                panic!("sched: runq overflow");
            }
            self.runq[idx].push_back(id);
        }
    }

    fn dequeue_next(&mut self) -> Option<TaskId> {
        // Starvation-free policy (2 levels):
        // - Prefer High, but after HIGH_QUOTA consecutive High picks, force a Normal pick (if any).
        let (first, second) = if self.high_credit == 0 {
            (Priority::Normal as usize, Priority::High as usize)
        } else {
            (Priority::High as usize, Priority::Normal as usize)
        };

        if let Some(id) = self.pop_ready_from(first) {
            self.record_pick(first);
            return Some(id);
        }
        if let Some(id) = self.pop_ready_from(second) {
            self.record_pick(second);
            return Some(id);
        }
        None
    }
}

static SCHED: Once<IrqSpinLock<SchedState>> = Once::new();

fn sched() -> &'static IrqSpinLock<SchedState> {
    SCHED.call_once(|| IrqSpinLock::new(SchedState::new()))
}

static KERNEL_MMU_ROOT: AtomicU64 = AtomicU64::new(0);

const HIGH_QUOTA: u8 = 3;

pub fn kernel_mmu_root() -> u64 {
    KERNEL_MMU_ROOT.load(Ordering::SeqCst)
}

#[cfg(target_arch = "aarch64")]
fn read_mmu_root() -> u64 {
    crate::mmu::aarch64::read_ttbr0_el1()
}

#[cfg(target_arch = "x86_64")]
fn read_mmu_root() -> u64 {
    crate::mmu::x86_64::current_cr3()
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
fn read_mmu_root() -> u64 {
    0
}

#[cfg(target_arch = "aarch64")]
fn write_mmu_root(root: u64) {
    if root != 0 && crate::mmu::aarch64::is_enabled() {
        crate::mmu::aarch64::enter_ttbr0(root);
    }
}

#[cfg(target_arch = "x86_64")]
fn write_mmu_root(root: u64) {
    if root != 0 && crate::mmu::x86_64::is_paging_enabled() {
        unsafe { crate::mmu::x86_64::write_cr3(root) };
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
fn write_mmu_root(_: u64) {}

extern "C" fn idle_entry(_: usize) -> ! {
    loop {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        core::hint::spin_loop();
    }
}

extern "C" fn reaper_entry(_: usize) -> ! {
    loop {
        reap_exited_tasks();
        // Keep it low frequency; stage-2 brings only a few tasks.
        sleep_ticks(50);
    }
}

fn reap_exited_tasks() {
    let mut sched = sched().lock();
    let current = sched.current;
    let mut i = 0usize;
    while i < sched.tasks.len() {
        let t = &sched.tasks[i];
        let keep = Some(t.id) == current
            || t.state != TaskState::Exited
            || t.name == "idle"
            || t.name == "reaper";
        if keep {
            i += 1;
            continue;
        }
        let mut t = sched.tasks.remove(i);
        unsafe {
            alloc::alloc::dealloc(t.stack_ptr, t.stack_layout);
        }
        serial::log_line_args(format_args!("sched: reaped task {}", t.id));
    }
}

pub fn init() {
    let mut sched = sched().lock();
    if !sched.tasks.is_empty() {
        return;
    }
    KERNEL_MMU_ROOT.store(read_mmu_root(), Ordering::SeqCst);
    let idle = spawn_inner_locked(
        &mut sched,
        "idle",
        1,
        crate::sandbox::DomainKind::Kernel,
        Priority::Normal,
        idle_entry,
        0,
        true,
    );
    let _reaper = spawn_inner_locked(
        &mut sched,
        "reaper",
        1,
        crate::sandbox::DomainKind::Kernel,
        Priority::Normal,
        reaper_entry,
        0,
        false,
    );
    sched.current = Some(idle);
    serial::log_line_args(format_args!("sched: init ok (idle={})", idle));
}

pub fn spawn_kernel_thread(
    name: &'static str,
    priority: Priority,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
) -> TaskId {
    spawn_domain_thread(name, 1, priority, entry, arg)
}

pub fn spawn_domain_thread(
    name: &'static str,
    domain_id: u32,
    priority: Priority,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
) -> TaskId {
    // DomainKind is maintained via a lock-free snapshot; keep the read outside the scheduler lock
    // to avoid inflating the critical section and to preserve historical lock ordering comments.
    let domain_kind = crate::sandbox::domain_kind_snapshot(domain_id as crate::sandbox::DomainId);
    let mut sched = sched().lock();
    spawn_inner_locked(
        &mut sched,
        name,
        domain_id,
        domain_kind,
        priority,
        entry,
        arg,
        false,
    )
}

fn spawn_inner_locked(
    sched: &mut SchedState,
    name: &'static str,
    domain_id: u32,
    domain_kind: crate::sandbox::DomainKind,
    priority: Priority,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
    is_idle: bool,
) -> TaskId {
    let id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
    if name == "irq-work" {
        serial::log_line("sched: spawn irq-work: begin");
    }
    let stack_layout = Layout::from_size_align(DEFAULT_STACK_SIZE, 16).expect("stack layout");
    if name == "irq-work" {
        serial::log_line_args(format_args!(
            "sched: spawn irq-work: stack alloc size=0x{:x}",
            DEFAULT_STACK_SIZE
        ));
    }
    let stack_ptr = unsafe { alloc::alloc::alloc(stack_layout) };
    if stack_ptr.is_null() {
        panic!("sched: OOM allocating stack");
    }
    let stack_top = unsafe { stack_ptr.add(DEFAULT_STACK_SIZE) } as u64;
    if name == "irq-work" {
        serial::log_line_args(format_args!(
            "sched: spawn irq-work: stack ok ptr=0x{:x}",
            stack_ptr as usize
        ));
    }

    let mut ctx = TaskContext::zeroed();
    #[cfg(target_arch = "aarch64")]
    {
        ctx.sp = stack_top & !0xf;
        ctx.pc = arch_aarch64::task_bootstrap as usize as u64;
        ctx.regs[0] = id as u64; // x0 = task id
    }
    #[cfg(target_arch = "x86_64")]
    {
        ctx.rsp = stack_top & !0xf;
        ctx.rip = arch_x86_64::task_bootstrap as usize as u64;
        // rdi is the first arg in SysV ABI.
        ctx.regs[6] = id as u64;
    }

    let task = Box::new(Task {
        id,
        name,
        priority,
        state: if is_idle {
            TaskState::Ready
        } else {
            TaskState::Ready
        },
        domain_id,
        domain_kind,
        slice_left: TIME_SLICE_TICKS,
        wake_tick: 0,
        entry,
        arg,
        ctx,
        mmu_root: read_mmu_root(),
        stack_ptr,
        stack_layout,
    });
    sched.tasks.push(task);
    sched.ensure_runq_capacity_locked();
    if !is_idle {
        sched.enqueue(id);
    } else {
        // idle is always runnable; keep it at the back of normal queue.
        sched.enqueue(id);
    }
    serial::log_line_args(format_args!(
        "sched: spawn id={} name={} dom={} prio={:?}",
        id, name, domain_id, priority
    ));
    if name == "irq-work" {
        serial::log_line("sched: spawn irq-work: done");
    }
    id
}

#[no_mangle]
extern "C" fn oneos_sched_task_bootstrap(task_id: u64) -> ! {
    let id = task_id as usize;
    let (entry, arg) = {
        let sched = sched().lock();
        let Some(t) = sched.tasks.iter().find(|t| t.id == id) else {
            panic!("sched: bootstrap missing task {}", id);
        };
        (t.entry, t.arg)
    };
    entry(arg)
}

fn update_ttbr1_tramp_state(domain: u32, mmu_root: u64) {
    #[cfg(target_arch = "aarch64")]
    {
        if !crate::mmu::aarch64::is_enabled() {
            return;
        }
        let kernel = KERNEL_MMU_ROOT.load(Ordering::SeqCst);
        let mut app_ttbr0 = 0u64;
        if domain > 2 {
            let kind = crate::sandbox::current_domain_kind_or_kernel();
            if matches!(
                kind,
                crate::sandbox::DomainKind::App | crate::sandbox::DomainKind::SystemService
            ) && mmu_root != 0
                && mmu_root != kernel
            {
                app_ttbr0 = mmu_root;
            }
        }
        crate::mmu::addrspace::ttbr1_tramp_state_set(kernel, app_ttbr0);
    }
}

pub fn notify_mmu_root_changed(new_root: u64) {
    let mut sched = sched().lock();
    let Some(cur) = sched.current else { return };
    let Some(t) = sched.tasks.iter_mut().find(|t| t.id == cur) else {
        return;
    };
    t.mmu_root = new_root;
    // Best-effort: keep TTBR1 trampoline return target consistent for App/SystemService domains.
    update_ttbr1_tramp_state(t.domain_id, new_root);
}

/// Best-effort: update the currently running task's `domain_id` and `domain_kind`.
///
/// Used by `sandbox::set_current_domain()` so explicit domain switches are immediately reflected
/// in the scheduler's per-task record (and survive preemption/resume).
pub fn try_set_current_task_domain(domain: u32, kind: crate::sandbox::DomainKind) {
    // Avoid locking during a context switch.
    if IN_SWITCH.load(Ordering::SeqCst) {
        return;
    }
    let Some(lock) = SCHED.get() else { return };
    let mut sched = lock.lock();
    let Some(cur) = sched.current else { return };
    if let Some(t) = sched.tasks.iter_mut().find(|t| t.id == cur) {
        t.domain_id = domain;
        t.domain_kind = kind;
    }
}

pub fn on_domain_stopped(domain: u32) {
    let Some(lock) = SCHED.get() else { return };
    let mut sched = lock.lock();
    for t in sched.tasks.iter_mut() {
        if t.domain_id == domain && t.name != "idle" && t.name != "reaper" {
            if t.state != TaskState::Exited {
                t.state = TaskState::Blocked;
            }
        }
    }
}

pub fn on_domain_killed(domain: u32) {
    let Some(lock) = SCHED.get() else { return };
    let mut sched = lock.lock();
    for t in sched.tasks.iter_mut() {
        if t.domain_id == domain && t.name != "idle" && t.name != "reaper" {
            t.state = TaskState::Exited;
        }
    }
}

/// Start scheduling by switching to the first runnable task (never returns).
pub fn start() -> ! {
    if STARTED.swap(true, Ordering::SeqCst) {
        panic!("sched: start called twice");
    }
    let next = {
        let mut sched = sched().lock();
        let next = sched.dequeue_next().unwrap_or_else(|| {
            // Fallback to idle.
            sched
                .tasks
                .iter()
                .find(|t| t.name == "idle")
                .map(|t| t.id)
                .unwrap()
        });
        if let Some(t) = sched.tasks.iter_mut().find(|t| t.id == next) {
            t.state = TaskState::Running;
            t.slice_left = TIME_SLICE_TICKS;
        }
        next
    };
    serial::log_line_args(format_args!("sched: start -> task {}", next));
    let (ctx_ptr, domain_id, domain_kind, mmu_root) = {
        let mut sched = sched().lock();
        sched.current = Some(next);
        let pos = sched
            .tasks
            .iter()
            .position(|t| t.id == next)
            .unwrap_or_else(|| panic!("sched: missing start task {}", next));
        let t = &mut sched.tasks[pos];
        let ctx_ptr = &mut t.ctx as *mut TaskContext as u64;
        (ctx_ptr, t.domain_id, t.domain_kind, t.mmu_root)
    };
    ONEOS_SCHED_CURRENT_CTX.store(ctx_ptr, Ordering::SeqCst);
    crate::sandbox::set_current_domain_raw_with_kind(
        domain_id as crate::sandbox::DomainId,
        domain_kind,
    );
    write_mmu_root(mmu_root);
    update_ttbr1_tramp_state(domain_id, mmu_root);
    unsafe { arch_start_first() }
}

unsafe fn arch_start_first() -> ! {
    let ctx = ONEOS_SCHED_CURRENT_CTX.load(Ordering::SeqCst) as *const TaskContext;
    #[cfg(target_arch = "aarch64")]
    {
        arch_aarch64::start_first(ctx)
    }
    #[cfg(target_arch = "x86_64")]
    {
        arch_x86_64::start_first(ctx)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        loop {
            core::hint::spin_loop();
        }
    }
}

pub fn yield_now() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        arch_aarch64::yield_now();
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        arch_x86_64::yield_now();
    }
}

pub fn sleep_ticks(ticks: u64) {
    if ticks == 0 {
        yield_now();
        return;
    }
    let wake = crate::timer::ticks().saturating_add(ticks);
    {
        let mut sched = sched().lock();
        let Some(cur) = sched.current else { return };
        if let Some(t) = sched.tasks.iter_mut().find(|t| t.id == cur) {
            t.state = TaskState::Sleeping;
            t.wake_tick = wake;
        }
    }
    yield_now();
}

pub fn current_task_id() -> Option<TaskId> {
    let sched = sched().lock();
    sched.current
}

pub fn block_current() {
    let mut sched = sched().lock();
    let Some(cur) = sched.current else { return };
    if let Some(t) = sched.tasks.iter_mut().find(|t| t.id == cur) {
        t.state = TaskState::Blocked;
    }
}

pub fn wake_task(id: TaskId) {
    let mut sched = sched().lock();
    if let Some(t) = sched.tasks.iter_mut().find(|t| t.id == id) {
        if matches!(t.state, TaskState::Blocked | TaskState::Sleeping) {
            t.state = TaskState::Ready;
            t.wake_tick = 0;
            sched.enqueue(id);
        }
    }
}

pub fn exit_current() -> ! {
    let cur = {
        let sched = sched().lock();
        sched.current
    };
    if let Some(cur) = cur {
        let mut sched = sched().lock();
        if let Some(t) = sched.tasks.iter_mut().find(|t| t.id == cur) {
            t.state = TaskState::Exited;
        }
    }
    yield_now();
    loop {
        core::hint::spin_loop();
    }
}

/// Called from the timer ISR: update time slice, wake sleepers, and request preemption.
pub fn on_tick() -> bool {
    static LOG_N: AtomicUsize = AtomicUsize::new(0);
    let now = crate::timer::ticks();
    {
        let mut sched = sched().lock();
        let log_n = LOG_N.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if log_n <= 10 {
            serial::log_line_args(format_args!(
                "sched: on_tick#{} now={} dom={} cur={:?} runq_len=[{},{}] runq_cap=[{},{}] tasks={}",
                log_n,
                now,
                crate::sandbox::current_domain(),
                sched.current,
                sched.runq[0].len(),
                sched.runq[1].len(),
                sched.runq[0].capacity(),
                sched.runq[1].capacity(),
                sched.tasks.len(),
            ));
        }
        // NOTE: This function is called from the timer IRQ. Keep it allocation-free.
        let mut i = 0usize;
        while i < sched.tasks.len() {
            let (wake, id) = {
                let t = &mut sched.tasks[i];
                if t.state == TaskState::Sleeping && t.wake_tick != 0 && now >= t.wake_tick {
                    t.state = TaskState::Ready;
                    t.wake_tick = 0;
                    (true, t.id)
                } else {
                    (false, 0)
                }
            };
            if wake {
                // Enqueue once; the queue has its capacity grown from non-IRQ spawn paths.
                sched.enqueue(id);
            }
            i += 1;
        }
        let Some(cur) = sched.current else {
            return false;
        };
        let Some(t) = sched.tasks.iter_mut().find(|t| t.id == cur) else {
            return false;
        };
        if t.state != TaskState::Running {
            return false;
        }
        if t.slice_left > 0 {
            t.slice_left -= 1;
        }
        if t.slice_left == 0 {
            t.slice_left = TIME_SLICE_TICKS;
            return true;
        }
    }
    false
}

pub fn request_preempt(pc: u64) {
    ONEOS_SCHED_PREEMPT_PC.store(pc, Ordering::SeqCst);
    PREEMPT_PENDING.store(true, Ordering::SeqCst);
}

pub fn preempt_pending() -> bool {
    PREEMPT_PENDING.load(Ordering::SeqCst)
}

#[no_mangle]
extern "C" fn oneos_sched_pick_next() -> *const TaskContext {
    if IN_SWITCH.swap(true, Ordering::SeqCst) {
        // Nested: keep running current.
        return ONEOS_SCHED_CURRENT_CTX.load(Ordering::SeqCst) as *const TaskContext;
    }

    // Clear preempt request (best-effort).
    PREEMPT_PENDING.store(false, Ordering::SeqCst);

    // Snapshot current MMU root into the task record.
    let current_root = read_mmu_root();

    let (next_ctx, next_domain, next_kind, next_root) = {
        let mut sched = sched().lock();
        if let Some(cur) = sched.current {
            if let Some(pos) = sched.tasks.iter().position(|t| t.id == cur) {
                let was_running = {
                    let t = &mut sched.tasks[pos];
                    t.mmu_root = current_root;
                    let was_running = t.state == TaskState::Running;
                    if was_running {
                        t.state = TaskState::Ready;
                    }
                    was_running
                };
                if was_running {
                    sched.enqueue(cur);
                }
            }
        }

        let next = sched.dequeue_next().unwrap_or_else(|| {
            // Always fall back to idle.
            sched
                .tasks
                .iter()
                .find(|t| t.name == "idle")
                .map(|t| t.id)
                .unwrap()
        });
        sched.current = Some(next);
        let pos = sched
            .tasks
            .iter()
            .position(|t| t.id == next)
            .unwrap_or_else(|| panic!("sched: missing task {}", next));
        let t = &mut sched.tasks[pos];
        t.state = TaskState::Running;
        t.slice_left = TIME_SLICE_TICKS;
        (
            &t.ctx as *const TaskContext,
            t.domain_id,
            t.domain_kind,
            t.mmu_root,
        )
    };

    // Install task-local domain+MMU root for the next task.
    crate::sandbox::set_current_domain_raw_with_kind(
        next_domain as crate::sandbox::DomainId,
        next_kind,
    );
    write_mmu_root(next_root);
    update_ttbr1_tramp_state(next_domain, next_root);

    IN_SWITCH.store(false, Ordering::SeqCst);
    ONEOS_SCHED_CURRENT_CTX.store(next_ctx as u64, Ordering::SeqCst);
    next_ctx
}
