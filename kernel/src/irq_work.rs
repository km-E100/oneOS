#![cfg(target_os = "none")]

use core::sync::atomic::{AtomicBool, Ordering};

use crate::drivers::serial;
use crate::sync::spinlock::IrqSpinLock;
use crate::sync::wait_queue::WaitQueue;

#[derive(Clone, Copy)]
struct WorkItem {
    func: usize,
    arg: usize,
}

impl WorkItem {
    const fn empty() -> Self {
        Self { func: 0, arg: 0 }
    }

    fn is_empty(&self) -> bool {
        self.func == 0
    }

    fn call(self) {
        if self.func == 0 {
            return;
        }
        let f: extern "C" fn(usize) = unsafe { core::mem::transmute(self.func) };
        f(self.arg);
    }
}

const WORK_CAP: usize = 64;

struct WorkRing {
    buf: [WorkItem; WORK_CAP],
    head: usize,
    tail: usize,
    count: usize,
}

impl WorkRing {
    const fn new() -> Self {
        Self {
            buf: [WorkItem::empty(); WORK_CAP],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn push(&mut self, item: WorkItem) -> bool {
        if self.count >= WORK_CAP {
            return false;
        }
        self.buf[self.tail] = item;
        self.tail = (self.tail + 1) % WORK_CAP;
        self.count += 1;
        true
    }

    fn pop(&mut self) -> Option<WorkItem> {
        if self.count == 0 {
            return None;
        }
        let item = self.buf[self.head];
        self.buf[self.head] = WorkItem::empty();
        self.head = (self.head + 1) % WORK_CAP;
        self.count -= 1;
        (!item.is_empty()).then_some(item)
    }
}

static INITED: AtomicBool = AtomicBool::new(false);
static WORK: IrqSpinLock<WorkRing> = IrqSpinLock::new(WorkRing::new());
static WAIT: IrqSpinLock<Option<WaitQueue>> = IrqSpinLock::new(None);

extern "C" fn worker_entry(_: usize) -> ! {
    loop {
        let next = { WORK.lock().pop() };
        if let Some(w) = next {
            w.call();
            continue;
        }
        if let Some(wq) = WAIT.lock().as_ref() {
            wq.wait();
        } else {
            crate::sched::yield_now();
        }
    }
}

pub fn init() {
    if INITED.swap(true, Ordering::SeqCst) {
        return;
    }
    serial::log_line("irq_work: init enter");
    *WAIT.lock() = Some(WaitQueue::new());
    serial::log_line("irq_work: waitqueue ready");
    serial::log_line("irq_work: spawning worker");
    let tid = crate::sched::spawn_kernel_thread(
        "irq-work",
        crate::sched::Priority::High,
        worker_entry,
        0,
    );
    serial::log_line_args(format_args!("irq_work: worker task {}", tid));
}

pub fn schedule(func: extern "C" fn(usize), arg: usize) -> bool {
    let ok = {
        WORK.lock().push(WorkItem {
            func: func as usize,
            arg,
        })
    };
    if ok {
        if let Some(wq) = WAIT.lock().as_ref() {
            wq.wake_one();
        }
    }
    ok
}
