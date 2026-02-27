#![cfg(target_os = "none")]

extern crate alloc;

use alloc::collections::VecDeque;

use crate::sched::{self, TaskId};

use super::spinlock::IrqSpinLock;

pub struct WaitQueue {
    q: IrqSpinLock<VecDeque<TaskId>>,
}

impl WaitQueue {
    pub fn new() -> Self {
        Self {
            q: IrqSpinLock::new(VecDeque::new()),
        }
    }

    pub fn wait(&self) {
        self.wait_with(|| {});
    }

    pub fn wait_with(&self, before_sleep: impl FnOnce()) {
        let Some(tid) = sched::current_task_id() else {
            before_sleep();
            return;
        };
        {
            let mut q = self.q.lock();
            q.push_back(tid);
            // Mark blocked while still holding the queue lock to avoid missed wakeups.
            sched::block_current();
        }
        before_sleep();
        sched::yield_now();
    }

    pub fn wake_one(&self) -> bool {
        let id = { self.q.lock().pop_front() };
        if let Some(id) = id {
            sched::wake_task(id);
            return true;
        }
        false
    }

    pub fn wake_all(&self) -> u32 {
        let mut n = 0u32;
        loop {
            if !self.wake_one() {
                break;
            }
            n = n.saturating_add(1);
        }
        n
    }
}
