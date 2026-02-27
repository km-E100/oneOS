#![cfg(target_os = "none")]

extern crate alloc;

use alloc::collections::VecDeque;

use crate::sched::{self, TaskId};

use super::spinlock::IrqSpinLock;

pub struct Semaphore {
    state: IrqSpinLock<SemState>,
}

struct SemState {
    count: isize,
    waiters: VecDeque<TaskId>,
}

impl Semaphore {
    pub fn new(count: isize) -> Self {
        Self {
            state: IrqSpinLock::new(SemState {
                count,
                waiters: VecDeque::new(),
            }),
        }
    }

    pub fn acquire(&self) {
        loop {
            let Some(tid) = sched::current_task_id() else {
                let mut st = self.state.lock();
                if st.count > 0 {
                    st.count -= 1;
                    return;
                }
                drop(st);
                continue;
            };
            let mut st = self.state.lock();
            if st.count > 0 {
                st.count -= 1;
                return;
            }
            st.waiters.push_back(tid);
            // Mark blocked while still holding the state lock to avoid missed wakeups.
            sched::block_current();
            drop(st);
            sched::yield_now();
        }
    }

    pub fn release(&self) {
        let mut st = self.state.lock();
        st.count += 1;
        if let Some(tid) = st.waiters.pop_front() {
            // Give the token directly to the woken task.
            st.count -= 1;
            sched::wake_task(tid);
        }
    }
}
