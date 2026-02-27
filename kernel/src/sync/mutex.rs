#![cfg(target_os = "none")]

extern crate alloc;

use alloc::collections::VecDeque;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

use crate::sched::{self, TaskId};

use super::spinlock::IrqSpinLock;

struct MutexState {
    owner: Option<TaskId>,
    waiters: VecDeque<TaskId>,
}

pub struct Mutex<T> {
    state: IrqSpinLock<MutexState>,
    data: UnsafeCell<T>,
}

pub struct MutexGuard<'a, T> {
    pub(crate) mutex: &'a Mutex<T>,
}

unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub fn new(value: T) -> Self {
        Self {
            state: IrqSpinLock::new(MutexState {
                owner: None,
                waiters: VecDeque::new(),
            }),
            data: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        loop {
            let Some(tid) = sched::current_task_id() else {
                // Not yet scheduled: behave like a simple spin lock.
                let mut st = self.state.lock();
                if st.owner.is_none() {
                    st.owner = Some(0);
                    break;
                }
                drop(st);
                continue;
            };

            let mut st = self.state.lock();
            if st.owner.is_none() {
                st.owner = Some(tid);
                break;
            }
            st.waiters.push_back(tid);
            // Mark blocked while still holding the state lock to avoid missed wakeups.
            sched::block_current();
            drop(st);
            sched::yield_now();
        }
        MutexGuard { mutex: self }
    }

    fn unlock(&self) {
        let mut st = self.state.lock();
        st.owner = None;
        if let Some(next) = st.waiters.pop_front() {
            sched::wake_task(next);
        }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<'a, T> MutexGuard<'a, T> {
    pub fn mutex(&self) -> &'a Mutex<T> {
        self.mutex
    }
}
