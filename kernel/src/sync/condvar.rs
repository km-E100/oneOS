#![cfg(target_os = "none")]

use super::mutex::{Mutex, MutexGuard};
use super::wait_queue::WaitQueue;

pub struct CondVar {
    wq: WaitQueue,
}

impl CondVar {
    pub fn new() -> Self {
        Self {
            wq: WaitQueue::new(),
        }
    }

    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        let mutex = guard.mutex();
        self.wq.wait_with(|| drop(guard));
        mutex.lock()
    }

    pub fn notify_one(&self) {
        let _ = self.wq.wake_one();
    }

    pub fn notify_all(&self) -> u32 {
        self.wq.wake_all()
    }
}
