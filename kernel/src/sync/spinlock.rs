#![cfg(target_os = "none")]

use core::ops::{Deref, DerefMut};

use spin::mutex::MutexGuard;

use super::irq::IrqGuard;

pub struct IrqSpinLock<T> {
    inner: spin::Mutex<T>,
}

pub struct IrqSpinLockGuard<'a, T> {
    guard: MutexGuard<'a, T>,
    _irq: IrqGuard,
}

impl<T> IrqSpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: spin::Mutex::new(value),
        }
    }

    #[inline(always)]
    pub fn lock(&self) -> IrqSpinLockGuard<'_, T> {
        let irq = IrqGuard::new();
        let guard = self.inner.lock();
        // Drop order matters: release the spin lock before restoring IRQ state to avoid
        // taking an interrupt while still holding the lock (deadlock if ISR also locks).
        IrqSpinLockGuard { guard, _irq: irq }
    }
}

impl<T> Deref for IrqSpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &*self.guard
    }
}

impl<T> DerefMut for IrqSpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.guard
    }
}
