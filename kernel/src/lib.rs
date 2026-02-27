#![no_std]
#![cfg_attr(target_os = "none", feature(alloc_error_handler))]

#[cfg(target_os = "none")]
pub mod app;
pub mod arch;
#[cfg(target_os = "none")]
pub mod audit;
#[cfg(target_os = "uefi")]
pub mod boot;
pub mod boot_info;
pub mod console;
pub mod display;
pub mod drivers;
pub mod gfx;
#[cfg(target_os = "none")]
pub mod goes;
#[cfg(target_os = "none")]
pub mod heap;
#[cfg(target_os = "none")]
pub mod ipc;
#[cfg(target_os = "none")]
pub mod irq_work;
#[cfg(target_os = "none")]
pub mod mmu;
pub mod panic;
#[cfg(target_os = "none")]
pub mod sandbox;
#[cfg(target_os = "none")]
pub mod sched;
#[cfg(target_os = "none")]
pub mod service;
pub mod shell;
#[cfg(target_os = "none")]
pub mod sync;
pub mod text;
#[cfg(target_os = "none")]
pub mod timer;
#[cfg(target_os = "none")]
pub mod virtio;
#[cfg(target_os = "none")]
pub mod workspace;

/// 共享内核入口，仅在 UEFI 目标下使用。
#[cfg(target_os = "uefi")]
pub fn kernel_entry() -> uefi::Status {
    boot::efi_main()
}
