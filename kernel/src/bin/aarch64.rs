#![cfg_attr(any(target_os = "uefi", target_os = "none"), no_std)]
#![cfg_attr(any(target_os = "uefi", target_os = "none"), no_main)]

#[cfg(not(any(target_os = "uefi", target_os = "none")))]
fn main() {}

#[cfg(target_os = "uefi")]
use oneos_kernel::kernel_entry;
#[cfg(target_os = "uefi")]
use uefi::cstr16;
#[cfg(target_os = "uefi")]
use uefi::prelude::*;

#[cfg(target_os = "uefi")]
#[entry]
fn efi_main() -> Status {
    // 直接通过 UEFI stdout 打一条日志，验证入口是否执行。
    uefi::system::with_stdout(|out| {
        let _ = out.output_string(cstr16!("oneOS kernel bin entry (aarch64)\r\n"));
    });

    kernel_entry()
}
