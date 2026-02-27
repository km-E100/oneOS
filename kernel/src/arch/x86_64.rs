#![allow(dead_code)]

/// x86_64 上用 HLT 循环停机。
#[cfg(target_arch = "x86_64")]
pub fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt") };
    }
}

/// 非 x86_64 架构下的占位实现，避免交叉编译报错。
#[cfg(not(target_arch = "x86_64"))]
pub fn halt() -> ! {
    loop {}
}
