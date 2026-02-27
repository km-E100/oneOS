pub mod aarch64;
pub mod x86_64;

/// 返回当前构建的架构名称。
pub fn arch_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64"
    }
}

/// 进入架构对应的“安全停机”状态。
pub fn halt() -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        return x86_64::halt();
    }
    #[cfg(target_arch = "aarch64")]
    {
        return aarch64::halt();
    }
    loop {}
}
