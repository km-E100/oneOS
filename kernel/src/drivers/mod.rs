/// 未来驱动初始化钩子，当前仅占位。
pub mod serial;

pub fn init() {
    crate::text::write_line("kernel: drivers::init enter");
    #[cfg(any(target_os = "uefi", target_os = "none"))]
    serial::init();
    crate::text::write_line("kernel: drivers::init leave");
}
