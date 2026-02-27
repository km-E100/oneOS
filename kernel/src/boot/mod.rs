use crate::{arch, drivers, text};
use crate::{boot_info, display, gfx};
use core::fmt::Write;
use uefi::prelude::*;

/// UEFI 入口：初始化服务、缓存 stdout、打印 banner，然后进入停机。
pub fn efi_main() -> Status {
    uefi::system::with_stdout(|s| {
        let _ = s.write_str("kernel boot::efi_main enter\r\n");
    });

    // 初始化 UEFI 辅助功能（日志/内存分配器等），失败也要停机
    if let Err(e) = uefi::helpers::init() {
        uefi::system::with_stdout(|s| {
            let _ = s.write_str("uefi helpers init failed\r\n");
        });
        uefi::system::with_stderr(|s| {
            let _ = s.write_str("uefi helpers init failed, halting\r\n");
        });
        // 打印错误状态码
        uefi::system::with_stdout(|s| {
            let _ = s.write_fmt(format_args!("helpers::init error: {:?}\r\n", e));
        });
        arch::halt();
    }
    uefi::system::with_stdout(|s| {
        let _ = s.write_str("kernel: helpers::init ok\r\n");
    });

    // 解析 bootloader 传递的 BootInfo 并初始化图形输出。
    if let Some(info) = boot_info::init_from_load_options() {
        if let Some(fb) = info.framebuffer() {
            display::init(fb);
            gfx::init(fb);
            uefi::system::with_stdout(|s| {
                let _ = s.write_str("kernel: display::init ok\r\n");
            });
        } else {
            uefi::system::with_stdout(|s| {
                let _ = s.write_str("kernel: no framebuffer info\r\n");
            });
        }
    } else {
        uefi::system::with_stdout(|s| {
            let _ = s.write_str("kernel: boot info unavailable\r\n");
        });
    }

    // 缓存 stdout 句柄供 text 模块使用
    uefi::system::with_stdout(|stdout| {
        text::init(stdout);
    });
    uefi::system::with_stdout(|s| {
        let _ = s.write_str("kernel: text::init done\r\n");
    });

    // 驱动占位初始化
    drivers::init();
    uefi::system::with_stdout(|s| {
        let _ = s.write_str("kernel: drivers::init done\r\n");
    });

    // 启动横幅
    text::write_line("oneOS kernel v0 (UEFI)");
    let _ = text::write_line_args(format_args!("arch: {}", arch::arch_name()));
    text::write_line("boot ok, entering shell...");

    // 进入内核交互 shell（串口输入）
    crate::shell::run();

    // shell 内部可能调用 halt/panic；若返回则直接停机
    arch::halt()
}
