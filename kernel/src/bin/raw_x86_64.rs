#![cfg_attr(any(target_os = "uefi", target_os = "none"), no_std)]
#![cfg_attr(any(target_os = "uefi", target_os = "none"), no_main)]

#[cfg(not(any(target_os = "uefi", target_os = "none")))]
fn main() {}

#[cfg(target_os = "none")]
mod bare {
    use core::arch::global_asm;
    use core::{ptr::addr_of_mut, slice};
    use oneos_boot_proto::{BootInfo, MemoryRegionType};
    use oneos_kernel::mmu;
    use oneos_kernel::timer;
    use oneos_kernel::{boot_info, display, drivers::serial, gfx, irq_work, sched, shell};
    use oneos_kernel::{heap, sandbox, virtio};

    global_asm!(
        r#"
        .intel_syntax noprefix
        .section .text.boot,"ax"
        .global _start
    _start:
        lea rsp, [rip + __stack_top]
        and rsp, -16
        call kstart
    "#
    );

    extern "C" {
        static mut __bss_start: u8;
        static mut __bss_end: u8;
    }

    #[no_mangle]
    pub extern "C" fn kstart(info: *const BootInfo) -> ! {
        zero_bss();

        serial::init();
        serial::log_line_args(format_args!(
            "oneOS raw x86_64: kstart info={:#x}",
            info as usize
        ));

        let _ = boot_info::init_raw(info);
        heap::init_from_boot_info();
        sandbox::init_from_boot_info();
        // Stage 5/M3: enforce W^X in ring0 by enabling NXE+WP.
        mmu::x86_64::enable_wx_protection();

        let boot = unsafe { info.as_ref() };
        serial::log_line_args(format_args!(
            "oneOS raw x86_64: boot_info_present={}",
            boot.is_some()
        ));

        if let Some(fb) = boot.and_then(|b| b.framebuffer()) {
            serial::log_line_args(format_args!(
                "oneOS raw x86_64: fb base={:#x} size={:#x} {}x{} stride={} fmt={:?}",
                fb.base, fb.size, fb.width, fb.height, fb.stride, fb.format
            ));
            serial::log_line("oneOS raw x86_64: display::init begin");
            display::init(fb);
            serial::log_line("oneOS raw x86_64: gfx::init begin");
            gfx::init(fb);
            serial::log_line("oneOS raw x86_64: gfx::init ok");
            serial::log_line("oneOS raw x86_64: display::init ok");
            display::write_line("oneOS raw x86_64 kernel");
            serial::log_line("oneOS raw x86_64: display header written");
            if let Some((ptr, len)) = boot.and_then(|b| b.memory_regions_raw()) {
                let regions = unsafe { slice::from_raw_parts(ptr, len) };
                let mut total = 0u64;
                let mut conventional = 0u64;
                for region in regions {
                    total = total.saturating_add(region.length);
                    if region.region_type == MemoryRegionType::Conventional {
                        conventional = conventional.saturating_add(region.length);
                    }
                }
                display::write_line_args(format_args!("memory map entries: {}", regions.len()));
                display::write_line_args(format_args!(
                    "total memory: {} MB",
                    total / (1024 * 1024)
                ));
                display::write_line_args(format_args!(
                    "usable memory: {} MB",
                    conventional / (1024 * 1024)
                ));
            } else {
                display::write_line("memory map unavailable");
            }
        } else {
            serial::log_line("oneOS raw x86_64: fb missing, no display output");
        }

        timer::init();

        virtio::keyboard::init();
        virtio::blk::init();

        serial::log_line("oneOS raw x86_64: init scheduler");
        sched::init();
        irq_work::init();

        extern "C" fn shell_task(_arg: usize) -> ! {
            shell::run_raw()
        }

        let _ = oneos_kernel::service::start("oneconsole", sandbox::default_user_name());
        let _ = oneos_kernel::service::start("goesd", sandbox::default_user_name());
        oneos_kernel::service::autostart();
        let _ = sched::spawn_domain_thread("shell", 2, sched::Priority::High, shell_task, 0);

        serial::log_line("oneOS raw x86_64: entering scheduler");
        sched::start();
    }

    fn zero_bss() {
        unsafe {
            let mut ptr = addr_of_mut!(__bss_start) as *mut u8;
            let end = addr_of_mut!(__bss_end) as *mut u8;
            while ptr < end {
                ptr.write_volatile(0);
                ptr = ptr.add(1);
            }
        }
    }
}
