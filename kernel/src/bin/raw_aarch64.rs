#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
mod bare {
    use core::ptr::addr_of_mut;
    use core::slice;

    use oneos_boot_proto::{BootInfo, MemoryRegionType};
    use oneos_kernel::arch;
    use oneos_kernel::timer;
    use oneos_kernel::{boot_info, display, drivers::serial, gfx, irq_work, sched, shell};
    use oneos_kernel::{heap, sandbox, virtio};

    extern "C" {
        static __text_start: u8;
        static __text_end: u8;
        static __rodata_start: u8;
        static __rodata_end: u8;
        static __data_start: u8;
        static __data_end: u8;
        static mut __bss_start: u8;
        static mut __bss_end: u8;
    }

    #[no_mangle]
    pub extern "C" fn kstart(info: *const BootInfo) -> ! {
        zero_bss();

        serial::init();
        // Drop UEFI page tables/caches first, then install our own MMU mappings (Stage 3).
        arch::aarch64::early_disable_mmu_for_raw_kernel();
        serial::log_line_args(format_args!(
            "oneOS raw aarch64: kstart info={:#x}",
            info as usize
        ));

        let _ = boot_info::init_raw(info);
        heap::init_from_boot_info();
        sandbox::init_from_boot_info();
        let boot = unsafe { info.as_ref() };

        serial::log_line_args(format_args!(
            "oneOS raw aarch64: boot_info_present={}",
            boot.is_some()
        ));

        if let Some(fb) = boot.and_then(|b| b.framebuffer()) {
            serial::log_line_args(format_args!(
                "oneOS raw aarch64: fb base={:#x} size={:#x} {}x{} stride={} fmt={:?}",
                fb.base, fb.size, fb.width, fb.height, fb.stride, fb.format
            ));
            serial::log_line("oneOS raw aarch64: display::init begin");
            display::init(fb);
            serial::log_line("oneOS raw aarch64: display::init ok");
            serial::log_line("oneOS raw aarch64: gfx::init begin");
            gfx::init(fb);
            serial::log_line("oneOS raw aarch64: gfx::init ok");

            serial::log_line("oneOS raw aarch64: display header write begin");
            display::write_line("oneOS raw aarch64 kernel");
            serial::log_line("oneOS raw aarch64: display header write ok");
            serial::log_line("oneOS raw aarch64: display::init ok");
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
            serial::log_line("oneOS raw aarch64: fb missing");
            serial::log_line("oneOS raw aarch64: fb missing, no display output");
        }

        timer::init();

        virtio::keyboard::init();
        virtio::blk::init();

        // Stage 3: enable MMU-backed address space (still no EL0/user-mode).
        //
        // We build a conservative identity-mapped TTBR0 page table that covers:
        // - kernel image region (0x4000_0000..0x4100_0000)
        // - heap region (from heap::stats)
        // - framebuffer region (if present)
        // - QEMU virt PL011 UART (0x0900_0000)
        // - QEMU virt PCIe MMIO window (0x1000_0000..0x2000_0000)
        // - PCI ECAM for bus 0 (0x4010_0000_00..+0x1_00000)
        //
        // Note: in this “all-EL1” model, page tables are used for address-space isolation
        // and fault capture, not for traditional privilege separation.
        if let Some(boot) = boot {
            serial::log_line("mmu: aarch64 build kernel TTBR0 begin");
            let sp_now: u64;
            unsafe {
                core::arch::asm!("mov {0}, sp", out(reg) sp_now, options(nomem, nostack, preserves_flags))
            };
            serial::log_line_args(format_args!("mmu: current sp=0x{:x}", sp_now));
            let (heap_start, heap_end, _used) = heap::stats();
            serial::log_line_args(format_args!(
                "mmu: heap range [0x{:x}..0x{:x})",
                heap_start, heap_end
            ));
            let mut layout = oneos_kernel::mmu::addrspace::AppSpaceLayout::new();
            let align_down_4k = |v: u64| v & !0xfff;
            let align_up_4k = |v: u64| (v + 0xfff) & !0xfff;

            // Kernel image mapping (W^X): split by linker sections.
            let text_start = core::ptr::addr_of!(__text_start) as u64;
            let text_end = core::ptr::addr_of!(__text_end) as u64;
            let ro_start = core::ptr::addr_of!(__rodata_start) as u64;
            let ro_end = core::ptr::addr_of!(__rodata_end) as u64;
            let data_start = core::ptr::addr_of!(__data_start) as u64;
            let data_end = core::ptr::addr_of!(__data_end) as u64;
            let bss_start = core::ptr::addr_of!(__bss_start) as u64;
            let bss_end = core::ptr::addr_of!(__bss_end) as u64;

            serial::log_line_args(format_args!(
                "mmu: kernel sections text=[0x{:x}..0x{:x}) ro=[0x{:x}..0x{:x}) data=[0x{:x}..0x{:x}) bss=[0x{:x}..0x{:x})",
                text_start, text_end, ro_start, ro_end, data_start, data_end, bss_start, bss_end
            ));

            if text_end > text_start {
                layout.push(oneos_kernel::mmu::addrspace::AppMap {
                    va: align_down_4k(text_start),
                    pa: align_down_4k(text_start),
                    len: align_up_4k(text_end) - align_down_4k(text_start),
                    exec: true,
                    writable: false,
                    device: false,
                });
            }
            if ro_end > ro_start {
                layout.push(oneos_kernel::mmu::addrspace::AppMap {
                    va: align_down_4k(ro_start),
                    pa: align_down_4k(ro_start),
                    len: align_up_4k(ro_end) - align_down_4k(ro_start),
                    exec: false,
                    writable: false,
                    device: false,
                });
            }
            if data_end > data_start {
                layout.push(oneos_kernel::mmu::addrspace::AppMap {
                    va: align_down_4k(data_start),
                    pa: align_down_4k(data_start),
                    len: align_up_4k(data_end) - align_down_4k(data_start),
                    exec: false,
                    writable: true,
                    device: false,
                });
            }
            if bss_end > bss_start {
                layout.push(oneos_kernel::mmu::addrspace::AppMap {
                    va: align_down_4k(bss_start),
                    pa: align_down_4k(bss_start),
                    len: align_up_4k(bss_end) - align_down_4k(bss_start),
                    exec: false,
                    writable: true,
                    device: false,
                });
            }

            // Stack window around SP (RW, NX).
            //
            // We intentionally cover a generous range to tolerate early boot stacks and
            // nested calls before we introduce per-domain stacks with MMU-backed spaces.
            let stack_start = align_down_4k(sp_now.saturating_sub(0x20000));
            let stack_end = align_up_4k(sp_now.saturating_add(0x20000));
            serial::log_line_args(format_args!(
                "mmu: stack map [0x{:x}..0x{:x}) (sp=0x{:x})",
                stack_start, stack_end, sp_now
            ));
            if stack_end > stack_start {
                layout.push(oneos_kernel::mmu::addrspace::AppMap {
                    va: stack_start,
                    pa: stack_start,
                    len: stack_end - stack_start,
                    exec: false,
                    writable: true,
                    device: false,
                });
            }

            // App load/exec window mapping in kernel space (RW, NX).
            //
            // Kernel needs to be able to copy/load into this memory, but should not execute
            // from it. App page tables will map code as RX and enforce W^X.
            let app_base = 0x4100_0000u64;
            let app_end = 0x4300_0000u64; // 32 MiB window
            serial::log_line_args(format_args!(
                "mmu: app window map [0x{:x}..0x{:x})",
                app_base, app_end
            ));
            layout.push(oneos_kernel::mmu::addrspace::AppMap {
                va: app_base,
                pa: app_base,
                len: app_end - app_base,
                exec: false,
                writable: true,
                device: false,
            });
            // Heap (RW, NX).
            if heap_end > heap_start {
                layout.push(oneos_kernel::mmu::addrspace::AppMap {
                    va: heap_start as u64,
                    pa: heap_start as u64,
                    len: (heap_end - heap_start) as u64,
                    exec: false,
                    writable: true,
                    device: false,
                });
            }
            // Framebuffer (RW, NX).
            if let Some(fb) = boot.framebuffer() {
                if fb.base != 0 && fb.size != 0 {
                    layout.push(oneos_kernel::mmu::addrspace::AppMap {
                        va: fb.base,
                        pa: fb.base,
                        len: fb.size,
                        exec: false,
                        writable: true,
                        device: false,
                    });
                }
            }
            // GIC MMIO (needed once interrupts are enabled; otherwise first IRQ will fault).
            // QEMU virt defaults:
            // - GICD: 0x0800_0000
            // - GICC: 0x0801_0000
            // Map both regions as RW, NX.
            layout.push(oneos_kernel::mmu::addrspace::AppMap {
                va: 0x0800_0000,
                pa: 0x0800_0000,
                len: 0x20_000,
                exec: false,
                writable: true,
                device: true,
            });
            // PL011 UART (Device, NX) – mapped as Normal for MVP builder; ok for QEMU.
            layout.push(oneos_kernel::mmu::addrspace::AppMap {
                va: 0x0900_0000,
                pa: 0x0900_0000,
                len: 0x1000,
                exec: false,
                writable: true,
                device: true,
            });
            // PCIe MMIO window (BARs):
            // QEMU virt may place virtio BARs very high (e.g. 0x0000_0080_0000_8000).
            // We map a small low window as a fallback, and also map precise windows based on
            // what our virtio drivers discovered.
            layout.push(oneos_kernel::mmu::addrspace::AppMap {
                va: 0x1000_0000,
                pa: 0x1000_0000,
                len: 0x0100_0000, // 16 MiB
                exec: false,
                writable: true,
                device: true,
            });
            if let Some((base, len)) = oneos_kernel::virtio::keyboard::mmu_required_mmio_window() {
                serial::log_line_args(format_args!(
                    "mmu: map virtio-keyboard mmio [0x{:x}..0x{:x})",
                    base,
                    base.saturating_add(len)
                ));
                layout.push(oneos_kernel::mmu::addrspace::AppMap {
                    va: base,
                    pa: base,
                    len,
                    exec: false,
                    writable: true,
                    device: true,
                });
            }
            if let Some((base, len)) = oneos_kernel::virtio::blk::mmu_required_mmio_window() {
                serial::log_line_args(format_args!(
                    "mmu: map virtio-blk mmio [0x{:x}..0x{:x})",
                    base,
                    base.saturating_add(len)
                ));
                layout.push(oneos_kernel::mmu::addrspace::AppMap {
                    va: base,
                    pa: base,
                    len,
                    exec: false,
                    writable: true,
                    device: true,
                });
            }
            // ECAM for bus 0: 1 MiB at 0x4010_0000_00
            layout.push(oneos_kernel::mmu::addrspace::AppMap {
                va: 0x4010_0000_00,
                pa: 0x4010_0000_00,
                len: 0x10_0000,
                exec: false,
                writable: true,
                device: true,
            });

            match oneos_kernel::mmu::addrspace::build_app_space_with_stats(&layout) {
                Ok((root, tables, pages)) => {
                    serial::log_line_args(format_args!(
                        "mmu: built kernel TTBR0 root=0x{:x} tables={} pages={}",
                        root, tables, pages
                    ));
                    // Route B scaffold (Stage 1): build a minimal fixed TTBR1 mapping
                    // for exception vectors + shared trampoline state.
                    let mut ttbr1_root: Option<u64> = None;
                    {
                        extern "C" {
                            static oneos_aarch64_ttbr1_vector_table: u8;
                        }
                        let mut l2 = oneos_kernel::mmu::addrspace::AppSpaceLayout::new();
                        let vec_pa = core::ptr::addr_of!(oneos_aarch64_ttbr1_vector_table) as u64;
                        let vec_pa_page = align_down_4k(vec_pa);
                        let vec_va = oneos_kernel::mmu::addrspace::ttbr1_tramp_vector_va();
                        l2.push(oneos_kernel::mmu::addrspace::AppMap {
                            va: vec_va,
                            pa: vec_pa_page,
                            len: 0x1000,
                            exec: true,
                            writable: false,
                            device: false,
                        });
                        let state_pa = oneos_kernel::mmu::addrspace::ttbr1_tramp_state_pa();
                        let state_pa_page = align_down_4k(state_pa);
                        let state_va = oneos_kernel::mmu::addrspace::ttbr1_tramp_state_va();
                        l2.push(oneos_kernel::mmu::addrspace::AppMap {
                            va: state_va,
                            pa: state_pa_page,
                            len: 0x1000,
                            exec: false,
                            writable: false,
                            device: false,
                        });
                        match oneos_kernel::mmu::addrspace::build_app_space_with_stats(&l2) {
                            Ok((r, t, p)) => {
                                serial::log_line_args(format_args!(
                                    "mmu: built TTBR1 trampoline root=0x{:x} tables={} pages={}",
                                    r, t, p
                                ));
                                ttbr1_root = Some(r);
                            }
                            Err(e) => {
                                serial::log_line_args(format_args!(
                                    "mmu: WARN: TTBR1 trampoline build failed: {:?} (fall back to TTBR0-only)",
                                    e
                                ));
                            }
                        }
                    }
                    unsafe {
                        if let Some(ttbr1) = ttbr1_root {
                            oneos_kernel::mmu::aarch64::enable_ttbr0_ttbr1(
                                root,
                                ttbr1,
                                oneos_kernel::mmu::aarch64::MmuConfig {
                                    mair_el1: oneos_kernel::mmu::aarch64::MAIR_EL1_MIN,
                                    tcr_el1:
                                        oneos_kernel::mmu::aarch64::TCR_EL1_MIN_TTBR0_TTBR1_48BIT,
                                },
                            );
                            oneos_kernel::mmu::addrspace::ttbr1_tramp_state_set(root, 0);
                            // IMPORTANT: VBAR_EL1 is configured earlier in `timer::init()`.
                            // When TTBR1 is enabled later, rebind VBAR_EL1 to the fixed TTBR1
                            // trampoline vector table so exceptions can always restore kernel TTBR0
                            // even if the current TTBR0 is an App/Service address space.
                            let vbar = oneos_kernel::mmu::addrspace::ttbr1_tramp_vector_va();
                            core::arch::asm!(
                                "msr vbar_el1, {0}",
                                "isb",
                                in(reg) vbar,
                                options(nomem, nostack, preserves_flags)
                            );
                        } else {
                            oneos_kernel::mmu::aarch64::enable(
                                root,
                                oneos_kernel::mmu::aarch64::MmuConfig {
                                    mair_el1: oneos_kernel::mmu::aarch64::MAIR_EL1_MIN,
                                    tcr_el1: oneos_kernel::mmu::aarch64::TCR_EL1_MIN_TTBR0_48BIT,
                                },
                            );
                        }
                    }
                    serial::log_line_args(format_args!(
                        "mmu: enabled (sctlr.mmu_on={}) ttbr0=0x{:x}",
                        oneos_kernel::mmu::aarch64::is_enabled(),
                        oneos_kernel::mmu::aarch64::current_ttbr0_el1()
                    ));
                    oneos_kernel::mmu::addrspace::refresh_kernel_pt_root_if_enabled();
                }
                Err(e) => {
                    serial::log_line_args(format_args!("mmu: build failed: {:?}", e));
                }
            }
        }

        serial::log_line("oneOS raw aarch64: init scheduler");
        sched::init();
        serial::log_line("oneOS raw aarch64: init irq_work");
        irq_work::init();
        serial::log_line("oneOS raw aarch64: irq_work init ok");

        extern "C" fn shell_task(_arg: usize) -> ! {
            shell::run_raw()
        }

        let _ = oneos_kernel::service::start("oneconsole", sandbox::default_user_name());
        let _ = oneos_kernel::service::start("goesd", sandbox::default_user_name());
        oneos_kernel::service::autostart();
        let _ = sched::spawn_domain_thread("shell", 2, sched::Priority::High, shell_task, 0);

        serial::log_line("oneOS raw aarch64: entering scheduler");
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
