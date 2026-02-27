#![cfg(target_os = "none")]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::drivers::serial;
use crate::sandbox::{self, DomainId};

pub mod abi;

type ServiceMain = extern "C" fn(*const abi::ServiceApi) -> i32;

#[derive(Clone)]
struct BuiltinService {
    name: &'static str,
    main: ServiceMain,
    priority: crate::sched::Priority,
    autostart: bool,
}

#[derive(Clone)]
struct RunningService {
    name: String,
    domain_id: DomainId,
    task_id: crate::sched::TaskId,
}

static RUNNING: Mutex<Vec<RunningService>> = Mutex::new(Vec::new());

fn builtins() -> &'static [BuiltinService] {
    &[
        BuiltinService {
            name: "oneconsole",
            main: oneconsole::oneos_service_main,
            priority: crate::sched::Priority::Normal,
            autostart: false,
        },
        BuiltinService {
            name: "goesd",
            main: goesd::oneos_service_main,
            priority: crate::sched::Priority::Normal,
            autostart: false,
        },
        BuiltinService {
            name: "svc_logger",
            main: svc_logger::oneos_service_main,
            priority: crate::sched::Priority::Normal,
            autostart: true,
        },
        BuiltinService {
            name: "svc_time",
            main: svc_time::oneos_service_main,
            priority: crate::sched::Priority::Normal,
            autostart: true,
        },
        BuiltinService {
            name: "svc_notify",
            main: svc_notify::oneos_service_main,
            priority: crate::sched::Priority::Normal,
            autostart: false,
        },
    ]
}

fn ensure_service_addrspace(domain: DomainId) {
    if !crate::mmu::switch::app_address_space_switch_enabled()
        || !crate::mmu::addrspace::current_mmu_enabled()
    {
        return;
    }
    let Some(asid) = crate::sandbox::domain_address_space(domain) else {
        return;
    };
    if crate::mmu::addrspace::pt_root(asid).is_some() {
        return;
    }

    let mut layout = crate::mmu::addrspace::AppSpaceLayout::new();
    unsafe {
        extern "C" {
            static __text_start: u8;
            static __text_end: u8;
            static __rodata_start: u8;
            static __rodata_end: u8;
            static __data_start: u8;
            static __data_end: u8;
            static __bss_start: u8;
            static __bss_end: u8;
        }
        let align_down_4k = |x: u64| x & !0xfffu64;
        let align_up_4k = |x: u64| (x + 0xfff) & !0xfffu64;

        let text_start = &raw const __text_start as *const u8 as u64;
        let text_end = &raw const __text_end as *const u8 as u64;
        let ro_start = &raw const __rodata_start as *const u8 as u64;
        let ro_end = &raw const __rodata_end as *const u8 as u64;
        let data_start = &raw const __data_start as *const u8 as u64;
        let data_end = &raw const __data_end as *const u8 as u64;
        let bss_start = &raw const __bss_start as *const u8 as u64;
        let bss_end = &raw const __bss_end as *const u8 as u64;

        if text_end > text_start {
            let s = align_down_4k(text_start);
            let e = align_up_4k(text_end);
            layout.push(crate::mmu::addrspace::AppMap {
                va: s,
                pa: s,
                len: e - s,
                exec: true,
                writable: false,
                device: false,
            });
        }
        if ro_end > ro_start {
            let s = align_down_4k(ro_start);
            let e = align_up_4k(ro_end);
            layout.push(crate::mmu::addrspace::AppMap {
                va: s,
                pa: s,
                len: e - s,
                exec: false,
                writable: false,
                device: false,
            });
        }
        let rw_start = core::cmp::min(data_start, bss_start);
        let rw_end = core::cmp::max(data_end, bss_end);
        if rw_end > rw_start {
            let s = align_down_4k(rw_start);
            let e = align_up_4k(rw_end);
            layout.push(crate::mmu::addrspace::AppMap {
                va: s,
                pa: s,
                len: e - s,
                exec: false,
                writable: true,
                device: false,
            });
        }
    }

    // Map current kernel stack window (RW, NX).
    let sp_now: u64;
    unsafe {
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("mov {0}, sp", out(reg) sp_now, options(nomem, nostack, preserves_flags));
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("mov {0}, rsp", out(reg) sp_now, options(nomem, nostack, preserves_flags));
    }
    let stack_start = sp_now.saturating_sub(0x40000) & !0xfffu64;
    let stack_end = (sp_now.saturating_add(0x20000) + 0xfff) & !0xfffu64;
    if stack_end > stack_start {
        layout.push(crate::mmu::addrspace::AppMap {
            va: stack_start,
            pa: stack_start,
            len: stack_end - stack_start,
            exec: false,
            writable: true,
            device: false,
        });
    }

    // Kernel heap (RW, NX).
    let (heap_start, heap_end, _used) = crate::heap::stats();
    if heap_end > heap_start {
        layout.push(crate::mmu::addrspace::AppMap {
            va: heap_start as u64,
            pa: heap_start as u64,
            len: (heap_end - heap_start) as u64,
            exec: false,
            writable: true,
            device: false,
        });
    }

    // Framebuffer (RW, NX).
    //
    // Note: services run under their own TTBR0/CR3 (Stage 4). Many kernel paths (including
    // log mirroring and console rendering) touch the framebuffer. Map it into ServiceDomain
    // spaces to avoid data aborts when a service is running while the kernel writes to the UI.
    if let Some(info) = crate::boot_info::get() {
        if let Some(fb) = info.framebuffer() {
            if fb.base != 0 && fb.size != 0 {
                layout.push(crate::mmu::addrspace::AppMap {
                    va: fb.base,
                    pa: fb.base,
                    len: fb.size,
                    exec: false,
                    writable: true,
                    device: false,
                });
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // GIC + PL011 for timer + serial.
        layout.push(crate::mmu::addrspace::AppMap {
            va: 0x0800_0000,
            pa: 0x0800_0000,
            len: 0x20_000,
            exec: false,
            writable: true,
            device: true,
        });
        layout.push(crate::mmu::addrspace::AppMap {
            va: 0x0900_0000,
            pa: 0x0900_0000,
            len: 0x1000,
            exec: false,
            writable: true,
            device: true,
        });
        // PCIe window (device).
        layout.push(crate::mmu::addrspace::AppMap {
            va: 0x1000_0000,
            pa: 0x1000_0000,
            len: 0x0100_0000,
            exec: false,
            writable: true,
            device: true,
        });

        // Virtio BAR windows (device).
        if let Some((base, len)) = crate::virtio::keyboard::mmu_required_mmio_window() {
            layout.push(crate::mmu::addrspace::AppMap {
                va: base,
                pa: base,
                len,
                exec: false,
                writable: true,
                device: true,
            });
        }
        if let Some((base, len)) = crate::virtio::blk::mmu_required_mmio_window() {
            layout.push(crate::mmu::addrspace::AppMap {
                va: base,
                pa: base,
                len,
                exec: false,
                writable: true,
                device: true,
            });
        }
    }

    match crate::mmu::addrspace::build_app_space_with_stats_and_pages(&layout) {
        Ok((root, _tables, _pages, pt_pages)) => {
            crate::mmu::addrspace::set_pt_root_with_pages(asid, root, pt_pages);
        }
        Err(_) => {
            serial::log_line_args(format_args!("service: mmu build failed domain={}", domain));
        }
    }
}

extern "C" fn service_entry(arg: usize) -> ! {
    let domain = arg as DomainId;
    crate::sandbox::set_current_domain(domain);
    ensure_service_addrspace(domain);
    if crate::mmu::switch::app_address_space_switch_enabled()
        && crate::mmu::addrspace::current_mmu_enabled()
    {
        if let Some(asid) = crate::sandbox::domain_address_space(domain) {
            if let Ok(_saved) = crate::mmu::addrspace::enter(asid) {
                // Keep service running under its TTBR0/CR3 until exit.
            }
        }
    }
    // All services share the same API address (mapped via kernel rodata in every AddressSpace).
    let _ = (abi::SERVICE_API).version;
    let main = {
        let running = RUNNING.lock();
        running
            .iter()
            .find(|r| r.domain_id == domain)
            .and_then(|r| builtins().iter().find(|b| b.name == r.name.as_str()))
            .map(|b| b.main)
    };
    let Some(main) = main else {
        serial::log_line_args(format_args!("service: missing entry for domain={}", domain));
        crate::sched::exit_current();
    };
    let code = main(&abi::SERVICE_API as *const abi::ServiceApi);
    serial::log_line_args(format_args!(
        "service: domain {} exited code={}",
        domain, code
    ));
    crate::sched::exit_current();
}

pub fn autostart() {
    for b in builtins() {
        if !b.autostart {
            continue;
        }
        let _ = start(b.name, sandbox::default_user_name());
    }
}

pub fn start(name: &str, user: &str) -> Result<DomainId, ()> {
    if RUNNING.lock().iter().any(|r| r.name == name) {
        return Ok(RUNNING
            .lock()
            .iter()
            .find(|r| r.name == name)
            .unwrap()
            .domain_id);
    }
    let Some(b) = builtins().iter().find(|b| b.name == name) else {
        return Err(());
    };
    let id = sandbox::spawn_service_domain(name, user).map_err(|_| ())?;
    let _ = sandbox::start_domain(id);
    crate::ipc::registry::register(name, id);
    if name == "oneconsole" {
        crate::console::mgr::set_backend_domain(id);
    }

    let tid = crate::sched::spawn_domain_thread(
        b.name,
        id as u32,
        b.priority,
        service_entry,
        id as usize,
    );
    RUNNING.lock().push(RunningService {
        name: name.into(),
        domain_id: id,
        task_id: tid,
    });
    serial::log_line_args(format_args!(
        "service: started name={} domain={} task={}",
        name, id, tid
    ));
    Ok(id)
}

pub fn stop(name: &str) -> Result<(), ()> {
    let (id, task) = {
        let mut running = RUNNING.lock();
        let Some(pos) = running.iter().position(|r| r.name == name) else {
            return Err(());
        };
        let r = running.remove(pos);
        (r.domain_id, r.task_id)
    };
    let _ = task;
    let _ = crate::sandbox::stop_domain(id);
    crate::ipc::registry::unregister_by_domain(id);
    crate::sandbox::kill_domain(id);
    Ok(())
}

pub fn restart(name: &str, user: &str) -> Result<DomainId, ()> {
    let _ = stop(name);
    start(name, user)
}

pub fn restart_by_domain(domain_id: DomainId) -> bool {
    let Some(detail) = crate::sandbox::domain_detail_by_id(domain_id) else {
        return false;
    };
    if detail.summary.kind != crate::sandbox::DomainKind::SystemService {
        return false;
    }
    // Only restart services we manage (present in RUNNING list).
    let name = detail.summary.name.clone();
    let owner = detail.summary.owner.clone();
    if RUNNING.lock().iter().all(|r| r.name != name) {
        return false;
    }
    let _ = restart(&name, &owner);
    true
}
