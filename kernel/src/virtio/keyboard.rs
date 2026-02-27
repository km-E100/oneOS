#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use core::cmp;
use core::ptr;
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;

use crate::virtio::virtq;
use crate::{console::KeyEvent, display, drivers::serial};

const KEYBOARD_BUS: usize = 0;
const KEYBOARD_SLOT: usize = 0x5;
const KEYBOARD_FUNC: usize = 0;

// Safety limit: reject absurdly large queues.
const QUEUE_SIZE_LIMIT: u16 = 1024;

const VIRTQ_DESC_F_WRITE: u16 = 1 << 1;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;

const VIRTIO_PCI_DEVICE_FEATURES: usize = 0x00;
const VIRTIO_PCI_DRIVER_FEATURES: usize = 0x04;
const VIRTIO_PCI_QUEUE_ADDRESS: usize = 0x08;
const VIRTIO_PCI_QUEUE_SIZE: usize = 0x0C;
const VIRTIO_PCI_QUEUE_SELECT: usize = 0x0E;
const VIRTIO_PCI_QUEUE_NOTIFY: usize = 0x10;
const VIRTIO_PCI_STATUS: usize = 0x12;
const VIRTIO_PCI_ISR_STATUS: usize = 0x13;

const COMMON_DEVICE_FEATURE_SELECT: usize = 0x00;
const COMMON_DEVICE_FEATURE: usize = 0x04;
const COMMON_DRIVER_FEATURE_SELECT: usize = 0x08;
const COMMON_DRIVER_FEATURE: usize = 0x0C;
const COMMON_MSIX_CONFIG: usize = 0x10;
const COMMON_NUM_QUEUES: usize = 0x12;
const COMMON_DEVICE_STATUS: usize = 0x14;
const COMMON_CONFIG_GENERATION: usize = 0x15;
const COMMON_QUEUE_SELECT: usize = 0x16;
const COMMON_QUEUE_SIZE: usize = 0x18;
const COMMON_QUEUE_MSIX_VECTOR: usize = 0x1A;
const COMMON_QUEUE_ENABLE: usize = 0x1C;
const COMMON_QUEUE_NOTIFY_OFF: usize = 0x1E;
const COMMON_QUEUE_DESC: usize = 0x20;
const COMMON_QUEUE_DRIVER: usize = 0x28;
const COMMON_QUEUE_DEVICE: usize = 0x30;

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioInputEvent {
    event_type: u16,
    code: u16,
    value: u32,
}

impl VirtioInputEvent {
    const fn new() -> Self {
        Self {
            event_type: 0,
            code: 0,
            value: 0,
        }
    }
}

struct KeyboardQueue {
    q: virtq::Queue,
    events: Box<[VirtioInputEvent]>,
}

impl KeyboardQueue {
    fn new(qsize: u16) -> Option<Self> {
        let q = virtq::Queue::new(qsize)?;
        let events = vec![VirtioInputEvent::new(); qsize as usize].into_boxed_slice();

        unsafe {
            // Descriptor table: one write-only buffer per descriptor.
            for i in 0..(qsize as usize) {
                let desc = q.desc_ptr().add(i);
                *desc = virtq::Desc {
                    addr: (&events[i] as *const VirtioInputEvent) as u64,
                    len: core::mem::size_of::<VirtioInputEvent>() as u32,
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                };
            }

            // Make all descriptors available immediately.
            (*q.avail_hdr_ptr()).flags = 0;
            (*q.used_hdr_ptr()).flags = 0;
            (*q.used_hdr_ptr()).idx = 0;
            for i in 0..(qsize as usize) {
                *q.avail_ring_ptr().add(i) = i as u16;
            }
            fence(Ordering::Release);
            (*q.avail_hdr_ptr()).idx = qsize;
        }

        Some(Self { q, events })
    }
}

#[derive(Clone, Copy)]
struct ModernBackend {
    common: *mut u8,
    notify: *mut u8,
    notify_multiplier: u32,
    isr: *mut u8,
    device_cfg: *mut u8,
}

unsafe impl Send for ModernBackend {}
unsafe impl Sync for ModernBackend {}

struct KeyboardState {
    legacy_base: usize,
    modern: Option<ModernBackend>,
    queue: Option<KeyboardQueue>,
    queue_size: u16,
    avail_idx: u16,
    used_idx: u16,
    notify_off: u16,
    shift: bool,
    ready: bool,
}

impl KeyboardState {
    const fn new() -> Self {
        Self {
            legacy_base: 0,
            modern: None,
            queue: None,
            queue_size: 0,
            avail_idx: 0,
            used_idx: 0,
            notify_off: 0,
            shift: false,
            ready: false,
        }
    }
}

static KEYBOARD: Mutex<KeyboardState> = Mutex::new(KeyboardState::new());

/// MMU bring-up helper: return the minimal MMIO window that must be mapped
/// for the already-initialized virtio-keyboard device to keep working after
/// enabling TTBR0-based translation.
///
/// This is intentionally conservative and allocation-free.
pub fn mmu_required_mmio_window() -> Option<(u64, u64)> {
    let guard = KEYBOARD.lock();
    if !guard.ready {
        return None;
    }
    let Some(backend) = guard.modern else {
        // Legacy path uses a single BAR base; mapping it correctly requires reading BARs again.
        return None;
    };

    let align_down_4k = |v: u64| v & !0xfff;
    let align_up_4k = |v: u64| (v + 0xfff) & !0xfff;

    let common = backend.common as u64;
    let notify = backend.notify as u64;
    let isr = backend.isr as u64;
    let device = backend.device_cfg as u64;

    let mut base = common;
    for v in [notify, isr, device] {
        if v < base {
            base = v;
        }
    }

    // The notify doorbell can be accessed at notify + notify_off * notify_multiplier.
    // Map a wider window to avoid needing to know notify_off during early MMU bring-up.
    let mut end = common.saturating_add(0x1000);
    end = end.max(isr.saturating_add(0x1000));
    end = end.max(device.saturating_add(0x1000));
    end = end.max(notify.saturating_add(0x10_000));

    let base = align_down_4k(base);
    let end = align_up_4k(end);
    let len = end.saturating_sub(base);
    if len == 0 {
        None
    } else {
        Some((base, len))
    }
}

#[cfg(target_arch = "aarch64")]
const PCI_ECAM_BASE: usize = 0x4010_0000_00;

#[cfg(target_arch = "aarch64")]
fn config_ptr(offset: usize) -> *const u32 {
    let bus = KEYBOARD_BUS << 20;
    let slot = KEYBOARD_SLOT << 15;
    let func = KEYBOARD_FUNC << 12;
    let addr = PCI_ECAM_BASE + bus + slot + func + offset;
    addr as *const u32
}

#[cfg(target_arch = "aarch64")]
fn config_read_u32(offset: usize) -> u32 {
    unsafe { ptr::read_volatile(config_ptr(offset)) }
}

#[cfg(target_arch = "aarch64")]
fn config_read_u16(offset: usize) -> u16 {
    unsafe { ptr::read_volatile(config_ptr(offset) as *const u16) }
}

#[cfg(target_arch = "aarch64")]
fn config_read_u8(offset: usize) -> u8 {
    unsafe { ptr::read_volatile(config_ptr(offset) as *const u8) }
}

#[cfg(target_arch = "aarch64")]
fn config_write_u16(offset: usize, value: u16) {
    unsafe {
        ptr::write_volatile(config_ptr(offset) as *mut u16, value);
    }
}

#[cfg(target_arch = "x86_64")]
mod pci_cfg {
    use super::{KEYBOARD_BUS, KEYBOARD_FUNC, KEYBOARD_SLOT};
    use crate::drivers::serial;
    use core::arch::asm;
    use core::sync::atomic::{AtomicBool, Ordering};

    const CONFIG_ADDR: u16 = 0xCF8;
    const CONFIG_DATA: u16 = 0xCFC;
    static DIAG_ONCE: AtomicBool = AtomicBool::new(false);

    #[inline(always)]
    fn cfg_addr(offset: u16) -> u32 {
        let bus = KEYBOARD_BUS as u32;
        let slot = KEYBOARD_SLOT as u32;
        let func = KEYBOARD_FUNC as u32;
        0x8000_0000u32 | (bus << 16) | (slot << 11) | (func << 8) | ((offset as u32) & 0xFC)
    }

    #[inline(always)]
    unsafe fn outl(port: u16, value: u32) {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
    }

    #[inline(always)]
    unsafe fn inl(port: u16) -> u32 {
        let mut value: u32;
        asm!("in eax, dx", in("dx") port, out("eax") value, options(nomem, nostack, preserves_flags));
        value
    }

    pub fn read_u32(offset: usize) -> u32 {
        unsafe {
            if !DIAG_ONCE.swap(true, Ordering::Relaxed) {
                serial::log_line("virtio-keyboard: pci_cfg diag build=v2");
            }
            // Diagnostic: log privilege state before doing port I/O.
            // Use fixed registers to avoid any sub-register/stack-model surprises in early bring-up.
            let rflags: u64;
            let cs: u16;
            asm!(
                "pushfq",
                "pop rax",
                out("rax") rflags,
                // Uses the stack (push/pop), so do NOT mark as `nomem`/`nostack`.
                options(preserves_flags)
            );
            asm!(
                "mov ax, cs",
                out("ax") cs,
                options(nomem, nostack, preserves_flags)
            );
            let iopl = (rflags >> 12) & 0x3;
            let cpl = (cs & 0x3) as u64;
            let addr = cfg_addr(offset as u16);
            serial::log_line_args(format_args!(
                "virtio-keyboard: pci_cfg read_u32 off=0x{:x} cfg=0x{:08x} cs=0x{:x} cpl={} iopl={} rflags=0x{:x}",
                offset, addr, cs, cpl, iopl, rflags
            ));

            outl(CONFIG_ADDR, addr);
            let val = inl(CONFIG_DATA);
            serial::log_line_args(format_args!(
                "virtio-keyboard: pci_cfg read_u32 off=0x{:x} -> 0x{:08x}",
                offset, val
            ));
            val
        }
    }

    pub fn read_u16(offset: usize) -> u16 {
        let aligned = offset & !0x3;
        let shift = (offset & 0x2) * 8;
        ((read_u32(aligned) >> shift) & 0xFFFF) as u16
    }

    pub fn read_u8(offset: usize) -> u8 {
        let aligned = offset & !0x3;
        let shift = (offset & 0x3) * 8;
        ((read_u32(aligned) >> shift) & 0xFF) as u8
    }

    pub fn write_u16(offset: usize, value: u16) {
        let aligned = offset & !0x3;
        let shift = (offset & 0x2) * 8;
        let mut cur = read_u32(aligned);
        cur &= !(0xFFFFu32 << shift);
        cur |= (value as u32) << shift;
        unsafe {
            outl(CONFIG_ADDR, cfg_addr(aligned as u16));
            outl(CONFIG_DATA, cur);
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn config_read_u32(offset: usize) -> u32 {
    pci_cfg::read_u32(offset)
}

#[cfg(target_arch = "x86_64")]
fn config_read_u16(offset: usize) -> u16 {
    pci_cfg::read_u16(offset)
}

#[cfg(target_arch = "x86_64")]
fn config_read_u8(offset: usize) -> u8 {
    pci_cfg::read_u8(offset)
}

#[cfg(target_arch = "x86_64")]
fn config_write_u16(offset: usize, value: u16) {
    pci_cfg::write_u16(offset, value)
}

fn read_bar_addresses() -> [Option<u64>; 6] {
    let mut bars = [None; 6];
    let mut index = 0;
    while index < 6 {
        let offset = 0x10 + index * 4;
        let bar_low = config_read_u32(offset);
        serial::log_line_args(format_args!(
            "virtio-keyboard: BAR{} raw=0x{:08x}",
            index, bar_low
        ));
        if bar_low == 0 || bar_low == 0xFFFF_FFFF {
            index += 1;
            continue;
        }
        if (bar_low & 0x1) == 1 {
            // I/O BAR not supported
            index += 1;
            continue;
        }
        let bar_type = (bar_low >> 1) & 0x3;
        let mut addr = (bar_low as u64) & !0xF;
        if bar_type == 0x2 && index + 1 < 6 {
            let bar_high = config_read_u32(offset + 4);
            addr |= (bar_high as u64) << 32;
            serial::log_line_args(format_args!(
                "virtio-keyboard: BAR{} high=0x{:08x}",
                index, bar_high
            ));
            bars[index] = Some(addr);
            index += 2;
        } else {
            bars[index] = Some(addr);
            index += 1;
        }
    }
    bars
}

struct ModernRegions {
    common: *mut u8,
    notify: *mut u8,
    notify_multiplier: u32,
    isr: *mut u8,
    device: *mut u8,
}

fn scan_modern_caps(bars: &[Option<u64>; 6]) -> Option<ModernRegions> {
    let mut next = config_read_u8(0x34) as usize;
    if next == 0 {
        return None;
    }
    let mut common = None;
    let mut notify = None;
    let mut notify_multiplier = 0;
    let mut isr = None;
    let mut device = None;
    let mut guard = 0;
    while next != 0 && guard < 256 {
        guard += 1;
        let cap_vndr = config_read_u8(next);
        let cap_next = config_read_u8(next + 1);
        if cap_vndr == 0x09 {
            let cfg_type = config_read_u8(next + 3);
            let bar_index = config_read_u8(next + 4) as usize;
            let offset = config_read_u32(next + 8) as u32;
            let length = config_read_u32(next + 12) as u32;
            let bar_addr = match bars.get(bar_index).copied().flatten() {
                Some(addr) => addr as usize,
                None => {
                    serial::log_line_args(format_args!(
                        "virtio-cap: type={} bar{} missing",
                        cfg_type, bar_index
                    ));
                    next = cap_next as usize;
                    continue;
                }
            };
            let region_ptr = (bar_addr + offset as usize) as *mut u8;
            serial::log_line_args(format_args!(
                "virtio-cap: type={} bar{} off=0x{:x} len=0x{:x}",
                cfg_type, bar_index, offset, length
            ));
            match cfg_type {
                1 => common = Some(region_ptr),
                2 => {
                    notify = Some(region_ptr);
                    notify_multiplier = config_read_u32(next + 16);
                }
                3 => isr = Some(region_ptr),
                4 => device = Some(region_ptr),
                5 => {}
                _ => {}
            }
        }
        next = cap_next as usize;
    }
    match (common, notify, isr, device) {
        (Some(common), Some(notify), Some(isr), Some(device)) => Some(ModernRegions {
            common,
            notify,
            notify_multiplier,
            isr,
            device,
        }),
        _ => None,
    }
}

fn select_legacy_bar(bars: &[Option<u64>; 6]) -> Option<usize> {
    for entry in bars.iter() {
        if let Some(addr) = entry {
            return Some(*addr as usize);
        }
    }
    None
}

fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { ptr::read_volatile(base.add(offset) as *const u32) }
}

fn mmio_write32(base: *mut u8, offset: usize, value: u32) {
    unsafe {
        ptr::write_volatile(base.add(offset) as *mut u32, value);
    }
}

fn mmio_read16(base: *mut u8, offset: usize) -> u16 {
    unsafe { ptr::read_volatile(base.add(offset) as *const u16) }
}

fn mmio_write16(base: *mut u8, offset: usize, value: u16) {
    unsafe {
        ptr::write_volatile(base.add(offset) as *mut u16, value);
    }
}

fn mmio_write_status(base: *mut u8, value: u8) {
    unsafe {
        ptr::write_volatile(base.add(VIRTIO_PCI_STATUS) as *mut u8, value);
    }
}

fn mmio_read_status(base: *mut u8) -> u8 {
    unsafe { ptr::read_volatile(base.add(VIRTIO_PCI_STATUS) as *const u8) }
}

pub fn init() {
    let mut state = KEYBOARD.lock();
    if state.ready {
        return;
    }
    serial::log_line("virtio-keyboard: probing bus 0 slot 5 func 0");
    let vendor_device = config_read_u32(0x00);
    serial::log_line_args(format_args!(
        "virtio-keyboard: cfg(0x00) vendor_device=0x{:08x}",
        vendor_device
    ));
    if vendor_device == 0xFFFF_FFFF {
        display::write_line("virtio-keyboard: not present (PCI config read failed)");
        serial::log_line("virtio-keyboard: config read returned 0xFFFF_FFFF");
        return;
    }
    let vendor = (vendor_device & 0xFFFF) as u16;
    let device = ((vendor_device >> 16) & 0xFFFF) as u16;
    serial::log_line("virtio-keyboard: cfg decode ok");
    serial::log_line_args(format_args!(
        "virtio-keyboard: vendor=0x{:04x} device=0x{:04x}",
        vendor, device
    ));

    // Ensure PCI Memory Space + Bus Master are enabled (needed after ExitBootServices).
    serial::log_line("virtio-keyboard: about to read PCI command");
    let cmd = config_read_u16(0x04);
    let new_cmd = cmd | 0x0006;
    if new_cmd != cmd {
        config_write_u16(0x04, new_cmd);
    }
    serial::log_line_args(format_args!(
        "virtio-keyboard: pci command 0x{:04x} -> 0x{:04x}",
        cmd, new_cmd
    ));

    let bars = read_bar_addresses();
    if let Some(regions) = scan_modern_caps(&bars) {
        serial::log_line("virtio-keyboard: using virtio 1.0 capabilities");
        if configure_modern(&mut state, vendor, device, regions) {
            return;
        }
        serial::log_line("virtio-keyboard: modern init failed, falling back to legacy");
    }

    if configure_legacy(&mut state, vendor, device, &bars) {
        return;
    }

    display::write_line("virtio-keyboard: initialization failed");
    serial::log_line("virtio-keyboard: unable to configure device");
}

fn configure_modern(
    state: &mut KeyboardState,
    vendor: u16,
    device: u16,
    regions: ModernRegions,
) -> bool {
    let common = regions.common;
    common_write_u8(common, COMMON_DEVICE_STATUS, 0);
    let mut status = STATUS_ACKNOWLEDGE;
    common_write_u8(common, COMMON_DEVICE_STATUS, status);
    status |= STATUS_DRIVER;
    common_write_u8(common, COMMON_DEVICE_STATUS, status);

    common_write_u32(common, COMMON_DEVICE_FEATURE_SELECT, 0);
    let host_features = common_read_u32(common, COMMON_DEVICE_FEATURE);
    common_write_u32(common, COMMON_DRIVER_FEATURE_SELECT, 0);
    common_write_u32(common, COMMON_DRIVER_FEATURE, host_features & 0);

    status |= STATUS_FEATURES_OK;
    common_write_u8(common, COMMON_DEVICE_STATUS, status);
    let confirmed = common_read_u8(common, COMMON_DEVICE_STATUS);
    if (confirmed & STATUS_FEATURES_OK) == 0 {
        display::write_line("virtio-keyboard: FEATURES_OK rejected");
        return false;
    }

    common_write_u16(common, COMMON_QUEUE_SELECT, 0);
    let device_qs = common_read_u16(common, COMMON_QUEUE_SIZE);
    if device_qs == 0 {
        display::write_line("virtio-keyboard: queue size is zero");
        return false;
    }
    if device_qs > QUEUE_SIZE_LIMIT {
        display::write_line_args(format_args!(
            "virtio-keyboard: queue too large (qs={})",
            device_qs
        ));
        return false;
    }

    let queue = match KeyboardQueue::new(device_qs) {
        Some(q) => q,
        None => {
            display::write_line("virtio-keyboard: queue alloc failed");
            return false;
        }
    };

    let desc_addr = queue.q.desc_ptr() as u64;
    let avail_addr = queue.q.avail_hdr_ptr() as u64;
    let used_addr = queue.q.used_hdr_ptr() as u64;
    common_write_u64(common, COMMON_QUEUE_DESC, desc_addr);
    common_write_u64(common, COMMON_QUEUE_DRIVER, avail_addr);
    common_write_u64(common, COMMON_QUEUE_DEVICE, used_addr);
    common_write_u16(common, COMMON_QUEUE_ENABLE, 1);
    let queue_notify_off = common_read_u16(common, COMMON_QUEUE_NOTIFY_OFF);

    status |= STATUS_DRIVER_OK;
    common_write_u8(common, COMMON_DEVICE_STATUS, status);

    state.queue = Some(queue);
    state.queue_size = device_qs;
    state.avail_idx = device_qs;
    state.used_idx = 0;
    state.notify_off = queue_notify_off;
    state.legacy_base = 0;
    state.modern = Some(ModernBackend {
        common,
        notify: regions.notify,
        notify_multiplier: regions.notify_multiplier,
        isr: regions.isr,
        device_cfg: regions.device,
    });
    state.ready = true;

    display::write_line_args(format_args!(
        "virtio-keyboard: modern ready (vendor=0x{:04x} device=0x{:04x})",
        vendor, device
    ));
    serial::log_line("virtio-keyboard: modern queue configured");
    notify_queue(state);
    true
}

fn configure_legacy(
    state: &mut KeyboardState,
    vendor: u16,
    device: u16,
    bars: &[Option<u64>; 6],
) -> bool {
    let Some(base_addr) = select_legacy_bar(bars) else {
        serial::log_line("virtio-keyboard: no usable legacy BAR");
        return false;
    };
    let base = base_addr as *mut u8;

    mmio_write_status(base, 0);
    mmio_write_status(base, STATUS_ACKNOWLEDGE);
    mmio_write_status(base, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    let host_features = mmio_read32(base, VIRTIO_PCI_DEVICE_FEATURES);
    mmio_write32(base, VIRTIO_PCI_DRIVER_FEATURES, host_features & 0);

    let mut status = STATUS_ACKNOWLEDGE | STATUS_DRIVER;
    status |= STATUS_FEATURES_OK;
    mmio_write_status(base, status);

    mmio_write16(base, VIRTIO_PCI_QUEUE_SELECT, 0);
    let device_qs = mmio_read16(base, VIRTIO_PCI_QUEUE_SIZE);
    if device_qs == 0 {
        display::write_line("virtio-keyboard: queue size is zero");
        return false;
    }
    if device_qs > QUEUE_SIZE_LIMIT {
        display::write_line_args(format_args!(
            "virtio-keyboard: queue too large (qs={})",
            device_qs
        ));
        return false;
    }

    let queue = match KeyboardQueue::new(device_qs) {
        Some(q) => q,
        None => {
            display::write_line("virtio-keyboard: queue alloc failed");
            return false;
        }
    };

    state.queue_size = device_qs;
    state.avail_idx = device_qs;
    state.used_idx = 0;
    state.notify_off = 0;
    state.legacy_base = base_addr;
    state.modern = None;

    let queue_addr = (queue.q.base_ptr() as u64 >> 12) as u32;
    mmio_write32(base, VIRTIO_PCI_QUEUE_ADDRESS, queue_addr);
    state.queue = Some(queue);

    status |= STATUS_DRIVER_OK;
    mmio_write_status(base, status);
    state.ready = true;

    display::write_line_args(format_args!(
        "virtio-keyboard: legacy ready (vendor=0x{:04x} device=0x{:04x})",
        vendor, device
    ));
    serial::log_line("virtio-keyboard: legacy queue configured");
    notify_queue(state);
    true
}

fn notify_queue(state: &KeyboardState) {
    if let Some(modern) = &state.modern {
        let offset = (state.notify_off as u32 as usize) * (modern.notify_multiplier as usize);
        unsafe {
            let doorbell = modern.notify.add(offset) as *mut u16;
            ptr::write_volatile(doorbell, 0u16);
        }
    } else if state.legacy_base != 0 {
        let base = state.legacy_base as *mut u8;
        mmio_write16(base, VIRTIO_PCI_QUEUE_NOTIFY, 0);
    }
}

fn acknowledge_interrupt(state: &KeyboardState) {
    if let Some(modern) = &state.modern {
        unsafe {
            ptr::read_volatile(modern.isr as *const u8);
        }
    } else if state.legacy_base != 0 {
        let base = state.legacy_base as *mut u8;
        let _ = mmio_read8(base, VIRTIO_PCI_ISR_STATUS);
    }
}

pub fn available() -> bool {
    KEYBOARD.lock().ready
}

pub fn poll_key() -> Option<KeyEvent> {
    let mut guard = KEYBOARD.lock();
    if !guard.ready {
        return None;
    }
    let queue_size = guard.queue_size;
    let used_idx = unsafe {
        let queue = guard.queue.as_ref()?;
        ptr::read_volatile(&(*queue.q.used_hdr_ptr()).idx)
    };
    if guard.used_idx == used_idx {
        return None;
    }
    fence(Ordering::Acquire);
    let ring_idx = (guard.used_idx % queue_size) as usize;
    let next_used = guard.used_idx.wrapping_add(1);

    let (desc_id, event) = {
        let queue = guard.queue.as_ref()?;
        let elem = unsafe { ptr::read_volatile(queue.q.used_ring_ptr().add(ring_idx)) };
        let desc_id = elem.id as usize;
        let event = queue.events.get(desc_id).copied()?;
        (desc_id, event)
    };
    guard.used_idx = next_used;

    // recycle descriptor
    let avail_slot = (guard.avail_idx % queue_size) as usize;
    let next_avail = guard.avail_idx.wrapping_add(1);
    unsafe {
        let queue = guard.queue.as_ref()?;
        ptr::write_volatile(queue.q.avail_ring_ptr().add(avail_slot), desc_id as u16);
        fence(Ordering::Release);
        ptr::write_volatile(&mut (*queue.q.avail_hdr_ptr()).idx, next_avail);
    }
    guard.avail_idx = next_avail;
    notify_queue(&guard);
    acknowledge_interrupt(&guard);

    handle_input_event(&mut guard, event)
}

fn mmio_read8(base: *mut u8, offset: usize) -> u8 {
    unsafe { ptr::read_volatile(base.add(offset) as *const u8) }
}

fn common_write_u8(base: *mut u8, offset: usize, value: u8) {
    unsafe { ptr::write_volatile(base.add(offset) as *mut u8, value) }
}

fn common_read_u8(base: *mut u8, offset: usize) -> u8 {
    unsafe { ptr::read_volatile(base.add(offset) as *const u8) }
}

fn common_write_u16(base: *mut u8, offset: usize, value: u16) {
    unsafe { ptr::write_volatile(base.add(offset) as *mut u16, value) }
}

fn common_read_u16(base: *mut u8, offset: usize) -> u16 {
    unsafe { ptr::read_volatile(base.add(offset) as *const u16) }
}

fn common_write_u32(base: *mut u8, offset: usize, value: u32) {
    unsafe { ptr::write_volatile(base.add(offset) as *mut u32, value) }
}

fn common_read_u32(base: *mut u8, offset: usize) -> u32 {
    unsafe { ptr::read_volatile(base.add(offset) as *const u32) }
}

fn common_write_u64(base: *mut u8, offset: usize, value: u64) {
    unsafe { ptr::write_volatile(base.add(offset) as *mut u64, value) }
}

fn handle_input_event(state: &mut KeyboardState, event: VirtioInputEvent) -> Option<KeyEvent> {
    const EV_KEY: u16 = 1;
    if event.event_type != EV_KEY {
        return None;
    }
    match event.code {
        42 | 54 => {
            match event.value {
                1 => state.shift = true,
                0 => state.shift = false,
                _ => {}
            }
            None
        }
        // modifiers we currently ignore
        29 | 97 | 56 | 100 | 58 | 125 => None, // ctrl/alt/caps/meta
        14 => {
            if event.value == 1 {
                Some(KeyEvent::Backspace)
            } else {
                None
            }
        }
        15 => (event.value == 1).then_some(KeyEvent::Tab),
        28 => {
            if event.value == 1 {
                Some(KeyEvent::Enter)
            } else {
                None
            }
        }
        code => {
            if event.value == 0 {
                return None;
            }
            match scancode_to_char(code, state.shift) {
                Some(ch) => Some(KeyEvent::Char(ch)),
                None => {
                    if event.value == 1 {
                        serial::log_line_args(format_args!(
                            "virtio-keyboard: unhandled code {} val {}",
                            event.code, event.value
                        ));
                    }
                    None
                }
            }
        }
    }
}

fn scancode_to_char(code: u16, shift: bool) -> Option<char> {
    let base = match code {
        2 => Some('1'),
        3 => Some('2'),
        4 => Some('3'),
        5 => Some('4'),
        6 => Some('5'),
        7 => Some('6'),
        8 => Some('7'),
        9 => Some('8'),
        10 => Some('9'),
        11 => Some('0'),
        12 => Some('-'),
        13 => Some('='),
        16 => Some('q'),
        17 => Some('w'),
        18 => Some('e'),
        19 => Some('r'),
        20 => Some('t'),
        21 => Some('y'),
        22 => Some('u'),
        23 => Some('i'),
        24 => Some('o'),
        25 => Some('p'),
        26 => Some('['),
        27 => Some(']'),
        30 => Some('a'),
        31 => Some('s'),
        32 => Some('d'),
        33 => Some('f'),
        34 => Some('g'),
        35 => Some('h'),
        36 => Some('j'),
        37 => Some('k'),
        38 => Some('l'),
        39 => Some(';'),
        40 => Some('\''),
        41 => Some('`'),
        43 => Some('\\'),
        44 => Some('z'),
        45 => Some('x'),
        46 => Some('c'),
        47 => Some('v'),
        48 => Some('b'),
        49 => Some('n'),
        50 => Some('m'),
        51 => Some(','),
        52 => Some('.'),
        53 => Some('/'),
        57 => Some(' '),
        _ => None,
    }?;
    Some(match (base, shift) {
        (c, true) if c.is_ascii_alphabetic() => c.to_ascii_uppercase(),
        ('1', true) => '!',
        ('2', true) => '@',
        ('3', true) => '#',
        ('4', true) => '$',
        ('5', true) => '%',
        ('6', true) => '^',
        ('7', true) => '&',
        ('8', true) => '*',
        ('9', true) => '(',
        ('0', true) => ')',
        ('-', true) => '_',
        ('=', true) => '+',
        ('[', true) => '{',
        (']', true) => '}',
        (';', true) => ':',
        ('\'', true) => '"',
        ('`', true) => '~',
        ('\\', true) => '|',
        (',', true) => '<',
        ('.', true) => '>',
        ('/', true) => '?',
        (c, _) => c,
    })
}
