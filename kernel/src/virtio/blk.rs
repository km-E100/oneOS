#![allow(dead_code)]

use core::cmp;
use core::ptr;
use core::sync::atomic::{fence, Ordering};

use spin::Mutex;

use crate::boot_info;
use crate::drivers::serial;
use crate::virtio::virtq;

// virtio PCI vendor/device
const PCI_VENDOR_REDHAT: u16 = 0x1af4;
const PCI_DEVICE_VIRTIO_BLK_MODERN: u16 = 0x1042;
const PCI_DEVICE_VIRTIO_BLK_TRANSITIONAL: u16 = 0x1001;

// PCI config offsets
const PCI_VENDOR_ID: usize = 0x00;
const PCI_DEVICE_ID: usize = 0x02;
const PCI_COMMAND: usize = 0x04;
const PCI_STATUS: usize = 0x06;
const PCI_CAP_PTR: usize = 0x34;
const PCI_BAR0: usize = 0x10;

const PCI_COMMAND_IO: u16 = 1 << 0;
const PCI_COMMAND_MEMORY: u16 = 1 << 1;
const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;
const PCI_STATUS_CAP_LIST: u16 = 1 << 4;

// Virtio 1.0 PCI capability
const PCI_CAP_ID_VENDOR: u8 = 0x09;

// cfg_type in virtio_pci_cap
const VIRTIO_PCI_CAP_COMMON: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY: u8 = 2;
const VIRTIO_PCI_CAP_ISR: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE: u8 = 4;

// Common config offsets (virtio 1.0)
const COMMON_DEVICE_FEATURE_SELECT: usize = 0x00;
const COMMON_DEVICE_FEATURE: usize = 0x04;
const COMMON_DRIVER_FEATURE_SELECT: usize = 0x08;
const COMMON_DRIVER_FEATURE: usize = 0x0C;
const COMMON_NUM_QUEUES: usize = 0x12;
const COMMON_DEVICE_STATUS: usize = 0x14;
const COMMON_QUEUE_SELECT: usize = 0x16;
const COMMON_QUEUE_SIZE: usize = 0x18;
const COMMON_QUEUE_ENABLE: usize = 0x1C;
const COMMON_QUEUE_NOTIFY_OFF: usize = 0x1E;
const COMMON_QUEUE_DESC: usize = 0x20;
const COMMON_QUEUE_DRIVER: usize = 0x28;
const COMMON_QUEUE_DEVICE: usize = 0x30;

// Device status bits
const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;

// Safety limit: reject absurdly large queues.
const QUEUE_SIZE_LIMIT: u16 = 1024;
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 1 << 1;

// virtio-blk request
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct BlkReqHeader {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

static mut REQ_HDR: BlkReqHeader = BlkReqHeader {
    req_type: VIRTIO_BLK_T_IN,
    reserved: 0,
    sector: 0,
};
static mut REQ_STATUS: u8 = 0;
static mut SECTOR_BUF: [u8; 512] = [0u8; 512];
// Large scratch buffer used to collapse many 512B sector reads into a small number of virtio
// requests (critical for GOES replay and App cold-start performance).
const BULK_BUF_SIZE: usize = 256 * 1024; // 256KiB
static mut BULK_BUF: [u8; BULK_BUF_SIZE] = [0u8; BULK_BUF_SIZE];

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

struct BlkState {
    backend: Option<ModernBackend>,
    queue: Option<virtq::Queue>,
    queue_size: u16,
    used_idx: u16,
    notify_off: u16,
    capacity_sectors: u64,
    ready: bool,
}

impl BlkState {
    const fn new() -> Self {
        Self {
            backend: None,
            queue: None,
            queue_size: 0,
            used_idx: 0,
            notify_off: 0,
            capacity_sectors: 0,
            ready: false,
        }
    }
}

static BLK: Mutex<BlkState> = Mutex::new(BlkState::new());

/// MMU bring-up helper: return the minimal MMIO window that must be mapped
/// for the already-initialized virtio-blk device to keep working after
/// enabling TTBR0-based translation.
///
/// This is intentionally conservative and allocation-free.
pub fn mmu_required_mmio_window() -> Option<(u64, u64)> {
    let guard = BLK.lock();
    if !guard.ready {
        return None;
    }
    let Some(backend) = guard.backend else {
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
fn ecam_addr(bus: u8, slot: u8, func: u8, offset: usize) -> usize {
    PCI_ECAM_BASE
        + ((bus as usize) << 20)
        + ((slot as usize) << 15)
        + ((func as usize) << 12)
        + offset
}

#[cfg(target_arch = "aarch64")]
fn pci_read_u32(bus: u8, slot: u8, func: u8, offset: usize) -> u32 {
    unsafe { ptr::read_volatile(ecam_addr(bus, slot, func, offset) as *const u32) }
}

#[cfg(target_arch = "aarch64")]
fn pci_read_u16(bus: u8, slot: u8, func: u8, offset: usize) -> u16 {
    unsafe { ptr::read_volatile(ecam_addr(bus, slot, func, offset) as *const u16) }
}

#[cfg(target_arch = "aarch64")]
fn pci_read_u8(bus: u8, slot: u8, func: u8, offset: usize) -> u8 {
    unsafe { ptr::read_volatile(ecam_addr(bus, slot, func, offset) as *const u8) }
}

#[cfg(target_arch = "aarch64")]
fn pci_write_u16(bus: u8, slot: u8, func: u8, offset: usize, value: u16) {
    unsafe { ptr::write_volatile(ecam_addr(bus, slot, func, offset) as *mut u16, value) }
}

#[cfg(target_arch = "x86_64")]
mod pci_cf8cfc {
    use core::arch::asm;

    const CONFIG_ADDR: u16 = 0xCF8;
    const CONFIG_DATA: u16 = 0xCFC;

    #[inline(always)]
    fn cfg_addr(bus: u8, slot: u8, func: u8, offset: u16) -> u32 {
        0x8000_0000u32
            | ((bus as u32) << 16)
            | ((slot as u32) << 11)
            | ((func as u32) << 8)
            | ((offset as u32) & 0xFC)
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

    pub fn read_u32(bus: u8, slot: u8, func: u8, offset: usize) -> u32 {
        unsafe {
            outl(CONFIG_ADDR, cfg_addr(bus, slot, func, offset as u16));
            inl(CONFIG_DATA)
        }
    }

    pub fn read_u16(bus: u8, slot: u8, func: u8, offset: usize) -> u16 {
        let aligned = offset & !0x3;
        let shift = (offset & 0x2) * 8;
        ((read_u32(bus, slot, func, aligned) >> shift) & 0xFFFF) as u16
    }

    pub fn read_u8(bus: u8, slot: u8, func: u8, offset: usize) -> u8 {
        let aligned = offset & !0x3;
        let shift = (offset & 0x3) * 8;
        ((read_u32(bus, slot, func, aligned) >> shift) & 0xFF) as u8
    }

    pub fn write_u16(bus: u8, slot: u8, func: u8, offset: usize, value: u16) {
        let aligned = offset & !0x3;
        let shift = (offset & 0x2) * 8;
        let mut cur = read_u32(bus, slot, func, aligned);
        cur &= !(0xFFFFu32 << shift);
        cur |= (value as u32) << shift;
        unsafe {
            outl(CONFIG_ADDR, cfg_addr(bus, slot, func, aligned as u16));
            outl(CONFIG_DATA, cur);
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn pci_read_u32(bus: u8, slot: u8, func: u8, offset: usize) -> u32 {
    pci_cf8cfc::read_u32(bus, slot, func, offset)
}

#[cfg(target_arch = "x86_64")]
fn pci_read_u16(bus: u8, slot: u8, func: u8, offset: usize) -> u16 {
    pci_cf8cfc::read_u16(bus, slot, func, offset)
}

#[cfg(target_arch = "x86_64")]
fn pci_read_u8(bus: u8, slot: u8, func: u8, offset: usize) -> u8 {
    pci_cf8cfc::read_u8(bus, slot, func, offset)
}

#[cfg(target_arch = "x86_64")]
fn pci_write_u16(bus: u8, slot: u8, func: u8, offset: usize, value: u16) {
    pci_cf8cfc::write_u16(bus, slot, func, offset, value)
}

#[derive(Clone, Copy)]
struct VirtioPciCap {
    cfg_type: u8,
    bar: u8,
    offset: u32,
    length: u32,
    notify_multiplier: u32,
}

fn parse_caps(bus: u8, slot: u8, func: u8) -> Option<(ModernBackend, u16)> {
    let status = pci_read_u16(bus, slot, func, PCI_STATUS);
    if (status & PCI_STATUS_CAP_LIST) == 0 {
        return None;
    }
    let cap_ptr = pci_read_u8(bus, slot, func, PCI_CAP_PTR) & !0x3;
    if cap_ptr == 0 {
        return None;
    }

    let bars = read_bar_addresses(bus, slot, func);

    let mut common: Option<VirtioPciCap> = None;
    let mut notify: Option<VirtioPciCap> = None;
    let mut isr: Option<VirtioPciCap> = None;
    let mut device: Option<VirtioPciCap> = None;

    let mut cur = cap_ptr as usize;
    let mut iter = 0;
    while cur != 0 && iter < 64 {
        iter += 1;
        let cap_id = pci_read_u8(bus, slot, func, cur);
        let next = pci_read_u8(bus, slot, func, cur + 1);
        if cap_id == PCI_CAP_ID_VENDOR {
            let cfg_type = pci_read_u8(bus, slot, func, cur + 3);
            let bar = pci_read_u8(bus, slot, func, cur + 4);
            let offset = pci_read_u32(bus, slot, func, cur + 8);
            let length = pci_read_u32(bus, slot, func, cur + 12);
            let notify_multiplier = if cfg_type == VIRTIO_PCI_CAP_NOTIFY {
                pci_read_u32(bus, slot, func, cur + 16)
            } else {
                0
            };
            let cap = VirtioPciCap {
                cfg_type,
                bar,
                offset,
                length,
                notify_multiplier,
            };
            match cfg_type {
                VIRTIO_PCI_CAP_COMMON => common = Some(cap),
                VIRTIO_PCI_CAP_NOTIFY => notify = Some(cap),
                VIRTIO_PCI_CAP_ISR => isr = Some(cap),
                VIRTIO_PCI_CAP_DEVICE => device = Some(cap),
                _ => {}
            }
        }
        cur = (next & !0x3) as usize;
    }

    let common = common?;
    let notify = notify?;
    let isr = isr?;
    let device = device?;

    let bar_common = *bars.get(common.bar as usize)?.as_ref()?;
    let bar_notify = *bars.get(notify.bar as usize)?.as_ref()?;
    let bar_isr = *bars.get(isr.bar as usize)?.as_ref()?;
    let bar_dev = *bars.get(device.bar as usize)?.as_ref()?;

    let backend = ModernBackend {
        common: (bar_common + common.offset as u64) as *mut u8,
        notify: (bar_notify + notify.offset as u64) as *mut u8,
        notify_multiplier: notify.notify_multiplier,
        isr: (bar_isr + isr.offset as u64) as *mut u8,
        device_cfg: (bar_dev + device.offset as u64) as *mut u8,
    };

    // Read virtio PCI queue notify off multiplier and queue size later.
    let num_queues = common_read_u16(backend.common, COMMON_NUM_QUEUES);
    Some((backend, num_queues))
}

fn read_bar_addresses(bus: u8, slot: u8, func: u8) -> [Option<u64>; 6] {
    let mut bars = [None; 6];
    let mut index = 0usize;
    while index < 6 {
        let off = PCI_BAR0 + index * 4;
        let raw = pci_read_u32(bus, slot, func, off);
        if raw == 0 {
            index += 1;
            continue;
        }
        // I/O BAR not supported here.
        if (raw & 1) != 0 {
            index += 1;
            continue;
        }
        let bar_type = (raw >> 1) & 0x3;
        if bar_type == 0x2 {
            // 64-bit
            let high = pci_read_u32(bus, slot, func, off + 4);
            let addr = ((high as u64) << 32) | ((raw as u64) & 0xFFFF_FFF0);
            bars[index] = Some(addr);
            index += 2;
        } else {
            bars[index] = Some((raw as u64) & 0xFFFF_FFF0);
            index += 1;
        }
    }
    bars
}

fn common_write_u8(base: *mut u8, offset: usize, value: u8) {
    unsafe { ptr::write_volatile(base.add(offset) as *mut u8, value) }
}

fn common_read_u16(base: *mut u8, offset: usize) -> u16 {
    unsafe { ptr::read_volatile(base.add(offset) as *const u16) }
}

fn common_write_u16(base: *mut u8, offset: usize, value: u16) {
    unsafe { ptr::write_volatile(base.add(offset) as *mut u16, value) }
}

fn common_read_u32(base: *mut u8, offset: usize) -> u32 {
    unsafe { ptr::read_volatile(base.add(offset) as *const u32) }
}

fn common_write_u32(base: *mut u8, offset: usize, value: u32) {
    unsafe { ptr::write_volatile(base.add(offset) as *mut u32, value) }
}

fn common_write_u64(base: *mut u8, offset: usize, value: u64) {
    unsafe { ptr::write_volatile(base.add(offset) as *mut u64, value) }
}

fn notify_queue(state: &BlkState) {
    let Some(backend) = &state.backend else {
        return;
    };
    let offset = (state.notify_off as u32 as usize) * (backend.notify_multiplier as usize);
    unsafe {
        let doorbell = backend.notify.add(offset) as *mut u16;
        ptr::write_volatile(doorbell, 0u16);
    }
}

fn ack_interrupt(state: &BlkState) {
    let Some(backend) = &state.backend else {
        return;
    };
    unsafe {
        ptr::read_volatile(backend.isr as *const u8);
    }
}

pub fn init() {
    let mut guard = BLK.lock();
    if guard.ready {
        return;
    }
    serial::log_line("virtio-blk: probing pci for block device");

    let mut found: Option<(u8, u8, u8)> = None;
    if let Some(info) = boot_info::get() {
        if let Some(id) = info.goes_device_id() {
            if id != 0 {
                let bus = ((id >> 16) & 0xff) as u8;
                let slot = ((id >> 8) & 0xff) as u8;
                let func = (id & 0xff) as u8;
                serial::log_line_args(format_args!(
                    "virtio-blk: prefer GOES device from boot_info: {}:{:02x}.{} (id=0x{:08x})",
                    bus, slot, func, id
                ));
                let vendor = pci_read_u16(bus, slot, func, PCI_VENDOR_ID);
                let device = pci_read_u16(bus, slot, func, PCI_DEVICE_ID);
                if vendor == PCI_VENDOR_REDHAT
                    && (device == PCI_DEVICE_VIRTIO_BLK_MODERN
                        || device == PCI_DEVICE_VIRTIO_BLK_TRANSITIONAL)
                {
                    found = Some((bus, slot, func));
                } else {
                    serial::log_line_args(format_args!(
                        "virtio-blk: preferred device mismatch vendor=0x{:04x} device=0x{:04x}, fallback to scan",
                        vendor, device
                    ));
                }
            }
        }
    }

    if found.is_none() {
        'scan: for slot in 0u8..32 {
            for func in 0u8..8 {
                let vendor = pci_read_u16(0, slot, func, PCI_VENDOR_ID);
                if vendor == 0xFFFF {
                    if func == 0 {
                        continue 'scan;
                    }
                    continue;
                }
                let device = pci_read_u16(0, slot, func, PCI_DEVICE_ID);
                if vendor == PCI_VENDOR_REDHAT {
                    serial::log_line_args(format_args!(
                        "virtio-blk: virtio candidate slot {} func {} device=0x{:04x}",
                        slot, func, device
                    ));
                }
                if vendor == PCI_VENDOR_REDHAT
                    && (device == PCI_DEVICE_VIRTIO_BLK_MODERN
                        || device == PCI_DEVICE_VIRTIO_BLK_TRANSITIONAL)
                {
                    found = Some((0, slot, func));
                    break 'scan;
                }
            }
        }
    }

    let Some((bus, slot, func)) = found else {
        serial::log_line("virtio-blk: not present");
        return;
    };
    serial::log_line_args(format_args!(
        "virtio-blk: found at bus {} slot {} func {}",
        bus, slot, func
    ));

    // Enable MEM + bus master.
    let cmd0 = pci_read_u16(bus, slot, func, PCI_COMMAND);
    let cmd1 = cmd0 | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER;
    if cmd1 != cmd0 {
        pci_write_u16(bus, slot, func, PCI_COMMAND, cmd1);
    }
    serial::log_line_args(format_args!(
        "virtio-blk: pci command {:#06x} -> {:#06x}",
        cmd0, cmd1
    ));

    let Some((backend, num_queues)) = parse_caps(bus, slot, func) else {
        serial::log_line("virtio-blk: virtio 1.0 capabilities missing");
        return;
    };
    serial::log_line_args(format_args!("virtio-blk: num_queues={}", num_queues));

    // Reset + ack/driver
    common_write_u8(backend.common, COMMON_DEVICE_STATUS, 0);
    common_write_u8(
        backend.common,
        COMMON_DEVICE_STATUS,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER,
    );

    // Negotiate features: accept 0 for now (read-only use).
    common_write_u32(backend.common, COMMON_DEVICE_FEATURE_SELECT, 0);
    let _device_features0 = common_read_u32(backend.common, COMMON_DEVICE_FEATURE);
    common_write_u32(backend.common, COMMON_DRIVER_FEATURE_SELECT, 0);
    common_write_u32(backend.common, COMMON_DRIVER_FEATURE, 0);
    common_write_u32(backend.common, COMMON_DRIVER_FEATURE_SELECT, 1);
    common_write_u32(backend.common, COMMON_DRIVER_FEATURE, 0);

    // FEATURES_OK
    let mut status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
    common_write_u8(backend.common, COMMON_DEVICE_STATUS, status);

    // Queue 0
    common_write_u16(backend.common, COMMON_QUEUE_SELECT, 0);
    let qs = common_read_u16(backend.common, COMMON_QUEUE_SIZE);
    if qs == 0 {
        serial::log_line("virtio-blk: queue size is zero");
        return;
    }
    if qs > QUEUE_SIZE_LIMIT {
        serial::log_line_args(format_args!("virtio-blk: queue too large (qs={})", qs));
        return;
    }

    let queue = match virtq::Queue::new(qs) {
        Some(q) => q,
        None => {
            serial::log_line("virtio-blk: queue alloc failed");
            return;
        }
    };
    unsafe {
        (*queue.avail_hdr_ptr()).flags = 0;
        (*queue.avail_hdr_ptr()).idx = 0;
        (*queue.used_hdr_ptr()).flags = 0;
        (*queue.used_hdr_ptr()).idx = 0;
        // descriptors are configured per request
    }

    let desc_addr = queue.desc_ptr() as u64;
    let avail_addr = queue.avail_hdr_ptr() as u64;
    let used_addr = queue.used_hdr_ptr() as u64;

    common_write_u64(backend.common, COMMON_QUEUE_DESC, desc_addr);
    common_write_u64(backend.common, COMMON_QUEUE_DRIVER, avail_addr);
    common_write_u64(backend.common, COMMON_QUEUE_DEVICE, used_addr);
    let notify_off = common_read_u16(backend.common, COMMON_QUEUE_NOTIFY_OFF);
    common_write_u16(backend.common, COMMON_QUEUE_ENABLE, 1);

    // Read capacity from device config (offset 0, u64)
    let cap = unsafe { ptr::read_volatile(backend.device_cfg as *const u64) };

    status |= STATUS_DRIVER_OK;
    common_write_u8(backend.common, COMMON_DEVICE_STATUS, status);

    guard.backend = Some(backend);
    guard.queue = Some(queue);
    guard.queue_size = qs;
    guard.used_idx = 0;
    guard.notify_off = notify_off;
    guard.capacity_sectors = cap;
    guard.ready = true;

    serial::log_line_args(format_args!("virtio-blk: ready (capacity={} sectors)", cap));
}

pub fn available() -> bool {
    BLK.lock().ready
}

pub fn capacity_bytes() -> Option<u64> {
    let guard = BLK.lock();
    if !guard.ready {
        return None;
    }
    Some(guard.capacity_sectors.saturating_mul(512))
}

fn submit_read_sector(state: &mut BlkState, lba: u64) -> bool {
    unsafe { submit_read_blocks(state, lba, &raw mut SECTOR_BUF as *mut _ as *mut u8, 1) }
}

unsafe fn submit_read_blocks(state: &mut BlkState, lba: u64, buf: *mut u8, blocks: usize) -> bool {
    let Some(_backend) = &state.backend else {
        return false;
    };
    let Some(queue) = state.queue.as_ref() else {
        return false;
    };
    let qs = state.queue_size;
    if qs < 3 {
        return false;
    }
    if blocks == 0 || blocks > (u32::MAX as usize / 512) {
        return false;
    }
    let data_len = (blocks * 512) as u32;

    REQ_HDR.req_type = VIRTIO_BLK_T_IN;
    REQ_HDR.reserved = 0;
    REQ_HDR.sector = lba;
    REQ_STATUS = 0xFF;

    // desc 0: header
    {
        let desc = queue.desc_ptr();
        (*desc.add(0)).addr = &raw const REQ_HDR as *const _ as u64;
        (*desc.add(0)).len = core::mem::size_of::<BlkReqHeader>() as u32;
        (*desc.add(0)).flags = VIRTQ_DESC_F_NEXT;
        (*desc.add(0)).next = 1;

        // desc 1: data (device writes)
        (*desc.add(1)).addr = buf as u64;
        (*desc.add(1)).len = data_len;
        (*desc.add(1)).flags = VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE;
        (*desc.add(1)).next = 2;

        // desc 2: status
        (*desc.add(2)).addr = &raw mut REQ_STATUS as *mut _ as u64;
        (*desc.add(2)).len = 1;
        (*desc.add(2)).flags = VIRTQ_DESC_F_WRITE;
        (*desc.add(2)).next = 0;
    }

    let avail_now = unsafe { ptr::read_volatile(&(*queue.avail_hdr_ptr()).idx) };
    let avail_slot = (avail_now % qs) as usize;
    unsafe {
        ptr::write_volatile(queue.avail_ring_ptr().add(avail_slot), 0);
    }
    fence(Ordering::Release);
    unsafe {
        ptr::write_volatile(&mut (*queue.avail_hdr_ptr()).idx, avail_now.wrapping_add(1));
    }

    notify_queue(state);

    // Poll for completion
    loop {
        let used_now = ptr::read_volatile(&raw const (*queue.used_hdr_ptr()).idx);
        if used_now != state.used_idx {
            state.used_idx = used_now;
            break;
        }
        core::hint::spin_loop();
    }
    fence(Ordering::Acquire);
    ack_interrupt(state);

    REQ_STATUS == 0
}

fn submit_write_sector(state: &mut BlkState, lba: u64) -> bool {
    let Some(_backend) = &state.backend else {
        return false;
    };
    let Some(queue) = state.queue.as_ref() else {
        return false;
    };
    let qs = state.queue_size;
    if qs < 3 {
        return false;
    }
    unsafe {
        REQ_HDR.req_type = VIRTIO_BLK_T_OUT;
        REQ_HDR.reserved = 0;
        REQ_HDR.sector = lba;
        REQ_STATUS = 0xFF;

        // desc 0: header
        let desc = queue.desc_ptr();
        (*desc.add(0)).addr = &raw const REQ_HDR as *const _ as u64;
        (*desc.add(0)).len = core::mem::size_of::<BlkReqHeader>() as u32;
        (*desc.add(0)).flags = VIRTQ_DESC_F_NEXT;
        (*desc.add(0)).next = 1;

        // desc 1: data (device reads)
        (*desc.add(1)).addr = &raw const SECTOR_BUF as *const _ as u64;
        (*desc.add(1)).len = 512;
        (*desc.add(1)).flags = VIRTQ_DESC_F_NEXT;
        (*desc.add(1)).next = 2;

        // desc 2: status
        (*desc.add(2)).addr = &raw mut REQ_STATUS as *mut _ as u64;
        (*desc.add(2)).len = 1;
        (*desc.add(2)).flags = VIRTQ_DESC_F_WRITE;
        (*desc.add(2)).next = 0;

        let avail_now = ptr::read_volatile(&raw const (*queue.avail_hdr_ptr()).idx);
        let avail_slot = (avail_now % qs) as usize;
        ptr::write_volatile(queue.avail_ring_ptr().add(avail_slot), 0);
        fence(Ordering::Release);
        ptr::write_volatile(&mut (*queue.avail_hdr_ptr()).idx, avail_now.wrapping_add(1));
    }

    notify_queue(state);

    // Poll for completion
    loop {
        let used_now = unsafe { ptr::read_volatile(&raw const (*queue.used_hdr_ptr()).idx) };
        if used_now != state.used_idx {
            state.used_idx = used_now;
            break;
        }
        core::hint::spin_loop();
    }
    fence(Ordering::Acquire);
    ack_interrupt(state);

    unsafe { REQ_STATUS == 0 }
}

pub fn read_at(offset: u64, out: &mut [u8]) -> bool {
    let mut guard = BLK.lock();
    if !guard.ready {
        return false;
    }
    if out.is_empty() {
        return true;
    }

    debug_assert!(BULK_BUF_SIZE % 512 == 0);

    let req_start = offset;
    let req_end = offset.saturating_add(out.len() as u64);
    let aligned_start = req_start & !511u64;
    let aligned_end = req_end.saturating_add(511) & !511u64;

    // Always prefer "few big reads": expand to 512B boundaries, then read via the reusable BULK buffer
    // in 256KiB chunks, and memcpy only the requested sub-range into `out`.
    let mut cur = aligned_start;
    while cur < aligned_end {
        let remaining = aligned_end - cur;
        let chunk = cmp::min(remaining, BULK_BUF_SIZE as u64);
        let blocks = (chunk / 512) as usize;
        let lba = cur / 512;

        unsafe {
            let ok = submit_read_blocks(
                &mut guard,
                lba,
                &raw mut BULK_BUF as *mut _ as *mut u8,
                blocks,
            );
            if !ok {
                return false;
            }
        }

        let chunk_start = cur;
        let chunk_end = cur.saturating_add(chunk);
        let overlap_start = cmp::max(req_start, chunk_start);
        let overlap_end = cmp::min(req_end, chunk_end);
        if overlap_end > overlap_start {
            let src_off = (overlap_start - chunk_start) as usize;
            let len = (overlap_end - overlap_start) as usize;
            let dst_off = (overlap_start - req_start) as usize;
            unsafe {
                out[dst_off..dst_off + len].copy_from_slice(&BULK_BUF[src_off..src_off + len]);
            }
        }

        cur = cur.saturating_add(chunk);
    }

    true
}

pub fn write_at(offset: u64, data: &[u8]) -> bool {
    let mut guard = BLK.lock();
    if !guard.ready {
        return false;
    }
    let mut off = offset;
    let mut src = data;
    while !src.is_empty() {
        let lba = off / 512;
        let in_off = (off % 512) as usize;
        let take = cmp::min(512 - in_off, src.len());

        if in_off == 0 && take == 512 {
            unsafe {
                SECTOR_BUF.copy_from_slice(&src[..512]);
            }
            if !submit_write_sector(&mut guard, lba) {
                return false;
            }
        } else {
            // read-modify-write a single sector
            if !submit_read_sector(&mut guard, lba) {
                return false;
            }
            unsafe {
                SECTOR_BUF[in_off..in_off + take].copy_from_slice(&src[..take]);
            }
            if !submit_write_sector(&mut guard, lba) {
                return false;
            }
        }

        off = off.saturating_add(take as u64);
        src = &src[take..];
    }
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlkError {
    NotReady,
    RequestFailed,
}

pub fn read_at_res(offset: u64, out: &mut [u8]) -> Result<(), BlkError> {
    if read_at(offset, out) {
        Ok(())
    } else if !available() {
        Err(BlkError::NotReady)
    } else {
        Err(BlkError::RequestFailed)
    }
}

pub fn write_at_res(offset: u64, data: &[u8]) -> Result<(), BlkError> {
    if write_at(offset, data) {
        Ok(())
    } else if !available() {
        Err(BlkError::NotReady)
    } else {
        Err(BlkError::RequestFailed)
    }
}
