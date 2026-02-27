#![cfg(all(target_os = "none", target_arch = "aarch64"))]

extern crate alloc;

use alloc::alloc::{alloc_zeroed, Layout};
use alloc::vec::Vec;
use core::arch::asm;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

pub const PAGE_SIZE: usize = 4096;
pub const PT_ENTRIES: usize = 512;

#[repr(align(4096))]
pub struct PageTable {
    pub entries: [u64; PT_ENTRIES],
}

impl PageTable {
    pub const fn new_zeroed() -> Self {
        Self {
            entries: [0; PT_ENTRIES],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum MemAttr {
    Normal,
    Device,
}

#[derive(Clone, Copy, Debug)]
pub struct MapFlags {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub user: bool, // reserved: we don't use EL0; kept for future semantic clarity
    pub attr: MemAttr,
}

impl MapFlags {
    pub const fn ro_x() -> Self {
        Self {
            read: true,
            write: false,
            exec: true,
            user: false,
            attr: MemAttr::Normal,
        }
    }
    pub const fn ro() -> Self {
        Self {
            read: true,
            write: false,
            exec: false,
            user: false,
            attr: MemAttr::Normal,
        }
    }
    pub const fn rw() -> Self {
        Self {
            read: true,
            write: true,
            exec: false,
            user: false,
            attr: MemAttr::Normal,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum MapError {
    OutOfMemory,
    Unaligned,
    Overflow,
}

/// AArch64 EL1 stage-1 MMU configuration (TTBR0-based).
///
/// v2/M1: config is defined and callable, but the kernel does not enable or switch MMU yet.
/// v3+: will be used to enter/leave AppDomain address spaces.
#[derive(Clone, Copy, Debug)]
pub struct MmuConfig {
    pub mair_el1: u64,
    pub tcr_el1: u64,
}

/// Minimal MAIR_EL1 with two attributes:
/// - AttrIndx=0: Normal, Inner/Outer Write-Back Write-Allocate (0xFF)
/// - AttrIndx=1: Device-nGnRE (0x04)
pub const MAIR_EL1_MIN: u64 = 0x04 << 8 | 0xFF;

/// Minimal TCR_EL1 for TTBR0 4KB granule, inner-shareable, WBWA caches, 48-bit VA.
///
/// Notes:
/// - We only use TTBR0_EL1 for AppDomain spaces (future).
/// - TTBR1_EL1 remains kernel/firmware mapping (out of scope in this milestone).
pub const TCR_EL1_MIN_TTBR0_48BIT: u64 = {
    // IPS: 48-bit physical address (0b101) is a safe default on QEMU virt; if hardware differs, adjust later.
    let ips = 0b101u64 << 32;
    // TG0=4KB (0b00) at [15:14]
    let tg0 = 0b00u64 << 14;
    // SH0=Inner Shareable (0b11) at [13:12]
    let sh0 = 0b11u64 << 12;
    // ORGN0/IRGN0 = WBWA (0b01) at [11:10] / [9:8]
    let orgn0 = 0b01u64 << 10;
    let irgn0 = 0b01u64 << 8;
    // T0SZ=16 => 48-bit VA space (64-48)
    let t0sz = 16u64;
    ips | tg0 | sh0 | orgn0 | irgn0 | t0sz
};

/// Minimal TCR_EL1 enabling both TTBR0 and TTBR1 (4KB granule, 48-bit VA).
///
/// This supports the "Route B" scaffold where TTBR1 hosts a fixed trampoline mapping
/// (exception vectors + minimal state), while TTBR0 can switch per AppDomain.
pub const TCR_EL1_MIN_TTBR0_TTBR1_48BIT: u64 = {
    let ips = 0b101u64 << 32;

    // TTBR0 settings (low VA)
    let tg0 = 0b00u64 << 14; // 4KB
    let sh0 = 0b11u64 << 12; // inner-shareable
    let orgn0 = 0b01u64 << 10; // WBWA
    let irgn0 = 0b01u64 << 8; // WBWA
    let t0sz = 16u64;

    // TTBR1 settings (high VA)
    let t1sz = 16u64 << 16;
    let a1 = 0u64 << 22; // ASID in TTBR0 (unused in v2)
    let tg1 = 0b10u64 << 30; // 4KB
    let sh1 = 0b11u64 << 28; // inner-shareable
    let orgn1 = 0b01u64 << 26; // WBWA
    let irgn1 = 0b01u64 << 24; // WBWA

    ips | tg0 | sh0 | orgn0 | irgn0 | t0sz | t1sz | a1 | tg1 | sh1 | orgn1 | irgn1
};

pub fn is_enabled() -> bool {
    // SCTLR_EL1.M bit (bit0)
    let sctlr: u64;
    unsafe { asm!("mrs {0}, sctlr_el1", out(reg) sctlr, options(nomem, nostack, preserves_flags)) };
    (sctlr & 1) != 0
}

pub fn current_ttbr0_el1() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {0}, ttbr0_el1", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub fn current_ttbr1_el1() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {0}, ttbr1_el1", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub fn read_ttbr0_el1() -> u64 {
    current_ttbr0_el1()
}

pub fn current_tcr_el1() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {0}, tcr_el1", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub fn current_mair_el1() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {0}, mair_el1", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub unsafe fn write_ttbr0_el1(val: u64) {
    // IMPORTANT: changing TTBR0 changes address translation. Do NOT use `nomem`,
    // otherwise LLVM may legally reorder memory accesses across this point.
    asm!(
        "msr ttbr0_el1, {0}",
        "isb",
        in(reg) val,
        options(nostack, preserves_flags)
    );
}

pub unsafe fn write_ttbr1_el1(val: u64) {
    // Same rationale as `write_ttbr0_el1`.
    asm!(
        "msr ttbr1_el1, {0}",
        "isb",
        in(reg) val,
        options(nostack, preserves_flags)
    );
}

/// Enter a new TTBR0_EL1 root (MVP: full EL1 TLB flush).
///
/// This must only be used when the MMU is already enabled.
pub fn enter_ttbr0(ttbr0: u64) {
    unsafe {
        // Ensure page table writes are visible before switching.
        asm!("dsb ishst", options(nostack, preserves_flags));
        write_ttbr0_el1(ttbr0);
        // Conservative: full invalidate (no ASID yet).
        asm!(
            "dsb ish",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }
    TLBI_VMALLE1_COUNT.fetch_add(1, Ordering::Relaxed);
}

static TLBI_VMALLE1_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn tlbi_vmalle1_count() -> u64 {
    TLBI_VMALLE1_COUNT.load(Ordering::Relaxed)
}

pub unsafe fn write_tcr_el1(val: u64) {
    asm!(
        "msr tcr_el1, {0}",
        "isb",
        in(reg) val,
        options(nostack, preserves_flags)
    );
}

pub unsafe fn write_mair_el1(val: u64) {
    asm!(
        "msr mair_el1, {0}",
        "isb",
        in(reg) val,
        options(nostack, preserves_flags)
    );
}

/// Enable stage-1 MMU (EL1) with the provided configuration and TTBR0 root.
///
/// v2/M1: not invoked by default. Caller is responsible for ensuring correct identity/kernel mappings.
pub unsafe fn enable(ttbr0_root: u64, cfg: MmuConfig) {
    write_mair_el1(cfg.mair_el1);
    write_tcr_el1(cfg.tcr_el1);
    write_ttbr0_el1(ttbr0_root);
    // Full TLB invalidate for safety (MVP; ASID will refine later).
    asm!(
        "dsb ish",
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        options(nostack, preserves_flags)
    );

    let mut sctlr: u64;
    asm!("mrs {0}, sctlr_el1", out(reg) sctlr, options(nomem, nostack, preserves_flags));
    sctlr |= 1; // M
    asm!(
        "msr sctlr_el1, {0}",
        "isb",
        in(reg) sctlr,
        options(nostack, preserves_flags)
    );
}

/// Enable stage-1 MMU (EL1) with explicit TTBR0/TTBR1 roots.
///
/// Used by the "Route B" scaffold to keep a fixed TTBR1 trampoline mapping alive while
/// switching TTBR0 for AppDomain address spaces.
pub unsafe fn enable_ttbr0_ttbr1(ttbr0_root: u64, ttbr1_root: u64, cfg: MmuConfig) {
    write_mair_el1(cfg.mair_el1);
    write_tcr_el1(cfg.tcr_el1);
    write_ttbr0_el1(ttbr0_root);
    write_ttbr1_el1(ttbr1_root);
    asm!("dsb ish", options(nomem, nostack, preserves_flags));
    asm!("tlbi vmalle1", options(nomem, nostack, preserves_flags));
    asm!("dsb ish", options(nomem, nostack, preserves_flags));
    asm!("isb", options(nomem, nostack, preserves_flags));

    let mut sctlr: u64;
    asm!("mrs {0}, sctlr_el1", out(reg) sctlr, options(nomem, nostack, preserves_flags));
    sctlr |= 1; // M
    asm!("msr sctlr_el1, {0}", in(reg) sctlr, options(nomem, nostack, preserves_flags));
    asm!("isb", options(nomem, nostack, preserves_flags));
}

pub unsafe fn disable() {
    let mut sctlr: u64;
    asm!("mrs {0}, sctlr_el1", out(reg) sctlr, options(nomem, nostack, preserves_flags));
    sctlr &= !1u64;
    asm!("msr sctlr_el1, {0}", in(reg) sctlr, options(nomem, nostack, preserves_flags));
    asm!("isb", options(nomem, nostack, preserves_flags));
}

pub trait PageTableAlloc {
    fn alloc_table(&mut self) -> Result<NonNull<PageTable>, MapError>;
}

pub struct HeapPageTableAlloc {
    allocated: Vec<NonNull<u8>>,
}

impl PageTableAlloc for HeapPageTableAlloc {
    fn alloc_table(&mut self) -> Result<NonNull<PageTable>, MapError> {
        // v2: allocate from heap; v3 can switch to a dedicated bump region.
        let layout =
            Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).map_err(|_| MapError::OutOfMemory)?;
        let ptr = unsafe { alloc_zeroed(layout) } as *mut PageTable;
        let nn = NonNull::new(ptr).ok_or(MapError::OutOfMemory)?;
        self.allocated.push(nn.cast::<u8>());
        Ok(nn)
    }
}

impl HeapPageTableAlloc {
    pub fn new() -> Self {
        Self {
            allocated: Vec::new(),
        }
    }

    pub fn take_allocated_pages(&mut self) -> Vec<u64> {
        let mut out = Vec::new();
        for p in self.allocated.drain(..) {
            out.push(p.as_ptr() as u64);
        }
        out
    }
}

// AArch64 Stage-1 descriptors (4KB granule).
const DESC_VALID: u64 = 1 << 0;
const DESC_TABLE: u64 = 1 << 1; // for non-leaf
const DESC_PAGE: u64 = 1 << 1; // for leaf (L3)

// Access permissions (simplified):
// AP[2:1] in bits [7:6] for stage-1.
// 00: EL1 RW, EL0 RW; 01: EL1 RW, EL0 RO; 10: EL1 RO, EL0 RO; 11: EL1 RO, EL0 NA
// We only care about EL1 for now; keep consistent and conservative.
const AP_SHIFT: u64 = 6;
const AP_EL1_RW: u64 = 0b00;
const AP_EL1_RO: u64 = 0b10;

// UXN/PXN: execute-never bits.
const UXN: u64 = 1 << 54;
const PXN: u64 = 1 << 53;

// Access Flag.
const AF: u64 = 1 << 10;

// Shareability bits [9:8]
const SH_SHIFT: u64 = 8;
const SH_INNER: u64 = 0b11;

// Not Global bit [11]
const NG: u64 = 1 << 11;

// AttrIndx[2:0] bits [4:2]
const ATTR_SHIFT: u64 = 2;
const ATTR_NORMAL: u64 = 0;
const ATTR_DEVICE: u64 = 1;

fn attr_index(attr: MemAttr) -> u64 {
    match attr {
        MemAttr::Normal => ATTR_NORMAL,
        MemAttr::Device => ATTR_DEVICE,
    }
}

fn leaf_desc(pa: u64, flags: MapFlags) -> u64 {
    let mut d = DESC_VALID | DESC_PAGE;
    // output address [47:12]
    d |= pa & 0x0000_FFFF_FFFF_F000;
    // mark accessed to avoid permission faults with hardware AF updates disabled
    d |= AF;
    // TTBR0 mappings should generally be non-global
    d |= NG;
    // Inner-shareable for normal memory; device shareability is implementation-defined but
    // Inner is safe for QEMU virt.
    d |= (SH_INNER & 0b11) << SH_SHIFT;
    let ap = if flags.write { AP_EL1_RW } else { AP_EL1_RO };
    d |= ap << AP_SHIFT;
    let attr = attr_index(flags.attr);
    d |= (attr & 0x7) << ATTR_SHIFT;
    // shareability / accessed / global bits omitted for MVP skeleton
    if !flags.exec {
        d |= UXN | PXN;
    }
    d
}

pub fn desc_is_writable(desc: u64) -> bool {
    // AP[2:1] at [7:6]
    let ap = (desc >> AP_SHIFT) & 0b11;
    ap == AP_EL1_RW
}

pub fn desc_is_executable(desc: u64) -> bool {
    (desc & (UXN | PXN)) == 0
}

pub fn desc_attr_index(desc: u64) -> u64 {
    (desc >> ATTR_SHIFT) & 0x7
}

pub fn desc_matches_flags(desc: u64, flags: MapFlags) -> bool {
    if (desc & DESC_VALID) == 0 {
        return false;
    }
    if desc_is_writable(desc) != flags.write {
        return false;
    }
    if desc_is_executable(desc) != flags.exec {
        return false;
    }
    if desc_attr_index(desc) != (attr_index(flags.attr) & 0x7) {
        return false;
    }
    true
}

fn table_desc(next: u64) -> u64 {
    // next is physical address of next-level table (4KB aligned)
    (next & 0x0000_FFFF_FFFF_F000) | DESC_VALID | DESC_TABLE
}

fn l0_index(va: u64) -> usize {
    ((va >> 39) & 0x1FF) as usize
}
fn l1_index(va: u64) -> usize {
    ((va >> 30) & 0x1FF) as usize
}
fn l2_index(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}
fn l3_index(va: u64) -> usize {
    ((va >> 12) & 0x1FF) as usize
}

pub struct AddressSpaceBuilder<A: PageTableAlloc> {
    alloc: A,
    root: NonNull<PageTable>,
    mapped_pages: u64,
    allocated_tables: u64,
}

impl<A: PageTableAlloc> AddressSpaceBuilder<A> {
    pub fn new(mut alloc: A) -> Result<Self, MapError> {
        let root = alloc.alloc_table()?;
        Ok(Self {
            alloc,
            root,
            mapped_pages: 0,
            allocated_tables: 1,
        })
    }

    pub fn root_pa(&self) -> u64 {
        // v2: treat VA==PA semantics; caller must provide real PA in v3.
        self.root.as_ptr() as u64
    }

    pub fn finish(self) -> (u64, A) {
        (self.root_pa(), self.alloc)
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.allocated_tables, self.mapped_pages)
    }

    pub fn map_range_4k(
        &mut self,
        va: u64,
        pa: u64,
        len: u64,
        flags: MapFlags,
    ) -> Result<(), MapError> {
        if (va as usize) % PAGE_SIZE != 0 || (pa as usize) % PAGE_SIZE != 0 {
            return Err(MapError::Unaligned);
        }
        let end = va.checked_add(len).ok_or(MapError::Overflow)?;
        let mut cur_va = va;
        let mut cur_pa = pa;
        while cur_va < end {
            self.map_page_4k(cur_va, cur_pa, flags)?;
            cur_va = cur_va
                .checked_add(PAGE_SIZE as u64)
                .ok_or(MapError::Overflow)?;
            cur_pa = cur_pa
                .checked_add(PAGE_SIZE as u64)
                .ok_or(MapError::Overflow)?;
        }
        Ok(())
    }

    pub fn map_page_4k(&mut self, va: u64, pa: u64, flags: MapFlags) -> Result<(), MapError> {
        if (va as usize) % PAGE_SIZE != 0 || (pa as usize) % PAGE_SIZE != 0 {
            return Err(MapError::Unaligned);
        }

        unsafe {
            let l0 = self.root.as_mut();
            let l1 = self.ensure_next_table(&mut l0.entries[l0_index(va)])?;
            let l2 = self.ensure_next_table(&mut l1.entries[l1_index(va)])?;
            let l3 = self.ensure_next_table(&mut l2.entries[l2_index(va)])?;
            l3.entries[l3_index(va)] = leaf_desc(pa, flags);
        }
        self.mapped_pages = self.mapped_pages.saturating_add(1);
        Ok(())
    }

    pub fn unmap_range_4k(&mut self, va: u64, len: u64) -> Result<(), MapError> {
        if (va as usize) % PAGE_SIZE != 0 {
            return Err(MapError::Unaligned);
        }
        let end = va.checked_add(len).ok_or(MapError::Overflow)?;
        let mut cur_va = va;
        while cur_va < end {
            self.unmap_page_4k(cur_va)?;
            cur_va = cur_va
                .checked_add(PAGE_SIZE as u64)
                .ok_or(MapError::Overflow)?;
        }
        Ok(())
    }

    fn unmap_page_4k(&mut self, va: u64) -> Result<(), MapError> {
        if (va as usize) % PAGE_SIZE != 0 {
            return Err(MapError::Unaligned);
        }
        unsafe {
            let l0 = self.root.as_mut();
            let e0 = &mut l0.entries[l0_index(va)];
            if (*e0 & DESC_VALID) == 0 {
                return Ok(());
            }
            let l1_pa = *e0 & 0x0000_FFFF_FFFF_F000;
            let l1 = &mut *(l1_pa as *mut PageTable);
            let e1 = &mut l1.entries[l1_index(va)];
            if (*e1 & DESC_VALID) == 0 {
                return Ok(());
            }
            let l2_pa = *e1 & 0x0000_FFFF_FFFF_F000;
            let l2 = &mut *(l2_pa as *mut PageTable);
            let e2 = &mut l2.entries[l2_index(va)];
            if (*e2 & DESC_VALID) == 0 {
                return Ok(());
            }
            let l3_pa = *e2 & 0x0000_FFFF_FFFF_F000;
            let l3 = &mut *(l3_pa as *mut PageTable);
            let e3 = &mut l3.entries[l3_index(va)];
            if (*e3 & DESC_VALID) != 0 {
                *e3 = 0;
                self.mapped_pages = self.mapped_pages.saturating_sub(1);
            }
        }
        Ok(())
    }

    unsafe fn ensure_next_table(
        &mut self,
        entry: &mut u64,
    ) -> Result<&'static mut PageTable, MapError> {
        if (*entry & DESC_VALID) == 0 {
            let next = self.alloc.alloc_table()?;
            self.allocated_tables = self.allocated_tables.saturating_add(1);
            let next_pa = next.as_ptr() as u64;
            *entry = table_desc(next_pa);
            return Ok(&mut *next.as_ptr());
        }
        // existing table: decode address
        let next_pa = *entry & 0x0000_FFFF_FFFF_F000;
        Ok(&mut *(next_pa as *mut PageTable))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PteKind {
    Invalid,
    Table,
    Page,
}

#[derive(Clone, Copy, Debug)]
pub struct PteInfo {
    pub kind: PteKind,
    pub desc: u64,
}

/// Walk a 4-level (4KB granule) page table and return the L3 entry (leaf) if present.
///
/// v2/M1: assumes `root_pa` is directly dereferenceable (VA==PA style). This is sufficient for
/// self-checking builders without switching TTBR. v3 will replace this with safe phys access.
pub unsafe fn walk_l3(root_pa: u64, va: u64) -> PteInfo {
    let l0 = &*(root_pa as *const PageTable);
    let e0 = l0.entries[l0_index(va)];
    if (e0 & DESC_VALID) == 0 {
        return PteInfo {
            kind: PteKind::Invalid,
            desc: 0,
        };
    }
    let l1 = &*((e0 & 0x0000_FFFF_FFFF_F000) as *const PageTable);
    let e1 = l1.entries[l1_index(va)];
    if (e1 & DESC_VALID) == 0 {
        return PteInfo {
            kind: PteKind::Invalid,
            desc: 0,
        };
    }
    let l2 = &*((e1 & 0x0000_FFFF_FFFF_F000) as *const PageTable);
    let e2 = l2.entries[l2_index(va)];
    if (e2 & DESC_VALID) == 0 {
        return PteInfo {
            kind: PteKind::Invalid,
            desc: 0,
        };
    }
    let l3 = &*((e2 & 0x0000_FFFF_FFFF_F000) as *const PageTable);
    let e3 = l3.entries[l3_index(va)];
    if (e3 & DESC_VALID) == 0 {
        return PteInfo {
            kind: PteKind::Invalid,
            desc: 0,
        };
    }
    PteInfo {
        kind: PteKind::Page,
        desc: e3,
    }
}
