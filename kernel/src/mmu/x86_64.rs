#![cfg(all(target_os = "none", target_arch = "x86_64"))]

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
    pub global: bool,
    pub attr: MemAttr,
}

impl MapFlags {
    pub const fn ro_x() -> Self {
        Self {
            read: true,
            write: false,
            exec: true,
            global: false,
            attr: MemAttr::Normal,
        }
    }
    pub const fn ro() -> Self {
        Self {
            read: true,
            write: false,
            exec: false,
            global: false,
            attr: MemAttr::Normal,
        }
    }
    pub const fn rw() -> Self {
        Self {
            read: true,
            write: true,
            exec: false,
            global: false,
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

pub trait PageTableAlloc {
    fn alloc_table(&mut self) -> Result<NonNull<PageTable>, MapError>;
}

pub struct HeapPageTableAlloc {
    allocated: Vec<NonNull<u8>>,
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

impl PageTableAlloc for HeapPageTableAlloc {
    fn alloc_table(&mut self) -> Result<NonNull<PageTable>, MapError> {
        let layout =
            Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).map_err(|_| MapError::OutOfMemory)?;
        let ptr = unsafe { alloc_zeroed(layout) } as *mut PageTable;
        let nn = NonNull::new(ptr).ok_or(MapError::OutOfMemory)?;
        self.allocated.push(nn.cast::<u8>());
        Ok(nn)
    }
}

// PTE flags
const P_PRESENT: u64 = 1 << 0;
const P_WRITE: u64 = 1 << 1;
const P_USER: u64 = 1 << 2;
const P_PWT: u64 = 1 << 3;
const P_PCD: u64 = 1 << 4;
const P_ACCESSED: u64 = 1 << 5;
const P_DIRTY: u64 = 1 << 6;
const P_PS: u64 = 1 << 7;
const P_GLOBAL: u64 = 1 << 8;
const P_NX: u64 = 1 << 63;

fn leaf_desc(pa: u64, flags: MapFlags) -> u64 {
    let mut d = P_PRESENT | P_ACCESSED | P_DIRTY;
    d |= pa & 0x000f_ffff_ffff_f000;
    if flags.write {
        d |= P_WRITE;
    }
    // v2: keep supervisor mappings (no ring3). We still set USER=0 for everything.
    let _ = P_USER;
    if flags.global {
        d |= P_GLOBAL;
    }
    // Cache policy: MVP uses default WB (no PWT/PCD). Device would need PCD/PWT or PAT; not used for AppSpace.
    match flags.attr {
        MemAttr::Normal => {}
        MemAttr::Device => {
            d |= P_PCD | P_PWT;
        }
    }
    if !flags.exec {
        d |= P_NX;
    }
    d
}

fn table_desc(pa: u64) -> u64 {
    // Next-level table pointer.
    (pa & 0x000f_ffff_ffff_f000) | P_PRESENT | P_WRITE
}

fn l4_index(va: u64) -> usize {
    ((va >> 39) & 0x1ff) as usize
}
fn l3_index(va: u64) -> usize {
    ((va >> 30) & 0x1ff) as usize
}
fn l2_index(va: u64) -> usize {
    ((va >> 21) & 0x1ff) as usize
}
fn l1_index(va: u64) -> usize {
    ((va >> 12) & 0x1ff) as usize
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
        // v2/M1: assumes root is identity-mapped (VA==PA style) for self-checks only.
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
            let l4 = self.root.as_mut();
            let l3 = self.ensure_next_table(&mut l4.entries[l4_index(va)])?;
            let l2 = self.ensure_next_table(&mut l3.entries[l3_index(va)])?;
            let l1 = self.ensure_next_table(&mut l2.entries[l2_index(va)])?;
            l1.entries[l1_index(va)] = leaf_desc(pa, flags);
        }
        self.mapped_pages = self.mapped_pages.saturating_add(1);
        Ok(())
    }

    unsafe fn ensure_next_table(
        &mut self,
        entry: &mut u64,
    ) -> Result<&'static mut PageTable, MapError> {
        if (*entry & P_PRESENT) == 0 {
            let next = self.alloc.alloc_table()?;
            self.allocated_tables = self.allocated_tables.saturating_add(1);
            let next_pa = next.as_ptr() as u64;
            *entry = table_desc(next_pa);
            return Ok(&mut *next.as_ptr());
        }
        if (*entry & P_PS) != 0 {
            // unexpected huge mapping in builder path
            return Err(MapError::Overflow);
        }
        let next_pa = *entry & 0x000f_ffff_ffff_f000;
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

pub unsafe fn walk_l1(root_pa: u64, va: u64) -> PteInfo {
    let l4 = &*(root_pa as *const PageTable);
    let e4 = l4.entries[l4_index(va)];
    if (e4 & P_PRESENT) == 0 {
        return PteInfo {
            kind: PteKind::Invalid,
            desc: 0,
        };
    }
    let l3 = &*((e4 & 0x000f_ffff_ffff_f000) as *const PageTable);
    let e3 = l3.entries[l3_index(va)];
    if (e3 & P_PRESENT) == 0 {
        return PteInfo {
            kind: PteKind::Invalid,
            desc: 0,
        };
    }
    let l2 = &*((e3 & 0x000f_ffff_ffff_f000) as *const PageTable);
    let e2 = l2.entries[l2_index(va)];
    if (e2 & P_PRESENT) == 0 {
        return PteInfo {
            kind: PteKind::Invalid,
            desc: 0,
        };
    }
    if (e2 & P_PS) != 0 {
        return PteInfo {
            kind: PteKind::Page,
            desc: e2,
        };
    }
    let l1 = &*((e2 & 0x000f_ffff_ffff_f000) as *const PageTable);
    let e1 = l1.entries[l1_index(va)];
    if (e1 & P_PRESENT) == 0 {
        return PteInfo {
            kind: PteKind::Invalid,
            desc: 0,
        };
    }
    PteInfo {
        kind: PteKind::Page,
        desc: e1,
    }
}

pub fn is_paging_enabled() -> bool {
    let cr0: u64;
    unsafe { asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags)) };
    (cr0 & (1 << 31)) != 0
}

pub fn current_cr3() -> u64 {
    let cr3: u64;
    unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
    cr3
}

pub unsafe fn write_cr3(val: u64) {
    asm!("mov cr3, {}", in(reg) val, options(nomem, nostack, preserves_flags));
}

pub fn read_msr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    ((hi as u64) << 32) | (lo as u64)
}

pub fn efer() -> u64 {
    // IA32_EFER MSR
    read_msr(0xC000_0080)
}

pub unsafe fn write_msr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo,
        in("edx") hi,
        options(nomem, nostack, preserves_flags)
    );
}

pub fn cr0() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub fn cr4() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub unsafe fn write_cr0(val: u64) {
    asm!("mov cr0, {}", in(reg) val, options(nomem, nostack, preserves_flags));
}

static X86_MMU_FEATURES: AtomicU64 = AtomicU64::new(0);

const FEAT_NXE: u64 = 1 << 0;
const FEAT_WP: u64 = 1 << 1;

/// Enable minimal x86_64 paging protections required for W^X enforcement in ring0:
/// - IA32_EFER.NXE (enables the NX bit in page tables)
/// - CR0.WP (enforces read-only pages for supervisor writes too)
///
/// This does not change privilege levels; oneOS still runs everything in ring0.
pub fn enable_wx_protection() {
    // Enable NXE.
    unsafe {
        let mut e = efer();
        let nxe = 1u64 << 11;
        if (e & nxe) == 0 {
            e |= nxe;
            write_msr(0xC000_0080, e);
        }
    }
    // Enable write-protect.
    unsafe {
        let mut c = cr0();
        let wp = 1u64 << 16;
        if (c & wp) == 0 {
            c |= wp;
            write_cr0(c);
        }
    }
    X86_MMU_FEATURES.store(FEAT_NXE | FEAT_WP, Ordering::Relaxed);
}

pub fn wx_protection_enabled() -> (bool, bool) {
    let feats = X86_MMU_FEATURES.load(Ordering::Relaxed);
    ((feats & FEAT_NXE) != 0, (feats & FEAT_WP) != 0)
}

/// Returns the *current* hardware state of W^X-related controls:
/// - (EFER.NXE, CR0.WP)
///
/// This is preferred for status/debug output (instead of relying on cached flags).
pub fn wx_protection_state() -> (bool, bool) {
    let e = efer();
    let c = cr0();
    let nxe = (e & (1u64 << 11)) != 0;
    let wp = (c & (1u64 << 16)) != 0;
    (nxe, wp)
}

pub fn desc_matches_flags(desc: u64, flags: MapFlags) -> bool {
    if (desc & P_PRESENT) == 0 {
        return false;
    }

    let writable = (desc & P_WRITE) != 0;
    if writable != flags.write {
        return false;
    }

    let executable = (desc & P_NX) == 0;
    if executable != flags.exec {
        return false;
    }

    let global = (desc & P_GLOBAL) != 0;
    if global != flags.global {
        return false;
    }

    let cache_bits = desc & (P_PCD | P_PWT);
    match flags.attr {
        MemAttr::Normal => {
            if cache_bits != 0 {
                return false;
            }
        }
        MemAttr::Device => {
            if cache_bits != (P_PCD | P_PWT) {
                return false;
            }
        }
    }

    true
}
