#![cfg(target_os = "none")]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;
use spin::Once;

use crate::drivers::serial;
use crate::sandbox::MemRegion;

pub type AddressSpaceId = u32;

#[repr(align(4096))]
struct SharedRoPage([u8; 4096]);

static mut APP_SHARED_RO_PAGE: SharedRoPage = SharedRoPage([0u8; 4096]);

#[cfg(target_arch = "aarch64")]
const APP_SHARED_RO_VA: u64 = 0x40ff_f000;
#[cfg(target_arch = "x86_64")]
const APP_SHARED_RO_VA: u64 = 0x2fff_f000;

/// AArch64 Route B scaffold: TTBR1 fixed trampoline region.
///
/// We keep a tiny TTBR1 mapping alive to host exception vectors and a small shared state page.
/// This lets the exception entry path restore the kernel TTBR0 even when the current TTBR0 is an
/// AppDomain page table (no EL0 split; this is for robustness, not a full security boundary).
#[cfg(target_arch = "aarch64")]
const TTBR1_TRAMP_VECTOR_VA: u64 = 0xffff_0000_0000_0000;
#[cfg(target_arch = "aarch64")]
const TTBR1_TRAMP_STATE_VA: u64 = 0xffff_0000_0000_1000;

#[repr(align(4096))]
struct Ttbr1TrampStatePage([u8; 4096]);

static mut TTBR1_TRAMP_STATE_PAGE: Ttbr1TrampStatePage = Ttbr1TrampStatePage([0u8; 4096]);

pub fn app_shared_ro_va() -> u64 {
    APP_SHARED_RO_VA
}

pub fn app_shared_ro_pa() -> u64 {
    // v2: VA==PA assumptions; see TODO-list_MMU-backed-AddressSpace for v3 changes.
    unsafe { &raw const APP_SHARED_RO_PAGE as *const SharedRoPage as u64 }
}

pub fn init_shared_ro_page() {
    // No heap, no formatting: keep it zero-alloc and deterministic.
    // Layout (all ASCII, fixed offsets):
    // - 0x000: magic/header
    // - 0x040: version/info
    // - 0x100: capability summary (semantic, not handles)
    // - 0x200: AppApiV1 table summary (names only; no pointers)
    const MAGIC: &[u8] = b"ONEOS-SHARED-RO\0";
    const VERSION: &[u8] = b"oneOS: shared_ro_page=v2 (no writable pointers)\n";
    const CAP_SUMMARY: &[u8] = b"caps: AppDomain has GOES_READ(App:<name>) + GOES_READ/WRITE(LAD:<app>) + optional CONSOLE/GPU\n";
    const API_SUMMARY: &[u8] =
        b"AppApiV1: console_read/console_write, goes_read, goes_write(LAD only), timer_feed\n";
    unsafe {
        let dst = core::ptr::addr_of_mut!(APP_SHARED_RO_PAGE) as *mut u8;
        for i in 0..4096usize {
            dst.add(i).write_volatile(0);
        }
        for (i, b) in MAGIC.iter().copied().enumerate() {
            dst.add(i).write_volatile(b);
        }
        for (i, b) in VERSION.iter().copied().enumerate() {
            dst.add(0x40 + i).write_volatile(b);
        }
        for (i, b) in CAP_SUMMARY.iter().copied().enumerate() {
            dst.add(0x100 + i).write_volatile(b);
        }
        for (i, b) in API_SUMMARY.iter().copied().enumerate() {
            dst.add(0x200 + i).write_volatile(b);
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub fn ttbr1_tramp_vector_va() -> u64 {
    TTBR1_TRAMP_VECTOR_VA
}

#[cfg(target_arch = "aarch64")]
pub fn ttbr1_tramp_state_va() -> u64 {
    TTBR1_TRAMP_STATE_VA
}

#[cfg(target_arch = "aarch64")]
pub fn ttbr1_tramp_state_pa() -> u64 {
    // v2: VA==PA assumptions; physical == address of the static page.
    unsafe { &raw const TTBR1_TRAMP_STATE_PAGE as *const Ttbr1TrampStatePage as u64 }
}

#[cfg(target_arch = "aarch64")]
pub fn ttbr1_tramp_state_set(kernel_ttbr0: u64, app_ttbr0: u64) {
    // Keep this allocation-free and safe for use on low-level paths.
    unsafe {
        let p = core::ptr::addr_of_mut!(TTBR1_TRAMP_STATE_PAGE) as *mut u64;
        p.write_volatile(kernel_ttbr0);
        p.add(1).write_volatile(app_ttbr0);
    }
}

#[cfg(target_arch = "aarch64")]
pub fn ttbr1_tramp_state_get() -> (u64, u64) {
    unsafe {
        let p = core::ptr::addr_of!(TTBR1_TRAMP_STATE_PAGE) as *const u64;
        (p.read_volatile(), p.add(1).read_volatile())
    }
}

/// v2/M1: build & self-check page tables is available but disabled by default to avoid
/// impacting app startup time until Stage 3 (TTBR0 switch) is ready.
pub const ENABLE_APP_PT_BUILD_SELFTEST: bool = false;

/// Returns whether the CPU MMU/paging is currently enabled for this architecture.
///
/// oneOS uses this as a guard for MMU-backed AddressSpace features (TTBR0/CR3 switching),
/// without introducing a traditional user/kernel privilege split.
pub fn current_mmu_enabled() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        return crate::mmu::aarch64::is_enabled();
    }
    #[cfg(target_arch = "x86_64")]
    {
        return crate::mmu::x86_64::is_paging_enabled();
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSpaceKind {
    Kernel,
    App,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSpaceBackend {
    /// v2: software-enforced region set only.
    RegionsOnly,
    /// v3+: MMU-backed page tables (future).
    #[allow(dead_code)]
    MmuBacked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Exec,
}

#[derive(Clone, Debug)]
pub struct AddressSpace {
    pub kind: AddressSpaceKind,
    pub backend: AddressSpaceBackend,
    pub regions: Vec<MemRegion>,
    /// v3+ placeholder: root of page tables / TTBR value.
    pub pt_root: Option<u64>,
    /// Allocated page-table pages backing `pt_root` (VA==PA v2 semantics).
    ///
    /// This enables Stage 1 `destroy_address_space()` to reclaim memory.
    pub pt_pages: Vec<u64>,
}

impl AddressSpace {
    fn new(kind: AddressSpaceKind) -> Self {
        Self {
            kind,
            backend: AddressSpaceBackend::RegionsOnly,
            regions: Vec::new(),
            pt_root: None,
            pt_pages: Vec::new(),
        }
    }
}

static NEXT_ID: AtomicU32 = AtomicU32::new(1);
static KERNEL_AS: Once<AddressSpaceId> = Once::new();
static SPACES: Mutex<Vec<(AddressSpaceId, AddressSpace)>> = Mutex::new(Vec::new());

pub fn kernel_id() -> AddressSpaceId {
    *KERNEL_AS.call_once(|| {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let mut aspace = AddressSpace::new(AddressSpaceKind::Kernel);

        // Stage 2/2x: record the currently active kernel page-table root if paging/MMU is enabled.
        // This does not change runtime behavior, but helps future MMU-backed switching and debugging.
        #[cfg(target_arch = "aarch64")]
        {
            if crate::mmu::aarch64::is_enabled() {
                aspace.pt_root = Some(crate::mmu::aarch64::current_ttbr0_el1());
                aspace.backend = AddressSpaceBackend::MmuBacked;
                serial::log_line_args(format_args!(
                    "addrspace: kernel asid={} recorded ttbr0=0x{:x}",
                    id,
                    aspace.pt_root.unwrap_or(0)
                ));
            } else {
                serial::log_line_args(format_args!(
                    "addrspace: kernel asid={} mmu disabled; no ttbr0 recorded",
                    id
                ));
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            if crate::mmu::x86_64::is_paging_enabled() {
                aspace.pt_root = Some(crate::mmu::x86_64::current_cr3());
                aspace.backend = AddressSpaceBackend::MmuBacked;
                serial::log_line_args(format_args!(
                    "addrspace: kernel asid={} recorded cr3=0x{:x}",
                    id,
                    aspace.pt_root.unwrap_or(0)
                ));
            } else {
                serial::log_line_args(format_args!(
                    "addrspace: kernel asid={} paging disabled; no cr3 recorded",
                    id
                ));
            }
        }

        SPACES.lock().push((id, aspace));
        id
    })
}

pub fn refresh_kernel_pt_root_if_enabled() {
    let id = kernel_id();
    if !current_mmu_enabled() {
        return;
    }

    let mut spaces = SPACES.lock();
    let Some((_, aspace)) = spaces.iter_mut().find(|(sid, _)| *sid == id) else {
        return;
    };

    if aspace.pt_root.is_some() {
        return;
    }

    #[cfg(target_arch = "aarch64")]
    {
        aspace.pt_root = Some(crate::mmu::aarch64::current_ttbr0_el1());
        aspace.backend = AddressSpaceBackend::MmuBacked;
        serial::log_line_args(format_args!(
            "addrspace: kernel asid={} refreshed ttbr0=0x{:x}",
            id,
            aspace.pt_root.unwrap_or(0)
        ));
    }
    #[cfg(target_arch = "x86_64")]
    {
        aspace.pt_root = Some(crate::mmu::x86_64::current_cr3());
        aspace.backend = AddressSpaceBackend::MmuBacked;
        serial::log_line_args(format_args!(
            "addrspace: kernel asid={} refreshed cr3=0x{:x}",
            id,
            aspace.pt_root.unwrap_or(0)
        ));
    }
}

pub fn new_app_address_space() -> AddressSpaceId {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    SPACES
        .lock()
        .push((id, AddressSpace::new(AddressSpaceKind::App)));
    id
}

pub fn set_regions(id: AddressSpaceId, regions: Vec<MemRegion>) {
    let mut spaces = SPACES.lock();
    if let Some((_, aspace)) = spaces.iter_mut().find(|(sid, _)| *sid == id) {
        aspace.regions = regions;
    }
}

pub fn set_pt_root(id: AddressSpaceId, pt_root: Option<u64>) {
    let mut spaces = SPACES.lock();
    if let Some((_, aspace)) = spaces.iter_mut().find(|(sid, _)| *sid == id) {
        aspace.pt_root = pt_root;
        if pt_root.is_some() {
            aspace.backend = AddressSpaceBackend::MmuBacked;
        } else {
            aspace.backend = AddressSpaceBackend::RegionsOnly;
            aspace.pt_pages.clear();
        }
    }
}

pub fn set_pt_root_with_pages(id: AddressSpaceId, pt_root: u64, pt_pages: Vec<u64>) {
    let mut spaces = SPACES.lock();
    if let Some((_, aspace)) = spaces.iter_mut().find(|(sid, _)| *sid == id) {
        aspace.pt_root = Some(pt_root);
        aspace.backend = AddressSpaceBackend::MmuBacked;
        aspace.pt_pages = pt_pages;
    }
}

pub fn pt_root(id: AddressSpaceId) -> Option<u64> {
    let spaces = SPACES.lock();
    spaces
        .iter()
        .find(|(sid, _)| *sid == id)
        .and_then(|(_, a)| a.pt_root)
}

pub fn destroy_address_space(id: AddressSpaceId) {
    // Never destroy kernel address space.
    if id == kernel_id() {
        return;
    }

    let (pt_root, pt_pages) = {
        let mut spaces = SPACES.lock();
        let Some((_, aspace)) = spaces.iter_mut().find(|(sid, _)| *sid == id) else {
            return;
        };
        let pt_root = aspace.pt_root.take();
        let pages = core::mem::take(&mut aspace.pt_pages);
        aspace.backend = AddressSpaceBackend::RegionsOnly;
        (pt_root, pages)
    };

    if pt_root.is_none() || pt_pages.is_empty() {
        return;
    }

    // Best-effort TLB flush to avoid stale translations referencing freed page tables.
    #[cfg(target_arch = "aarch64")]
    {
        if crate::mmu::aarch64::is_enabled() {
            crate::mmu::aarch64::enter_ttbr0(crate::mmu::aarch64::read_ttbr0_el1());
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if crate::mmu::x86_64::is_paging_enabled() {
            // Reload CR3 to flush.
            let cr3 = crate::mmu::x86_64::current_cr3();
            unsafe { crate::mmu::x86_64::write_cr3(cr3) };
        }
    }

    // Free all allocated table pages.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    unsafe {
        use alloc::alloc::dealloc;
        use alloc::alloc::Layout;
        let layout = Layout::from_size_align(4096, 4096).ok();
        if let Some(layout) = layout {
            for p in pt_pages {
                dealloc(p as *mut u8, layout);
            }
        }
    }
}

pub fn backend(id: AddressSpaceId) -> AddressSpaceBackend {
    let spaces = SPACES.lock();
    spaces
        .iter()
        .find(|(sid, _)| *sid == id)
        .map(|(_, a)| a.backend)
        .unwrap_or(AddressSpaceBackend::RegionsOnly)
}

/// Unified AddressSpace enter/leave wrappers (Stage 1).
///
/// This keeps all TTBR0/CR3 switching in `mmu::switch`, while letting higher layers
/// (App/Service runners) talk in terms of `AddressSpaceId`.
pub fn enter(
    id: AddressSpaceId,
) -> Result<crate::mmu::switch::SavedSpace, crate::mmu::switch::SwitchError> {
    let Some(root) = pt_root(id) else {
        return Err(crate::mmu::switch::SwitchError::UnsupportedArch);
    };
    crate::mmu::switch::enter_app_space(root)
}

pub fn leave(saved: crate::mmu::switch::SavedSpace) -> Result<(), crate::mmu::switch::SwitchError> {
    crate::mmu::switch::leave_app_space(saved)
}

pub fn regions_len(id: AddressSpaceId) -> usize {
    let spaces = SPACES.lock();
    spaces
        .iter()
        .find(|(sid, _)| *sid == id)
        .map(|(_, a)| a.regions.len())
        .unwrap_or(0)
}

pub fn regions(id: AddressSpaceId) -> Vec<MemRegion> {
    let spaces = SPACES.lock();
    spaces
        .iter()
        .find(|(sid, _)| *sid == id)
        .map(|(_, a)| a.regions.clone())
        .unwrap_or_default()
}

fn access_str(access: Access) -> &'static str {
    match access {
        Access::Read => "R",
        Access::Write => "W",
        Access::Exec => "X",
    }
}

pub fn check_user_ptr(id: AddressSpaceId, ptr: *const u8, len: usize, access: Access) -> bool {
    if ptr.is_null() || len == 0 {
        return true;
    }
    let start = ptr as usize;
    let end = match start.checked_add(len) {
        Some(v) => v,
        None => return false,
    };

    let spaces = SPACES.lock();
    let Some((_, aspace)) = spaces.iter().find(|(sid, _)| *sid == id) else {
        return false;
    };

    // v2: if region set is empty, treat as unrestricted (Kernel/Shell). AppDomain should
    // always configure regions explicitly.
    if aspace.regions.is_empty() {
        return true;
    }

    let need = match access {
        Access::Read => crate::sandbox::MEM_RIGHT_READ,
        Access::Write => crate::sandbox::MEM_RIGHT_WRITE,
        // v2: Exec is validated as Read for now; v3+ will map to XN/PXN flags.
        Access::Exec => crate::sandbox::MEM_RIGHT_READ,
    };

    for (idx, r) in aspace.regions.iter().enumerate() {
        if start >= r.start && end <= r.end && (r.rights & need) == need {
            return true;
        }
        if start < r.end && end > r.start {
            // Overlaps but not fully contained or missing rights; keep scanning to find a full match.
            // No logging here: logging is handled by sandbox on failure to avoid log spam.
            let _ = idx;
        }
    }
    false
}

/// Serial-only diagnostics for `check_user_ptr` failures.
///
/// This is intentionally allocation-free to avoid cascading heap pressure when a failing
/// AppDomain repeatedly triggers pointer checks.
pub fn log_check_failure(
    id: AddressSpaceId,
    domain_id: u32,
    ptr: *const u8,
    len: usize,
    access: Access,
) {
    if ptr.is_null() || len == 0 {
        serial::log_line_args(format_args!(
            "addrspace: check failed domain={} asid={} ptr=null len={} access={:?}",
            domain_id, id, len, access
        ));
        return;
    }
    let start = ptr as usize;
    let end = match start.checked_add(len) {
        Some(v) => v,
        None => {
            serial::log_line_args(format_args!(
                "addrspace: check failed domain={} asid={} ptr=0x{:x} len={} access={:?} (overflow)",
                domain_id, id, start, len, access
            ));
            return;
        }
    };
    let need = match access {
        Access::Read => crate::sandbox::MEM_RIGHT_READ,
        Access::Write => crate::sandbox::MEM_RIGHT_WRITE,
        Access::Exec => crate::sandbox::MEM_RIGHT_READ,
    };

    let spaces = SPACES.lock();
    let Some((_, aspace)) = spaces.iter().find(|(sid, _)| *sid == id) else {
        serial::log_line_args(format_args!(
            "addrspace: check failed domain={} asid={} ptr=0x{:x} len={} access={:?} (missing aspace)",
            domain_id, id, start, len, access
        ));
        return;
    };

    let mut overlaps = 0usize;
    for (i, r) in aspace.regions.iter().enumerate() {
        let overlaps_region = start < r.end && end > r.start;
        if overlaps_region {
            overlaps = overlaps.saturating_add(1);
            let ok_rights = (r.rights & need) == need;
            serial::log_line_args(format_args!(
                "addrspace:  region#{} [0x{:x}..0x{:x}) rights=0x{:x} need=0x{:x} rights_ok={}",
                i, r.start, r.end, r.rights, need, ok_rights
            ));
        }
    }

    serial::log_line_args(format_args!(
        "addrspace: check failed domain={} asid={} ptr=0x{:x} len={} access={:?} overlaps={}",
        domain_id, id, start, len, access, overlaps
    ));
    let _ = access_str(access);
}

// --------------------------------------------------------------------------------------
// v2/M1: Page-table build (AArch64 only), for future MMU-backed AddressSpace.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    UnsupportedArch,
    MapFailed,
}

#[derive(Clone, Copy, Debug)]
pub struct AppMap {
    pub va: u64,
    pub pa: u64,
    pub len: u64,
    pub exec: bool,
    pub writable: bool,
    pub device: bool,
}

#[derive(Clone, Debug)]
pub struct AppSpaceLayout {
    pub maps: Vec<AppMap>,
}

impl AppSpaceLayout {
    pub fn new() -> Self {
        Self { maps: Vec::new() }
    }
    pub fn push(&mut self, map: AppMap) {
        self.maps.push(map);
    }
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn align_down_4k(x: u64) -> u64 {
    x & !(crate::mmu::aarch64::PAGE_SIZE as u64 - 1)
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn align_up_4k(x: u64) -> u64 {
    let mask = crate::mmu::aarch64::PAGE_SIZE as u64 - 1;
    (x + mask) & !mask
}

/// Build an AArch64 4KB-granule page table root for an AppDomain layout.
///
/// v2/M1 limitation: the returned `pt_root_pa` is treated as dereferenceable (VA==PA style)
/// and is only used for self-checking until Stage 3 (TTBR0 switch) is implemented.
pub fn build_app_space(layout: &AppSpaceLayout) -> Result<u64, BuildError> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        use crate::mmu::aarch64::{
            AddressSpaceBuilder, HeapPageTableAlloc, MapError, MapFlags, MemAttr,
        };

        let mut builder = AddressSpaceBuilder::new(HeapPageTableAlloc::new())
            .map_err(|_| BuildError::MapFailed)?;
        for m in layout.maps.iter().copied() {
            let start = align_down_4k(m.va);
            let end = align_up_4k(m.va.saturating_add(m.len));
            let pa_start = align_down_4k(m.pa);
            let len = end.saturating_sub(start);
            let flags = MapFlags {
                read: true,
                write: m.writable,
                exec: m.exec,
                user: false,
                attr: if m.device {
                    MemAttr::Device
                } else {
                    MemAttr::Normal
                },
            };
            builder
                .map_range_4k(start, pa_start, len, flags)
                .map_err(|_e: MapError| BuildError::MapFailed)?;
        }
        Ok(builder.root_pa())
    }
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        use crate::mmu::x86_64::{
            AddressSpaceBuilder, HeapPageTableAlloc, MapError, MapFlags, MemAttr,
        };

        let mut builder = AddressSpaceBuilder::new(HeapPageTableAlloc::new())
            .map_err(|_| BuildError::MapFailed)?;
        for m in layout.maps.iter().copied() {
            let page_mask = crate::mmu::x86_64::PAGE_SIZE as u64 - 1;
            let start = m.va & !page_mask;
            let end = (m.va.saturating_add(m.len) + page_mask) & !page_mask;
            let pa_start = m.pa & !page_mask;
            let len = end.saturating_sub(start);
            let flags = MapFlags {
                read: true,
                write: m.writable,
                exec: m.exec,
                global: false,
                attr: if m.device {
                    MemAttr::Device
                } else {
                    MemAttr::Normal
                },
            };
            builder
                .map_range_4k(start, pa_start, len, flags)
                .map_err(|_e: MapError| BuildError::MapFailed)?;
        }
        Ok(builder.root_pa())
    }
    #[cfg(not(all(
        target_os = "none",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = layout;
        Err(BuildError::UnsupportedArch)
    }
}

pub fn build_app_space_with_stats(layout: &AppSpaceLayout) -> Result<(u64, u64, u64), BuildError> {
    let (root, tables, pages, _pt_pages) = build_app_space_with_stats_and_pages(layout)?;
    Ok((root, tables, pages))
}

pub fn build_app_space_with_stats_and_pages(
    layout: &AppSpaceLayout,
) -> Result<(u64, u64, u64, Vec<u64>), BuildError> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        use crate::mmu::aarch64::{
            AddressSpaceBuilder, HeapPageTableAlloc, MapError, MapFlags, MemAttr,
        };

        let mut builder = AddressSpaceBuilder::new(HeapPageTableAlloc::new())
            .map_err(|_| BuildError::MapFailed)?;
        for m in layout.maps.iter().copied() {
            let start = align_down_4k(m.va);
            let end = align_up_4k(m.va.saturating_add(m.len));
            let pa_start = align_down_4k(m.pa);
            let len = end.saturating_sub(start);
            let flags = MapFlags {
                read: true,
                write: m.writable,
                exec: m.exec,
                user: false,
                attr: if m.device {
                    MemAttr::Device
                } else {
                    MemAttr::Normal
                },
            };
            builder
                .map_range_4k(start, pa_start, len, flags)
                .map_err(|_e: MapError| BuildError::MapFailed)?;
        }
        let (tables, pages) = builder.stats();
        let (root, mut alloc) = builder.finish();
        let pt_pages = alloc.take_allocated_pages();
        Ok((root, tables, pages, pt_pages))
    }
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        use crate::mmu::x86_64::{
            AddressSpaceBuilder, HeapPageTableAlloc, MapError, MapFlags, MemAttr,
        };

        let mut builder = AddressSpaceBuilder::new(HeapPageTableAlloc::new())
            .map_err(|_| BuildError::MapFailed)?;
        for m in layout.maps.iter().copied() {
            let page_mask = crate::mmu::x86_64::PAGE_SIZE as u64 - 1;
            let start = m.va & !page_mask;
            let end = (m.va.saturating_add(m.len) + page_mask) & !page_mask;
            let pa_start = m.pa & !page_mask;
            let len = end.saturating_sub(start);
            let flags = MapFlags {
                read: true,
                write: m.writable,
                exec: m.exec,
                global: false,
                attr: if m.device {
                    MemAttr::Device
                } else {
                    MemAttr::Normal
                },
            };
            builder
                .map_range_4k(start, pa_start, len, flags)
                .map_err(|_e: MapError| BuildError::MapFailed)?;
        }
        let (tables, pages) = builder.stats();
        let (root, mut alloc) = builder.finish();
        let pt_pages = alloc.take_allocated_pages();
        Ok((root, tables, pages, pt_pages))
    }
    #[cfg(not(all(
        target_os = "none",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = layout;
        Err(BuildError::UnsupportedArch)
    }
}

/// Best-effort self-check for a freshly built App page table root.
///
/// v2/M1: this runs without switching TTBR0. It assumes `pt_root_pa` is dereferenceable
/// (VA==PA style) and is used only for diagnosing builder correctness.
pub fn selfcheck_app_space(pt_root_pa: u64, layout: &AppSpaceLayout) -> bool {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        use crate::mmu::aarch64::{desc_matches_flags, walk_l3, MapFlags, MemAttr, PteKind};

        let mut ok = true;
        for (i, m) in layout.maps.iter().copied().enumerate() {
            let flags = MapFlags {
                read: true,
                write: m.writable,
                exec: m.exec,
                user: false,
                attr: if m.device {
                    MemAttr::Device
                } else {
                    MemAttr::Normal
                },
            };
            let start = m.va;
            let end = m.va.saturating_add(m.len).saturating_sub(1);
            for (label, va) in [("start", start), ("end", end)] {
                let info = unsafe { walk_l3(pt_root_pa, va) };
                if info.kind != PteKind::Page {
                    serial::log_line_args(format_args!(
                        "mmu-selfcheck: map#{} {} va=0x{:x} missing",
                        i, label, va
                    ));
                    ok = false;
                    continue;
                }
                if !desc_matches_flags(info.desc, flags) {
                    serial::log_line_args(format_args!(
                        "mmu-selfcheck: map#{} {} va=0x{:x} flags mismatch desc=0x{:x} want(exec={}, w={})",
                        i,
                        label,
                        va,
                        info.desc,
                        m.exec,
                        m.writable
                    ));
                    ok = false;
                }
            }
        }
        ok
    }
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        use crate::mmu::x86_64::{desc_matches_flags, walk_l1, MapFlags, MemAttr, PteKind};

        let mut ok = true;
        for (i, m) in layout.maps.iter().copied().enumerate() {
            let flags = MapFlags {
                read: true,
                write: m.writable,
                exec: m.exec,
                global: false,
                attr: if m.device {
                    MemAttr::Device
                } else {
                    MemAttr::Normal
                },
            };
            let start = m.va;
            let end = m.va.saturating_add(m.len).saturating_sub(1);
            for (label, va) in [("start", start), ("end", end)] {
                let info = unsafe { walk_l1(pt_root_pa, va) };
                if info.kind != PteKind::Page {
                    crate::drivers::serial::log_line_args(format_args!(
                        "mmu-selfcheck: map#{} {} va=0x{:x} missing",
                        i, label, va
                    ));
                    ok = false;
                    continue;
                }
                if !desc_matches_flags(info.desc, flags) {
                    crate::drivers::serial::log_line_args(format_args!(
                        "mmu-selfcheck: map#{} {} va=0x{:x} flags mismatch desc=0x{:x} want(exec={}, w={})",
                        i, label, va, info.desc, m.exec, m.writable
                    ));
                    ok = false;
                }
            }
        }
        ok
    }
    #[cfg(not(all(
        target_os = "none",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = pt_root_pa;
        let _ = layout;
        true
    }
}
