#![cfg(target_os = "none")]

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

use oneos_boot_proto::MemoryRegionType;

use crate::{boot_info, drivers::serial};

const HEAP_SIZE_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

pub fn init_from_boot_info() -> bool {
    let Some(regions) = boot_info::memory_regions() else {
        serial::log_line("heap: boot info memory map unavailable");
        return false;
    };

    // Pick the largest Conventional region.
    let mut best_base = 0u64;
    let mut best_len = 0u64;
    for r in regions {
        if r.region_type != MemoryRegionType::Conventional {
            continue;
        }
        if r.length > best_len {
            best_base = r.base;
            best_len = r.length;
        }
    }
    if best_len == 0 {
        serial::log_line("heap: no Conventional region found");
        return false;
    }

    let heap_len = core::cmp::min(best_len as usize, HEAP_SIZE_BYTES);
    if heap_len < 1024 * 1024 {
        serial::log_line_args(format_args!(
            "heap: Conventional region too small (len={:#x})",
            best_len
        ));
        return false;
    }

    let region_end = best_base.saturating_add(best_len);
    let heap_start = align_down(region_end as usize - heap_len, 16);
    let heap_end = heap_start + heap_len;

    unsafe {
        if ALLOCATOR.init(heap_start, heap_end) {
            serial::log_line_args(format_args!(
                "heap: init ok base={:#x} size={:#x}",
                heap_start, heap_len
            ));
            true
        } else {
            serial::log_line("heap: already initialized");
            true
        }
    }
}

pub fn stats() -> (usize, usize, usize) {
    (
        ALLOCATOR.start.load(Ordering::Relaxed),
        ALLOCATOR.end.load(Ordering::Relaxed),
        ALLOCATOR.used.load(Ordering::Relaxed),
    )
}

pub fn used_bytes() -> usize {
    ALLOCATOR.used.load(Ordering::Relaxed)
}

pub fn dump_free_list(max_nodes: usize) {
    let start = ALLOCATOR.start.load(Ordering::Relaxed);
    let end = ALLOCATOR.end.load(Ordering::Relaxed);
    if start == 0 || end == 0 {
        serial::log_line("heap: free list unavailable (not initialized)");
        return;
    }
    let used = ALLOCATOR.used.load(Ordering::Relaxed);
    serial::log_line_args(format_args!(
        "heap: dump_free_list heap=[0x{:x}..0x{:x}) used=0x{:x}",
        start, end, used
    ));
    let head = ALLOCATOR.head.lock();
    let mut n = 0usize;
    let mut cur = head.next.as_deref();
    while let Some(node) = cur {
        serial::log_line_args(format_args!(
            "heap: free#{} addr=0x{:x} size=0x{:x} end=0x{:x}",
            n,
            node.start_addr(),
            node.size,
            node.end_addr()
        ));
        n += 1;
        if n >= max_nodes {
            break;
        }
        cur = node.next.as_deref();
    }
    if cur.is_some() {
        serial::log_line_args(format_args!(
            "heap: free list truncated (>= {} nodes)",
            max_nodes
        ));
    }
}

fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

fn align_down(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}

#[repr(C)]
struct ListNode {
    size: usize,
    next: Option<&'static mut ListNode>,
}

impl ListNode {
    const fn new(size: usize) -> Self {
        Self { size, next: None }
    }

    fn start_addr(&self) -> usize {
        self as *const Self as usize
    }

    fn end_addr(&self) -> usize {
        self.start_addr().saturating_add(self.size)
    }
}

struct LinkedListAllocator {
    start: AtomicUsize,
    end: AtomicUsize,
    used: AtomicUsize,
    head: spin::Mutex<ListNode>,
}

impl LinkedListAllocator {
    const fn new() -> Self {
        Self {
            start: AtomicUsize::new(0),
            end: AtomicUsize::new(0),
            used: AtomicUsize::new(0),
            head: spin::Mutex::new(ListNode::new(0)),
        }
    }

    unsafe fn init(&self, start: usize, end: usize) -> bool {
        let existing = self.start.load(Ordering::Relaxed);
        if existing != 0 {
            return false;
        }
        self.start.store(start, Ordering::Relaxed);
        self.end.store(end, Ordering::Relaxed);
        self.used.store(0, Ordering::Relaxed);

        let mut head = self.head.lock();
        head.next = None;

        let mut region_start = start;
        let region_end = end;
        let align = core::mem::align_of::<ListNode>();
        region_start = align_up(region_start, align);
        if region_start >= region_end {
            return false;
        }
        let size = region_end - region_start;
        if size < core::mem::size_of::<ListNode>() {
            return false;
        }

        // SAFETY: region_start points into the reserved heap region and is suitably aligned.
        let node_ptr = region_start as *mut ListNode;
        node_ptr.write(ListNode::new(size));
        head.next = Some(&mut *node_ptr);
        true
    }

    fn alloc_inner(&self, layout: Layout) -> *mut u8 {
        let start = self.start.load(Ordering::Relaxed);
        let end = self.end.load(Ordering::Relaxed);
        if start == 0 || end == 0 {
            return null_mut();
        }

        let mut size = layout.size().max(1);
        let mut align = layout.align().max(16).next_power_of_two();
        // Ensure the allocated block can later hold a ListNode when freed.
        size = size.max(core::mem::size_of::<ListNode>());
        align = align.max(core::mem::align_of::<ListNode>());

        let mut head = self.head.lock();

        let mut cur = &mut *head;
        while let Some(ref mut region) = cur.next {
            if let Some((alloc_start, alloc_end)) = alloc_from_region(region, size, align) {
                let region_start = region.start_addr();
                let region_end = region.end_addr();

                // Remove region from list.
                let mut taken = cur.next.take().unwrap();
                cur.next = taken.next.take();

                // Prefix free region before alloc_start.
                if alloc_start > region_start {
                    add_free_region_locked(&mut head, region_start, alloc_start - region_start);
                }

                // Suffix free region after alloc_end.
                if alloc_end < region_end {
                    add_free_region_locked(&mut head, alloc_end, region_end - alloc_end);
                }

                self.used.fetch_add(size, Ordering::Relaxed);
                return alloc_start as *mut u8;
            }
            cur = cur.next.as_mut().unwrap();
        }
        null_mut()
    }

    unsafe fn dealloc_inner(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let mut size = layout.size().max(1);
        let mut align = layout.align().max(16).next_power_of_two();
        size = size.max(core::mem::size_of::<ListNode>());
        align = align.max(core::mem::align_of::<ListNode>());
        let addr = ptr as usize;
        // The returned pointer should already satisfy alignment, but keep behavior stable.
        if (addr & (align - 1)) != 0 {
            return;
        }

        let mut head = self.head.lock();
        add_free_region_locked(&mut head, addr, size);
        self.used.fetch_sub(size, Ordering::Relaxed);
    }
}

fn alloc_from_region(region: &ListNode, size: usize, align: usize) -> Option<(usize, usize)> {
    let region_start = region.start_addr();
    let region_end = region.end_addr();
    let alloc_start = align_up(region_start, align);
    let alloc_end = alloc_start.checked_add(size)?;
    if alloc_end > region_end {
        return None;
    }
    Some((alloc_start, alloc_end))
}

fn add_free_region_locked(head: &mut ListNode, addr: usize, size: usize) {
    // Align the start address so we can place a ListNode there; shrink size accordingly.
    let align = core::mem::align_of::<ListNode>();
    let aligned_addr = align_up(addr, align);
    let delta = aligned_addr.saturating_sub(addr);
    if delta >= size {
        return;
    }
    let size = size - delta;
    if size < core::mem::size_of::<ListNode>() {
        return;
    }
    if aligned_addr == 0 {
        return;
    }

    // Insert sorted by address.
    let mut cur: *mut ListNode = head as *mut ListNode;
    unsafe {
        while let Some(ref mut next) = (*cur).next {
            if next.start_addr() >= aligned_addr {
                break;
            }
            cur = (&mut **next) as *mut ListNode;
        }
    }

    // SAFETY: free region address lies within the reserved heap range, and we're writing a ListNode into it.
    let node_ptr = aligned_addr as *mut ListNode;
    unsafe { node_ptr.write(ListNode::new(size)) };
    let node_ref = unsafe { &mut *node_ptr };
    unsafe {
        node_ref.next = (*cur).next.take();
        (*cur).next = Some(node_ref);
        // Merge previous with inserted if adjacent.
        merge_adjacent(&mut *cur);
        // Merge inserted with its next if adjacent.
        if let Some(ref mut inserted) = (*cur).next {
            merge_adjacent(&mut **inserted);
        }
    }

    // Note: we intentionally do not do a full list coalesce pass here to keep
    // dealloc cheap; the above local merges cover the common adjacent cases.
}

fn merge_adjacent(node: &mut ListNode) {
    let node_end = node.end_addr();
    let Some(next) = node.next.as_mut() else {
        return;
    };
    if node_end == next.start_addr() {
        let next_next = next.next.take();
        node.size = node.size.saturating_add(next.size);
        node.next = next_next;
    }
}

unsafe impl GlobalAlloc for LinkedListAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.alloc_inner(layout)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        self.dealloc_inner(_ptr, _layout)
    }
}

#[global_allocator]
static ALLOCATOR: LinkedListAllocator = LinkedListAllocator::new();

#[alloc_error_handler]
fn oom(layout: Layout) -> ! {
    let (start, end, used_ctr) = stats();
    let used = used_bytes();
    serial::log_line_args(format_args!(
        "heap: OOM request size={} align={} heap=[0x{:x}..0x{:x}) used=0x{:x} used_ctr=0x{:x}",
        layout.size(),
        layout.align(),
        start,
        end,
        used,
        used_ctr
    ));
    dump_free_list(12);
    panic!("oom: {} bytes align {}", layout.size(), layout.align())
}
