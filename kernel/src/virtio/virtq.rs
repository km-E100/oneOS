#![allow(dead_code)]

extern crate alloc;

use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use core::mem;
use core::ptr::NonNull;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Desc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

impl Desc {
    pub const fn new() -> Self {
        Self {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }
    }
}

#[repr(C)]
pub struct AvailHdr {
    pub flags: u16,
    pub idx: u16,
}

#[repr(C)]
pub struct UsedHdr {
    pub flags: u16,
    pub idx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UsedElem {
    pub id: u32,
    pub len: u32,
}

impl UsedElem {
    pub const fn new() -> Self {
        Self { id: 0, len: 0 }
    }
}

struct Alloc {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl Drop for Alloc {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

pub struct Queue {
    alloc: Alloc,
    qsize: u16,
    desc: *mut Desc,
    avail: *mut AvailHdr,
    used: *mut UsedHdr,
    avail_ring: *mut u16,
    used_ring: *mut UsedElem,
}

unsafe impl Send for Queue {}
unsafe impl Sync for Queue {}

impl Queue {
    pub fn new(qsize: u16) -> Option<Self> {
        if qsize == 0 {
            return None;
        }
        let q = qsize as usize;

        let desc_bytes = mem::size_of::<Desc>().checked_mul(q)?;
        let avail_bytes = mem::size_of::<AvailHdr>()
            .checked_add(mem::size_of::<u16>().checked_mul(q)?)?
            .checked_add(mem::size_of::<u16>())?; // used_event
        let used_bytes = mem::size_of::<UsedHdr>()
            .checked_add(mem::size_of::<UsedElem>().checked_mul(q)?)?
            .checked_add(mem::size_of::<u16>())?; // avail_event

        // Layout for split virtqueue:
        // - desc table: 16-byte aligned
        // - avail ring: 2-byte aligned
        // - used ring: 4-byte aligned
        // Whole region: 4096 aligned for legacy `QUEUE_ADDRESS` use.
        let mut off = 0usize;
        let desc_off = off;
        off = off.checked_add(align_up(desc_bytes, 16))?;
        off = align_up(off, 2);
        let avail_off = off;
        off = off.checked_add(align_up(avail_bytes, 2))?;
        off = align_up(off, 4);
        let used_off = off;
        off = off.checked_add(align_up(used_bytes, 4))?;
        let total = align_up(off, 4096);

        let layout = Layout::from_size_align(total, 4096).ok()?;
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw)?;
        let base = ptr.as_ptr();

        let desc = unsafe { base.add(desc_off) as *mut Desc };
        let avail = unsafe { base.add(avail_off) as *mut AvailHdr };
        let used = unsafe { base.add(used_off) as *mut UsedHdr };
        let avail_ring = unsafe { (avail as *mut u8).add(mem::size_of::<AvailHdr>()) as *mut u16 };
        let used_ring =
            unsafe { (used as *mut u8).add(mem::size_of::<UsedHdr>()) as *mut UsedElem };

        Some(Self {
            alloc: Alloc { ptr, layout },
            qsize,
            desc,
            avail,
            used,
            avail_ring,
            used_ring,
        })
    }

    #[inline]
    pub fn qsize(&self) -> u16 {
        self.qsize
    }

    #[inline]
    pub fn base_ptr(&self) -> *mut u8 {
        self.alloc.ptr.as_ptr()
    }

    #[inline]
    pub fn desc_ptr(&self) -> *mut Desc {
        self.desc
    }

    #[inline]
    pub fn avail_hdr_ptr(&self) -> *mut AvailHdr {
        self.avail
    }

    #[inline]
    pub fn used_hdr_ptr(&self) -> *mut UsedHdr {
        self.used
    }

    #[inline]
    pub fn avail_ring_ptr(&self) -> *mut u16 {
        self.avail_ring
    }

    #[inline]
    pub fn used_ring_ptr(&self) -> *mut UsedElem {
        self.used_ring
    }
}
