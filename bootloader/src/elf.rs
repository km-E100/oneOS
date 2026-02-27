use alloc::vec::Vec;
use core::mem;
use core::ptr::copy_nonoverlapping;
use uefi::boot::{self, AllocateType, MemoryType};
use uefi::prelude::*;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PT_LOAD: u32 = 1;

#[cfg(target_arch = "aarch64")]
const ELF_MACHINE: u16 = 0xB7;
#[cfg(target_arch = "x86_64")]
const ELF_MACHINE: u16 = 0x3E;

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

pub struct LoadedSegment {
    pub physical_addr: u64,
    pub mem_size: u64,
    pub file_size: u64,
    pub file_offset: u64,
}

pub struct ElfImage {
    pub entry: u64,
    pub segments: Vec<LoadedSegment>,
}

impl ElfImage {
    pub fn parse(data: &[u8]) -> Result<Self, Status> {
        if data.len() < mem::size_of::<Elf64Ehdr>() {
            return Err(Status::LOAD_ERROR);
        }
        let header = unsafe { *(data.as_ptr() as *const Elf64Ehdr) };
        if header.e_ident[..4] != ELF_MAGIC {
            return Err(Status::UNSUPPORTED);
        }
        if header.e_machine != ELF_MACHINE {
            return Err(Status::UNSUPPORTED);
        }

        let phoff = header.e_phoff as usize;
        let phentsize = header.e_phentsize as usize;
        let phnum = header.e_phnum as usize;

        let mut segments = Vec::new();
        for idx in 0..phnum {
            let offset = phoff + idx * phentsize;
            if offset + phentsize > data.len() {
                return Err(Status::LOAD_ERROR);
            }
            let ph = unsafe { *(data.as_ptr().add(offset) as *const Elf64Phdr) };
            if ph.p_type != PT_LOAD {
                continue;
            }
            if ph.p_memsz == 0 {
                continue;
            }
            segments.push(LoadedSegment {
                physical_addr: ph.p_paddr,
                mem_size: ph.p_memsz,
                file_size: ph.p_filesz,
                file_offset: ph.p_offset,
            });
        }

        Ok(Self {
            entry: header.e_entry,
            segments,
        })
    }
}

pub struct SegmentLoadError {
    pub status: Status,
    pub physical_addr: u64,
    pub mem_size: u64,
    pub file_size: u64,
}

pub fn load_segments(image: &ElfImage, file_data: &[u8]) -> Result<(), SegmentLoadError> {
    // Notes:
    // - UEFI AllocateType::Address requires page alignment.
    // - ELF PT_LOAD segments may legally start at non-page-aligned addresses (p_paddr % 0x1000 != 0),
    //   and multiple segments can share a page. So we allocate a single page-aligned range covering
    //   all segments, then copy each segment into its intended physical address.
    let (load_base, load_size) = load_range(image).ok_or(SegmentLoadError {
        status: Status::LOAD_ERROR,
        physical_addr: 0,
        mem_size: 0,
        file_size: 0,
    })?;
    let pages = ((load_size + 0xfff) / 0x1000) as usize;

    let base_ptr = match boot::allocate_pages(
        AllocateType::Address(load_base),
        MemoryType::LOADER_CODE,
        pages,
    ) {
        Ok(ptr) => ptr.as_ptr() as *mut u8,
        Err(e) => {
            return Err(SegmentLoadError {
                status: e.status(),
                physical_addr: load_base,
                mem_size: load_size,
                file_size: 0,
            })
        }
    };

    unsafe {
        core::ptr::write_bytes(base_ptr, 0, load_size as usize);
    }

    for segment in &image.segments {
        let file_offset = segment.file_offset as usize;
        let file_size = segment.file_size as usize;
        if file_offset
            .checked_add(file_size)
            .map_or(true, |end| end > file_data.len())
        {
            return Err(SegmentLoadError {
                status: Status::LOAD_ERROR,
                physical_addr: segment.physical_addr,
                mem_size: segment.mem_size,
                file_size: segment.file_size,
            });
        }

        let seg_offset = segment
            .physical_addr
            .checked_sub(load_base)
            .ok_or(SegmentLoadError {
                status: Status::LOAD_ERROR,
                physical_addr: segment.physical_addr,
                mem_size: segment.mem_size,
                file_size: segment.file_size,
            })?;
        let dest = unsafe { base_ptr.add(seg_offset as usize) };

        unsafe {
            copy_nonoverlapping(file_data.as_ptr().add(file_offset), dest, file_size);
            if segment.mem_size > segment.file_size {
                core::ptr::write_bytes(
                    dest.add(file_size),
                    0,
                    (segment.mem_size - segment.file_size) as usize,
                );
            }
        }
    }
    Ok(())
}

fn align_down(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + (align - 1)) & !(align - 1)
}

fn load_range(image: &ElfImage) -> Option<(u64, u64)> {
    let mut min = u64::MAX;
    let mut max = 0u64;

    for seg in &image.segments {
        min = min.min(seg.physical_addr);
        max = max.max(seg.physical_addr.checked_add(seg.mem_size)?);
    }
    if min == u64::MAX || max <= min {
        return None;
    }

    let base = align_down(min, 0x1000);
    let end = align_up(max, 0x1000);
    Some((base, end - base))
}

pub fn debug_load_range(image: &ElfImage) -> Option<(u64, u64)> {
    load_range(image)
}
