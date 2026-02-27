#![cfg(target_os = "none")]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug)]
pub enum ElfError {
    TooSmall,
    BadMagic,
    UnsupportedClass,
    UnsupportedEndian,
    BadHeader,
    BadProgramHeader,
    UnsupportedMachine,
}

#[derive(Clone, Copy, Debug)]
pub struct ElfInfo {
    pub entry: u64,
    pub phoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
    pub machine: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

fn u16_le(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(0..2)?.try_into().ok()?))
}
fn u32_le(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(0..4)?.try_into().ok()?))
}
fn u64_le(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(0..8)?.try_into().ok()?))
}

pub fn parse_elf64_le(bytes: &[u8]) -> Result<(ElfInfo, Vec<ProgramHeader>), ElfError> {
    // ELF64 header size is 64 bytes.
    if bytes.len() < 0x40 {
        return Err(ElfError::TooSmall);
    }
    if &bytes[0..4] != b"\x7fELF" {
        return Err(ElfError::BadMagic);
    }
    // EI_CLASS: 2=ELF64
    if bytes[4] != 2 {
        return Err(ElfError::UnsupportedClass);
    }
    // EI_DATA: 1=little
    if bytes[5] != 1 {
        return Err(ElfError::UnsupportedEndian);
    }
    // e_machine at 0x12
    let machine = u16_le(&bytes[0x12..0x14]).ok_or(ElfError::BadHeader)?;

    // Validate machine matches current arch (x86_64=62, aarch64=183).
    let expected = if cfg!(target_arch = "x86_64") {
        62u16
    } else if cfg!(target_arch = "aarch64") {
        183u16
    } else {
        0u16
    };
    if expected != 0 && machine != expected {
        return Err(ElfError::UnsupportedMachine);
    }

    let entry = u64_le(&bytes[0x18..0x20]).ok_or(ElfError::BadHeader)?;
    let phoff = u64_le(&bytes[0x20..0x28]).ok_or(ElfError::BadHeader)?;
    let phentsize = u16_le(&bytes[0x36..0x38]).ok_or(ElfError::BadHeader)?;
    let phnum = u16_le(&bytes[0x38..0x3a]).ok_or(ElfError::BadHeader)?;

    if phentsize as usize == 0 || phnum == 0 {
        return Ok((
            ElfInfo {
                entry,
                phoff,
                phentsize,
                phnum,
                machine,
            },
            Vec::new(),
        ));
    }
    if phentsize as usize != 56 {
        // We only support ELF64 program header size 56 for now.
        return Err(ElfError::BadProgramHeader);
    }

    let ph_table_end = phoff
        .checked_add((phentsize as u64).saturating_mul(phnum as u64))
        .ok_or(ElfError::BadProgramHeader)?;
    if ph_table_end as usize > bytes.len() {
        return Err(ElfError::BadProgramHeader);
    }

    let mut phdrs = Vec::new();
    for i in 0..phnum as usize {
        let base = phoff as usize + i * (phentsize as usize);
        let ph = &bytes[base..base + phentsize as usize];
        let p_type = u32_le(&ph[0x00..0x04]).ok_or(ElfError::BadProgramHeader)?;
        let flags = u32_le(&ph[0x04..0x08]).ok_or(ElfError::BadProgramHeader)?;
        let offset = u64_le(&ph[0x08..0x10]).ok_or(ElfError::BadProgramHeader)?;
        let vaddr = u64_le(&ph[0x10..0x18]).ok_or(ElfError::BadProgramHeader)?;
        let filesz = u64_le(&ph[0x20..0x28]).ok_or(ElfError::BadProgramHeader)?;
        let memsz = u64_le(&ph[0x28..0x30]).ok_or(ElfError::BadProgramHeader)?;
        let align = u64_le(&ph[0x30..0x38]).ok_or(ElfError::BadProgramHeader)?;
        phdrs.push(ProgramHeader {
            p_type,
            flags,
            offset,
            vaddr,
            filesz,
            memsz,
            align,
        });
    }

    Ok((
        ElfInfo {
            entry,
            phoff,
            phentsize,
            phnum,
            machine,
        },
        phdrs,
    ))
}

pub fn format_elf_report(info: &ElfInfo, phdrs: &[ProgramHeader]) -> Vec<String> {
    let mut out = Vec::new();
    out.push(alloc::format!(
        "ELF: machine={} entry=0x{:x} phoff=0x{:x} phnum={}",
        info.machine,
        info.entry,
        info.phoff,
        info.phnum
    ));
    for (i, ph) in phdrs.iter().enumerate() {
        // PT_LOAD = 1
        let ty = if ph.p_type == 1 { "LOAD" } else { "OTHER" };
        out.push(alloc::format!(
            "  PH#{:02} {:>5} off=0x{:x} vaddr=0x{:x} file=0x{:x} mem=0x{:x} flags=0x{:x} align=0x{:x}",
            i,
            ty,
            ph.offset,
            ph.vaddr,
            ph.filesz,
            ph.memsz,
            ph.flags,
            ph.align
        ));
    }
    out
}
