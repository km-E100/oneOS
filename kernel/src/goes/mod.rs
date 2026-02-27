#![cfg(target_os = "none")]

use core::mem;

use spin::Once;

use crate::drivers::serial;
use crate::virtio;
use oneos_boot_proto::crc32::crc32_ieee_with_zeroed_range;

pub mod crc32;
pub mod records;
pub mod replay;
pub mod view;
pub mod writer;

const GOES_MANIFEST_BLOCK_SIZE: usize = 4096;
const GOES_MANIFEST_MAGIC_V01: &[u8; 4] = b"OGMF";
const GOES_MANIFEST_ENTRY_NAME_LEN: usize = 32;
const GOES_MANIFEST_ENTRY_SIZE: usize = 48;
const GOES_CHECKPOINT_BLOCK_SIZE: usize = 4096;
const GOES_CHECKPOINT_MAGIC_V01: &[u8; 4] = b"GOCP";
const GOES_BOOT_MANIFEST_BLOCK_SIZE: usize = 4096;
const GOES_BOOT_MANIFEST_MAGIC_V01: &[u8; 4] = b"GOBM";

#[derive(Clone, Copy, Debug)]
pub struct GoesSuperblockV01 {
    pub version: u32,
    pub header_size: u32,
    pub block_size: u32,
    pub flags: u32,
    pub checkpoint_offset: u64,
    pub manifest_offset: u64,
    pub record_log_offset: u64,
    pub record_log_len: u64,
    pub kernel_x86_offset: u64,
    pub kernel_x86_len: u64,
    pub kernel_aa_offset: u64,
    pub kernel_aa_len: u64,
    pub default_user: [u8; 32],
}

static GOES_SB: Once<GoesSuperblockV01> = Once::new();
static GOES_MANIFEST: Once<GoesManifestV01> = Once::new();
static GOES_CHECKPOINT: Once<GoesCheckpointV01> = Once::new();
static GOES_BOOT_MANIFEST: Once<GoesBootManifestV01> = Once::new();

#[derive(Clone, Copy, Debug)]
pub struct GoesManifestV01 {
    pub flags: u32,
    pub default_user: [u8; 32],
    pub workspace_count: u32,
    pub workspace_entries_offset: u32,
    pub kernel_x86_offset: u64,
    pub kernel_x86_len: u64,
    pub kernel_aa_offset: u64,
    pub kernel_aa_len: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct GoesCheckpointV01 {
    pub seq: u64,
    pub boot_manifest_offset: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct GoesBootManifestV01 {
    pub flags: u32,
    pub seq: u64,
    pub active_set: u32,
    pub set_count: u32,
    pub default_user: [u8; 32],
    pub set_entries_offset: u32,
    pub set_entry_size: u32,
}

fn get_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn get_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let bytes = buf.get(off..off + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn parse_superblock(buf: &[u8]) -> Option<GoesSuperblockV01> {
    if buf.len() < 256 {
        return None;
    }
    if &buf[0..4] != b"GOES" {
        return None;
    }
    let stored_crc = get_u32_le(buf, 0x68).unwrap_or(0);
    if stored_crc != 0 {
        let calc = crc32_ieee_with_zeroed_range(&buf[..256], 0x68, 4);
        if calc != stored_crc {
            return None;
        }
    }
    let version = get_u32_le(buf, 0x04)?;
    let header_size = get_u32_le(buf, 0x08)?;
    let block_size = get_u32_le(buf, 0x0c)?;
    let flags = get_u32_le(buf, 0x10)?;
    let checkpoint_offset = get_u64_le(buf, 0x18)?;
    let manifest_offset = get_u64_le(buf, 0x20)?;
    let kernel_x86_offset = get_u64_le(buf, 0x28)?;
    let kernel_x86_len = get_u64_le(buf, 0x30)?;
    let kernel_aa_offset = get_u64_le(buf, 0x38)?;
    let kernel_aa_len = get_u64_le(buf, 0x40)?;
    let record_log_offset = get_u64_le(buf, 0x70).unwrap_or(0);
    let record_log_len = get_u64_le(buf, 0x78).unwrap_or(0);
    let mut default_user = [0u8; 32];
    default_user.copy_from_slice(buf.get(0x48..0x48 + 32)?);
    Some(GoesSuperblockV01 {
        version,
        header_size,
        block_size,
        flags,
        checkpoint_offset,
        manifest_offset,
        record_log_offset,
        record_log_len,
        kernel_x86_offset,
        kernel_x86_len,
        kernel_aa_offset,
        kernel_aa_len,
        default_user,
    })
}

fn parse_manifest(buf: &[u8]) -> Option<GoesManifestV01> {
    if buf.len() < 0x60 {
        return None;
    }
    if &buf[0..4] != GOES_MANIFEST_MAGIC_V01 {
        return None;
    }
    let version = get_u32_le(buf, 0x04)?;
    if version != 1 {
        return None;
    }
    let stored_crc = get_u32_le(buf, 0x60).unwrap_or(0);
    if stored_crc != 0 {
        let calc = crc32_ieee_with_zeroed_range(buf, 0x60, 4);
        if calc != stored_crc {
            return None;
        }
    }
    let flags = get_u32_le(buf, 0x08)?;
    let mut default_user = [0u8; 32];
    default_user.copy_from_slice(buf.get(0x10..0x10 + 32)?);
    let workspace_count = get_u32_le(buf, 0x30)?;
    let workspace_entries_offset = get_u32_le(buf, 0x38)?;
    let kernel_x86_offset = get_u64_le(buf, 0x40)?;
    let kernel_x86_len = get_u64_le(buf, 0x48)?;
    let kernel_aa_offset = get_u64_le(buf, 0x50)?;
    let kernel_aa_len = get_u64_le(buf, 0x58)?;
    Some(GoesManifestV01 {
        flags,
        default_user,
        workspace_count,
        workspace_entries_offset,
        kernel_x86_offset,
        kernel_x86_len,
        kernel_aa_offset,
        kernel_aa_len,
    })
}

fn parse_checkpoint(buf: &[u8]) -> Option<GoesCheckpointV01> {
    if buf.len() < 0x20 {
        return None;
    }
    if &buf[0..4] != GOES_CHECKPOINT_MAGIC_V01 {
        return None;
    }
    let version = get_u32_le(buf, 0x04)?;
    if version != 1 {
        return None;
    }
    let stored_crc = get_u32_le(buf, 0x20).unwrap_or(0);
    if stored_crc != 0 {
        let calc = crc32_ieee_with_zeroed_range(buf, 0x20, 4);
        if calc != stored_crc {
            return None;
        }
    }
    let seq = get_u64_le(buf, 0x10)?;
    let boot_manifest_offset = get_u64_le(buf, 0x18)?;
    Some(GoesCheckpointV01 {
        seq,
        boot_manifest_offset,
    })
}

fn parse_boot_manifest(buf: &[u8]) -> Option<GoesBootManifestV01> {
    if buf.len() < 0x60 {
        return None;
    }
    if &buf[0..4] != GOES_BOOT_MANIFEST_MAGIC_V01 {
        return None;
    }
    let version = get_u32_le(buf, 0x04)?;
    if version != 1 {
        return None;
    }
    let stored_crc = get_u32_le(buf, 0x48).unwrap_or(0);
    if stored_crc != 0 {
        let calc = crc32_ieee_with_zeroed_range(buf, 0x48, 4);
        if calc != stored_crc {
            return None;
        }
    }
    let flags = get_u32_le(buf, 0x0c)?;
    let seq = get_u64_le(buf, 0x10)?;
    let active_set = get_u32_le(buf, 0x18)?;
    let set_count = get_u32_le(buf, 0x1c)?;
    let mut default_user = [0u8; 32];
    default_user.copy_from_slice(buf.get(0x20..0x20 + 32)?);
    let set_entries_offset = get_u32_le(buf, 0x40)?;
    let set_entry_size = get_u32_le(buf, 0x44)?;
    Some(GoesBootManifestV01 {
        flags,
        seq,
        active_set,
        set_count,
        default_user,
        set_entries_offset,
        set_entry_size,
    })
}

pub fn probe() -> Option<&'static GoesSuperblockV01> {
    if let Some(existing) = GOES_SB.get() {
        return Some(existing);
    }
    if !virtio::blk::available() {
        serial::log_line("goes: virtio-blk unavailable");
        return None;
    }
    let mut buf = [0u8; 256];
    if virtio::blk::read_at_res(0, &mut buf).is_err() {
        serial::log_line("goes: read superblock failed");
        return None;
    }
    let Some(sb) = parse_superblock(&buf) else {
        serial::log_line_args(format_args!(
            "goes: superblock parse failed (first4={:02x} {:02x} {:02x} {:02x})",
            buf[0], buf[1], buf[2], buf[3]
        ));
        // 额外提示：若读到的是 FAT/MBR，通常不是 GOES 盘（可能选错了块设备）。
        if buf[0] == 0xEB || buf[0] == 0xE9 {
            serial::log_line("goes: hint: looks like a FAT boot sector; kernel may be reading ESP disk, not GOES disk");
        }
        return None;
    };
    if sb.header_size as usize > mem::size_of_val(&buf) {
        // v0.1: fixed header; ignore for now.
    }
    serial::log_line_args(format_args!(
        "goes: superblock ok (ver={}, flags=0x{:x})",
        sb.version, sb.flags
    ));
    Some(GOES_SB.call_once(|| sb))
}

pub fn checkpoint() -> Option<&'static GoesCheckpointV01> {
    if let Some(existing) = GOES_CHECKPOINT.get() {
        return Some(existing);
    }
    let sb = probe()?;
    if sb.checkpoint_offset == 0 {
        return None;
    }
    let mut buf = [0u8; GOES_CHECKPOINT_BLOCK_SIZE];
    if virtio::blk::read_at_res(sb.checkpoint_offset, &mut buf).is_err() {
        serial::log_line("goes: read checkpoint failed");
        return None;
    }
    let Some(chk) = parse_checkpoint(&buf) else {
        serial::log_line("goes: checkpoint parse failed");
        return None;
    };
    serial::log_line_args(format_args!(
        "goes: checkpoint ok (seq={}, bootmanifest_off={:#x})",
        chk.seq, chk.boot_manifest_offset
    ));
    Some(GOES_CHECKPOINT.call_once(|| chk))
}

pub fn boot_manifest() -> Option<&'static GoesBootManifestV01> {
    if let Some(existing) = GOES_BOOT_MANIFEST.get() {
        return Some(existing);
    }
    let chk = checkpoint()?;
    if chk.boot_manifest_offset == 0 {
        return None;
    }
    let mut buf = [0u8; GOES_BOOT_MANIFEST_BLOCK_SIZE];
    if virtio::blk::read_at_res(chk.boot_manifest_offset, &mut buf).is_err() {
        serial::log_line("goes: read bootmanifest failed");
        return None;
    }
    let Some(bm) = parse_boot_manifest(&buf) else {
        serial::log_line("goes: bootmanifest parse failed");
        return None;
    };
    serial::log_line_args(format_args!(
        "goes: bootmanifest ok (seq={}, active_set={}/{})",
        bm.seq, bm.active_set, bm.set_count
    ));
    Some(GOES_BOOT_MANIFEST.call_once(|| bm))
}

pub fn manifest() -> Option<&'static GoesManifestV01> {
    if let Some(existing) = GOES_MANIFEST.get() {
        return Some(existing);
    }
    let sb = probe()?;
    if sb.manifest_offset == 0 {
        return None;
    }
    let mut buf = [0u8; GOES_MANIFEST_BLOCK_SIZE];
    if virtio::blk::read_at_res(sb.manifest_offset, &mut buf).is_err() {
        serial::log_line("goes: read manifest failed");
        return None;
    }
    let Some(m) = parse_manifest(&buf) else {
        serial::log_line("goes: manifest parse failed");
        return None;
    };
    serial::log_line_args(format_args!(
        "goes: manifest ok (flags=0x{:x}, ws_count={})",
        m.flags, m.workspace_count
    ));
    Some(GOES_MANIFEST.call_once(|| m))
}

pub fn workspace_name_at(idx: u32, out: &mut [u8; GOES_MANIFEST_ENTRY_NAME_LEN]) -> Option<()> {
    let sb = probe()?;
    let m = manifest()?;
    if idx >= m.workspace_count {
        return None;
    }
    let base = m.workspace_entries_offset as u64 + (idx as u64) * (GOES_MANIFEST_ENTRY_SIZE as u64);
    let entry_off = sb.manifest_offset + base;
    if virtio::blk::read_at_res(entry_off, out).is_err() {
        return None;
    }
    Some(())
}
