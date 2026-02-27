#![cfg_attr(target_os = "uefi", no_std)]
#![cfg_attr(target_os = "uefi", no_main)]

#[cfg(not(target_os = "uefi"))]
fn main() {}

extern crate alloc;

mod elf;

use alloc::vec;
use alloc::vec::Vec;
use core::mem;
use core::ptr;
use oneos_boot_proto::crc32::crc32_ieee_with_zeroed_range;
use oneos_boot_proto::{
    BootInfo, FrameBufferFormat, FrameBufferInfo, MemoryRegion, MemoryRegionType, MemoryRegions,
};
use uefi::boot::{MemoryType, PAGE_SIZE};
use uefi::cstr16;
use uefi::data_types::CStr16;
use uefi::mem::memory_map::{MemoryMap, MemoryType as UefiMemoryType};
use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::device_path::{hardware, DevicePath};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::block::BlockIO;
use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode, FileType};
use uefi::proto::media::fs::SimpleFileSystem;

#[entry]
fn efi_main() -> Status {
    if let Err(e) = uefi::helpers::init() {
        log_err(format_args!("bootloader init failed: {:?}\r\n", e));
        return Status::ABORTED;
    }

    log_info(format_args!("oneOS bootloader start ({})\r\n", arch_name()));

    match load_and_start_kernel() {
        Ok(_) => Status::SUCCESS,
        Err(e) => {
            log_err(format_args!(
                "bootloader: failed to start kernel: {:?}\r\n",
                e
            ));
            Status::ABORTED
        }
    }
}

fn load_and_start_kernel() -> uefi::Result<()> {
    let handle = uefi::boot::image_handle();
    log_info(format_args!("bootloader: image_handle = {:?}\r\n", handle));

    let loaded = uefi::boot::open_protocol_exclusive::<LoadedImage>(handle)?;
    log_info(format_args!("bootloader: LoadedImage protocol opened\r\n"));

    let device = loaded.device().ok_or(uefi::Status::NOT_FOUND)?;
    log_info(format_args!("bootloader: device handle = {:?}\r\n", device));

    let mut fs = uefi::boot::open_protocol_exclusive::<SimpleFileSystem>(device)?;
    log_info(format_args!(
        "bootloader: SimpleFileSystem opened for device\r\n"
    ));

    let mut root = fs.open_volume()?;

    // Recovery 判定（v0.x：基于 ESP 上的 BootFlag/BootState 文件；可通过 xtask 写入模拟）。
    let (recovery, sip_override, mmu_strict) = match decide_recovery_mode(&mut root) {
        Ok(v) => v,
        Err(e) => {
            log_err(format_args!(
                "bootloader: recovery state read failed: {:?}\r\n",
                e.status()
            ));
            (false, None, true)
        }
    };

    let mut boot_info = build_boot_info();
    boot_info.set_recovery_mode(recovery);
    boot_info.set_mmu_strict(mmu_strict);
    log_info(format_args!(
        "bootloader: framebuffer {}x{} stride {} format {:?}\r\n",
        boot_info.framebuffer().map(|f| f.width).unwrap_or(0),
        boot_info.framebuffer().map(|f| f.height).unwrap_or(0),
        boot_info.framebuffer().map(|f| f.stride).unwrap_or(0),
        boot_info
            .framebuffer()
            .map(|f| f.format)
            .unwrap_or(FrameBufferFormat::Unknown)
    ));

    let boot_info_ptr = stage_boot_info(&boot_info)?;
    log_info(format_args!(
        "bootloader: boot info staged at {:#x}\r\n",
        boot_info_ptr as usize
    ));

    if try_boot_goes_kernel(boot_info_ptr, recovery, sip_override)? {
        return Ok(());
    }

    if try_boot_raw_kernel(&mut root, boot_info_ptr)? {
        return Ok(());
    }

    // Fallback to UEFI kernel image
    let kernel_bytes = read_file(&mut root, kernel_path())?;
    log_info(format_args!(
        "bootloader: kernel file read into buffer, invoking load_image\r\n"
    ));

    let image = uefi::boot::load_image(
        handle,
        uefi::boot::LoadImageSource::FromBuffer {
            buffer: &kernel_bytes,
            file_path: None,
        },
    )?;
    log_info(format_args!(
        "bootloader: load_image() returned handle {:?}\r\n",
        image
    ));

    attach_boot_info(image, boot_info_ptr as *const u8)?;
    uefi::boot::start_image(image)?;
    Ok(())
}

const ONEBOOT_BOOTFLAG_PATH: &CStr16 = cstr16!("\\EFI\\ONEOS\\BOOTFLAG.BIN");
const ONEBOOT_BOOTSTAT_PATH: &CStr16 = cstr16!("\\EFI\\ONEOS\\BOOTSTAT.BIN");
const ONEBOOT_SIP_PATH: &CStr16 = cstr16!("\\EFI\\ONEOS\\SIP.BIN");

const ONEBOOT_BOOTFLAG_MAGIC: &[u8; 4] = b"OBFL";
const ONEBOOT_BOOTSTAT_MAGIC: &[u8; 4] = b"OBST";
const ONEBOOT_SIP_MAGIC: &[u8; 4] = b"OSIP";

fn decide_recovery_mode(root: &mut Directory) -> uefi::Result<(bool, Option<bool>, bool)> {
    let mut force_recovery = false;
    let mut mark_success = false;
    let mut mmu_strict = true;
    let mut bootflag = [0u8; 512];
    if read_fixed_512(root, ONEBOOT_BOOTFLAG_PATH, &mut bootflag).is_ok() {
        if parse_bootflag(
            &bootflag,
            &mut force_recovery,
            &mut mark_success,
            &mut mmu_strict,
        ) {
            log_info(format_args!(
                "bootloader: bootflag (force_recovery={}, mark_success={}, mmu_strict={})\r\n",
                force_recovery, mark_success, mmu_strict
            ));
        }
    }

    let mut failures = 0u32;
    let mut last_boot_id = 0u64;
    let mut last_panic_code = 0u32;
    let mut ring_head = 0u32;
    let mut bootstat = [0u8; 512];
    if read_fixed_512(root, ONEBOOT_BOOTSTAT_PATH, &mut bootstat).is_ok() {
        if parse_bootstat(
            &bootstat,
            &mut failures,
            &mut last_boot_id,
            &mut last_panic_code,
            &mut ring_head,
        ) {
            log_info(format_args!(
                "bootloader: bootstate (failures={}, last_boot_id={}, last_panic=0x{:x}, ring_head={})\r\n",
                failures, last_boot_id, last_panic_code, ring_head
            ));
        }
    }

    // One-shot: MARK_SUCCESS clears failure counter (useful for manual recovery exit).
    if mark_success {
        failures = 0;
        write_bootstat(
            &mut bootstat,
            failures,
            last_boot_id,
            last_panic_code,
            ring_head,
        );
        let _ = write_fixed_512(root, ONEBOOT_BOOTSTAT_PATH, &bootstat);
        // Clear mark_success flag.
        write_bootflag(&mut bootflag, force_recovery, false, mmu_strict);
        let _ = write_fixed_512(root, ONEBOOT_BOOTFLAG_PATH, &bootflag);
        mark_success = false;
    }

    // Increment boot_id for observability (v0.x).
    let boot_id = last_boot_id.wrapping_add(1);
    write_bootstat(&mut bootstat, failures, boot_id, last_panic_code, ring_head);
    let _ = write_fixed_512(root, ONEBOOT_BOOTSTAT_PATH, &bootstat);

    // One-shot: ForceRecovery flag is consumed by oneboot.
    if force_recovery {
        write_bootflag(&mut bootflag, false, mark_success, mmu_strict);
        let _ = write_fixed_512(root, ONEBOOT_BOOTFLAG_PATH, &bootflag);
    }

    let recovery = force_recovery || failures >= 3;
    let sip_override = read_sip_override(root);
    if recovery {
        log_info(format_args!("bootloader: entering recovery mode\r\n"));
    }
    Ok((recovery, sip_override, mmu_strict))
}

fn read_sip_override(root: &mut Directory) -> Option<bool> {
    let mut buf = [0u8; 512];
    if read_fixed_512(root, ONEBOOT_SIP_PATH, &mut buf).is_err() {
        return None;
    }
    parse_sip(&buf)
}

fn parse_sip(buf: &[u8; 512]) -> Option<bool> {
    if &buf[0..4] != ONEBOOT_SIP_MAGIC {
        return None;
    }
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap_or([0; 4]));
    if version != 1 {
        return None;
    }
    let stored_crc = u32::from_le_bytes(buf[12..16].try_into().unwrap_or([0; 4]));
    if stored_crc != 0 {
        let calc = crc32_ieee_with_zeroed_range(buf, 12, 4);
        if calc != stored_crc {
            return None;
        }
    }
    let sip_on = u32::from_le_bytes(buf[8..12].try_into().unwrap_or([0; 4])) != 0;
    Some(sip_on)
}

fn read_fixed_512(root: &mut Directory, path: &CStr16, out: &mut [u8; 512]) -> uefi::Result<()> {
    let handle = root.open(path, FileMode::Read, FileAttribute::empty())?;
    let mut file = match handle.into_type()? {
        FileType::Regular(f) => f,
        FileType::Dir(_) => return Err(uefi::Status::UNSUPPORTED.into()),
    };
    let mut tmp = [0u8; 512];
    let n = file.read(&mut tmp)?;
    if n != 512 {
        // Accept shorter files as zero-padded.
        out.fill(0);
        out[..n].copy_from_slice(&tmp[..n]);
    } else {
        *out = tmp;
    }
    Ok(())
}

fn write_fixed_512(root: &mut Directory, path: &CStr16, data: &[u8; 512]) -> uefi::Result<()> {
    let handle = root.open(path, FileMode::CreateReadWrite, FileAttribute::empty())?;
    let mut file = match handle.into_type()? {
        FileType::Regular(f) => f,
        FileType::Dir(_) => return Err(uefi::Status::UNSUPPORTED.into()),
    };
    file.set_position(0)?;
    let _ = file.write(data).map_err(|e| e.status())?;
    Ok(())
}

fn parse_bootflag(
    buf: &[u8; 512],
    force: &mut bool,
    mark_success: &mut bool,
    mmu_strict: &mut bool,
) -> bool {
    if &buf[0..4] != ONEBOOT_BOOTFLAG_MAGIC {
        return false;
    }
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap_or([0; 4]));
    if version != 1 {
        return false;
    }
    let stored_crc = u32::from_le_bytes(buf[16..20].try_into().unwrap_or([0; 4]));
    if stored_crc != 0 {
        let calc = crc32_ieee_with_zeroed_range(buf, 16, 4);
        if calc != stored_crc {
            return false;
        }
    }
    let flags = u32::from_le_bytes(buf[8..12].try_into().unwrap_or([0; 4]));
    *force = (flags & 0b1) != 0;
    *mark_success = (flags & 0b10) != 0;
    // bit2: mmu_strict_off (default strict on)
    *mmu_strict = (flags & 0b100) == 0;
    true
}

fn write_bootflag(buf: &mut [u8; 512], force: bool, mark_success: bool, mmu_strict: bool) {
    buf.fill(0);
    buf[0..4].copy_from_slice(ONEBOOT_BOOTFLAG_MAGIC);
    buf[4..8].copy_from_slice(&1u32.to_le_bytes());
    let mut flags = 0u32;
    if force {
        flags |= 0b1;
    }
    if mark_success {
        flags |= 0b10;
    }
    if !mmu_strict {
        flags |= 0b100;
    }
    buf[8..12].copy_from_slice(&flags.to_le_bytes());
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());
    buf[16..20].copy_from_slice(&0u32.to_le_bytes());
    let crc = crc32_ieee_with_zeroed_range(buf, 16, 4);
    buf[16..20].copy_from_slice(&crc.to_le_bytes());
}

fn parse_bootstat(
    buf: &[u8; 512],
    failures: &mut u32,
    last_boot_id: &mut u64,
    last_panic: &mut u32,
    ring_head: &mut u32,
) -> bool {
    if &buf[0..4] != ONEBOOT_BOOTSTAT_MAGIC {
        return false;
    }
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap_or([0; 4]));
    if version != 1 {
        return false;
    }
    let stored_crc = u32::from_le_bytes(buf[32..36].try_into().unwrap_or([0; 4]));
    if stored_crc != 0 {
        let calc = crc32_ieee_with_zeroed_range(buf, 32, 4);
        if calc != stored_crc {
            return false;
        }
    }
    *failures = u32::from_le_bytes(buf[8..12].try_into().unwrap_or([0; 4]));
    *last_boot_id = u64::from_le_bytes(buf[16..24].try_into().unwrap_or([0; 8]));
    *last_panic = u32::from_le_bytes(buf[24..28].try_into().unwrap_or([0; 4]));
    *ring_head = u32::from_le_bytes(buf[28..32].try_into().unwrap_or([0; 4]));
    true
}

fn write_bootstat(
    buf: &mut [u8; 512],
    failures: u32,
    last_boot_id: u64,
    last_panic: u32,
    ring_head: u32,
) {
    buf.fill(0);
    buf[0..4].copy_from_slice(ONEBOOT_BOOTSTAT_MAGIC);
    buf[4..8].copy_from_slice(&1u32.to_le_bytes());
    buf[8..12].copy_from_slice(&failures.to_le_bytes());
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());
    buf[16..24].copy_from_slice(&last_boot_id.to_le_bytes());
    buf[24..28].copy_from_slice(&last_panic.to_le_bytes());
    buf[28..32].copy_from_slice(&ring_head.to_le_bytes());
    buf[32..36].copy_from_slice(&0u32.to_le_bytes());
    let crc = crc32_ieee_with_zeroed_range(buf, 32, 4);
    buf[32..36].copy_from_slice(&crc.to_le_bytes());
}

const GOES_SB_HEADER_SIZE_V01: usize = 256;
const GOES_MANIFEST_BLOCK_SIZE: usize = 4096;
const GOES_MANIFEST_MAGIC_V01: &[u8; 4] = b"OGMF";
const GOES_CHECKPOINT_BLOCK_SIZE: usize = 4096;
const GOES_CHECKPOINT_MAGIC_V01: &[u8; 4] = b"GOCP";
const GOES_BOOT_MANIFEST_BLOCK_SIZE: usize = 4096;
const GOES_BOOT_MANIFEST_MAGIC_V01: &[u8; 4] = b"GOBM";
const GOES_FLAG_ADMIN: u32 = 1 << 0;
const GOES_FLAG_SIP_ON: u32 = 1 << 1;

#[derive(Clone, Copy)]
struct GoesSuperblockV01 {
    version: u32,
    header_size: u32,
    block_size: u32,
    flags: u32,
    checkpoint_offset: u64,
    manifest_offset: u64,
    record_log_offset: u64,
    record_log_len: u64,
    kernel_x86_offset: u64,
    kernel_x86_len: u64,
    kernel_aa_offset: u64,
    kernel_aa_len: u64,
    default_user: [u8; 32],
}

#[derive(Clone, Copy)]
struct GoesManifestV01 {
    flags: u32,
    default_user: [u8; 32],
    kernel_x86_offset: u64,
    kernel_x86_len: u64,
    kernel_aa_offset: u64,
    kernel_aa_len: u64,
}

#[derive(Clone, Copy)]
struct GoesCheckpointV01 {
    seq: u64,
    boot_manifest_offset: u64,
}

#[derive(Clone, Copy)]
struct GoesBootManifestV01 {
    flags: u32,
    seq: u64,
    active_set: u32,
    set_count: u32,
    default_user: [u8; 32],
    set_entries_offset: u32,
    set_entry_size: u32,
}

fn get_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn get_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let bytes = buf.get(off..off + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn try_boot_goes_kernel(
    boot_info_ptr: *const BootInfo,
    recovery: bool,
    sip_override: Option<bool>,
) -> uefi::Result<bool> {
    let handles = match uefi::boot::find_handles::<BlockIO>() {
        Ok(h) => h,
        Err(_) => return Ok(false),
    };
    if handles.is_empty() {
        return Ok(false);
    }
    for handle in handles {
        let mut bio = match uefi::boot::open_protocol_exclusive::<BlockIO>(handle) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let media = bio.media();
        if !media.is_media_present() {
            continue;
        }
        let media_id = media.media_id();
        // Read first 4KiB (or up to 8 sectors) to probe for GOES magic.
        let block_size = media.block_size() as usize;
        let probe_len = 4096usize;
        let blocks = (probe_len + block_size - 1) / block_size;
        let mut buf = vec![0u8; blocks * block_size];
        if bio.read_blocks(media.media_id(), 0, &mut buf).is_err() {
            continue;
        }
        let sb = match parse_goes_superblock(&buf) {
            Some(s) => s,
            None => continue,
        };
        if sb.version != 1 {
            continue;
        }

        // Prefer Checkpoint->BootManifest (active_set). Fallback to manifest / superblock fields.
        let mut effective_flags = sb.flags;
        let mut effective_default_user = sb.default_user;
        let mut kernel_off = 0u64;
        let mut kernel_len = 0u64;

        if sb.checkpoint_offset != 0 {
            if let Ok(cbuf) =
                read_device_bytes(&mut bio, sb.checkpoint_offset, GOES_CHECKPOINT_BLOCK_SIZE)
            {
                if let Some(chk) = parse_goes_checkpoint(&cbuf) {
                    if chk.boot_manifest_offset != 0 {
                        if let Ok(bmbuf) = read_device_bytes(
                            &mut bio,
                            chk.boot_manifest_offset,
                            GOES_BOOT_MANIFEST_BLOCK_SIZE,
                        ) {
                            if let Some(bm) = parse_goes_boot_manifest(&bmbuf) {
                                effective_flags = bm.flags;
                                effective_default_user = bm.default_user;
                                let (off, len) = select_kernel_from_boot_manifest(&bmbuf, &bm);
                                if off != 0 && len != 0 {
                                    kernel_off = off;
                                    kernel_len = len;
                                    log_info(format_args!(
                                        "bootloader: GOES bootmanifest ok (set={}/{}, admin={}, sip={})\r\n",
                                        bm.active_set,
                                        bm.set_count,
                                        (bm.flags & GOES_FLAG_ADMIN) != 0,
                                        if (bm.flags & GOES_FLAG_SIP_ON) != 0 {
                                            "on"
                                        } else {
                                            "off"
                                        }
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        if kernel_off == 0 || kernel_len == 0 {
            // Try to parse structured manifest (v0.1).
            if sb.manifest_offset != 0 {
                if let Ok(mbuf) =
                    read_device_bytes(&mut bio, sb.manifest_offset, GOES_MANIFEST_BLOCK_SIZE)
                {
                    if let Some(m) = parse_goes_manifest(&mbuf) {
                        effective_flags = m.flags;
                        effective_default_user = m.default_user;
                        let (off, len) = select_kernel_from_manifest(&m);
                        if off != 0 && len != 0 {
                            kernel_off = off;
                            kernel_len = len;
                            log_info(format_args!(
                                "bootloader: GOES manifest ok (admin={}, sip={})\r\n",
                                (m.flags & GOES_FLAG_ADMIN) != 0,
                                if (m.flags & GOES_FLAG_SIP_ON) != 0 {
                                    "on"
                                } else {
                                    "off"
                                }
                            ));
                        }
                    }
                }
            }
        }

        if kernel_off == 0 || kernel_len == 0 {
            let (off, len) = select_kernel(&sb);
            kernel_off = off;
            kernel_len = len;
        }

        // SIP state is stored in the fixed GOES BootManifest/Manifest flags (no record-log scan).
        // Optional legacy override from ESP SIP.BIN (one-shot).
        let sip_override_effective = sip_override;
        log_info(format_args!(
            "bootloader: GOES detected on {:?} (block_size={}, admin={}, sip={})\r\n",
            handle,
            block_size,
            (effective_flags & GOES_FLAG_ADMIN) != 0,
            if (effective_flags & GOES_FLAG_SIP_ON) != 0 {
                "on"
            } else {
                "off"
            }
        ));
        if let Some(sip_on) = sip_override_effective {
            if sip_on {
                effective_flags |= GOES_FLAG_SIP_ON;
            } else {
                effective_flags &= !GOES_FLAG_SIP_ON;
            }
            log_info(format_args!(
                "bootloader: sip override applied from ESP\r\n",
            ));
        }

        unsafe {
            // 把 GOES 状态（默认用户等）传给内核，用于 shell 上下文等。
            let info = &mut *(boot_info_ptr as *const BootInfo as *mut BootInfo);
            info.set_goes(effective_flags, &effective_default_user);
            // v1(raw 内核)：device_id 使用 PCI BDF（bus<<16|dev<<8|func），用于内核侧精确绑定 GOES virtio-blk 设备。
            // 若无法解析 PCI 信息，则写入 0（内核会回退到扫描第一个 virtio-blk 设备）。
            let goes_dev_id = if let Some((bus, dev, fun)) = device_pci_bdf(handle) {
                let id = BootInfo::pci_bdf(bus, dev, fun);
                log_info(format_args!(
                    "bootloader: GOES device pci bdf={} {}.{}\r\n",
                    bus, dev, fun
                ));
                id
            } else {
                log_info(format_args!(
                    "bootloader: GOES device pci bdf unavailable, fallback to id=0 (media_id={})\r\n",
                    media_id
                ));
                0
            };
            // superblock 位于 LBA0；System ws id 先占位为 1。
            info.set_goes_location(goes_dev_id, 0, 1);
            // v0.x：Recovery 判定来自 ESP（BootFlag/BootState），这里直接透传。
            info.set_recovery_mode(recovery);
        }

        if kernel_off == 0 || kernel_len == 0 {
            log_err(format_args!("bootloader: GOES kernel missing\r\n"));
            continue;
        }
        log_info(format_args!(
            "bootloader: GOES kernel offset={:#x} len={:#x}\r\n",
            kernel_off, kernel_len
        ));
        let kernel_bytes = match read_device_bytes(&mut bio, kernel_off, kernel_len as usize) {
            Ok(v) => v,
            Err(e) => {
                log_err(format_args!(
                    "bootloader: GOES read failed: {:?}\r\n",
                    e.status()
                ));
                continue;
            }
        };
        let elf_image = match elf::ElfImage::parse(&kernel_bytes) {
            Ok(img) => img,
            Err(status) => {
                log_err(format_args!(
                    "bootloader: GOES ELF parse failed: {:?}\r\n",
                    status
                ));
                continue;
            }
        };
        log_info(format_args!(
            "bootloader: GOES ELF entry {:#x}, {} segments\r\n",
            elf_image.entry,
            elf_image.segments.len()
        ));
        if let Some((base, size)) = elf::debug_load_range(&elf_image) {
            log_info(format_args!(
                "bootloader: GOES ELF load range base={:#x} size={:#x}\r\n",
                base, size
            ));
        }
        if let Err(err) = elf::load_segments(&elf_image, &kernel_bytes) {
            log_err(format_args!(
                "bootloader: GOES load_segments failed status={:?} addr={:#x}\r\n",
                err.status, err.physical_addr
            ));
            continue;
        }
        log_info(format_args!(
            "bootloader: GOES kernel loaded, jumping to entry {:#x}\r\n",
            elf_image.entry
        ));
        unsafe {
            boot_raw_kernel(boot_info_ptr, elf_image.entry);
        }
    }
    Ok(false)
}

fn parse_goes_manifest(buf: &[u8]) -> Option<GoesManifestV01> {
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
    // Optional crc32 at 0x60 (over full 4K with this field zeroed).
    if buf.len() >= GOES_MANIFEST_BLOCK_SIZE {
        let stored_crc = get_u32_le(buf, 0x60).unwrap_or(0);
        if stored_crc != 0 {
            let calc = crc32_ieee_with_zeroed_range(&buf[..GOES_MANIFEST_BLOCK_SIZE], 0x60, 4);
            if calc != stored_crc {
                return None;
            }
        }
    }
    let flags = get_u32_le(buf, 0x08)?;
    let mut default_user = [0u8; 32];
    default_user.copy_from_slice(buf.get(0x10..0x10 + 32)?);
    let kernel_x86_offset = get_u64_le(buf, 0x40)?;
    let kernel_x86_len = get_u64_le(buf, 0x48)?;
    let kernel_aa_offset = get_u64_le(buf, 0x50)?;
    let kernel_aa_len = get_u64_le(buf, 0x58)?;
    Some(GoesManifestV01 {
        flags,
        default_user,
        kernel_x86_offset,
        kernel_x86_len,
        kernel_aa_offset,
        kernel_aa_len,
    })
}

fn device_pci_bdf(handle: Handle) -> Option<(u8, u8, u8)> {
    let dp = uefi::boot::open_protocol_exclusive::<DevicePath>(handle).ok()?;
    let mut last: Option<(u8, u8, u8)> = None;
    for node in dp.node_iter() {
        if let Ok(pci) = <&hardware::Pci>::try_from(node) {
            // v1：QEMU/virt 先假设单 bus=0。真实多 bus 需要从更完整的路径/协议获得 bus。
            last = Some((0, pci.device(), pci.function()));
        }
    }
    last
}

fn parse_goes_checkpoint(buf: &[u8]) -> Option<GoesCheckpointV01> {
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

fn parse_goes_boot_manifest(buf: &[u8]) -> Option<GoesBootManifestV01> {
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

fn select_kernel_from_boot_manifest(buf: &[u8], bm: &GoesBootManifestV01) -> (u64, u64) {
    let entry_size = bm.set_entry_size as usize;
    if entry_size == 0 {
        return (0, 0);
    }
    if bm.active_set >= bm.set_count {
        return (0, 0);
    }
    let base = bm.set_entries_offset as usize + (bm.active_set as usize) * entry_size;
    // entry:
    // 0x08: kernel_x86_offset
    // 0x10: kernel_x86_len
    // 0x18: kernel_aa_offset
    // 0x20: kernel_aa_len
    #[cfg(target_arch = "x86_64")]
    {
        let off = get_u64_le(buf, base + 0x08).unwrap_or(0);
        let len = get_u64_le(buf, base + 0x10).unwrap_or(0);
        (off, len)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let off = get_u64_le(buf, base + 0x18).unwrap_or(0);
        let len = get_u64_le(buf, base + 0x20).unwrap_or(0);
        (off, len)
    }
}

fn select_kernel_from_manifest(m: &GoesManifestV01) -> (u64, u64) {
    #[cfg(target_arch = "x86_64")]
    {
        (m.kernel_x86_offset, m.kernel_x86_len)
    }
    #[cfg(target_arch = "aarch64")]
    {
        (m.kernel_aa_offset, m.kernel_aa_len)
    }
}

fn parse_goes_superblock(buf: &[u8]) -> Option<GoesSuperblockV01> {
    if buf.len() < GOES_SB_HEADER_SIZE_V01 {
        return None;
    }
    if &buf[0..4] != b"GOES" {
        return None;
    }
    let stored_crc = get_u32_le(buf, 0x68).unwrap_or(0);
    if stored_crc != 0 {
        let calc = crc32_ieee_with_zeroed_range(&buf[..GOES_SB_HEADER_SIZE_V01], 0x68, 4);
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

const GORE_MAGIC: &[u8; 4] = b"GORE";
const GORE_HEADER_SIZE: usize = 32;
const GORE_ALIGN: u64 = 8;
const RECORD_SIP_OVERRIDE_V1: u32 = 0x1_0301;

#[derive(Clone, Copy, Debug)]
struct GoreHeader {
    record_type: u32,
    payload_len: u32,
    seq: u64,
    crc32: u32,
}

fn align_up_u64(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

fn parse_gore_header(buf: &[u8; GORE_HEADER_SIZE]) -> Option<GoreHeader> {
    if &buf[0..4] != GORE_MAGIC {
        return None;
    }
    let version = u16::from_le_bytes(buf[4..6].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let record_type = u32::from_le_bytes(buf[8..12].try_into().ok()?);
    let payload_len = u32::from_le_bytes(buf[12..16].try_into().ok()?);
    let seq = u64::from_le_bytes(buf[16..24].try_into().ok()?);
    let crc32 = u32::from_le_bytes(buf[24..28].try_into().ok()?);
    Some(GoreHeader {
        record_type,
        payload_len,
        seq,
        crc32,
    })
}

mod crc32_stream {
    // IEEE CRC32 (polynomial 0xEDB88320), little-endian, init=0xFFFF_FFFF, xorout=0xFFFF_FFFF.
    const fn make_table() -> [u32; 256] {
        let mut table = [0u32; 256];
        let mut i = 0usize;
        while i < 256 {
            let mut crc = i as u32;
            let mut j = 0usize;
            while j < 8 {
                if (crc & 1) != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
                j += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    }

    const TABLE: [u32; 256] = make_table();

    pub fn init() -> u32 {
        0xFFFF_FFFF
    }

    pub fn update(mut crc: u32, bytes: &[u8]) -> u32 {
        for &b in bytes {
            let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
            crc = (crc >> 8) ^ TABLE[idx];
        }
        crc
    }

    pub fn finalize(crc: u32) -> u32 {
        !crc
    }
}

fn compute_gore_crc32(bio: &mut BlockIO, record_off: u64, payload_len: u32) -> uefi::Result<u32> {
    // Performance note:
    // - UEFI BlockIO reads are relatively expensive.
    // - Avoid 512B-per-read loops and avoid allocating a fresh Vec per read.
    // - Read in bigger chunks and reuse a scratch buffer.
    const PAYLOAD_CHUNK: usize = 64 * 1024;

    if payload_len as u64 >= (1 << 20) {
        let iters =
            ((payload_len as u64 + (PAYLOAD_CHUNK as u64 - 1)) / (PAYLOAD_CHUNK as u64)) as u64;
        log_info(format_args!(
            "bootloader: crc32 scan begin (off={:#x}, payload_len={:#x}, chunk={:#x}, iters~{})\r\n",
            record_off, payload_len, PAYLOAD_CHUNK, iters
        ));
    }

    let mut scratch: Vec<u8> = Vec::new();
    let mut hdr = [0u8; GORE_HEADER_SIZE];
    let hb = read_device_bytes_reuse(bio, record_off, GORE_HEADER_SIZE, &mut scratch)?;
    hdr.copy_from_slice(hb);
    hdr[24..28].fill(0);

    let mut crc = crc32_stream::init();
    crc = crc32_stream::update(crc, &hdr);
    let mut remaining = payload_len as usize;
    let mut off = 0usize;
    while remaining > 0 {
        let take = core::cmp::min(remaining, PAYLOAD_CHUNK);
        let chunk = read_device_bytes_reuse(
            bio,
            record_off + GORE_HEADER_SIZE as u64 + off as u64,
            take,
            &mut scratch,
        )?;
        crc = crc32_stream::update(crc, chunk);
        remaining -= take;
        off += take;
    }
    let out = crc32_stream::finalize(crc);
    if payload_len as u64 >= (1 << 20) {
        log_info(format_args!(
            "bootloader: crc32 scan end (off={:#x}, payload_len={:#x}, crc={:#x})\r\n",
            record_off, payload_len, out
        ));
    }
    Ok(out)
}

fn read_sip_override_from_record_log(
    bio: &mut BlockIO,
    sb: &GoesSuperblockV01,
) -> uefi::Result<Option<bool>> {
    if sb.record_log_offset == 0 || sb.record_log_len == 0 {
        return Ok(None);
    }
    let base = sb.record_log_offset;
    let len = sb.record_log_len;
    let mut off = 0u64;
    let mut last: Option<(u64, bool)> = None;
    let mut scratch: Vec<u8> = Vec::new();
    log_info(format_args!(
        "bootloader: sip override scan begin (record_log_off={:#x}, len={:#x})\r\n",
        base, len
    ));

    while off + (GORE_HEADER_SIZE as u64) <= len {
        let hb = match read_device_bytes_reuse(bio, base + off, GORE_HEADER_SIZE, &mut scratch) {
            Ok(v) => v,
            Err(_) => break,
        };
        let mut hdr_bytes = [0u8; GORE_HEADER_SIZE];
        hdr_bytes.copy_from_slice(hb);
        let Some(h) = parse_gore_header(&hdr_bytes) else {
            break;
        };
        let total = align_up_u64(GORE_HEADER_SIZE as u64 + h.payload_len as u64, GORE_ALIGN);
        if off + total > len {
            break;
        }

        // Performance: only validate (CRC) and parse the one record we care about.
        if h.record_type == RECORD_SIP_OVERRIDE_V1 && h.payload_len as usize >= 8 {
            let crc = compute_gore_crc32(bio, base + off, h.payload_len)?;
            if crc != h.crc32 {
                break;
            }
            let p = read_device_bytes_reuse(
                bio,
                base + off + GORE_HEADER_SIZE as u64,
                16.min(h.payload_len as usize),
                &mut scratch,
            )?;
            if p.len() >= 8 {
                let ver = u32::from_le_bytes(p[0..4].try_into().unwrap_or([0; 4]));
                if ver == 1 {
                    let sip_on = u32::from_le_bytes(p[4..8].try_into().unwrap_or([0; 4])) != 0;
                    last = Some((h.seq, sip_on));
                    log_info(format_args!(
                        "bootloader: sip override record seen (seq={}, sip={})\r\n",
                        h.seq,
                        if sip_on { "on" } else { "off" }
                    ));
                }
            }
        }

        off = off.saturating_add(total);
    }

    if let Some((seq, sip_on)) = last {
        log_info(format_args!(
            "bootloader: sip override from record log (seq={}, sip={})\r\n",
            seq,
            if sip_on { "on" } else { "off" }
        ));
        return Ok(Some(sip_on));
    }
    log_info(format_args!(
        "bootloader: sip override scan end (found=false)\r\n"
    ));
    Ok(None)
}

fn select_kernel(sb: &GoesSuperblockV01) -> (u64, u64) {
    #[cfg(target_arch = "x86_64")]
    {
        (sb.kernel_x86_offset, sb.kernel_x86_len)
    }
    #[cfg(target_arch = "aarch64")]
    {
        (sb.kernel_aa_offset, sb.kernel_aa_len)
    }
}

fn read_device_bytes(bio: &mut BlockIO, offset: u64, len: usize) -> uefi::Result<Vec<u8>> {
    let media = bio.media();
    let block_size = media.block_size() as u64;
    let start_lba = offset / block_size;
    let start_off = (offset % block_size) as usize;
    let total = start_off + len;
    let blocks = (total as u64 + block_size - 1) / block_size;
    let mut tmp = vec![0u8; (blocks * block_size) as usize];
    bio.read_blocks(media.media_id(), start_lba, &mut tmp)?;
    Ok(tmp[start_off..start_off + len].to_vec())
}

fn read_device_bytes_reuse<'a>(
    bio: &mut BlockIO,
    offset: u64,
    len: usize,
    scratch: &'a mut Vec<u8>,
) -> uefi::Result<&'a [u8]> {
    let media = bio.media();
    let block_size = media.block_size() as u64;
    let start_lba = offset / block_size;
    let start_off = (offset % block_size) as usize;
    let total = start_off + len;
    let blocks = (total as u64 + block_size - 1) / block_size;
    let need = (blocks * block_size) as usize;

    if scratch.len() < need {
        scratch.resize(need, 0);
    }
    bio.read_blocks(media.media_id(), start_lba, &mut scratch[..need])?;
    Ok(&scratch[start_off..start_off + len])
}

fn kernel_path() -> &'static uefi::data_types::CStr16 {
    #[cfg(target_arch = "x86_64")]
    {
        cstr16!("\\EFI\\oneOS\\KERNELX64.EFI")
    }
    #[cfg(target_arch = "aarch64")]
    {
        cstr16!("\\EFI\\oneOS\\KERNELAA64.EFI")
    }
}

fn raw_kernel_path() -> &'static uefi::data_types::CStr16 {
    #[cfg(target_arch = "x86_64")]
    {
        cstr16!("\\EFI\\oneOS\\KERNELX64.BIN")
    }
    #[cfg(target_arch = "aarch64")]
    {
        cstr16!("\\EFI\\oneOS\\KERNELAA64.BIN")
    }
}

fn arch_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64"
    }
}

struct ArrayString<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> ArrayString<N> {
    const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl<const N: usize> core::fmt::Write for ArrayString<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > N {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

fn log_err(args: core::fmt::Arguments) {
    let mut buf = ArrayString::<256>::new();
    let _ = core::fmt::write(&mut buf, args);
    print_err(buf.as_str());
    print_out(buf.as_str());
}

fn log_info(args: core::fmt::Arguments) {
    let mut buf = ArrayString::<256>::new();
    let _ = core::fmt::write(&mut buf, args);
    print_out(buf.as_str());
}

fn build_boot_info() -> BootInfo {
    let framebuffer = query_framebuffer_info();
    let memory_regions = collect_memory_regions().unwrap_or_else(|_| MemoryRegions::empty());
    BootInfo::from_parts(framebuffer, memory_regions)
}

fn try_set_best_gop_mode(gop: &mut GraphicsOutput) {
    // 优先选择一个跨架构一致的 GOP mode（便于统一调试与截图），否则再退回到更高分辨率。
    // 仅接受 RGB/BGR 帧缓冲格式，避免 BLT-only 或未知格式。
    let current = gop.current_mode_info();
    let (cur_w, cur_h) = current.resolution();

    let preferred_res = (1024usize, 768usize);
    let mut preferred: Option<uefi::proto::console::gop::Mode> = None;

    let mut best: Option<uefi::proto::console::gop::Mode> = None;
    let mut best_area: usize = cur_w.saturating_mul(cur_h);

    for mode in gop.modes() {
        let info = mode.info();
        match info.pixel_format() {
            PixelFormat::Rgb | PixelFormat::Bgr => {}
            _ => continue,
        }

        let (w, h) = info.resolution();
        if (w, h) == preferred_res {
            preferred = Some(mode);
        }

        let area = w.saturating_mul(h);
        if area > best_area {
            best_area = area;
            best = Some(mode);
        }
    }

    let selected = preferred.or(best);
    let Some(best_mode) = selected else {
        return;
    };

    let (w, h) = best_mode.info().resolution();
    log_info(format_args!(
        "bootloader: GOP set_mode {}x{} -> {}x{}\r\n",
        cur_w, cur_h, w, h
    ));
    if let Err(e) = gop.set_mode(&best_mode) {
        log_err(format_args!("bootloader: GOP set_mode failed: {:?}\r\n", e));
    }
}

fn query_framebuffer_info() -> Option<FrameBufferInfo> {
    let handle = uefi::boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
    let mut gop = uefi::boot::open_protocol_exclusive::<GraphicsOutput>(handle).ok()?;
    try_set_best_gop_mode(&mut gop);
    let mode = gop.current_mode_info();
    let (width, height) = mode.resolution();
    let stride = mode.stride();
    let format = match mode.pixel_format() {
        PixelFormat::Rgb => FrameBufferFormat::Rgb,
        PixelFormat::Bgr => FrameBufferFormat::Bgr,
        _ => FrameBufferFormat::Unknown,
    };
    if format == FrameBufferFormat::Unknown {
        return None;
    }
    let mut fb = gop.frame_buffer();
    Some(FrameBufferInfo::new(
        fb.as_mut_ptr() as u64,
        fb.size() as u64,
        width as u32,
        height as u32,
        stride as u32,
        format,
    ))
}

fn stage_boot_info(info: &BootInfo) -> uefi::Result<*const BootInfo> {
    let size = mem::size_of::<BootInfo>();
    let ptr = uefi::boot::allocate_pool(MemoryType::LOADER_DATA, size)?;
    unsafe {
        ptr::copy_nonoverlapping(info as *const BootInfo as *const u8, ptr.as_ptr(), size);
    }
    Ok(ptr.as_ptr() as *const BootInfo)
}

fn attach_boot_info(image: Handle, boot_info_ptr: *const u8) -> uefi::Result<()> {
    let mut kernel_loaded = uefi::boot::open_protocol_exclusive::<LoadedImage>(image)?;
    let size = mem::size_of::<BootInfo>() as u32;
    unsafe {
        kernel_loaded.set_load_options(boot_info_ptr, size);
    }
    Ok(())
}

fn collect_memory_regions() -> uefi::Result<MemoryRegions> {
    let memory_map = uefi::boot::memory_map(MemoryType::LOADER_DATA)?;
    let entries = memory_map.entries();
    let count = entries.len();
    if count == 0 {
        return Ok(MemoryRegions::empty());
    }

    let bytes = count
        .checked_mul(mem::size_of::<MemoryRegion>())
        .ok_or(uefi::Status::OUT_OF_RESOURCES)?;
    let buffer = uefi::boot::allocate_pool(MemoryType::LOADER_DATA, bytes)?;
    for (idx, desc) in entries.enumerate() {
        let region = MemoryRegion {
            base: desc.phys_start,
            length: desc.page_count.saturating_mul(PAGE_SIZE as u64),
            region_type: convert_memory_type(desc.ty),
            attributes: desc.att.bits(),
        };
        unsafe {
            (buffer.as_ptr() as *mut MemoryRegion)
                .add(idx)
                .write(region);
        }
    }

    Ok(MemoryRegions::from_raw(
        buffer.as_ptr() as u64,
        count as u32,
    ))
}

fn convert_memory_type(ty: UefiMemoryType) -> MemoryRegionType {
    match ty {
        UefiMemoryType::RESERVED => MemoryRegionType::Reserved,
        UefiMemoryType::LOADER_CODE => MemoryRegionType::LoaderCode,
        UefiMemoryType::LOADER_DATA => MemoryRegionType::LoaderData,
        UefiMemoryType::BOOT_SERVICES_CODE => MemoryRegionType::BootServicesCode,
        UefiMemoryType::BOOT_SERVICES_DATA => MemoryRegionType::BootServicesData,
        UefiMemoryType::RUNTIME_SERVICES_CODE => MemoryRegionType::RuntimeServicesCode,
        UefiMemoryType::RUNTIME_SERVICES_DATA => MemoryRegionType::RuntimeServicesData,
        UefiMemoryType::CONVENTIONAL => MemoryRegionType::Conventional,
        UefiMemoryType::UNUSABLE => MemoryRegionType::Unusable,
        UefiMemoryType::ACPI_RECLAIM => MemoryRegionType::AcpiReclaim,
        UefiMemoryType::ACPI_NON_VOLATILE => MemoryRegionType::AcpiNvs,
        UefiMemoryType::MMIO => MemoryRegionType::Mmio,
        UefiMemoryType::MMIO_PORT_SPACE => MemoryRegionType::MmioPortSpace,
        UefiMemoryType::PAL_CODE => MemoryRegionType::PalCode,
        UefiMemoryType::PERSISTENT_MEMORY => MemoryRegionType::PersistentMemory,
        _ => MemoryRegionType::Unknown,
    }
}

fn read_file(root: &mut Directory, path: &CStr16) -> uefi::Result<Vec<u8>> {
    let handle = root.open(path, FileMode::Read, FileAttribute::empty())?;
    let mut file = match handle.into_type()? {
        FileType::Regular(file) => file,
        _ => return Err(Status::NOT_FOUND.into()),
    };
    let mut info_buf = [0u8; 512];
    let info = file
        .get_info::<FileInfo>(&mut info_buf)
        .map_err(|_| Status::BUFFER_TOO_SMALL)?;
    let size = info.file_size() as usize;
    if size == 0 {
        return Err(Status::LOAD_ERROR.into());
    }
    let mut buf = vec![0u8; size];
    file.read(&mut buf)?;
    Ok(buf)
}

fn try_boot_raw_kernel(root: &mut Directory, boot_info_ptr: *const BootInfo) -> uefi::Result<bool> {
    let raw_path = raw_kernel_path();
    match read_file(root, raw_path) {
        Ok(bytes) => {
            log_info(format_args!(
                "bootloader: raw kernel {} found ({} bytes)\r\n",
                raw_path,
                bytes.len()
            ));
            let elf_image = match elf::ElfImage::parse(&bytes) {
                Ok(img) => img,
                Err(status) => {
                    log_err(format_args!(
                        "bootloader: ELF parse failed: {:?}\r\n",
                        status
                    ));
                    return Ok(false);
                }
            };
            log_info(format_args!(
                "bootloader: ELF entry {:#x}, {} segments\r\n",
                elf_image.entry,
                elf_image.segments.len()
            ));
            for (idx, seg) in elf_image.segments.iter().enumerate() {
                log_info(format_args!(
                    "bootloader: segment #{idx} addr={:#x} mem={:#x} file={:#x}\r\n",
                    seg.physical_addr, seg.mem_size, seg.file_size
                ));
            }
            // Helpful for debugging UEFI allocation failures (alignment/overlap).
            if let Some((base, size)) = elf::debug_load_range(&elf_image) {
                log_info(format_args!(
                    "bootloader: ELF load range base={:#x} size={:#x}\r\n",
                    base, size
                ));
            }
            if let Err(err) = elf::load_segments(&elf_image, &bytes) {
                log_err(format_args!(
                    "bootloader: load_segments failed status={:?} addr={:#x} mem={:#x} file={:#x}\r\n",
                    err.status,
                    err.physical_addr,
                    err.mem_size,
                    err.file_size
                ));
                return Ok(false);
            }
            log_info(format_args!(
                "bootloader: raw kernel segments loaded, jumping to entry {:#x}\r\n",
                elf_image.entry
            ));
            unsafe {
                boot_raw_kernel(boot_info_ptr, elf_image.entry);
            }
            #[allow(unreachable_code)]
            {
                return Ok(true);
            }
        }
        Err(e) if e.status() == Status::NOT_FOUND => {
            log_info(format_args!(
                "bootloader: raw kernel {} not found, falling back\r\n",
                raw_path
            ));
            return Ok(false);
        }
        Err(e) => {
            log_err(format_args!(
                "bootloader: failed to read raw kernel {:?}\r\n",
                e.status()
            ));
            return Ok(false);
        }
    }
}

unsafe fn boot_raw_kernel(boot_info: *const BootInfo, entry: u64) -> ! {
    let _ = uefi::boot::exit_boot_services(None);
    #[cfg(target_arch = "aarch64")]
    {
        let entry_fn: extern "C" fn(*const BootInfo) -> ! = core::mem::transmute(entry as usize);
        entry_fn(boot_info)
    }
    #[cfg(target_arch = "x86_64")]
    {
        // UEFI uses the Microsoft x64 calling convention, but our raw kernel entry uses the
        // SysV ABI (x86_64-unknown-none). Pass BootInfo in RDI explicitly.
        core::arch::asm!(
            "mov rdi, {boot}",
            "jmp {entry}",
            boot = in(reg) boot_info,
            entry = in(reg) entry as usize,
            options(noreturn)
        );
    }
}

fn print_err(s: &str) {
    uefi::system::with_stderr(|out| {
        let mut utf16 = [0u16; 512];
        if let Ok(cstr) = CStr16::from_str_with_buf(s, &mut utf16) {
            let _ = out.output_string(cstr);
        }
    });
}

fn print_out(s: &str) {
    uefi::system::with_stdout(|out| {
        let mut utf16 = [0u16; 512];
        if let Ok(cstr) = CStr16::from_str_with_buf(s, &mut utf16) {
            let _ = out.output_string(cstr);
        }
    });
}

#[cfg(target_os = "uefi")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
