#![cfg(target_os = "none")]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp;

use crate::virtio;

use super::crc32;

pub const MAGIC_V01: &[u8; 4] = b"GORE";
pub const HEADER_SIZE: usize = 32;
pub const ALIGN: u64 = 8;

// v1 internal record types (0x1xxx range).
pub const RECORD_SHELL_TEXT_V1: u32 = 0x1_0001;
pub const RECORD_CREATE_OBJECT_V1: u32 = 0x1_0002;
pub const RECORD_ADD_EDGE_V1: u32 = 0x1_0003;
pub const RECORD_REMOVE_EDGE_V1: u32 = 0x1_0004;
pub const RECORD_UPDATE_OBJECT_META_V1: u32 = 0x1_0005;
pub const RECORD_APP_MANIFEST_V1: u32 = 0x1_0100;
pub const RECORD_APP_BINARY_V1: u32 = 0x1_0101;
pub const RECORD_APP_CAPS_V1: u32 = 0x1_0102;
pub const RECORD_APP_REMOVE_V1: u32 = 0x1_0103;
// v2 app records (backward-compatible additions; v1 remains readable).
pub const RECORD_APP_MANIFEST_V2: u32 = 0x1_0110;
pub const RECORD_APP_BINARY_V2: u32 = 0x1_0111;
pub const RECORD_APP_CAPS_V2: u32 = 0x1_0112;
pub const RECORD_APP_REMOVE_V2: u32 = 0x1_0113;
/// v2: Applications registry record (name -> App workspace mapping).
pub const RECORD_APP_REGISTRY_V1: u32 = 0x1_0114;
/// v1: AppConfig text content record (name/app_ws + UTF-8 bytes).
pub const RECORD_APP_CONFIG_TEXT_V1: u32 = 0x1_0115;
/// v1: User config override (written into User:<name> workspace; app_name + user + UTF-8 bytes).
pub const RECORD_APP_USER_CONFIG_TEXT_V1: u32 = 0x1_0116;
/// v1: per-user app binary verification cache (written into User:<name> workspace).
pub const RECORD_APP_VERIFY_CACHE_V1: u32 = 0x1_0117;
/// v1: system-shipped app marker (written by installer into App:<name> workspace; used to skip runtime CRC for shipped apps).
pub const RECORD_APP_SHIPPED_V1: u32 = 0x1_0118;
/// v1: system-shipped app “segment image” (installer-generated; avoids ELF parsing and non-LOAD sections at runtime).
pub const RECORD_APP_IMAGE_V1: u32 = 0x1_0119;
/// v1: AppAsset blob stored in App:<name> workspace (name/app_ws + asset_name + bytes).
pub const RECORD_APP_ASSET_BLOB_V1: u32 = 0x1_0120;
pub const RECORD_CREATE_WORKSPACE_V1: u32 = 0x1_0200;
pub const RECORD_ACCOUNT_OBJECT_V1: u32 = 0x1_0201;
pub const RECORD_UPDATE_BOOT_MANIFEST_V1: u32 = 0x1_0202;
pub const RECORD_WORKSPACE_SPEC_V1: u32 = 0x1_0203;
pub const RECORD_AUDIT_V1: u32 = 0x1_0300;
pub const RECORD_SIP_OVERRIDE_V1: u32 = 0x1_0301;
pub const RECORD_AUDIT_EVENT_V1: u32 = 0x1_0302;

// v0.1 installer records (written by xtask; keep parsing-compatible).
pub const RECORD_ACCOUNT_OBJECT_V01: u32 = 5;
pub const RECORD_WORKSPACE_OBJECT_V01: u32 = 6;

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub record_type: u32,
    pub payload_len: u32,
    pub seq: u64,
    pub crc32: u32,
}

pub fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

pub fn parse_header(buf: &[u8; HEADER_SIZE]) -> Option<Header> {
    if &buf[0..4] != MAGIC_V01 {
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
    Some(Header {
        record_type,
        payload_len,
        seq,
        crc32,
    })
}

pub fn build_header(record_type: u32, payload_len: u32, seq: u64) -> [u8; HEADER_SIZE] {
    let mut header = [0u8; HEADER_SIZE];
    header[0..4].copy_from_slice(MAGIC_V01);
    header[4..6].copy_from_slice(&1u16.to_le_bytes());
    header[6..8].copy_from_slice(&0u16.to_le_bytes());
    header[8..12].copy_from_slice(&record_type.to_le_bytes());
    header[12..16].copy_from_slice(&payload_len.to_le_bytes());
    header[16..24].copy_from_slice(&seq.to_le_bytes());
    header[24..28].copy_from_slice(&0u32.to_le_bytes()); // crc placeholder
    header[28..32].copy_from_slice(&0u32.to_le_bytes());
    header
}

pub fn compute_crc_for_parts(header_with_zero_crc: &[u8; HEADER_SIZE], payload: &[u8]) -> u32 {
    let mut crc = crc32::init();
    crc = crc32::update(crc, header_with_zero_crc);
    crc = crc32::update(crc, payload);
    crc32::finalize(crc)
}

pub fn compute_crc_from_disk(record_off: u64, payload_len: u32) -> Option<u32> {
    // Reads header+payload from disk and computes CRC32 with header.crc field zeroed.
    const PAYLOAD_CHUNK: usize = 64 * 1024;
    let mut hdr = [0u8; HEADER_SIZE];
    if virtio::blk::read_at_res(record_off, &mut hdr).is_err() {
        return None;
    }
    hdr[24..28].fill(0);

    let mut crc = crc32::init();
    crc = crc32::update(crc, &hdr);

    let mut remaining = payload_len as usize;
    let mut off = 0usize;
    let mut scratch = Vec::new();
    scratch.resize(PAYLOAD_CHUNK, 0);
    while remaining > 0 {
        let take = cmp::min(remaining, scratch.len());
        if virtio::blk::read_at_res(
            record_off + HEADER_SIZE as u64 + off as u64,
            &mut scratch[..take],
        )
        .is_err()
        {
            return None;
        }
        crc = crc32::update(crc, &scratch[..take]);
        remaining -= take;
        off += take;
    }
    Some(crc32::finalize(crc))
}

pub fn encode_name32(name: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = name.as_bytes();
    let n = bytes.len().min(out.len());
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

pub fn name32_to_str(name: &[u8; 32]) -> &str {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    core::str::from_utf8(&name[..end])
        .unwrap_or("<non-utf8>")
        .trim()
}
