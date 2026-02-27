#![cfg(target_os = "none")]

extern crate alloc;

use core::cmp;
use core::sync::atomic::{AtomicBool, Ordering};

use spin::Mutex;

use crate::drivers::serial;
use crate::sandbox;
use crate::virtio;

use super::records;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    GoesUnavailable,
    NoRecordLog,
    PermissionDenied,
    NoSpace,
    IoError,
    InvalidRecord,
}

#[derive(Clone, Copy, Debug)]
struct WriterState {
    base: u64,
    len: u64,
    tail: u64,
    next_seq: u64,
}

static INITED: AtomicBool = AtomicBool::new(false);
static STATE: Mutex<WriterState> = Mutex::new(WriterState {
    base: 0,
    len: 0,
    tail: 0,
    next_seq: 0,
});

#[derive(Clone, Copy)]
struct ComposedCache {
    epoch: u64,
    ws32: [u8; 32],
    is_composed: bool,
}

static COMPOSED_CACHE: Mutex<ComposedCache> = Mutex::new(ComposedCache {
    epoch: 0,
    ws32: [0u8; 32],
    is_composed: false,
});

fn cached_is_composed(workspace: &str) -> bool {
    let epoch = crate::goes::replay::epoch();
    let ws32 = records::encode_name32(workspace);
    {
        let cache = COMPOSED_CACHE.lock();
        if cache.epoch == epoch && cache.ws32 == ws32 {
            return cache.is_composed;
        }
    }
    let is_composed = crate::goes::replay::workspace_is_composed(workspace);
    {
        let mut cache = COMPOSED_CACHE.lock();
        cache.epoch = epoch;
        cache.ws32 = ws32;
        cache.is_composed = is_composed;
    }
    is_composed
}

fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

fn crc32_record_stream(record_off: u64, payload_len: u32) -> Result<u32, WriteError> {
    records::compute_crc_from_disk(record_off, payload_len).ok_or(WriteError::IoError)
}

fn init_state_if_needed() -> Result<(), WriteError> {
    if INITED.load(Ordering::SeqCst) {
        return Ok(());
    }
    if !virtio::blk::available() {
        return Err(WriteError::GoesUnavailable);
    }
    let Some(sb) = crate::goes::probe() else {
        return Err(WriteError::GoesUnavailable);
    };
    if sb.record_log_offset == 0 || sb.record_log_len == 0 {
        serial::log_line("goes-writer: record_log missing");
        return Err(WriteError::NoRecordLog);
    }

    let base = sb.record_log_offset;
    let len = sb.record_log_len;

    let mut tail = 0u64;
    let mut next_seq = 0u64;

    // Scan forward until first invalid record (crash-safe).
    loop {
        if tail + records::HEADER_SIZE as u64 > len {
            break;
        }
        let mut hdr_bytes = [0u8; records::HEADER_SIZE];
        if virtio::blk::read_at_res(base + tail, &mut hdr_bytes).is_err() {
            return Err(WriteError::IoError);
        }
        let Some(h) = records::parse_header(&hdr_bytes) else {
            break;
        };
        let total = align_up(
            records::HEADER_SIZE as u64 + h.payload_len as u64,
            records::ALIGN,
        );
        if tail + total > len {
            break;
        }

        let crc = crc32_record_stream(base + tail, h.payload_len)?;
        if crc != h.crc32 {
            break;
        }

        tail = tail.saturating_add(total);
        next_seq = next_seq.max(h.seq.saturating_add(1));
    }

    {
        let mut st = STATE.lock();
        st.base = base;
        st.len = len;
        st.tail = tail;
        st.next_seq = next_seq;
    }
    INITED.store(true, Ordering::SeqCst);
    serial::log_line_args(format_args!(
        "goes-writer: ready (base={:#x}, len={:#x}, tail={:#x}, next_seq={})",
        base, len, tail, next_seq
    ));
    Ok(())
}

pub fn append_record(workspace: &str, record_type: u32, payload: &[u8]) -> Result<u64, WriteError> {
    init_state_if_needed()?;

    // v1: composed workspace is read-only and cannot be written directly.
    //
    // IMPORTANT: do not call `replay::snapshot()` (via `workspace_is_composed`) in the audit write path.
    // During early boot, audit emission can be frequent; forcing full index rebuilds can cause massive
    // heap pressure and OOM before the shell even starts.
    //
    // Audit records are always written into system/user-owned writable workspaces (User:<name> / Users),
    // so skipping composed checks here does not weaken the “composed workspace is read-only” guarantee.
    let skip_composed_check =
        record_type == records::RECORD_AUDIT_EVENT_V1 || record_type == records::RECORD_AUDIT_V1;
    if !skip_composed_check && cached_is_composed(workspace) {
        return Err(WriteError::PermissionDenied);
    }

    // App package objects must never be written into Applications workspace (registry only).
    if workspace.eq_ignore_ascii_case("Applications") {
        match record_type {
            records::RECORD_APP_MANIFEST_V1
            | records::RECORD_APP_MANIFEST_V2
            | records::RECORD_APP_BINARY_V1
            | records::RECORD_APP_BINARY_V2
            | records::RECORD_APP_CAPS_V1
            | records::RECORD_APP_CAPS_V2
            | records::RECORD_APP_CONFIG_TEXT_V1
            | records::RECORD_APP_USER_CONFIG_TEXT_V1
            | records::RECORD_APP_ASSET_BLOB_V1 => {
                serial::log_line(
                    "goes-writer: denied app package record in Applications (registry only)",
                );
                return Err(WriteError::PermissionDenied);
            }
            _ => {}
        }
    }

    // AppAsset blob must be written into the matching App workspace (no path semantics).
    if record_type == records::RECORD_APP_ASSET_BLOB_V1 {
        // payload v1:
        // u32 ver, u32 flags, name[32], app_ws[32], asset_name[32], u32 len, bytes[len]
        if payload.len() >= 4 + 4 + 32 + 32 + 32 + 4 {
            let mut app_ws = [0u8; 32];
            app_ws.copy_from_slice(&payload[40..72]);
            let app_ws = records::name32_to_str(&app_ws);
            if !app_ws.is_empty() {
                if !workspace.eq_ignore_ascii_case(app_ws) {
                    serial::log_line_args(format_args!(
                        "goes-writer: denied app asset (workspace mismatch, expected={})",
                        app_ws
                    ));
                    return Err(WriteError::PermissionDenied);
                }
                if !app_ws.to_ascii_lowercase().starts_with("app:") {
                    serial::log_line_args(format_args!(
                        "goes-writer: denied app asset (invalid app workspace={})",
                        app_ws
                    ));
                    return Err(WriteError::PermissionDenied);
                }
                if let Some(scope) = sandbox::parse_workspace(app_ws) {
                    if sandbox::require_goes_write(scope, app_ws).is_err() {
                        serial::log_line_args(format_args!(
                            "goes-writer: denied app asset for {} (no write permission)",
                            app_ws
                        ));
                        return Err(WriteError::PermissionDenied);
                    }
                }
            }
        }
    }

    // User config override must be written into the matching User:<name> workspace.
    if record_type == records::RECORD_APP_USER_CONFIG_TEXT_V1 {
        if payload.len() >= 4 + 4 + 32 + 32 {
            let mut user = [0u8; 32];
            user.copy_from_slice(&payload[40..72]);
            let u = records::name32_to_str(&user);
            if !u.is_empty() {
                let expected = alloc::format!("User:{u}");
                // v1: override is stored at the user root workspace (not Users).
                if !workspace.eq_ignore_ascii_case(&expected) {
                    serial::log_line_args(format_args!(
                        "goes-writer: denied user app config (workspace mismatch, expected={})",
                        expected
                    ));
                    return Err(WriteError::PermissionDenied);
                }
                // Additionally enforce write permission on that user's workspace (no cross-user override).
                if let Some(scope) = sandbox::parse_workspace(&expected) {
                    if sandbox::require_goes_write(scope, &expected).is_err() {
                        serial::log_line_args(format_args!(
                            "goes-writer: denied user app config for {} (no write permission)",
                            expected
                        ));
                        return Err(WriteError::PermissionDenied);
                    }
                }
            }
        }
    }

    // App verify cache must be written into the matching User:<name> workspace.
    if record_type == records::RECORD_APP_VERIFY_CACHE_V1 {
        if payload.len() >= 4 + 4 + 32 + 32 {
            let mut user = [0u8; 32];
            user.copy_from_slice(&payload[8..40]);
            let u = records::name32_to_str(&user);
            if !u.is_empty() {
                let expected = alloc::format!("User:{u}");
                if !workspace.eq_ignore_ascii_case(&expected) {
                    serial::log_line_args(format_args!(
                        "goes-writer: denied app verify cache (workspace mismatch, expected={})",
                        expected
                    ));
                    return Err(WriteError::PermissionDenied);
                }
                if let Some(scope) = sandbox::parse_workspace(&expected) {
                    if sandbox::require_goes_write(scope, &expected).is_err() {
                        serial::log_line_args(format_args!(
                            "goes-writer: denied app verify cache for {} (no write permission)",
                            expected
                        ));
                        return Err(WriteError::PermissionDenied);
                    }
                }
            }
        }
    }

    // v2: SIP 状态只能在 Recovery 中切换（Normal 禁止），且必须是 admin。
    if record_type == records::RECORD_SIP_OVERRIDE_V1 {
        let ctx = sandbox::context();
        if !ctx.recovery || !ctx.user_is_admin {
            serial::log_line("goes-writer: denied sip override (requires recovery+admin)");
            return Err(WriteError::PermissionDenied);
        }
    }

    // v2 基线：冻结系统级 Workspace 的身份与语义，禁止通过写路径创建/替换/改写它们。
    // 注意：这不是 SIP 的“写 System”权限控制，而是更底层的“不可变前提”约束。
    if record_type == records::RECORD_CREATE_WORKSPACE_V1 {
        if payload.len() >= 40 {
            let mut name = [0u8; 32];
            name.copy_from_slice(&payload[8..40]);
            let n = records::name32_to_str(&name);
            if crate::workspace::is_system_workspace_name_ci(n) {
                serial::log_line_args(format_args!(
                    "goes-writer: denied create_workspace for frozen system workspace: {}",
                    n
                ));
                return Err(WriteError::PermissionDenied);
            }

            // Users 语义：User:<name>/... 属于该用户，必须要求对应 User:<name> 的写权限。
            if let Some(rest) = n.strip_prefix("User:") {
                let owner = rest.split('/').next().unwrap_or(rest);
                if !owner.is_empty() {
                    let owner_ws = alloc::format!("User:{owner}");
                    if let Some(scope) = sandbox::parse_workspace(&owner_ws) {
                        if sandbox::require_goes_write(scope, &owner_ws).is_err() {
                            serial::log_line_args(format_args!(
                                "goes-writer: denied create_workspace for {} (no owner write permission)",
                                n
                            ));
                            return Err(WriteError::PermissionDenied);
                        }
                    }
                }
            }
        }
    } else if record_type == records::RECORD_WORKSPACE_SPEC_V1 {
        // payload: u32 ver, u32 reserved, name[32], ...
        if payload.len() >= 4 + 4 + 32 {
            let mut name = [0u8; 32];
            name.copy_from_slice(&payload[8..40]);
            let n = records::name32_to_str(&name);
            if crate::workspace::is_system_workspace_name_ci(n) {
                serial::log_line_args(format_args!(
                    "goes-writer: denied workspace_spec for frozen system workspace: {}",
                    n
                ));
                return Err(WriteError::PermissionDenied);
            }
        }
    }

    // System/Users/Library/Applications 的只读语义不能被“跨 workspace 记录”绕过：
    // 例如在 User 工作区写一条 UpdateObjectMeta 把 System 对象改名/迁出，
    // 或把对象迁入 System / 迁入其他用户的 User:<name>，都属于对目标 workspace 的写操作。
    if record_type == records::RECORD_CREATE_OBJECT_V1 {
        if payload.len() >= 80 {
            let mut ws_buf = [0u8; 32];
            ws_buf.copy_from_slice(&payload[16..48]);
            let target_ws = records::name32_to_str(&ws_buf);
            if let Some(scope) = sandbox::parse_workspace(target_ws) {
                if sandbox::require_goes_write(scope, target_ws).is_err() {
                    serial::log_line_args(format_args!(
                        "goes-writer: denied create_object targeting {} (no target write permission)",
                        target_ws
                    ));
                    return Err(WriteError::PermissionDenied);
                }
            }
        }
    } else if record_type == records::RECORD_UPDATE_OBJECT_META_V1 {
        if payload.len() >= 80 {
            let obj_id = u64::from_le_bytes(payload[4..12].try_into().unwrap_or([0; 8]));
            let Some(idx) = crate::goes::replay::snapshot() else {
                serial::log_line("goes-writer: denied meta update (index unavailable)");
                return Err(WriteError::PermissionDenied);
            };

            // If the object currently lives in a protected workspace, any metadata change is a write to that workspace.
            if let Some(obj) = idx.objects.get(&obj_id) {
                if let Some(scope) = sandbox::parse_workspace(&obj.workspace) {
                    if sandbox::require_goes_write(scope, &obj.workspace).is_err() {
                        serial::log_line_args(format_args!(
                            "goes-writer: denied meta update on {} object without write permission",
                            obj.workspace
                        ));
                        return Err(WriteError::PermissionDenied);
                    }
                }
            }

            // If the update requests moving into a protected workspace, that is also a write to the target workspace.
            let mut ws_buf = [0u8; 32];
            ws_buf.copy_from_slice(&payload[16..48]);
            let new_ws = records::name32_to_str(&ws_buf);
            if !new_ws.is_empty() {
                if let Some(scope) = sandbox::parse_workspace(new_ws) {
                    if sandbox::require_goes_write(scope, new_ws).is_err() {
                        serial::log_line_args(format_args!(
                            "goes-writer: denied moving object into {} without write permission",
                            new_ws
                        ));
                        return Err(WriteError::PermissionDenied);
                    }
                }
            }
        }
    } else if record_type == records::RECORD_ADD_EDGE_V1
        || record_type == records::RECORD_REMOVE_EDGE_V1
    {
        if payload.len() >= 24 {
            let from = u64::from_le_bytes(payload[4..12].try_into().unwrap_or([0; 8]));
            let to = u64::from_le_bytes(payload[12..20].try_into().unwrap_or([0; 8]));
            let Some(idx) = crate::goes::replay::snapshot() else {
                serial::log_line("goes-writer: denied edge update (index unavailable)");
                return Err(WriteError::PermissionDenied);
            };

            let mut check_obj = |id: u64| -> Result<(), WriteError> {
                let Some(obj) = idx.objects.get(&id) else {
                    return Ok(());
                };
                let Some(scope) = sandbox::parse_workspace(&obj.workspace) else {
                    return Ok(());
                };
                if sandbox::require_goes_write(scope, &obj.workspace).is_err() {
                    serial::log_line_args(format_args!(
                        "goes-writer: denied edge touching {} object without write permission",
                        obj.workspace
                    ));
                    return Err(WriteError::PermissionDenied);
                }
                Ok(())
            };

            check_obj(from)?;
            check_obj(to)?;
        }
    }

    let Some(ws) = sandbox::parse_workspace(workspace) else {
        return Err(WriteError::InvalidRecord);
    };
    if sandbox::require_goes_write(ws, workspace).is_err() {
        return Err(WriteError::PermissionDenied);
    }

    let mut st = STATE.lock();
    let base = st.base;
    let len = st.len;
    let tail = st.tail;
    let seq = st.next_seq;

    let total = align_up(
        records::HEADER_SIZE as u64 + payload.len() as u64,
        records::ALIGN,
    );
    if tail + total > len {
        return Err(WriteError::NoSpace);
    }

    let mut header = records::build_header(record_type, payload.len() as u32, seq);
    let crc = records::compute_crc_for_parts(&header, payload);
    header[24..28].copy_from_slice(&crc.to_le_bytes());

    let record_off = base + tail;
    if virtio::blk::write_at_res(record_off, &header).is_err() {
        return Err(WriteError::IoError);
    }
    if !payload.is_empty()
        && virtio::blk::write_at_res(record_off + records::HEADER_SIZE as u64, payload).is_err()
    {
        return Err(WriteError::IoError);
    }

    let pad_len = total - (records::HEADER_SIZE as u64 + payload.len() as u64);
    if pad_len > 0 {
        let zeros = [0u8; 64];
        let mut written = 0u64;
        while written < pad_len {
            let take = cmp::min((pad_len - written) as usize, zeros.len());
            if virtio::blk::write_at_res(
                record_off + records::HEADER_SIZE as u64 + payload.len() as u64 + written,
                &zeros[..take],
            )
            .is_err()
            {
                return Err(WriteError::IoError);
            }
            written += take as u64;
        }
    }

    st.tail = st.tail.saturating_add(total);
    st.next_seq = st.next_seq.saturating_add(1);
    serial::log_line_args(format_args!(
        "goes-writer: append ok (type=0x{:x}, seq={}, off={:#x}, size={:#x})",
        record_type, seq, record_off, total
    ));

    // v2: Library 写入也需要审计（最佳努力；失败不 panic）。
    if workspace.eq_ignore_ascii_case("Library")
        && record_type != records::RECORD_AUDIT_V1
        && record_type != records::RECORD_AUDIT_EVENT_V1
    {
        crate::audit::emit(
            crate::audit::EVENT_WRITE,
            "Library",
            "goes_write",
            record_type as u64,
            seq,
        );
    }

    // v2: System Workspace 的写入必须产生可回放的审计事件（GOES log record）。
    // 仅在 System 写入成功时追加审计记录；审计记录本身不再递归触发审计。
    if workspace.eq_ignore_ascii_case("System") && record_type != records::RECORD_AUDIT_V1 {
        let domain = sandbox::current_domain();
        let mut audit_payload = [0u8; 20];
        audit_payload[0..4].copy_from_slice(&1u32.to_le_bytes());
        audit_payload[4..8].copy_from_slice(&domain.to_le_bytes());
        audit_payload[8..12].copy_from_slice(&record_type.to_le_bytes());
        audit_payload[12..20].copy_from_slice(&seq.to_le_bytes());

        let audit_total = align_up(
            records::HEADER_SIZE as u64 + audit_payload.len() as u64,
            records::ALIGN,
        );
        if st.tail + audit_total <= len {
            let audit_seq = st.next_seq;
            let mut header = records::build_header(
                records::RECORD_AUDIT_V1,
                audit_payload.len() as u32,
                audit_seq,
            );
            let crc = records::compute_crc_for_parts(&header, &audit_payload);
            header[24..28].copy_from_slice(&crc.to_le_bytes());
            let audit_off = base + st.tail;
            if virtio::blk::write_at_res(audit_off, &header).is_ok()
                && virtio::blk::write_at_res(
                    audit_off + records::HEADER_SIZE as u64,
                    &audit_payload,
                )
                .is_ok()
            {
                let pad_len =
                    audit_total - (records::HEADER_SIZE as u64 + audit_payload.len() as u64);
                if pad_len > 0 {
                    let zeros = [0u8; 64];
                    let mut written = 0u64;
                    while written < pad_len {
                        let take = cmp::min((pad_len - written) as usize, zeros.len());
                        let _ = virtio::blk::write_at_res(
                            audit_off
                                + records::HEADER_SIZE as u64
                                + audit_payload.len() as u64
                                + written,
                            &zeros[..take],
                        );
                        written += take as u64;
                    }
                }
                st.tail = st.tail.saturating_add(audit_total);
                st.next_seq = st.next_seq.saturating_add(1);
                serial::log_line_args(format_args!(
                    "audit: system_write domain={} type=0x{:x} seq={}",
                    domain, record_type, seq
                ));
            } else {
                serial::log_line("audit: failed to append audit record");
            }
        } else {
            serial::log_line("audit: no space for audit record");
        }
    }

    // Avoid making audit flush OOM: audit events are not required to be visible in the fast index.
    // They are replayable from the record log at boot, but we do not invalidate the in-memory index here.
    let should_invalidate =
        record_type != records::RECORD_AUDIT_EVENT_V1 && record_type != records::RECORD_AUDIT_V1;
    if should_invalidate {
        crate::goes::replay::invalidate();
    }
    Ok(seq)
}
