#![cfg(target_os = "none")]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::sync::atomic::{AtomicUsize, Ordering as UOrdering};

use spin::Mutex;

use crate::drivers::serial;
use crate::sandbox;
use crate::virtio;

use super::records;

#[derive(Clone, Debug)]
pub struct ObjectInfo {
    pub id: u64,
    pub obj_type: u32,
    pub workspace: String,
    pub name: String,
    pub created_seq: u64,
}

#[derive(Clone, Debug)]
pub struct EdgeInfo {
    pub from: u64,
    pub to: u64,
    pub edge_type: u32,
    pub seq: u64,
    pub removed: bool,
}

#[derive(Clone, Debug)]
pub struct AccountInfo {
    pub username: String,
    pub admin: bool,
    pub disabled: bool,
    pub home_workspace: String,
    pub seq: u64,
}

#[derive(Clone, Debug)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub entry: String,
    pub removed: bool,
    pub caps_mask: u64,
    pub binary_size: u64,
    pub workspace: String,
    /// True if this app was installed as a system-shipped package (trusted by installer).
    pub shipped: bool,
    pub seq: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct AppBinaryLocator {
    /// Absolute disk offset of the record header in GOES record log.
    pub record_off: u64,
    pub payload_len: u32,
    pub seq: u64,
    /// Header crc32 field (not validated during boot replay for AppBinary records).
    pub crc32: u32,
    /// Arch discriminator for AppBinary v2 payloads (0=any/universal, 1=x86_64, 2=aarch64).
    pub arch: u32,
    /// Record type backing this locator (e.g. RECORD_APP_BINARY_V2 / RECORD_APP_IMAGE_V1).
    pub record_type: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct AppAssetLocator {
    /// Absolute disk offset of the record header in GOES record log.
    pub record_off: u64,
    pub payload_len: u32,
    pub seq: u64,
    /// Header crc32 field (not validated during boot replay for large assets).
    pub crc32: u32,
    /// Asset content length (bytes).
    pub data_len: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct AppVerifyCacheEntry {
    pub binary_seq: u64,
    pub binary_crc32: u32,
    pub binary_len: u32,
    pub seq: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct AppShippedEntry {
    pub arch: u32,
    pub binary_seq: u64,
    pub binary_len: u32,
    pub seq: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceKind {
    Writable = 0,
    Composed = 1,
}

#[derive(Clone, Debug)]
pub struct WorkspaceSpec {
    pub name: String,
    pub kind: WorkspaceKind,
    pub sources: Vec<String>,
    pub seq: u64,
}

#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub event: u32,
    pub domain_id: u32,
    pub arg0: u64,
    pub arg1: u64,
    pub name: String,
    pub target_ws: String,
    pub stored_ws: String,
    pub seq: u64,
}

#[derive(Default, Clone)]
pub struct Index {
    pub objects: BTreeMap<u64, ObjectInfo>,
    pub edges: Vec<EdgeInfo>,
    pub accounts: BTreeMap<String, AccountInfo>,
    pub apps: BTreeMap<String, AppInfo>,
    /// Latest AppBinary record locator per app name + arch (used to avoid record log scans).
    pub app_binaries: BTreeMap<(String, u32), AppBinaryLocator>,
    /// Latest system-shipped AppImage locator per app name + arch.
    pub app_images: BTreeMap<(String, u32), AppBinaryLocator>,
    /// AppConfig UTF-8 bytes, keyed by app name.
    pub app_configs: BTreeMap<String, Vec<u8>>,
    pub user_app_configs: BTreeMap<(String, String), Vec<u8>>,
    /// AppAsset locators: (app, asset_name) -> locator (content is read lazily from disk).
    pub app_assets: BTreeMap<(String, String), AppAssetLocator>,
    /// App binary verification cache: (user, app) -> last verified binary seq/crc/len.
    pub app_verify_cache: BTreeMap<(String, String), AppVerifyCacheEntry>,
    /// System-shipped app marker: (app, arch) -> expected binary seq/len (enables skipping runtime CRC).
    pub app_shipped: BTreeMap<(String, u32), AppShippedEntry>,
    pub workspaces: BTreeMap<String, u64>,
    pub workspace_specs: BTreeMap<String, WorkspaceSpec>,
    pub boot_active_set: Option<u32>,
    pub boot_default_user: Option<String>,
    pub audit_events: Vec<AuditEvent>,
    pub last_seq: u64,
}

pub fn binary_payload_len(locator: &AppBinaryLocator) -> u32 {
    match locator.record_type {
        records::RECORD_APP_BINARY_V2 => locator.payload_len.saturating_sub(48),
        records::RECORD_APP_IMAGE_V1 => locator.payload_len.saturating_sub(56),
        _ => locator.payload_len,
    }
}

static INVALIDATED: AtomicBool = AtomicBool::new(true);
static INDEX: Mutex<Option<Index>> = Mutex::new(None);
static SNAPSHOT_FAIL_LOGGED: AtomicBool = AtomicBool::new(false);
static SNAPSHOT_REBUILD_LOGS: AtomicUsize = AtomicUsize::new(0);
static INVALIDATE_LOGS: AtomicUsize = AtomicUsize::new(0);
static EPOCH: AtomicU64 = AtomicU64::new(1);

fn log_snapshot_fail(msg: &str) {
    if !SNAPSHOT_FAIL_LOGGED.swap(true, Ordering::SeqCst) {
        serial::log_line(msg);
    }
}

pub fn invalidate() {
    INVALIDATED.store(true, Ordering::SeqCst);
    let epoch = EPOCH.fetch_add(1, Ordering::SeqCst) + 1;
    let n = INVALIDATE_LOGS.fetch_add(1, UOrdering::Relaxed);
    if n < 8 || (n & 0x3f) == 0x3f {
        serial::log_line_args(format_args!(
            "goes-replay: invalidate (n={}, epoch={}, domain={})",
            n + 1,
            epoch,
            sandbox::current_domain()
        ));
    }
}

pub fn epoch() -> u64 {
    EPOCH.load(Ordering::Relaxed)
}

pub fn snapshot() -> Option<Index> {
    if !virtio::blk::available() {
        log_snapshot_fail("goes-replay: snapshot unavailable (virtio-blk not ready)");
        return None;
    }
    let Some(sb) = crate::goes::probe() else {
        log_snapshot_fail("goes-replay: snapshot unavailable (GOES superblock not found/invalid)");
        return None;
    };
    if sb.record_log_offset == 0 || sb.record_log_len == 0 {
        log_snapshot_fail(
            "goes-replay: snapshot unavailable (record_log not configured in superblock)",
        );
        return None;
    }

    if INVALIDATED.swap(false, Ordering::SeqCst) {
        let (heap_start, heap_end, heap_used) = crate::heap::stats();
        let used = crate::heap::used_bytes();
        let n = SNAPSHOT_REBUILD_LOGS.fetch_add(1, UOrdering::Relaxed);
        serial::log_line_args(format_args!(
            "goes-replay: rebuilding index (n={}, domain={}, heap_used={:#x} [{:#x}..{:#x}] used_ctr={:#x}, log_off={:#x} len={:#x})",
            n + 1,
            sandbox::current_domain(),
            used,
            heap_start,
            heap_end,
            heap_used,
            sb.record_log_offset,
            sb.record_log_len
        ));
        let idx = replay_build(sb.record_log_offset, sb.record_log_len)?;
        *INDEX.lock() = Some(idx);
    }

    let full = INDEX.lock().clone()?;
    Some(filter_index_for_current_domain(&full))
}

fn filter_index_for_current_domain(full: &Index) -> Index {
    let mut out = Index::default();
    out.boot_active_set = full.boot_active_set;
    out.boot_default_user = full.boot_default_user.clone();
    out.last_seq = full.last_seq;

    // Workspace 可见性：只暴露 domain+capability+policy 允许的 workspace（+四大系统 workspace）。
    crate::workspace::seed_system_workspaces(&mut out.workspaces);
    for (name, seq) in full.workspaces.iter() {
        if crate::workspace::is_system_workspace_name(name) {
            continue;
        }
        if crate::sandbox::can_goes_read_quiet(name) {
            out.workspaces.insert(name.clone(), *seq);
        }
    }

    // Objects：按对象所在 workspace 过滤。
    for (id, obj) in full.objects.iter() {
        if crate::sandbox::can_goes_read_quiet(&obj.workspace) {
            out.objects.insert(*id, obj.clone());
        }
    }

    // Edges：只保留两端对象均可见的边。
    for e in full.edges.iter() {
        if out.objects.contains_key(&e.from) && out.objects.contains_key(&e.to) {
            out.edges.push(e.clone());
        }
    }

    // Workspace specs：仅暴露可见 workspace 的 spec（系统 workspace 的 spec 被冻结语义忽略）。
    for (name, spec) in full.workspace_specs.iter() {
        if crate::workspace::is_system_workspace_name(name) {
            continue;
        }
        if crate::sandbox::can_goes_read_quiet(name) {
            out.workspace_specs.insert(name.clone(), spec.clone());
        }
    }

    // Applications：允许列出（normal 需要 run 能力的前置读取）。
    if crate::sandbox::can_goes_read_quiet("Applications") {
        out.apps = full.apps.clone();
    }

    // App binary locators：仅暴露当前可见的 app（且其 App workspace 可读）。
    for ((name, arch), loc) in full.app_binaries.iter() {
        let app_ws_ok = full
            .apps
            .get(name)
            .map(|a| !a.workspace.is_empty() && crate::sandbox::can_goes_read_quiet(&a.workspace))
            .unwrap_or(false);
        if app_ws_ok {
            out.app_binaries.insert((name.clone(), *arch), *loc);
        }
    }

    // App image locators：仅暴露当前可见的 app（且其 App workspace 可读）。
    for ((name, arch), loc) in full.app_images.iter() {
        let app_ws_ok = full
            .apps
            .get(name)
            .map(|a| !a.workspace.is_empty() && crate::sandbox::can_goes_read_quiet(&a.workspace))
            .unwrap_or(false);
        if app_ws_ok {
            out.app_images.insert((name.clone(), *arch), *loc);
        }
    }

    // App shipped markers：仅暴露当前可见的 app（且其 App workspace 可读）。
    for ((name, arch), ent) in full.app_shipped.iter() {
        let app_ws_ok = full
            .apps
            .get(name)
            .map(|a| !a.workspace.is_empty() && crate::sandbox::can_goes_read_quiet(&a.workspace))
            .unwrap_or(false);
        if app_ws_ok {
            out.app_shipped.insert((name.clone(), *arch), *ent);
        }
    }

    // Audit events：仅暴露其存储 workspace 可见的事件（默认写入 User:<name> 或 Users）。
    for evt in full.audit_events.iter() {
        if crate::sandbox::can_goes_read_quiet(&evt.stored_ws) {
            out.audit_events.push(evt.clone());
        }
    }

    // App configs：按 App workspace 可见性过滤。
    for (name, bytes) in full.app_configs.iter() {
        if let Some(app) = full.apps.get(name) {
            if !app.workspace.is_empty() && crate::sandbox::can_goes_read_quiet(&app.workspace) {
                out.app_configs.insert(name.clone(), bytes.clone());
            }
        }
    }

    // App assets：按 App workspace 可见性过滤（只暴露 locator，不载入 bytes）。
    for ((app_name, asset_name), loc) in full.app_assets.iter() {
        let app_ws_ok = full
            .apps
            .get(app_name)
            .map(|a| !a.workspace.is_empty() && crate::sandbox::can_goes_read_quiet(&a.workspace))
            .unwrap_or(false);
        if app_ws_ok {
            out.app_assets
                .insert((app_name.clone(), asset_name.clone()), *loc);
        }
    }

    // User App configs：按用户 Workspace 可见性过滤；同时要求 App workspace 可读（避免泄漏无权查看的 App）。
    for ((user, app), bytes) in full.user_app_configs.iter() {
        let mut user_ws = String::from("User:");
        user_ws.push_str(user);
        let app_ws_ok = full
            .apps
            .get(app)
            .map(|a| !a.workspace.is_empty() && crate::sandbox::can_goes_read_quiet(&a.workspace))
            .unwrap_or(false);
        if crate::sandbox::can_goes_read_quiet(&user_ws) && app_ws_ok {
            out.user_app_configs
                .insert((user.clone(), app.clone()), bytes.clone());
        }
    }

    // App verify cache：仅暴露当前用户 (User:<name>) 可见的缓存。
    {
        let ctx = crate::sandbox::context();
        let end = ctx
            .default_user
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(ctx.default_user.len());
        if end > 0 {
            if let Ok(u) = core::str::from_utf8(&ctx.default_user[..end]) {
                let u = u.trim().to_string();
                let mut user_ws = String::from("User:");
                user_ws.push_str(&u);
                if crate::sandbox::can_goes_read_quiet(&user_ws) {
                    for ((user, app), entry) in full.app_verify_cache.iter() {
                        if user != &u {
                            continue;
                        }
                        let app_ws_ok = full
                            .apps
                            .get(app)
                            .map(|a| {
                                !a.workspace.is_empty()
                                    && crate::sandbox::can_goes_read_quiet(&a.workspace)
                            })
                            .unwrap_or(false);
                        if app_ws_ok {
                            out.app_verify_cache
                                .insert((user.clone(), app.clone()), *entry);
                        }
                    }
                }
            }
        }
    }

    // Users：非 admin 只允许看到自己的账号记录（避免枚举全体用户）。
    if crate::sandbox::can_goes_read_quiet("Users") {
        out.accounts = full.accounts.clone();
    } else {
        let ctx = crate::sandbox::context();
        let end = ctx
            .default_user
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(ctx.default_user.len());
        if end > 0 {
            if let Ok(u) = core::str::from_utf8(&ctx.default_user[..end]) {
                let u = u.trim();
                if let Some(a) = full.accounts.get(u) {
                    out.accounts.insert(u.to_string(), a.clone());
                }
            }
        }
    }

    out
}

pub fn workspace_is_composed(name: &str) -> bool {
    let Some(idx) = snapshot() else { return false };
    if let Some(spec) = idx.workspace_specs.get(name) {
        return spec.kind == WorkspaceKind::Composed;
    }
    false
}

fn replay_build(base: u64, len: u64) -> Option<Index> {
    let mut idx = Index::default();
    // 冻结语义：系统级 Workspace 永远存在（不依赖可变写路径记录）。
    crate::workspace::seed_system_workspaces(&mut idx.workspaces);
    let mut off = 0u64;
    let mut records_ok = 0u64;
    let mut records_bad = 0u64;
    let mut last_progress_mib = 0u64;

    while off + records::HEADER_SIZE as u64 <= len {
        let mib = off >> 20;
        if mib != last_progress_mib && (mib % 4) == 0 {
            last_progress_mib = mib;
            serial::log_line_args(format_args!(
                "goes-replay: progress off={:#x} ({}MiB) ok={} bad={}",
                off, mib, records_ok, records_bad
            ));
        }
        let mut hdr_bytes = [0u8; records::HEADER_SIZE];
        if virtio::blk::read_at_res(base + off, &mut hdr_bytes).is_err() {
            serial::log_line_args(format_args!(
                "goes-replay: read header failed at off={:#x}",
                base + off
            ));
            records_bad += 1;
            break;
        }
        let Some(h) = records::parse_header(&hdr_bytes) else {
            break;
        };
        let total = records::align_up(
            records::HEADER_SIZE as u64 + h.payload_len as u64,
            records::ALIGN,
        );
        if off + total > len {
            break;
        }

        // Performance / UX: some app package records can be multiple MiB (binaries/assets).
        // During boot, we must not scan+CRC their whole payload; replay only needs a small prefix
        // to build the index/locators.
        if matches!(
            h.record_type,
            records::RECORD_APP_BINARY_V1
                | records::RECORD_APP_BINARY_V2
                | records::RECORD_APP_IMAGE_V1
                | records::RECORD_APP_ASSET_BLOB_V1
        ) {
            if h.record_type == records::RECORD_APP_ASSET_BLOB_V1 {
                const PREFIX_LEN: usize = 4 + 4 + 32 + 32 + 32 + 4; // 108
                if h.payload_len as usize >= PREFIX_LEN {
                    let mut prefix = [0u8; PREFIX_LEN];
                    if virtio::blk::read_at_res(
                        base + off + records::HEADER_SIZE as u64,
                        &mut prefix,
                    )
                    .is_ok()
                    {
                        let (name, app_ws, asset, data_len) =
                            decode_app_asset_blob_v1_prefix(&prefix)?;

                        // Ensure workspace exists and app record is visible.
                        idx.workspaces.entry(app_ws.clone()).or_insert(h.seq);
                        if let Some(app) = idx.apps.get_mut(&name) {
                            if app.workspace.is_empty() {
                                app.workspace = app_ws.clone();
                            }
                            app.seq = app.seq.max(h.seq);
                        } else {
                            idx.apps.insert(
                                name.clone(),
                                AppInfo {
                                    name: name.clone(),
                                    version: String::new(),
                                    entry: String::new(),
                                    removed: false,
                                    caps_mask: 0,
                                    binary_size: 0,
                                    workspace: app_ws.clone(),
                                    shipped: false,
                                    seq: h.seq,
                                },
                            );
                        }

                        let loc = AppAssetLocator {
                            record_off: base + off,
                            payload_len: h.payload_len,
                            seq: h.seq,
                            crc32: h.crc32,
                            data_len,
                        };
                        idx.app_assets.insert((name.clone(), asset.clone()), loc);

                        // Surface as an object inside App workspace (not a directory tree).
                        ensure_app_package_objects(&mut idx, &name);
                        let aid = app_asset_id(&name, &asset);
                        idx.objects.insert(
                            aid,
                            ObjectInfo {
                                id: aid,
                                obj_type: OBJ_TYPE_APP_ASSET,
                                workspace: app_ws.clone(),
                                name: alloc::format!("AppAsset:{}", asset),
                                created_seq: 0,
                            },
                        );

                        idx.last_seq = idx.last_seq.max(h.seq);
                        records_ok += 1;
                        off = off.saturating_add(total);
                        continue;
                    }
                }
            }

            let prefix_len = if h.record_type == records::RECORD_APP_IMAGE_V1 {
                56usize
            } else {
                48usize
            };
            if h.payload_len as usize >= prefix_len {
                let mut prefix = [0u8; 56];
                if virtio::blk::read_at_res(
                    base + off + records::HEADER_SIZE as u64,
                    &mut prefix[..prefix_len],
                )
                .is_ok()
                {
                    if h.record_type == records::RECORD_APP_IMAGE_V1 {
                        let (name, arch, img_len) =
                            decode_app_image_v1_prefix(&prefix[..prefix_len])?;
                        let key = name.clone();
                        if let Some(app) = idx.apps.get_mut(&name) {
                            app.binary_size = img_len as u64;
                            app.seq = app.seq.max(h.seq);
                        } else {
                            idx.apps.insert(
                                name.clone(),
                                AppInfo {
                                    name,
                                    version: String::new(),
                                    entry: String::new(),
                                    removed: false,
                                    caps_mask: 0,
                                    binary_size: img_len as u64,
                                    workspace: String::new(),
                                    shipped: false,
                                    seq: h.seq,
                                },
                            );
                        }
                        let loc = AppBinaryLocator {
                            record_off: base + off,
                            payload_len: h.payload_len,
                            seq: h.seq,
                            crc32: h.crc32,
                            arch,
                            record_type: h.record_type,
                        };
                        idx.app_images.insert((key.clone(), arch), loc);
                        // Also treat AppImage as the runtime-loadable binary for this arch.
                        idx.app_binaries.insert((key.clone(), arch), loc);
                        ensure_app_package_objects(&mut idx, &key);
                        idx.last_seq = idx.last_seq.max(h.seq);
                        records_ok += 1;
                        off = off.saturating_add(total);
                        continue;
                    }

                    let (name, size, arch) = match h.record_type {
                        records::RECORD_APP_BINARY_V1 => {
                            decode_app_binary_v1(&prefix[..48]).map(|(n, s)| (n, s, 0u32))
                        }
                        records::RECORD_APP_BINARY_V2 => {
                            decode_app_binary_v2_with_arch(&prefix[..48])
                        }
                        _ => None,
                    }?;
                    let key = name.clone();
                    if let Some(app) = idx.apps.get_mut(&name) {
                        app.binary_size = size;
                        app.seq = app.seq.max(h.seq);
                    } else {
                        idx.apps.insert(
                            name.clone(),
                            AppInfo {
                                name,
                                version: String::new(),
                                entry: String::new(),
                                removed: false,
                                caps_mask: 0,
                                binary_size: size,
                                workspace: String::new(),
                                shipped: false,
                                seq: h.seq,
                            },
                        );
                    }
                    idx.app_binaries.insert(
                        (key.clone(), arch),
                        AppBinaryLocator {
                            record_off: base + off,
                            payload_len: h.payload_len,
                            seq: h.seq,
                            crc32: h.crc32,
                            arch,
                            record_type: h.record_type,
                        },
                    );
                    ensure_app_package_objects(&mut idx, &key);
                    idx.last_seq = idx.last_seq.max(h.seq);
                    records_ok += 1;
                    off = off.saturating_add(total);
                    continue;
                }
                serial::log_line_args(format_args!(
                    "goes-replay: app binary prefix read failed off={:#x} len={:#x}",
                    base + off,
                    h.payload_len
                ));
                records_bad += 1;
                off = off.saturating_add(total);
                continue;
            }
        }

        if h.payload_len as u64 >= (1 << 20) {
            serial::log_line_args(format_args!(
                "goes-replay: large record seq={} type={:#x} payload_len={:#x} off={:#x}",
                h.seq,
                h.record_type,
                h.payload_len,
                base + off
            ));
        }
        let Some(crc) = records::compute_crc_from_disk(base + off, h.payload_len) else {
            records_bad += 1;
            break;
        };
        if crc != h.crc32 {
            records_bad += 1;
            break;
        }

        if h.payload_len as u64 >= (1 << 20) {
            serial::log_line_args(format_args!(
                "goes-replay: large record crc ok seq={} type={:#x}",
                h.seq, h.record_type
            ));
        }

        if h.payload_len >= 0x8000 {
            let (hs, he, used_ctr) = crate::heap::stats();
            serial::log_line_args(format_args!(
                "goes-replay: alloc payload buf seq={} type={:#x} payload_len={:#x} off={:#x} heap_used={:#x} used_ctr={:#x} heap=[0x{:x}..0x{:x})",
                h.seq,
                h.record_type,
                h.payload_len,
                base + off,
                crate::heap::used_bytes(),
                used_ctr,
                hs,
                he
            ));
        }

        let mut payload = Vec::with_capacity(h.payload_len as usize);
        payload.resize(h.payload_len as usize, 0);
        if h.payload_len > 0
            && virtio::blk::read_at_res(base + off + records::HEADER_SIZE as u64, &mut payload)
                .is_err()
        {
            records_bad += 1;
            break;
        }

        if h.payload_len as u64 >= (1 << 20) {
            serial::log_line_args(format_args!(
                "goes-replay: large record payload read ok seq={} type={:#x}",
                h.seq, h.record_type
            ));
        }
        apply_record(&mut idx, h.record_type, h.seq, &payload);
        idx.last_seq = idx.last_seq.max(h.seq);
        records_ok += 1;
        off = off.saturating_add(total);
    }

    serial::log_line_args(format_args!(
        "goes-replay: built index (ok={}, bad={}, last_seq={})",
        records_ok, records_bad, idx.last_seq
    ));
    Some(idx)
}

fn apply_record(idx: &mut Index, record_type: u32, seq: u64, payload: &[u8]) {
    match record_type {
        records::RECORD_CREATE_OBJECT_V1 => {
            if let Some(obj) = decode_create_object_v1(payload, seq) {
                idx.objects.insert(obj.id, obj);
            }
        }
        records::RECORD_UPDATE_OBJECT_META_V1 => {
            apply_update_object_meta_v1(idx, payload);
        }
        records::RECORD_ADD_EDGE_V1 => {
            if let Some(edge) = decode_edge_v1(payload, seq, false) {
                idx.edges.push(edge);
            }
        }
        records::RECORD_REMOVE_EDGE_V1 => {
            if let Some(edge) = decode_edge_v1(payload, seq, true) {
                idx.edges.push(edge);
            }
        }
        records::RECORD_ACCOUNT_OBJECT_V01 => {
            if let Some(acct) = decode_account_object_v01(payload, seq) {
                idx.accounts.insert(acct.username.clone(), acct);
            }
        }
        records::RECORD_ACCOUNT_OBJECT_V1 => {
            if let Some(acct) = decode_account_object_v1(payload, seq) {
                idx.accounts.insert(acct.username.clone(), acct);
            }
        }
        records::RECORD_WORKSPACE_OBJECT_V01 => {
            if let Some((name, ws_seq)) = decode_workspace_object_v01(payload, seq) {
                idx.workspaces.insert(name, ws_seq);
            }
        }
        records::RECORD_CREATE_WORKSPACE_V1 => {
            if let Some((name, ws_seq)) = decode_create_workspace_v1(payload, seq) {
                // 冻结语义：禁止通过写路径“创建/替换”系统级 Workspace。
                if crate::workspace::is_system_workspace_name_ci(&name) {
                    serial::log_line_args(format_args!(
                        "goes-replay: ignored create_workspace for frozen system workspace: {}",
                        name
                    ));
                    return;
                }
                idx.workspaces.insert(name, ws_seq);
            }
        }
        records::RECORD_WORKSPACE_SPEC_V1 => {
            if let Some(spec) = decode_workspace_spec_v1(payload, seq) {
                // 冻结语义：系统级 Workspace 的语义不可被 spec 改写。
                if crate::workspace::is_system_workspace_name_ci(&spec.name) {
                    serial::log_line_args(format_args!(
                        "goes-replay: ignored workspace_spec for frozen system workspace: {}",
                        spec.name
                    ));
                    return;
                }
                idx.workspace_specs.insert(spec.name.clone(), spec);
            }
        }
        records::RECORD_APP_MANIFEST_V1 => {
            if let Some(app) = decode_app_manifest_v1(payload, seq) {
                idx.apps.insert(app.name.clone(), app);
            }
        }
        records::RECORD_APP_MANIFEST_V2 => {
            if let Some(app) = decode_app_manifest_v2(payload, seq) {
                upsert_app(idx, app);
            }
        }
        records::RECORD_APP_BINARY_V1 => {
            if let Some((name, size)) = decode_app_binary_v1(payload) {
                let key = name.clone();
                if let Some(app) = idx.apps.get_mut(&name) {
                    app.binary_size = size;
                } else {
                    idx.apps.insert(
                        name.clone(),
                        AppInfo {
                            name,
                            version: String::new(),
                            entry: String::new(),
                            removed: false,
                            caps_mask: 0,
                            binary_size: size,
                            workspace: String::new(),
                            shipped: false,
                            seq,
                        },
                    );
                }
                ensure_app_package_objects(idx, &key);
            }
        }
        records::RECORD_APP_BINARY_V2 => {
            if let Some((name, size)) = decode_app_binary_v2(payload) {
                let key = name.clone();
                if let Some(app) = idx.apps.get_mut(&name) {
                    app.binary_size = size;
                } else {
                    idx.apps.insert(
                        name.clone(),
                        AppInfo {
                            name,
                            version: String::new(),
                            entry: String::new(),
                            removed: false,
                            caps_mask: 0,
                            binary_size: size,
                            workspace: String::new(),
                            shipped: false,
                            seq,
                        },
                    );
                }
                ensure_app_package_objects(idx, &key);
            }
        }
        records::RECORD_APP_SHIPPED_V1 => {
            if let Some((name, arch, binary_seq, binary_len)) = decode_app_shipped_v1(payload) {
                idx.app_shipped.insert(
                    (name.clone(), arch),
                    AppShippedEntry {
                        arch,
                        binary_seq,
                        binary_len,
                        seq,
                    },
                );
                if let Some(app) = idx.apps.get_mut(&name) {
                    app.shipped = true;
                }
            }
        }
        records::RECORD_APP_VERIFY_CACHE_V1 => {
            if let Some((user, app, binary_seq, binary_crc, binary_len)) =
                decode_app_verify_cache_v1(payload)
            {
                idx.app_verify_cache.insert(
                    (user, app),
                    AppVerifyCacheEntry {
                        binary_seq,
                        binary_crc32: binary_crc,
                        binary_len,
                        seq,
                    },
                );
            }
        }
        records::RECORD_APP_CAPS_V1 => {
            if let Some((name, mask)) = decode_app_caps_v1(payload) {
                let key = name.clone();
                if let Some(app) = idx.apps.get_mut(&name) {
                    app.caps_mask = mask;
                } else {
                    idx.apps.insert(
                        name.clone(),
                        AppInfo {
                            name,
                            version: String::new(),
                            entry: String::new(),
                            removed: false,
                            caps_mask: mask,
                            binary_size: 0,
                            workspace: String::new(),
                            shipped: false,
                            seq,
                        },
                    );
                }
                ensure_app_package_objects(idx, &key);
            }
        }
        records::RECORD_APP_CAPS_V2 => {
            if let Some((name, mask)) = decode_app_caps_v2(payload) {
                let key = name.clone();
                if let Some(app) = idx.apps.get_mut(&name) {
                    app.caps_mask = mask;
                } else {
                    idx.apps.insert(
                        name.clone(),
                        AppInfo {
                            name,
                            version: String::new(),
                            entry: String::new(),
                            removed: false,
                            caps_mask: mask,
                            binary_size: 0,
                            workspace: String::new(),
                            shipped: false,
                            seq,
                        },
                    );
                }
                ensure_app_package_objects(idx, &key);
            }
        }
        records::RECORD_APP_REGISTRY_V1 => {
            if let Some((name, app_ws)) = decode_app_registry_v1(payload) {
                // registry is stored in Applications; ensure workspace exists and update mapping.
                idx.workspaces.entry(app_ws.clone()).or_insert(seq);
                if let Some(app) = idx.apps.get_mut(&name) {
                    app.workspace = app_ws.clone();
                } else {
                    idx.apps.insert(
                        name.clone(),
                        AppInfo {
                            name: name.clone(),
                            version: String::new(),
                            entry: String::new(),
                            removed: false,
                            caps_mask: 0,
                            binary_size: 0,
                            workspace: app_ws.clone(),
                            shipped: false,
                            seq,
                        },
                    );
                }
                ensure_app_package_objects(idx, &name);
            }
        }
        records::RECORD_APP_CONFIG_TEXT_V1 => {
            if let Some((name, app_ws, text)) = decode_app_config_text_v1(payload) {
                // Store content; also ensure app exists and mapping is consistent.
                if let Some(app) = idx.apps.get(&name) {
                    if !app.workspace.is_empty() && app.workspace != app_ws {
                        serial::log_line_args(format_args!(
                            "goes-replay: app config workspace mismatch: {} reg={} cfg={}",
                            name, app.workspace, app_ws
                        ));
                    }
                }
                idx.app_configs.insert(name.clone(), text);
                // Ensure app workspace exists for visibility and objects.
                idx.workspaces.entry(app_ws.clone()).or_insert(seq);
                if let Some(app) = idx.apps.get_mut(&name) {
                    if app.workspace.is_empty() {
                        app.workspace = app_ws.clone();
                    }
                }
                ensure_app_package_objects(idx, &name);
            }
        }
        records::RECORD_APP_USER_CONFIG_TEXT_V1 => {
            if let Some((app, user, text)) = decode_app_user_config_text_v1(payload) {
                idx.user_app_configs.insert((user, app), text);
            }
        }
        records::RECORD_APP_REMOVE_V1 => {
            if let Some(name) = decode_app_remove_v1(payload) {
                let key = name.clone();
                if let Some(app) = idx.apps.get_mut(&name) {
                    app.removed = true;
                } else {
                    idx.apps.insert(
                        name.clone(),
                        AppInfo {
                            name,
                            version: String::new(),
                            entry: String::new(),
                            removed: true,
                            caps_mask: 0,
                            binary_size: 0,
                            workspace: String::new(),
                            shipped: false,
                            seq,
                        },
                    );
                }
                remove_app_package_objects(idx, &key);
            }
        }
        records::RECORD_APP_REMOVE_V2 => {
            if let Some(name) = decode_app_remove_v2(payload) {
                let key = name.clone();
                if let Some(app) = idx.apps.get_mut(&name) {
                    app.removed = true;
                } else {
                    idx.apps.insert(
                        name.clone(),
                        AppInfo {
                            name,
                            version: String::new(),
                            entry: String::new(),
                            removed: true,
                            caps_mask: 0,
                            binary_size: 0,
                            workspace: String::new(),
                            shipped: false,
                            seq,
                        },
                    );
                }
                remove_app_package_objects(idx, &key);
            }
        }
        records::RECORD_UPDATE_BOOT_MANIFEST_V1 => {
            if let Some((active_set, user)) = decode_boot_manifest_update_v1(payload) {
                idx.boot_active_set = Some(active_set);
                idx.boot_default_user = user;
            }
        }
        records::RECORD_AUDIT_EVENT_V1 => {
            if let Some(evt) = decode_audit_event_v1(payload, seq) {
                // Keep memory bounded: store only last N events.
                const MAX_AUDIT_EVENTS: usize = 256;
                if idx.audit_events.len() >= MAX_AUDIT_EVENTS {
                    let drain = idx.audit_events.len().saturating_sub(MAX_AUDIT_EVENTS - 1);
                    idx.audit_events.drain(0..drain);
                }
                idx.audit_events.push(evt);
            }
        }
        _ => {
            // ignore unknown/stub records in v1
        }
    }
}

fn decode_audit_event_v1(payload: &[u8], seq: u64) -> Option<AuditEvent> {
    // payload layout (fixed 128 bytes):
    // u32 ver, u32 event, u32 domain_id, u32 reserved, u64 arg0, u64 arg1,
    // name[32], target_ws[32], stored_ws[32]
    if payload.len() < 128 {
        return None;
    }
    let ver = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if ver != 1 {
        return None;
    }
    let event = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let domain_id = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let arg0 = u64::from_le_bytes([
        payload[16],
        payload[17],
        payload[18],
        payload[19],
        payload[20],
        payload[21],
        payload[22],
        payload[23],
    ]);
    let arg1 = u64::from_le_bytes([
        payload[24],
        payload[25],
        payload[26],
        payload[27],
        payload[28],
        payload[29],
        payload[30],
        payload[31],
    ]);
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[32..64]);
    let mut target_ws = [0u8; 32];
    target_ws.copy_from_slice(&payload[64..96]);
    let mut stored_ws = [0u8; 32];
    stored_ws.copy_from_slice(&payload[96..128]);
    Some(AuditEvent {
        event,
        domain_id,
        arg0,
        arg1,
        name: records::name32_to_str(&name).to_string(),
        target_ws: records::name32_to_str(&target_ws).to_string(),
        stored_ws: records::name32_to_str(&stored_ws).to_string(),
        seq,
    })
}

pub fn app_config_bytes_for_user<'a>(idx: &'a Index, app: &str, user: &str) -> Option<&'a [u8]> {
    if let Some(v) = idx
        .user_app_configs
        .get(&(user.to_string(), app.to_string()))
    {
        return Some(v.as_slice());
    }
    idx.app_configs.get(app).map(|v| v.as_slice())
}

// App package objects (derived, not a directory tree):
// - Applications stores registry entry (name -> App workspace)
// - App:<name> stores AppManifest/AppConfig/AppBinary objects
const OBJ_TYPE_APP_REGISTRY: u32 = 0xA001;
const OBJ_TYPE_APP_MANIFEST: u32 = 0xA002;
const OBJ_TYPE_APP_CONFIG: u32 = 0xA003;
const OBJ_TYPE_APP_BINARY: u32 = 0xA004;
const OBJ_TYPE_APP_ASSET: u32 = 0xA005;

fn fnv1a64(seed: u64, bytes: &[u8]) -> u64 {
    let mut hash = seed;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn app_object_id(name: &str, kind: u64) -> u64 {
    // kind distinguishes registry/manifest/config/binary.
    let mut hash = 0xcbf29ce484222325u64 ^ kind;
    hash = fnv1a64(hash, name.as_bytes());
    hash
}

fn app_registry_id(name: &str) -> u64 {
    app_object_id(name, 0x01)
}

fn app_manifest_id(name: &str) -> u64 {
    app_object_id(name, 0x02)
}

fn app_config_id(name: &str) -> u64 {
    app_object_id(name, 0x03)
}

fn app_binary_id(name: &str) -> u64 {
    app_object_id(name, 0x04)
}

fn app_asset_id(name: &str, asset: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64 ^ 0x05;
    hash = fnv1a64(hash, name.as_bytes());
    hash = fnv1a64(hash, b"\0");
    hash = fnv1a64(hash, asset.as_bytes());
    hash
}

fn upsert_app(idx: &mut Index, mut app: AppInfo) {
    let key = app.name.clone();
    // If registry already established workspace mapping, preserve it.
    if let Some(old) = idx.apps.get(&app.name) {
        if !old.workspace.is_empty() {
            app.workspace = old.workspace.clone();
        }
        // Preserve shipped marker if already known.
        if old.shipped {
            app.shipped = true;
        }
    }
    // Otherwise, fall back to derived workspace name.
    if app.workspace.is_empty() {
        app.workspace = derive_app_workspace_name(&app.name, app.seq);
    }
    idx.workspaces
        .entry(app.workspace.clone())
        .or_insert(app.seq);
    idx.apps.insert(key.clone(), app);
    ensure_app_package_objects(idx, &key);
}

pub fn is_system_shipped_app(
    idx: &Index,
    name: &str,
    arch: u32,
    bin_seq: u64,
    bin_len: u32,
) -> bool {
    idx.app_shipped
        .get(&(name.to_string(), arch))
        .map(|e| e.binary_seq == bin_seq && e.binary_len == bin_len)
        .unwrap_or(false)
}

fn ensure_app_package_objects(idx: &mut Index, name: &str) {
    let ws = idx
        .apps
        .get(name)
        .map(|a| a.workspace.as_str())
        .unwrap_or("Applications");
    if ws.is_empty() {
        return;
    }

    // Registry entry object in Applications (name -> App workspace mapping).
    let reg_id = app_registry_id(name);
    idx.objects.entry(reg_id).or_insert(ObjectInfo {
        id: reg_id,
        obj_type: OBJ_TYPE_APP_REGISTRY,
        workspace: "Applications".to_string(),
        name: name.to_string(),
        created_seq: 0,
    });

    // Package objects in App workspace.
    let mid = app_manifest_id(name);
    idx.objects.entry(mid).or_insert(ObjectInfo {
        id: mid,
        obj_type: OBJ_TYPE_APP_MANIFEST,
        workspace: ws.to_string(),
        name: "AppManifest".to_string(),
        created_seq: 0,
    });
    let cid = app_config_id(name);
    idx.objects.entry(cid).or_insert(ObjectInfo {
        id: cid,
        obj_type: OBJ_TYPE_APP_CONFIG,
        workspace: ws.to_string(),
        name: "AppConfig".to_string(),
        created_seq: 0,
    });
    let bid = app_binary_id(name);
    idx.objects.entry(bid).or_insert(ObjectInfo {
        id: bid,
        obj_type: OBJ_TYPE_APP_BINARY,
        workspace: ws.to_string(),
        name: "AppBinary".to_string(),
        created_seq: 0,
    });

    // Ensure workspace exists in list too (for ws list).
    idx.workspaces.entry(ws.to_string()).or_insert(0);
}

fn remove_app_package_objects(idx: &mut Index, name: &str) {
    let ws = idx
        .apps
        .get(name)
        .map(|a| a.workspace.clone())
        .unwrap_or_default();
    idx.objects.remove(&app_registry_id(name));
    idx.objects.remove(&app_manifest_id(name));
    idx.objects.remove(&app_config_id(name));
    idx.objects.remove(&app_binary_id(name));
    // Remove derived asset objects and locators.
    let mut to_remove: Vec<String> = Vec::new();
    for ((app, asset), _loc) in idx.app_assets.iter() {
        if app == name {
            to_remove.push(asset.clone());
        }
    }
    for asset in to_remove {
        idx.app_assets.remove(&(name.to_string(), asset.clone()));
        idx.objects.remove(&app_asset_id(name, &asset));
    }
    if !ws.is_empty() {
        idx.workspaces.remove(&ws);
    }
}

fn decode_create_object_v1(payload: &[u8], seq: u64) -> Option<ObjectInfo> {
    // v1 payload:
    // u32 version(1)
    // u64 object_id
    // u32 obj_type
    // workspace[32]
    // name[32]
    if payload.len() < 4 + 8 + 4 + 32 + 32 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut id = u64::from_le_bytes(payload[4..12].try_into().ok()?);
    let obj_type = u32::from_le_bytes(payload[12..16].try_into().ok()?);
    let mut ws = [0u8; 32];
    ws.copy_from_slice(&payload[16..48]);
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[48..80]);

    if id == 0 {
        id = seq;
    }

    Some(ObjectInfo {
        id,
        obj_type,
        workspace: records::name32_to_str(&ws).to_string(),
        name: records::name32_to_str(&name).to_string(),
        created_seq: seq,
    })
}

fn decode_edge_v1(payload: &[u8], seq: u64, removed: bool) -> Option<EdgeInfo> {
    // v1 payload:
    // u32 version(1)
    // u64 from
    // u64 to
    // u32 edge_type
    if payload.len() < 4 + 8 + 8 + 4 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let from = u64::from_le_bytes(payload[4..12].try_into().ok()?);
    let to = u64::from_le_bytes(payload[12..20].try_into().ok()?);
    let edge_type = u32::from_le_bytes(payload[20..24].try_into().ok()?);
    Some(EdgeInfo {
        from,
        to,
        edge_type,
        seq,
        removed,
    })
}

fn decode_workspace_spec_v1(payload: &[u8], seq: u64) -> Option<WorkspaceSpec> {
    // v1 payload (variable):
    // u32 version(1), u32 flags(0),
    // name[32],
    // kind u8 (0=writable,1=composed),
    // source_count u8,
    // reserved u16,
    // sources: source_count * name[32]
    if payload.len() < 4 + 4 + 32 + 1 + 1 + 2 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let kind = match payload[40] {
        0 => WorkspaceKind::Writable,
        1 => WorkspaceKind::Composed,
        _ => WorkspaceKind::Writable,
    };
    let source_count = payload[41] as usize;
    let base = 44usize;
    let needed = base + source_count * 32;
    if payload.len() < needed {
        return None;
    }
    let mut sources = Vec::new();
    for i in 0..source_count {
        let mut s = [0u8; 32];
        let off = base + i * 32;
        s.copy_from_slice(&payload[off..off + 32]);
        let ss = records::name32_to_str(&s).to_string();
        if !ss.is_empty() {
            sources.push(ss);
        }
    }
    Some(WorkspaceSpec {
        name,
        kind,
        sources,
        seq,
    })
}

pub fn encode_workspace_spec_payload_v1(
    name: &str,
    kind: WorkspaceKind,
    sources: &[&str],
    out: &mut Vec<u8>,
) {
    out.clear();
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&records::encode_name32(name));
    out.push(kind as u8);
    out.push(sources.len().min(8) as u8);
    out.extend_from_slice(&0u16.to_le_bytes());
    for s in sources.iter().take(8) {
        out.extend_from_slice(&records::encode_name32(s));
    }
}

fn apply_update_object_meta_v1(idx: &mut Index, payload: &[u8]) {
    // v1 payload:
    // u32 version(1), u64 object_id, u32 new_type(0=keep), workspace[32](empty=keep), name[32](empty=keep)
    if payload.len() < 4 + 8 + 4 + 32 + 32 {
        return;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok().unwrap_or([0; 4]));
    if version != 1 {
        return;
    }
    let obj_id = u64::from_le_bytes(payload[4..12].try_into().ok().unwrap_or([0; 8]));
    let new_type = u32::from_le_bytes(payload[12..16].try_into().ok().unwrap_or([0; 4]));
    let mut ws = [0u8; 32];
    ws.copy_from_slice(&payload[16..48]);
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[48..80]);

    let Some(obj) = idx.objects.get_mut(&obj_id) else {
        return;
    };
    if new_type != 0 {
        obj.obj_type = new_type;
    }
    let ws_s = records::name32_to_str(&ws);
    if !ws_s.is_empty() {
        obj.workspace = ws_s.to_string();
    }
    let name_s = records::name32_to_str(&name);
    if !name_s.is_empty() {
        obj.name = name_s.to_string();
    }
}

pub fn encode_create_object_payload_v1(
    id: u64,
    obj_type: u32,
    workspace: &str,
    name: &str,
    out: &mut [u8; 80],
) {
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..12].copy_from_slice(&id.to_le_bytes());
    out[12..16].copy_from_slice(&obj_type.to_le_bytes());
    out[16..48].copy_from_slice(&records::encode_name32(workspace));
    out[48..80].copy_from_slice(&records::encode_name32(name));
}

pub fn encode_edge_payload_v1(from: u64, to: u64, edge_type: u32, out: &mut [u8; 24]) {
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..12].copy_from_slice(&from.to_le_bytes());
    out[12..20].copy_from_slice(&to.to_le_bytes());
    out[20..24].copy_from_slice(&edge_type.to_le_bytes());
}

fn decode_account_object_v01(payload: &[u8], seq: u64) -> Option<AccountInfo> {
    // payload v0.1 (xtask):
    // u32 version(1), u32 flags, name[32], u32 password_len, [password bytes...]
    if payload.len() < 4 + 4 + 32 + 4 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let flags = u32::from_le_bytes(payload[4..8].try_into().ok()?);
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let username = records::name32_to_str(&name).to_string();
    if username.is_empty() {
        return None;
    }
    let admin = (flags & 1) != 0; // bit0=admin (v0.1)
    let disabled = (flags & 2) != 0; // bit1=disabled (reserved for v1)
    let mut home_workspace = String::from("User:");
    home_workspace.push_str(&username);
    Some(AccountInfo {
        username,
        admin,
        disabled,
        home_workspace,
        seq,
    })
}

fn decode_account_object_v1(payload: &[u8], seq: u64) -> Option<AccountInfo> {
    // v1 payload:
    // u32 version(1), u32 flags, username[32], home_ws[32]
    if payload.len() < 4 + 4 + 32 + 32 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let flags = u32::from_le_bytes(payload[4..8].try_into().ok()?);
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let username = records::name32_to_str(&name).to_string();
    if username.is_empty() {
        return None;
    }
    let mut home = [0u8; 32];
    home.copy_from_slice(&payload[40..72]);
    let home_workspace = records::name32_to_str(&home).to_string();
    let admin = (flags & 1) != 0;
    let disabled = (flags & 2) != 0;
    Some(AccountInfo {
        username,
        admin,
        disabled,
        home_workspace,
        seq,
    })
}

fn decode_workspace_object_v01(payload: &[u8], seq: u64) -> Option<(String, u64)> {
    // payload v0.1:
    // u32 version(1), u32 flags, name[32]
    if payload.len() < 4 + 4 + 32 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let s = records::name32_to_str(&name).to_string();
    if s.is_empty() {
        return None;
    }
    Some((s, seq))
}

fn decode_create_workspace_v1(payload: &[u8], seq: u64) -> Option<(String, u64)> {
    // v1 payload:
    // u32 version(1), u32 flags, name[32]
    if payload.len() < 4 + 4 + 32 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let s = records::name32_to_str(&name).to_string();
    if s.is_empty() {
        return None;
    }
    Some((s, seq))
}

fn decode_boot_manifest_update_v1(payload: &[u8]) -> Option<(u32, Option<String>)> {
    // v1 payload:
    // u32 version(1), u32 active_set, default_user[32]
    if payload.len() < 4 + 4 + 32 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let active_set = u32::from_le_bytes(payload[4..8].try_into().ok()?);
    let mut user = [0u8; 32];
    user.copy_from_slice(&payload[8..40]);
    let u = records::name32_to_str(&user).to_string();
    let user_opt = (!u.is_empty()).then_some(u);
    Some((active_set, user_opt))
}

fn decode_app_manifest_v1(payload: &[u8], seq: u64) -> Option<AppInfo> {
    // v1 payload:
    // u32 version(1), u32 flags(0), name[32], entry[32]
    if payload.len() < 4 + 4 + 32 + 32 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let mut entry = [0u8; 32];
    entry.copy_from_slice(&payload[40..72]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let entry = records::name32_to_str(&entry).to_string();
    let ws = derive_app_workspace_name(&name, seq);
    Some(AppInfo {
        name,
        version: String::new(),
        entry,
        removed: false,
        caps_mask: 0,
        binary_size: 0,
        workspace: ws,
        shipped: false,
        seq,
    })
}

/// Derive the workspace name that stores an app's package objects.
///
/// v2 语义：每个应用默认拥有一个 App workspace（用于存放该 app 的对象集合），
/// 但它不是系统级 Workspace（不影响 System/Users/Applications/Library 冻结语义）。
///
/// Naming:
/// - Prefer `App:<name>` when it fits in GOES name32 (<=32 bytes).
/// - Fallback to `App#<seq>` to guarantee bounded length and uniqueness.
pub fn derive_app_workspace_name(name: &str, seq: u64) -> String {
    let mut s = String::from("App:");
    s.push_str(name);
    if s.as_bytes().len() <= 32 {
        return s;
    }
    alloc::format!("App#{}", seq)
}

fn decode_app_registry_v1(payload: &[u8]) -> Option<(String, String)> {
    // payload:
    // u32 version(1), u32 flags(0), name[32], app_ws[32]
    if payload.len() < 4 + 4 + 32 + 32 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let mut ws = [0u8; 32];
    ws.copy_from_slice(&payload[40..72]);
    let ws = records::name32_to_str(&ws).to_string();
    if ws.is_empty() {
        return None;
    }
    Some((name, ws))
}

fn decode_app_config_text_v1(payload: &[u8]) -> Option<(String, String, Vec<u8>)> {
    // payload v1:
    // u32 version(1), u32 flags(0)
    // name[32], app_ws[32], u32 len, bytes[len]
    if payload.len() < 4 + 4 + 32 + 32 + 4 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let mut app_ws = [0u8; 32];
    app_ws.copy_from_slice(&payload[40..72]);
    let len = u32::from_le_bytes(payload[72..76].try_into().ok()?) as usize;
    if payload.len() < 76 + len {
        return None;
    }
    let bytes = payload[76..76 + len].to_vec();
    Some((
        records::name32_to_str(&name).to_string(),
        records::name32_to_str(&app_ws).to_string(),
        bytes,
    ))
}

fn decode_app_asset_blob_v1_prefix(prefix: &[u8]) -> Option<(String, String, String, u32)> {
    // payload v1 prefix (fixed 108 bytes):
    // u32 version(1), u32 flags(0),
    // app_name[32], app_ws[32], asset_name[32], u32 len, bytes[len...]
    if prefix.len() < 4 + 4 + 32 + 32 + 32 + 4 {
        return None;
    }
    let version = u32::from_le_bytes(prefix[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut app = [0u8; 32];
    app.copy_from_slice(&prefix[8..40]);
    let mut app_ws = [0u8; 32];
    app_ws.copy_from_slice(&prefix[40..72]);
    let mut asset = [0u8; 32];
    asset.copy_from_slice(&prefix[72..104]);
    let len = u32::from_le_bytes(prefix[104..108].try_into().ok()?);

    let app = records::name32_to_str(&app).to_string();
    let app_ws = records::name32_to_str(&app_ws).to_string();
    let asset = records::name32_to_str(&asset).to_string();
    if app.is_empty() || app_ws.is_empty() || asset.is_empty() {
        return None;
    }
    Some((app, app_ws, asset, len))
}

fn decode_app_user_config_text_v1(payload: &[u8]) -> Option<(String, String, Vec<u8>)> {
    // payload v1:
    // u32 version(1), u32 flags(0)
    // app_name[32], user[32], u32 len, bytes[len]
    if payload.len() < 4 + 4 + 32 + 32 + 4 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut app = [0u8; 32];
    app.copy_from_slice(&payload[8..40]);
    let mut user = [0u8; 32];
    user.copy_from_slice(&payload[40..72]);
    let len = u32::from_le_bytes(payload[72..76].try_into().ok()?) as usize;
    if payload.len() < 76 + len {
        return None;
    }
    let bytes = payload[76..76 + len].to_vec();
    let app = records::name32_to_str(&app).to_string();
    let user = records::name32_to_str(&user).to_string();
    if app.is_empty() || user.is_empty() {
        return None;
    }
    Some((app, user, bytes))
}

pub fn encode_app_manifest_payload_v1(name: &str, entry: &str, out: &mut [u8; 72]) {
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&records::encode_name32(name));
    out[40..72].copy_from_slice(&records::encode_name32(entry));
}

fn decode_app_manifest_v2(payload: &[u8], seq: u64) -> Option<AppInfo> {
    // v2 payload:
    // u32 version(2), u32 flags(0), name[32], entry[32], ver[32]
    if payload.len() < 4 + 4 + 32 + 32 + 32 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 2 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let mut entry = [0u8; 32];
    entry.copy_from_slice(&payload[40..72]);
    let mut ver = [0u8; 32];
    ver.copy_from_slice(&payload[72..104]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let entry = records::name32_to_str(&entry).to_string();
    let ver = records::name32_to_str(&ver).to_string();
    let ws = derive_app_workspace_name(&name, seq);
    Some(AppInfo {
        name,
        version: ver,
        entry,
        removed: false,
        caps_mask: 0,
        binary_size: 0,
        workspace: ws,
        shipped: false,
        seq,
    })
}

pub fn encode_app_manifest_payload_v2(
    name: &str,
    entry: &str,
    version_str: &str,
    out: &mut [u8; 104],
) {
    out[0..4].copy_from_slice(&2u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&records::encode_name32(name));
    out[40..72].copy_from_slice(&records::encode_name32(entry));
    out[72..104].copy_from_slice(&records::encode_name32(version_str));
}

fn decode_app_binary_v1(payload: &[u8]) -> Option<(String, u64)> {
    // v1 payload: u32 version(1), u32 flags(0), name[32], u64 size
    if payload.len() < 4 + 4 + 32 + 8 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let size = u64::from_le_bytes(payload[40..48].try_into().ok()?);
    Some((name, size))
}

fn decode_app_binary_v2(payload: &[u8]) -> Option<(String, u64)> {
    // v2 payload: u32 version(2), u32 flags(0), name[32], u64 size, [bytes...]
    if payload.len() < 4 + 4 + 32 + 8 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 2 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let size = u64::from_le_bytes(payload[40..48].try_into().ok()?);
    Some((name, size))
}

fn decode_app_binary_v2_with_arch(payload: &[u8]) -> Option<(String, u64, u32)> {
    // v2 payload: u32 version(2), u32 arch, name[32], u64 size, [bytes...]
    if payload.len() < 4 + 4 + 32 + 8 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 2 {
        return None;
    }
    let arch = u32::from_le_bytes(payload[4..8].try_into().ok()?);
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let size = u64::from_le_bytes(payload[40..48].try_into().ok()?);
    Some((name, size, arch))
}

fn decode_app_image_v1_prefix(payload: &[u8]) -> Option<(String, u32, u32)> {
    // v1 payload prefix: u32 version(1), u32 arch, name[32], u64 source_seq, u32 image_len, u32 reserved
    if payload.len() < 56 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let arch = u32::from_le_bytes(payload[4..8].try_into().ok()?);
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let image_len = u32::from_le_bytes(payload[48..52].try_into().ok()?);
    Some((name, arch, image_len))
}

pub fn current_arch_id() -> u32 {
    if cfg!(target_arch = "x86_64") {
        1
    } else if cfg!(target_arch = "aarch64") {
        2
    } else {
        0
    }
}

pub fn select_app_binary_locator(idx: &Index, app: &str) -> Option<AppBinaryLocator> {
    let arch = current_arch_id();
    if let Some(loc) = idx.app_binaries.get(&(app.to_string(), arch)) {
        return Some(*loc);
    }
    idx.app_binaries.get(&(app.to_string(), 0)).copied()
}

fn decode_app_caps_v1(payload: &[u8]) -> Option<(String, u64)> {
    // v1 payload: u32 version(1), u32 flags(0), name[32], u64 caps_mask
    if payload.len() < 4 + 4 + 32 + 8 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let mask = u64::from_le_bytes(payload[40..48].try_into().ok()?);
    Some((name, mask))
}

fn decode_app_caps_v2(payload: &[u8]) -> Option<(String, u64)> {
    // v2 payload: u32 version(2), u32 flags(0), name[32], u64 caps_mask
    if payload.len() < 4 + 4 + 32 + 8 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 2 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let mask = u64::from_le_bytes(payload[40..48].try_into().ok()?);
    Some((name, mask))
}

fn decode_app_remove_v1(payload: &[u8]) -> Option<String> {
    // v1 payload: u32 version(1), u32 flags(0), name[32]
    if payload.len() < 4 + 4 + 32 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    Some(name)
}

fn decode_app_remove_v2(payload: &[u8]) -> Option<String> {
    // v2 payload: u32 version(2), u32 flags(0), name[32]
    if payload.len() < 4 + 4 + 32 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 2 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    Some(name)
}

fn decode_app_verify_cache_v1(payload: &[u8]) -> Option<(String, String, u64, u32, u32)> {
    // payload: u32 ver(1), u32 flags(0), user[32], app[32], u64 binary_seq, u32 binary_crc32, u32 binary_len
    if payload.len() < 4 + 4 + 32 + 32 + 8 + 4 + 4 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let mut user = [0u8; 32];
    user.copy_from_slice(&payload[8..40]);
    let user = records::name32_to_str(&user).to_string();
    if user.is_empty() {
        return None;
    }
    let mut app = [0u8; 32];
    app.copy_from_slice(&payload[40..72]);
    let app = records::name32_to_str(&app).to_string();
    if app.is_empty() {
        return None;
    }
    let binary_seq = u64::from_le_bytes(payload[72..80].try_into().ok()?);
    let binary_crc = u32::from_le_bytes(payload[80..84].try_into().ok()?);
    let binary_len = u32::from_le_bytes(payload[84..88].try_into().ok()?);
    Some((user, app, binary_seq, binary_crc, binary_len))
}

fn decode_app_shipped_v1(payload: &[u8]) -> Option<(String, u32, u64, u32)> {
    // payload: u32 ver(1), u32 arch, name[32], u64 binary_seq, u32 binary_len, u32 reserved
    if payload.len() < 4 + 4 + 32 + 8 + 4 + 4 {
        return None;
    }
    let version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if version != 1 {
        return None;
    }
    let arch = u32::from_le_bytes(payload[4..8].try_into().ok()?);
    let mut name = [0u8; 32];
    name.copy_from_slice(&payload[8..40]);
    let name = records::name32_to_str(&name).to_string();
    if name.is_empty() {
        return None;
    }
    let binary_seq = u64::from_le_bytes(payload[40..48].try_into().ok()?);
    let binary_len = u32::from_le_bytes(payload[48..52].try_into().ok()?);
    Some((name, arch, binary_seq, binary_len))
}

pub fn encode_app_binary_payload_v1(name: &str, size: u64, out: &mut [u8; 48]) {
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&records::encode_name32(name));
    out[40..48].copy_from_slice(&size.to_le_bytes());
}

pub fn encode_app_binary_payload_v2_header(name: &str, size: u64, out: &mut [u8; 48]) {
    // Header part; caller may append bytes after this 48-byte prefix.
    out[0..4].copy_from_slice(&2u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&records::encode_name32(name));
    out[40..48].copy_from_slice(&size.to_le_bytes());
}

pub fn encode_app_caps_payload_v1(name: &str, caps_mask: u64, out: &mut [u8; 48]) {
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&records::encode_name32(name));
    out[40..48].copy_from_slice(&caps_mask.to_le_bytes());
}

pub fn encode_app_caps_payload_v2(name: &str, caps_mask: u64, out: &mut [u8; 48]) {
    out[0..4].copy_from_slice(&2u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&records::encode_name32(name));
    out[40..48].copy_from_slice(&caps_mask.to_le_bytes());
}

pub fn encode_app_remove_payload_v1(name: &str, out: &mut [u8; 40]) {
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&records::encode_name32(name));
}

pub fn encode_app_remove_payload_v2(name: &str, out: &mut [u8; 40]) {
    out[0..4].copy_from_slice(&2u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&records::encode_name32(name));
}

pub fn encode_update_object_meta_payload_v1(
    obj_id: u64,
    new_type: u32,
    workspace: Option<&str>,
    name: Option<&str>,
    out: &mut [u8; 80],
) {
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..12].copy_from_slice(&obj_id.to_le_bytes());
    out[12..16].copy_from_slice(&new_type.to_le_bytes());
    out[16..48].copy_from_slice(&records::encode_name32(workspace.unwrap_or("")));
    out[48..80].copy_from_slice(&records::encode_name32(name.unwrap_or("")));
}

pub fn encode_create_workspace_payload_v1(name: &str, flags: u32, out: &mut [u8; 40]) {
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&flags.to_le_bytes());
    out[8..40].copy_from_slice(&records::encode_name32(name));
}

pub fn encode_account_object_payload_v1(
    username: &str,
    flags: u32,
    home_ws: &str,
    out: &mut [u8; 72],
) {
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&flags.to_le_bytes());
    out[8..40].copy_from_slice(&records::encode_name32(username));
    out[40..72].copy_from_slice(&records::encode_name32(home_ws));
}

pub fn encode_boot_manifest_update_payload_v1(
    active_set: u32,
    default_user: &str,
    out: &mut [u8; 40],
) {
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&active_set.to_le_bytes());
    out[8..40].copy_from_slice(&records::encode_name32(default_user));
}
