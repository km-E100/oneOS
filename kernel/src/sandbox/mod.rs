#![cfg(target_os = "none")]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;
use spin::Once;

use crate::boot_info;
use crate::drivers::serial;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceKind<'a> {
    System,
    Library,
    Applications,
    Users,
    User(&'a str),
    /// Service workspace (stored under System scope for now).
    ///
    /// v2: 用于把 /services 打包为 `Service:<name>`，不引入路径语义。
    Service(&'a str),
    /// Per-app private data scope (logically under Library).
    ///
    /// v2 最小实现：使用独立 workspace 名称 `LAD:<app>` 表达 “Library/AppData/<app>” 语义，
    /// 避免引入路径/目录树，同时保持 scope 可精确匹配、不可前缀绕过。
    LibraryAppData(&'a str),
    /// App workspace (stored under Applications).
    ///
    /// v2 语义：每个 App 可以拥有自己的 `App:<name>`（或 `App#<seq>`）workspace，
    /// 但它不改变“四大系统级 Workspace（System/Users/Applications/Library）冻结语义”。
    App(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainKind {
    Kernel,
    SystemService,
    App,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapType {
    GoesRead,
    GoesWrite,
    Console,
    GpuDraw,
    IpcSend,
    IpcRecv,
    // Stage 3 policy resource types (placeholders for v2+ service-ification).
    FbMap,
    GpuSubmit,
    BlkRead,
    BlkWrite,
    InputRead,
}

pub const CONSOLE_RIGHT_READ: u32 = 1 << 0;
pub const CONSOLE_RIGHT_WRITE: u32 = 1 << 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPolicy {
    Kill,
    Restart,
    Quarantine,
    Escalate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxError {
    PermissionDenied,
    InvalidScope,
    MissingCapability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    IllegalCapability,
    InvalidPointer,
    PolicyViolation,
    InvalidMemoryAccess,
}

#[derive(Clone, Copy, Debug)]
pub struct SandboxContext {
    pub recovery: bool,
    pub sip_on: bool,
    pub user_is_admin: bool,
    pub default_user: [u8; 32],
}

static CTX: Once<SandboxContext> = Once::new();
static INITED: AtomicBool = AtomicBool::new(false);
static BOOT_PHASE: AtomicBool = AtomicBool::new(true);

pub type DomainId = u32;
pub type CapHandle = u32;

pub const MEM_RIGHT_READ: u32 = 1 << 0;
pub const MEM_RIGHT_WRITE: u32 = 1 << 1;

#[derive(Clone, Copy, Debug)]
pub struct MemRegion {
    pub start: usize,
    pub end: usize,
    pub rights: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Capability {
    pub cap_type: CapType,
    pub scope: WorkspaceKind<'static>,
    pub rights: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainState {
    Created,
    Running,
    Stopped,
    Quarantined,
}

#[derive(Clone, Debug)]
pub struct Domain {
    pub id: DomainId,
    pub kind: DomainKind,
    pub owner: String,
    pub owner_admin: bool,
    pub name: String,
    pub workspace_scope: Vec<WorkspaceKind<'static>>,
    pub caps: Vec<CapHandle>,
    pub addr_space: crate::mmu::addrspace::AddressSpaceId,
    pub fault_policy: FaultPolicy,
    pub boot_critical: bool,
    pub state: DomainState,
    pub fault_count: u32,
    pub restart_count: u32,
}

static DOMAINS: Mutex<Vec<Domain>> = Mutex::new(Vec::new());
static CAPS: Mutex<Vec<(u32, Capability)>> = Mutex::new(Vec::new()); // (gen, cap)
static CURRENT_DOMAIN_ID: AtomicU32 = AtomicU32::new(0);
static CURRENT_DOMAIN_KIND: AtomicU32 = AtomicU32::new(domain_kind_to_u32(DomainKind::Kernel));
static TOTAL_FAULTS: AtomicU64 = AtomicU64::new(0);

// DomainId -> DomainKind quick table (lock-free).
//
// Motivation: timer/IRQ/preempt paths must never take `DOMAINS.lock()` (spin mutex).
// Storing the current kind in `CURRENT_DOMAIN_KIND` helps for "current domain" checks, but
// some paths need to derive kind from a domain id (e.g. `set_current_domain_raw()`).
//
// Encoding: 2 bits per domain id, 64 domains -> 2x u64.
const DOMAIN_KIND_FAST_MAX: u32 = 64;
const DOMAIN_KIND_FAST_SHIFT: u32 = 2; // bits per entry
const DOMAIN_KIND_FAST_PER_WORD: u32 = 64 / DOMAIN_KIND_FAST_SHIFT; // 32
static DOMAIN_KIND_FAST_0: AtomicU64 = AtomicU64::new(0);
static DOMAIN_KIND_FAST_1: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
fn domain_kind_fast_get(id: DomainId) -> DomainKind {
    if id >= DOMAIN_KIND_FAST_MAX {
        return DomainKind::Kernel;
    }
    let idx = id / DOMAIN_KIND_FAST_PER_WORD;
    let off = (id % DOMAIN_KIND_FAST_PER_WORD) * DOMAIN_KIND_FAST_SHIFT;
    let word = match idx {
        0 => DOMAIN_KIND_FAST_0.load(Ordering::Relaxed),
        1 => DOMAIN_KIND_FAST_1.load(Ordering::Relaxed),
        _ => 0,
    };
    domain_kind_from_u32(((word >> off) & 0x3) as u32)
}

#[inline(always)]
fn domain_kind_fast_set(id: DomainId, kind: DomainKind) {
    if id >= DOMAIN_KIND_FAST_MAX {
        return;
    }
    let idx = id / DOMAIN_KIND_FAST_PER_WORD;
    let off = (id % DOMAIN_KIND_FAST_PER_WORD) * DOMAIN_KIND_FAST_SHIFT;
    let mask = 0x3u64 << off;
    let val = (domain_kind_to_u32(kind) as u64) << off;

    let slot = match idx {
        0 => &DOMAIN_KIND_FAST_0,
        1 => &DOMAIN_KIND_FAST_1,
        _ => return,
    };
    // RMW: keep lock-free even under concurrent writers (rare).
    let mut cur = slot.load(Ordering::Relaxed);
    loop {
        let next = (cur & !mask) | val;
        match slot.compare_exchange_weak(cur, next, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => break,
            Err(v) => cur = v,
        }
    }
}

#[inline(always)]
fn domain_kind_fast_clear(id: DomainId) {
    domain_kind_fast_set(id, DomainKind::Kernel);
}

pub fn total_faults() -> u64 {
    TOTAL_FAULTS.load(Ordering::Relaxed)
}

pub fn init_from_boot_info() {
    if INITED.swap(true, Ordering::SeqCst) {
        return;
    }
    serial::log_line("sandbox: init_from_boot_info begin");
    let mut default_user = [0u8; 32];
    let mut sip_on = true;
    let mut recovery = false;
    let mut mmu_strict = true;

    if let Some(info) = boot_info::get() {
        serial::log_line("sandbox: boot_info present");
        recovery = info.is_recovery_mode();
        mmu_strict = info.mmu_strict();
        if let Some(flags) = info.goes_flags() {
            sip_on = (flags & 0b10) != 0;
        }
        if let Some(raw) = info.goes_default_user_raw() {
            default_user.copy_from_slice(raw);
        }
    } else if let Some(sb) = crate::goes::probe() {
        serial::log_line("sandbox: boot_info missing, using superblock");
        sip_on = (sb.flags & 0b10) != 0;
        default_user.copy_from_slice(&sb.default_user);
    }

    // Stage 1 (Post-MMU): strict mode controls whether we default to per-domain page-table switching.
    // Default: enabled (strict=on). When disabled, we keep the system runnable for debugging but
    // MUST print a clear warning.
    crate::mmu::switch::set_app_address_space_switch_enabled(mmu_strict);
    if !mmu_strict {
        serial::log_line("sandbox: WARNING: mmu_strict=off (address space isolation disabled)");
    }

    let user_is_admin = is_admin_name(&default_user);
    let ctx = SandboxContext {
        recovery,
        sip_on,
        user_is_admin,
        default_user,
    };
    serial::log_line("sandbox: context prepared");
    CTX.call_once(|| {
        serial::log_line_args(format_args!(
            "sandbox: init (recovery={}, sip={}, admin={})",
            ctx.recovery,
            if ctx.sip_on { "on" } else { "off" },
            ctx.user_is_admin
        ));
        ctx
    });

    serial::log_line("sandbox: init_domains begin");
    init_domains();
    serial::log_line("sandbox: init_domains done");
    serial::log_line("sandbox: init_from_boot_info done");
}

pub fn mark_boot_success() {
    // v2: “boot critical path” ends when shell is ready to accept input.
    BOOT_PHASE.store(false, Ordering::SeqCst);
    crate::audit::try_flush();
}

pub fn in_boot_phase() -> bool {
    BOOT_PHASE.load(Ordering::SeqCst)
}

pub fn context() -> &'static SandboxContext {
    CTX.get().unwrap_or_else(|| {
        // Fallback: treat as Normal + SIP ON.
        CTX.call_once(|| SandboxContext {
            recovery: false,
            sip_on: true,
            user_is_admin: false,
            default_user: [0u8; 32],
        })
    })
}

pub fn default_user_name() -> &'static str {
    default_user_str(&context().default_user).unwrap_or("unknown")
}

/// Quiet capability+policy check for GOES_WRITE.
///
/// - No logging
/// - No audit emit
/// - No Domain fault side effects
///
/// Used by early boot helpers (e.g. audit buffering) to avoid recursion/deadlocks.
pub fn can_goes_write_quiet(workspace: WorkspaceKind<'_>) -> bool {
    let cur = current_domain();
    if !domain_in_scope(cur, workspace) {
        return false;
    }
    if !domain_has_cap(cur, CapType::GoesWrite, workspace) {
        return false;
    }
    check_goes_write(workspace).is_ok()
}

fn init_domains() {
    let ctx = context();
    serial::log_line("sandbox: init_domains enter");
    let user = default_user_str(&ctx.default_user).unwrap_or("unknown");
    // WorkspaceKind::User stores the *owner name* (e.g. "admin"), not the "User:<name>" string.
    // This keeps scope checks consistent with parse_workspace("User:<name>") which yields the owner.
    let user_owner = leak_workspace_str(user);

    {
        let mut domains = DOMAINS.lock();
        if !domains.is_empty() {
            serial::log_line("sandbox: init_domains skipped (already initialized)");
            return;
        }

        // Kernel domain (TCB).
        serial::log_line("sandbox: init_domains add Kernel domain");
        let mut kernel_scope = Vec::new();
        kernel_scope.push(WorkspaceKind::System);
        kernel_scope.push(WorkspaceKind::Library);
        kernel_scope.push(WorkspaceKind::Applications);
        kernel_scope.push(WorkspaceKind::Users);
        kernel_scope.push(WorkspaceKind::User(user_owner));
        domains.push(Domain {
            id: 1,
            kind: DomainKind::Kernel,
            owner: String::from("System"),
            owner_admin: true,
            name: String::from("Kernel"),
            workspace_scope: kernel_scope,
            caps: Vec::new(),
            addr_space: crate::mmu::addrspace::kernel_id(),
            fault_policy: FaultPolicy::Kill,
            boot_critical: true,
            state: DomainState::Running,
            fault_count: 0,
            restart_count: 0,
        });
        domain_kind_fast_set(1, DomainKind::Kernel);

        // Shell/System service domain (single-task model for v1/v2).
        serial::log_line("sandbox: init_domains add Shell domain");
        let mut shell_scope = Vec::new();
        // v2: shell 需要读系统级 Workspace（列应用/读库/读系统配置），以及读写自己的 User:<name>。
        shell_scope.push(WorkspaceKind::System);
        shell_scope.push(WorkspaceKind::Library);
        shell_scope.push(WorkspaceKind::Applications);
        shell_scope.push(WorkspaceKind::User(user_owner));
        domains.push(Domain {
            id: 2,
            kind: DomainKind::SystemService,
            owner: user.into(),
            owner_admin: ctx.user_is_admin,
            name: String::from("Shell"),
            workspace_scope: shell_scope,
            caps: Vec::new(),
            addr_space: crate::mmu::addrspace::kernel_id(),
            fault_policy: FaultPolicy::Kill,
            boot_critical: true,
            state: DomainState::Running,
            fault_count: 0,
            restart_count: 0,
        });
        domain_kind_fast_set(2, DomainKind::SystemService);
    } // drop DOMAINS lock before grant_cap() to avoid self-deadlock

    // Default current: kernel domain.
    set_current_domain(1);
    serial::log_line("sandbox: init_domains set current domain=1");
    crate::ipc::register_domain(1);
    crate::ipc::register_domain(2);

    // Grant capabilities.
    serial::log_line("sandbox: init_domains grant GOES_READ");
    // Kernel: 作为 TCB，可读四大系统 workspace + Users。
    let _ = grant_cap(
        1,
        Capability {
            cap_type: CapType::GoesRead,
            scope: WorkspaceKind::System,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        1,
        Capability {
            cap_type: CapType::GoesRead,
            scope: WorkspaceKind::Library,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        1,
        Capability {
            cap_type: CapType::GoesRead,
            scope: WorkspaceKind::Applications,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        1,
        Capability {
            cap_type: CapType::GoesRead,
            scope: WorkspaceKind::Users,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        1,
        Capability {
            cap_type: CapType::GoesRead,
            scope: WorkspaceKind::User(user_owner),
            rights: 0x1,
        },
    );

    // Shell: 读系统级 workspace + 读自己的 User:<name>（避免绕过跨用户读取）。
    let _ = grant_cap(
        2,
        Capability {
            cap_type: CapType::GoesRead,
            scope: WorkspaceKind::System,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        2,
        Capability {
            cap_type: CapType::GoesRead,
            scope: WorkspaceKind::Library,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        2,
        Capability {
            cap_type: CapType::GoesRead,
            scope: WorkspaceKind::Applications,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        2,
        Capability {
            cap_type: CapType::GoesRead,
            scope: WorkspaceKind::User(user_owner),
            rights: 0x1,
        },
    );

    // IPC: shell/kernel can send/recv (service discovery + ping).
    let _ = grant_cap(
        1,
        Capability {
            cap_type: CapType::IpcSend,
            scope: WorkspaceKind::System,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        1,
        Capability {
            cap_type: CapType::IpcRecv,
            scope: WorkspaceKind::System,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        2,
        Capability {
            cap_type: CapType::IpcSend,
            scope: WorkspaceKind::System,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        2,
        Capability {
            cap_type: CapType::IpcRecv,
            scope: WorkspaceKind::System,
            rights: 0x1,
        },
    );

    // Write: user workspace.
    serial::log_line("sandbox: init_domains grant GOES_WRITE(User:<default>)");
    let _ = grant_cap(
        2,
        Capability {
            cap_type: CapType::GoesWrite,
            scope: WorkspaceKind::User(user_owner),
            rights: 0x2,
        },
    );

    // Admin extras.
    if ctx.user_is_admin {
        serial::log_line("sandbox: init_domains grant admin write caps");
        let _ = grant_cap(
            2,
            Capability {
                cap_type: CapType::GoesWrite,
                scope: WorkspaceKind::Applications,
                rights: 0x2,
            },
        );
        let _ = grant_cap(
            2,
            Capability {
                cap_type: CapType::GoesWrite,
                scope: WorkspaceKind::Library,
                rights: 0x2,
            },
        );
        let _ = grant_cap(
            2,
            Capability {
                cap_type: CapType::GoesWrite,
                scope: WorkspaceKind::Users,
                rights: 0x2,
            },
        );
        if ctx.recovery && !ctx.sip_on {
            serial::log_line("sandbox: init_domains grant System write (recovery+sip-off)");
            let _ = grant_cap(
                2,
                Capability {
                    cap_type: CapType::GoesWrite,
                    scope: WorkspaceKind::System,
                    rights: 0x2,
                },
            );
        }
    }

    // GPU: allow Kernel + Shell for v1 debug (gfx info/test). Apps do not get this cap.
    serial::log_line("sandbox: init_domains grant GPU_DRAW");
    let _ = grant_cap(
        1,
        Capability {
            cap_type: CapType::GpuDraw,
            scope: WorkspaceKind::System,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        2,
        Capability {
            cap_type: CapType::GpuDraw,
            scope: WorkspaceKind::System,
            rights: 0x1,
        },
    );

    serial::log_line("sandbox: domains/caps initialized (kernel=1, shell=2)");
    serial::log_line("sandbox: init_domains leave");
}

/// Low-level setter used by the scheduler/boot glue.
///
/// This only updates the CPU-global view and does **not** touch the scheduler task record.
pub fn set_current_domain_raw(id: DomainId) {
    // NOTE: This function is used by scheduler/boot glue, including timer/IRQ preemption paths.
    // It must be lock-free (no DOMAINS.lock()).
    CURRENT_DOMAIN_ID.store(id, Ordering::SeqCst);
    CURRENT_DOMAIN_KIND.store(
        domain_kind_to_u32(domain_kind_fast_get(id)),
        Ordering::SeqCst,
    );
}

/// Snapshot a domain's kind by id.
///
/// This is lock-free by design and safe to call from timer/IRQ preemption paths.
pub fn domain_kind_snapshot(id: DomainId) -> DomainKind {
    // Lock-free by design: safe for timer/IRQ/preempt paths.
    domain_kind_fast_get(id)
}

/// Low-level setter used by the scheduler/boot glue when the caller already knows the domain kind.
///
/// This is safe to call from timer/IRQ preemption paths (lock-free).
pub fn set_current_domain_raw_with_kind(id: DomainId, kind: DomainKind) {
    CURRENT_DOMAIN_ID.store(id, Ordering::SeqCst);
    CURRENT_DOMAIN_KIND.store(domain_kind_to_u32(kind), Ordering::SeqCst);
}

/// Set the current domain for the *current task*.
///
/// Rationale:
/// - `CURRENT_DOMAIN_*` is a CPU-global value used by capability checks and trap glue.
/// - The scheduler restores the domain on each context switch from the task's `domain_id`.
/// - If code switches domains (e.g. running an AppDomain inside a shell task) we must update
///   the task record immediately; relying on preemption-time snapshots is incomplete and can
///   leave a task "stuck" in the wrong domain and later killed/reaped.
pub fn set_current_domain(id: DomainId) {
    let kind = domain_kind_snapshot(id);
    set_current_domain_raw_with_kind(id, kind);
    #[cfg(target_os = "none")]
    crate::sched::try_set_current_task_domain(id as u32, kind);
}

pub fn current_domain() -> DomainId {
    CURRENT_DOMAIN_ID.load(Ordering::SeqCst)
}

/// Returns the current domain kind, defaulting to `Kernel` if the domain id is unknown.
///
/// NOTE: This is the "value" form used by low-level trap/interrupt glue.
/// Keep the legacy `current_domain_kind() -> Option<DomainKind>` below for existing checks.
pub fn current_domain_kind_or_kernel() -> DomainKind {
    domain_kind_from_u32(CURRENT_DOMAIN_KIND.load(Ordering::SeqCst))
}

pub fn fault(kind: FaultKind, msg: &str) {
    let domain_id = current_domain();
    apply_fault(domain_id, kind, msg);
}

fn apply_fault(domain_id: DomainId, kind: FaultKind, msg: &str) {
    TOTAL_FAULTS.fetch_add(1, Ordering::Relaxed);
    let (policy, boot_critical, state) = {
        let domains = DOMAINS.lock();
        let d = domains.iter().find(|d| d.id == domain_id);
        (
            d.map(|d| d.fault_policy).unwrap_or(FaultPolicy::Kill),
            d.map(|d| d.boot_critical).unwrap_or(false),
            d.map(|d| d.state).unwrap_or(DomainState::Running),
        )
    };

    serial::log_line_args(format_args!(
        "sandbox: FAULT domain={} kind={:?} policy={:?} state={:?} msg={}",
        domain_id, kind, policy, state, msg
    ));

    // Audit: record faults as system events. This must never panic.
    let domain_name = {
        let domains = DOMAINS.lock();
        domains
            .iter()
            .find(|d| d.id == domain_id)
            .map(|d| d.name.clone())
            .unwrap_or_else(|| alloc::format!("domain#{domain_id}"))
    };
    crate::audit::emit_for_domain(
        domain_id,
        crate::audit::EVENT_DOMAIN_FAULT,
        "System",
        &domain_name,
        kind as u64,
        policy as u64,
    );

    {
        let mut domains = DOMAINS.lock();
        if let Some(d) = domains.iter_mut().find(|d| d.id == domain_id) {
            d.fault_count = d.fault_count.saturating_add(1);
        }
    }

    // Boot critical failure during boot phase: treat as boot failure (panic) so that
    // oneboot can count/trigger recovery path. App faults must not panic the system.
    if boot_critical && BOOT_PHASE.load(Ordering::SeqCst) {
        panic!(
            "boot-critical domain fault: domain={} kind={:?}",
            domain_id, kind
        );
    }

    match policy {
        FaultPolicy::Kill => {
            let _ = stop_domain(domain_id);
        }
        FaultPolicy::Restart => {
            // Stage 4: services are restartable by policy. For managed ServiceDomain,
            // restart means re-spawn a fresh domain/task and re-register it.
            if !crate::service::restart_by_domain(domain_id) {
                let _ = restart_domain(domain_id);
            }
        }
        FaultPolicy::Quarantine => {
            let _ = quarantine_domain(domain_id);
        }
        FaultPolicy::Escalate => {
            // v2: escalation policy is a placeholder; quarantine for now.
            let _ = quarantine_domain(domain_id);
        }
    }
}

fn current_domain_kind() -> Option<DomainKind> {
    Some(current_domain_kind_or_kernel())
}

const fn domain_kind_to_u32(kind: DomainKind) -> u32 {
    match kind {
        DomainKind::Kernel => 0,
        DomainKind::SystemService => 1,
        DomainKind::App => 2,
    }
}

fn domain_kind_from_u32(v: u32) -> DomainKind {
    match v {
        1 => DomainKind::SystemService,
        2 => DomainKind::App,
        _ => DomainKind::Kernel,
    }
}

fn domain_kind_by_id(id: DomainId) -> Option<DomainKind> {
    let domains = DOMAINS.lock();
    domains.iter().find(|d| d.id == id).map(|d| d.kind)
}

fn is_app_domain(id: DomainId) -> bool {
    domain_kind_fast_get(id) == DomainKind::App
}

pub fn spawn_app_domain(
    app_name: &str,
    user: &str,
    app_workspace: &str,
    caps_mask: u64,
) -> Result<DomainId, SandboxError> {
    // Domain scope uses the owner string ("admin"), not the prefixed workspace name.
    let user_owner = leak_workspace_str(user);
    let app_owner = parse_workspace(app_workspace)
        .and_then(|ws| match ws {
            WorkspaceKind::App(name) => Some(name),
            _ => None,
        })
        .ok_or(SandboxError::InvalidScope)?;
    let app_owner = leak_workspace_str(app_owner);
    let app_data_ws = alloc::format!("LAD:{}", app_owner);
    let app_data_owner = parse_workspace(&app_data_ws)
        .and_then(|ws| match ws {
            WorkspaceKind::LibraryAppData(name) => Some(name),
            _ => None,
        })
        .ok_or(SandboxError::InvalidScope)?;
    let app_data_owner = leak_workspace_str(app_data_owner);

    let mut domains = DOMAINS.lock();
    let mut next = 3u32;
    for d in domains.iter() {
        next = next.max(d.id.saturating_add(1));
    }
    let id = next;

    let mut scope = Vec::new();
    scope.push(WorkspaceKind::App(app_owner));
    scope.push(WorkspaceKind::LibraryAppData(app_data_owner));

    let asid = crate::mmu::addrspace::new_app_address_space();
    domains.push(Domain {
        id,
        kind: DomainKind::App,
        owner: user.into(),
        owner_admin: false,
        name: app_name.into(),
        workspace_scope: scope,
        caps: Vec::new(),
        addr_space: asid,
        fault_policy: FaultPolicy::Kill,
        boot_critical: false,
        state: DomainState::Created,
        fault_count: 0,
        restart_count: 0,
    });
    domain_kind_fast_set(id, DomainKind::App);
    drop(domains);
    crate::ipc::register_domain(id);

    // v3+ hook: if/when we build an MMU-backed page table for this domain, it will be bound here.
    // For now we keep RegionsOnly backend and only enforce via region set checks.
    crate::mmu::addrspace::set_pt_root(asid, None);

    // AppDomain caps are granted strictly based on AppManifest/AppCapabilities.
    //
    // 注意：console/gpu 属于“非 workspace 资源”，这里通过 rights bits 表达 read/write。
    // v2 硬化：AppDomain 永远只读 App:<name> 包 workspace；永远不可写。
    let _ = grant_cap(
        id,
        Capability {
            cap_type: CapType::GoesRead,
            scope: WorkspaceKind::App(app_owner),
            rights: 0x1,
        },
    );
    // v2 最小实现：AppDomain 只读/可写其私有 Library AppData 区域（workspace= `LAD:<app>`）。
    let _ = grant_cap(
        id,
        Capability {
            cap_type: CapType::GoesRead,
            scope: WorkspaceKind::LibraryAppData(app_data_owner),
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        id,
        Capability {
            cap_type: CapType::GoesWrite,
            scope: WorkspaceKind::LibraryAppData(app_data_owner),
            rights: 0x2,
        },
    );

    if (caps_mask & crate::app::CAP_CONSOLE) != 0 {
        let _ = grant_cap(
            id,
            Capability {
                cap_type: CapType::Console,
                scope: WorkspaceKind::System,
                rights: CONSOLE_RIGHT_READ | CONSOLE_RIGHT_WRITE,
            },
        );
    }
    if (caps_mask & crate::app::CAP_GPU) != 0 {
        let _ = grant_cap(
            id,
            Capability {
                cap_type: CapType::GpuDraw,
                scope: WorkspaceKind::System,
                rights: 0x1,
            },
        );
    }
    if (caps_mask & crate::app::CAP_IPC) != 0 {
        let _ = grant_cap(
            id,
            Capability {
                cap_type: CapType::IpcSend,
                scope: WorkspaceKind::System,
                rights: 0x1,
            },
        );
        let _ = grant_cap(
            id,
            Capability {
                cap_type: CapType::IpcRecv,
                scope: WorkspaceKind::System,
                rights: 0x1,
            },
        );
    }
    Ok(id)
}

/// Minimal ServiceDomain spawn helper (Stage 1).
///
/// Services run in-kernel (no EL0) but may use a separate AddressSpace for isolation/testing.
pub fn spawn_service_domain(name: &str, user: &str) -> Result<DomainId, SandboxError> {
    let user_owner = leak_workspace_str(user);

    let mut domains = DOMAINS.lock();
    let mut next = 3u32;
    for d in domains.iter() {
        next = next.max(d.id.saturating_add(1));
    }
    let id = next;

    let mut scope = Vec::new();
    scope.push(WorkspaceKind::System);
    scope.push(WorkspaceKind::Library);
    scope.push(WorkspaceKind::Applications);
    scope.push(WorkspaceKind::User(user_owner));

    let asid = crate::mmu::addrspace::new_app_address_space();
    domains.push(Domain {
        id,
        kind: DomainKind::SystemService,
        owner: user.into(),
        owner_admin: context().user_is_admin,
        name: name.into(),
        workspace_scope: scope,
        caps: Vec::new(),
        addr_space: asid,
        fault_policy: FaultPolicy::Restart,
        boot_critical: false,
        state: DomainState::Created,
        fault_count: 0,
        restart_count: 0,
    });
    domain_kind_fast_set(id, DomainKind::SystemService);
    drop(domains);
    crate::ipc::register_domain(id);

    // Minimal caps: allow console I/O for demo services.
    let _ = grant_cap(
        id,
        Capability {
            cap_type: CapType::Console,
            scope: WorkspaceKind::System,
            rights: CONSOLE_RIGHT_READ | CONSOLE_RIGHT_WRITE,
        },
    );
    let _ = grant_cap(
        id,
        Capability {
            cap_type: CapType::IpcSend,
            scope: WorkspaceKind::System,
            rights: 0x1,
        },
    );
    let _ = grant_cap(
        id,
        Capability {
            cap_type: CapType::IpcRecv,
            scope: WorkspaceKind::System,
            rights: 0x1,
        },
    );
    Ok(id)
}

pub fn kill_domain(id: DomainId) {
    crate::sched::on_domain_killed(id);
    let removed = {
        let mut domains = DOMAINS.lock();
        if let Some(pos) = domains.iter().position(|d| d.id == id) {
            let name = domains[pos].name.clone();
            let asid = domains[pos].addr_space;
            domains.remove(pos);
            domain_kind_fast_clear(id);
            serial::log_line_args(format_args!(
                "sandbox: domain killed id={} name={}",
                id, name
            ));
            Some(asid)
        } else {
            None
        }
    };
    if let Some(asid) = removed {
        crate::ipc::unregister_domain(id);
        // Stage 1: address space lifecycle must be reclaimable.
        if asid != crate::mmu::addrspace::kernel_id() {
            crate::mmu::addrspace::destroy_address_space(asid);
        }
        serial::log_line("sandbox: kill_domain audit emit begin");
        crate::audit::emit_for_domain(
            id,
            crate::audit::EVENT_DOMAIN_KILL,
            "System",
            "domain_kill",
            id as u64,
            0,
        );
        serial::log_line("sandbox: kill_domain audit emit end");
    }
}

pub fn start_domain(id: DomainId) -> Result<(), SandboxError> {
    let mut domains = DOMAINS.lock();
    let Some(d) = domains.iter_mut().find(|d| d.id == id) else {
        return Err(SandboxError::InvalidScope);
    };
    if d.state == DomainState::Quarantined {
        return Err(SandboxError::PermissionDenied);
    }
    d.state = DomainState::Running;
    Ok(())
}

pub fn stop_domain(id: DomainId) -> Result<(), SandboxError> {
    let revoked = {
        let mut domains = DOMAINS.lock();
        let Some(d) = domains.iter_mut().find(|d| d.id == id) else {
            return Err(SandboxError::InvalidScope);
        };
        d.state = DomainState::Stopped;
        // v2: minimal “resource reclaim” semantics: drop cap handles from the domain.
        let revoked = d.caps.len() as u64;
        d.caps.clear();
        revoked
    };
    crate::sched::on_domain_stopped(id);
    serial::log_line("sandbox: stop_domain audit emit begin");
    crate::audit::emit(
        crate::audit::EVENT_CAP_REVOKE,
        "System",
        "domain_stop",
        id as u64,
        revoked,
    );
    serial::log_line("sandbox: stop_domain audit emit end");
    Ok(())
}

pub fn set_domain_regions(
    domain_id: DomainId,
    regions: Vec<MemRegion>,
) -> Result<(), SandboxError> {
    let mut domains = DOMAINS.lock();
    let Some(d) = domains.iter_mut().find(|d| d.id == domain_id) else {
        return Err(SandboxError::InvalidScope);
    };
    crate::mmu::addrspace::set_regions(d.addr_space, regions);
    Ok(())
}

pub fn validate_domain_ptr(ptr: *const u8, len: usize, write: bool) -> bool {
    let domain_id = current_domain();
    let (kind, asid) = {
        let domains = DOMAINS.lock();
        let Some(d) = domains.iter().find(|d| d.id == domain_id) else {
            return false;
        };
        (d.kind, d.addr_space)
    };

    let access = if write {
        crate::mmu::addrspace::Access::Write
    } else {
        crate::mmu::addrspace::Access::Read
    };
    let ok = crate::mmu::addrspace::check_user_ptr(asid, ptr, len, access);
    if !ok && kind == DomainKind::App {
        crate::mmu::addrspace::log_check_failure(asid, domain_id, ptr, len, access);
        // v2: unify “illegal memory access” semantics. Even before MMU-backed isolation,
        // out-of-region pointers are treated as InvalidMemoryAccess for AppDomain.
        fault(
            FaultKind::InvalidMemoryAccess,
            "pointer outside addressspace regions",
        );
    }
    ok
}

pub fn current_address_space() -> crate::mmu::addrspace::AddressSpaceId {
    let domains = DOMAINS.lock();
    domains
        .iter()
        .find(|d| d.id == current_domain())
        .map(|d| d.addr_space)
        .unwrap_or_else(crate::mmu::addrspace::kernel_id)
}

pub fn domain_address_space(id: DomainId) -> Option<crate::mmu::addrspace::AddressSpaceId> {
    let domains = DOMAINS.lock();
    domains.iter().find(|d| d.id == id).map(|d| d.addr_space)
}

fn scope_code(scope: WorkspaceKind<'_>) -> u64 {
    match scope {
        WorkspaceKind::System => 1,
        WorkspaceKind::Library => 2,
        WorkspaceKind::Applications => 3,
        WorkspaceKind::App(_) => 3, // App:* is under Applications umbrella
        WorkspaceKind::Users => 4,
        WorkspaceKind::User(_) => 5,
        WorkspaceKind::LibraryAppData(_) => 6,
        WorkspaceKind::Service(_) => 1, // Service:* is under System umbrella
    }
}

pub fn restart_domain(id: DomainId) -> Result<(), SandboxError> {
    {
        let mut domains = DOMAINS.lock();
        let Some(d) = domains.iter_mut().find(|d| d.id == id) else {
            return Err(SandboxError::InvalidScope);
        };
        d.restart_count = d.restart_count.saturating_add(1);
        d.state = DomainState::Running;
        // Note: caps are not automatically re-granted in v2 single-task model.
    }
    Ok(())
}

pub fn quarantine_domain(id: DomainId) -> Result<(), SandboxError> {
    let mut domains = DOMAINS.lock();
    let Some(d) = domains.iter_mut().find(|d| d.id == id) else {
        return Err(SandboxError::InvalidScope);
    };
    d.state = DomainState::Quarantined;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct DomainSummary {
    pub id: DomainId,
    pub kind: DomainKind,
    pub state: DomainState,
    pub boot_critical: bool,
    pub owner: String,
    pub owner_admin: bool,
    pub name: String,
    pub addr_space: crate::mmu::addrspace::AddressSpaceId,
    pub addr_space_backend: crate::mmu::addrspace::AddressSpaceBackend,
    pub addr_space_regions: usize,
    pub addr_space_pt_root: Option<u64>,
    pub fault_policy: FaultPolicy,
    pub fault_count: u32,
    pub restart_count: u32,
}

pub fn list_domains() -> Vec<DomainSummary> {
    let domains = DOMAINS.lock();
    domains
        .iter()
        .map(|d| DomainSummary {
            id: d.id,
            kind: d.kind,
            state: d.state,
            boot_critical: d.boot_critical,
            owner: d.owner.clone(),
            owner_admin: d.owner_admin,
            name: d.name.clone(),
            addr_space: d.addr_space,
            addr_space_backend: crate::mmu::addrspace::backend(d.addr_space),
            addr_space_regions: crate::mmu::addrspace::regions_len(d.addr_space),
            addr_space_pt_root: crate::mmu::addrspace::pt_root(d.addr_space),
            fault_policy: d.fault_policy,
            fault_count: d.fault_count,
            restart_count: d.restart_count,
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct DomainDetail {
    pub summary: DomainSummary,
    pub workspace_scope: Vec<WorkspaceKind<'static>>,
    pub caps: Vec<Capability>,
}

pub fn domain_detail_by_id(id: DomainId) -> Option<DomainDetail> {
    let domains = DOMAINS.lock();
    let d = domains.iter().find(|d| d.id == id)?.clone();
    drop(domains);
    let mut caps_out = Vec::new();
    for h in d.caps.iter().copied() {
        if let Some(cap) = cap_by_handle(h) {
            caps_out.push(cap);
        }
    }
    Some(DomainDetail {
        summary: DomainSummary {
            id: d.id,
            kind: d.kind,
            state: d.state,
            boot_critical: d.boot_critical,
            owner: d.owner.clone(),
            owner_admin: d.owner_admin,
            name: d.name.clone(),
            addr_space: d.addr_space,
            addr_space_backend: crate::mmu::addrspace::backend(d.addr_space),
            addr_space_regions: crate::mmu::addrspace::regions_len(d.addr_space),
            addr_space_pt_root: crate::mmu::addrspace::pt_root(d.addr_space),
            fault_policy: d.fault_policy,
            fault_count: d.fault_count,
            restart_count: d.restart_count,
        },
        workspace_scope: d.workspace_scope.clone(),
        caps: caps_out,
    })
}

pub fn domain_id_by_name(name: &str) -> Option<DomainId> {
    let domains = DOMAINS.lock();
    domains
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case(name))
        .map(|d| d.id)
}

fn grant_cap(domain_id: DomainId, cap: Capability) -> Result<CapHandle, SandboxError> {
    serial::log_line("sandbox: grant_cap enter");
    serial::log_line("sandbox: grant_cap locking CAPS");
    let handle: CapHandle = {
        let mut caps = CAPS.lock();
        serial::log_line("sandbox: grant_cap CAPS locked");
        let idx = caps.len();
        let gen = 1u32;
        caps.push((gen, cap));
        ((gen as u32) << 16) | (idx as u32 & 0xFFFF)
    };

    serial::log_line("sandbox: grant_cap locking DOMAINS");
    {
        let mut domains = DOMAINS.lock();
        serial::log_line("sandbox: grant_cap DOMAINS locked");
        let Some(d) = domains.iter_mut().find(|d| d.id == domain_id) else {
            return Err(SandboxError::InvalidScope);
        };
        d.caps.push(handle);
    }

    serial::log_line("sandbox: grant_cap ok");
    serial::log_line("sandbox: grant_cap audit emit begin");
    crate::audit::emit(
        crate::audit::EVENT_CAP_GRANT,
        "System",
        "cap_grant",
        cap.cap_type as u64,
        scope_code(cap.scope),
    );
    serial::log_line("sandbox: grant_cap audit emit end");
    Ok(handle)
}

fn cap_by_handle(handle: CapHandle) -> Option<Capability> {
    let idx = (handle & 0xFFFF) as usize;
    let gen = (handle >> 16) as u32;
    let caps = CAPS.lock();
    let (stored_gen, cap) = caps.get(idx).copied()?;
    (stored_gen == gen).then_some(cap)
}

fn domain_has_cap(domain_id: DomainId, cap_type: CapType, scope: WorkspaceKind<'_>) -> bool {
    // Avoid lock-order deadlocks (CAPS <-> DOMAINS) by copying the handle list first.
    let handles: Vec<CapHandle> = {
        let domains = DOMAINS.lock();
        let Some(d) = domains.iter().find(|d| d.id == domain_id) else {
            return false;
        };
        d.caps.clone()
    };
    for h in handles {
        let Some(cap) = cap_by_handle(h) else {
            continue;
        };
        if cap.cap_type != cap_type {
            continue;
        }
        if scope_matches(cap.scope, scope) {
            return true;
        }
    }
    false
}

fn scope_matches(granted: WorkspaceKind<'static>, want: WorkspaceKind<'_>) -> bool {
    match (granted, want) {
        (WorkspaceKind::System, WorkspaceKind::System) => true,
        (WorkspaceKind::System, WorkspaceKind::Service(_)) => true,
        (WorkspaceKind::Library, WorkspaceKind::Library) => true,
        (WorkspaceKind::Library, WorkspaceKind::LibraryAppData(_)) => true, // Library implies all per-app appdata
        (WorkspaceKind::Applications, WorkspaceKind::Applications) => true,
        (WorkspaceKind::Applications, WorkspaceKind::App(_)) => true, // Applications implies all App:* workspaces
        (WorkspaceKind::Users, WorkspaceKind::Users) => true,
        (WorkspaceKind::Users, WorkspaceKind::User(_)) => true, // v1: Users implies any User:<name> read/write by policy layer
        (WorkspaceKind::User(a), WorkspaceKind::User(b)) => a == b,
        (WorkspaceKind::LibraryAppData(a), WorkspaceKind::LibraryAppData(b)) => a == b,
        (WorkspaceKind::App(a), WorkspaceKind::App(b)) => a == b,
        (WorkspaceKind::Service(a), WorkspaceKind::Service(b)) => a == b,
        _ => false,
    }
}

pub fn parse_workspace<'a>(s: &'a str) -> Option<WorkspaceKind<'a>> {
    match s {
        "System" => Some(WorkspaceKind::System),
        "Library" => Some(WorkspaceKind::Library),
        "Applications" => Some(WorkspaceKind::Applications),
        "Users" => Some(WorkspaceKind::Users),
        _ => {
            let prefix = "User:";
            if let Some(rest) = s.strip_prefix(prefix) {
                // v1: allow user sub-workspaces like `User:alice/foo` but keep permission bound to owner `alice`.
                let owner = rest.split('/').next().unwrap_or(rest);
                if owner.is_empty() {
                    None
                } else {
                    Some(WorkspaceKind::User(owner))
                }
            } else if let Some(rest) = s.strip_prefix("LAD:") {
                let app = rest.split('/').next().unwrap_or(rest);
                if app.is_empty() {
                    None
                } else {
                    Some(WorkspaceKind::LibraryAppData(app))
                }
            } else if let Some(rest) = s.strip_prefix("App:") {
                // v2: allow app sub-workspaces like `App:Foo/bar` but keep scope bound to app name `Foo`.
                let app = rest.split('/').next().unwrap_or(rest);
                if app.is_empty() {
                    None
                } else {
                    Some(WorkspaceKind::App(app))
                }
            } else if let Some(rest) = s.strip_prefix("App#") {
                // v2 fallback form: `App#<seq>` is still an app workspace.
                let app = rest.split('/').next().unwrap_or(rest);
                if app.is_empty() {
                    None
                } else {
                    Some(WorkspaceKind::App(app))
                }
            } else if let Some(rest) = s.strip_prefix("Service:") {
                let svc = rest.split('/').next().unwrap_or(rest);
                if svc.is_empty() {
                    None
                } else {
                    Some(WorkspaceKind::Service(svc))
                }
            } else {
                None
            }
        }
    }
}

pub fn check_goes_read(workspace: WorkspaceKind<'_>) -> Result<(), SandboxError> {
    let ctx = context();
    match workspace {
        WorkspaceKind::System => Ok(()),
        WorkspaceKind::Service(_) => Ok(()),
        WorkspaceKind::Library => Ok(()),
        WorkspaceKind::LibraryAppData(_) => Ok(()),
        WorkspaceKind::Applications => Ok(()),
        WorkspaceKind::App(_) => Ok(()),
        WorkspaceKind::Users => {
            if ctx.user_is_admin {
                Ok(())
            } else {
                Err(SandboxError::PermissionDenied)
            }
        }
        WorkspaceKind::User(name) => {
            if ctx.user_is_admin {
                return Ok(());
            }
            let Some(current) = default_user_str(&ctx.default_user) else {
                return Err(SandboxError::PermissionDenied);
            };
            if current == name {
                Ok(())
            } else {
                Err(SandboxError::PermissionDenied)
            }
        }
    }
}

fn domain_in_scope(domain_id: DomainId, scope: WorkspaceKind<'_>) -> bool {
    let domains = DOMAINS.lock();
    let Some(d) = domains.iter().find(|d| d.id == domain_id) else {
        return false;
    };
    d.workspace_scope
        .iter()
        .copied()
        .any(|w| scope_matches(w, scope))
}

pub fn require_goes_read(
    workspace: WorkspaceKind<'_>,
    workspace_str: &str,
) -> Result<(), SandboxError> {
    let cur = current_domain();
    if !domain_in_scope(cur, workspace) {
        log_denied(CapType::GoesRead, workspace_str);
        if is_app_domain(cur) {
            fault(
                FaultKind::PolicyViolation,
                "goes_read outside workspace scope",
            );
        }
        return Err(SandboxError::InvalidScope);
    }
    if !domain_has_cap(cur, CapType::GoesRead, workspace) {
        log_denied(CapType::GoesRead, workspace_str);
        if is_app_domain(cur) {
            fault(FaultKind::IllegalCapability, "goes_read missing capability");
        }
        return Err(SandboxError::MissingCapability);
    }
    match check_goes_read(workspace) {
        Ok(()) => Ok(()),
        Err(e) => {
            if is_app_domain(cur) {
                fault(FaultKind::PolicyViolation, "goes_read policy denied");
            }
            Err(e)
        }
    }
}

pub fn can_goes_read_quiet(workspace_str: &str) -> bool {
    let Some(ws) = parse_workspace(workspace_str) else {
        return false;
    };
    // NOTE: this is intentionally "quiet" (no denied logs). It is used by GOES replay filtering,
    // which may probe many workspaces/objects during boot.
    let cur = current_domain();
    if !domain_in_scope(cur, ws) {
        return false;
    }
    if !domain_has_cap(cur, CapType::GoesRead, ws) {
        return false;
    }
    check_goes_read(ws).is_ok()
}

pub fn check_goes_write(workspace: WorkspaceKind<'_>) -> Result<(), SandboxError> {
    let ctx = context();

    // v2 硬化：AppDomain 只能写入其私有 AppData 区域（Library/AppData/<app>）。
    // 其他任意写操作都必须被拒绝，并触发 fault（由上层 require_goes_write 处理）。
    if current_domain_kind() == Some(DomainKind::App)
        && !matches!(workspace, WorkspaceKind::LibraryAppData(_))
    {
        return Err(SandboxError::PermissionDenied);
    }

    // SIP rules (hard).
    if matches!(workspace, WorkspaceKind::System) {
        if !ctx.recovery || ctx.sip_on {
            return Err(SandboxError::PermissionDenied);
        }
        return Ok(());
    }

    // v1 简化权限：
    // - Library：仅 admin 可写
    // - Applications：仅 admin 可写（install/remove 等）
    // - Users/User:<name>：只能写自己的 User:<name>；admin 可写 Users（用于测试/修复）
    match workspace {
        WorkspaceKind::Library | WorkspaceKind::Applications | WorkspaceKind::App(_) => {
            if ctx.user_is_admin {
                Ok(())
            } else {
                Err(SandboxError::PermissionDenied)
            }
        }
        WorkspaceKind::Service(_) => {
            if ctx.user_is_admin {
                Ok(())
            } else {
                Err(SandboxError::PermissionDenied)
            }
        }
        WorkspaceKind::LibraryAppData(_) => Ok(()),
        WorkspaceKind::Users => {
            if ctx.user_is_admin {
                Ok(())
            } else {
                Err(SandboxError::PermissionDenied)
            }
        }
        WorkspaceKind::User(name) => {
            if ctx.user_is_admin {
                return Ok(());
            }
            let Some(current) = default_user_str(&ctx.default_user) else {
                return Err(SandboxError::PermissionDenied);
            };
            if current == name {
                Ok(())
            } else {
                Err(SandboxError::PermissionDenied)
            }
        }
        WorkspaceKind::System => unreachable!(),
    }
}

pub fn require_goes_write(
    workspace: WorkspaceKind<'_>,
    workspace_str: &str,
) -> Result<(), SandboxError> {
    // Capability enforcement (Domain + CapabilityTable).
    let cur = current_domain();
    if !domain_in_scope(cur, workspace) {
        log_denied(CapType::GoesWrite, workspace_str);
        if is_app_domain(cur) {
            fault(
                FaultKind::PolicyViolation,
                "goes_write outside workspace scope",
            );
        }
        return Err(SandboxError::InvalidScope);
    }
    if !domain_has_cap(cur, CapType::GoesWrite, workspace) {
        log_denied(CapType::GoesWrite, workspace_str);
        if is_app_domain(cur) {
            fault(
                FaultKind::IllegalCapability,
                "goes_write missing capability",
            );
        }
        return Err(SandboxError::MissingCapability);
    }
    // Policy enforcement (SIP/User rules).
    match check_goes_write(workspace) {
        Ok(()) => Ok(()),
        Err(e) => {
            if is_app_domain(cur) {
                fault(FaultKind::PolicyViolation, "goes_write policy denied");
            }
            Err(e)
        }
    }
}

pub fn require_gpu_draw() -> Result<(), SandboxError> {
    let cur = current_domain();
    if !domain_has_cap(cur, CapType::GpuDraw, WorkspaceKind::System) {
        log_denied(CapType::GpuDraw, "GPU");
        if is_app_domain(cur) {
            fault(FaultKind::IllegalCapability, "gpu_draw missing capability");
        }
        return Err(SandboxError::MissingCapability);
    }
    Ok(())
}

pub fn require_ipc_send() -> Result<(), SandboxError> {
    let cur = current_domain();
    if !domain_has_cap(cur, CapType::IpcSend, WorkspaceKind::System) {
        log_denied(CapType::IpcSend, "IPC_SEND");
        if matches!(
            domain_kind_by_id(cur),
            Some(DomainKind::App | DomainKind::SystemService)
        ) {
            fault(FaultKind::IllegalCapability, "ipc_send without capability");
        }
        return Err(SandboxError::MissingCapability);
    }
    Ok(())
}

pub fn require_ipc_recv() -> Result<(), SandboxError> {
    let cur = current_domain();
    if !domain_has_cap(cur, CapType::IpcRecv, WorkspaceKind::System) {
        log_denied(CapType::IpcRecv, "IPC_RECV");
        if matches!(
            domain_kind_by_id(cur),
            Some(DomainKind::App | DomainKind::SystemService)
        ) {
            fault(FaultKind::IllegalCapability, "ipc_recv without capability");
        }
        return Err(SandboxError::MissingCapability);
    }
    Ok(())
}

pub fn require_console_write_service() -> Result<(), SandboxError> {
    let cur = current_domain();
    if current_domain_kind() != Some(DomainKind::SystemService) {
        log_denied(CapType::Console, "CONSOLE_WRITE(service_domain)");
        return Err(SandboxError::InvalidScope);
    }
    if !domain_has_console_rights(cur, CONSOLE_RIGHT_WRITE) {
        log_denied(CapType::Console, "CONSOLE_WRITE(service)");
        fault(
            FaultKind::IllegalCapability,
            "service console_write without capability",
        );
        return Err(SandboxError::MissingCapability);
    }
    Ok(())
}

pub fn caps_mask_for_current_domain() -> u64 {
    let domain_id = current_domain();
    // Avoid lock-order deadlocks by copying handle list first.
    let handles: Vec<CapHandle> = {
        let domains = DOMAINS.lock();
        let Some(d) = domains.iter().find(|d| d.id == domain_id) else {
            return 0;
        };
        d.caps.clone()
    };
    let mut mask = 0u64;
    for h in handles {
        let Some(cap) = cap_by_handle(h) else {
            continue;
        };
        match cap.cap_type {
            CapType::Console => mask |= crate::app::CAP_CONSOLE,
            CapType::GpuDraw => mask |= crate::app::CAP_GPU,
            CapType::IpcSend | CapType::IpcRecv => mask |= crate::app::CAP_IPC,
            _ => {}
        }
    }
    mask
}

fn domain_has_console_rights(domain_id: DomainId, rights: u32) -> bool {
    // Avoid lock-order deadlocks (CAPS <-> DOMAINS) by copying the handle list first.
    let handles: Vec<CapHandle> = {
        let domains = DOMAINS.lock();
        let Some(d) = domains.iter().find(|d| d.id == domain_id) else {
            return false;
        };
        d.caps.clone()
    };
    for h in handles {
        let Some(cap) = cap_by_handle(h) else {
            continue;
        };
        if cap.cap_type != CapType::Console {
            continue;
        }
        if (cap.rights & rights) == rights {
            return true;
        }
    }
    false
}

pub fn require_console_read() -> Result<(), SandboxError> {
    let cur = current_domain();
    // AppApi console I/O is only valid for AppDomain (sandboxed apps).
    // Shell/kernel use their own console paths.
    if current_domain_kind() != Some(DomainKind::App) {
        log_denied(CapType::Console, "CONSOLE_READ(domain)");
        return Err(SandboxError::InvalidScope);
    }
    if !domain_has_console_rights(cur, CONSOLE_RIGHT_READ) {
        log_denied(CapType::Console, "CONSOLE_READ");
        if is_app_domain(cur) {
            fault(
                FaultKind::IllegalCapability,
                "console_read without capability",
            );
        }
        return Err(SandboxError::MissingCapability);
    }
    Ok(())
}

pub fn require_console_write() -> Result<(), SandboxError> {
    let cur = current_domain();
    if current_domain_kind() != Some(DomainKind::App) {
        log_denied(CapType::Console, "CONSOLE_WRITE(domain)");
        return Err(SandboxError::InvalidScope);
    }
    if !domain_has_console_rights(cur, CONSOLE_RIGHT_WRITE) {
        log_denied(CapType::Console, "CONSOLE_WRITE");
        if is_app_domain(cur) {
            fault(
                FaultKind::IllegalCapability,
                "console_write without capability",
            );
        }
        return Err(SandboxError::MissingCapability);
    }
    Ok(())
}

fn default_user_str(raw: &[u8; 32]) -> Option<&str> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    if end == 0 {
        return None;
    }
    core::str::from_utf8(&raw[..end])
        .ok()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

fn is_admin_name(raw: &[u8; 32]) -> bool {
    default_user_str(raw) == Some("admin")
}

fn leak_workspace_str(s: &str) -> &'static str {
    // v1: single-user/single-domain; leak is acceptable for now.
    let mut owned = String::new();
    owned.push_str(s);
    Box::leak(owned.into_boxed_str())
}

pub fn log_denied(cap: CapType, workspace: &str) {
    serial::log_line_args(format_args!(
        "sandbox: denied cap={:?} workspace={}",
        cap, workspace
    ));
}
