#![cfg(target_os = "none")]

extern crate alloc;

use alloc::string::String;
use spin::Mutex;

pub const EVENT_CAP_GRANT: u32 = 1;
pub const EVENT_CAP_REVOKE: u32 = 2;
pub const EVENT_WRITE: u32 = 3;
pub const EVENT_USER_CREATE: u32 = 4;
pub const EVENT_USER_DISABLE: u32 = 5;
pub const EVENT_USER_ENABLE: u32 = 6;
pub const EVENT_USER_SWITCH: u32 = 7;
pub const EVENT_APP_INSTALL: u32 = 8;
pub const EVENT_APP_REMOVE: u32 = 9;
pub const EVENT_APP_RUN: u32 = 10;
pub const EVENT_APP_STOP: u32 = 11;
pub const EVENT_SIP_SET: u32 = 12;
pub const EVENT_DOMAIN_FAULT: u32 = 13;
pub const EVENT_DOMAIN_KILL: u32 = 14;
pub const EVENT_IPC_SEND: u32 = 15;
pub const EVENT_IPC_DENIED: u32 = 16;

const MAX_PENDING: usize = 256;

#[derive(Clone, Copy)]
struct PendingEvent {
    offender_domain_id: u32,
    event: u32,
    arg0: u64,
    arg1: u64,
    name32: [u8; 32],
    target_ws32: [u8; 32],
}

impl PendingEvent {
    const ZERO: PendingEvent = PendingEvent {
        offender_domain_id: 0,
        event: 0,
        arg0: 0,
        arg1: 0,
        name32: [0u8; 32],
        target_ws32: [0u8; 32],
    };
}

struct Ring {
    buf: [PendingEvent; MAX_PENDING],
    head: usize,
    tail: usize,
    len: usize,
}

impl Ring {
    const fn new() -> Self {
        Self {
            buf: [PendingEvent::ZERO; MAX_PENDING],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    fn push(&mut self, ev: PendingEvent) {
        if self.len == MAX_PENDING {
            // Drop oldest.
            self.tail = (self.tail + 1) % MAX_PENDING;
            self.len = MAX_PENDING - 1;
        }
        self.buf[self.head] = ev;
        self.head = (self.head + 1) % MAX_PENDING;
        self.len += 1;
    }

    fn pop(&mut self) -> Option<PendingEvent> {
        if self.len == 0 {
            return None;
        }
        let ev = self.buf[self.tail];
        self.tail = (self.tail + 1) % MAX_PENDING;
        self.len -= 1;
        Some(ev)
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }
}

static PENDING: Mutex<Ring> = Mutex::new(Ring::new());

fn current_user() -> Option<String> {
    let ctx = crate::sandbox::context();
    let end = ctx
        .default_user
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(ctx.default_user.len());
    if end == 0 {
        return None;
    }
    core::str::from_utf8(&ctx.default_user[..end])
        .ok()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

fn choose_audit_workspace_quiet() -> Option<String> {
    let user = current_user()?;
    let mut ws = String::from("User:");
    ws.push_str(&user);
    if let Some(k) = crate::sandbox::parse_workspace(&ws) {
        if crate::sandbox::can_goes_write_quiet(k) {
            return Some(ws);
        }
    }
    if crate::sandbox::can_goes_write_quiet(crate::sandbox::WorkspaceKind::Users) {
        return Some(String::from("Users"));
    }
    None
}

fn try_append(ws: &str, ev: PendingEvent) -> Result<(), crate::goes::writer::WriteError> {
    let mut payload = [0u8; 128];
    payload[0..4].copy_from_slice(&1u32.to_le_bytes());
    payload[4..8].copy_from_slice(&ev.event.to_le_bytes());
    payload[8..12].copy_from_slice(&(ev.offender_domain_id as u32).to_le_bytes());
    payload[12..16].copy_from_slice(&0u32.to_le_bytes());
    payload[16..24].copy_from_slice(&ev.arg0.to_le_bytes());
    payload[24..32].copy_from_slice(&ev.arg1.to_le_bytes());
    payload[32..64].copy_from_slice(&ev.name32);
    payload[64..96].copy_from_slice(&ev.target_ws32);
    payload[96..128].copy_from_slice(&crate::goes::records::encode_name32(ws));
    crate::goes::writer::append_record(ws, crate::goes::records::RECORD_AUDIT_EVENT_V1, &payload)
        .map(|_| ())
}

pub fn try_flush() {
    if crate::sandbox::in_boot_phase() {
        return;
    }
    let pending_len = {
        let ring = PENDING.lock();
        ring.len
    };
    if pending_len == 0 {
        return;
    }

    // Flush as Shell domain to avoid offender-domain recursion.
    let prev = crate::sandbox::current_domain();
    if prev != 2 {
        crate::sandbox::set_current_domain(2);
    }

    let Some(ws) = choose_audit_workspace_quiet() else {
        if prev != 2 {
            crate::sandbox::set_current_domain(prev);
        }
        return;
    };

    crate::drivers::serial::log_line_args(format_args!(
        "audit: try_flush begin (pending={}, ws={})",
        pending_len, ws
    ));

    loop {
        let ev = {
            let mut ring = PENDING.lock();
            ring.pop()
        };
        let Some(ev) = ev else { break };
        match try_append(&ws, ev) {
            Ok(()) => {}
            Err(_) => {
                // If GOES isn't ready yet, keep the event for later.
                let mut ring = PENDING.lock();
                ring.push(ev);
                break;
            }
        }
    }

    let remaining = {
        let ring = PENDING.lock();
        ring.len
    };
    crate::drivers::serial::log_line_args(format_args!(
        "audit: try_flush end (remaining={})",
        remaining
    ));

    if prev != 2 {
        crate::sandbox::set_current_domain(prev);
    }
}

pub fn emit(event: u32, target_ws: &str, name: &str, arg0: u64, arg1: u64) {
    emit_for_domain(
        crate::sandbox::current_domain(),
        event,
        target_ws,
        name,
        arg0,
        arg1,
    );
}

pub fn emit_for_domain(
    offender_domain_id: u32,
    event: u32,
    target_ws: &str,
    name: &str,
    arg0: u64,
    arg1: u64,
) {
    let ev = PendingEvent {
        offender_domain_id,
        event,
        arg0,
        arg1,
        name32: crate::goes::records::encode_name32(name),
        target_ws32: crate::goes::records::encode_name32(target_ws),
    };

    // During boot or before GOES is ready, do not attempt writes (avoid recursion + slowdowns).
    if crate::sandbox::in_boot_phase() {
        PENDING.lock().push(ev);
        return;
    }

    let prev = crate::sandbox::current_domain();
    if prev != 2 {
        crate::sandbox::set_current_domain(2);
    }

    let Some(ws) = choose_audit_workspace_quiet() else {
        PENDING.lock().push(ev);
        if prev != 2 {
            crate::sandbox::set_current_domain(prev);
        }
        return;
    };

    if try_append(&ws, ev).is_err() {
        PENDING.lock().push(ev);
    }

    if prev != 2 {
        crate::sandbox::set_current_domain(prev);
    }
}
