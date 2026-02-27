#![cfg(target_os = "none")]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

use crate::sandbox::{self, DomainId};

pub mod registry;

pub const OPCODE_PING: u32 = 1;
pub const OPCODE_PONG: u32 = 2;
pub const OPCODE_NOTIFY_TEXT: u32 = 3;

const MAX_PAYLOAD: usize = 512;
const MAX_QUEUE_LEN: usize = 64;

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub src_domain: DomainId,
    pub dst_service: [u8; 32],
    pub opcode: u32,
    pub len: u32,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub header: Header,
    pub payload: Vec<u8>,
}

fn encode_name32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    let n = core::cmp::min(bytes.len(), out.len());
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcError {
    PermissionDenied,
    NoSuchService,
    NoSuchDomain,
    QueueFull,
    PayloadTooLarge,
    WouldBlock,
    Timeout,
}

struct Mailbox {
    domain_id: DomainId,
    q: Mutex<VecDeque<Message>>,
}

static MAILBOXES: Mutex<Vec<Mailbox>> = Mutex::new(Vec::new());

pub fn register_domain(domain_id: DomainId) {
    let mut mbs = MAILBOXES.lock();
    if mbs.iter().any(|m| m.domain_id == domain_id) {
        return;
    }
    mbs.push(Mailbox {
        domain_id,
        q: Mutex::new(VecDeque::new()),
    });
}

pub fn unregister_domain(domain_id: DomainId) {
    let mut mbs = MAILBOXES.lock();
    if let Some(pos) = mbs.iter().position(|m| m.domain_id == domain_id) {
        mbs.remove(pos);
    }
    registry::unregister_by_domain(domain_id);
}

pub fn send_to_domain(domain_id: DomainId, opcode: u32, payload: &[u8]) -> Result<(), IpcError> {
    if sandbox::require_ipc_send().is_err() {
        crate::audit::emit(
            crate::audit::EVENT_IPC_DENIED,
            "System",
            "ipc_send",
            domain_id as u64,
            opcode as u64,
        );
        return Err(IpcError::PermissionDenied);
    }
    if payload.len() > MAX_PAYLOAD {
        return Err(IpcError::PayloadTooLarge);
    }
    {
        let mbs = MAILBOXES.lock();
        let Some(mb) = mbs.iter().find(|m| m.domain_id == domain_id) else {
            return Err(IpcError::NoSuchDomain);
        };
        let mut q = mb.q.lock();
        if q.len() >= MAX_QUEUE_LEN {
            return Err(IpcError::QueueFull);
        }
        let src = sandbox::current_domain();
        q.push_back(Message {
            header: Header {
                src_domain: src,
                dst_service: [0u8; 32],
                opcode,
                len: payload.len().min(u32::MAX as usize) as u32,
            },
            payload: payload.to_vec(),
        });
        drop(q);
    }
    crate::audit::emit(
        crate::audit::EVENT_IPC_SEND,
        "System",
        "ipc_send",
        domain_id as u64,
        opcode as u64,
    );
    Ok(())
}

pub fn send_to_service(service: &str, opcode: u32, payload: &[u8]) -> Result<DomainId, IpcError> {
    let Some(domain_id) = registry::resolve(service) else {
        return Err(IpcError::NoSuchService);
    };
    if sandbox::require_ipc_send().is_err() {
        crate::audit::emit(
            crate::audit::EVENT_IPC_DENIED,
            "System",
            "ipc_send",
            domain_id as u64,
            opcode as u64,
        );
        return Err(IpcError::PermissionDenied);
    }
    if payload.len() > MAX_PAYLOAD {
        return Err(IpcError::PayloadTooLarge);
    }
    {
        let mbs = MAILBOXES.lock();
        let Some(mb) = mbs.iter().find(|m| m.domain_id == domain_id) else {
            return Err(IpcError::NoSuchDomain);
        };
        let mut q = mb.q.lock();
        if q.len() >= MAX_QUEUE_LEN {
            return Err(IpcError::QueueFull);
        }
        let src = sandbox::current_domain();
        q.push_back(Message {
            header: Header {
                src_domain: src,
                dst_service: encode_name32(service),
                opcode,
                len: payload.len().min(u32::MAX as usize) as u32,
            },
            payload: payload.to_vec(),
        });
        drop(q);
    }
    crate::audit::emit(
        crate::audit::EVENT_IPC_SEND,
        "System",
        "ipc_send",
        domain_id as u64,
        opcode as u64,
    );
    Ok(domain_id)
}

/// Kernel-internal IPC send to a service without requiring the caller to hold IPC capability.
///
/// Used for safe delegation patterns where an AppDomain capability (e.g. CONSOLE) is implemented
/// by forwarding work to a privileged ServiceDomain (e.g. oneconsole).
pub fn send_to_service_kernel(service: &str, opcode: u32, payload: &[u8]) -> Result<DomainId, IpcError> {
    let Some(domain_id) = registry::resolve(service) else {
        return Err(IpcError::NoSuchService);
    };
    if payload.len() > MAX_PAYLOAD {
        return Err(IpcError::PayloadTooLarge);
    }
    {
        let mbs = MAILBOXES.lock();
        let Some(mb) = mbs.iter().find(|m| m.domain_id == domain_id) else {
            return Err(IpcError::NoSuchDomain);
        };
        let mut q = mb.q.lock();
        if q.len() >= MAX_QUEUE_LEN {
            return Err(IpcError::QueueFull);
        }
        let src = sandbox::current_domain();
        q.push_back(Message {
            header: Header {
                src_domain: src,
                dst_service: encode_name32(service),
                opcode,
                len: payload.len().min(u32::MAX as usize) as u32,
            },
            payload: payload.to_vec(),
        });
        drop(q);
    }
    // Still emit audit, but do not treat this as an IPC capability check.
    crate::audit::emit(
        crate::audit::EVENT_IPC_SEND,
        "System",
        "ipc_send_kernel",
        domain_id as u64,
        opcode as u64,
    );
    Ok(domain_id)
}

pub fn recv(blocking: bool, timeout_ticks: Option<u64>) -> Result<Message, IpcError> {
    if sandbox::require_ipc_recv().is_err() {
        crate::audit::emit(crate::audit::EVENT_IPC_DENIED, "System", "ipc_recv", 0, 0);
        return Err(IpcError::PermissionDenied);
    }
    let domain_id = sandbox::current_domain();
    // Fast path (and also validates domain_id exists).
    let first = {
        let mbs = MAILBOXES.lock();
        let Some(mb) = mbs.iter().find(|m| m.domain_id == domain_id) else {
            return Err(IpcError::NoSuchDomain);
        };
        let mut q = mb.q.lock();
        q.pop_front()
    };
    if let Some(msg) = first {
        return Ok(msg);
    }
    if !blocking {
        return Err(IpcError::WouldBlock);
    }

    if let Some(ticks) = timeout_ticks {
        let deadline = crate::timer::ticks().saturating_add(ticks);
        loop {
            let got = {
                let mbs = MAILBOXES.lock();
                let Some(mb) = mbs.iter().find(|m| m.domain_id == domain_id) else {
                    return Err(IpcError::NoSuchDomain);
                };
                let mut q = mb.q.lock();
                q.pop_front()
            };
            if let Some(msg) = got {
                return Ok(msg);
            }
            if crate::timer::ticks() >= deadline {
                return Err(IpcError::Timeout);
            }
            crate::sched::sleep_ticks(1);
        }
    }

    loop {
        let got = {
            let mbs = MAILBOXES.lock();
            let Some(mb) = mbs.iter().find(|m| m.domain_id == domain_id) else {
                return Err(IpcError::NoSuchDomain);
            };
            let mut q = mb.q.lock();
            q.pop_front()
        };
        if let Some(msg) = got {
            return Ok(msg);
        }
        crate::sched::sleep_ticks(1);
    }
}

pub fn ping_service(service: &str, timeout_ticks: u64) -> Result<(DomainId, u64), IpcError> {
    let nonce = crate::timer::ticks();
    let payload = nonce.to_le_bytes();
    let domain_id = send_to_service(service, OPCODE_PING, &payload)?;
    let start = crate::timer::ticks();
    loop {
        let msg = recv(true, Some(timeout_ticks))?;
        if msg.header.opcode == OPCODE_PONG
            && msg.header.src_domain == domain_id
            && msg.payload.as_slice() == payload
        {
            let end = crate::timer::ticks();
            return Ok((domain_id, end.saturating_sub(start)));
        }
        // Ignore unrelated messages for now (v2 minimal).
    }
}
