#![cfg(target_os = "none")]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use spin::Mutex;

use crate::console::KeyEvent;
use crate::sandbox::DomainId;

pub type SessionId = u32;

pub use oneos_service::ConsoleOutHeader;

// Output stream identifiers (minimal).
pub const STREAM_STDOUT: u32 = 1;
pub const STREAM_STDERR: u32 = 2;

// Output operations (TTY semantics; backend decides how to render).
pub const OP_WRITE: u32 = 0;
pub const OP_BACKSPACE: u32 = 1;
pub const OP_CLEAR: u32 = 2;

struct Session {
    id: SessionId,
    owner_domain: DomainId,
    input: VecDeque<KeyEvent>,
    out: VecDeque<OutputRecord>,
    last_write_seq: u64,
}

struct OutputRecord {
    hdr: ConsoleOutHeader,
    payload: Vec<u8>,
}

const MAX_OUTPUT_QUEUE: usize = 1024;
const MAX_INPUT_QUEUE: usize = 256;
const CHUNK: usize = 128;

static NEXT_SESSION: AtomicU32 = AtomicU32::new(1);
static FOREGROUND: AtomicU32 = AtomicU32::new(0);
static BACKEND_DOMAIN: AtomicU32 = AtomicU32::new(0);
static INPUT_ROUTER_STARTED: AtomicU32 = AtomicU32::new(0);

static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);
static ACKED_SEQ: AtomicU64 = AtomicU64::new(0);

static SESSIONS: Mutex<Vec<Session>> = Mutex::new(Vec::new());
static DOMAIN_SESSIONS: Mutex<Vec<(DomainId, SessionId)>> = Mutex::new(Vec::new());

pub fn start_input_router() {
    // 0 -> not started, 1 -> started
    if INPUT_ROUTER_STARTED
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    extern "C" fn router(_arg: usize) -> ! {
        // Always run in Kernel domain.
        crate::sandbox::set_current_domain(1);
        let mut input = crate::console::RawInput::new();
        loop {
            if let Some(evt) = crate::console::ConsoleIn::poll_key(&mut input) {
                push_input_to_foreground(evt);
            } else {
                crate::sched::yield_now();
            }
        }
    }
    let _ = crate::sched::spawn_domain_thread("console-in", 1, crate::sched::Priority::High, router, 0);
}

pub fn set_backend_domain(domain: DomainId) {
    BACKEND_DOMAIN.store(domain, Ordering::SeqCst);
}

pub fn backend_domain() -> DomainId {
    BACKEND_DOMAIN.load(Ordering::SeqCst)
}

pub fn is_backend_current_domain() -> bool {
    is_backend_caller()
}

fn is_backend_caller() -> bool {
    let cur = crate::sandbox::current_domain();
    cur != 0 && cur == BACKEND_DOMAIN.load(Ordering::SeqCst)
}

pub fn create_session(owner_domain: DomainId) -> SessionId {
    let id = NEXT_SESSION.fetch_add(1, Ordering::SeqCst).max(1);
    let mut sessions = SESSIONS.lock();
    sessions.push(Session {
        id,
        owner_domain,
        input: VecDeque::new(),
        out: VecDeque::new(),
        last_write_seq: 0,
    });
    id
}

pub fn close_session(id: SessionId) {
    {
        let mut dom_map = DOMAIN_SESSIONS.lock();
        dom_map.retain(|&(_d, s)| s != id);
    }
    let mut sessions = SESSIONS.lock();
    if let Some(pos) = sessions.iter().position(|s| s.id == id) {
        sessions.remove(pos);
    }
    // If the session was foreground, fall back to 0 (no input).
    if FOREGROUND.load(Ordering::SeqCst) == id {
        FOREGROUND.store(0, Ordering::SeqCst);
    }
}

pub fn bind_domain_session(domain: DomainId, session: SessionId) {
    let mut dom_map = DOMAIN_SESSIONS.lock();
    if let Some(e) = dom_map.iter_mut().find(|(d, _)| *d == domain) {
        e.1 = session;
        return;
    }
    dom_map.push((domain, session));
}

pub fn session_for_domain(domain: DomainId) -> Option<SessionId> {
    let dom_map = DOMAIN_SESSIONS.lock();
    dom_map.iter().find(|(d, _)| *d == domain).map(|x| x.1)
}

pub fn ensure_session_for_current_domain() -> SessionId {
    let dom = crate::sandbox::current_domain();
    if let Some(s) = session_for_domain(dom) {
        return s;
    }
    let s = create_session(dom);
    bind_domain_session(dom, s);
    s
}

pub fn set_foreground(session: SessionId) {
    FOREGROUND.store(session, Ordering::SeqCst);
}

pub fn foreground() -> SessionId {
    FOREGROUND.load(Ordering::SeqCst)
}

fn session_mut<'a>(sessions: &'a mut Vec<Session>, id: SessionId) -> Option<&'a mut Session> {
    sessions.iter_mut().find(|s| s.id == id)
}

fn total_out_len_locked(sessions: &Vec<Session>) -> usize {
    sessions.iter().map(|s| s.out.len()).sum()
}

fn push_out_record(session: SessionId, rec: OutputRecord) {
    let mut rec = Some(rec);
    loop {
        let mut sessions = SESSIONS.lock();
        if total_out_len_locked(&sessions) < MAX_OUTPUT_QUEUE {
            if let Some(s) = session_mut(&mut sessions, session) {
                let rec = rec.take().unwrap();
                s.last_write_seq = rec.hdr.seq;
                s.out.push_back(rec);
            }
            return;
        }
        drop(sessions);
        crate::sched::yield_now();
    }
}

pub fn write(session: SessionId, stream: u32, bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        return last_seq_for_session(session);
    }
    let mut off = 0usize;
    let mut last = 0u64;
    while off < bytes.len() {
        let n = core::cmp::min(bytes.len() - off, CHUNK);
        let seq = NEXT_SEQ.fetch_add(1, Ordering::SeqCst);
        let mut payload = Vec::with_capacity(n);
        payload.extend_from_slice(&bytes[off..off + n]);
        let hdr = ConsoleOutHeader {
            session,
            stream,
            op: OP_WRITE,
            len: n as u32,
            seq,
        };
        push_out_record(session, OutputRecord { hdr, payload });
        last = seq;
        off += n;
    }
    last
}

pub fn backspace(session: SessionId, count: u32) -> u64 {
    if count == 0 {
        return last_seq_for_session(session);
    }
    let seq = NEXT_SEQ.fetch_add(1, Ordering::SeqCst);
    let hdr = ConsoleOutHeader {
        session,
        stream: STREAM_STDOUT,
        op: OP_BACKSPACE,
        len: count,
        seq,
    };
    push_out_record(
        session,
        OutputRecord {
            hdr,
            payload: Vec::new(),
        },
    );
    seq
}

pub fn clear(session: SessionId) -> u64 {
    let seq = NEXT_SEQ.fetch_add(1, Ordering::SeqCst);
    let hdr = ConsoleOutHeader {
        session,
        stream: STREAM_STDOUT,
        op: OP_CLEAR,
        len: 0,
        seq,
    };
    push_out_record(
        session,
        OutputRecord {
            hdr,
            payload: Vec::new(),
        },
    );
    seq
}

pub fn flush(upto_seq: u64) {
    while ACKED_SEQ.load(Ordering::SeqCst) < upto_seq {
        crate::sched::sleep_ticks(1);
    }
}

pub fn acked_seq() -> u64 {
    ACKED_SEQ.load(Ordering::SeqCst)
}

pub fn last_seq_for_session(session: SessionId) -> u64 {
    let sessions = SESSIONS.lock();
    sessions
        .iter()
        .find(|s| s.id == session)
        .map(|s| s.last_write_seq)
        .unwrap_or(0)
}

pub fn push_input_to_foreground(evt: KeyEvent) {
    let fg = foreground();
    if fg == 0 {
        return;
    }
    let mut sessions = SESSIONS.lock();
    let Some(s) = session_mut(&mut sessions, fg) else {
        return;
    };
    if s.input.len() >= MAX_INPUT_QUEUE {
        // Drop oldest to keep system responsive.
        let _ = s.input.pop_front();
    }
    s.input.push_back(evt);
}

pub fn read_key(session: SessionId, blocking: bool) -> Option<KeyEvent> {
    loop {
        {
            let mut sessions = SESSIONS.lock();
            if let Some(s) = session_mut(&mut sessions, session) {
                if let Some(evt) = s.input.pop_front() {
                    return Some(evt);
                }
            } else {
                return None;
            }
        }
        if !blocking {
            return None;
        }
        crate::sched::yield_now();
    }
}

// -----------------------------------------------------------------------------
// Backend ABI (polled by UI service)

pub fn backend_recv(
    hdr: &mut ConsoleOutHeader,
    buf: &mut [u8],
    blocking: bool,
    timeout_ticks: u64,
) -> isize {
    if !is_backend_caller() {
        return -1;
    }
    let deadline = crate::timer::ticks().saturating_add(timeout_ticks);
    loop {
        let rec = {
            let mut sessions = SESSIONS.lock();
            let mut best_idx: Option<usize> = None;
            let mut best_seq: u64 = u64::MAX;
            for (i, s) in sessions.iter().enumerate() {
                if let Some(front) = s.out.front() {
                    if front.hdr.seq < best_seq {
                        best_seq = front.hdr.seq;
                        best_idx = Some(i);
                    }
                }
            }
            best_idx.and_then(|i| sessions.get_mut(i)?.out.pop_front())
        };
        if let Some(mut rec) = rec {
            // Copy header + payload into caller buffer.
            *hdr = rec.hdr;
            if rec.hdr.op == OP_WRITE {
                let n = core::cmp::min(buf.len(), rec.payload.len());
                buf[..n].copy_from_slice(&rec.payload[..n]);
                // If truncated, fix len to what we actually return.
                hdr.len = n as u32;
                rec.payload.clear();
                return n as isize;
            }
            // Non-bytes ops have no payload.
            return 0;
        }
        if !blocking {
            return -2;
        }
        if timeout_ticks != 0 && crate::timer::ticks() >= deadline {
            return -3;
        }
        crate::sched::sleep_ticks(1);
    }
}

pub fn backend_ack(seq: u64) -> isize {
    if !is_backend_caller() {
        return -1;
    }
    let mut cur = ACKED_SEQ.load(Ordering::SeqCst);
    while seq > cur {
        match ACKED_SEQ.compare_exchange_weak(cur, seq, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => break,
            Err(v) => cur = v,
        }
    }
    0
}
