#![cfg(target_os = "none")]

extern crate alloc;

use crate::console::KeyEvent;
use crate::sandbox;
use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleError {
    PermissionDenied,
    InputFailed,
}

pub fn write_str(s: &str) -> Result<(), ConsoleError> {
    sandbox::require_console_write().map_err(|_| ConsoleError::PermissionDenied)?;
    let session = crate::console::mgr::ensure_session_for_current_domain();
    let seq = crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, s.as_bytes());
    // Line-buffered/conditional flush: only block when a line boundary is printed.
    if s.as_bytes().contains(&b'\n') {
        crate::console::mgr::flush(seq);
    }
    Ok(())
}

pub fn write_line(s: &str) -> Result<(), ConsoleError> {
    sandbox::require_console_write().map_err(|_| ConsoleError::PermissionDenied)?;
    let session = crate::console::mgr::ensure_session_for_current_domain();
    let _ = crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, s.as_bytes());
    let seq = crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, b"\n");
    crate::console::mgr::flush(seq);
    Ok(())
}

pub fn write_line_args(args: fmt::Arguments) -> Result<(), ConsoleError> {
    sandbox::require_console_write().map_err(|_| ConsoleError::PermissionDenied)?;
    let session = crate::console::mgr::ensure_session_for_current_domain();
    let s = alloc::format!("{}", args);
    let _ = crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, s.as_bytes());
    let seq = crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, b"\n");
    crate::console::mgr::flush(seq);
    Ok(())
}

pub fn read_line(buf: &mut [u8]) -> Result<usize, ConsoleError> {
    sandbox::require_console_read().map_err(|_| ConsoleError::PermissionDenied)?;
    let session = crate::console::mgr::ensure_session_for_current_domain();
    crate::console::mgr::flush(crate::console::mgr::last_seq_for_session(session));
    read_line_impl(session, buf).ok_or(ConsoleError::InputFailed)
}

fn read_line_impl(session: crate::console::mgr::SessionId, buf: &mut [u8]) -> Option<usize> {
    let mut len = 0usize;
    loop {
        let evt = match crate::console::mgr::read_key(session, true) {
            Some(e) => e,
            None => continue,
        };
        match evt {
            KeyEvent::Char(ch) => {
                if len < buf.len() && ch.is_ascii() {
                    buf[len] = ch as u8;
                    len += 1;
                    let one = [ch as u8];
                    let _ = crate::console::mgr::write(
                        session,
                        crate::console::mgr::STREAM_STDOUT,
                        &one,
                    );
                }
            }
            KeyEvent::Backspace => {
                if len > 0 {
                    len -= 1;
                    let _ = crate::console::mgr::backspace(session, 1);
                }
            }
            KeyEvent::Enter => {
                let s =
                    crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, b"\n");
                crate::console::mgr::flush(s);
                break;
            }
            KeyEvent::Tab => {
                if len < buf.len() {
                    buf[len] = b'\t';
                    len += 1;
                    let _ = crate::console::mgr::write(
                        session,
                        crate::console::mgr::STREAM_STDOUT,
                        b"\t",
                    );
                }
            }
        }
    }
    Some(len)
}
