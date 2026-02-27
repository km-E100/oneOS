use core::fmt;
#[cfg(target_os = "uefi")]
use core::ptr;
#[cfg(target_os = "uefi")]
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::display;

#[cfg(target_os = "uefi")]
use uefi::data_types::CStr16;
#[cfg(target_os = "uefi")]
use uefi::proto::console::text::Output;
#[cfg(target_os = "uefi")]
use uefi::Error;

#[cfg(target_os = "uefi")]
pub type Status = uefi::Status;
#[cfg(not(target_os = "uefi"))]
pub type Status = ();

#[cfg(target_os = "uefi")]
static STDOUT_PTR: AtomicPtr<Output> = AtomicPtr::new(ptr::null_mut());

/// 在启动阶段缓存 stdout。
#[cfg(target_os = "uefi")]
pub fn init(stdout: &mut Output) {
    STDOUT_PTR.store(stdout as *mut Output, Ordering::SeqCst);
}

/// 写一行纯文本。
pub fn write_line(line: &str) {
    let _ = write_fmt(format_args!("{line}\r\n"));
}

/// 写格式化参数。
pub fn write_fmt(args: fmt::Arguments) -> Result<(), Status> {
    let mut buf = ArrayString::<512>::new();
    let _ = fmt::write(&mut buf, args);
    let text = buf.as_str();
    let res = write_raw(text);
    display::write_str(text);
    res
}

/// 写一行格式化参数（自动追加 CRLF）。
pub fn write_line_args(args: fmt::Arguments) -> Result<(), Status> {
    let mut buf = ArrayString::<512>::new();
    let _ = fmt::write(&mut buf, args);
    let _ = buf.push_str("\r\n");
    let text = buf.as_str();
    let res = write_raw(text);
    display::write_str(text);
    res
}

#[cfg(target_os = "uefi")]
fn write_raw(s: &str) -> Result<(), Status> {
    let ptr = STDOUT_PTR.load(Ordering::SeqCst);
    if ptr.is_null() {
        return Ok(()); // 未初始化时静默 no-op，保证 panic 安全
    }

    // 简易 UTF-16 缓冲，过长时截断
    let mut utf16_buf = [0u16; 512];
    let cstr = match CStr16::from_str_with_buf(s, &mut utf16_buf) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };

    unsafe {
        (*ptr)
            .output_string(cstr)
            .map(|_| ())
            .map_err(|e: Error<_>| e.status())
    }
}

#[cfg(not(target_os = "uefi"))]
fn write_raw(_s: &str) -> Result<(), Status> {
    Ok(())
}

/// 简易的可变长字符串缓冲（无分配）。
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

    fn push_str(&mut self, s: &str) -> Result<(), ()> {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > N {
            return Err(());
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

impl<const N: usize> fmt::Write for ArrayString<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str(s).map_err(|_| fmt::Error)
    }
}
