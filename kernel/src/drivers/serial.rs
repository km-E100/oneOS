#[cfg(target_os = "uefi")]
mod uefi_serial {
    use uefi::boot;
    use uefi::proto::console::serial::Serial;

    /// 串口驱动：基于 UEFI Serial IO 协议，为内核 shell 提供输入。
    pub fn init() {
        crate::text::write_line("kernel: serial::init (UEFI Serial IO)");

        // 当前阶段仅探测串口是否存在，shell 仍优先走 UEFI stdin。
        if let Err(e) = boot::get_handle_for_protocol::<Serial>() {
            let _ = crate::text::write_line_args(format_args!(
                "serial: Serial IO probe failed: {:?}",
                e.status()
            ));
        } else {
            crate::text::write_line("serial: Serial IO available (not yet used by shell)");
        }
    }

    pub fn available() -> bool {
        // 暂时关闭串口输入路径，shell 使用 UEFI stdin。
        false
    }

    /// 读取一行（阻塞），遇到错误或未初始化则返回 None。
    pub fn read_line(buf: &mut [u8]) -> Option<usize> {
        let handle = match boot::get_handle_for_protocol::<Serial>() {
            Ok(h) => h,
            Err(e) => {
                crate::text::write_line_args(format_args!(
                    "serial: get_handle_for_protocol failed: {:?}",
                    e.status()
                ))
                .ok();
                return None;
            }
        };

        // 独占打开串口协议，读完一行后自动关闭。
        let mut serial = match boot::open_protocol_exclusive::<Serial>(handle) {
            Ok(p) => p,
            Err(e) => {
                crate::text::write_line_args(format_args!(
                    "serial: open_protocol_exclusive failed: {:?}",
                    e.status()
                ))
                .ok();
                return None;
            }
        };

        let mut filled = 0usize;

        for b in buf.iter_mut() {
            let byte = match read_byte_blocking(&mut serial) {
                Some(c) => c,
                None => return None,
            };
            *b = byte;
            filled += 1;
            if byte == b'\r' || byte == b'\n' {
                break;
            }
        }

        if filled == 0 {
            None
        } else {
            Some(filled)
        }
    }

    fn read_byte_blocking(serial: &mut Serial) -> Option<u8> {
        let mut buf = [0u8; 1];
        loop {
            match serial.read(&mut buf) {
                Ok(()) => return Some(buf[0]),
                Err(err) => {
                    let status = err.status();
                    let count = *err.data();
                    if count > 0 {
                        // 虽然返回了错误状态，但已经读到字节了，先消费。
                        return Some(buf[0]);
                    }
                    crate::text::write_line_args(format_args!("serial: read error: {:?}", status))
                        .ok();
                    return None;
                }
            }
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
mod raw_serial {
    use crate::display;

    const UART_BASE: usize = 0x0900_0000;
    const DR: usize = 0x00;
    const FR: usize = 0x18;
    const FR_TXFF: u32 = 1 << 5;
    const FR_RXFE: u32 = 1 << 4;

    pub fn init() {
        // QEMU virt 上默认是 PL011，无需额外初始化。
    }

    pub fn available() -> bool {
        true
    }

    pub fn read_line(buf: &mut [u8]) -> Option<usize> {
        let mut filled = 0usize;
        let len = buf.len();
        for b in buf.iter_mut() {
            let byte = read_byte_blocking()?;
            match byte {
                b'\r' | b'\n' => {
                    crate::mmu::switch::with_kernel_space(|| display::write_char('\n'));
                    break;
                }
                0x08 | 0x7f => {
                    if filled > 0 {
                        filled -= 1;
                        crate::mmu::switch::with_kernel_space(|| display::backspace());
                    }
                }
                _ => {
                    if filled < len {
                        *b = byte;
                        filled += 1;
                        crate::mmu::switch::with_kernel_space(|| display::write_char(byte as char));
                    }
                }
            }
        }
        if filled == 0 {
            None
        } else {
            Some(filled)
        }
    }

    fn read_byte_blocking() -> Option<u8> {
        loop {
            let fr = unsafe { core::ptr::read_volatile((UART_BASE + FR) as *const u32) };
            if (fr & FR_RXFE) == 0 {
                let dr = unsafe { core::ptr::read_volatile((UART_BASE + DR) as *const u32) };
                return Some((dr & 0xFF) as u8);
            }
        }
    }

    pub fn try_read_byte() -> Option<u8> {
        let fr = unsafe { core::ptr::read_volatile((UART_BASE + FR) as *const u32) };
        if (fr & FR_RXFE) == 0 {
            let dr = unsafe { core::ptr::read_volatile((UART_BASE + DR) as *const u32) };
            Some((dr & 0xFF) as u8)
        } else {
            None
        }
    }

    pub fn write_byte(byte: u8) {
        loop {
            let fr = unsafe { core::ptr::read_volatile((UART_BASE + FR) as *const u32) };
            if (fr & FR_TXFF) == 0 {
                break;
            }
        }
        unsafe {
            core::ptr::write_volatile((UART_BASE + DR) as *mut u32, byte as u32);
        }
    }

    pub fn write_str(s: &str) {
        for b in s.bytes() {
            match b {
                b'\n' => {
                    write_byte(b'\r');
                    write_byte(b'\n');
                }
                _ => write_byte(b),
            }
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod raw_serial {
    use crate::display;
    use core::arch::asm;

    const COM1: u16 = 0x3F8;
    const LSR: u16 = COM1 + 5;
    const THR: u16 = COM1 + 0;
    const RBR: u16 = COM1 + 0;
    const IER: u16 = COM1 + 1;
    const LCR: u16 = COM1 + 3;
    const FCR: u16 = COM1 + 2;
    const MCR: u16 = COM1 + 4;

    const LSR_DATA_READY: u8 = 1 << 0;
    const LSR_THR_EMPTY: u8 = 1 << 5;

    pub fn init() {
        unsafe {
            outb(IER, 0x00);
            outb(LCR, 0x80); // DLAB
            outb(THR, 0x01); // divisor low (115200)
            outb(IER, 0x00); // divisor high
            outb(LCR, 0x03); // 8N1
            outb(FCR, 0xC7); // enable FIFO, clear, 14-byte threshold
            outb(MCR, 0x0B); // IRQs enabled, RTS/DSR
        }
    }

    pub fn available() -> bool {
        true
    }

    pub fn read_line(buf: &mut [u8]) -> Option<usize> {
        let mut filled = 0usize;
        let len = buf.len();
        for b in buf.iter_mut() {
            let byte = read_byte_blocking()?;
            match byte {
                b'\r' | b'\n' => {
                    crate::mmu::switch::with_kernel_space(|| display::write_char('\n'));
                    break;
                }
                0x08 | 0x7f => {
                    if filled > 0 {
                        filled -= 1;
                        crate::mmu::switch::with_kernel_space(|| display::backspace());
                    }
                }
                _ => {
                    if filled < len {
                        *b = byte;
                        filled += 1;
                        crate::mmu::switch::with_kernel_space(|| display::write_char(byte as char));
                    }
                }
            }
        }
        if filled == 0 {
            None
        } else {
            Some(filled)
        }
    }

    fn read_byte_blocking() -> Option<u8> {
        loop {
            let lsr = unsafe { inb(LSR) };
            if (lsr & LSR_DATA_READY) != 0 {
                return Some(unsafe { inb(RBR) });
            }
        }
    }

    pub fn try_read_byte() -> Option<u8> {
        let lsr = unsafe { inb(LSR) };
        if (lsr & LSR_DATA_READY) != 0 {
            Some(unsafe { inb(RBR) })
        } else {
            None
        }
    }

    pub fn write_byte(byte: u8) {
        loop {
            let lsr = unsafe { inb(LSR) };
            if (lsr & LSR_THR_EMPTY) != 0 {
                break;
            }
        }
        unsafe { outb(THR, byte) };
    }

    pub fn write_str(s: &str) {
        for b in s.bytes() {
            match b {
                b'\n' => {
                    write_byte(b'\r');
                    write_byte(b'\n');
                }
                _ => write_byte(b),
            }
        }
    }

    unsafe fn inb(port: u16) -> u8 {
        let mut value: u8;
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
        value
    }

    unsafe fn outb(port: u16, value: u8) {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[cfg(target_os = "none")]
pub use raw_serial::*;
#[cfg(target_os = "uefi")]
pub use uefi_serial::*;

#[cfg(target_os = "none")]
use core::sync::atomic::{AtomicBool, Ordering};

/// 启动阶段把串口日志同步到 framebuffer（QEMU 窗口），进入系统后可关闭。
#[cfg(target_os = "none")]
static MIRROR_LOG_TO_DISPLAY: AtomicBool = AtomicBool::new(true);

#[cfg(target_os = "none")]
pub fn set_log_mirror_to_display(enabled: bool) {
    MIRROR_LOG_TO_DISPLAY.store(enabled, Ordering::Relaxed);
}

#[cfg(target_os = "uefi")]
pub fn log_line(_s: &str) {}

#[cfg(target_os = "uefi")]
pub fn log_line_args(_args: core::fmt::Arguments) {}

#[cfg(not(any(target_os = "uefi", target_os = "none")))]
pub fn log_line(_s: &str) {}

#[cfg(not(any(target_os = "uefi", target_os = "none")))]
pub fn log_line_args(_args: core::fmt::Arguments) {}

#[cfg(not(any(target_os = "uefi", target_os = "none")))]
pub fn set_log_mirror_to_display(_enabled: bool) {}

#[cfg(target_os = "none")]
pub fn log_line(s: &str) {
    raw_serial::write_str(s);
    raw_serial::write_str("\r\n");
    if MIRROR_LOG_TO_DISPLAY.load(Ordering::Relaxed) {
        // IRQ-safe: avoid deadlocks if a timer interrupt logs while foreground holds the display lock.
        crate::mmu::switch::with_kernel_space(|| {
            let _ = crate::display::try_write_line(s);
        });
    }
}

#[cfg(target_os = "none")]
pub fn log_line_args(args: core::fmt::Arguments) {
    use core::fmt::Write;

    struct SerialWriter;
    impl Write for SerialWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            raw_serial::write_str(s);
            Ok(())
        }
    }

    let mut writer = SerialWriter;
    let _ = writer.write_fmt(args);
    raw_serial::write_str("\r\n");
    if MIRROR_LOG_TO_DISPLAY.load(Ordering::Relaxed) {
        // IRQ-safe: avoid deadlocks if a timer interrupt logs while foreground holds the display lock.
        crate::mmu::switch::with_kernel_space(|| {
            let _ = crate::display::try_write_line_args(args);
        });
    }
}

#[cfg(target_os = "none")]
pub fn poll_key() -> Option<crate::console::KeyEvent> {
    let byte = try_read_byte()?;
    match byte {
        b'\r' | b'\n' => Some(crate::console::KeyEvent::Enter),
        b'\t' => Some(crate::console::KeyEvent::Tab),
        0x08 | 0x7f => Some(crate::console::KeyEvent::Backspace),
        b if b.is_ascii() => Some(crate::console::KeyEvent::Char(b as char)),
        _ => None,
    }
}
