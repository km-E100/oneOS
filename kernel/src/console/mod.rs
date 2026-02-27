#[cfg(target_os = "none")]
use crate::{display, drivers::serial, virtio};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEvent {
    Char(char),
    Backspace,
    Enter,
    Tab,
}

pub trait ConsoleOut {
    fn write_str(&mut self, s: &str);
    fn write_char(&mut self, ch: char);
    fn backspace(&mut self);
    fn clear(&mut self);
}

pub trait ConsoleIn {
    fn poll_key(&mut self) -> Option<KeyEvent>;
}

#[cfg(target_os = "none")]
pub mod line;

#[cfg(target_os = "none")]
pub mod mgr;

#[cfg(target_os = "none")]
pub struct FramebufferOut;

#[cfg(target_os = "none")]
impl ConsoleOut for FramebufferOut {
    fn write_str(&mut self, s: &str) {
        display::write_str(s);
    }

    fn write_char(&mut self, ch: char) {
        display::write_char(ch);
    }

    fn backspace(&mut self) {
        display::backspace();
    }

    fn clear(&mut self) {
        display::clear();
    }
}

#[cfg(target_os = "none")]
pub struct RawInput {
    prefer_virtio: bool,
}

#[cfg(target_os = "none")]
impl RawInput {
    pub fn new() -> Self {
        Self {
            prefer_virtio: virtio::keyboard::available(),
        }
    }

    pub fn set_prefer_virtio(&mut self, enabled: bool) {
        self.prefer_virtio = enabled;
    }
}

#[cfg(target_os = "none")]
impl ConsoleIn for RawInput {
    fn poll_key(&mut self) -> Option<KeyEvent> {
        if self.prefer_virtio {
            if let Some(evt) = virtio::keyboard::poll_key() {
                return Some(evt);
            }
        }
        serial::poll_key()
    }
}
