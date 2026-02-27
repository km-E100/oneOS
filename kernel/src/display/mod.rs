use core::fmt;
use core::ptr;

use oneos_boot_proto::{FrameBufferFormat, FrameBufferInfo};
use spin::Mutex;

const CHAR_WIDTH: usize = 6;
const CHAR_HEIGHT: usize = 10;
const COLUMN_SPACING: usize = 1;
const LINE_SPACING: usize = 2;

// 字体像素缩放：每个 glyph 像素点绘制为 SCALE×SCALE 的方块。
// 提升“像素密度/清晰度”（代价是单字符占用像素更大、可显示列数减少）。
const FONT_SCALE: usize = 2;

static DISPLAY: Mutex<Option<DisplayState>> = Mutex::new(None);

#[inline]
fn with_framebuffer_mapped<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(target_os = "none")]
    {
        crate::mmu::switch::with_kernel_space(f)
    }
    #[cfg(not(target_os = "none"))]
    {
        f()
    }
}

pub fn init(info: &FrameBufferInfo) {
    if info.base == 0 || info.size == 0 {
        return;
    }
    if matches!(info.format, FrameBufferFormat::Unknown) {
        return;
    }
    let mut guard = DISPLAY.lock();
    *guard = Some(DisplayState::new(info));
    if let Some(state) = guard.as_mut() {
        state.clear();
    }
}

pub fn write_line(s: &str) {
    write_str(s);
    write_str("\n");
}

pub fn write_str(s: &str) {
    if let Some(state) = DISPLAY.lock().as_mut() {
        state.write_str(s);
    }
}

pub fn write_line_args(args: fmt::Arguments) {
    let mut buf = LineBuffer::<256>::new();
    let _ = fmt::write(&mut buf, args);
    write_line(buf.as_str());
}

pub fn write_char(ch: char) {
    let mut buf = [0u8; 4];
    let s = ch.encode_utf8(&mut buf);
    write_str(s);
}

pub fn backspace() {
    if let Some(state) = DISPLAY.lock().as_mut() {
        state.backspace();
    }
}

pub fn clear() {
    if let Some(state) = DISPLAY.lock().as_mut() {
        state.clear();
    }
}

/// Non-blocking write helpers for IRQ-safe logging.
///
/// These functions avoid deadlocks when called from interrupt context while the
/// foreground code holds the display lock. They return `true` if the write
/// succeeded, `false` if the display was unavailable or locked.
pub fn try_write_str(s: &str) -> bool {
    let Some(mut guard) = DISPLAY.try_lock() else {
        return false;
    };
    let Some(state) = guard.as_mut() else {
        return false;
    };
    state.write_str(s);
    true
}

pub fn try_write_line(s: &str) -> bool {
    let Some(mut guard) = DISPLAY.try_lock() else {
        return false;
    };
    let Some(state) = guard.as_mut() else {
        return false;
    };
    state.write_str(s);
    state.write_str("\n");
    true
}

pub fn try_write_line_args(args: fmt::Arguments) -> bool {
    let Some(mut guard) = DISPLAY.try_lock() else {
        return false;
    };
    let Some(state) = guard.as_mut() else {
        return false;
    };
    let mut buf = LineBuffer::<256>::new();
    let _ = fmt::write(&mut buf, args);
    state.write_str(buf.as_str());
    state.write_str("\n");
    true
}

pub fn try_backspace() -> bool {
    let Some(mut guard) = DISPLAY.try_lock() else {
        return false;
    };
    let Some(state) = guard.as_mut() else {
        return false;
    };
    state.backspace();
    true
}

struct DisplayState {
    base: *mut u8,
    width: usize,
    height: usize,
    stride: usize,
    bytes_per_pixel: usize,
    cursor_x: usize,
    cursor_y: usize,
    fg: [u8; 4],
}

unsafe impl Send for DisplayState {}
unsafe impl Sync for DisplayState {}

impl DisplayState {
    #[inline]
    const fn char_width_px() -> usize {
        CHAR_WIDTH * FONT_SCALE
    }

    #[inline]
    const fn char_height_px() -> usize {
        CHAR_HEIGHT * FONT_SCALE
    }

    #[inline]
    const fn column_spacing_px() -> usize {
        COLUMN_SPACING * FONT_SCALE
    }

    #[inline]
    const fn line_spacing_px() -> usize {
        LINE_SPACING * FONT_SCALE
    }

    fn new(info: &FrameBufferInfo) -> Self {
        let fg = color_bytes(info.format, 0xFF, 0xFF, 0xFF);
        Self {
            base: info.base as *mut u8,
            width: info.width as usize,
            height: info.height as usize,
            stride: info.stride as usize,
            bytes_per_pixel: 4,
            cursor_x: 0,
            cursor_y: 0,
            fg,
        }
    }

    fn stride_bytes(&self) -> usize {
        self.stride * self.bytes_per_pixel
    }

    fn clear(&mut self) {
        let size = self.height * self.stride_bytes();
        with_framebuffer_mapped(|| unsafe {
            ptr::write_bytes(self.base, 0, size);
        });
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    fn write_str(&mut self, s: &str) {
        for ch in s.chars() {
            match ch {
                '\r' => continue,
                '\n' => {
                    self.newline();
                }
                '\t' => {
                    for _ in 0..4 {
                        self.write_char(' ');
                    }
                }
                _ => self.write_char(ch),
            }
        }
    }

    fn write_char(&mut self, ch: char) {
        // Framebuffer may not be mapped in an AppDomain TTBR0; switch back to
        // kernel mappings for the actual pixel touches.
        with_framebuffer_mapped(|| {
            let char_w = Self::char_width_px();
            let char_h = Self::char_height_px();
            if self.cursor_x + char_w >= self.width {
                self.newline();
            }
            if self.cursor_y + char_h >= self.height {
                self.scroll();
            }

            let glyph = glyph_for(ch);
            for (row_idx, row_bits) in glyph.rows.iter().enumerate() {
                for col in 0..CHAR_WIDTH {
                    if (row_bits >> (CHAR_WIDTH - 1 - col)) & 1 == 1 {
                        let x0 = self.cursor_x + col * FONT_SCALE;
                        let y0 = self.cursor_y + row_idx * FONT_SCALE;
                        for dy in 0..FONT_SCALE {
                            let y = y0 + dy;
                            if y >= self.height {
                                break;
                            }
                            for dx in 0..FONT_SCALE {
                                let x = x0 + dx;
                                if x >= self.width {
                                    break;
                                }
                                self.write_pixel(x, y, true);
                            }
                        }
                    }
                }
            }
            self.cursor_x += char_w + Self::column_spacing_px();
        });
    }

    fn backspace(&mut self) {
        with_framebuffer_mapped(|| {
            let step = Self::char_width_px() + Self::column_spacing_px();
            if self.cursor_x >= step {
                self.cursor_x -= step;
            } else {
                // 简单处理：不跨行回退
                self.cursor_x = 0;
            }
            let x0 = self.cursor_x;
            let y0 = self.cursor_y;
            for row in 0..Self::char_height_px() {
                let y = y0 + row;
                if y >= self.height {
                    break;
                }
                for col in 0..step {
                    let x = x0 + col;
                    if x >= self.width {
                        break;
                    }
                    self.write_pixel(x, y, false);
                }
            }
        });
    }

    fn newline(&mut self) {
        self.cursor_x = 0;
        self.cursor_y += Self::char_height_px() + Self::line_spacing_px();
        if self.cursor_y + Self::char_height_px() >= self.height {
            self.scroll();
        }
    }

    fn scroll(&mut self) {
        let line_height = Self::char_height_px() + Self::line_spacing_px();
        if line_height >= self.height {
            self.clear();
            return;
        }
        let stride_bytes = self.stride_bytes();
        let move_bytes = (self.height - line_height) * stride_bytes;
        with_framebuffer_mapped(|| unsafe {
            ptr::copy(
                self.base.add(line_height * stride_bytes),
                self.base,
                move_bytes,
            );
            ptr::write_bytes(self.base.add(move_bytes), 0, line_height * stride_bytes);
        });
        if self.cursor_y >= line_height {
            self.cursor_y -= line_height;
        } else {
            self.cursor_y = 0;
        }
    }

    fn write_pixel(&mut self, x: usize, y: usize, on: bool) {
        if x >= self.width || y >= self.height {
            return;
        }
        let offset = y * self.stride + x;
        let ptr = unsafe { self.base.add(offset * self.bytes_per_pixel) };
        if on {
            with_framebuffer_mapped(|| unsafe {
                ptr::copy_nonoverlapping(self.fg.as_ptr(), ptr, self.bytes_per_pixel);
            });
        } else {
            with_framebuffer_mapped(|| unsafe {
                ptr::write_bytes(ptr, 0, self.bytes_per_pixel);
            });
        }
    }
}

fn color_bytes(format: FrameBufferFormat, r: u8, g: u8, b: u8) -> [u8; 4] {
    match format {
        FrameBufferFormat::Rgb => [r, g, b, 0],
        FrameBufferFormat::Bgr => [b, g, r, 0],
        FrameBufferFormat::Unknown => [r, g, b, 0],
    }
}

#[derive(Clone, Copy)]
struct Glyph {
    rows: [u8; CHAR_HEIGHT],
}

const fn glyph(rows: [u8; CHAR_HEIGHT]) -> Glyph {
    Glyph { rows }
}

struct GlyphEntry {
    ch: char,
    glyph: Glyph,
}

struct LineBuffer<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> LineBuffer<N> {
    const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl<const N: usize> fmt::Write for LineBuffer<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > N {
            return Err(fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

const GLYPH_UNKNOWN: Glyph = glyph([
    0b011110, 0b100001, 0b000010, 0b000100, 0b001000, 0b001000, 0b000000, 0b001000, 0b000000,
    0b000000,
]);

const GLYPH_SPACE: Glyph = glyph([0; CHAR_HEIGHT]);
const GLYPH_A: Glyph = glyph([
    0b001100, 0b010010, 0b010010, 0b011110, 0b010010, 0b010010, 0b010010, 0, 0, 0,
]);
const GLYPH_B: Glyph = glyph([
    0b011100, 0b010010, 0b010010, 0b011100, 0b010010, 0b010010, 0b011100, 0, 0, 0,
]);
const GLYPH_C: Glyph = glyph([
    0b001100, 0b010010, 0b010000, 0b010000, 0b010000, 0b010010, 0b001100, 0, 0, 0,
]);
const GLYPH_D: Glyph = glyph([
    0b011100, 0b010010, 0b010010, 0b010010, 0b010010, 0b010010, 0b011100, 0, 0, 0,
]);
const GLYPH_E: Glyph = glyph([
    0b011110, 0b010000, 0b010000, 0b011100, 0b010000, 0b010000, 0b011110, 0, 0, 0,
]);
const GLYPH_F: Glyph = glyph([
    0b011110, 0b010000, 0b010000, 0b011100, 0b010000, 0b010000, 0b010000, 0, 0, 0,
]);
const GLYPH_G: Glyph = glyph([
    0b001100, 0b010010, 0b010000, 0b010111, 0b010010, 0b010010, 0b001110, 0, 0, 0,
]);
const GLYPH_H: Glyph = glyph([
    0b010010, 0b010010, 0b010010, 0b011110, 0b010010, 0b010010, 0b010010, 0, 0, 0,
]);
const GLYPH_I: Glyph = glyph([
    0b001110, 0b000100, 0b000100, 0b000100, 0b000100, 0b000100, 0b001110, 0, 0, 0,
]);
const GLYPH_J: Glyph = glyph([
    0b000111, 0b000010, 0b000010, 0b000010, 0b010010, 0b010010, 0b001100, 0, 0, 0,
]);
const GLYPH_K: Glyph = glyph([
    0b010010, 0b010100, 0b011000, 0b010100, 0b010010, 0b010010, 0b010010, 0, 0, 0,
]);
const GLYPH_L: Glyph = glyph([
    0b010000, 0b010000, 0b010000, 0b010000, 0b010000, 0b010000, 0b011110, 0, 0, 0,
]);
const GLYPH_M: Glyph = glyph([
    0b010010, 0b011110, 0b011110, 0b010010, 0b010010, 0b010010, 0b010010, 0, 0, 0,
]);
const GLYPH_N: Glyph = glyph([
    0b010010, 0b011010, 0b011010, 0b010110, 0b010110, 0b010110, 0b010010, 0, 0, 0,
]);
const GLYPH_O: Glyph = glyph([
    0b001100, 0b010010, 0b010010, 0b010010, 0b010010, 0b010010, 0b001100, 0, 0, 0,
]);
const GLYPH_P: Glyph = glyph([
    0b011100, 0b010010, 0b010010, 0b011100, 0b010000, 0b010000, 0b010000, 0, 0, 0,
]);
const GLYPH_Q: Glyph = glyph([
    0b001100, 0b010010, 0b010010, 0b010010, 0b010010, 0b001100, 0b000110, 0, 0, 0,
]);
const GLYPH_R: Glyph = glyph([
    0b011100, 0b010010, 0b010010, 0b011100, 0b010100, 0b010010, 0b010010, 0, 0, 0,
]);
const GLYPH_S: Glyph = glyph([
    0b001110, 0b010000, 0b010000, 0b001100, 0b000010, 0b000010, 0b011100, 0, 0, 0,
]);
const GLYPH_T: Glyph = glyph([
    0b011110, 0b000100, 0b000100, 0b000100, 0b000100, 0b000100, 0b000100, 0, 0, 0,
]);
const GLYPH_U: Glyph = glyph([
    0b010010, 0b010010, 0b010010, 0b010010, 0b010010, 0b010010, 0b001100, 0, 0, 0,
]);
const GLYPH_V: Glyph = glyph([
    0b010010, 0b010010, 0b010010, 0b010010, 0b010010, 0b001100, 0b001100, 0, 0, 0,
]);
const GLYPH_W: Glyph = glyph([
    0b010010, 0b010010, 0b010010, 0b010010, 0b011110, 0b011110, 0b010010, 0, 0, 0,
]);
const GLYPH_X: Glyph = glyph([
    0b010010, 0b010010, 0b001100, 0b000100, 0b001100, 0b010010, 0b010010, 0, 0, 0,
]);
const GLYPH_Y: Glyph = glyph([
    0b010010, 0b010010, 0b001100, 0b000100, 0b000100, 0b000100, 0b000100, 0, 0, 0,
]);
const GLYPH_Z: Glyph = glyph([
    0b011110, 0b000010, 0b000100, 0b001000, 0b010000, 0b010000, 0b011110, 0, 0, 0,
]);

const GLYPH_0: Glyph = glyph([
    0b001100, 0b010010, 0b010110, 0b011010, 0b010010, 0b010010, 0b001100, 0, 0, 0,
]);
const GLYPH_1: Glyph = glyph([
    0b000100, 0b001100, 0b000100, 0b000100, 0b000100, 0b000100, 0b001110, 0, 0, 0,
]);
const GLYPH_2: Glyph = glyph([
    0b001100, 0b010010, 0b000010, 0b000100, 0b001000, 0b010000, 0b011110, 0, 0, 0,
]);
const GLYPH_3: Glyph = glyph([
    0b001100, 0b010010, 0b000010, 0b000100, 0b000010, 0b010010, 0b001100, 0, 0, 0,
]);
const GLYPH_4: Glyph = glyph([
    0b000010, 0b000110, 0b001010, 0b010010, 0b011110, 0b000010, 0b000010, 0, 0, 0,
]);
const GLYPH_5: Glyph = glyph([
    0b011110, 0b010000, 0b011100, 0b000010, 0b000010, 0b010010, 0b001100, 0, 0, 0,
]);
const GLYPH_6: Glyph = glyph([
    0b001100, 0b010000, 0b011100, 0b010010, 0b010010, 0b010010, 0b001100, 0, 0, 0,
]);
const GLYPH_7: Glyph = glyph([
    0b011110, 0b000010, 0b000100, 0b001000, 0b010000, 0b010000, 0b010000, 0, 0, 0,
]);
const GLYPH_8: Glyph = glyph([
    0b001100, 0b010010, 0b010010, 0b001100, 0b010010, 0b010010, 0b001100, 0, 0, 0,
]);
const GLYPH_9: Glyph = glyph([
    0b001100, 0b010010, 0b010010, 0b001110, 0b000010, 0b000010, 0b001100, 0, 0, 0,
]);

const GLYPH_DOT: Glyph = glyph([0, 0, 0, 0, 0, 0, 0b000100, 0b000100, 0, 0]);
const GLYPH_COLON: Glyph = glyph([0, 0b000100, 0b000100, 0, 0b000100, 0b000100, 0, 0, 0, 0]);
const GLYPH_COMMA: Glyph = glyph([0, 0, 0, 0, 0, 0b000100, 0b000100, 0b001000, 0, 0]);
const GLYPH_DASH: Glyph = glyph([0, 0, 0, 0, 0b001110, 0, 0, 0, 0, 0]);
const GLYPH_UNDERSCORE: Glyph = glyph([0, 0, 0, 0, 0, 0, 0, 0, 0b011110, 0]);
const GLYPH_SLASH: Glyph = glyph([
    0b000010, 0b000100, 0b001000, 0b010000, 0b010000, 0b100000, 0, 0, 0, 0,
]);
const GLYPH_BACKSLASH: Glyph = glyph([
    0b010000, 0b001000, 0b000100, 0b000010, 0b000010, 0b000001, 0, 0, 0, 0,
]);
const GLYPH_LPAREN: Glyph = glyph([
    0b000100, 0b001000, 0b010000, 0b010000, 0b010000, 0b010000, 0b001000, 0b000100, 0, 0,
]);
const GLYPH_RPAREN: Glyph = glyph([
    0b001000, 0b000100, 0b000010, 0b000010, 0b000010, 0b000010, 0b000100, 0b001000, 0, 0,
]);
const GLYPH_EXCLAMATION: Glyph = glyph([
    0b000100, 0b000100, 0b000100, 0b000100, 0b000100, 0, 0b000100, 0, 0, 0,
]);
const GLYPH_QUESTION: Glyph = glyph([
    0b001100, 0b010010, 0b000010, 0b000100, 0b000100, 0, 0b000100, 0, 0, 0,
]);
const GLYPH_APOSTROPHE: Glyph = glyph([0b000100, 0b000100, 0b000010, 0, 0, 0, 0, 0, 0, 0]);
const GLYPH_QUOTE: Glyph = glyph([0b010010, 0b010010, 0b001100, 0, 0, 0, 0, 0, 0, 0]);
const GLYPH_GT: Glyph = glyph([
    0b010000, 0b001000, 0b000100, 0b000010, 0b000100, 0b001000, 0b010000, 0, 0, 0,
]);
const GLYPH_LT: Glyph = glyph([
    0b000010, 0b000100, 0b001000, 0b010000, 0b001000, 0b000100, 0b000010, 0, 0, 0,
]);

const GLYPH_SEMICOLON: Glyph = glyph([
    0, 0b000100, 0b000100, 0, 0b000100, 0b000100, 0b001000, 0, 0, 0,
]);
const GLYPH_PLUS: Glyph = glyph([
    0, 0, 0b000100, 0b000100, 0b011110, 0b000100, 0b000100, 0, 0, 0,
]);
const GLYPH_EQUAL: Glyph = glyph([0, 0, 0, 0b011110, 0, 0b011110, 0, 0, 0, 0]);
const GLYPH_AT: Glyph = glyph([
    0b001100, 0b010010, 0b010110, 0b010110, 0b010100, 0b010000, 0b001110, 0, 0, 0,
]);
const GLYPH_HASH: Glyph = glyph([
    0b001010, 0b001010, 0b011110, 0b001010, 0b011110, 0b001010, 0b001010, 0, 0, 0,
]);
const GLYPH_DOLLAR: Glyph = glyph([
    0b000100, 0b001110, 0b010000, 0b001100, 0b000010, 0b011100, 0b000100, 0, 0, 0,
]);
const GLYPH_PERCENT: Glyph = glyph([
    0b011000, 0b011001, 0b000010, 0b000100, 0b001000, 0b100110, 0b000110, 0, 0, 0,
]);
const GLYPH_CARET: Glyph = glyph([0b000100, 0b001010, 0b010001, 0, 0, 0, 0, 0, 0, 0]);
const GLYPH_AMPERSAND: Glyph = glyph([
    0b001100, 0b010010, 0b001100, 0b001000, 0b010101, 0b010010, 0b001101, 0, 0, 0,
]);
const GLYPH_ASTERISK: Glyph = glyph([
    0, 0b000100, 0b010101, 0b001110, 0b010101, 0b000100, 0, 0, 0, 0,
]);
const GLYPH_LBRACKET: Glyph = glyph([
    0b001100, 0b001000, 0b001000, 0b001000, 0b001000, 0b001000, 0b001100, 0, 0, 0,
]);
const GLYPH_RBRACKET: Glyph = glyph([
    0b001100, 0b000100, 0b000100, 0b000100, 0b000100, 0b000100, 0b001100, 0, 0, 0,
]);
const GLYPH_LBRACE: Glyph = glyph([
    0b000110, 0b001000, 0b001000, 0b010000, 0b001000, 0b001000, 0b000110, 0, 0, 0,
]);
const GLYPH_RBRACE: Glyph = glyph([
    0b011000, 0b000100, 0b000100, 0b000010, 0b000100, 0b000100, 0b011000, 0, 0, 0,
]);
const GLYPH_PIPE: Glyph = glyph([
    0b000100, 0b000100, 0b000100, 0b000100, 0b000100, 0b000100, 0b000100, 0, 0, 0,
]);
const GLYPH_TILDE: Glyph = glyph([0, 0, 0b001010, 0b010100, 0, 0, 0, 0, 0, 0]);
const GLYPH_BACKTICK: Glyph = glyph([0b001000, 0b000100, 0, 0, 0, 0, 0, 0, 0, 0]);

const GLYPH_LOWER_A: Glyph = glyph([
    0, 0, 0b001100, 0b000010, 0b001110, 0b010010, 0b001110, 0, 0, 0,
]);
const GLYPH_LOWER_B: Glyph = glyph([
    0b010000, 0b010000, 0b011100, 0b010010, 0b010010, 0b010010, 0b011100, 0, 0, 0,
]);
const GLYPH_LOWER_C: Glyph = glyph([
    0, 0, 0b001100, 0b010010, 0b010000, 0b010010, 0b001100, 0, 0, 0,
]);
const GLYPH_LOWER_D: Glyph = glyph([
    0b000010, 0b000010, 0b001110, 0b010010, 0b010010, 0b010010, 0b001110, 0, 0, 0,
]);
const GLYPH_LOWER_E: Glyph = glyph([
    0, 0, 0b001100, 0b010010, 0b011110, 0b010000, 0b001100, 0, 0, 0,
]);
const GLYPH_LOWER_F: Glyph = glyph([
    0b000110, 0b001000, 0b001000, 0b011100, 0b001000, 0b001000, 0b001000, 0, 0, 0,
]);
const GLYPH_LOWER_G: Glyph = glyph([
    0, 0, 0b001110, 0b010010, 0b010010, 0b001110, 0b000010, 0b001100, 0, 0,
]);
const GLYPH_LOWER_H: Glyph = glyph([
    0b010000, 0b010000, 0b011100, 0b010010, 0b010010, 0b010010, 0b010010, 0, 0, 0,
]);
const GLYPH_LOWER_I: Glyph = glyph([
    0b000100, 0, 0b001100, 0b000100, 0b000100, 0b000100, 0b001110, 0, 0, 0,
]);
const GLYPH_LOWER_J: Glyph = glyph([
    0b000010, 0, 0b000110, 0b000010, 0b000010, 0b010010, 0b010010, 0b001100, 0, 0,
]);
const GLYPH_LOWER_K: Glyph = glyph([
    0b010000, 0b010000, 0b010010, 0b010100, 0b011000, 0b010100, 0b010010, 0, 0, 0,
]);
const GLYPH_LOWER_L: Glyph = glyph([
    0b001100, 0b000100, 0b000100, 0b000100, 0b000100, 0b000100, 0b001110, 0, 0, 0,
]);
const GLYPH_LOWER_M: Glyph = glyph([
    0, 0, 0b011010, 0b010101, 0b010101, 0b010101, 0b010101, 0, 0, 0,
]);
const GLYPH_LOWER_N: Glyph = glyph([
    0, 0, 0b011100, 0b010010, 0b010010, 0b010010, 0b010010, 0, 0, 0,
]);
const GLYPH_LOWER_O: Glyph = glyph([
    0, 0, 0b001100, 0b010010, 0b010010, 0b010010, 0b001100, 0, 0, 0,
]);
const GLYPH_LOWER_P: Glyph = glyph([
    0, 0, 0b011100, 0b010010, 0b010010, 0b011100, 0b010000, 0b010000, 0, 0,
]);
const GLYPH_LOWER_Q: Glyph = glyph([
    0, 0, 0b001110, 0b010010, 0b010010, 0b001110, 0b000010, 0b000010, 0, 0,
]);
const GLYPH_LOWER_R: Glyph = glyph([
    0, 0, 0b010110, 0b011000, 0b010000, 0b010000, 0b010000, 0, 0, 0,
]);
const GLYPH_LOWER_S: Glyph = glyph([
    0, 0, 0b001110, 0b010000, 0b001100, 0b000010, 0b011100, 0, 0, 0,
]);
const GLYPH_LOWER_T: Glyph = glyph([
    0b001000, 0b001000, 0b011100, 0b001000, 0b001000, 0b001010, 0b000100, 0, 0, 0,
]);
const GLYPH_LOWER_U: Glyph = glyph([
    0, 0, 0b010010, 0b010010, 0b010010, 0b010010, 0b001110, 0, 0, 0,
]);
const GLYPH_LOWER_V: Glyph = glyph([
    0, 0, 0b010010, 0b010010, 0b010010, 0b001100, 0b001100, 0, 0, 0,
]);
const GLYPH_LOWER_W: Glyph = glyph([
    0, 0, 0b010010, 0b010010, 0b010010, 0b011110, 0b011110, 0, 0, 0,
]);
const GLYPH_LOWER_X: Glyph = glyph([
    0, 0, 0b010010, 0b001100, 0b000100, 0b001100, 0b010010, 0, 0, 0,
]);
const GLYPH_LOWER_Y: Glyph = glyph([
    0, 0, 0b010010, 0b010010, 0b010010, 0b001110, 0b000010, 0b001100, 0, 0,
]);
const GLYPH_LOWER_Z: Glyph = glyph([
    0, 0, 0b011110, 0b000100, 0b001000, 0b010000, 0b011110, 0, 0, 0,
]);

const GLYPH_TABLE: &[GlyphEntry] = &[
    GlyphEntry {
        ch: ' ',
        glyph: GLYPH_SPACE,
    },
    GlyphEntry {
        ch: 'A',
        glyph: GLYPH_A,
    },
    GlyphEntry {
        ch: 'B',
        glyph: GLYPH_B,
    },
    GlyphEntry {
        ch: 'C',
        glyph: GLYPH_C,
    },
    GlyphEntry {
        ch: 'D',
        glyph: GLYPH_D,
    },
    GlyphEntry {
        ch: 'E',
        glyph: GLYPH_E,
    },
    GlyphEntry {
        ch: 'F',
        glyph: GLYPH_F,
    },
    GlyphEntry {
        ch: 'G',
        glyph: GLYPH_G,
    },
    GlyphEntry {
        ch: 'H',
        glyph: GLYPH_H,
    },
    GlyphEntry {
        ch: 'I',
        glyph: GLYPH_I,
    },
    GlyphEntry {
        ch: 'J',
        glyph: GLYPH_J,
    },
    GlyphEntry {
        ch: 'K',
        glyph: GLYPH_K,
    },
    GlyphEntry {
        ch: 'L',
        glyph: GLYPH_L,
    },
    GlyphEntry {
        ch: 'M',
        glyph: GLYPH_M,
    },
    GlyphEntry {
        ch: 'N',
        glyph: GLYPH_N,
    },
    GlyphEntry {
        ch: 'O',
        glyph: GLYPH_O,
    },
    GlyphEntry {
        ch: 'P',
        glyph: GLYPH_P,
    },
    GlyphEntry {
        ch: 'Q',
        glyph: GLYPH_Q,
    },
    GlyphEntry {
        ch: 'R',
        glyph: GLYPH_R,
    },
    GlyphEntry {
        ch: 'S',
        glyph: GLYPH_S,
    },
    GlyphEntry {
        ch: 'T',
        glyph: GLYPH_T,
    },
    GlyphEntry {
        ch: 'U',
        glyph: GLYPH_U,
    },
    GlyphEntry {
        ch: 'V',
        glyph: GLYPH_V,
    },
    GlyphEntry {
        ch: 'W',
        glyph: GLYPH_W,
    },
    GlyphEntry {
        ch: 'X',
        glyph: GLYPH_X,
    },
    GlyphEntry {
        ch: 'Y',
        glyph: GLYPH_Y,
    },
    GlyphEntry {
        ch: 'Z',
        glyph: GLYPH_Z,
    },
    GlyphEntry {
        ch: 'a',
        glyph: GLYPH_LOWER_A,
    },
    GlyphEntry {
        ch: 'b',
        glyph: GLYPH_LOWER_B,
    },
    GlyphEntry {
        ch: 'c',
        glyph: GLYPH_LOWER_C,
    },
    GlyphEntry {
        ch: 'd',
        glyph: GLYPH_LOWER_D,
    },
    GlyphEntry {
        ch: 'e',
        glyph: GLYPH_LOWER_E,
    },
    GlyphEntry {
        ch: 'f',
        glyph: GLYPH_LOWER_F,
    },
    GlyphEntry {
        ch: 'g',
        glyph: GLYPH_LOWER_G,
    },
    GlyphEntry {
        ch: 'h',
        glyph: GLYPH_LOWER_H,
    },
    GlyphEntry {
        ch: 'i',
        glyph: GLYPH_LOWER_I,
    },
    GlyphEntry {
        ch: 'j',
        glyph: GLYPH_LOWER_J,
    },
    GlyphEntry {
        ch: 'k',
        glyph: GLYPH_LOWER_K,
    },
    GlyphEntry {
        ch: 'l',
        glyph: GLYPH_LOWER_L,
    },
    GlyphEntry {
        ch: 'm',
        glyph: GLYPH_LOWER_M,
    },
    GlyphEntry {
        ch: 'n',
        glyph: GLYPH_LOWER_N,
    },
    GlyphEntry {
        ch: 'o',
        glyph: GLYPH_LOWER_O,
    },
    GlyphEntry {
        ch: 'p',
        glyph: GLYPH_LOWER_P,
    },
    GlyphEntry {
        ch: 'q',
        glyph: GLYPH_LOWER_Q,
    },
    GlyphEntry {
        ch: 'r',
        glyph: GLYPH_LOWER_R,
    },
    GlyphEntry {
        ch: 's',
        glyph: GLYPH_LOWER_S,
    },
    GlyphEntry {
        ch: 't',
        glyph: GLYPH_LOWER_T,
    },
    GlyphEntry {
        ch: 'u',
        glyph: GLYPH_LOWER_U,
    },
    GlyphEntry {
        ch: 'v',
        glyph: GLYPH_LOWER_V,
    },
    GlyphEntry {
        ch: 'w',
        glyph: GLYPH_LOWER_W,
    },
    GlyphEntry {
        ch: 'x',
        glyph: GLYPH_LOWER_X,
    },
    GlyphEntry {
        ch: 'y',
        glyph: GLYPH_LOWER_Y,
    },
    GlyphEntry {
        ch: 'z',
        glyph: GLYPH_LOWER_Z,
    },
    GlyphEntry {
        ch: '0',
        glyph: GLYPH_0,
    },
    GlyphEntry {
        ch: '1',
        glyph: GLYPH_1,
    },
    GlyphEntry {
        ch: '2',
        glyph: GLYPH_2,
    },
    GlyphEntry {
        ch: '3',
        glyph: GLYPH_3,
    },
    GlyphEntry {
        ch: '4',
        glyph: GLYPH_4,
    },
    GlyphEntry {
        ch: '5',
        glyph: GLYPH_5,
    },
    GlyphEntry {
        ch: '6',
        glyph: GLYPH_6,
    },
    GlyphEntry {
        ch: '7',
        glyph: GLYPH_7,
    },
    GlyphEntry {
        ch: '8',
        glyph: GLYPH_8,
    },
    GlyphEntry {
        ch: '9',
        glyph: GLYPH_9,
    },
    GlyphEntry {
        ch: '.',
        glyph: GLYPH_DOT,
    },
    GlyphEntry {
        ch: ':',
        glyph: GLYPH_COLON,
    },
    GlyphEntry {
        ch: ',',
        glyph: GLYPH_COMMA,
    },
    GlyphEntry {
        ch: ';',
        glyph: GLYPH_SEMICOLON,
    },
    GlyphEntry {
        ch: '-',
        glyph: GLYPH_DASH,
    },
    GlyphEntry {
        ch: '_',
        glyph: GLYPH_UNDERSCORE,
    },
    GlyphEntry {
        ch: '+',
        glyph: GLYPH_PLUS,
    },
    GlyphEntry {
        ch: '=',
        glyph: GLYPH_EQUAL,
    },
    GlyphEntry {
        ch: '/',
        glyph: GLYPH_SLASH,
    },
    GlyphEntry {
        ch: '\\',
        glyph: GLYPH_BACKSLASH,
    },
    GlyphEntry {
        ch: '(',
        glyph: GLYPH_LPAREN,
    },
    GlyphEntry {
        ch: ')',
        glyph: GLYPH_RPAREN,
    },
    GlyphEntry {
        ch: '!',
        glyph: GLYPH_EXCLAMATION,
    },
    GlyphEntry {
        ch: '?',
        glyph: GLYPH_QUESTION,
    },
    GlyphEntry {
        ch: '\'',
        glyph: GLYPH_APOSTROPHE,
    },
    GlyphEntry {
        ch: '"',
        glyph: GLYPH_QUOTE,
    },
    GlyphEntry {
        ch: '`',
        glyph: GLYPH_BACKTICK,
    },
    GlyphEntry {
        ch: '~',
        glyph: GLYPH_TILDE,
    },
    GlyphEntry {
        ch: '|',
        glyph: GLYPH_PIPE,
    },
    GlyphEntry {
        ch: '[',
        glyph: GLYPH_LBRACKET,
    },
    GlyphEntry {
        ch: ']',
        glyph: GLYPH_RBRACKET,
    },
    GlyphEntry {
        ch: '{',
        glyph: GLYPH_LBRACE,
    },
    GlyphEntry {
        ch: '}',
        glyph: GLYPH_RBRACE,
    },
    GlyphEntry {
        ch: '@',
        glyph: GLYPH_AT,
    },
    GlyphEntry {
        ch: '#',
        glyph: GLYPH_HASH,
    },
    GlyphEntry {
        ch: '$',
        glyph: GLYPH_DOLLAR,
    },
    GlyphEntry {
        ch: '%',
        glyph: GLYPH_PERCENT,
    },
    GlyphEntry {
        ch: '^',
        glyph: GLYPH_CARET,
    },
    GlyphEntry {
        ch: '&',
        glyph: GLYPH_AMPERSAND,
    },
    GlyphEntry {
        ch: '*',
        glyph: GLYPH_ASTERISK,
    },
    GlyphEntry {
        ch: '>',
        glyph: GLYPH_GT,
    },
    GlyphEntry {
        ch: '<',
        glyph: GLYPH_LT,
    },
];

fn glyph_for(ch: char) -> &'static Glyph {
    for entry in GLYPH_TABLE {
        if entry.ch == ch {
            return &entry.glyph;
        }
    }
    if ch.is_ascii_lowercase() {
        let up = ch.to_ascii_uppercase();
        for entry in GLYPH_TABLE {
            if entry.ch == up {
                return &entry.glyph;
            }
        }
    }
    &GLYPH_UNKNOWN
}
