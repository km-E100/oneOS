#[cfg(target_os = "none")]
use crate::display;

#[cfg(target_os = "none")]
use spin::Mutex;

#[cfg(target_os = "none")]
#[derive(Clone, Copy)]
struct LineState {
    active: bool,
    prompt_len: usize,
    input_len: usize,
    prompt: [u8; 96],
    input: [u8; 256],
}

#[cfg(target_os = "none")]
static STATE: Mutex<LineState> = Mutex::new(LineState {
    active: false,
    prompt_len: 0,
    input_len: 0,
    prompt: [0; 96],
    input: [0; 256],
});

#[cfg(target_os = "none")]
fn map_byte(b: u8) -> char {
    match b {
        b'\n' => '\n',
        b'\t' => '\t',
        0x20..=0x7e => b as char,
        _ => '?',
    }
}

#[cfg(target_os = "none")]
fn write_bytes_direct(bytes: &[u8]) {
    for &b in bytes {
        display::write_char(map_byte(b));
    }
}

/// Begin interactive input mode for the current prompt line.
///
/// While active, async output should not corrupt the prompt or the user’s partially typed input.
#[cfg(target_os = "none")]
pub fn begin(prompt: &str) {
    let mut st = STATE.lock();
    st.active = true;
    st.input_len = 0;
    st.prompt_len = 0;
    let bytes = prompt.as_bytes();
    let n = core::cmp::min(bytes.len(), st.prompt.len());
    st.prompt[..n].copy_from_slice(&bytes[..n]);
    st.prompt_len = n;
}

/// Start interactive mode and render the prompt.
///
/// This is the preferred entry point for the shell so prompt rendering is fully
/// owned by the line discipline.
#[cfg(target_os = "none")]
pub fn begin_and_draw(prompt: &str) {
    begin(prompt);
    write_bytes_direct(prompt.as_bytes());
}

/// End interactive input mode.
#[cfg(target_os = "none")]
pub fn end() {
    let mut st = STATE.lock();
    st.active = false;
    st.prompt_len = 0;
    st.input_len = 0;
}

/// Record a single ASCII input character (the shell echoes separately).
#[cfg(target_os = "none")]
pub fn push_char(ch: char) {
    if !ch.is_ascii() {
        return;
    }
    let mut st = STATE.lock();
    if !st.active || st.input_len >= st.input.len() {
        return;
    }
    let idx = st.input_len;
    st.input[idx] = ch as u8;
    st.input_len = idx + 1;
}

/// Record a backspace (the shell echoes separately).
#[cfg(target_os = "none")]
pub fn pop_char() {
    let mut st = STATE.lock();
    if !st.active || st.input_len == 0 {
        return;
    }
    st.input_len -= 1;
}

/// Write output that may happen asynchronously while the shell is waiting for input.
///
/// Policy:
/// - Always move to a fresh line before emitting async output.
/// - Ensure a trailing newline, then redraw `prompt + current_input`.
#[cfg(target_os = "none")]
pub fn write_async_bytes(bytes: &[u8]) {
    let mut st = STATE.lock();
    if !st.active {
        drop(st);
        write_bytes_direct(bytes);
        return;
    }

    // Move away from the in-progress prompt/input line.
    display::write_char('\n');
    write_bytes_direct(bytes);
    if !bytes.ends_with(b"\n") {
        display::write_char('\n');
    }

    // Redraw prompt + current input.
    write_bytes_direct(&st.prompt[..st.prompt_len]);
    write_bytes_direct(&st.input[..st.input_len]);
}
