extern crate alloc;

use crate::arch;
#[cfg(target_os = "none")]
use crate::console::KeyEvent;
#[cfg(target_os = "uefi")]
use crate::drivers::serial;
#[cfg(target_os = "none")]
use alloc::vec::Vec;
use alloc::{format, string::String};
use core::fmt;

use crate::boot_info;
#[cfg(target_os = "none")]
use crate::drivers::serial;
#[cfg(target_os = "uefi")]
use crate::text;
use oneos_boot_proto::MemoryRegionType;

#[cfg(target_os = "none")]
use alloc::string::ToString;

#[cfg(target_os = "uefi")]
enum InputMode {
    Serial,
    Stdin,
}

const MAX_ARGS: usize = 16;
#[cfg(target_os = "none")]
const GOES_RECORD_TYPE_SHELL_TEXT_V1: u32 = 0x1_0001;
#[cfg(target_os = "none")]
const GOES_RECORD_TYPE_CREATE_OBJECT_V1: u32 = 0x1_0002;
#[cfg(target_os = "none")]
const GOES_RECORD_TYPE_ADD_EDGE_V1: u32 = 0x1_0003;
#[cfg(target_os = "none")]
const GOES_RECORD_TYPE_REMOVE_EDGE_V1: u32 = 0x1_0004;
#[cfg(target_os = "none")]
const GOES_RECORD_TYPE_UPDATE_OBJECT_META_V1: u32 = 0x1_0005;
#[cfg(target_os = "none")]
const GOES_RECORD_TYPE_APP_MANIFEST_V1: u32 = 0x1_0100;
#[cfg(target_os = "none")]
const GOES_RECORD_TYPE_CREATE_WORKSPACE_V1: u32 = 0x1_0200;
#[cfg(target_os = "none")]
const GOES_RECORD_TYPE_ACCOUNT_OBJECT_V1: u32 = 0x1_0201;
#[cfg(target_os = "none")]
const GOES_RECORD_TYPE_UPDATE_BOOT_MANIFEST_V1: u32 = 0x1_0202;
#[cfg(target_os = "none")]
const GOES_RECORD_TYPE_WORKSPACE_SPEC_V1: u32 = 0x1_0203;

trait ShellOut {
    fn write_line(&mut self, s: &str);
    fn write_fmt(&mut self, args: fmt::Arguments);
    fn clear(&mut self);
}

#[cfg(target_os = "uefi")]
struct UefiOut;

#[cfg(target_os = "uefi")]
impl ShellOut for UefiOut {
    fn write_line(&mut self, s: &str) {
        let _ = text::write_line(s);
    }

    fn write_fmt(&mut self, args: fmt::Arguments) {
        let _ = text::write_line_args(args);
    }

    fn clear(&mut self) {
        // UEFI text console：QEMU 下支持 ANSI 清屏；真实固件上可能无效但不影响运行。
        let _ = text::write_line("\u{1b}[2J\u{1b}[H");
    }
}

#[cfg(target_os = "none")]
struct DisplayOut;

#[cfg(target_os = "none")]
impl ShellOut for DisplayOut {
    fn write_line(&mut self, s: &str) {
        let session = crate::console::mgr::ensure_session_for_current_domain();
        let _ =
            crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, s.as_bytes());
        let _ = crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, b"\n");
    }

    fn write_fmt(&mut self, args: fmt::Arguments) {
        let session = crate::console::mgr::ensure_session_for_current_domain();
        let s = alloc::format!("{}", args);
        let _ =
            crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, s.as_bytes());
        let _ = crate::console::mgr::write(session, crate::console::mgr::STREAM_STDOUT, b"\n");
    }

    fn clear(&mut self) {
        let session = crate::console::mgr::ensure_session_for_current_domain();
        let seq = crate::console::mgr::clear(session);
        crate::console::mgr::flush(seq);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Normal,
    Recovery,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Workspace {
    System,
    Library,
    Applications,
    Users,
    User(String),
    Other(String),
}

impl Workspace {
    fn label(&self) -> &str {
        match self {
            Workspace::System => "System",
            Workspace::Library => "Library",
            Workspace::Applications => "Applications",
            Workspace::Users => "Users",
            Workspace::User(name) => name.as_str(),
            Workspace::Other(name) => name.as_str(),
        }
    }

    #[cfg(target_os = "none")]
    fn name(&self) -> &str {
        match self {
            Workspace::System => "System",
            Workspace::Library => "Library",
            Workspace::Applications => "Applications",
            Workspace::Users => "Users",
            Workspace::User(name) => name.as_str(),
            Workspace::Other(name) => name.as_str(),
        }
    }
}

#[derive(Clone, Debug)]
struct ShellContext {
    mode: Mode,
    sip_on: bool,
    workspace: Workspace,
    user: Option<String>,
}

impl ShellContext {
    fn new_default() -> Self {
        let mut ctx = Self {
            mode: Mode::Normal,
            sip_on: true,
            workspace: Workspace::System,
            user: None,
        };
        ctx.apply_boot_info();
        ctx
    }

    fn apply_boot_info(&mut self) {
        let mut boot_raw = None::<[u8; 32]>;
        if let Some(info) = boot_info::get() {
            self.mode = if info.is_recovery_mode() {
                Mode::Recovery
            } else {
                Mode::Normal
            };
            if let Some(flags) = info.goes_flags() {
                // bit1: sip_on
                self.sip_on = (flags & 0b10) != 0;
            }
            if let Some(raw) = info.goes_default_user_raw() {
                boot_raw = Some(*raw);
            }
        }

        // v1: BootManifest 是默认用户的权威来源（若可用）。
        #[cfg(target_os = "none")]
        {
            if let Some(sb) = crate::goes::probe() {
                self.sip_on = (sb.flags & 0b10) != 0;
            }

            // 1) Record log 中的 BootManifest update（最高优先级）
            if let Some(idx) = crate::goes::replay::snapshot() {
                if let Some(name) = idx.boot_default_user.as_deref() {
                    if self.apply_default_user_name(name) {
                        self.apply_disabled_policy(&idx);
                        return;
                    }
                }
            }

            // 2) 固化 BootManifest block（v0.1 格式；由 oneboot 填充）
            if let Some(bm) = crate::goes::boot_manifest() {
                if self.apply_default_user_raw(&bm.default_user) {
                    if let Some(idx) = crate::goes::replay::snapshot() {
                        self.apply_disabled_policy(&idx);
                    }
                    return;
                }
            }

            // 3) superblock fallback
            if let Some(sb) = crate::goes::probe() {
                if self.apply_default_user_raw(&sb.default_user) {
                    if let Some(idx) = crate::goes::replay::snapshot() {
                        self.apply_disabled_policy(&idx);
                    }
                    return;
                }
            }
        }

        // 4) boot_info fallback（当 GOES 不可用时）
        if let Some(raw) = boot_raw.as_ref() {
            let _ = self.apply_default_user_raw(raw);
        }
    }

    #[cfg(target_os = "none")]
    fn apply_default_user_name(&mut self, name: &str) -> bool {
        let name = name.trim();
        if name.is_empty() {
            return false;
        }
        self.user = Some(name.into());
        self.workspace = Workspace::User(format!("User:{name}"));
        true
    }

    #[cfg(target_os = "none")]
    fn apply_disabled_policy(&mut self, idx: &crate::goes::replay::Index) {
        let Some(name) = self.user.as_deref() else {
            return;
        };
        if let Some(acct) = idx.accounts.get(name) {
            if !acct.disabled {
                return;
            }
        } else {
            return;
        }

        serial::log_line_args(format_args!(
            "shell: default_user '{}' is disabled; falling back",
            name
        ));

        if let Some(admin) = idx.accounts.get("admin") {
            if !admin.disabled {
                let _ = self.apply_default_user_name("admin");
                return;
            }
        }

        self.user = None;
        self.workspace = Workspace::System;
    }

    fn apply_default_user_raw(&mut self, raw: &[u8; 32]) -> bool {
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        if end == 0 {
            return false;
        }
        let Ok(name) = core::str::from_utf8(&raw[..end]) else {
            return false;
        };
        let name = name.trim();
        if name.is_empty() {
            return false;
        }
        self.user = Some(name.into());
        self.workspace = Workspace::User(format!("User:{name}"));
        true
    }

    fn prompt(&self) -> String {
        // v0.x：先只显示 workspace；后续在 GOES 接入后再显示更完整的上下文。
        let mut p = String::new();
        p.push_str("oneOS[");
        p.push_str(self.workspace.label());
        if self.mode == Mode::Recovery {
            p.push_str("|recovery");
        }
        if !self.sip_on {
            p.push_str("|sip-off");
        }
        p.push_str("]> ");
        p
    }
}

#[derive(Clone, Copy)]
struct Argv<'a> {
    args: [&'a str; MAX_ARGS],
    len: usize,
    truncated: bool,
}

impl<'a> Argv<'a> {
    fn new() -> Self {
        Self {
            args: [""; MAX_ARGS],
            len: 0,
            truncated: false,
        }
    }

    fn push(&mut self, s: &'a str) {
        if self.len < self.args.len() {
            self.args[self.len] = s;
            self.len += 1;
        } else {
            self.truncated = true;
        }
    }

    fn get(&self, idx: usize) -> Option<&'a str> {
        (idx < self.len).then_some(self.args[idx])
    }

    fn as_slice(&self) -> &[&'a str] {
        &self.args[..self.len]
    }
}

fn parse_argv(line: &str) -> Option<(&str, Argv<'_>)> {
    let mut parts = line.split_whitespace();
    let cmd = parts.next()?;
    let mut argv = Argv::new();
    for a in parts {
        argv.push(a);
    }
    Some((cmd, argv))
}

#[cfg(target_os = "none")]
fn parse_view_common(
    argv: &Argv<'_>,
    start: usize,
) -> (Option<String>, crate::goes::view::ViewOrder, Option<usize>) {
    let mut ws = None::<String>;
    let mut order = crate::goes::view::ViewOrder::SeqAsc;
    let mut limit = None::<usize>;
    let mut i = start;
    while let Some(a) = argv.get(i) {
        match a {
            "--ws" => {
                if let Some(v) = argv.get(i + 1) {
                    ws = Some(v.to_string());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--desc" => {
                order = crate::goes::view::ViewOrder::SeqDesc;
                i += 1;
            }
            "--limit" => {
                if let Some(v) = argv.get(i + 1) {
                    if let Some(n) = parse_u64_auto(v) {
                        limit = Some(n.min(usize::MAX as u64) as usize);
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    (ws, order, limit)
}

#[cfg(target_os = "none")]
fn resolve_ws_sources(idx: &crate::goes::replay::Index, ws: &str) -> Vec<String> {
    if let Some(spec) = idx.workspace_specs.get(ws) {
        if spec.kind == crate::goes::replay::WorkspaceKind::Composed {
            let mut out = Vec::new();
            for s in spec.sources.iter() {
                if s == ws {
                    serial::log_line_args(format_args!(
                        "ws: composed mapping contains itself: {}",
                        ws
                    ));
                    continue;
                }
                if let Some(s2) = idx.workspace_specs.get(s) {
                    if s2.kind == crate::goes::replay::WorkspaceKind::Composed {
                        // v1 limitation: no recursion
                        serial::log_line_args(format_args!(
                            "ws: composed mapping recursion not supported ({} includes {})",
                            ws, s
                        ));
                        continue;
                    }
                }
                if !out.iter().any(|x| x == s) {
                    out.push(s.clone());
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }
    alloc::vec![ws.to_string()]
}

struct Command {
    name: &'static str,
    usage: &'static str,
    help: &'static str,
    handler: fn(&mut ShellContext, &mut dyn ShellOut, Argv<'_>),
}

fn cmd_help(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv<'_>) {
    out.write_line("commands:");
    for c in COMMANDS {
        out.write_fmt(format_args!("  {:<22} {}", c.usage, c.help));
    }
}

fn cmd_echo(_ctx: &mut ShellContext, out: &mut dyn ShellOut, argv: Argv<'_>) {
    let mut buf = LineBuffer::<256>::new();
    let mut first = true;
    for a in argv.as_slice().iter().copied() {
        if !first {
            let _ = buf.push(' ');
        }
        first = false;
        buf.push_str(a);
    }
    out.write_line(buf.as_str());
}

fn cmd_arch(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv<'_>) {
    out.write_fmt(format_args!("arch: {}", crate::arch::arch_name()));
}

fn cmd_clear(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv<'_>) {
    out.clear();
}

fn cmd_panic(_ctx: &mut ShellContext, _out: &mut dyn ShellOut, _argv: Argv<'_>) {
    panic!("manual panic requested");
}

fn cmd_halt(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv<'_>) {
    out.write_line("halting...");
    arch::halt();
}

fn cmd_mem(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv<'_>) {
    write_mem(out);
}

fn cmd_gfx(_ctx: &mut ShellContext, out: &mut dyn ShellOut, argv: Argv<'_>) {
    match argv.get(0) {
        Some("info") | None => {
            #[cfg(target_os = "none")]
            {
                match crate::gfx::info() {
                    Some(i) => {
                        out.write_fmt(format_args!(
                            "gfx: {}x{} stride={} fmt={:?} backend=framebuffer",
                            i.width, i.height, i.stride, i.format
                        ));
                    }
                    None => out.write_line("gfx: unavailable"),
                }
                return;
            }
            #[cfg(target_os = "uefi")]
            out.write_line("gfx: unavailable in uefi mode");
        }
        Some("test") => {
            #[cfg(target_os = "none")]
            {
                match crate::gfx::test_pattern() {
                    Ok(()) => out.write_line("gfx: test done"),
                    Err(crate::gfx::GfxError::Unavailable) => out.write_line("gfx: unavailable"),
                    Err(crate::gfx::GfxError::PermissionDenied) => {
                        out.write_line("gfx: permission denied (missing GPU_DRAW capability)")
                    }
                }
                return;
            }
            #[cfg(target_os = "uefi")]
            out.write_line("gfx: unavailable in uefi mode");
        }
        _ => out.write_line("usage: gfx [info|test]"),
    }
}

fn cmd_goes(ctx: &mut ShellContext, out: &mut dyn ShellOut, argv: Argv<'_>) {
    match argv.get(0) {
        Some("status") | None => {
            #[cfg(target_os = "none")]
            {
                if let Some(sb) = crate::goes::probe() {
                    let admin = (sb.flags & 1) != 0;
                    let user = ctx.user.as_deref().unwrap_or("unknown");
                    if let Some(bm) = crate::goes::boot_manifest() {
                        out.write_fmt(format_args!(
                            "GOES: present (admin={}, sip={}, default_user={}, blk_size={}, active_set={}/{})",
                            admin,
                            if ctx.sip_on { "on" } else { "off" },
                            user,
                            sb.block_size,
                            bm.active_set,
                            bm.set_count
                        ));
                    } else {
                        out.write_fmt(format_args!(
                            "GOES: present (admin={}, sip={}, default_user={}, blk_size={})",
                            admin,
                            if ctx.sip_on { "on" } else { "off" },
                            user,
                            sb.block_size
                        ));
                    }
                    if ctx.user.is_none() {
                        ctx.apply_boot_info();
                    }
                    return;
                }
            }

            if let Some(info) = boot_info::get() {
                if info.goes_present() {
                    let admin = info.goes_flags().unwrap_or(0) & 1 != 0;
                    let sip_on = info.goes_flags().unwrap_or(0) & 0b10 != 0;
                    let user = ctx.user.as_deref().unwrap_or("unknown");
                    out.write_fmt(format_args!(
                        "GOES: present (admin={}, sip={}, default_user={}, device_id={:?}, superblock_lba={:?}, system_ws_id={:?})",
                        admin,
                        if sip_on { "on" } else { "off" },
                        user,
                        info.goes_device_id(),
                        info.goes_superblock_lba(),
                        info.goes_system_ws_id()
                    ));
                } else {
                    out.write_line("GOES: not present");
                }
            } else {
                out.write_line("GOES: boot info unavailable");
            }
        }
        Some("ls") => {
            #[cfg(target_os = "none")]
            {
                let ws = ctx.workspace.name();
                let Some(idx) = crate::goes::replay::snapshot() else {
                    out.write_line("goes: index unavailable");
                    return;
                };
                let sources = resolve_ws_sources(&idx, ws);
                let view = crate::goes::view::ViewObject::roots_union(&sources);
                let rows = crate::goes::view::run_view(&view, &idx);
                let mut count = 0usize;
                for r in rows {
                    let crate::goes::view::ViewRow::Object(o) = r else { continue };
                    out.write_fmt(format_args!("  {:#x}  type=0x{:x}  name={}", o.id, o.obj_type, o.name));
                    count += 1;
                    if count >= 64 {
                        out.write_line("  ...");
                        break;
                    }
                }
                out.write_fmt(format_args!("goes: ls workspace={} ({} objects)", ws, count));
            }
            #[cfg(not(target_os = "none"))]
            {
                out.write_line("GOES: ls unavailable");
            }
        }
        Some("manifest") => {
            #[cfg(target_os = "none")]
            {
                if let Some(m) = crate::goes::manifest() {
                    out.write_fmt(format_args!(
                        "manifest: flags=0x{:x} workspaces={}",
                        m.flags, m.workspace_count
                    ));
                    let mut name = [0u8; 32];
                    let count = m.workspace_count.min(16);
                    for i in 0..count {
                        if crate::goes::workspace_name_at(i, &mut name).is_none() {
                            continue;
                        }
                        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                        let s = core::str::from_utf8(&name[..end]).unwrap_or("<non-utf8>");
                        out.write_fmt(format_args!("  - {s}"));
                    }
                    if m.workspace_count > count {
                        out.write_line("  ...");
                    }
                } else {
                    out.write_line("manifest: <unavailable>");
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                out.write_line("GOES: manifest unavailable");
            }
        }
        Some("append") => {
            #[cfg(target_os = "none")]
            {
                let Some(workspace) = argv.get(1) else {
                    out.write_line("usage: goes append <System|Library|Applications|Users|User:name> <text...>");
                    return;
                };
                let mut text = LineBuffer::<384>::new();
                let mut first = true;
                for a in argv.as_slice().iter().copied().skip(2) {
                    if !first {
                        text.push_str(" ");
                    }
                    first = false;
                    text.push_str(a);
                }
                if text.as_str().is_empty() {
                    out.write_line("usage: goes append <Workspace> <text...>");
                    return;
                }

                let mut payload = [0u8; 512];
                let mut n = 0usize;
                let mut push = |bytes: &[u8]| -> bool {
                    if n + bytes.len() > payload.len() {
                        return false;
                    }
                    payload[n..n + bytes.len()].copy_from_slice(bytes);
                    n += bytes.len();
                    true
                };
                if !push(workspace.as_bytes()) || !push(&[0]) || !push(text.as_str().as_bytes()) || !push(&[0]) {
                    out.write_line("goes append: payload too long");
                    return;
                }

                match crate::goes::writer::append_record(workspace, GOES_RECORD_TYPE_SHELL_TEXT_V1, &payload[..n]) {
                    Ok(seq) => {
                        serial::log_line_args(format_args!("shell: goes append ok (seq={})", seq));
                        out.write_fmt(format_args!("goes: appended record seq={seq}"));
                    }
                    Err(e) => {
                        serial::log_line_args(format_args!("shell: goes append failed: {:?}", e));
                        out.write_fmt(format_args!("goes append failed: {:?}", e));
                        explain_goes_write_error(out, workspace, &e);
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("GOES: append unavailable");
            }
        }
        Some("mkobj") => {
            #[cfg(target_os = "none")]
            {
                let Some(ty_s) = argv.get(1) else {
                    out.write_line("usage: goes mkobj <type_u32> <name...>");
                    return;
                };
                let Some(obj_type) = parse_u32_auto(ty_s) else {
                    out.write_line("goes mkobj: invalid type");
                    return;
                };
                let mut name = LineBuffer::<64>::new();
                let mut first = true;
                for a in argv.as_slice().iter().copied().skip(2) {
                    if !first {
                        name.push_str(" ");
                    }
                    first = false;
                    name.push_str(a);
                }
                if name.as_str().is_empty() {
                    out.write_line("usage: goes mkobj <type_u32> <name...>");
                    return;
                }

                let ws = ctx.workspace.name();
                let mut payload = [0u8; 80];
                // id=0 => replay uses seq as id
                crate::goes::replay::encode_create_object_payload_v1(0, obj_type, ws, name.as_str(), &mut payload);
                match crate::goes::writer::append_record(ws, GOES_RECORD_TYPE_CREATE_OBJECT_V1, &payload) {
                    Ok(seq) => {
                        serial::log_line_args(format_args!("shell: goes mkobj ok (id={:#x})", seq));
                        out.write_fmt(format_args!("goes: object created id={:#x}", seq));
                    }
                    Err(e) => {
                        serial::log_line_args(format_args!("shell: goes mkobj failed: {:?}", e));
                        out.write_fmt(format_args!("goes mkobj failed: {:?}", e));
                        explain_goes_write_error(out, ws, &e);
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                out.write_line("GOES: mkobj unavailable");
            }
        }
        Some("addedge") => {
            #[cfg(target_os = "none")]
            {
                let Some(from_s) = argv.get(1) else {
                    out.write_line("usage: goes addedge <from_u64> <to_u64> <edge_type_u32>");
                    return;
                };
                let Some(to_s) = argv.get(2) else {
                    out.write_line("usage: goes addedge <from_u64> <to_u64> <edge_type_u32>");
                    return;
                };
                let Some(et_s) = argv.get(3) else {
                    out.write_line("usage: goes addedge <from_u64> <to_u64> <edge_type_u32>");
                    return;
                };
                let Some(from) = parse_u64_auto(from_s) else {
                    out.write_line("goes addedge: invalid from");
                    return;
                };
                let Some(to) = parse_u64_auto(to_s) else {
                    out.write_line("goes addedge: invalid to");
                    return;
                };
                let Some(edge_type) = parse_u32_auto(et_s) else {
                    out.write_line("goes addedge: invalid edge_type");
                    return;
                };
                let ws = ctx.workspace.name();
                let mut payload = [0u8; 24];
                crate::goes::replay::encode_edge_payload_v1(from, to, edge_type, &mut payload);
                match crate::goes::writer::append_record(ws, GOES_RECORD_TYPE_ADD_EDGE_V1, &payload) {
                    Ok(seq) => {
                        serial::log_line_args(format_args!("shell: goes addedge ok (seq={})", seq));
                        out.write_fmt(format_args!("goes: edge added seq={seq}"));
                    }
                    Err(e) => {
                        serial::log_line_args(format_args!("shell: goes addedge failed: {:?}", e));
                        out.write_fmt(format_args!("goes addedge failed: {:?}", e));
                        explain_goes_write_error(out, ws, &e);
                        #[cfg(target_os = "none")]
                        {
                            if matches!(e, crate::goes::writer::WriteError::PermissionDenied) {
                                if let Some(idx) = crate::goes::replay::snapshot() {
                                    let mut touches_system = false;
                                    if let Some(obj) = idx.objects.get(&from) {
                                        touches_system |= obj.workspace.eq_ignore_ascii_case("System");
                                    }
                                    if let Some(obj) = idx.objects.get(&to) {
                                        touches_system |= obj.workspace.eq_ignore_ascii_case("System");
                                    }
                                    if touches_system {
                                        out.write_line("hint: this edge touches System workspace; it is read-only in normal mode");
                                        out.write_line("hint: require Recovery + SIP OFF + system-write capability to modify System");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                out.write_line("GOES: addedge unavailable");
            }
        }
        Some("rmedge") => {
            #[cfg(target_os = "none")]
            {
                let Some(from_s) = argv.get(1) else {
                    out.write_line("usage: goes rmedge <from_u64> <to_u64> <edge_type_u32>");
                    return;
                };
                let Some(to_s) = argv.get(2) else {
                    out.write_line("usage: goes rmedge <from_u64> <to_u64> <edge_type_u32>");
                    return;
                };
                let Some(et_s) = argv.get(3) else {
                    out.write_line("usage: goes rmedge <from_u64> <to_u64> <edge_type_u32>");
                    return;
                };
                let Some(from) = parse_u64_auto(from_s) else {
                    out.write_line("goes rmedge: invalid from");
                    return;
                };
                let Some(to) = parse_u64_auto(to_s) else {
                    out.write_line("goes rmedge: invalid to");
                    return;
                };
                let Some(edge_type) = parse_u32_auto(et_s) else {
                    out.write_line("goes rmedge: invalid edge_type");
                    return;
                };
                let ws = ctx.workspace.name();
                let mut payload = [0u8; 24];
                crate::goes::replay::encode_edge_payload_v1(from, to, edge_type, &mut payload);
                match crate::goes::writer::append_record(ws, GOES_RECORD_TYPE_REMOVE_EDGE_V1, &payload) {
                    Ok(seq) => {
                        serial::log_line_args(format_args!("shell: goes rmedge ok (seq={})", seq));
                        out.write_fmt(format_args!("goes: edge removed seq={seq}"));
                    }
                    Err(e) => {
                        serial::log_line_args(format_args!("shell: goes rmedge failed: {:?}", e));
                        out.write_fmt(format_args!("goes rmedge failed: {:?}", e));
                        explain_goes_write_error(out, ws, &e);
                        #[cfg(target_os = "none")]
                        {
                            if matches!(e, crate::goes::writer::WriteError::PermissionDenied) {
                                if let Some(idx) = crate::goes::replay::snapshot() {
                                    let mut touches_system = false;
                                    if let Some(obj) = idx.objects.get(&from) {
                                        touches_system |= obj.workspace.eq_ignore_ascii_case("System");
                                    }
                                    if let Some(obj) = idx.objects.get(&to) {
                                        touches_system |= obj.workspace.eq_ignore_ascii_case("System");
                                    }
                                    if touches_system {
                                        out.write_line("hint: this edge touches System workspace; it is read-only in normal mode");
                                        out.write_line("hint: require Recovery + SIP OFF + system-write capability to modify System");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                out.write_line("GOES: rmedge unavailable");
            }
        }
        Some("edges") => {
            #[cfg(target_os = "none")]
            {
                let Some(id_s) = argv.get(1) else {
                    out.write_line("usage: goes edges <object_id_u64>");
                    return;
                };
                let Some(id) = parse_u64_auto(id_s) else {
                    out.write_line("goes edges: invalid id");
                    return;
                };
                let Some(idx) = crate::goes::replay::snapshot() else {
                    out.write_line("goes: index unavailable");
                    return;
                };
                out.write_fmt(format_args!("edges from {:#x}:", id));
                let mut n = 0usize;
                for e in idx.edges.iter().filter(|e| e.from == id && !e.removed) {
                    out.write_fmt(format_args!("  -> {:#x} (type=0x{:x})", e.to, e.edge_type));
                    n += 1;
                    if n >= 64 {
                        out.write_line("  ...");
                        break;
                    }
                }
                out.write_fmt(format_args!("edges to {:#x}:", id));
                let mut n2 = 0usize;
                for e in idx.edges.iter().filter(|e| e.to == id && !e.removed) {
                    out.write_fmt(format_args!("  <- {:#x} (type=0x{:x})", e.from, e.edge_type));
                    n2 += 1;
                    if n2 >= 64 {
                        out.write_line("  ...");
                        break;
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                out.write_line("GOES: edges unavailable");
            }
        }
        Some("view") => {
            // v1 View 执行器（非 SQL）：roots/out/in/type/owner + order/limit
            match argv.get(1) {
                Some("list") | None => {
                    out.write_line("views:");
                    out.write_line("  roots              (list objects in current workspace)");
                    out.write_line("  out <id>           (list out-edges)");
                    out.write_line("  in <id>            (list in-edges)");
                    out.write_line("  type <u32>         (filter objects by type)");
                    out.write_line("  owner <name>       (filter objects by owner; maps to User:<name>)");
                    out.write_line("options:");
                    out.write_line("  --ws <Workspace>   (override source workspace for object views)");
                    out.write_line("  --desc             (order by seq desc)");
                    out.write_line("  --limit <n>        (limit rows)");
                }
                Some("run") => {
                    let Some(view) = argv.get(2) else {
                        out.write_line("usage: goes view run <roots|out|in|type|owner> [...]");
                        return;
                    };

                    match view {
                        "roots" => {
                            #[cfg(target_os = "none")]
                            {
                                let Some(idx) = crate::goes::replay::snapshot() else {
                                    out.write_line("goes: index unavailable");
                                    return;
                                };
                                let (ws_override, order, limit) = parse_view_common(&argv, 3);
                                let base_ws = ws_override.as_deref().unwrap_or(ctx.workspace.name());
                                let sources = resolve_ws_sources(&idx, base_ws);
                                let view = crate::goes::view::ViewObject::roots_union(&sources)
                                    .with_order(order)
                                    .with_limit(limit);
                                let rows = crate::goes::view::run_view(&view, &idx);
                                for r in rows {
                                    let crate::goes::view::ViewRow::Object(o) = r else { continue };
                                    out.write_fmt(format_args!("  {:#x}  type=0x{:x}  name={}", o.id, o.obj_type, o.name));
                                }
                            }
                            #[cfg(not(target_os = "none"))]
                            {
                                out.write_line("view roots unavailable");
                            }
                        }
                        "out" => {
                            #[cfg(target_os = "none")]
                            {
                                let Some(id) = argv.get(3) else {
                                    out.write_line("usage: goes view run out <id>");
                                    return;
                                };
                                let Some(obj) = parse_u64_auto(id) else {
                                    out.write_line("out: invalid id");
                                    return;
                                };
                                let Some(idx) = crate::goes::replay::snapshot() else {
                                    out.write_line("goes: index unavailable");
                                    return;
                                };
                                let (_ws_override, order, limit) = parse_view_common(&argv, 4);
                                let view = crate::goes::view::ViewObject::roots(ctx.workspace.name())
                                    .with_filter(crate::goes::view::ViewFilter::OutEdges(obj))
                                    .with_order(order)
                                    .with_limit(limit);
                                let rows = crate::goes::view::run_view(&view, &idx);
                                for r in rows {
                                    let crate::goes::view::ViewRow::Edge(e) = r else { continue };
                                    out.write_fmt(format_args!("  -> {:#x} (type=0x{:x})", e.to, e.edge_type));
                                }
                            }
                            #[cfg(not(target_os = "none"))]
                            {
                                out.write_line("view out unavailable");
                            }
                        }
                        "in" => {
                            #[cfg(target_os = "none")]
                            {
                                let Some(id) = argv.get(3) else {
                                    out.write_line("usage: goes view run in <id>");
                                    return;
                                };
                                let Some(obj) = parse_u64_auto(id) else {
                                    out.write_line("in: invalid id");
                                    return;
                                };
                                let Some(idx) = crate::goes::replay::snapshot() else {
                                    out.write_line("goes: index unavailable");
                                    return;
                                };
                                let (_ws_override, order, limit) = parse_view_common(&argv, 4);
                                let view = crate::goes::view::ViewObject::roots(ctx.workspace.name())
                                    .with_filter(crate::goes::view::ViewFilter::InEdges(obj))
                                    .with_order(order)
                                    .with_limit(limit);
                                let rows = crate::goes::view::run_view(&view, &idx);
                                for r in rows {
                                    let crate::goes::view::ViewRow::Edge(e) = r else { continue };
                                    out.write_fmt(format_args!("  <- {:#x} (type=0x{:x})", e.from, e.edge_type));
                                }
                            }
                            #[cfg(not(target_os = "none"))]
                            {
                                out.write_line("view in unavailable");
                            }
                        }
                        "type" => {
                            #[cfg(target_os = "none")]
                            {
                                let Some(ty_s) = argv.get(3) else {
                                    out.write_line("usage: goes view run type <u32>");
                                    return;
                                };
                                let Some(ty) = parse_u32_auto(ty_s) else {
                                    out.write_line("type: invalid");
                                    return;
                                };
                                let Some(idx) = crate::goes::replay::snapshot() else {
                                    out.write_line("goes: index unavailable");
                                    return;
                                };
                                let (ws_override, order, limit) = parse_view_common(&argv, 4);
                                let base_ws = ws_override.as_deref().unwrap_or(ctx.workspace.name());
                                let sources = resolve_ws_sources(&idx, base_ws);
                                let view = crate::goes::view::ViewObject::roots_union(&sources)
                                    .with_filter(crate::goes::view::ViewFilter::ObjType(ty))
                                    .with_order(order)
                                    .with_limit(limit);
                                let rows = crate::goes::view::run_view(&view, &idx);
                                for r in rows {
                                    let crate::goes::view::ViewRow::Object(o) = r else { continue };
                                    out.write_fmt(format_args!("  {:#x}  type=0x{:x}  name={}", o.id, o.obj_type, o.name));
                                }
                            }
                            #[cfg(not(target_os = "none"))]
                            {
                                out.write_line("view type unavailable");
                            }
                        }
                        "owner" => {
                            #[cfg(target_os = "none")]
                            {
                                let Some(who) = argv.get(3) else {
                                    out.write_line("usage: goes view run owner <name>");
                                    return;
                                };
                                let Some(idx) = crate::goes::replay::snapshot() else {
                                    out.write_line("goes: index unavailable");
                                    return;
                                };
                                let (ws_override, order, limit) = parse_view_common(&argv, 4);
                                let base_ws = ws_override.as_deref().unwrap_or(ctx.workspace.name());
                                let sources = resolve_ws_sources(&idx, base_ws);
                                let view = crate::goes::view::ViewObject::roots_union(&sources)
                                    .with_filter(crate::goes::view::ViewFilter::Owner(who.to_string()))
                                    .with_order(order)
                                    .with_limit(limit);
                                let rows = crate::goes::view::run_view(&view, &idx);
                                for r in rows {
                                    let crate::goes::view::ViewRow::Object(o) = r else { continue };
                                    out.write_fmt(format_args!("  {:#x}  type=0x{:x}  name={}", o.id, o.obj_type, o.name));
                                }
                            }
                            #[cfg(not(target_os = "none"))]
                            {
                                out.write_line("view owner unavailable");
                            }
                        }
                        _ => out.write_line("unknown view (try `goes view list`)"),
                    }
                }
                _ => out.write_line("usage: goes view [list|run ...]"),
            }
        }
        Some("meta") => {
            #[cfg(target_os = "none")]
            {
                let Some(id_s) = argv.get(1) else {
                    out.write_line("usage: goes meta <obj_id> <ws|-|-> <type|0> <name|->");
                    out.write_line("  example: goes meta 0x10 - 0 newname");
                    return;
                };
                let Some(obj_id) = parse_u64_auto(id_s) else {
                    out.write_line("goes meta: invalid obj_id");
                    return;
                };
                let ws_s = argv.get(2).unwrap_or("-");
                let ty_s = argv.get(3).unwrap_or("0");
                let name_s = argv.get(4).unwrap_or("-");
                let new_ws = if ws_s == "-" { None } else { Some(ws_s) };
                let new_name = if name_s == "-" { None } else { Some(name_s) };
                let new_type = parse_u32_auto(ty_s).unwrap_or(0);

                // Write into the object's current workspace (v1: simplest rule).
                let ws = ctx.workspace.name();
                let mut payload = [0u8; 80];
                crate::goes::replay::encode_update_object_meta_payload_v1(
                    obj_id,
                    new_type,
                    new_ws,
                    new_name,
                    &mut payload,
                );
                match crate::goes::writer::append_record(ws, GOES_RECORD_TYPE_UPDATE_OBJECT_META_V1, &payload) {
                    Ok(seq) => out.write_fmt(format_args!("goes: meta updated (seq={seq})")),
                    Err(e) => {
                        out.write_fmt(format_args!("goes meta failed: {:?}", e));
                        explain_goes_write_error(out, ws, &e);
                        #[cfg(target_os = "none")]
                        {
                            if matches!(e, crate::goes::writer::WriteError::PermissionDenied) {
                                let mut touches_system = false;
                                if let Some(new_ws) = new_ws {
                                    touches_system |= new_ws.eq_ignore_ascii_case("System");
                                }
                                if let Some(idx) = crate::goes::replay::snapshot() {
                                    if let Some(obj) = idx.objects.get(&obj_id) {
                                        touches_system |= obj.workspace.eq_ignore_ascii_case("System");
                                    }
                                }
                                if touches_system {
                                    out.write_line("hint: this operation touches System workspace; it is read-only in normal mode");
                                    out.write_line("hint: require Recovery + SIP OFF + system-write capability to modify System");
                                }
                            }
                        }
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("goes: meta unavailable");
            }
        }
        Some("mkws") => {
            #[cfg(target_os = "none")]
            {
                let Some(name) = argv.get(1) else {
                    out.write_line("usage: goes mkws <name>");
                    return;
                };
                if crate::workspace::is_system_workspace_name_ci(name) {
                    out.write_line("goes mkws: system workspaces are frozen (System/Users/Applications/Library)");
                    return;
                }
                let mut payload = [0u8; 40];
                crate::goes::replay::encode_create_workspace_payload_v1(name, 0, &mut payload);
                let ws = "Users";
                match crate::goes::writer::append_record(ws, GOES_RECORD_TYPE_CREATE_WORKSPACE_V1, &payload) {
                    Ok(seq) => out.write_fmt(format_args!("workspace created (seq={seq})")),
                    Err(e) => {
                        out.write_fmt(format_args!("goes mkws failed: {:?}", e));
                        explain_goes_write_error(out, ws, &e);
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("goes: mkws unavailable");
            }
        }
        Some("mkuser") => {
            #[cfg(target_os = "none")]
            {
                let Some(name) = argv.get(1) else {
                    out.write_line("usage: goes mkuser <username> [admin|normal] [disabled]");
                    return;
                };
                let kind = argv.get(2).unwrap_or("normal");
                let disabled_flag = argv.get(3) == Some("disabled");
                let mut flags = 0u32;
                if kind == "admin" {
                    flags |= 1;
                }
                if disabled_flag {
                    flags |= 2;
                }
                let mut home_ws = String::from("User:");
                home_ws.push_str(name);
                let mut payload = [0u8; 72];
                crate::goes::replay::encode_account_object_payload_v1(name, flags, &home_ws, &mut payload);
                let ws = "Users";
                match crate::goes::writer::append_record(ws, GOES_RECORD_TYPE_ACCOUNT_OBJECT_V1, &payload) {
                    Ok(seq) => {
                        crate::audit::emit(
                            crate::audit::EVENT_USER_CREATE,
                            "Users",
                            name,
                            flags as u64,
                            seq,
                        );
                        out.write_fmt(format_args!("user record written (seq={seq})"))
                    }
                    Err(e) => {
                        out.write_fmt(format_args!("goes mkuser failed: {:?}", e));
                        explain_goes_write_error(out, ws, &e);
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("goes: mkuser unavailable");
            }
        }
        Some("boot") => {
            #[cfg(target_os = "none")]
            {
                match argv.get(1) {
                    Some("set-active") => {
                        let Some(n) = argv.get(2).and_then(parse_u32_auto) else {
                            out.write_line("usage: goes boot set-active <n>");
                            return;
                        };
                        let user = argv.get(3).unwrap_or("");
                        let mut payload = [0u8; 40];
                        crate::goes::replay::encode_boot_manifest_update_payload_v1(n, user, &mut payload);
                        let ws = "System";
                        match crate::goes::writer::append_record(ws, GOES_RECORD_TYPE_UPDATE_BOOT_MANIFEST_V1, &payload) {
                            Ok(seq) => {
                                if !user.trim().is_empty() {
                                    crate::audit::emit(
                                        crate::audit::EVENT_USER_SWITCH,
                                        "System",
                                        user,
                                        n as u64,
                                        seq,
                                    );
                                }
                                out.write_fmt(format_args!("bootmanifest update recorded (seq={seq})"))
                            }
                            Err(e) => {
                                out.write_fmt(format_args!("goes boot failed: {:?}", e));
                                explain_goes_write_error(out, ws, &e);
                            }
                        }
                    }
                    _ => {
                        out.write_line("usage: goes boot set-active <n> [default_user]");
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("goes: boot unavailable");
            }
        }
        _ => out.write_line("usage: goes [status|ls|manifest|append|mkobj|meta|mkws|mkuser|boot|addedge|rmedge|edges|view]"),
    }
}

#[cfg(target_os = "none")]
fn parse_u32_auto(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        u32::from_str_radix(s, 10).ok()
    }
}

#[cfg(target_os = "none")]
fn parse_u64_auto(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        u64::from_str_radix(s, 10).ok()
    }
}

fn cmd_ws(ctx: &mut ShellContext, out: &mut dyn ShellOut, argv: Argv<'_>) {
    match argv.get(0) {
        Some("list") | None => {
            #[cfg(target_os = "none")]
            {
                let mut list = String::from("workspaces: System, Library, Applications, Users");
                if let Some(user) = ctx.user.as_deref() {
                    list.push_str(", ");
                    list.push_str("User:");
                    list.push_str(user);
                }
                if let Some(idx) = crate::goes::replay::snapshot() {
                    let mut extra = 0usize;
                    for (name, _) in idx.workspaces.iter() {
                        // avoid printing the built-ins twice
                        if matches!(
                            name.as_str(),
                            "System" | "Library" | "Applications" | "Users"
                        ) {
                            continue;
                        }
                        list.push_str(", ");
                        list.push_str(name);
                        extra += 1;
                        if extra >= 8 {
                            list.push_str(", ...");
                            break;
                        }
                    }
                }
                out.write_line(&list);
            }
            #[cfg(not(target_os = "none"))]
            {
                if let Some(user) = ctx.user.as_deref() {
                    out.write_fmt(format_args!(
                        "workspaces: System, Library, Applications, Users, User:{}",
                        user
                    ));
                } else {
                    out.write_line("workspaces: System, Library, Applications, Users");
                }
            }
        }
        Some("enter") => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: ws enter <System|Library|Applications|Users|User:name>");
                return;
            };
            if !ws_enter_allowed(ctx, name) {
                out.write_line("ws: permission denied");
                return;
            }
            if try_enter_ws(ctx, name) {
                out.write_fmt(format_args!("entered: {}", ctx.workspace.label()));
            } else {
                out.write_line("ws: unknown workspace");
            }
        }
        Some("set") => {
            #[cfg(target_os = "none")]
            {
                let Some(name) = argv.get(1) else {
                    out.write_line("usage: ws set <name> <writable|composed> [sources...]");
                    return;
                };
                if crate::workspace::is_system_workspace_name_ci(name) {
                    out.write_line(
                        "ws set: system workspaces are frozen (System/Users/Applications/Library)",
                    );
                    return;
                }
                let Some(kind_s) = argv.get(2) else {
                    out.write_line("usage: ws set <name> <writable|composed> [sources...]");
                    return;
                };
                let kind = match kind_s {
                    "writable" => crate::goes::replay::WorkspaceKind::Writable,
                    "composed" => crate::goes::replay::WorkspaceKind::Composed,
                    _ => {
                        out.write_line("ws set: kind must be writable|composed");
                        return;
                    }
                };
                let mut sources: [&str; 8] = [""; 8];
                let mut n = 0usize;
                for s in argv.as_slice().iter().copied().skip(3) {
                    if n >= sources.len() {
                        break;
                    }
                    sources[n] = s;
                    n += 1;
                }

                // spec records are metadata; store them in a workspace the caller can write:
                // - for User:<owner>/... allow the owner to write into User:<owner>
                // - otherwise require admin and write into Users
                let meta_ws = if let Some(rest) = name.strip_prefix("User:") {
                    let owner = rest.split('/').next().unwrap_or(rest);
                    if ctx.user.as_deref() == Some(owner) || crate::sandbox::context().user_is_admin
                    {
                        let mut ws = String::from("User:");
                        ws.push_str(owner);
                        ws
                    } else {
                        "Users".to_string()
                    }
                } else {
                    "Users".to_string()
                };

                let src_slice = &sources[..n];
                let mut payload = alloc::vec::Vec::new();
                crate::goes::replay::encode_workspace_spec_payload_v1(
                    name,
                    kind,
                    src_slice,
                    &mut payload,
                );
                match crate::goes::writer::append_record(
                    &meta_ws,
                    GOES_RECORD_TYPE_WORKSPACE_SPEC_V1,
                    &payload,
                ) {
                    Ok(seq) => out.write_fmt(format_args!("ws spec updated (seq={seq})")),
                    Err(e) => {
                        out.write_fmt(format_args!("ws set failed: {:?}", e));
                        explain_goes_write_error(out, &meta_ws, &e);
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                out.write_line("ws: set unavailable");
            }
        }
        Some("info") => {
            #[cfg(target_os = "none")]
            {
                let name = argv.get(1).unwrap_or(ctx.workspace.name());
                let Some(idx) = crate::goes::replay::snapshot() else {
                    out.write_line("ws: GOES index unavailable");
                    return;
                };
                if let Some(spec) = idx.workspace_specs.get(name) {
                    let kind = match spec.kind {
                        crate::goes::replay::WorkspaceKind::Writable => "writable",
                        crate::goes::replay::WorkspaceKind::Composed => "composed",
                    };
                    out.write_fmt(format_args!(
                        "ws: {name} (kind={kind}, sources={})",
                        spec.sources.len()
                    ));
                    for s in spec.sources.iter().take(16) {
                        out.write_fmt(format_args!("  - {s}"));
                    }
                    if spec.sources.len() > 16 {
                        out.write_line("  ...");
                    }
                } else {
                    out.write_fmt(format_args!("ws: {name} (no spec; default writable)"));
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                out.write_line("ws: info unavailable");
            }
        }
        _ => out.write_line("usage: ws [list|enter <name>]"),
    }
}

#[cfg(target_os = "none")]
fn fits_name32(s: &str) -> bool {
    !s.is_empty() && s.as_bytes().len() <= 32
}

#[cfg(target_os = "none")]
fn find_object_by_name(idx: &crate::goes::replay::Index, ws: &str, name: &str) -> Option<u64> {
    idx.objects
        .values()
        .find(|o| o.workspace == ws && o.name == name)
        .map(|o| o.id)
}

#[cfg(target_os = "none")]
fn make_parse_users_path(path: &str) -> Option<(&str, &str)> {
    // Accept `/Users/<user>/<name>` only (v1 limitation).
    let mut parts = path.split('/').filter(|s| !s.is_empty());
    let root = parts.next()?;
    if root != "Users" {
        return None;
    }
    let user = parts.next()?;
    let name = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some((user, name))
}

fn cmd_make(ctx: &mut ShellContext, out: &mut dyn ShellOut, argv: Argv<'_>) {
    #[cfg(target_os = "none")]
    {
        let kind = argv.get(0);
        let (mode, name) = match kind {
            Some("file") => (Some("file"), argv.get(1)),
            Some("ws") => (Some("ws"), argv.get(1)),
            Some(v) => (None, Some(v)),
            None => (None, None),
        };
        let Some(name) = name else {
            out.write_line("usage: make [file|ws] <name>");
            out.write_line("  make <name>        (infer: name with '.' => file, else ws)");
            out.write_line("  make file <name>   (create object in workspace)");
            out.write_line("  make ws <name>     (create workspace)");
            out.write_line("  path: /Users/<u>/<name> (v1)");
            return;
        };

        let infer_file = name.contains('.');
        let is_ws = mode == Some("ws") || (mode.is_none() && !infer_file);
        let is_file = mode == Some("file") || (mode.is_none() && infer_file);

        let Some(idx) = crate::goes::replay::snapshot() else {
            out.write_line("make: GOES index unavailable");
            return;
        };

        if is_ws {
            let ws_name = if name.starts_with('/') {
                if let Some((user, leaf)) = make_parse_users_path(name) {
                    format!("User:{user}/{leaf}")
                } else {
                    out.write_line("make ws: unsupported path (v1: only /Users/<u>/<name>)");
                    return;
                }
            } else if name.starts_with("User:") {
                name.to_string()
            } else {
                let Some(user) = ctx.user.as_deref() else {
                    out.write_line("make ws: no user context");
                    return;
                };
                format!("User:{user}/{name}")
            };

            // v2：禁止把系统级 Workspace 当作普通 workspace 创建/覆盖。
            if crate::workspace::is_system_workspace_name_ci(&ws_name) {
                out.write_line(
                    "make ws: system workspaces are frozen (System/Users/Applications/Library)",
                );
                return;
            }

            if !fits_name32(&ws_name) {
                out.write_line("make ws: name too long (max 32 bytes) or empty");
                return;
            }
            if idx.workspaces.contains_key(&ws_name) {
                out.write_line("make ws: already exists");
                return;
            }

            // Write workspace creation record into a workspace the caller can write:
            // user sub-workspace => write into User:<owner>
            let meta_ws = if let Some(rest) = ws_name.strip_prefix("User:") {
                let owner = rest.split('/').next().unwrap_or(rest);
                let mut w = String::from("User:");
                w.push_str(owner);
                w
            } else {
                ctx.workspace.name().to_string()
            };

            let mut payload = [0u8; 40];
            crate::goes::replay::encode_create_workspace_payload_v1(&ws_name, 0, &mut payload);
            match crate::goes::writer::append_record(
                &meta_ws,
                GOES_RECORD_TYPE_CREATE_WORKSPACE_V1,
                &payload,
            ) {
                Ok(seq) => out.write_fmt(format_args!("make ws: created {ws_name} (seq={seq})")),
                Err(e) => {
                    out.write_fmt(format_args!("make ws failed: {:?}", e));
                    explain_goes_write_error(out, &meta_ws, &e);
                }
            }
            return;
        }

        if is_file {
            // Determine target workspace and object name.
            let (target_ws, obj_name) = if name.starts_with('/') {
                if let Some((user, leaf)) = make_parse_users_path(name) {
                    (format!("User:{user}"), leaf.to_string())
                } else {
                    out.write_line("make file: unsupported path (v1: only /Users/<u>/<name>)");
                    return;
                }
            } else {
                (ctx.workspace.name().to_string(), name.to_string())
            };

            if !fits_name32(&target_ws) || !fits_name32(&obj_name) {
                out.write_line("make file: name too long (max 32 bytes) or empty");
                return;
            }
            if find_object_by_name(&idx, &target_ws, &obj_name).is_some() {
                out.write_line("make file: already exists");
                return;
            }

            let obj_type = 1u32; // v1: treat as Blob-like
            let mut payload = [0u8; 80];
            crate::goes::replay::encode_create_object_payload_v1(
                0,
                obj_type,
                &target_ws,
                &obj_name,
                &mut payload,
            );
            match crate::goes::writer::append_record(
                &target_ws,
                GOES_RECORD_TYPE_CREATE_OBJECT_V1,
                &payload,
            ) {
                Ok(seq) => out.write_fmt(format_args!(
                    "make file: created {obj_name} (id={:#x})",
                    seq
                )),
                Err(e) => {
                    out.write_fmt(format_args!("make file failed: {:?}", e));
                    explain_goes_write_error(out, &target_ws, &e);
                }
            }
            return;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = ctx;
        let _ = argv;
        out.write_line("make: unavailable");
    }
}

fn ws_enter_allowed(ctx: &ShellContext, target: &str) -> bool {
    let is_admin = {
        #[cfg(target_os = "none")]
        {
            crate::sandbox::context().user_is_admin
        }
        #[cfg(not(target_os = "none"))]
        {
            ctx.user.as_deref() == Some("admin")
        }
    };
    if is_admin {
        return true;
    }
    // v1: Users 只能进入自己的 User:<name>
    if target.starts_with("User:") || target.starts_with("user:") {
        let n = target.splitn(2, ':').nth(1).unwrap_or("").trim();
        let n = n.split('/').next().unwrap_or(n).trim();
        let Some(cur) = ctx.user.as_deref() else {
            return false;
        };
        return cur == n;
    }
    true
}

fn cmd_whoami(ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv<'_>) {
    let name = ctx.user.as_deref().unwrap_or("unknown");
    #[cfg(target_os = "none")]
    {
        if let Some(idx) = crate::goes::replay::snapshot() {
            if let Some(acct) = idx.accounts.get(name) {
                out.write_fmt(format_args!(
                    "user: {} (admin={}, disabled={}, home={})",
                    acct.username, acct.admin, acct.disabled, acct.home_workspace
                ));
                return;
            }
        }
    }
    out.write_fmt(format_args!("user: {}", name));
}

fn cmd_user(_ctx: &mut ShellContext, out: &mut dyn ShellOut, argv: Argv<'_>) {
    #[cfg(target_os = "none")]
    {
        match argv.get(0) {
            Some("list") | None => {
                let Some(idx) = crate::goes::replay::snapshot() else {
                    out.write_line("user: GOES index unavailable");
                    return;
                };
                out.write_line("users:");
                let mut n = 0usize;
                for a in idx.accounts.values() {
                    out.write_fmt(format_args!(
                        "  {} (admin={}, disabled={}, home={})",
                        a.username, a.admin, a.disabled, a.home_workspace
                    ));
                    n += 1;
                    if n >= 64 {
                        out.write_line("  ...");
                        break;
                    }
                }
            }
            Some("create") => {
                let Some(name) = argv.get(1) else {
                    out.write_line("usage: user create <name> [admin|normal]");
                    return;
                };
                let kind = argv.get(2).unwrap_or("normal");
                let mut flags = 0u32;
                if kind == "admin" {
                    flags |= 1;
                }
                let mut home_ws = String::from("User:");
                home_ws.push_str(name);
                let mut payload = [0u8; 72];
                crate::goes::replay::encode_account_object_payload_v1(
                    name,
                    flags,
                    &home_ws,
                    &mut payload,
                );
                let ws = "Users";
                match crate::goes::writer::append_record(
                    ws,
                    GOES_RECORD_TYPE_ACCOUNT_OBJECT_V1,
                    &payload,
                ) {
                    Ok(seq) => {
                        crate::audit::emit(
                            crate::audit::EVENT_USER_CREATE,
                            "Users",
                            name,
                            flags as u64,
                            seq,
                        );
                        out.write_fmt(format_args!("user: record written (seq={seq})"))
                    }
                    Err(e) => {
                        out.write_fmt(format_args!("user create failed: {:?}", e));
                        explain_goes_write_error(out, ws, &e);
                    }
                }
            }
            Some("disable") | Some("enable") => {
                let Some(name) = argv.get(1) else {
                    out.write_line("usage: user disable <name>");
                    out.write_line("       user enable <name>");
                    return;
                };
                let enable = argv.get(0) == Some("enable");
                let Some(idx) = crate::goes::replay::snapshot() else {
                    out.write_line("user: GOES index unavailable");
                    return;
                };
                let Some(old) = idx.accounts.get(name) else {
                    out.write_line("user: not found");
                    return;
                };
                let mut flags = 0u32;
                if old.admin {
                    flags |= 1;
                }
                if !enable {
                    flags |= 2;
                }
                let mut payload = [0u8; 72];
                crate::goes::replay::encode_account_object_payload_v1(
                    &old.username,
                    flags,
                    &old.home_workspace,
                    &mut payload,
                );
                let ws = "Users";
                match crate::goes::writer::append_record(
                    ws,
                    GOES_RECORD_TYPE_ACCOUNT_OBJECT_V1,
                    &payload,
                ) {
                    Ok(seq) => {
                        crate::audit::emit(
                            if enable {
                                crate::audit::EVENT_USER_ENABLE
                            } else {
                                crate::audit::EVENT_USER_DISABLE
                            },
                            "Users",
                            &old.username,
                            enable as u64,
                            seq,
                        );
                        out.write_fmt(format_args!("user: updated (seq={seq})"))
                    }
                    Err(e) => {
                        out.write_fmt(format_args!("user update failed: {:?}", e));
                        explain_goes_write_error(out, ws, &e);
                    }
                }
            }
            _ => out.write_line("usage: user [list|create|disable|enable]"),
        }
        return;
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = argv;
        out.write_line("user: unavailable");
    }
}

fn cmd_sip(ctx: &mut ShellContext, out: &mut dyn ShellOut, argv: Argv<'_>) {
    match argv.get(0) {
        Some("status") | None => {
            out.write_fmt(format_args!(
                "sip: {} (mode={})",
                if ctx.sip_on { "on" } else { "off" },
                if ctx.mode == Mode::Recovery {
                    "recovery"
                } else {
                    "normal"
                }
            ));
        }
        Some("on") | Some("off") => {
            #[cfg(target_os = "none")]
            {
                let desired_on = argv.get(0) == Some("on");
                let sbx = crate::sandbox::context();
                if !sbx.recovery {
                    out.write_line("sip: can only be changed in recovery mode");
                    return;
                }
                if !sbx.user_is_admin {
                    out.write_line("sip: admin required");
                    return;
                }

                let mut payload = [0u8; 16];
                payload[0..4].copy_from_slice(&1u32.to_le_bytes());
                payload[4..8].copy_from_slice(&(desired_on as u32).to_le_bytes());
                payload[8..16].copy_from_slice(&0u64.to_le_bytes());

                // Persist SIP override into GOES record log (applies on next boot via oneboot).
                let ws = "Users";
                match crate::goes::writer::append_record(
                    ws,
                    crate::goes::records::RECORD_SIP_OVERRIDE_V1,
                    &payload,
                ) {
                    Ok(seq) => {
                        #[cfg(target_os = "none")]
                        {
                            crate::audit::emit(
                                crate::audit::EVENT_SIP_SET,
                                "System",
                                if desired_on { "sip_on" } else { "sip_off" },
                                desired_on as u64,
                                seq,
                            );
                        }
                        out.write_fmt(format_args!(
                            "sip: override recorded ({}), reboot to apply (seq={})",
                            if desired_on { "on" } else { "off" },
                            seq
                        ));
                    }
                    Err(e) => {
                        out.write_fmt(format_args!("sip set failed: {:?}", e));
                        #[cfg(target_os = "none")]
                        explain_goes_write_error(out, ws, &e);
                    }
                }
                return;
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("sip: unavailable");
            }
        }
        _ => out.write_line("usage: sip [status|on|off]"),
    }
}

fn cmd_reboot(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv<'_>) {
    out.write_line("reboot: stub");
}

fn cmd_app(ctx: &mut ShellContext, out: &mut dyn ShellOut, argv: Argv<'_>) {
    match argv.get(0) {
        Some("list") | None => {
            #[cfg(target_os = "none")]
            {
                let Some(idx) = crate::goes::replay::snapshot() else {
                    out.write_line("app: GOES index unavailable");
                    return;
                };
                out.write_line("apps:");
                let running = crate::app::running_list();
                for a in idx.apps.values() {
                    let status = if a.removed {
                        "removed"
                    } else if running.contains_key(&a.name) {
                        "running"
                    } else {
                        "installed"
                    };
                    out.write_fmt(format_args!(
                        "  - {} (ver={}, entry={}, status={}, caps=0x{:x}, bin={}B)",
                        a.name,
                        if a.version.is_empty() {
                            "<none>"
                        } else {
                            a.version.as_str()
                        },
                        a.entry,
                        status,
                        a.caps_mask,
                        a.binary_size
                    ));
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("app: unavailable");
            }
        }
        Some("info") => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: app info <name>");
                return;
            };
            #[cfg(target_os = "none")]
            {
                let Some(idx) = crate::goes::replay::snapshot() else {
                    out.write_line("app: GOES index unavailable");
                    return;
                };
                if let Some(a) = idx.apps.get(name) {
                    out.write_fmt(format_args!("name: {}", a.name));
                    out.write_fmt(format_args!(
                        "version: {}",
                        if a.version.is_empty() {
                            "<none>"
                        } else {
                            a.version.as_str()
                        }
                    ));
                    out.write_fmt(format_args!("entry: {}", a.entry));
                    out.write_fmt(format_args!("seq: {}", a.seq));
                    out.write_fmt(format_args!("workspace: {}", a.workspace));
                    out.write_fmt(format_args!(
                        "appdata_scope: Library/AppData/{} (ws=LAD:{})",
                        a.name, a.name
                    ));
                    out.write_fmt(format_args!("removed: {}", a.removed));
                    out.write_fmt(format_args!("caps_mask: 0x{:x}", a.caps_mask));
                    out.write_fmt(format_args!("binary_size: {} bytes", a.binary_size));

                    // Debug: show current domain caps summary (helps verify sandbox policy wiring).
                    let cur = crate::sandbox::current_domain();
                    if let Some(detail) = crate::sandbox::domain_detail_by_id(cur) {
                        out.write_fmt(format_args!(
                            "current_domain: id={} kind={:?} name={} owner={} admin={}",
                            detail.summary.id,
                            detail.summary.kind,
                            detail.summary.name,
                            detail.summary.owner,
                            detail.summary.owner_admin
                        ));
                        out.write_line("current_caps:");
                        for cap in detail.caps.iter() {
                            out.write_fmt(format_args!(
                                "  - {:?} scope={:?} rights=0x{:x}",
                                cap.cap_type, cap.scope, cap.rights
                            ));
                        }
                    }
                } else {
                    out.write_line("app: not found");
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("app: unavailable");
            }
        }
        Some("install") | Some("add") => {
            #[cfg(target_os = "none")]
            {
                let Some(name) = argv.get(1) else {
                    out.write_line("usage: app install <name> <entry> [version] [caps_mask_hex]");
                    return;
                };
                let Some(entry) = argv.get(2) else {
                    out.write_line("usage: app install <name> <entry> [version] [caps_mask_hex]");
                    return;
                };
                let version = argv.get(3).unwrap_or("0.0.0");
                let caps_mask = argv
                    .get(4)
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0);
                match crate::app::install(name, entry, version, caps_mask) {
                    Ok(seq) => {
                        serial::log_line_args(format_args!("shell: app install ok (seq={})", seq));
                        out.write_fmt(format_args!("app: installed (seq={seq})"));
                    }
                    Err(e) => {
                        serial::log_line_args(format_args!("shell: app install failed: {:?}", e));
                        out.write_fmt(format_args!("app install failed: {:?}", e));
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("app: unavailable");
            }
        }
        Some("assets") => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: app assets <name>");
                return;
            };
            #[cfg(target_os = "none")]
            {
                let Some(idx) = crate::goes::replay::snapshot() else {
                    out.write_line("app: GOES index unavailable");
                    return;
                };
                if !idx.apps.contains_key(name) {
                    out.write_line("app: not found");
                    return;
                }
                out.write_fmt(format_args!("assets for {}:", name));
                let mut found = 0usize;
                for ((app, asset), loc) in idx.app_assets.iter() {
                    if app != name {
                        continue;
                    }
                    found += 1;
                    out.write_fmt(format_args!(
                        "  - {} ({}B, seq={})",
                        asset, loc.data_len, loc.seq
                    ));
                }
                if found == 0 {
                    out.write_line("  (none)");
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("app: unavailable");
            }
        }
        Some("run") => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: app run <name>");
                return;
            };
            #[cfg(target_os = "none")]
            {
                if crate::sandbox::context().recovery {
                    out.write_line("app: disabled in recovery mode");
                    return;
                }
                let Some(user) = ctx.user.as_deref() else {
                    out.write_line("app: no user context");
                    return;
                };
                // Default is foreground: run the app synchronously and return to the prompt after it exits.
                // Use `--bg` to spawn in background (output may interleave with the prompt).
                let bg = matches!(argv.get(2), Some("--bg"));
                // Debug: show the AppDomain intended read/write ranges (no path semantics).
                if let Some(idx) = crate::goes::replay::snapshot() {
                    if let Some(app) = idx.apps.get(name) {
                        serial::log_line_args(format_args!(
                            "shell: app run scope read={} rw=LAD:{}",
                            app.workspace, app.name
                        ));
                    }
                }
                if bg {
                    let args = alloc::boxed::Box::new((
                        alloc::string::String::from(name),
                        alloc::string::String::from(user),
                    ));
                    let arg_ptr = alloc::boxed::Box::into_raw(args) as usize;
                    extern "C" fn app_task(arg: usize) -> ! {
                        let boxed = unsafe {
                            alloc::boxed::Box::from_raw(
                                arg as *mut (alloc::string::String, alloc::string::String),
                            )
                        };
                        let (name, user) = *boxed;
                        serial::log_line_args(format_args!(
                            "sched: app task start name={} user={}",
                            name, user
                        ));
                        match crate::app::run(&name, &user) {
                            Ok(domain) => {
                                let _ = crate::app::console_write_line_args(format_args!(
                                    "app: run ok (domain={})",
                                    domain
                                ));
                            }
                            Err(e) => {
                                let _ = crate::app::console_write_line_args(format_args!(
                                    "app: run failed: {:?}",
                                    e
                                ));
                            }
                        }
                        crate::sched::exit_current();
                    }
                    let tid = crate::sched::spawn_domain_thread(
                        "app",
                        crate::sandbox::current_domain() as u32,
                        crate::sched::Priority::Normal,
                        app_task,
                        arg_ptr,
                    );
                    out.write_fmt(format_args!("app: spawned task {}", tid));
                } else {
                    // Foreground run: execute in a dedicated task and wait.
                    //
                    // Rationale:
                    // The scheduler snapshots `sandbox::current_domain()` into the running task on
                    // preemption. `app::run()` switches the current domain to an AppDomain while it
                    // executes; if we run it directly on the shell task, a timer tick can “convert”
                    // the shell task into the AppDomain and it may later be killed/reaped.
                    use core::sync::atomic::{AtomicBool, Ordering};

                    struct AppFgShared {
                        done: AtomicBool,
                        name: alloc::string::String,
                        user: alloc::string::String,
                        result: spin::Mutex<alloc::string::String>,
                    }

                    let shared = alloc::boxed::Box::new(AppFgShared {
                        done: AtomicBool::new(false),
                        name: alloc::string::String::from(name),
                        user: alloc::string::String::from(user),
                        result: spin::Mutex::new(alloc::string::String::new()),
                    });
                    let shared_ptr = alloc::boxed::Box::into_raw(shared);

                    extern "C" fn app_fg_task(arg: usize) -> ! {
                        let shared = unsafe { &*(arg as *const AppFgShared) };
                        serial::log_line_args(format_args!(
                            "sched: app fg task start name={} user={}",
                            shared.name, shared.user
                        ));
                        let msg = match crate::app::run(&shared.name, &shared.user) {
                            Ok(domain) => alloc::format!("app: run ok (domain={})", domain),
                            Err(e) => alloc::format!("app: run failed: {:?}", e),
                        };
                        *shared.result.lock() = msg;
                        shared.done.store(true, Ordering::Release);
                        crate::sched::exit_current();
                    }

                    let _tid = crate::sched::spawn_domain_thread(
                        "app-fg",
                        2,
                        crate::sched::Priority::Normal,
                        app_fg_task,
                        shared_ptr as usize,
                    );

                    while !unsafe { (*shared_ptr).done.load(Ordering::Acquire) } {
                        crate::sched::sleep_ticks(1);
                    }

                    let msg = unsafe { (*shared_ptr).result.lock().clone() };
                    unsafe {
                        drop(alloc::boxed::Box::from_raw(shared_ptr));
                    }
                    out.write_fmt(format_args!("{}", msg));
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("app: unavailable");
            }
        }
        Some("stress") => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: app stress <name> <count>");
                return;
            };
            let Some(count) = argv.get(2).and_then(|s| s.parse::<u32>().ok()) else {
                out.write_line("usage: app stress <name> <count>");
                return;
            };
            #[cfg(target_os = "none")]
            {
                if crate::sandbox::context().recovery {
                    out.write_line("app: disabled in recovery mode");
                    return;
                }
                let Some(user) = ctx.user.as_deref() else {
                    out.write_line("app: no user context");
                    return;
                };
                out.write_fmt(format_args!(
                    "app: stress start name={} count={}",
                    name, count
                ));
                let mut ok = 0u32;
                for i in 0..count {
                    match crate::app::run(name, user) {
                        Ok(_code) => {
                            ok += 1;
                            if (i + 1) % 10 == 0 {
                                // Keep display logs compact; detailed info remains on serial.
                                out.write_fmt(format_args!(
                                    "app: stress progress {}/{}",
                                    i + 1,
                                    count
                                ));
                            }
                        }
                        Err(e) => {
                            out.write_fmt(format_args!(
                                "app: stress failed at iter {}: {:?}",
                                i + 1,
                                e
                            ));
                            break;
                        }
                    }
                }
                out.write_fmt(format_args!("app: stress done ok={}/{}", ok, count));
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("app: unavailable");
            }
        }
        Some("stop") => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: app stop <name>");
                return;
            };
            #[cfg(target_os = "none")]
            {
                let _ = ctx;
                match crate::app::stop(name) {
                    Ok(()) => out.write_line("app: stopped"),
                    Err(e) => out.write_fmt(format_args!("app stop failed: {:?}", e)),
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("app: unavailable");
            }
        }
        Some("remove") => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: app remove <name>");
                return;
            };
            #[cfg(target_os = "none")]
            {
                let _ = ctx;
                match crate::app::remove(name) {
                    Ok(seq) => out.write_fmt(format_args!("app: removed (seq={seq})")),
                    Err(e) => out.write_fmt(format_args!("app remove failed: {:?}", e)),
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = ctx;
                out.write_line("app: unavailable");
            }
        }
        _ => out.write_line("usage: app [list|info|assets|install|run|stress|stop|remove]"),
    }
}

#[cfg(target_os = "none")]
fn explain_goes_write_error(
    out: &mut dyn ShellOut,
    workspace: &str,
    e: &crate::goes::writer::WriteError,
) {
    use crate::goes::writer::WriteError;
    match e {
        WriteError::PermissionDenied => {
            #[cfg(target_os = "none")]
            {
                if crate::goes::replay::workspace_is_composed(workspace) {
                    out.write_line("hint: composed workspace is read-only; write into one of its sources or a writable workspace");
                    return;
                }
            }
            if workspace.eq_ignore_ascii_case("System") {
                out.write_line("hint: System is read-only in normal mode; use Recovery + SIP OFF to write");
            } else if workspace.eq_ignore_ascii_case("Library") || workspace.eq_ignore_ascii_case("Applications") {
                out.write_line("hint: this workspace requires admin to write");
            } else if workspace.eq_ignore_ascii_case("Users") {
                out.write_line("hint: Users is restricted; write into your own User:<name> workspace");
            } else if workspace.to_ascii_lowercase().starts_with("user:") {
                out.write_line("hint: you can only write into your own User:<name> workspace (unless admin)");
            }
        }
        WriteError::NoSpace => out.write_line("hint: GOES record log is full; recreate image via `xtask install --recovery --sip-off`"),
        _ => {}
    }
}

#[cfg(target_os = "none")]
pub(crate) fn user_scope_id(username: &str) -> u64 {
    // FNV-1a 64-bit
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in username.as_bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

const COMMANDS: &[Command] = &[
    Command {
        name: "help",
        usage: "help",
        help: "list commands",
        handler: cmd_help,
    },
    Command {
        name: "echo",
        usage: "echo <txt>",
        help: "print text",
        handler: cmd_echo,
    },
    Command {
        name: "arch",
        usage: "arch",
        help: "print architecture",
        handler: cmd_arch,
    },
    Command {
        name: "clear",
        usage: "clear",
        help: "clear screen",
        handler: cmd_clear,
    },
    Command {
        name: "panic",
        usage: "panic",
        help: "trigger kernel panic",
        handler: cmd_panic,
    },
    Command {
        name: "halt",
        usage: "halt",
        help: "halt CPU",
        handler: cmd_halt,
    },
    Command {
        name: "mem",
        usage: "mem",
        help: "print memory summary",
        handler: cmd_mem,
    },
    Command {
        name: "gfx",
        usage: "gfx [info|test]",
        help: "graphics debug (framebuffer draw)",
        handler: cmd_gfx,
    },
    Command {
        name: "mmu",
        usage: "mmu [status|selftest]",
        help: "address space / MMU debug (v2+)",
        handler: cmd_mmu,
    },
    Command {
        name: "goes",
        usage: "goes [status|ls|manifest|append|mkobj|addedge|rmedge|edges|view]",
        help: "GOES commands",
        handler: cmd_goes,
    },
    Command {
        name: "ws",
        usage: "ws [list|enter <name>]",
        help: "workspace commands",
        handler: cmd_ws,
    },
    Command {
        name: "make",
        usage: "make [file|ws] <name>",
        help: "create object/workspace (v1)",
        handler: cmd_make,
    },
    Command {
        name: "app",
        usage: "app [list|info|assets|add|run|stop|remove]",
        help: "application lifecycle (v1 stub)",
        handler: cmd_app,
    },
    Command {
        name: "whoami",
        usage: "whoami",
        help: "print current user",
        handler: cmd_whoami,
    },
    Command {
        name: "user",
        usage: "user [list|create|disable|enable]",
        help: "user management (admin-only for writes)",
        handler: cmd_user,
    },
    Command {
        name: "domain",
        usage: "domain [list|info <id|name>|stop|start|restart|quarantine <id>]",
        help: "sandbox domain management (v2)",
        handler: cmd_domain,
    },
    Command {
        name: "service",
        usage: "service [list|info <name>|ping <name>|run <name>|stop <name>|restart <name>|demo]",
        help: "service registry + IPC ping (stage 3)",
        handler: cmd_service,
    },
    Command {
        name: "sip",
        usage: "sip [status|on|off]",
        help: "system integrity protection (recovery-only for changes)",
        handler: cmd_sip,
    },
    Command {
        name: "reboot",
        usage: "reboot",
        help: "reboot (stub)",
        handler: cmd_reboot,
    },
];

fn dispatch(ctx: &mut ShellContext, out: &mut dyn ShellOut, line: &str) {
    let Some((cmd, argv)) = parse_argv(line) else {
        return;
    };
    if argv.truncated {
        out.write_line("warning: too many args, ignoring extras");
    }
    if ctx.mode == Mode::Recovery && !allowed_in_recovery(cmd) {
        out.write_line("command disabled in recovery mode");
        out.write_line("hint: use 'help' to see available commands");
        return;
    }
    for c in COMMANDS {
        if c.name == cmd {
            (c.handler)(ctx, out, argv);
            return;
        }
    }
    out.write_line("unknown command (try 'help')");
}

fn allowed_in_recovery(cmd: &str) -> bool {
    matches!(
        cmd,
        "help"
            | "clear"
            | "arch"
            | "mem"
            | "gfx"
            | "mmu"
            | "goes"
            | "ws"
            | "whoami"
            | "user"
            | "domain"
            | "sip"
            | "halt"
            | "reboot"
    )
}

/// UEFI 模式下的 shell：使用 UEFI 控制台输出和 stdin 输入。
#[cfg(target_os = "uefi")]
pub fn run() {
    let mut out = UefiOut;
    out.write_line("oneOS shell ready. Type 'help' for commands.");
    let mode = if serial::available() {
        InputMode::Serial
    } else {
        out.write_line("serial unavailable, fallback to UEFI stdin.");
        InputMode::Stdin
    };
    let mut ctx = ShellContext::new_default();
    loop {
        let prompt = ctx.prompt();
        out.write_fmt(format_args!("{prompt}"));
        let mut buf = [0u8; 128];
        let Some(len) = read_line(&mode, &mut buf) else {
            out.write_line("input read failed, halting.");
            arch::halt();
        };
        let line = core::str::from_utf8(&buf[..len]).unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        dispatch(&mut ctx, &mut out, line);
    }
}

/// raw 内核模式下的 shell：输出到 framebuffer，输入来自 PL011 串口。
#[cfg(target_os = "none")]
pub fn run_raw() -> ! {
    // v1: single-task model but still enforce Domain + Capability rules.
    crate::sandbox::set_current_domain(2);
    crate::sandbox::mark_boot_success();
    crate::mmu::addrspace::init_shared_ro_page();

    // 启动阶段日志已同步到屏幕；进入 shell 后清屏并关闭日志镜像，避免干扰交互。
    serial::set_log_mirror_to_display(false);
    crate::console::mgr::start_input_router();

    // Establish a shell session and take foreground.
    let shell_session = crate::console::mgr::ensure_session_for_current_domain();
    crate::console::mgr::set_foreground(shell_session);
    let clear_seq = crate::console::mgr::clear(shell_session);
    crate::console::mgr::flush(clear_seq);

    let mut out = DisplayOut;
    out.write_line("oneOS raw shell ready. Type 'help' for commands.");
    let mut ctx = ShellContext::new_default();
    loop {
        let prompt = ctx.prompt();
        let mut buf = [0u8; 256];
        // Print prompt and flush so it appears before we block on input.
        let pseq = crate::console::mgr::write(
            shell_session,
            crate::console::mgr::STREAM_STDOUT,
            prompt.as_bytes(),
        );
        crate::console::mgr::flush(pseq);
        let Some(len) = read_line_session(shell_session, &mut buf) else {
            out.write_line("input failed, halting.");
            arch::halt();
        };
        let line = core::str::from_utf8(&buf[..len]).unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut out = DisplayOut;
        dispatch(&mut ctx, &mut out, line);
        // Ensure command output is rendered before the next prompt.
        let last = crate::console::mgr::last_seq_for_session(shell_session);
        crate::console::mgr::flush(last);
    }
}

#[cfg(target_os = "none")]
fn cmd_mmu(ctx: &mut ShellContext, out: &mut dyn ShellOut, argv: Argv) {
    let sub = argv.args.get(1).copied().unwrap_or("status");
    match sub {
        "status" => {}
        "selftest" => {
            let Some(user_name) = ctx.user.clone() else {
                out.write_line("mmu selftest: no user context");
                return;
            };
            out.write_line("mmu: selftest begin");
            let faults0 = crate::sandbox::total_faults();

            // 1) Stress workspace enter/GOES view roots (no path semantics).
            if let Some(idx) = crate::goes::replay::snapshot() {
                let user_ws = alloc::format!("User:{user_name}");
                let targets = [
                    "System",
                    "Library",
                    "Applications",
                    "Users",
                    user_ws.as_str(),
                ];
                for _ in 0..8 {
                    for ws in targets.iter().copied() {
                        if !try_enter_ws(ctx, ws) {
                            out.write_fmt(format_args!("mmu selftest: ws enter failed: {ws}"));
                            return;
                        }
                        let sources = resolve_ws_sources(&idx, ctx.workspace.name());
                        let view = crate::goes::view::ViewObject::roots_union(&sources);
                        let rows = crate::goes::view::run_view(&view, &idx);
                        let mut count = 0usize;
                        for r in rows {
                            if matches!(r, crate::goes::view::ViewRow::Object(_)) {
                                count += 1;
                            }
                        }
                        let _ = count;
                    }
                }
            } else {
                out.write_line("mmu selftest: GOES index unavailable");
                return;
            }

            // 2) Stress faults: invalid read/write should not kill shell.
            for _ in 0..50 {
                let _ = crate::app::run("fault_read", &user_name);
            }
            for _ in 0..50 {
                let _ = crate::app::run("fault_write", &user_name);
            }
            // Stage 5/M3 checks:
            // - write into RX .text should fault
            // - execute from NX stack should fault
            for _ in 0..5 {
                let _ = crate::app::run("fault_text", &user_name);
            }
            for _ in 0..5 {
                let _ = crate::app::run("fault_exec", &user_name);
            }

            // 3) Low-memory pressure (best-effort, no panic).
            let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            let bytes = 12 * 1024 * 1024;
            match buf.try_reserve_exact(bytes) {
                Ok(()) => {
                    buf.resize(bytes, 0);
                    drop(buf);
                    out.write_line("mmu selftest: mem pressure ok");
                }
                Err(_) => {
                    out.write_line("mmu selftest: mem pressure skipped (reserve failed)");
                }
            }

            let faults1 = crate::sandbox::total_faults();
            out.write_fmt(format_args!(
                "mmu: selftest done (faults {} -> {})",
                faults0, faults1
            ));
            return;
        }
        _ => {
            out.write_line("usage: mmu [status|selftest]");
            return;
        }
    }

    let dom = crate::sandbox::current_domain();
    let asid = crate::sandbox::current_address_space();
    let pt = crate::mmu::addrspace::pt_root(asid);
    if let Some(v) = pt {
        out.write_fmt(format_args!(
            "mmu: domain={} asid={} pt_root=0x{:x}\n",
            dom, asid, v
        ));
    } else {
        out.write_fmt(format_args!(
            "mmu: domain={} asid={} pt_root=<none>\n",
            dom, asid
        ));
    }

    #[cfg(target_arch = "aarch64")]
    {
        let en = crate::mmu::aarch64::is_enabled();
        let ttbr0 = crate::mmu::aarch64::current_ttbr0_el1();
        let ttbr1 = crate::mmu::aarch64::current_ttbr1_el1();
        let tcr = crate::mmu::aarch64::current_tcr_el1();
        let mair = crate::mmu::aarch64::current_mair_el1();
        let tlbi = crate::mmu::aarch64::tlbi_vmalle1_count();
        out.write_fmt(format_args!(
            "mmu: aarch64 enabled={} ttbr0=0x{:x} ttbr1=0x{:x} tcr=0x{:x} mair=0x{:x} tlbi_vmalle1={}\n",
            en, ttbr0, ttbr1, tcr, mair, tlbi
        ));
    }

    #[cfg(target_arch = "x86_64")]
    {
        let pg = crate::mmu::x86_64::is_paging_enabled();
        let cr3 = crate::mmu::x86_64::current_cr3();
        let efer = crate::mmu::x86_64::efer();
        let cr0 = crate::mmu::x86_64::cr0();
        let cr4 = crate::mmu::x86_64::cr4();
        let (nxe, wp) = crate::mmu::x86_64::wx_protection_state();
        let pg_hw = (cr0 & (1u64 << 31)) != 0;
        let pae = (cr4 & (1u64 << 5)) != 0;
        let lme = (efer & (1u64 << 8)) != 0;
        let lma = (efer & (1u64 << 10)) != 0;
        out.write_fmt(format_args!(
            "mmu: x86_64 paging={} (cr0.pg={}) cr3=0x{:x}\n",
            pg, pg_hw, cr3
        ));
        out.write_fmt(format_args!(
            "mmu: x86_64 cr0=0x{:x} (wp={}) cr4=0x{:x} (pae={})\n",
            cr0, wp, cr4, pae
        ));
        out.write_fmt(format_args!(
            "mmu: x86_64 efer=0x{:x} (lme={} lma={} nxe={})\n",
            efer, lme, lma, nxe
        ));
    }

    let (enters, leaves, restores) = crate::mmu::switch::switch_stats();
    out.write_fmt(format_args!(
        "mmu: switch enter={} leave={} trap_restore={}\n",
        enters, leaves, restores
    ));
    out.write_fmt(format_args!(
        "mmu: strict={}\n",
        if crate::mmu::switch::app_address_space_switch_enabled() {
            "on"
        } else {
            "off"
        }
    ));
}

#[cfg(target_os = "uefi")]
fn cmd_mmu(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv) {
    out.write_line("mmu: unavailable in UEFI shell mode");
}

#[cfg(not(any(target_os = "none", target_os = "uefi")))]
fn cmd_mmu(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv) {
    out.write_line("mmu: unavailable on host target");
}

#[cfg(target_os = "none")]
fn cmd_domain(ctx: &mut ShellContext, out: &mut dyn ShellOut, argv: Argv) {
    if argv.args.len() < 2 {
        out.write_line("usage: domain [list|info <id|name>|stop|start|restart|quarantine <id>]");
        return;
    }
    let sub = argv.args[1];
    match sub {
        "list" => {
            let domains = crate::sandbox::list_domains();
            out.write_line("domains:");
            for d in domains {
                out.write_fmt(format_args!(
                    "  id={} kind={:?} state={:?} boot_critical={} admin={} asid={} as={:?} regions={} pt_root={} policy={:?} faults={} restarts={} name={}",
                    d.id,
                    d.kind,
                    d.state,
                    d.boot_critical,
                    d.owner_admin,
                    d.addr_space,
                    d.addr_space_backend,
                    d.addr_space_regions,
                    if d.addr_space_pt_root.is_some() { "yes" } else { "no" },
                    d.fault_policy,
                    d.fault_count,
                    d.restart_count,
                    d.name
                ));
                out.write_line("");
            }
        }
        "info" => {
            let Some(key) = argv.args.get(2).copied() else {
                out.write_line("usage: domain info <id|name>");
                return;
            };
            let id = key
                .parse::<u32>()
                .ok()
                .or_else(|| crate::sandbox::domain_id_by_name(key));
            let Some(id) = id else {
                out.write_line("domain not found");
                return;
            };
            let Some(detail) = crate::sandbox::domain_detail_by_id(id) else {
                out.write_line("domain not found");
                return;
            };
            let s = detail.summary;
            out.write_fmt(format_args!(
                "domain id={} name={} kind={:?} state={:?} boot_critical={} admin={} asid={} as={:?} regions={} pt_root={:?} policy={:?} faults={} restarts={}\n",
                s.id,
                s.name,
                s.kind,
                s.state,
                s.boot_critical,
                s.owner_admin,
                s.addr_space,
                s.addr_space_backend,
                s.addr_space_regions,
                s.addr_space_pt_root,
                s.fault_policy,
                s.fault_count,
                s.restart_count
            ));
            out.write_line("  scope:");
            for ws in detail.workspace_scope.iter() {
                out.write_fmt(format_args!("    {:?}", ws));
                out.write_line("");
            }
            out.write_line("  caps:");
            for cap in detail.caps.iter() {
                out.write_fmt(format_args!(
                    "    type={:?} scope={:?} rights=0x{:x}",
                    cap.cap_type, cap.scope, cap.rights
                ));
                out.write_line("");
            }
        }
        "stop" | "start" | "restart" | "quarantine" => {
            #[cfg(target_os = "none")]
            {
                let is_admin = ctx.user.as_deref() == Some("admin");
                if !is_admin {
                    out.write_line("permission denied: admin required");
                    return;
                }
            }
            let Some(id_s) = argv.args.get(2).copied() else {
                out.write_fmt(format_args!("usage: domain {sub} <id>\n"));
                return;
            };
            let Ok(id) = id_s.parse::<u32>() else {
                out.write_line("invalid domain id");
                return;
            };
            if id == 1 {
                out.write_line("refusing to modify Kernel domain");
                return;
            }
            let r = match sub {
                "stop" => crate::sandbox::stop_domain(id),
                "start" => crate::sandbox::start_domain(id),
                "restart" => crate::sandbox::restart_domain(id),
                "quarantine" => crate::sandbox::quarantine_domain(id),
                _ => unreachable!(),
            };
            match r {
                Ok(()) => {
                    out.write_fmt(format_args!("ok: domain {sub} id={id}\n"));
                }
                Err(e) => {
                    out.write_fmt(format_args!("domain {sub} failed: {:?}\n", e));
                }
            }
        }
        _ => {
            out.write_line("usage: domain [list|info <id|name>|stop|start|restart|quarantine <id>]")
        }
    }
}

#[cfg(target_os = "none")]
fn cmd_service(ctx: &mut ShellContext, out: &mut dyn ShellOut, argv: Argv) {
    let sub = argv.get(0).unwrap_or("help");

    match sub {
        "list" => {
            let list = crate::ipc::registry::list();
            if list.is_empty() {
                out.write_line("service: (empty)");
                return;
            }
            for s in list {
                out.write_fmt(format_args!("{} -> domain {}\n", s.name, s.domain_id));
            }
        }
        "info" => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: service info <name>");
                return;
            };
            let Some(id) = crate::ipc::registry::resolve(name) else {
                out.write_line("service: not found");
                return;
            };
            if let Some(detail) = crate::sandbox::domain_detail_by_id(id) {
                out.write_fmt(format_args!(
                    "service: {} -> domain {} kind={:?} state={:?} faults={}\n",
                    name, id, detail.summary.kind, detail.summary.state, detail.summary.fault_count
                ));
            } else {
                out.write_fmt(format_args!(
                    "service: {} -> domain {} (no domain detail)\n",
                    name, id
                ));
            }
        }
        "ping" => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: service ping <name>");
                return;
            };
            match crate::ipc::ping_service(name, 100) {
                Ok((id, rtt)) => out.write_fmt(format_args!(
                    "service: ping {} ok (domain={}, rtt_ticks={})\n",
                    name, id, rtt
                )),
                Err(e) => out.write_fmt(format_args!(
                    "service: ping {} failed: {:?}\n",
                    name, e
                )),
            }
        }
        "run" => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: service run <name>");
                return;
            };
            let Some(user) = ctx.user.clone() else {
                out.write_line("service: no user context");
                return;
            };
            match crate::service::start(name, &user) {
                Ok(id) => out.write_fmt(format_args!("service: started {} (domain={})\n", name, id)),
                Err(_) => out.write_line("service: start failed"),
            }
        }
        "stop" => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: service stop <name>");
                return;
            };
            match crate::service::stop(name) {
                Ok(()) => out.write_fmt(format_args!("service: stopped {}\n", name)),
                Err(_) => out.write_line("service: stop failed"),
            }
        }
        "restart" => {
            let Some(name) = argv.get(1) else {
                out.write_line("usage: service restart <name>");
                return;
            };
            let Some(user) = ctx.user.clone() else {
                out.write_line("service: no user context");
                return;
            };
            match crate::service::restart(name, &user) {
                Ok(id) => out.write_fmt(format_args!("service: restarted {} (domain={})\n", name, id)),
                Err(_) => out.write_line("service: restart failed"),
            }
        }
        "demo" => {
            let Some(user) = ctx.user.clone() else {
                out.write_line("service: no user context");
                return;
            };

            let prev = crate::sandbox::current_domain();
            let id = match crate::sandbox::spawn_service_domain("svc_demo", &user) {
                Ok(id) => id,
                Err(_) => {
                    out.write_line("service: spawn failed");
                    return;
                }
            };
            let _ = crate::sandbox::start_domain(id);
            crate::sandbox::set_current_domain(id);

            // Build a minimal per-service address space (reusing the AppDomain builder path).
            if crate::mmu::switch::app_address_space_switch_enabled() && crate::mmu::addrspace::current_mmu_enabled() {
                if let Some(asid) = crate::sandbox::domain_address_space(id) {
                    let mut layout = crate::mmu::addrspace::AppSpaceLayout::new();

                    unsafe {
                        extern "C" {
                            static __text_start: u8;
                            static __text_end: u8;
                            static __rodata_start: u8;
                            static __rodata_end: u8;
                            static __data_start: u8;
                            static __data_end: u8;
                            static __bss_start: u8;
                            static __bss_end: u8;
                        }
                        let align_down_4k = |x: u64| x & !0xfffu64;
                        let align_up_4k = |x: u64| (x + 0xfff) & !0xfffu64;

                        let text_start = &raw const __text_start as *const u8 as u64;
                        let text_end = &raw const __text_end as *const u8 as u64;
                        let ro_start = &raw const __rodata_start as *const u8 as u64;
                        let ro_end = &raw const __rodata_end as *const u8 as u64;
                        let data_start = &raw const __data_start as *const u8 as u64;
                        let data_end = &raw const __data_end as *const u8 as u64;
                        let bss_start = &raw const __bss_start as *const u8 as u64;
                        let bss_end = &raw const __bss_end as *const u8 as u64;

                        if text_end > text_start {
                            let s = align_down_4k(text_start);
                            let e = align_up_4k(text_end);
                            layout.push(crate::mmu::addrspace::AppMap { va: s, pa: s, len: e - s, exec: true, writable: false, device: false });
                        }
                        if ro_end > ro_start {
                            let s = align_down_4k(ro_start);
                            let e = align_up_4k(ro_end);
                            layout.push(crate::mmu::addrspace::AppMap { va: s, pa: s, len: e - s, exec: false, writable: false, device: false });
                        }
                        let rw_start = core::cmp::min(data_start, bss_start);
                        let rw_end = core::cmp::max(data_end, bss_end);
                        if rw_end > rw_start {
                            let s = align_down_4k(rw_start);
                            let e = align_up_4k(rw_end);
                            layout.push(crate::mmu::addrspace::AppMap { va: s, pa: s, len: e - s, exec: false, writable: true, device: false });
                        }
                    }

                    // Map current kernel stack window (RW, NX).
                    let sp_now: u64;
                    unsafe {
                        #[cfg(target_arch = "aarch64")]
                        core::arch::asm!("mov {0}, sp", out(reg) sp_now, options(nomem, nostack, preserves_flags));
                        #[cfg(target_arch = "x86_64")]
                        core::arch::asm!("mov {0}, rsp", out(reg) sp_now, options(nomem, nostack, preserves_flags));
                    }
                    let stack_start = sp_now.saturating_sub(0x40000) & !0xfffu64;
                    let stack_end = (sp_now.saturating_add(0x20000) + 0xfff) & !0xfffu64;
                    if stack_end > stack_start {
                        layout.push(crate::mmu::addrspace::AppMap { va: stack_start, pa: stack_start, len: stack_end - stack_start, exec: false, writable: true, device: false });
                    }

                    // Kernel heap (RW, NX).
                    let (heap_start, heap_end, _used) = crate::heap::stats();
                    if heap_end > heap_start {
                        layout.push(crate::mmu::addrspace::AppMap { va: heap_start as u64, pa: heap_start as u64, len: (heap_end - heap_start) as u64, exec: false, writable: true, device: false });
                    }

                    // Framebuffer (RW, NX) for console output.
                    if let Some(info) = crate::boot_info::get().and_then(|b| b.framebuffer()) {
                        if info.base != 0 && info.size != 0 {
                            layout.push(crate::mmu::addrspace::AppMap { va: info.base, pa: info.base, len: info.size, exec: false, writable: true, device: false });
                        }
                    }

                    #[cfg(target_arch = "aarch64")]
                    {
                        // GIC + PL011 for timer + serial.
                        layout.push(crate::mmu::addrspace::AppMap { va: 0x0800_0000, pa: 0x0800_0000, len: 0x20_000, exec: false, writable: true, device: true });
                        layout.push(crate::mmu::addrspace::AppMap { va: 0x0900_0000, pa: 0x0900_0000, len: 0x1000, exec: false, writable: true, device: true });
                    }

                    match crate::mmu::addrspace::build_app_space_with_stats_and_pages(&layout) {
                        Ok((root, _tables, _pages, pt_pages)) => {
                            crate::mmu::addrspace::set_pt_root_with_pages(asid, root, pt_pages);
                        }
                        Err(_) => {
                            out.write_line("service: mmu build failed");
                            crate::sandbox::set_current_domain(prev);
                            let _ = crate::sandbox::stop_domain(id);
                            crate::sandbox::kill_domain(id);
                            return;
                        }
                    }
                }
            }

            // Enter the service space and run a tiny demo body.
            if crate::mmu::switch::app_address_space_switch_enabled() && crate::mmu::addrspace::current_mmu_enabled() {
                if let Some(asid) = crate::sandbox::domain_address_space(id) {
                    if let Ok(saved) = crate::mmu::addrspace::enter(asid) {
                        crate::drivers::serial::log_line("service demo: entered service address space");
                        let _ = crate::mmu::addrspace::leave(saved);
                    }
                }
            }

            crate::sandbox::set_current_domain(prev);
            let _ = crate::sandbox::stop_domain(id);
            crate::sandbox::kill_domain(id);
            out.write_line("service: demo ok");
        }
        _ => out.write_line("usage: service [list|info <name>|ping <name>|run <name>|stop <name>|restart <name>|demo]"),
    }
}

#[cfg(target_os = "uefi")]
fn cmd_service(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv) {
    out.write_line("service: unavailable in UEFI shell mode");
}

#[cfg(not(any(target_os = "none", target_os = "uefi")))]
fn cmd_service(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv) {
    out.write_line("service: unavailable on host target");
}

#[cfg(target_os = "uefi")]
fn cmd_domain(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv) {
    out.write_line("domain: unavailable in UEFI shell mode");
}

#[cfg(not(any(target_os = "none", target_os = "uefi")))]
fn cmd_domain(_ctx: &mut ShellContext, out: &mut dyn ShellOut, _argv: Argv) {
    out.write_line("domain: unavailable on host target");
}

#[cfg(target_os = "none")]
fn read_line_session(session: crate::console::mgr::SessionId, buf: &mut [u8]) -> Option<usize> {
    let mut len = 0usize;
    let mut overflow = false;
    loop {
        let Some(evt) = crate::console::mgr::read_key(session, true) else {
            return None;
        };
        match evt {
            KeyEvent::Char(ch) => {
                if len < buf.len() {
                    buf[len] = ch as u8;
                    len += 1;
                    let one = [ch as u8];
                    let _ = crate::console::mgr::write(
                        session,
                        crate::console::mgr::STREAM_STDOUT,
                        &one,
                    );
                } else if !overflow {
                    overflow = true;
                    // 单次提示，避免刷屏
                    let s = crate::console::mgr::write(
                        session,
                        crate::console::mgr::STREAM_STDOUT,
                        b"\n[input too long; truncating]\n",
                    );
                    crate::console::mgr::flush(s);
                    // 重新输出 prompt 由上层负责；这里保持简单：继续读直到 Enter。
                }
            }
            KeyEvent::Backspace => {
                if len > 0 {
                    len -= 1;
                    let _ = crate::console::mgr::backspace(session, 1);
                }
            }
            KeyEvent::Tab => {
                // v0.2: 先把 Tab 展开为空格，不做补全
                for _ in 0..4 {
                    if len >= buf.len() {
                        overflow = true;
                        break;
                    }
                    buf[len] = b' ';
                    len += 1;
                    let _ = crate::console::mgr::write(
                        session,
                        crate::console::mgr::STREAM_STDOUT,
                        b" ",
                    );
                }
            }
            KeyEvent::Enter => {
                let s = crate::console::mgr::write(
                    session,
                    crate::console::mgr::STREAM_STDOUT,
                    b"\n",
                );
                crate::console::mgr::flush(s);
                return Some(len);
            }
        }
    }
}

#[cfg(target_os = "uefi")]
fn read_line(mode: &InputMode, buf: &mut [u8]) -> Option<usize> {
    match mode {
        InputMode::Serial => serial::read_line(buf),
        InputMode::Stdin => read_line_stdin(buf),
    }
}

#[cfg(target_os = "uefi")]
fn read_line_stdin(buf: &mut [u8]) -> Option<usize> {
    use uefi::proto::console::text::{Input, Key};
    let mut filled = 0;
    for b in buf.iter_mut() {
        let ch: Option<Key> = uefi::system::with_stdin(|stdin: &mut Input| loop {
            if let Ok(key_opt) = stdin.read_key() {
                if let Some(k) = key_opt {
                    break Some(k);
                }
            }
        });
        match ch {
            Some(Key::Printable(c)) => {
                let code = u16::from(c) as u32;
                let byte = code.min(0xFF) as u8;
                *b = byte;
                filled += 1;
            }
            _ => {}
        }
        if filled > 0 {
            if *b == b'\r' || *b == b'\n' {
                break;
            }
        }
    }
    if filled == 0 {
        None
    } else {
        Some(filled)
    }
}

fn try_enter_ws(ctx: &mut ShellContext, name: &str) -> bool {
    let ws = match name {
        "System" | "system" => Workspace::System,
        "Library" | "library" => Workspace::Library,
        "Applications" | "apps" | "applications" => Workspace::Applications,
        "Users" | "users" => Workspace::Users,
        _ if name.starts_with("User:") || name.starts_with("user:") => {
            let n = name.splitn(2, ':').nth(1).unwrap_or("").trim();
            if n.is_empty() {
                return false;
            }
            Workspace::User(format!("User:{n}"))
        }
        _ => {
            #[cfg(target_os = "none")]
            {
                // Allow entering dynamically created workspaces, but only if they exist in GOES.
                if let Some(idx) = crate::goes::replay::snapshot() {
                    if idx.workspaces.contains_key(name) {
                        Workspace::Other(name.to_string())
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                return false;
            }
        }
    };
    ctx.workspace = ws;
    true
}

fn write_mem(out: &mut dyn ShellOut) {
    let Some(regions) = boot_info::memory_regions() else {
        out.write_line("mem: boot info unavailable");
        return;
    };
    let mut total = 0u64;
    let mut usable = 0u64;
    for r in regions {
        total = total.saturating_add(r.length);
        if r.region_type == MemoryRegionType::Conventional {
            usable = usable.saturating_add(r.length);
        }
    }
    out.write_fmt(format_args!("memory map entries: {}", regions.len()));
    out.write_fmt(format_args!("total memory: {} MB", total / (1024 * 1024)));
    out.write_fmt(format_args!("usable memory: {} MB", usable / (1024 * 1024)));
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

    fn push(&mut self, ch: char) -> Result<(), ()> {
        let mut tmp = [0u8; 4];
        let s = ch.encode_utf8(&mut tmp);
        self.push_str(s);
        Ok(())
    }

    fn push_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let remaining = N.saturating_sub(self.len);
        let n = remaining.min(bytes.len());
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}
