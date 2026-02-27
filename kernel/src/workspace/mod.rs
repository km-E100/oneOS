#![cfg(target_os = "none")]

extern crate alloc;

/// oneOS 的系统级 Workspace（冻结语义，任何版本都不可变）：
/// - System / Users / Applications / Library
///
/// 注意：这里的“冻结”指语义与身份不可被用户/应用通过 GOES 写路径改写，
/// 并不代表 System 在 Recovery+SIP=OFF 下完全不可写（写权限仍由 sandbox/policy 决定）。

pub const SYSTEM_WORKSPACES: [&str; 4] = ["System", "Users", "Applications", "Library"];

pub fn is_system_workspace_name(name: &str) -> bool {
    SYSTEM_WORKSPACES.iter().any(|&s| s == name)
}

/// 为避免把 Workspace 当“目录/路径别名”，以及避免利用大小写创建“伪 System”等混淆空间，
/// 系统级 Workspace 名称按 ASCII 不区分大小写视为保留。
pub fn is_system_workspace_name_ci(name: &str) -> bool {
    SYSTEM_WORKSPACES
        .iter()
        .any(|&s| name.eq_ignore_ascii_case(s))
}

pub fn seed_system_workspaces(
    workspaces: &mut alloc::collections::BTreeMap<alloc::string::String, u64>,
) {
    // seq=0: 表示“系统内建”，不来自可变写路径。
    for &w in SYSTEM_WORKSPACES.iter() {
        workspaces.entry(w.into()).or_insert(0);
    }
}
