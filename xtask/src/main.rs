use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use oneos_boot_proto::crc32::{crc32_ieee, crc32_ieee_with_zeroed_range};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use xshell::{cmd, Shell};

mod esp;

#[derive(Parser)]
#[command(author, version, about = "oneOS build helper (xtask)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 构建指定架构（默认 all），并生成 ESP 目录与通用包。
    Build {
        #[arg(value_enum, long, default_value_t = Arch::All)]
        arch: Arch,
        /// 构建 profile，默认 debug
        #[arg(long, default_value = "debug")]
        profile: String,
    },
    /// 运行 QEMU（需要已存在的 ESP 目录）
    Run {
        #[arg(value_enum, long, default_value_t = Arch::X86_64)]
        arch: Arch,
        /// OVMF/EDK2 固件路径（例：/usr/local/share/edk2-ovmf/x64/OVMF_CODE.fd）
        #[arg(long)]
        firmware: Option<PathBuf>,
        /// 可选：OVMF_VARS 路径（若需要可写变量）
        #[arg(long)]
        vars: Option<PathBuf>,
        /// 内存大小，默认 1024M
        #[arg(long, default_value = "1024")]
        mem: String,
        /// QEMU 显示模式：auto/headless/cocoa/sdl/gtk
        #[arg(value_enum, long, default_value_t = DisplayMode::Auto)]
        display: DisplayMode,
    },
    /// 生成系统 GOES 镜像（oneos-goes.img）
    Install {
        /// 启用 admin 账户（无密码，仅用于测试）
        #[arg(long)]
        admin: bool,
        /// 更新已存在的 oneos-goes.img（默认只写入 Library/Applications/Users）
        #[arg(long)]
        update: bool,
        /// 显式声明在 Recovery 环境执行（允许写入 System 以及切换默认用户等）
        #[arg(long)]
        recovery: bool,
        /// 关闭 SIP（仅与 --recovery 一起使用）
        #[arg(long)]
        sip_off: bool,
        /// 构建 profile，默认 debug
        #[arg(long, default_value = "debug")]
        profile: String,
    },
    /// 读取/修改 GOES 镜像（用于切换 active_set 等）
    Goes {
        #[command(subcommand)]
        command: GoesCommand,
        /// GOES 镜像路径（默认 dist/oneos-goes.img）
        #[arg(long)]
        image: Option<PathBuf>,
    },
    /// 读取/修改 ESP 引导状态（BootFlag/BootState，用于 Recovery）
    Esp {
        #[command(subcommand)]
        command: EspCommand,
        /// ESP 镜像路径（默认 dist/oneos-esp.img）
        #[arg(long)]
        image: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum GoesCommand {
    /// 打印 Checkpoint/BootManifest 信息
    Show,
    /// 切换 BootManifest 的 active_set（写回镜像）
    SetActive {
        /// 目标 set 索引（0..set_count）
        #[arg(long)]
        set: u32,
    },
    /// 设置 SIP 开关（写回镜像；必须显式声明在 Recovery 环境操作）
    SetSip {
        #[arg(value_enum, long)]
        sip: SipState,
        /// 必须显式传入，表示在 Recovery Mode 执行此操作
        #[arg(long)]
        recovery: bool,
    },
}

#[derive(Subcommand)]
enum EspCommand {
    /// 打印 BootFlag/BootState（用于排查 Recovery 判定）
    Show,
    /// 设置/清除 ForceRecovery（一次性；oneboot 读取后会自动清除）
    ForceRecovery {
        #[arg(value_enum, long)]
        state: SipState,
    },
    /// 设置连续失败次数（用于模拟“>=3 次失败进入 recovery”）
    SetFailures {
        #[arg(long)]
        count: u32,
    },
    /// 清零连续失败次数
    ClearFailures,
    /// 追加一条 PanicRecord（写入 BootState 的 ring buffer，并递增 failures）
    RecordPanic {
        #[arg(long)]
        code: u32,
    },
    /// 标记“本次启动成功”（oneboot 会在下次启动时自动清零 failures；一次性）
    MarkSuccess,
    /// 设置 MMU isolation strict（开发期开关；默认 on）
    SetMmuStrict {
        #[arg(value_enum, long)]
        state: SipState,
    },
    /// 设置 ESP 镜像中的 SIP 镜像值（v0.x：用于 bootloader 透传给内核显示；GOES 仍保留 flags）
    SetSip {
        #[arg(value_enum, long)]
        sip: SipState,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SipState {
    #[value(name = "on")]
    On,
    #[value(name = "off")]
    Off,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Arch {
    #[value(name = "x86_64")]
    X86_64,
    #[value(name = "aarch64")]
    Aarch64,
    #[value(name = "all")]
    All,
}

impl Arch {
    fn all_list(self) -> Vec<Arch> {
        match self {
            Arch::All => vec![Arch::X86_64, Arch::Aarch64],
            other => vec![other],
        }
    }

    fn target(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64-unknown-uefi",
            Arch::Aarch64 => "aarch64-unknown-uefi",
            Arch::All => unreachable!(),
        }
    }

    fn bin(self) -> &'static str {
        match self {
            Arch::X86_64 => "oneos-x86_64",
            Arch::Aarch64 => "oneos-aarch64",
            Arch::All => unreachable!(),
        }
    }

    fn boot_filename(self) -> &'static str {
        match self {
            Arch::X86_64 => "BOOTX64.EFI",
            Arch::Aarch64 => "BOOTAA64.EFI",
            Arch::All => unreachable!(),
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let sh = Shell::new()?;
    match cli.command {
        Commands::Build { arch, profile } => build(&sh, arch, &profile)?,
        Commands::Run {
            arch,
            firmware,
            vars,
            mem,
            display,
        } => run_qemu(
            &sh,
            arch,
            firmware.as_deref(),
            vars.as_deref(),
            &mem,
            display,
        )?,
        Commands::Install {
            admin,
            update,
            recovery,
            sip_off,
            profile,
        } => install(&sh, admin, update, recovery, sip_off, &profile)?,
        Commands::Goes { command, image } => {
            let dist = sh.current_dir().join("dist");
            let img = image.unwrap_or_else(|| dist.join("oneos-goes.img"));
            match command {
                GoesCommand::Show => goes_show(&img)?,
                GoesCommand::SetActive { set } => goes_set_active(&img, set)?,
                GoesCommand::SetSip { sip, recovery } => {
                    goes_set_sip(&img, sip == SipState::On, recovery)?
                }
            }
        }
        Commands::Esp { command, image } => {
            let dist = sh.current_dir().join("dist");
            let img = image.unwrap_or_else(|| dist.join("oneos-esp.img"));
            match command {
                EspCommand::Show => esp_show(&img)?,
                EspCommand::ForceRecovery { state } => {
                    esp_set_force_recovery(&img, state == SipState::On)?
                }
                EspCommand::SetFailures { count } => esp_set_failures(&img, count)?,
                EspCommand::ClearFailures => esp_set_failures(&img, 0)?,
                EspCommand::RecordPanic { code } => esp_record_panic(&img, code)?,
                EspCommand::MarkSuccess => esp_mark_success(&img)?,
                EspCommand::SetMmuStrict { state } => {
                    esp_set_mmu_strict(&img, state == SipState::On)?
                }
                EspCommand::SetSip { sip } => esp_set_sip(&img, sip == SipState::On)?,
            }
        }
    }
    Ok(())
}

fn build(sh: &Shell, arch: Arch, profile: &str) -> Result<()> {
    for a in arch.all_list() {
        build_arch(sh, a, profile)?;
    }
    // 生成通用包（包含两个架构的 BOOT*.EFI）
    finalize_universal(sh)?;
    Ok(())
}

fn build_arch(sh: &Shell, arch: Arch, profile: &str) -> Result<()> {
    let target = arch.target();
    let bin = arch.bin();
    if profile == "release" {
        cmd!(
            sh,
            "cargo +nightly build -Z build-std=core,compiler_builtins,alloc -p oneos-kernel --bin {bin} --target {target} --release"
        )
        .run()
        .context("building kernel with nightly build-std (release)")?;
    } else {
        cmd!(
            sh,
            "cargo +nightly build -Z build-std=core,compiler_builtins,alloc -p oneos-kernel --bin {bin} --target {target}"
        )
        .run()
        .context("building kernel with nightly build-std (debug)")?;
    }

    // 构建 bootloader
    let bl_bin = "oneos-bootloader";
    if profile == "release" {
        cmd!(
            sh,
            "cargo +nightly build -Z build-std=core,compiler_builtins,alloc -p oneos-bootloader --bin {bl_bin} --target {target} --release"
        )
        .run()
        .context("building bootloader (release)")?;
    } else {
        cmd!(
            sh,
            "cargo +nightly build -Z build-std=core,compiler_builtins,alloc -p oneos-bootloader --bin {bl_bin} --target {target}"
        )
        .run()
        .context("building bootloader (debug)")?;
    }

    let project_root = sh.current_dir();
    let build_dir = if profile == "release" {
        "release"
    } else {
        "debug"
    };
    let kernel_img = project_root
        .join("target")
        .join(target)
        .join(build_dir)
        .join(format!("{bin}.efi"));
    let bootloader_img = project_root
        .join("target")
        .join(target)
        .join(build_dir)
        .join(format!("{bl_bin}.efi"));
    let dist = project_root.join("dist");
    let esp_root = dist.join(format!("esp-{}", arch_name(arch)));
    copy_kernel_and_bootloader(&kernel_img, &bootloader_img, &esp_root, arch)?;
    match arch {
        Arch::Aarch64 => {
            build_raw_kernel_aarch64(sh, profile)?;
            let raw_kernel = raw_kernel_path_aarch64(project_root.as_path(), profile);
            copy_raw_kernel(&raw_kernel, &esp_root, arch)?;
            let raw_universal = dist.join("universal");
            copy_raw_kernel(&raw_kernel, &raw_universal, arch)?;
        }
        Arch::X86_64 => {
            build_raw_kernel_x86_64(sh, profile)?;
            let raw_kernel = raw_kernel_path_x86_64(project_root.as_path(), profile);
            copy_raw_kernel(&raw_kernel, &esp_root, arch)?;
            let raw_universal = dist.join("universal");
            copy_raw_kernel(&raw_kernel, &raw_universal, arch)?;
        }
        Arch::All => {}
    }
    // 同步到 universal 目录（即便只构建单一架构，也先放进去）
    let universal = dist.join("universal");
    copy_kernel_and_bootloader(&kernel_img, &bootloader_img, &universal, arch)?;

    println!(
        "[xtask] built kernel+bootloader for {target} -> esp:{}",
        esp_root.display()
    );
    Ok(())
}

fn copy_kernel_and_bootloader(
    kernel: &Path,
    bootloader: &Path,
    esp_root: &Path,
    arch: Arch,
) -> Result<()> {
    let boot_dir = esp_root.join("EFI/Boot");
    let os_dir = esp_root.join("EFI/oneOS");
    fs::create_dir_all(&boot_dir).context("creating ESP boot dir")?;
    fs::create_dir_all(&os_dir).context("creating ESP oneOS dir")?;

    // bootloader -> BOOT*.EFI
    let bl_dest = boot_dir.join(arch.boot_filename());
    fs::copy(bootloader, &bl_dest)
        .with_context(|| format!("copying {} to {}", bootloader.display(), bl_dest.display()))?;

    // kernel -> EFI/oneOS/KERNEL*.EFI
    let k_name = match arch {
        Arch::X86_64 => "KERNELX64.EFI",
        Arch::Aarch64 => "KERNELAA64.EFI",
        Arch::All => "KERNEL.EFI",
    };
    let k_dest = os_dir.join(k_name);
    fs::copy(kernel, &k_dest)
        .with_context(|| format!("copying {} to {}", kernel.display(), k_dest.display()))?;
    Ok(())
}

fn build_raw_kernel_aarch64(sh: &Shell, profile: &str) -> Result<()> {
    let target = "aarch64-unknown-none-softfloat";
    let bin = "oneos-raw-aarch64";
    if profile == "release" {
        cmd!(
            sh,
            "cargo +nightly build -Z build-std=core,compiler_builtins,alloc -p oneos-kernel --bin {bin} --target {target} --release"
        )
        .run()
        .context("building raw aarch64 kernel (release)")?;
    } else {
        cmd!(
            sh,
            "cargo +nightly build -Z build-std=core,compiler_builtins,alloc -p oneos-kernel --bin {bin} --target {target}"
        )
        .run()
        .context("building raw aarch64 kernel (debug)")?;
    }
    Ok(())
}

fn build_raw_kernel_x86_64(sh: &Shell, profile: &str) -> Result<()> {
    let target = "x86_64-unknown-none";
    let bin = "oneos-raw-x86_64";
    if profile == "release" {
        cmd!(
            sh,
            "cargo +nightly build -Z build-std=core,compiler_builtins,alloc -p oneos-kernel --bin {bin} --target {target} --release"
        )
        .run()
        .context("building raw x86_64 kernel (release)")?;
    } else {
        cmd!(
            sh,
            "cargo +nightly build -Z build-std=core,compiler_builtins,alloc -p oneos-kernel --bin {bin} --target {target}"
        )
        .run()
        .context("building raw x86_64 kernel (debug)")?;
    }
    Ok(())
}

fn raw_kernel_path_aarch64(project_root: &Path, profile: &str) -> PathBuf {
    let build_dir = if profile == "release" {
        "release"
    } else {
        "debug"
    };
    project_root
        .join("target")
        .join("aarch64-unknown-none-softfloat")
        .join(build_dir)
        .join("oneos-raw-aarch64")
}

fn raw_kernel_path_x86_64(project_root: &Path, profile: &str) -> PathBuf {
    let build_dir = if profile == "release" {
        "release"
    } else {
        "debug"
    };
    project_root
        .join("target")
        .join("x86_64-unknown-none")
        .join(build_dir)
        .join("oneos-raw-x86_64")
}

fn copy_raw_kernel(raw_kernel: &Path, esp_root: &Path, arch: Arch) -> Result<()> {
    let os_dir = esp_root.join("EFI/oneOS");
    fs::create_dir_all(&os_dir).context("creating ESP oneOS dir for raw kernel")?;
    let dest = match arch {
        Arch::X86_64 => os_dir.join("KERNELX64.BIN"),
        Arch::Aarch64 => os_dir.join("KERNELAA64.BIN"),
        Arch::All => return Ok(()),
    };
    fs::copy(raw_kernel, &dest)
        .with_context(|| format!("copying {} to {}", raw_kernel.display(), dest.display()))?;
    if let (Ok(src_meta), Ok(dst_meta)) = (fs::metadata(raw_kernel), fs::metadata(&dest)) {
        println!(
            "[xtask] raw kernel copied: {} ({} bytes) -> {} ({} bytes)",
            raw_kernel.display(),
            src_meta.len(),
            dest.display(),
            dst_meta.len()
        );
    }
    Ok(())
}

fn finalize_universal(sh: &Shell) -> Result<()> {
    // 仅提示现状，不强制生成镜像
    let root = sh.current_dir().join("dist/universal/EFI/Boot");
    if root.exists() {
        println!("[xtask] universal package ready at {}", root.display());
    } else {
        println!("[xtask] universal package not complete (need both arches)");
    }
    Ok(())
}

fn install(
    sh: &Shell,
    admin: bool,
    update: bool,
    recovery: bool,
    sip_off: bool,
    profile: &str,
) -> Result<()> {
    // 为了保证内核 blob 是最新的：先构建双架构并同步到 dist/universal
    eprintln!("[xtask] install: build all (profile={profile})");
    build(sh, Arch::All, profile)?;

    let project_root = sh.current_dir();
    let dist = project_root.join("dist");
    fs::create_dir_all(&dist).context("creating dist dir")?;

    // 生成通用 ESP 镜像（包含 BOOTX64.EFI/BOOTAA64.EFI）
    let esp_img = dist.join("oneos-esp.img");
    eprintln!("[xtask] install: creating ESP image: {}", esp_img.display());
    create_esp_image(sh, &esp_img, &dist.join("universal"))?;
    println!("[xtask] ESP image ready at {}", esp_img.display());

    let x86_blob = dist.join("universal/EFI/oneOS/KERNELX64.BIN");
    let aa_blob = dist.join("universal/EFI/oneOS/KERNELAA64.BIN");
    if !x86_blob.exists() || !aa_blob.exists() {
        anyhow::bail!(
            "missing raw kernel blobs in dist/universal: {} {}",
            x86_blob.display(),
            aa_blob.display()
        );
    }
    eprintln!(
        "[xtask] install: kernel blobs found: {} ({:?}), {} ({:?})",
        x86_blob.display(),
        fs::metadata(&x86_blob).map(|m| m.len()).ok(),
        aa_blob.display(),
        fs::metadata(&aa_blob).map(|m| m.len()).ok()
    );

    let goes_img = dist.join("oneos-goes.img");
    let exists = goes_img.exists();
    let allow_system_write = !exists || (recovery && sip_off);
    if sip_off && !recovery {
        anyhow::bail!("`--sip-off` requires `--recovery`");
    }
    if exists && update == false && !allow_system_write {
        anyhow::bail!(
            "refusing to overwrite existing GOES System data without `--recovery --sip-off` (use `--update` for safe updates)"
        );
    }

    if update && exists && !allow_system_write {
        // Safe update path: only append user/app/library records; no System rewrite.
        eprintln!(
            "[xtask] install: updating existing GOES (safe mode): {}",
            goes_img.display()
        );
        if admin {
            anyhow::bail!(
                "`--admin` on an existing image requires `--recovery --sip-off` because it changes default_user (System)"
            );
        }
        // Safe update also refreshes kernel blobs in-place (without changing offsets/lengths).
        // If the new kernel is larger than the reserved slot, require a full recovery rebuild.
        goes_update_kernel_blobs_in_place(&goes_img, &x86_blob, &aa_blob)?;
        // Best-effort: append an installer stamp to record log (non-System semantics).
        goes_append_installer_stamp(&goes_img)?;
        println!(
            "[xtask] GOES image updated (safe mode) at {}",
            goes_img.display()
        );
        return Ok(());
    }

    eprintln!(
        "[xtask] install: creating GOES image: {} (admin={}, recovery={}, sip_off={})",
        goes_img.display(),
        admin,
        recovery,
        sip_off
    );
    create_goes_image(&goes_img, &x86_blob, &aa_blob, admin)?;
    println!("[xtask] GOES image ready at {}", goes_img.display());
    Ok(())
}

const ESP_IMAGE_SIZE_MB: u64 = 64;
/// 预留给 GOES 内核 slot 的增长空间（用于 `install --update` 原地刷新内核）。
///
/// 说明：
/// - BootManifest/superblock 中的 `kernel_*_len` 被视为“slot 大小”，不是“当前内核精确大小”。
/// - Bootloader 会按 slot 大小读取，再解析 ELF；尾部 0 填充是安全的。
/// - 这样可避免每次内核变大就必须进入 Recovery 修改 System 元数据。
const GOES_KERNEL_SLOT_SLACK_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB

// GOES v1 record types (must match `kernel/src/goes/records.rs`).
const GOES_RECORD_APP_MANIFEST_V2: u32 = 0x1_0110;
#[allow(dead_code)]
const GOES_RECORD_APP_BINARY_V2: u32 = 0x1_0111;
const GOES_RECORD_APP_CAPS_V2: u32 = 0x1_0112;
const GOES_RECORD_APP_REGISTRY_V1: u32 = 0x1_0114;
const GOES_RECORD_APP_CONFIG_TEXT_V1: u32 = 0x1_0115;
const GOES_RECORD_APP_SHIPPED_V1: u32 = 0x1_0118;
const GOES_RECORD_APP_IMAGE_V1: u32 = 0x1_0119;
const GOES_RECORD_APP_ASSET_BLOB_V1: u32 = 0x1_0120;
const GOES_RECORD_CREATE_WORKSPACE_V1: u32 = 0x1_0200;

// App caps mask (must match `kernel/src/app/mod.rs`).
const APP_CAP_CONSOLE: u64 = 1 << 0;

#[derive(Clone, Debug)]
struct RepoAsset {
    name: String,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct RepoApp {
    name: String,
    version: String,
    entry: String,
    caps_mask: u64,
    config_text: Vec<u8>,
    assets: Vec<RepoAsset>,
    binary_x86_64: Vec<u8>,
    binary_aarch64: Vec<u8>,
}

#[derive(Clone, Debug)]
struct RepoService {
    name: String,
}

fn parse_manifest_kv(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim().to_string();
        let mut v = v.trim().to_string();
        if let Some(stripped) = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            v = stripped.to_string();
        }
        map.insert(k, v);
    }
    map
}

fn parse_u64_auto(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn load_repo_apps(repo_root: &Path) -> Result<Vec<RepoApp>> {
    let apps_root = repo_root.join("applications");
    if !apps_root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for ent in
        fs::read_dir(&apps_root).with_context(|| format!("read_dir {}", apps_root.display()))?
    {
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        let dir = ent.path();
        let manifest_path = dir.join("manifest.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest_text = fs::read_to_string(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?;
        let kv = parse_manifest_kv(&manifest_text);
        let name = kv
            .get("name")
            .cloned()
            .unwrap_or_else(|| ent.file_name().to_string_lossy().to_string());
        let version = kv
            .get("version")
            .cloned()
            .unwrap_or_else(|| "0.1".to_string());
        let entry = kv
            .get("entry")
            .cloned()
            .unwrap_or_else(|| "elf:v1".to_string());
        let caps_mask = kv
            .get("caps_mask")
            .and_then(|s| parse_u64_auto(s))
            .unwrap_or(APP_CAP_CONSOLE);

        let config_path = dir.join("config.toml");
        let config_text = if config_path.exists() {
            fs::read(&config_path).with_context(|| format!("read {}", config_path.display()))?
        } else {
            Vec::new()
        };

        // Optional assets: packaged into App:<name> workspace as AppAsset blobs (no path semantics).
        let mut assets: Vec<RepoAsset> = Vec::new();
        let assets_dir = dir.join("assets");
        if assets_dir.exists() {
            for ent in fs::read_dir(&assets_dir)
                .with_context(|| format!("read_dir {}", assets_dir.display()))?
            {
                let ent = ent?;
                let ty = ent.file_type()?;
                if !ty.is_file() {
                    anyhow::bail!(
                        "unsupported asset entry (only files allowed, no subdirs): {}",
                        ent.path().display()
                    );
                }
                let file_name = ent.file_name().to_string_lossy().to_string();
                if file_name.as_bytes().len() > 32 {
                    anyhow::bail!(
                        "asset name too long (must fit name32 <= 32 bytes): {}",
                        file_name
                    );
                }
                let bytes = fs::read(ent.path())
                    .with_context(|| format!("read asset {}", ent.path().display()))?;
                assets.push(RepoAsset {
                    name: file_name,
                    bytes,
                });
            }
            assets.sort_by(|a, b| a.name.cmp(&b.name));
        }

        // Apps are Rust-only: Cargo.toml is required.
        let cargo_toml = dir.join("Cargo.toml");
        if !cargo_toml.exists() {
            anyhow::bail!(
                "app {} is missing Cargo.toml; oneOS apps are Rust-only (no .one scripts)",
                dir.display()
            );
        }
        let pkg = parse_package_name_from_cargo_toml(&cargo_toml)
            .with_context(|| format!("parse package name {}", cargo_toml.display()))?;
        // Build both architectures as bare-metal ELF binaries.
        // Performance: system-shipped apps are built in release to reduce GOES AppBinary size.
        let binary_x86_64 = build_repo_app_elf(repo_root, &pkg, "x86_64-unknown-none", true)
            .with_context(|| format!("build app {} for x86_64", pkg))?;
        let binary_aarch64 =
            build_repo_app_elf(repo_root, &pkg, "aarch64-unknown-none-softfloat", true)
                .with_context(|| format!("build app {} for aarch64", pkg))?;
        out.push(RepoApp {
            name,
            version,
            entry,
            caps_mask,
            config_text,
            assets,
            binary_x86_64,
            binary_aarch64,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn load_repo_services(repo_root: &Path) -> Result<Vec<RepoService>> {
    let root = repo_root.join("services");
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for ent in fs::read_dir(&root).with_context(|| format!("read_dir {}", root.display()))? {
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        let dir = ent.path();
        if dir.file_name().and_then(|s| s.to_str()) == Some("sdk") {
            continue;
        }
        let manifest_path = dir.join("manifest.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest_text = fs::read_to_string(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?;
        let kv = parse_manifest_kv(&manifest_text);
        let name = kv
            .get("name")
            .cloned()
            .unwrap_or_else(|| ent.file_name().to_string_lossy().to_string());
        out.push(RepoService { name });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn parse_package_name_from_cargo_toml(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut in_package = false;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            in_package = line.trim() == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() != "name" {
                continue;
            }
            let mut v = v.trim().to_string();
            if let Some(stripped) = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                v = stripped.to_string();
            }
            if !v.is_empty() {
                return Ok(v);
            }
        }
    }
    anyhow::bail!("missing [package].name in {}", path.display())
}

fn build_repo_app_elf(
    repo_root: &Path,
    package: &str,
    target: &str,
    release: bool,
) -> Result<Vec<u8>> {
    // Build under `applications/` workspace, but keep artifacts in repo root target dir for reuse.
    let manifest = repo_root.join("applications/Cargo.toml");
    if !manifest.exists() {
        anyhow::bail!(
            "missing applications workspace manifest: {}",
            manifest.display()
        );
    }

    // Ensure app ELF has a stable entry and a safe load address in oneOS raw-kernel mode.
    let linker_script = match target {
        "x86_64-unknown-none" => repo_root.join("applications/sdk/oneos-app/link-x86_64.ld"),
        "aarch64-unknown-none-softfloat" => {
            repo_root.join("applications/sdk/oneos-app/link-aarch64.ld")
        }
        _ => anyhow::bail!("unsupported app target for ELF build: {}", target),
    };
    if !linker_script.exists() {
        anyhow::bail!("missing app linker script: {}", linker_script.display());
    }
    // Use `CARGO_ENCODED_RUSTFLAGS` so paths containing spaces work reliably.
    // ENTRY(oneos_app_main) in linker script => stable ABI entry.
    let mut encoded = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if !encoded.is_empty() {
        encoded.push('\x1f');
    }
    encoded.push_str("-C\x1flink-arg=-T");
    encoded.push('\x1f');
    encoded.push_str("-C\x1flink-arg=");
    encoded.push_str(&linker_script.to_string_lossy());

    // For system-shipped apps we use `--release` and strip symbols to reduce AppBinary size,
    // which directly improves cold-start I/O time inside the guest.
    if release {
        encoded.push('\x1f');
        encoded.push_str("-C\x1fdebuginfo=0");
        encoded.push('\x1f');
        encoded.push_str("-C\x1fstrip=symbols");
    }

    let mut cmd = Command::new("cargo");
    cmd.arg("+nightly")
        .arg("build")
        .arg("-Z")
        .arg("build-std=core,compiler_builtins,alloc")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("-p")
        .arg(package)
        .arg("--target")
        .arg(target);
    if release {
        cmd.arg("--release");
    }
    let status = cmd
        .env("CARGO_ENCODED_RUSTFLAGS", encoded)
        .status()
        .with_context(|| format!("spawn cargo build for app {} ({})", package, target))?;
    if !status.success() {
        anyhow::bail!("cargo build failed for app {} ({})", package, target);
    }
    // Cargo default target dir is `applications/target` when using `applications/Cargo.toml`.
    let mut bin = repo_root.join("applications/target");
    bin.push(target);
    bin.push(if release { "release" } else { "debug" });
    bin.push(package);
    let bytes = fs::read(&bin).with_context(|| format!("read built app {}", bin.display()))?;
    Ok(bytes)
}

fn create_esp_image(sh: &Shell, esp_img: &Path, universal_root: &Path) -> Result<()> {
    let bootx = universal_root.join("EFI/Boot/BOOTX64.EFI");
    let boota = universal_root.join("EFI/Boot/BOOTAA64.EFI");
    if !bootx.exists() || !boota.exists() {
        anyhow::bail!(
            "missing universal bootloaders: {} {}",
            bootx.display(),
            boota.display()
        );
    }

    let _ = sh;
    // 纯 Rust 写入 FAT32 ESP 镜像，避免依赖 qemu-img / mtools，提升 Windows 可用性。
    esp::create_esp_image_fat32(esp_img, &bootx, &boota, ESP_IMAGE_SIZE_MB)?;

    Ok(())
}

const ONEBOOT_BOOTFLAG_MAGIC: &[u8; 4] = b"OBFL";
const ONEBOOT_BOOTSTAT_MAGIC: &[u8; 4] = b"OBST";
const ONEBOOT_SIP_MAGIC: &[u8; 4] = b"OSIP";

fn esp_show(esp_img: &Path) -> Result<()> {
    let bootflag = esp::read_bootflag_from_esp_image(esp_img)?;
    let bootstat = esp::read_bootstat_from_esp_image(esp_img)?;
    let sip = esp::read_sip_from_esp_image(esp_img).ok();
    let (force_recovery, mark_success, mmu_strict) = parse_bootflag(&bootflag)?;
    let (failures, last_boot_id, last_panic_code, ring_head) = parse_bootstat(&bootstat)?;
    println!(
        "ESP: {} force_recovery={} mark_success={} mmu_strict={}",
        esp_img.display(),
        force_recovery,
        mark_success,
        mmu_strict
    );
    println!(
        "ESP: consecutive_failures={} last_boot_id={} last_panic_code=0x{:x} ring_head={}",
        failures, last_boot_id, last_panic_code, ring_head
    );
    let entries = read_bootstat_ring(&bootstat);
    for (i, (bid, code)) in entries.iter().enumerate() {
        if *bid != 0 || *code != 0 {
            println!("  panic#{i}: boot_id={} code=0x{:x}", bid, code);
        }
    }
    if let Some(sip) = sip {
        if let Ok(sip_on) = parse_sip(&sip) {
            println!("ESP: sip={}", if sip_on { "on" } else { "off" });
        }
    }
    Ok(())
}

fn esp_set_force_recovery(esp_img: &Path, on: bool) -> Result<()> {
    let mut bootflag = esp::read_bootflag_from_esp_image(esp_img)?;
    let (_force, mark_success, mmu_strict) = parse_bootflag(&bootflag)?;
    write_bootflag(&mut bootflag, on, mark_success, mmu_strict);
    esp::write_bootflag_to_esp_image(esp_img, &bootflag)?;
    println!("ESP: force_recovery -> {} ({})", on, esp_img.display());
    Ok(())
}

fn esp_set_failures(esp_img: &Path, count: u32) -> Result<()> {
    let mut bootstat = esp::read_bootstat_from_esp_image(esp_img)?;
    let (_old, last_boot_id, last_panic_code, ring_head) = parse_bootstat(&bootstat)?;
    let entries = read_bootstat_ring(&bootstat);
    write_bootstat(
        &mut bootstat,
        count,
        last_boot_id,
        last_panic_code,
        ring_head,
        &entries,
    );
    esp::write_bootstat_to_esp_image(esp_img, &bootstat)?;
    println!(
        "ESP: consecutive_failures -> {} ({})",
        count,
        esp_img.display()
    );
    Ok(())
}

fn esp_record_panic(esp_img: &Path, code: u32) -> Result<()> {
    let mut bootstat = esp::read_bootstat_from_esp_image(esp_img)?;
    let (mut failures, last_boot_id, _last_panic_code, mut ring_head) = parse_bootstat(&bootstat)?;
    let idx = (ring_head % 8) as usize;
    ring_head = ring_head.wrapping_add(1);
    failures = failures.wrapping_add(1);
    let mut entries = read_bootstat_ring(&bootstat);
    entries[idx] = (last_boot_id, code);
    write_bootstat(
        &mut bootstat,
        failures,
        last_boot_id,
        code,
        ring_head,
        &entries,
    );
    esp::write_bootstat_to_esp_image(esp_img, &bootstat)?;
    println!(
        "ESP: record_panic code=0x{:x} -> failures={} ({})",
        code,
        failures,
        esp_img.display()
    );
    Ok(())
}

fn esp_mark_success(esp_img: &Path) -> Result<()> {
    let mut bootflag = esp::read_bootflag_from_esp_image(esp_img)?;
    let (force, _mark_success, mmu_strict) = parse_bootflag(&bootflag)?;
    write_bootflag(&mut bootflag, force, true, mmu_strict);
    esp::write_bootflag_to_esp_image(esp_img, &bootflag)?;
    println!("ESP: mark_success set (oneboot will clear failures on next boot)");
    Ok(())
}

fn esp_set_mmu_strict(esp_img: &Path, strict: bool) -> Result<()> {
    let mut bootflag = esp::read_bootflag_from_esp_image(esp_img)?;
    let (force, mark_success, _mmu_strict) = parse_bootflag(&bootflag)?;
    write_bootflag(&mut bootflag, force, mark_success, strict);
    esp::write_bootflag_to_esp_image(esp_img, &bootflag)?;
    println!("ESP: mmu_strict -> {} ({})", strict, esp_img.display());
    Ok(())
}

fn esp_set_sip(esp_img: &Path, sip_on: bool) -> Result<()> {
    let mut buf = [0u8; 512];
    write_sip(&mut buf, sip_on);
    esp::write_sip_to_esp_image(esp_img, &buf)?;
    println!(
        "ESP: sip -> {} ({})",
        if sip_on { "on" } else { "off" },
        esp_img.display()
    );
    Ok(())
}

fn parse_bootflag(buf: &[u8; 512]) -> Result<(bool, bool, bool)> {
    if &buf[0..4] != ONEBOOT_BOOTFLAG_MAGIC {
        anyhow::bail!("invalid BootFlag magic");
    }
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if version != 1 {
        anyhow::bail!("unsupported BootFlag version: {}", version);
    }
    let stored_crc = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let calc = crc32_ieee_with_zeroed_range(buf, 16, 4);
    if stored_crc != 0 && stored_crc != calc {
        anyhow::bail!("BootFlag crc mismatch");
    }
    let flags = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let force_recovery = (flags & 0b1) != 0;
    let mark_success = (flags & 0b10) != 0;
    let mmu_strict = (flags & 0b100) == 0;
    Ok((force_recovery, mark_success, mmu_strict))
}

fn write_bootflag(buf: &mut [u8; 512], force_recovery: bool, mark_success: bool, mmu_strict: bool) {
    buf.fill(0);
    buf[0..4].copy_from_slice(ONEBOOT_BOOTFLAG_MAGIC);
    buf[4..8].copy_from_slice(&1u32.to_le_bytes());
    let mut flags = 0u32;
    if force_recovery {
        flags |= 0b1;
    }
    if mark_success {
        flags |= 0b10;
    }
    if !mmu_strict {
        flags |= 0b100;
    }
    buf[8..12].copy_from_slice(&flags.to_le_bytes());
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());
    buf[16..20].copy_from_slice(&0u32.to_le_bytes());
    let crc = crc32_ieee_with_zeroed_range(buf, 16, 4);
    buf[16..20].copy_from_slice(&crc.to_le_bytes());
}

fn parse_sip(buf: &[u8; 512]) -> Result<bool> {
    if &buf[0..4] != ONEBOOT_SIP_MAGIC {
        anyhow::bail!("invalid SIP magic");
    }
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if version != 1 {
        anyhow::bail!("unsupported SIP version: {}", version);
    }
    let stored_crc = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let calc = crc32_ieee_with_zeroed_range(buf, 12, 4);
    if stored_crc != 0 && stored_crc != calc {
        anyhow::bail!("SIP crc mismatch");
    }
    let sip_on = u32::from_le_bytes(buf[8..12].try_into().unwrap()) != 0;
    Ok(sip_on)
}

fn write_sip(buf: &mut [u8; 512], sip_on: bool) {
    buf.fill(0);
    buf[0..4].copy_from_slice(ONEBOOT_SIP_MAGIC);
    buf[4..8].copy_from_slice(&1u32.to_le_bytes());
    buf[8..12].copy_from_slice(&(if sip_on { 1u32 } else { 0u32 }).to_le_bytes());
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());
    let crc = crc32_ieee_with_zeroed_range(buf, 12, 4);
    buf[12..16].copy_from_slice(&crc.to_le_bytes());
}

fn parse_bootstat(buf: &[u8; 512]) -> Result<(u32, u64, u32, u32)> {
    if &buf[0..4] != ONEBOOT_BOOTSTAT_MAGIC {
        anyhow::bail!("invalid BootState magic");
    }
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if version != 1 {
        anyhow::bail!("unsupported BootState version: {}", version);
    }
    let stored_crc = u32::from_le_bytes(buf[32..36].try_into().unwrap());
    let calc = crc32_ieee_with_zeroed_range(buf, 32, 4);
    if stored_crc != 0 && stored_crc != calc {
        anyhow::bail!("BootState crc mismatch");
    }
    let failures = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let last_boot_id = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let last_panic_code = u32::from_le_bytes(buf[24..28].try_into().unwrap());
    let ring_head = u32::from_le_bytes(buf[28..32].try_into().unwrap());
    Ok((failures, last_boot_id, last_panic_code, ring_head))
}

fn write_bootstat(
    buf: &mut [u8; 512],
    failures: u32,
    last_boot_id: u64,
    last_panic_code: u32,
    ring_head: u32,
    ring: &[(u64, u32); 8],
) {
    buf.fill(0);
    buf[0..4].copy_from_slice(ONEBOOT_BOOTSTAT_MAGIC);
    buf[4..8].copy_from_slice(&1u32.to_le_bytes());
    buf[8..12].copy_from_slice(&failures.to_le_bytes());
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());
    buf[16..24].copy_from_slice(&last_boot_id.to_le_bytes());
    buf[24..28].copy_from_slice(&last_panic_code.to_le_bytes());
    buf[28..32].copy_from_slice(&ring_head.to_le_bytes());
    buf[32..36].copy_from_slice(&0u32.to_le_bytes());
    // ring entries start at 0x24 (36)
    let mut off = 0x24usize;
    for (boot_id, code) in ring.iter() {
        buf[off..off + 8].copy_from_slice(&boot_id.to_le_bytes());
        buf[off + 8..off + 12].copy_from_slice(&code.to_le_bytes());
        buf[off + 12..off + 16].copy_from_slice(&0u32.to_le_bytes());
        off += 16;
    }
    let crc = crc32_ieee_with_zeroed_range(buf, 32, 4);
    buf[32..36].copy_from_slice(&crc.to_le_bytes());
}

fn read_bootstat_ring(buf: &[u8; 512]) -> [(u64, u32); 8] {
    let mut out = [(0u64, 0u32); 8];
    let mut off = 0x24usize;
    for i in 0..8 {
        let boot_id = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        let code = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
        out[i] = (boot_id, code);
        off += 16;
    }
    out
}
const GOES_BLOCK_SIZE: u64 = 4096;
const GOES_SB_HEADER_SIZE_V01: u32 = 256;
const GOES_MANIFEST_BLOCK_SIZE: usize = 4096;
const GOES_MANIFEST_MAGIC_V01: &[u8; 4] = b"OGMF";
const GOES_MANIFEST_ENTRY_NAME_LEN: usize = 32;
const GOES_MANIFEST_ENTRY_SIZE: u32 = 48;
const GOES_CHECKPOINT_MAGIC_V01: &[u8; 4] = b"GOCP";
const GOES_BOOT_MANIFEST_MAGIC_V01: &[u8; 4] = b"GOBM";
const GOES_BOOT_MANIFEST_BLOCK_SIZE: usize = 4096;
const GOES_BOOT_MANIFEST_ENTRY_SIZE: u32 = 48;
const GOES_RECORD_MAGIC_V01: &[u8; 4] = b"GORE";

const GOES_FLAG_ADMIN: u32 = 1 << 0;
const GOES_FLAG_SIP_ON: u32 = 1 << 1;

const GOES_RECORD_TYPE_BOOT_MANIFEST_SNAPSHOT: u32 = 1;
const GOES_RECORD_TYPE_WORKSPACE_LIST: u32 = 2;
const GOES_RECORD_TYPE_KERNEL_REFS: u32 = 3;
const GOES_RECORD_TYPE_EDGE_LIST: u32 = 4;
const GOES_RECORD_TYPE_ACCOUNT_OBJECT: u32 = 5;
const GOES_RECORD_TYPE_WORKSPACE_OBJECT: u32 = 6;
const GOES_RECORD_TYPE_INSTALLER_STAMP: u32 = 7;

// 为了支持 `xtask install --update` 的“追加式安全更新”，RecordLog 预留固定容量。
// v0.1：仅用于追加少量记录（例如 installer stamp），避免修改 superblock/bootmanifest 等 System 区域。
const GOES_RECORD_LOG_MIN_LEN: u64 = 1024 * 1024; // 1 MiB

#[derive(Clone, Copy)]
struct GoesSuperblockV01Fields {
    checkpoint_offset: u64,
    manifest_offset: u64,
    kernel_x86_offset: u64,
    kernel_x86_len: u64,
    kernel_aa_offset: u64,
    kernel_aa_len: u64,
    record_log_offset: u64,
    record_log_len: u64,
    flags: u32,
    default_user: [u8; 32],
}

#[derive(Clone, Copy)]
struct GoesManifestV01Fields {
    flags: u32,
    default_user: [u8; 32],
    kernel_x86_offset: u64,
    kernel_x86_len: u64,
    kernel_aa_offset: u64,
    kernel_aa_len: u64,
}

#[derive(Clone, Copy)]
struct GoesCheckpointV01Fields {
    seq: u64,
    boot_manifest_offset: u64,
}

#[derive(Clone, Copy)]
struct GoesBootSetV01 {
    flags: u32,
    kernel_x86_offset: u64,
    kernel_x86_len: u64,
    kernel_aa_offset: u64,
    kernel_aa_len: u64,
}

#[derive(Clone, Copy)]
struct GoesBootManifestV01Fields {
    flags: u32,
    seq: u64,
    active_set: u32,
    set_count: u32,
    default_user: [u8; 32],
    set_entries: [GoesBootSetV01; 2],
}

fn put_u32_le(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64_le(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn get_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn get_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let bytes = buf.get(off..off + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn encode_goes_superblock_v01(out: &mut [u8], fields: GoesSuperblockV01Fields) {
    // v0.1 superblock header (little-endian, fixed offsets)
    // 0x00: magic "GOES" (4)
    // 0x04: version (u32)
    // 0x08: header_size (u32)
    // 0x0c: block_size (u32)
    // 0x10: flags (u32)  bit0=admin
    // 0x14: reserved (u32)
    // 0x18: checkpoint_offset (u64)
    // 0x20: manifest_offset (u64)
    // 0x28: kernel_x86_offset (u64)
    // 0x30: kernel_x86_len (u64)
    // 0x38: kernel_aa_offset (u64)
    // 0x40: kernel_aa_len (u64)
    // 0x48: default_user (32 bytes, UTF-8, NUL padded)
    // 0x68: crc32 (u32)  (ieee, over header_size bytes with this field zeroed)
    // 0x70: record_log_offset (u64)
    // 0x78: record_log_len (u64)
    out.fill(0);
    out[0..4].copy_from_slice(b"GOES");
    put_u32_le(out, 0x04, 1);
    put_u32_le(out, 0x08, GOES_SB_HEADER_SIZE_V01);
    put_u32_le(out, 0x0c, GOES_BLOCK_SIZE as u32);
    put_u32_le(out, 0x10, fields.flags);
    put_u32_le(out, 0x14, 0);
    put_u64_le(out, 0x18, fields.checkpoint_offset);
    put_u64_le(out, 0x20, fields.manifest_offset);
    put_u64_le(out, 0x28, fields.kernel_x86_offset);
    put_u64_le(out, 0x30, fields.kernel_x86_len);
    put_u64_le(out, 0x38, fields.kernel_aa_offset);
    put_u64_le(out, 0x40, fields.kernel_aa_len);
    out[0x48..0x48 + 32].copy_from_slice(&fields.default_user);
    put_u64_le(out, 0x70, fields.record_log_offset);
    put_u64_le(out, 0x78, fields.record_log_len);

    // crc32 over header_size bytes with crc field zeroed
    put_u32_le(out, 0x68, 0);
    let crc = crc32_ieee_with_zeroed_range(&out[..GOES_SB_HEADER_SIZE_V01 as usize], 0x68, 4);
    put_u32_le(out, 0x68, crc);
}

fn encode_goes_checkpoint_v01(out: &mut [u8], fields: GoesCheckpointV01Fields) {
    // Checkpoint v0.1 (little-endian, fixed offsets)
    // 0x00: magic "GOCP" (4)
    // 0x04: version (u32) = 1
    // 0x08: reserved (u32)
    // 0x0c: reserved (u32)
    // 0x10: seq (u64)
    // 0x18: boot_manifest_offset (u64)
    // 0x20: crc32 (u32) (ieee, over full 4K with this field zeroed)
    out.fill(0);
    out[0..4].copy_from_slice(GOES_CHECKPOINT_MAGIC_V01);
    put_u32_le(out, 0x04, 1);
    put_u64_le(out, 0x10, fields.seq);
    put_u64_le(out, 0x18, fields.boot_manifest_offset);
    put_u32_le(out, 0x20, 0);
    let crc = crc32_ieee_with_zeroed_range(out, 0x20, 4);
    put_u32_le(out, 0x20, crc);
}

fn encode_goes_boot_manifest_v01(out: &mut [u8], fields: GoesBootManifestV01Fields) {
    // BootManifest v0.1 (little-endian, fixed offsets)
    // 0x00: magic "GOBM" (4)
    // 0x04: version (u32) = 1
    // 0x08: header_size (u32) = 0x100
    // 0x0c: flags (u32)
    // 0x10: seq (u64)
    // 0x18: active_set (u32)
    // 0x1c: set_count (u32)
    // 0x20: default_user (32 bytes)
    // 0x40: set_entries_offset (u32) = 0x100
    // 0x44: set_entry_size (u32) = 48
    // 0x48: crc32 (u32) (ieee, over full 4K with this field zeroed)
    //
    // BootSet entry (48 bytes):
    // 0x00: flags (u32)
    // 0x04: reserved (u32)
    // 0x08: kernel_x86_offset (u64)
    // 0x10: kernel_x86_len (u64)
    // 0x18: kernel_aa_offset (u64)
    // 0x20: kernel_aa_len (u64)
    out.fill(0);
    out[0..4].copy_from_slice(GOES_BOOT_MANIFEST_MAGIC_V01);
    put_u32_le(out, 0x04, 1);
    put_u32_le(out, 0x08, 0x100);
    put_u32_le(out, 0x0c, fields.flags);
    put_u64_le(out, 0x10, fields.seq);
    put_u32_le(out, 0x18, fields.active_set);
    put_u32_le(out, 0x1c, fields.set_count);
    out[0x20..0x20 + 32].copy_from_slice(&fields.default_user);
    put_u32_le(out, 0x40, 0x100);
    put_u32_le(out, 0x44, GOES_BOOT_MANIFEST_ENTRY_SIZE);
    put_u32_le(out, 0x48, 0);

    let base = 0x100usize;
    let entry_size = GOES_BOOT_MANIFEST_ENTRY_SIZE as usize;
    for (i, s) in fields.set_entries.iter().enumerate() {
        let off = base + i * entry_size;
        put_u32_le(out, off + 0x00, s.flags);
        put_u32_le(out, off + 0x04, 0);
        put_u64_le(out, off + 0x08, s.kernel_x86_offset);
        put_u64_le(out, off + 0x10, s.kernel_x86_len);
        put_u64_le(out, off + 0x18, s.kernel_aa_offset);
        put_u64_le(out, off + 0x20, s.kernel_aa_len);
    }

    let crc = crc32_ieee_with_zeroed_range(out, 0x48, 4);
    put_u32_le(out, 0x48, crc);
}

fn encode_goes_manifest_v01(
    out: &mut [u8],
    fields: GoesManifestV01Fields,
    workspaces: &[&str],
) -> Result<()> {
    // Manifest layout (little-endian, fixed offsets):
    // 0x00: magic "OGMF" (4)
    // 0x04: version (u32) = 1
    // 0x08: flags (u32)  bit0=admin, bit1=sip_on (reserved for future)
    // 0x0c: reserved (u32)
    // 0x10: default_user (32 bytes, UTF-8, NUL padded)
    // 0x30: workspace_count (u32)
    // 0x34: reserved (u32)
    // 0x38: workspace_entries_offset (u32) = 0x100
    // 0x3c: workspace_entry_size (u32) = 48
    // 0x40: kernel_x86_offset (u64)
    // 0x48: kernel_x86_len (u64)
    // 0x50: kernel_aa_offset (u64)
    // 0x58: kernel_aa_len (u64)
    // 0x60: crc32 (u32) (ieee, over full 4K with this field zeroed)
    // 0x64..: reserved
    //
    // Workspace entry (48 bytes):
    // 0x00: name[32] (UTF-8, NUL padded)
    // 0x20: flags (u32) (0 for now)
    // 0x24: reserved (u32)
    // 0x28: reserved[8]
    out.fill(0);
    out[0..4].copy_from_slice(GOES_MANIFEST_MAGIC_V01);
    put_u32_le(out, 0x04, 1);
    put_u32_le(out, 0x08, fields.flags);
    put_u32_le(out, 0x0c, 0);
    out[0x10..0x10 + 32].copy_from_slice(&fields.default_user);
    put_u32_le(out, 0x30, workspaces.len() as u32);
    put_u32_le(out, 0x34, 0);
    put_u32_le(out, 0x38, 0x100);
    put_u32_le(out, 0x3c, GOES_MANIFEST_ENTRY_SIZE);
    put_u64_le(out, 0x40, fields.kernel_x86_offset);
    put_u64_le(out, 0x48, fields.kernel_x86_len);
    put_u64_le(out, 0x50, fields.kernel_aa_offset);
    put_u64_le(out, 0x58, fields.kernel_aa_len);
    put_u32_le(out, 0x60, 0);

    let entries_off = 0x100usize;
    let entry_size = GOES_MANIFEST_ENTRY_SIZE as usize;
    let total_needed = entries_off + entry_size * workspaces.len();
    if total_needed > out.len() {
        anyhow::bail!("manifest too small for workspace list");
    }

    for (i, ws) in workspaces.iter().enumerate() {
        let mut name = [0u8; GOES_MANIFEST_ENTRY_NAME_LEN];
        let bytes = ws.as_bytes();
        let n = bytes.len().min(name.len());
        name[..n].copy_from_slice(&bytes[..n]);
        let base = entries_off + i * entry_size;
        out[base..base + GOES_MANIFEST_ENTRY_NAME_LEN].copy_from_slice(&name);
        // flags/reserved are zero for now
    }

    let crc = crc32_ieee_with_zeroed_range(out, 0x60, 4);
    put_u32_le(out, 0x60, crc);

    Ok(())
}

fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

fn goes_update_kernel_blobs_in_place(
    goes_img: &Path,
    x86_blob: &Path,
    aa_blob: &Path,
) -> Result<()> {
    let mut x86 = Vec::new();
    fs::File::open(x86_blob)
        .with_context(|| format!("open {}", x86_blob.display()))?
        .read_to_end(&mut x86)
        .context("read x86 blob")?;
    let mut aa = Vec::new();
    fs::File::open(aa_blob)
        .with_context(|| format!("open {}", aa_blob.display()))?
        .read_to_end(&mut aa)
        .context("read aarch64 blob")?;

    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(goes_img)
        .with_context(|| format!("open {}", goes_img.display()))?;

    let mut sb = vec![0u8; GOES_BLOCK_SIZE as usize];
    f.read_exact(&mut sb).context("read superblock")?;
    let Some(sb_fields) = parse_goes_superblock_v01(&sb) else {
        anyhow::bail!("invalid GOES superblock");
    };

    // Prefer BootManifest set entries (authoritative for boot). Fall back to superblock offsets.
    let mut x86_targets: Vec<(u64, u64)> = Vec::new();
    let mut aa_targets: Vec<(u64, u64)> = Vec::new();

    if sb_fields.checkpoint_offset != 0 {
        f.seek(SeekFrom::Start(sb_fields.checkpoint_offset))
            .context("seek checkpoint")?;
        let mut chk = vec![0u8; GOES_BLOCK_SIZE as usize];
        f.read_exact(&mut chk).context("read checkpoint")?;
        if let Some(chk_fields) = parse_goes_checkpoint_v01(&chk) {
            if chk_fields.boot_manifest_offset != 0 {
                f.seek(SeekFrom::Start(chk_fields.boot_manifest_offset))
                    .context("seek bootmanifest")?;
                let mut bm = vec![0u8; GOES_BOOT_MANIFEST_BLOCK_SIZE];
                f.read_exact(&mut bm).context("read bootmanifest")?;
                if let Some((_flags, _seq, _active_set, set_count, _du)) =
                    parse_goes_boot_manifest_header_v01(&bm)
                {
                    let set_entries_offset = get_u32_le(&bm, 0x40).unwrap_or(0x100) as usize;
                    let set_entry_size =
                        get_u32_le(&bm, 0x44).unwrap_or(GOES_BOOT_MANIFEST_ENTRY_SIZE) as usize;
                    for i in 0..(set_count.min(8) as usize) {
                        let base = set_entries_offset + i * set_entry_size;
                        if base + set_entry_size > bm.len() {
                            break;
                        }
                        let xoff = get_u64_le(&bm, base + 0x08).unwrap_or(0);
                        let xlen = get_u64_le(&bm, base + 0x10).unwrap_or(0);
                        let aoff = get_u64_le(&bm, base + 0x18).unwrap_or(0);
                        let alen = get_u64_le(&bm, base + 0x20).unwrap_or(0);
                        if xoff != 0 && xlen != 0 {
                            x86_targets.push((xoff, xlen));
                        }
                        if aoff != 0 && alen != 0 {
                            aa_targets.push((aoff, alen));
                        }
                    }
                }
            }
        }
    }

    if x86_targets.is_empty() && sb_fields.kernel_x86_offset != 0 && sb_fields.kernel_x86_len != 0 {
        x86_targets.push((sb_fields.kernel_x86_offset, sb_fields.kernel_x86_len));
    }
    if aa_targets.is_empty() && sb_fields.kernel_aa_offset != 0 && sb_fields.kernel_aa_len != 0 {
        aa_targets.push((sb_fields.kernel_aa_offset, sb_fields.kernel_aa_len));
    }

    x86_targets.sort_unstable();
    x86_targets.dedup();
    aa_targets.sort_unstable();
    aa_targets.dedup();

    let mut write_blob = |name: &str, blob: &[u8], targets: &[(u64, u64)]| -> Result<()> {
        if targets.is_empty() {
            anyhow::bail!("GOES image has no {} kernel slot", name);
        }
        for (off, len) in targets.iter().copied() {
            if blob.len() as u64 > len {
                anyhow::bail!(
                    "new {} kernel too large for slot (need {} bytes, slot {} bytes); use `xtask install --recovery --sip-off`",
                    name,
                    blob.len(),
                    len
                );
            }
            eprintln!(
                "[xtask] goes: update {} kernel in-place: off={:#x} slot_len={:#x} new_len={:#x}",
                name,
                off,
                len,
                blob.len()
            );
            f.seek(SeekFrom::Start(off))
                .with_context(|| format!("seek {} kernel slot", name))?;
            f.write_all(blob)
                .with_context(|| format!("write {} kernel bytes", name))?;
            // Zero tail to avoid leaving stale bytes.
            let tail = len.saturating_sub(blob.len() as u64);
            if tail > 0 {
                let zeros = [0u8; 4096];
                let mut remaining = tail;
                while remaining > 0 {
                    let take = (remaining as usize).min(zeros.len());
                    f.write_all(&zeros[..take]).context("write padding")?;
                    remaining -= take as u64;
                }
            }
        }
        Ok(())
    };

    write_blob("x86_64", &x86, &x86_targets)?;
    write_blob("aarch64", &aa, &aa_targets)?;
    f.flush().ok();
    Ok(())
}

fn align_up_usize(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

fn append_record_v01(out: &mut Vec<u8>, record_type: u32, seq: u64, payload: &[u8]) {
    // Record header v0.1 (32 bytes, little-endian):
    // 0x00: magic "GORE" (4)
    // 0x04: version (u16)=1
    // 0x06: reserved (u16)=0
    // 0x08: record_type (u32)
    // 0x0c: payload_len (u32)
    // 0x10: seq (u64)
    // 0x18: crc32 (u32) (ieee, over header+payload with this field zeroed)
    // 0x1c: reserved (u32)=0
    let mut header = [0u8; 32];
    header[0..4].copy_from_slice(GOES_RECORD_MAGIC_V01);
    header[4..6].copy_from_slice(&1u16.to_le_bytes());
    header[6..8].copy_from_slice(&0u16.to_le_bytes());
    header[8..12].copy_from_slice(&record_type.to_le_bytes());
    header[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    header[16..24].copy_from_slice(&seq.to_le_bytes());
    header[24..28].copy_from_slice(&0u32.to_le_bytes());
    header[28..32].copy_from_slice(&0u32.to_le_bytes());

    // Compute crc over header+payload with crc field zeroed.
    let mut tmp = Vec::with_capacity(header.len() + payload.len());
    tmp.extend_from_slice(&header);
    tmp.extend_from_slice(payload);
    let crc = crc32_ieee_with_zeroed_range(&tmp, 24, 4);
    header[24..28].copy_from_slice(&crc.to_le_bytes());

    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    let padded = align_up_usize(out.len(), 8);
    out.resize(padded, 0);
}

fn encode_name32(name: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = name.as_bytes();
    let n = bytes.len().min(out.len());
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

fn encode_app_manifest_v2_payload(name: &str, entry: &str, version: &str) -> [u8; 104] {
    let mut out = [0u8; 104];
    out[0..4].copy_from_slice(&2u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&encode_name32(name));
    out[40..72].copy_from_slice(&encode_name32(entry));
    out[72..104].copy_from_slice(&encode_name32(version));
    out
}

#[allow(dead_code)]
fn encode_app_binary_v2_header_arch(name: &str, size: u64, arch: u32) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[0..4].copy_from_slice(&2u32.to_le_bytes());
    // v2 extension: reserved field carries arch (0=any, 1=x86_64, 2=aarch64).
    out[4..8].copy_from_slice(&arch.to_le_bytes());
    out[8..40].copy_from_slice(&encode_name32(name));
    out[40..48].copy_from_slice(&size.to_le_bytes());
    out
}

fn encode_app_caps_v2_payload(name: &str, caps_mask: u64) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[0..4].copy_from_slice(&2u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&encode_name32(name));
    out[40..48].copy_from_slice(&caps_mask.to_le_bytes());
    out
}

fn derive_app_workspace_name(name: &str, manifest_seq: u64) -> String {
    let s = format!("App:{}", name);
    if s.as_bytes().len() <= 32 {
        return s;
    }
    format!("App#{}", manifest_seq)
}

fn derive_app_data_workspace_name(name: &str, manifest_seq: u64) -> String {
    let s = format!("LAD:{}", name);
    if s.as_bytes().len() <= 32 {
        return s;
    }
    format!("LAD#{}", manifest_seq)
}

fn derive_service_workspace_name(name: &str, manifest_seq: u64) -> String {
    let s = format!("Service:{}", name);
    if s.as_bytes().len() <= 32 {
        return s;
    }
    format!("Service#{}", manifest_seq)
}

fn encode_create_workspace_payload_v1(name: &str) -> [u8; 40] {
    // v1 payload:
    // u32 version(1), u32 flags, name[32]
    let mut out = [0u8; 40];
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&encode_name32(name));
    out
}

fn encode_app_registry_payload_v1(name: &str, app_ws: &str) -> [u8; 72] {
    // payload:
    // u32 version(1), u32 flags(0), name[32], app_ws[32]
    let mut out = [0u8; 72];
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..40].copy_from_slice(&encode_name32(name));
    out[40..72].copy_from_slice(&encode_name32(app_ws));
    out
}

fn encode_app_config_text_payload_v1(name: &str, app_ws: &str, bytes: &[u8]) -> Vec<u8> {
    // payload v1:
    // u32 version(1), u32 flags(0), name[32], app_ws[32], u32 len, bytes[len]
    let mut out = Vec::with_capacity(4 + 4 + 32 + 32 + 4 + bytes.len());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&encode_name32(name));
    out.extend_from_slice(&encode_name32(app_ws));
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn encode_app_asset_blob_v1_payload(
    name: &str,
    app_ws: &str,
    asset_name: &str,
    bytes: &[u8],
) -> Vec<u8> {
    // payload v1:
    // u32 version(1), u32 flags(0), name[32], app_ws[32], asset_name[32], u32 len, bytes[len]
    let mut out = Vec::with_capacity(4 + 4 + 32 + 32 + 32 + 4 + bytes.len());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&encode_name32(name));
    out.extend_from_slice(&encode_name32(app_ws));
    out.extend_from_slice(&encode_name32(asset_name));
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn encode_app_shipped_payload_v1(
    name: &str,
    arch: u32,
    binary_seq: u64,
    binary_len: u32,
) -> [u8; 56] {
    // payload: u32 ver(1), u32 arch, name[32], u64 binary_seq, u32 binary_len, u32 reserved
    let mut out = [0u8; 56];
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&arch.to_le_bytes());
    out[8..40].copy_from_slice(&encode_name32(name));
    out[40..48].copy_from_slice(&binary_seq.to_le_bytes());
    out[48..52].copy_from_slice(&binary_len.to_le_bytes());
    out[52..56].copy_from_slice(&0u32.to_le_bytes());
    out
}

fn encode_app_image_v1_prefix(name: &str, arch: u32, image_len: u32) -> [u8; 56] {
    // payload: u32 ver(1), u32 arch, name[32], u64 source_seq(0), u32 image_len, u32 reserved
    let mut out = [0u8; 56];
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&arch.to_le_bytes());
    out[8..40].copy_from_slice(&encode_name32(name));
    out[40..48].copy_from_slice(&0u64.to_le_bytes());
    out[48..52].copy_from_slice(&image_len.to_le_bytes());
    out[52..56].copy_from_slice(&0u32.to_le_bytes());
    out
}

fn build_oapp_image_from_elf(elf: &[u8]) -> Result<Vec<u8>> {
    // Build a compact segment image:
    // OAPP header(24) + seg table + concatenated PT_LOAD bytes.
    //
    // OAPP v1:
    // - header[20..24] = 0 (reserved)
    // - seg entry (16 bytes): vaddr(u64), filesz(u32), memsz(u32)
    //
    // OAPP v2:
    // - header[20..24] = seg_entry_size (u32)
    // - seg entry (24 bytes):
    //     vaddr(u64), filesz(u32), memsz(u32), flags(u32), reserved(u32)
    if elf.len() < 0x40 {
        anyhow::bail!("elf too small");
    }
    if &elf[0..4] != b"\x7FELF" {
        anyhow::bail!("not an ELF");
    }
    // EI_CLASS=2 (64-bit), EI_DATA=1 (LE)
    if elf.get(4).copied() != Some(2) || elf.get(5).copied() != Some(1) {
        anyhow::bail!("unsupported elf class/data");
    }
    let entry = u64::from_le_bytes(elf[0x18..0x20].try_into().unwrap_or([0; 8]));
    let phoff = u64::from_le_bytes(elf[0x20..0x28].try_into().unwrap_or([0; 8])) as usize;
    let phentsize = u16::from_le_bytes(elf[0x36..0x38].try_into().unwrap_or([0; 2])) as usize;
    let phnum = u16::from_le_bytes(elf[0x38..0x3a].try_into().unwrap_or([0; 2])) as usize;
    if phoff == 0 || phnum == 0 || phentsize < 56 {
        anyhow::bail!("invalid phdr table");
    }
    let table_end = phoff
        .checked_add(
            phentsize
                .checked_mul(phnum)
                .ok_or_else(|| anyhow::anyhow!("phdr overflow"))?,
        )
        .ok_or_else(|| anyhow::anyhow!("phdr overflow"))?;
    if table_end > elf.len() {
        anyhow::bail!("phdr table out of range");
    }

    #[derive(Clone, Copy)]
    struct Seg {
        vaddr: u64,
        filesz: u32,
        memsz: u32,
        flags: u32,
        off: usize,
    }
    let mut segs: Vec<Seg> = Vec::new();
    let mut total_filesz: usize = 0;
    for i in 0..phnum {
        let o = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(elf[o..o + 4].try_into().unwrap_or([0; 4]));
        if p_type != 1 {
            continue;
        }
        let p_flags = u32::from_le_bytes(elf[o + 4..o + 8].try_into().unwrap_or([0; 4]));
        let p_offset = u64::from_le_bytes(elf[o + 8..o + 16].try_into().unwrap_or([0; 8])) as usize;
        let p_vaddr = u64::from_le_bytes(elf[o + 16..o + 24].try_into().unwrap_or([0; 8]));
        let p_filesz = u64::from_le_bytes(elf[o + 32..o + 40].try_into().unwrap_or([0; 8]));
        let p_memsz = u64::from_le_bytes(elf[o + 40..o + 48].try_into().unwrap_or([0; 8]));
        if p_memsz == 0 {
            continue;
        }
        if p_filesz > u32::MAX as u64 || p_memsz > u32::MAX as u64 {
            anyhow::bail!("segment too large");
        }
        let filesz = p_filesz as usize;
        if p_offset
            .checked_add(filesz)
            .ok_or_else(|| anyhow::anyhow!("seg overflow"))?
            > elf.len()
        {
            anyhow::bail!("segment out of range");
        }
        total_filesz = total_filesz.saturating_add(filesz);
        segs.push(Seg {
            vaddr: p_vaddr,
            filesz: p_filesz as u32,
            memsz: p_memsz as u32,
            flags: p_flags,
            off: p_offset,
        });
    }
    if segs.is_empty() {
        anyhow::bail!("no PT_LOAD segments");
    }

    let header_len = 24usize;
    let seg_entry_size = 24usize;
    let table_len = segs.len() * seg_entry_size;
    let mut out = Vec::new();
    out.resize(header_len + table_len + total_filesz, 0u8);
    out[0..4].copy_from_slice(b"OAPP");
    out[4..8].copy_from_slice(&2u32.to_le_bytes());
    out[8..16].copy_from_slice(&entry.to_le_bytes());
    out[16..20].copy_from_slice(&(segs.len() as u32).to_le_bytes());
    out[20..24].copy_from_slice(&(seg_entry_size as u32).to_le_bytes());

    let mut t = header_len;
    for seg in segs.iter() {
        out[t..t + 8].copy_from_slice(&seg.vaddr.to_le_bytes());
        out[t + 8..t + 12].copy_from_slice(&seg.filesz.to_le_bytes());
        out[t + 12..t + 16].copy_from_slice(&seg.memsz.to_le_bytes());
        out[t + 16..t + 20].copy_from_slice(&seg.flags.to_le_bytes());
        out[t + 20..t + 24].copy_from_slice(&0u32.to_le_bytes());
        t += seg_entry_size;
    }

    let mut d = header_len + table_len;
    for seg in segs.iter() {
        let filesz = seg.filesz as usize;
        if filesz != 0 {
            out[d..d + filesz].copy_from_slice(&elf[seg.off..seg.off + filesz]);
            d += filesz;
        }
    }
    Ok(out)
}

fn encode_workspace_object_v01_payload(name: &str, flags: u32) -> Vec<u8> {
    // payload v0.1:
    // u32 version(1), u32 flags, name[32]
    let mut out = Vec::with_capacity(4 + 4 + 32);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&encode_name32(name));
    out
}

fn encode_account_object_v01_payload(name: &str, flags: u32, password: Option<&[u8]>) -> Vec<u8> {
    // payload v0.1:
    // u32 version(1), u32 flags, name[32], u32 password_len, [password bytes...]
    let pw = password.unwrap_or(&[]);
    let mut out = Vec::with_capacity(4 + 4 + 32 + 4 + pw.len());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&encode_name32(name));
    out.extend_from_slice(&(pw.len() as u32).to_le_bytes());
    out.extend_from_slice(pw);
    out
}

fn goes_append_installer_stamp(img: &Path) -> Result<()> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(img)
        .with_context(|| format!("open {}", img.display()))?;

    let mut sb = vec![0u8; GOES_BLOCK_SIZE as usize];
    f.read_exact(&mut sb).context("read superblock")?;
    let Some(sb_fields) = parse_goes_superblock_v01(&sb) else {
        anyhow::bail!("invalid GOES superblock (cannot append installer stamp)");
    };
    if sb_fields.record_log_offset == 0 || sb_fields.record_log_len == 0 {
        anyhow::bail!("GOES record_log missing (cannot append installer stamp)");
    }

    let mut buf = vec![0u8; sb_fields.record_log_len as usize];
    f.seek(SeekFrom::Start(sb_fields.record_log_offset))
        .context("seek record log")?;
    f.read_exact(&mut buf).context("read record log")?;

    // Find append position by scanning existing records (same as goes_show).
    let mut off = 0usize;
    let mut last_seq = 0u64;
    while off + 32 <= buf.len() {
        if &buf[off..off + 4] != GOES_RECORD_MAGIC_V01 {
            break;
        }
        let version = u16::from_le_bytes(buf[off + 4..off + 6].try_into().unwrap_or([0u8, 0u8]));
        if version != 1 {
            break;
        }
        let payload_len = u32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap()) as usize;
        let seq = u64::from_le_bytes(buf[off + 16..off + 24].try_into().unwrap());
        let end = off + 32 + payload_len;
        if end > buf.len() {
            break;
        }
        last_seq = last_seq.max(seq);
        off = align_up_usize(end, 8);
    }

    // Build stamp record.
    // payload v0.1:
    // u32 version(1), u32 action(1=update), u64 unix_secs, tag[32]
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut payload = Vec::with_capacity(4 + 4 + 8 + 32);
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&1u32.to_le_bytes()); // action=update
    payload.extend_from_slice(&unix_secs.to_le_bytes());
    payload.extend_from_slice(&encode_name32("xtask-install-update"));

    let mut record = Vec::new();
    append_record_v01(
        &mut record,
        GOES_RECORD_TYPE_INSTALLER_STAMP,
        last_seq.wrapping_add(1),
        &payload,
    );

    if off + record.len() > buf.len() {
        anyhow::bail!(
            "GOES record_log is full (need {} bytes, have {}); recreate image with `xtask install --recovery --sip-off`",
            record.len(),
            buf.len().saturating_sub(off)
        );
    }

    eprintln!(
        "[xtask] goes: append installer stamp: off={:#x} seq={}",
        off,
        last_seq.wrapping_add(1)
    );
    f.seek(SeekFrom::Start(sb_fields.record_log_offset + off as u64))
        .context("seek record log (append)")?;
    f.write_all(&record).context("write installer stamp")?;
    f.flush().ok();
    Ok(())
}

fn create_goes_image(path: &Path, x86_blob: &Path, aa_blob: &Path, admin: bool) -> Result<()> {
    let mut x86 = Vec::new();
    eprintln!("[xtask] goes: reading x86 blob: {}", x86_blob.display());
    fs::File::open(x86_blob)
        .with_context(|| format!("open {}", x86_blob.display()))?
        .read_to_end(&mut x86)
        .context("read x86 blob")?;
    let mut aa = Vec::new();
    eprintln!("[xtask] goes: reading aarch64 blob: {}", aa_blob.display());
    fs::File::open(aa_blob)
        .with_context(|| format!("open {}", aa_blob.display()))?
        .read_to_end(&mut aa)
        .context("read aarch64 blob")?;

    // Layout (bytes):
    // 0x0000_0000 superblock (4K)
    // 0x0000_1000 checkpoint (4K)
    // 0x0000_2000 manifest (4K)
    // 0x0000_3000 bootmanifest (4K)
    // 0x0010_0000 kernel blobs (aligned)
    let super_off = 0u64;
    let checkpoint_off = GOES_BLOCK_SIZE;
    let manifest_off = GOES_BLOCK_SIZE * 2;
    let boot_manifest_off = GOES_BLOCK_SIZE * 3;
    let mut cursor = 0x0010_0000u64;
    cursor = align_up(cursor, GOES_BLOCK_SIZE);

    let kernel_x86_off = cursor;
    let kernel_x86_blob_len = x86.len() as u64;
    let kernel_x86_len = align_up(
        kernel_x86_blob_len + GOES_KERNEL_SLOT_SLACK_BYTES,
        GOES_BLOCK_SIZE,
    );
    cursor = align_up(kernel_x86_off + kernel_x86_len, GOES_BLOCK_SIZE);

    let kernel_aa_off = cursor;
    let kernel_aa_blob_len = aa.len() as u64;
    let kernel_aa_len = align_up(
        kernel_aa_blob_len + GOES_KERNEL_SLOT_SLACK_BYTES,
        GOES_BLOCK_SIZE,
    );
    cursor = align_up(kernel_aa_off + kernel_aa_len, GOES_BLOCK_SIZE);

    let mut default_user = [0u8; 32];
    if admin {
        let name = b"admin";
        default_user[..name.len()].copy_from_slice(name);
    }

    let workspaces: Vec<&str> = if admin {
        vec!["System", "Library", "Applications", "Users", "User:admin"]
    } else {
        vec!["System", "Library", "Applications", "Users"]
    };

    let flags = (if admin { GOES_FLAG_ADMIN } else { 0 }) | GOES_FLAG_SIP_ON;

    // manifest block
    let mut manifest_block = vec![0u8; GOES_MANIFEST_BLOCK_SIZE];
    encode_goes_manifest_v01(
        &mut manifest_block,
        GoesManifestV01Fields {
            flags,
            default_user,
            kernel_x86_offset: kernel_x86_off,
            kernel_x86_len,
            kernel_aa_offset: kernel_aa_off,
            kernel_aa_len,
        },
        &workspaces,
    )?;

    // bootmanifest block (active_set switch)
    let mut boot_manifest_block = vec![0u8; GOES_BOOT_MANIFEST_BLOCK_SIZE];
    let set0 = GoesBootSetV01 {
        flags: 0,
        kernel_x86_offset: kernel_x86_off,
        kernel_x86_len,
        kernel_aa_offset: kernel_aa_off,
        kernel_aa_len,
    };
    // v0.1：写两份相同的 set，便于验证 active_set 切换链路（未来可替换为不同版本）。
    encode_goes_boot_manifest_v01(
        &mut boot_manifest_block,
        GoesBootManifestV01Fields {
            flags,
            seq: 1,
            active_set: 0,
            set_count: 2,
            default_user,
            set_entries: [set0, set0],
        },
    );

    // record log (append-only, v0.1)
    let record_log_off = align_up(cursor, GOES_BLOCK_SIZE);
    let mut record_log = Vec::new();
    append_record_v01(
        &mut record_log,
        GOES_RECORD_TYPE_BOOT_MANIFEST_SNAPSHOT,
        1,
        &boot_manifest_block,
    );
    let mut ws_payload = Vec::new();
    for ws in &workspaces {
        ws_payload.extend_from_slice(ws.as_bytes());
        ws_payload.push(0);
    }
    append_record_v01(
        &mut record_log,
        GOES_RECORD_TYPE_WORKSPACE_LIST,
        2,
        &ws_payload,
    );
    let mut kern_payload = Vec::new();
    // payload v0.1:
    // u32 version(1), u32 reserved, u32 active_set, u32 set_count,
    // then N entries of (u32 flags, u32 reserved, u64 x86_off, u64 x86_len, u64 aa_off, u64 aa_len)
    kern_payload.extend_from_slice(&1u32.to_le_bytes());
    kern_payload.extend_from_slice(&0u32.to_le_bytes());
    kern_payload.extend_from_slice(&0u32.to_le_bytes()); // active_set=0
    kern_payload.extend_from_slice(&2u32.to_le_bytes()); // set_count=2
    for _ in 0..2 {
        kern_payload.extend_from_slice(&0u32.to_le_bytes());
        kern_payload.extend_from_slice(&0u32.to_le_bytes());
        kern_payload.extend_from_slice(&kernel_x86_off.to_le_bytes());
        kern_payload.extend_from_slice(&kernel_x86_len.to_le_bytes());
        kern_payload.extend_from_slice(&kernel_aa_off.to_le_bytes());
        kern_payload.extend_from_slice(&kernel_aa_len.to_le_bytes());
    }
    append_record_v01(
        &mut record_log,
        GOES_RECORD_TYPE_KERNEL_REFS,
        3,
        &kern_payload,
    );
    let mut edge_payload = Vec::new();
    // payload v0.1: NUL separated triples: from\0edge_type\0to\0 ...
    // System contains BootManifest
    edge_payload.extend_from_slice(b"System\0contains\0BootManifest\0");
    // BootManifest references KernelImage (active_set)
    edge_payload.extend_from_slice(b"BootManifest\0references\0KernelImage\0");
    // System references Library
    edge_payload.extend_from_slice(b"System\0references\0Library\0");
    if admin {
        // Users contains User:admin
        edge_payload.extend_from_slice(b"Users\0contains\0User:admin\0");
        // User:admin owns AccountObject (name=admin, v0.1 uses synthetic object name "Account:admin")
        edge_payload.extend_from_slice(b"User:admin\0owns\0Account:admin\0");
        // System default_user -> User:admin (for whoami/prompt)
        edge_payload.extend_from_slice(b"System\0default_user\0User:admin\0");
    }
    append_record_v01(
        &mut record_log,
        GOES_RECORD_TYPE_EDGE_LIST,
        4,
        &edge_payload,
    );

    let mut next_seq = 5u64;
    if admin {
        // v0.1: 写入最小 admin 账户对象与 workspace 对象（无密码，仅测试）。
        let ws_obj = encode_workspace_object_v01_payload("User:admin", 0);
        append_record_v01(
            &mut record_log,
            GOES_RECORD_TYPE_WORKSPACE_OBJECT,
            next_seq,
            &ws_obj,
        );
        next_seq += 1;
        let account_flags = 1u32; // bit0=admin (v0.1)
        let acct_obj = encode_account_object_v01_payload("admin", account_flags, None);
        append_record_v01(
            &mut record_log,
            GOES_RECORD_TYPE_ACCOUNT_OBJECT,
            next_seq,
            &acct_obj,
        );
        next_seq += 1;
    }

    // Built-in apps are sourced from repo `applications/*` and packaged as App workspaces.
    // Applications workspace only stores name->App:<name> registry relations.
    let repo_root = env::current_dir().context("current_dir")?;
    let apps = load_repo_apps(&repo_root)?;
    if apps.is_empty() {
        eprintln!(
            "[xtask] goes: no repo apps found under {}/applications",
            repo_root.display()
        );
    }
    for app in apps {
        let name = app.name.as_str();
        let entry = app.entry.as_str();
        let ver = app.version.as_str();
        let caps = app.caps_mask;
        let manifest_seq = next_seq;
        let manifest = encode_app_manifest_v2_payload(name, entry, ver);
        append_record_v01(
            &mut record_log,
            GOES_RECORD_APP_MANIFEST_V2,
            manifest_seq,
            &manifest,
        );
        next_seq += 1;
        // System-shipped apps: store an installer-generated segment image (OAPP) per arch.
        // This avoids ELF parsing and non-LOAD sections at runtime.
        let oapp_x86 = build_oapp_image_from_elf(&app.binary_x86_64)
            .with_context(|| format!("build OAPP image for {} (x86_64)", name))?;
        let mut img_payload_x86 = Vec::with_capacity(56 + oapp_x86.len());
        img_payload_x86.extend_from_slice(&encode_app_image_v1_prefix(
            name,
            1,
            oapp_x86.len() as u32,
        ));
        img_payload_x86.extend_from_slice(&oapp_x86);
        let img_seq_x86 = next_seq;
        append_record_v01(
            &mut record_log,
            GOES_RECORD_APP_IMAGE_V1,
            img_seq_x86,
            &img_payload_x86,
        );
        next_seq += 1;

        let oapp_aa = build_oapp_image_from_elf(&app.binary_aarch64)
            .with_context(|| format!("build OAPP image for {} (aarch64)", name))?;
        let mut img_payload_aa = Vec::with_capacity(56 + oapp_aa.len());
        img_payload_aa.extend_from_slice(&encode_app_image_v1_prefix(
            name,
            2,
            oapp_aa.len() as u32,
        ));
        img_payload_aa.extend_from_slice(&oapp_aa);
        let img_seq_aa = next_seq;
        append_record_v01(
            &mut record_log,
            GOES_RECORD_APP_IMAGE_V1,
            img_seq_aa,
            &img_payload_aa,
        );
        next_seq += 1;

        let cap = encode_app_caps_v2_payload(name, caps);
        append_record_v01(&mut record_log, GOES_RECORD_APP_CAPS_V2, next_seq, &cap);
        next_seq += 1;

        // v2: each app has its own App workspace (stored under Applications).
        let app_ws = derive_app_workspace_name(name, manifest_seq);
        let ws_payload = encode_create_workspace_payload_v1(&app_ws);
        append_record_v01(
            &mut record_log,
            GOES_RECORD_CREATE_WORKSPACE_V1,
            next_seq,
            &ws_payload,
        );
        next_seq += 1;

        // v2 minimal: per-app private data workspace in Library scope (no path semantics).
        // Represented as `LAD:<app>` and enforced by sandbox policy.
        let app_data_ws = derive_app_data_workspace_name(name, manifest_seq);
        let ws_payload = encode_create_workspace_payload_v1(&app_data_ws);
        append_record_v01(
            &mut record_log,
            GOES_RECORD_CREATE_WORKSPACE_V1,
            next_seq,
            &ws_payload,
        );
        next_seq += 1;

        // Applications registry: name -> App workspace mapping.
        let reg = encode_app_registry_payload_v1(name, &app_ws);
        append_record_v01(&mut record_log, GOES_RECORD_APP_REGISTRY_V1, next_seq, &reg);
        next_seq += 1;

        // AppConfig text content (stored in App workspace, no path semantics).
        let cfg = encode_app_config_text_payload_v1(name, &app_ws, &app.config_text);
        append_record_v01(
            &mut record_log,
            GOES_RECORD_APP_CONFIG_TEXT_V1,
            next_seq,
            &cfg,
        );
        next_seq += 1;

        // App assets (optional): stored in App workspace as blob records (no path semantics).
        for asset in app.assets.iter() {
            let payload =
                encode_app_asset_blob_v1_payload(name, &app_ws, &asset.name, &asset.bytes);
            append_record_v01(
                &mut record_log,
                GOES_RECORD_APP_ASSET_BLOB_V1,
                next_seq,
                &payload,
            );
            next_seq += 1;
        }

        // C3: mark repo apps as system-shipped, with expected image seq/len per arch.
        // This allows the kernel to skip runtime CRC for shipped apps as long as the image record matches.
        let shipped_x86 =
            encode_app_shipped_payload_v1(name, 1, img_seq_x86, oapp_x86.len() as u32);
        append_record_v01(
            &mut record_log,
            GOES_RECORD_APP_SHIPPED_V1,
            next_seq,
            &shipped_x86,
        );
        next_seq += 1;
        let shipped_aa = encode_app_shipped_payload_v1(name, 2, img_seq_aa, oapp_aa.len() as u32);
        append_record_v01(
            &mut record_log,
            GOES_RECORD_APP_SHIPPED_V1,
            next_seq,
            &shipped_aa,
        );
        next_seq += 1;
    }

    // Built-in services are sourced from repo `services/*` and packaged as Service workspaces.
    // Stage 4: runtime still links services into kernel; GOES workspaces are created for
    // future service packaging without introducing path semantics.
    let services = load_repo_services(&repo_root)?;
    for svc in services {
        let ws = derive_service_workspace_name(&svc.name, next_seq);
        let ws_payload = encode_create_workspace_payload_v1(&ws);
        append_record_v01(
            &mut record_log,
            GOES_RECORD_CREATE_WORKSPACE_V1,
            next_seq,
            &ws_payload,
        );
        next_seq += 1;
    }

    let record_log_len = align_up(
        (record_log.len() as u64).max(GOES_RECORD_LOG_MIN_LEN),
        GOES_BLOCK_SIZE,
    );
    record_log.resize(record_log_len as usize, 0);

    let image_size = align_up(record_log_off + record_log_len, GOES_BLOCK_SIZE);

    eprintln!(
        "[xtask] goes: layout: size={:#x} super={:#x} chk={:#x} manifest={:#x} bootmanifest={:#x} record_log={:#x} record_len={:#x} x86_off={:#x} x86_len={:#x} aa_off={:#x} aa_len={:#x}",
        image_size,
        super_off,
        checkpoint_off,
        manifest_off,
        boot_manifest_off,
        record_log_off,
        record_log_len,
        kernel_x86_off,
        kernel_x86_len,
        kernel_aa_off,
        kernel_aa_len
    );

    let mut f = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    eprintln!("[xtask] goes: set_len {}", image_size);
    f.set_len(image_size)
        .with_context(|| format!("set_len {}", image_size))?;

    // superblock
    eprintln!("[xtask] goes: write superblock");
    f.seek(SeekFrom::Start(super_off))
        .context("seek superblock")?;
    let mut sb_block = vec![0u8; GOES_BLOCK_SIZE as usize];
    encode_goes_superblock_v01(
        &mut sb_block[..GOES_SB_HEADER_SIZE_V01 as usize],
        GoesSuperblockV01Fields {
            checkpoint_offset: checkpoint_off,
            manifest_offset: manifest_off,
            kernel_x86_offset: kernel_x86_off,
            kernel_x86_len,
            kernel_aa_offset: kernel_aa_off,
            kernel_aa_len,
            record_log_offset: record_log_off,
            record_log_len,
            flags,
            default_user,
        },
    );
    f.write_all(&sb_block).context("write superblock")?;

    // checkpoint: points to bootmanifest (active_set switch)
    eprintln!("[xtask] goes: write checkpoint");
    f.seek(SeekFrom::Start(checkpoint_off))
        .context("seek checkpoint")?;
    let mut checkpoint_block = vec![0u8; GOES_BLOCK_SIZE as usize];
    encode_goes_checkpoint_v01(
        &mut checkpoint_block,
        GoesCheckpointV01Fields {
            seq: 1,
            boot_manifest_offset: boot_manifest_off,
        },
    );
    f.write_all(&checkpoint_block).context("write checkpoint")?;

    // manifest (structured)
    eprintln!("[xtask] goes: write manifest");
    f.seek(SeekFrom::Start(manifest_off))
        .context("seek manifest")?;
    f.write_all(&manifest_block).context("write manifest")?;

    // bootmanifest (active_set switch)
    eprintln!("[xtask] goes: write bootmanifest");
    f.seek(SeekFrom::Start(boot_manifest_off))
        .context("seek bootmanifest")?;
    f.write_all(&boot_manifest_block)
        .context("write bootmanifest")?;

    // blobs
    eprintln!("[xtask] goes: write x86 blob");
    f.seek(SeekFrom::Start(kernel_x86_off))
        .context("seek x86 blob")?;
    f.write_all(&x86).context("write x86 blob")?;
    if kernel_x86_len > kernel_x86_blob_len {
        // 尾部 padding 保持为 0，避免残留旧数据（也让 slot 可安全复用）。
        // 文件新建 + set_len 后未写区域按读取语义就是 0，这里只做显式覆盖以防未来改成复用文件。
        let pad = kernel_x86_len - kernel_x86_blob_len;
        let zeros = [0u8; 4096];
        let mut left = pad;
        while left > 0 {
            let take = (left as usize).min(zeros.len());
            f.write_all(&zeros[..take]).context("write x86 padding")?;
            left -= take as u64;
        }
    }
    eprintln!("[xtask] goes: write aarch64 blob");
    f.seek(SeekFrom::Start(kernel_aa_off))
        .context("seek aarch64 blob")?;
    f.write_all(&aa).context("write aarch64 blob")?;
    if kernel_aa_len > kernel_aa_blob_len {
        let pad = kernel_aa_len - kernel_aa_blob_len;
        let zeros = [0u8; 4096];
        let mut left = pad;
        while left > 0 {
            let take = (left as usize).min(zeros.len());
            f.write_all(&zeros[..take])
                .context("write aarch64 padding")?;
            left -= take as u64;
        }
    }

    // record log
    eprintln!("[xtask] goes: write record log");
    f.seek(SeekFrom::Start(record_log_off))
        .context("seek record log")?;
    f.write_all(&record_log).context("write record log")?;

    eprintln!("[xtask] goes: flush");
    f.flush().ok();
    Ok(())
}

fn parse_goes_superblock_v01(buf: &[u8]) -> Option<GoesSuperblockV01Fields> {
    if buf.len() < GOES_SB_HEADER_SIZE_V01 as usize {
        return None;
    }
    if &buf[0..4] != b"GOES" {
        return None;
    }
    let version = get_u32_le(buf, 0x04)?;
    if version != 1 {
        return None;
    }
    let stored_crc = get_u32_le(buf, 0x68).unwrap_or(0);
    if stored_crc != 0 {
        let calc = crc32_ieee_with_zeroed_range(&buf[..GOES_SB_HEADER_SIZE_V01 as usize], 0x68, 4);
        if calc != stored_crc {
            return None;
        }
    }
    let checkpoint_offset = get_u64_le(buf, 0x18)?;
    let manifest_offset = get_u64_le(buf, 0x20)?;
    let kernel_x86_offset = get_u64_le(buf, 0x28)?;
    let kernel_x86_len = get_u64_le(buf, 0x30)?;
    let kernel_aa_offset = get_u64_le(buf, 0x38)?;
    let kernel_aa_len = get_u64_le(buf, 0x40)?;
    let record_log_offset = get_u64_le(buf, 0x70).unwrap_or(0);
    let record_log_len = get_u64_le(buf, 0x78).unwrap_or(0);
    let flags = get_u32_le(buf, 0x10)?;
    let mut default_user = [0u8; 32];
    default_user.copy_from_slice(buf.get(0x48..0x48 + 32)?);
    Some(GoesSuperblockV01Fields {
        checkpoint_offset,
        manifest_offset,
        kernel_x86_offset,
        kernel_x86_len,
        kernel_aa_offset,
        kernel_aa_len,
        record_log_offset,
        record_log_len,
        flags,
        default_user,
    })
}

fn parse_goes_checkpoint_v01(buf: &[u8]) -> Option<GoesCheckpointV01Fields> {
    if buf.len() < 0x20 {
        return None;
    }
    if &buf[0..4] != GOES_CHECKPOINT_MAGIC_V01 {
        return None;
    }
    let version = get_u32_le(buf, 0x04)?;
    if version != 1 {
        return None;
    }
    let stored_crc = get_u32_le(buf, 0x20).unwrap_or(0);
    if stored_crc != 0 {
        let calc = crc32_ieee_with_zeroed_range(buf, 0x20, 4);
        if calc != stored_crc {
            return None;
        }
    }
    let seq = get_u64_le(buf, 0x10)?;
    let boot_manifest_offset = get_u64_le(buf, 0x18)?;
    Some(GoesCheckpointV01Fields {
        seq,
        boot_manifest_offset,
    })
}

fn parse_goes_boot_manifest_header_v01(buf: &[u8]) -> Option<(u32, u64, u32, u32, [u8; 32])> {
    if buf.len() < 0x60 {
        return None;
    }
    if &buf[0..4] != GOES_BOOT_MANIFEST_MAGIC_V01 {
        return None;
    }
    let version = get_u32_le(buf, 0x04)?;
    if version != 1 {
        return None;
    }
    let stored_crc = get_u32_le(buf, 0x48).unwrap_or(0);
    if stored_crc != 0 {
        let calc = crc32_ieee_with_zeroed_range(buf, 0x48, 4);
        if calc != stored_crc {
            return None;
        }
    }
    let flags = get_u32_le(buf, 0x0c)?;
    let seq = get_u64_le(buf, 0x10)?;
    let active_set = get_u32_le(buf, 0x18)?;
    let set_count = get_u32_le(buf, 0x1c)?;
    let mut default_user = [0u8; 32];
    default_user.copy_from_slice(buf.get(0x20..0x20 + 32)?);
    Some((flags, seq, active_set, set_count, default_user))
}

fn goes_show(img: &Path) -> Result<()> {
    let mut f = fs::File::open(img).with_context(|| format!("open {}", img.display()))?;
    let mut sb = vec![0u8; GOES_BLOCK_SIZE as usize];
    f.read_exact(&mut sb).context("read superblock")?;
    let Some(sb_fields) = parse_goes_superblock_v01(&sb) else {
        anyhow::bail!("invalid GOES superblock");
    };
    f.seek(SeekFrom::Start(sb_fields.checkpoint_offset))
        .context("seek checkpoint")?;
    let mut chk = vec![0u8; GOES_BLOCK_SIZE as usize];
    f.read_exact(&mut chk).context("read checkpoint")?;
    let Some(chk_fields) = parse_goes_checkpoint_v01(&chk) else {
        anyhow::bail!("invalid GOES checkpoint");
    };
    f.seek(SeekFrom::Start(chk_fields.boot_manifest_offset))
        .context("seek bootmanifest")?;
    let mut bm = vec![0u8; GOES_BOOT_MANIFEST_BLOCK_SIZE];
    f.read_exact(&mut bm).context("read bootmanifest")?;
    let Some((_flags, bm_seq, active_set, set_count, _du)) =
        parse_goes_boot_manifest_header_v01(&bm)
    else {
        anyhow::bail!("invalid GOES bootmanifest");
    };
    let sip_on = (sb_fields.flags & GOES_FLAG_SIP_ON) != 0;
    println!(
        "GOES: checkpoint_seq={} bootmanifest_off={:#x} bootmanifest_seq={} active_set={} set_count={} record_log_off={:#x} record_log_len={:#x}",
        chk_fields.seq,
        chk_fields.boot_manifest_offset,
        bm_seq,
        active_set,
        set_count,
        sb_fields.record_log_offset,
        sb_fields.record_log_len
    );
    println!(
        "GOES: flags=0x{:x} (admin={}, sip={})",
        sb_fields.flags,
        (sb_fields.flags & GOES_FLAG_ADMIN) != 0,
        if sip_on { "on" } else { "off" }
    );

    if sb_fields.record_log_offset != 0 && sb_fields.record_log_len != 0 {
        let mut buf = vec![0u8; sb_fields.record_log_len as usize];
        f.seek(SeekFrom::Start(sb_fields.record_log_offset))
            .context("seek record log")?;
        f.read_exact(&mut buf).context("read record log")?;
        // Best-effort scan records (header+payload, 8-byte aligned).
        let mut off = 0usize;
        let mut count = 0u32;
        while off + 32 <= buf.len() {
            if &buf[off..off + 4] != GOES_RECORD_MAGIC_V01 {
                break;
            }
            let version = u16::from_le_bytes(buf[off + 4..off + 6].try_into().unwrap_or([0, 0]));
            if version != 1 {
                break;
            }
            let record_type = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
            let payload_len =
                u32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap()) as usize;
            let seq = u64::from_le_bytes(buf[off + 16..off + 24].try_into().unwrap());
            let end = off + 32 + payload_len;
            if end > buf.len() {
                break;
            }
            println!(
                "  record#{count}: type={} seq={} len={}",
                record_type, seq, payload_len
            );
            count += 1;
            off = align_up_usize(end, 8);
        }
    }
    Ok(())
}

fn goes_set_active(img: &Path, set: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(img)
        .with_context(|| format!("open {}", img.display()))?;

    let mut sb = vec![0u8; GOES_BLOCK_SIZE as usize];
    f.read_exact(&mut sb).context("read superblock")?;
    let Some(sb_fields) = parse_goes_superblock_v01(&sb) else {
        anyhow::bail!("invalid GOES superblock");
    };

    f.seek(SeekFrom::Start(sb_fields.checkpoint_offset))
        .context("seek checkpoint")?;
    let mut chk = vec![0u8; GOES_BLOCK_SIZE as usize];
    f.read_exact(&mut chk).context("read checkpoint")?;
    let Some(mut chk_fields) = parse_goes_checkpoint_v01(&chk) else {
        anyhow::bail!("invalid GOES checkpoint");
    };

    f.seek(SeekFrom::Start(chk_fields.boot_manifest_offset))
        .context("seek bootmanifest")?;
    let mut bm = vec![0u8; GOES_BOOT_MANIFEST_BLOCK_SIZE];
    f.read_exact(&mut bm).context("read bootmanifest")?;

    let Some((flags, bm_seq, _active_set, set_count, default_user)) =
        parse_goes_boot_manifest_header_v01(&bm)
    else {
        anyhow::bail!("invalid GOES bootmanifest");
    };
    if set >= set_count {
        anyhow::bail!("set out of range: set={} set_count={}", set, set_count);
    }

    let new_bm_seq = bm_seq.wrapping_add(1);
    put_u64_le(&mut bm, 0x10, new_bm_seq);
    put_u32_le(&mut bm, 0x18, set);
    // Recompute bootmanifest crc (0x48) over full block.
    put_u32_le(&mut bm, 0x48, 0);
    let bm_crc = crc32_ieee_with_zeroed_range(&bm, 0x48, 4);
    put_u32_le(&mut bm, 0x48, bm_crc);

    chk_fields.seq = chk_fields.seq.wrapping_add(1);
    encode_goes_checkpoint_v01(&mut chk, chk_fields);

    f.seek(SeekFrom::Start(sb_fields.checkpoint_offset))
        .context("seek checkpoint (write)")?;
    f.write_all(&chk).context("write checkpoint")?;
    f.seek(SeekFrom::Start(chk_fields.boot_manifest_offset))
        .context("seek bootmanifest (write)")?;
    f.write_all(&bm).context("write bootmanifest")?;
    f.flush().ok();

    let user = core::str::from_utf8(&default_user)
        .ok()
        .unwrap_or("<non-utf8>")
        .trim_end_matches('\0');
    println!(
        "GOES: active_set -> {} (bootmanifest_seq={} checkpoint_seq={}, admin={}, default_user={})",
        set,
        new_bm_seq,
        chk_fields.seq,
        (flags & 1) != 0,
        user
    );
    Ok(())
}

fn goes_set_sip(img: &Path, sip_on: bool, recovery: bool) -> Result<()> {
    if !recovery {
        anyhow::bail!("refusing to change SIP in Normal Mode; re-run with `--recovery`");
    }
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(img)
        .with_context(|| format!("open {}", img.display()))?;

    // Read/parse superblock
    let mut sb_block = vec![0u8; GOES_BLOCK_SIZE as usize];
    f.read_exact(&mut sb_block).context("read superblock")?;
    let Some(sb_fields) = parse_goes_superblock_v01(&sb_block) else {
        anyhow::bail!("invalid GOES superblock");
    };

    // Update superblock flags (bit1 = sip_on) + crc
    let mut new_flags = sb_fields.flags;
    if sip_on {
        new_flags |= GOES_FLAG_SIP_ON;
    } else {
        new_flags &= !GOES_FLAG_SIP_ON;
    }
    put_u32_le(&mut sb_block, 0x10, new_flags);
    put_u32_le(&mut sb_block, 0x68, 0);
    let sb_crc =
        crc32_ieee_with_zeroed_range(&sb_block[..GOES_SB_HEADER_SIZE_V01 as usize], 0x68, 4);
    put_u32_le(&mut sb_block, 0x68, sb_crc);

    // Update manifest flags + crc (if present)
    if sb_fields.manifest_offset != 0 {
        f.seek(SeekFrom::Start(sb_fields.manifest_offset))
            .context("seek manifest")?;
        let mut m = vec![0u8; GOES_MANIFEST_BLOCK_SIZE];
        f.read_exact(&mut m).context("read manifest")?;
        if &m[0..4] == GOES_MANIFEST_MAGIC_V01 {
            put_u32_le(&mut m, 0x08, new_flags);
            put_u32_le(&mut m, 0x60, 0);
            let m_crc = crc32_ieee_with_zeroed_range(&m, 0x60, 4);
            put_u32_le(&mut m, 0x60, m_crc);
            f.seek(SeekFrom::Start(sb_fields.manifest_offset))
                .context("seek manifest (write)")?;
            f.write_all(&m).context("write manifest")?;
        }
    }

    // Read checkpoint -> bootmanifest
    f.seek(SeekFrom::Start(sb_fields.checkpoint_offset))
        .context("seek checkpoint")?;
    let mut chk = vec![0u8; GOES_BLOCK_SIZE as usize];
    f.read_exact(&mut chk).context("read checkpoint")?;
    let Some(mut chk_fields) = parse_goes_checkpoint_v01(&chk) else {
        anyhow::bail!("invalid GOES checkpoint");
    };

    f.seek(SeekFrom::Start(chk_fields.boot_manifest_offset))
        .context("seek bootmanifest")?;
    let mut bm = vec![0u8; GOES_BOOT_MANIFEST_BLOCK_SIZE];
    f.read_exact(&mut bm).context("read bootmanifest")?;
    let Some((_bm_flags, bm_seq, active_set, set_count, default_user)) =
        parse_goes_boot_manifest_header_v01(&bm)
    else {
        anyhow::bail!("invalid GOES bootmanifest");
    };

    // Update bootmanifest flags + seq + crc
    let new_bm_seq = bm_seq.wrapping_add(1);
    put_u32_le(&mut bm, 0x0c, new_flags);
    put_u64_le(&mut bm, 0x10, new_bm_seq);
    put_u32_le(&mut bm, 0x48, 0);
    let bm_crc = crc32_ieee_with_zeroed_range(&bm, 0x48, 4);
    put_u32_le(&mut bm, 0x48, bm_crc);

    // Update checkpoint seq + crc
    chk_fields.seq = chk_fields.seq.wrapping_add(1);
    encode_goes_checkpoint_v01(&mut chk, chk_fields);

    // Write back: superblock + checkpoint + bootmanifest
    f.seek(SeekFrom::Start(0))
        .context("seek superblock (write)")?;
    f.write_all(&sb_block).context("write superblock")?;
    f.seek(SeekFrom::Start(sb_fields.checkpoint_offset))
        .context("seek checkpoint (write)")?;
    f.write_all(&chk).context("write checkpoint")?;
    f.seek(SeekFrom::Start(chk_fields.boot_manifest_offset))
        .context("seek bootmanifest (write)")?;
    f.write_all(&bm).context("write bootmanifest")?;
    f.flush().ok();

    let user = core::str::from_utf8(&default_user)
        .ok()
        .unwrap_or("<non-utf8>")
        .trim_end_matches('\0');
    println!(
        "GOES: SIP {} (active_set={}/{}, default_user={})",
        if sip_on { "ON" } else { "OFF" },
        active_set,
        set_count,
        user
    );
    Ok(())
}

fn run_qemu(
    sh: &Shell,
    arch: Arch,
    firmware: Option<&Path>,
    vars: Option<&Path>,
    mem: &str,
    display: DisplayMode,
) -> Result<()> {
    let dist = sh.current_dir().join("dist");
    let esp = dist.join(format!("esp-{}", arch_name(arch)));
    if !esp.exists() {
        anyhow::bail!("ESP 目录不存在：{}，请先运行 xtask build", esp.display());
    }
    if matches!(arch, Arch::Aarch64) {
        warn_if_raw_kernel_stale(sh, &esp);
    }
    warn_if_goes_kernel_stale(sh, arch, &esp);

    match arch {
        Arch::X86_64 => run_qemu_x86(sh, &esp, firmware, vars, mem, display),
        Arch::Aarch64 => run_qemu_aarch64(sh, &esp, firmware, mem, display),
        Arch::All => unreachable!(),
    }
}

fn run_qemu_x86(
    sh: &Shell,
    esp: &Path,
    firmware: Option<&Path>,
    vars: Option<&Path>,
    mem: &str,
    display: DisplayMode,
) -> Result<()> {
    let bios = resolve_firmware_path(Arch::X86_64, firmware)?;
    let display_arg = display.qemu_arg();
    let dist = sh.current_dir().join("dist");
    let esp_img = dist.join("oneos-esp.img");
    let esp_drive = if esp_img.exists() {
        format!("format=raw,file={}", esp_img.display())
    } else {
        format!("format=raw,file=fat:rw:{}", esp.display())
    };
    // 选择 vars：用户提供且存在 > i386 fallback > 无
    let user_vars = vars.map(PathBuf::from);
    let chosen_vars = match user_vars {
        Some(v) if v.exists() => Some(v),
        Some(v) => {
            eprintln!(
                "[xtask] 提供的 vars 不存在：{}，尝试使用默认 fallback",
                v.display()
            );
            None
        }
        None => None,
    };

    let goes_img = dist.join("oneos-goes.img");
    let goes_drive = if goes_img.exists() {
        Some(goes_img)
    } else {
        None
    };

    if let Some(v) = chosen_vars {
        if let Some(goes) = &goes_drive {
            cmd!(
                sh,
                "qemu-system-x86_64 -machine q35 -m {mem} -serial stdio -monitor none -display {display_arg} -device virtio-keyboard-pci,bus=pcie.0,addr=0x5 -drive if=pflash,format=raw,readonly=on,file={bios} -drive if=pflash,format=raw,file={v} -drive {esp_drive} -drive file={goes},format=raw,if=virtio"
            )
            .run()
            .context("running qemu x86_64")?;
            return Ok(());
        }
        cmd!(
            sh,
            "qemu-system-x86_64 -machine q35 -m {mem} -serial stdio -monitor none -display {display_arg} -device virtio-keyboard-pci,bus=pcie.0,addr=0x5 -drive if=pflash,format=raw,readonly=on,file={bios} -drive if=pflash,format=raw,file={v} -drive {esp_drive}"
        )
        .run()
        .context("running qemu x86_64")?;
    } else {
        let fallback = resolve_vars_path(vars);
        if let Some(fallback) = fallback {
            eprintln!("[xtask] 使用 fallback vars: {}", fallback.display());
            if let Some(goes) = &goes_drive {
                cmd!(
                sh,
                "qemu-system-x86_64 -machine q35 -m {mem} -serial stdio -monitor none -display {display_arg} -device virtio-keyboard-pci,bus=pcie.0,addr=0x5 -drive if=pflash,format=raw,readonly=on,file={bios} -drive if=pflash,format=raw,file={fallback} -drive {esp_drive} -drive file={goes},format=raw,if=virtio"
            )
                .run()
                .context("running qemu x86_64 (fallback vars)")?;
                return Ok(());
            }
            cmd!(
                sh,
                "qemu-system-x86_64 -machine q35 -m {mem} -serial stdio -monitor none -display {display_arg} -device virtio-keyboard-pci,bus=pcie.0,addr=0x5 -drive if=pflash,format=raw,readonly=on,file={bios} -drive if=pflash,format=raw,file={fallback} -drive {esp_drive}"
            )
            .run()
            .context("running qemu x86_64 (fallback vars)")?;
        } else {
            eprintln!("[xtask] 未找到 vars，直接启动（固件会使用内置/临时变量）");
            if let Some(goes) = &goes_drive {
                cmd!(
                    sh,
                    "qemu-system-x86_64 -machine q35 -m {mem} -serial stdio -monitor none -display {display_arg} -device virtio-keyboard-pci,bus=pcie.0,addr=0x5 -drive if=pflash,format=raw,readonly=on,file={bios} -drive {esp_drive} -drive file={goes},format=raw,if=virtio"
                )
                .run()
                .context("running qemu x86_64 (no vars)")?;
                return Ok(());
            }
            cmd!(
                sh,
                "qemu-system-x86_64 -machine q35 -m {mem} -serial stdio -monitor none -display {display_arg} -device virtio-keyboard-pci,bus=pcie.0,addr=0x5 -drive if=pflash,format=raw,readonly=on,file={bios} -drive {esp_drive}"
            )
            .run()
            .context("running qemu x86_64 (no vars)")?;
        }
    }
    Ok(())
}

fn run_qemu_aarch64(
    sh: &Shell,
    esp: &Path,
    firmware: Option<&Path>,
    mem: &str,
    display: DisplayMode,
) -> Result<()> {
    let bios = resolve_firmware_path(Arch::Aarch64, firmware)?;
    let display_arg = display.qemu_arg();
    let dist = sh.current_dir().join("dist");
    let esp_img = dist.join("oneos-esp.img");
    let esp_drive = if esp_img.exists() {
        format!("format=raw,file={}", esp_img.display())
    } else {
        format!("format=raw,file=fat:rw:{}", esp.display())
    };

    let goes_img = dist.join("oneos-goes.img");
    if goes_img.exists() {
        cmd!(
            sh,
            "qemu-system-aarch64 -machine virt -cpu cortex-a72 -m {mem} -serial stdio -monitor none -display {display_arg} -bios {bios} -device ramfb -device virtio-keyboard-pci,bus=pcie.0,addr=0x5 -drive {esp_drive} -drive if=none,file={goes_img},format=raw,id=goes -device virtio-blk-pci,drive=goes,bus=pcie.0,addr=0x6"
        )
        .run()
        .context("running qemu aarch64")?;
    } else {
        cmd!(
            sh,
            "qemu-system-aarch64 -machine virt -cpu cortex-a72 -m {mem} -serial stdio -monitor none -display {display_arg} -bios {bios} -device ramfb -device virtio-keyboard-pci,bus=pcie.0,addr=0x5 -drive {esp_drive}"
        )
        .run()
        .context("running qemu aarch64")?;
    }
    Ok(())
}

fn arch_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "x86_64",
        Arch::Aarch64 => "aarch64",
        Arch::All => "all",
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum DisplayMode {
    #[value(name = "auto")]
    Auto,
    #[value(name = "headless")]
    Headless,
    #[value(name = "cocoa")]
    Cocoa,
    #[value(name = "sdl")]
    Sdl,
    #[value(name = "gtk")]
    Gtk,
}

impl DisplayMode {
    fn qemu_arg(self) -> &'static str {
        match self {
            DisplayMode::Auto => {
                if cfg!(target_os = "macos") {
                    "cocoa"
                } else if cfg!(target_os = "windows") {
                    "sdl"
                } else {
                    "gtk"
                }
            }
            DisplayMode::Headless => "none",
            DisplayMode::Cocoa => "cocoa",
            DisplayMode::Sdl => "sdl",
            DisplayMode::Gtk => "gtk",
        }
    }
}

fn resolve_firmware_path(arch: Arch, explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }

    let env_key = match arch {
        Arch::X86_64 => "ONEOS_EDK2_X86_64_CODE",
        Arch::Aarch64 => "ONEOS_EDK2_AARCH64_CODE",
        Arch::All => unreachable!(),
    };
    if let Some(v) = env::var_os(env_key) {
        let p = PathBuf::from(v);
        if p.exists() {
            return Ok(p);
        }
    }

    // macOS Homebrew 默认
    if cfg!(target_os = "macos") {
        let p = match arch {
            Arch::X86_64 => PathBuf::from("/opt/homebrew/share/qemu/edk2-x86_64-code.fd"),
            Arch::Aarch64 => PathBuf::from("/opt/homebrew/share/qemu/edk2-aarch64-code.fd"),
            Arch::All => unreachable!(),
        };
        if p.exists() {
            return Ok(p);
        }
    }

    anyhow::bail!(
        "未找到固件路径；请用 --firmware 指定或设置环境变量 {}",
        env_key
    )
}

fn resolve_vars_path(explicit: Option<&Path>) -> Option<PathBuf> {
    // 用户显式指定且存在 > env > macOS fallback
    if let Some(p) = explicit {
        if p.exists() {
            return Some(p.to_path_buf());
        }
        return None;
    }

    if let Some(v) = env::var_os("ONEOS_EDK2_X86_64_VARS") {
        let p = PathBuf::from(v);
        if p.exists() {
            return Some(p);
        }
    }

    if cfg!(target_os = "macos") {
        let p = PathBuf::from("/opt/homebrew/share/qemu/edk2-i386-vars.fd");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn warn_if_raw_kernel_stale(sh: &Shell, esp: &Path) {
    let project_root = sh.current_dir();
    let candidates = [
        project_root.join("target/aarch64-unknown-none-softfloat/debug/oneos-raw-aarch64"),
        project_root.join("target/aarch64-unknown-none-softfloat/release/oneos-raw-aarch64"),
    ];
    let src_path = candidates.iter().find(|p| p.exists());
    let Some(src_path) = src_path else {
        return;
    };
    let dist_path = esp.join("EFI/oneOS/KERNELAA64.BIN");
    if !dist_path.exists() {
        eprintln!(
            "[xtask] 警告：ESP 中缺少 raw kernel ({})，请重新运行 xtask build",
            dist_path.display()
        );
        return;
    }
    let src_meta = match fs::metadata(src_path) {
        Ok(m) => m,
        Err(_) => return,
    };
    let dst_meta = match fs::metadata(&dist_path) {
        Ok(m) => m,
        Err(_) => return,
    };
    let size_diff = src_meta.len() != dst_meta.len();
    let newer_src = match (src_meta.modified(), dst_meta.modified()) {
        (Ok(s), Ok(d)) => s > d,
        _ => false,
    };
    if size_diff || newer_src {
        eprintln!(
            "[xtask] 警告：raw kernel 可能未同步到 ESP。\n  构建产物: {} ({} bytes)\n  ESP 文件: {} ({} bytes)\n  请运行 `cargo run -p xtask -- build --arch aarch64` 重新复制。",
            src_path.display(),
            src_meta.len(),
            dist_path.display(),
            dst_meta.len()
        );
    }
}

fn warn_if_goes_kernel_stale(sh: &Shell, arch: Arch, esp: &Path) {
    let dist = sh.current_dir().join("dist");
    let goes_img = dist.join("oneos-goes.img");
    if !goes_img.exists() {
        return;
    }

    let expected = match arch {
        Arch::X86_64 => esp.join("EFI/oneOS/KERNELX64.BIN"),
        Arch::Aarch64 => esp.join("EFI/oneOS/KERNELAA64.BIN"),
        Arch::All => return,
    };
    if !expected.exists() {
        return;
    }

    let expected_bytes = match fs::read(&expected) {
        Ok(b) => b,
        Err(_) => return,
    };
    let expected_crc = crc32_ieee(&expected_bytes);

    let mut f = match fs::File::open(&goes_img) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut sb = vec![0u8; GOES_BLOCK_SIZE as usize];
    if f.read_exact(&mut sb).is_err() {
        return;
    }
    let Some(fields) = parse_goes_superblock_v01(&sb) else {
        return;
    };
    let (off, len) = match arch {
        Arch::X86_64 => (fields.kernel_x86_offset, fields.kernel_x86_len),
        Arch::Aarch64 => (fields.kernel_aa_offset, fields.kernel_aa_len),
        Arch::All => return,
    };
    if off == 0 || len == 0 {
        return;
    }

    // 注意：GOES 中的 `kernel_*_len` 现在被视为“slot 大小”（包含 padding），
    // 不一定等于 raw kernel 的精确长度；因此这里只比较与 ESP raw kernel 等长的前缀。
    let cmp_len = (len as usize).min(expected_bytes.len());
    let mut embedded = vec![0u8; cmp_len];
    if f.seek(SeekFrom::Start(off)).is_err() {
        return;
    }
    if f.read_exact(&mut embedded).is_err() {
        return;
    }
    let embedded_crc = crc32_ieee(&embedded);

    if cmp_len != expected_bytes.len() || embedded_crc != expected_crc {
        eprintln!(
            "[xtask] 警告：GOES 镜像中的内核与 ESP 中的 raw kernel 不一致，QEMU 启动会使用 GOES 内核，可能导致你看到旧的 shell 命令集。\n  GOES: {} (off={:#x}, len={:#x}, crc32=0x{:08x})\n  ESP:  {} (len={:#x}, crc32=0x{:08x})\n  解决：运行 `cargo run -p xtask -- install --recovery --sip-off`（如需 admin 再加 `--admin`）重新生成系统 GOES；或临时移走 dist/oneos-goes.img 让 bootloader 从 ESP 启动。",
            goes_img.display(),
            off,
            len,
            embedded_crc,
            expected.display(),
            expected_bytes.len(),
            expected_crc
        );
    }
}
