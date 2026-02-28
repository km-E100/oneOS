# oneOS

oneOS is an experimental operating system kernel written in Rust.

- ✅ UEFI-based boot
- ✅ AArch64 support (stable)
- ⚠️ x86_64 under active debugging (#UD investigation)
- 🔧 Custom GOES filesystem
- 🔄 BootState & Recovery mechanism implemented

---

## 🚀 Quick Start (Windows)

### 1️⃣ Install toolchain

```bash
rustup toolchain install nightly
rustup target add aarch64-unknown-uefi x86_64-unknown-uefi
2️⃣ Build
cargo run -p xtask -- build
3️⃣ Run (AArch64 recommended)
cargo run -p xtask -- run --arch aarch64 --display sdl --mem 1024
Optional: Run on x86_64
cargo run -p xtask -- run --arch x86_64 --display sdl --mem 1024

Make sure QEMU is installed and firmware paths are configured.
Windows uses --display sdl.

📦 Project Structure
kernel/          Core kernel
bootloader/      UEFI bootloader
applications/    User programs
xtask/           Build & run automation
dist/            Generated ESP & GOES images
🧠 Architecture Overview

UEFI bootloader loads raw kernel image

Dual architecture support (AArch64 / x86_64)

Custom GOES filesystem for system partition

BootState mechanism:

Consecutive failure tracking

Panic ring buffer

One-boot recovery flags

SIP state mirroring via ESP

🔄 Recovery & ESP Control

Advanced boot and recovery commands are documented in:

docs/boot-and-recovery.md

Includes:

Force recovery mode

Set failure counters

Record panic entries

Toggle SIP mirror state

📷 Example Output

(Insert your VGA / QEMU screenshot here)

📌 Current Status

 UEFI boot

 Dual-arch build system

 GOES filesystem image generation

 Recovery / BootState logic

 User domain isolation

 SMP support

 x86_64 #UD root cause resolution

🧪 x86_64 #UD Investigation

x86_64 currently triggers #UD when entering scheduler.

Tracked in:
👉 Issue #1 (RIP=0xA0078)

Contributions welcome.

🌊 Why oneOS?

This project is an exploration of:

Low-level OS architecture

UEFI boot flow

Filesystem design

Cross-architecture kernel design

Fault tracking & recovery strategy

It is not production-ready.
It is a learning and experimentation platform.

🤝 Contributing

Pull requests and issue reports are welcome.

If you're interested in:

x86_64 debugging

Scheduler design

Filesystem improvements

UEFI boot internals

Feel free to open a discussion.

License

MIT License
