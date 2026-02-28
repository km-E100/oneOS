# oneOS

oneOS is an experimental operating system kernel written in Rust.

- ✅ UEFI boot
- ✅ AArch64 support (recommended)
- ⚠️ x86_64 under active debugging (#UD investigation)
- 🔧 Custom GOES filesystem
- 🔄 BootState & Recovery mechanism

---

# 🚀 Quick Start (Windows)

## 1️⃣ Install QEMU (Recommended Default Path)

Download and install QEMU for Windows:

https://www.qemu.org/download/

⚠️ Recommended installation path:

C:\Program Files\qemu\

Make sure firmware exists at:

C:\Program Files\qemu\share\edk2-aarch64-code.fd  
C:\Program Files\qemu\share\edk2-x86_64-code.fd  

---

## 2️⃣ Install Rust Nightly

```bash
rustup toolchain install nightly
rustup target add aarch64-unknown-uefi x86_64-unknown-uefi
3️⃣ Build
cargo run -p xtask -- build
4️⃣ Run (AArch64 Recommended)
cargo run -p xtask -- run --arch aarch64 --firmware "C:\Program Files\qemu\share\edk2-aarch64-code.fd" --display sdl --mem 4096
Optional: Run on x86_64
cargo run -p xtask -- run --arch x86_64 --firmware "C:\Program Files\qemu\share\edk2-x86_64-code.fd" --display sdl --mem 1024

If QEMU is installed in a different location, adjust the --firmware path accordingly.

📦 Project Structure
kernel/          Core kernel
bootloader/      UEFI bootloader
applications/    User programs
xtask/           Build & run automation
dist/            Generated ESP & GOES images
📌 Current Status

 Dual-architecture build

 UEFI boot

 GOES filesystem image generation

 Recovery / BootState logic

 User isolation

 SMP support

 x86_64 #UD root cause resolution

🧪 x86_64 Debugging

x86_64 currently triggers #UD when entering scheduler.
Tracked in Issue #1.

Contributions welcome.

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

build_and_run.txt

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
