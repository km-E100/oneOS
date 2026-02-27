cargo run -p xtask -- build
cargo run -p xtask -- install --admin --recovery --sip-off
cargo run -p xtask -- run --arch aarch64 --firmware /opt/homebrew/share/qemu/edk2-aarch64-code.fd --display cocoa --mem 1024
cargo run -p xtask -- run --arch x86_64 --firmware /opt/homebrew/share/qemu/edk2-x86_64-code.fd --display cocoa --mem 1024