use std::env;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let script_name = match target.as_str() {
        "aarch64-unknown-none-softfloat" => "aarch64-raw.ld",
        "x86_64-unknown-none" => "x86_64-raw.ld",
        _ => return,
    };

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let script = manifest_dir.join(script_name);

    println!(
        "cargo:rerun-if-changed={}",
        script.to_str().expect("linker script path must be UTF-8")
    );

    let script_abs = script.canonicalize().expect("canonicalize linker script");

    println!(
        "cargo:rustc-link-arg=-T{}",
        script_abs
            .to_str()
            .expect("canonical linker script path must be UTF-8")
    );
}
