#![no_std]

mod ipc;
mod ui;

use oneos_service::ServiceApi;

// When linked into the kernel as a normal Rust dependency, multiple services would otherwise
// export the same unmangled symbol name (`oneos_service_main`) and collide at link time.
// Keep the stable symbol only for standalone/service-binary builds.
#[cfg_attr(not(feature = "kernel-builtin"), no_mangle)]
pub extern "C" fn oneos_service_main(api: *const ServiceApi) -> i32 {
    ui::run(api)
}
