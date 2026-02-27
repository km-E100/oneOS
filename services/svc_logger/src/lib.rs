#![no_std]

mod ipc;
mod logger;

use oneos_service::ServiceApi;

// See `services/oneconsole/src/lib.rs` for why `no_mangle` is gated.
#[cfg_attr(not(feature = "kernel-builtin"), no_mangle)]
pub extern "C" fn oneos_service_main(api: *const ServiceApi) -> i32 {
    logger::run(api)
}
