use core::slice;

use oneos_boot_proto::{BootInfo, MemoryRegion};
use spin::Once;

static BOOT_INFO: Once<BootInfo> = Once::new();

/// UEFI 模式：从 UEFI load options 中解析 bootloader 传递的 BootInfo。
#[cfg(target_os = "uefi")]
pub fn init_from_load_options() -> Option<&'static BootInfo> {
    use core::{mem, ptr};
    use uefi::proto::loaded_image::LoadedImage;

    if let Some(info) = BOOT_INFO.get() {
        return Some(info);
    }

    let handle = uefi::boot::image_handle();
    let loaded = uefi::boot::open_protocol_exclusive::<LoadedImage>(handle).ok()?;
    let bytes = loaded.load_options_as_bytes()?;
    if bytes.len() < mem::size_of::<BootInfo>() {
        return None;
    }

    let info = unsafe { ptr::read_unaligned(bytes.as_ptr() as *const BootInfo) };
    Some(BOOT_INFO.call_once(|| info))
}

/// raw 模式：由 raw kernel 入口直接注入 BootInfo 指针（复制到静态存储）。
#[cfg(target_os = "none")]
pub fn init_raw(info: *const BootInfo) -> Option<&'static BootInfo> {
    if let Some(existing) = BOOT_INFO.get() {
        return Some(existing);
    }
    let info = unsafe { info.as_ref()? };
    Some(BOOT_INFO.call_once(|| *info))
}

pub fn get() -> Option<&'static BootInfo> {
    BOOT_INFO.get()
}

pub fn memory_regions() -> Option<&'static [MemoryRegion]> {
    let info = get()?;
    let (ptr, len) = info.memory_regions_raw()?;
    if len == 0 {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}
