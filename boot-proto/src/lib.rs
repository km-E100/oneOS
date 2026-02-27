#![no_std]

use core::mem;

pub mod crc32 {
    // IEEE CRC32 (polynomial 0xEDB88320), little-endian, init=0xFFFF_FFFF, xorout=0xFFFF_FFFF.
    const fn make_table() -> [u32; 256] {
        let mut table = [0u32; 256];
        let mut i = 0usize;
        while i < 256 {
            let mut crc = i as u32;
            let mut j = 0usize;
            while j < 8 {
                if (crc & 1) != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
                j += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    }

    const TABLE: [u32; 256] = make_table();

    pub fn crc32_ieee(bytes: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &b in bytes {
            let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
            crc = (crc >> 8) ^ TABLE[idx];
        }
        !crc
    }

    pub fn crc32_ieee_with_zeroed_range(bytes: &[u8], zero_start: usize, zero_len: usize) -> u32 {
        let zero_end = zero_start.saturating_add(zero_len);
        let mut crc: u32 = 0xFFFF_FFFF;
        for (i, &b) in bytes.iter().enumerate() {
            let v = if i >= zero_start && i < zero_end {
                0u8
            } else {
                b
            };
            let idx = ((crc ^ (v as u32)) & 0xFF) as usize;
            crc = (crc >> 8) ^ TABLE[idx];
        }
        !crc
    }
}

/// 描述引导阶段获取到的帧缓冲信息。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FrameBufferInfo {
    pub base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: FrameBufferFormat,
}

impl FrameBufferInfo {
    pub const fn new(
        base: u64,
        size: u64,
        width: u32,
        height: u32,
        stride: u32,
        format: FrameBufferFormat,
    ) -> Self {
        Self {
            base,
            size,
            width,
            height,
            stride,
            format,
        }
    }

    pub const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            width: 0,
            height: 0,
            stride: 0,
            format: FrameBufferFormat::Unknown,
        }
    }
}

/// 枚举帧缓冲像素格式（当前支持 RGB/BGR）。
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameBufferFormat {
    Rgb = 0,
    Bgr = 1,
    Unknown = 0xFFFF_FFFF,
}

impl Default for FrameBufferFormat {
    fn default() -> Self {
        FrameBufferFormat::Unknown
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryRegions {
    pub ptr: u64,
    pub len: u32,
    pub entry_size: u32,
}

impl MemoryRegions {
    pub const fn empty() -> Self {
        Self {
            ptr: 0,
            len: 0,
            entry_size: 0,
        }
    }

    pub const fn from_raw(ptr: u64, len: u32) -> Self {
        Self {
            ptr,
            len,
            entry_size: mem::size_of::<MemoryRegion>() as u32,
        }
    }

    pub const fn ptr(&self) -> u64 {
        self.ptr
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.ptr == 0 || self.len == 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryRegion {
    pub base: u64,
    pub length: u64,
    pub region_type: MemoryRegionType,
    pub attributes: u64,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryRegionType {
    Reserved = 0,
    LoaderCode = 1,
    LoaderData = 2,
    BootServicesCode = 3,
    BootServicesData = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    Conventional = 7,
    Unusable = 8,
    AcpiReclaim = 9,
    AcpiNvs = 10,
    Mmio = 11,
    MmioPortSpace = 12,
    PalCode = 13,
    PersistentMemory = 14,
    Unknown = 0xFFFF_FFFF,
}

impl Default for MemoryRegionType {
    fn default() -> Self {
        MemoryRegionType::Unknown
    }
}

/// Bootloader 传给内核的启动信息。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootInfo {
    framebuffer: FrameBufferInfo,
    framebuffer_present: u32,
    memory_regions: MemoryRegions,
    goes_present: u32,
    goes_flags: u32,
    goes_default_user: [u8; 32],
    boot_mode: u32,
    /// GOES 所在块设备标识。
    ///
    /// v1(raw 内核)：约定为 PCI BDF 编码：`(bus << 16) | (device << 8) | function`。
    /// - bus/device/function 均为 u8
    /// - 目前 oneOS 在 QEMU/virt 上假设 bus=0（单 root bus）；真实多 bus 后续扩展
    ///
    /// 若 bootloader 无法从设备路径解析 PCI 信息，该字段可能为 0。
    goes_device_id: u32,
    goes_superblock_lba: u64,
    goes_system_ws_id: u64,
    /// MMU isolation strict mode.
    ///
    /// v2/v3: when enabled, the kernel will default to switching into per-domain address spaces
    /// (TTBR0/CR3) and treating missing/failed page tables as a hard error for `app run`.
    ///
    /// This is a *debuggable* policy knob, not a security boundary.
    mmu_strict: u32,
}

impl BootInfo {
    /// 将 PCI BDF 编码为 u32：`(bus << 16) | (device << 8) | function`。
    pub const fn pci_bdf(bus: u8, device: u8, function: u8) -> u32 {
        ((bus as u32) << 16) | ((device as u32) << 8) | (function as u32)
    }

    /// 从 u32 解码 PCI BDF：返回 (bus, device, function)。
    pub const fn pci_bdf_decode(id: u32) -> (u8, u8, u8) {
        (
            ((id >> 16) & 0xff) as u8,
            ((id >> 8) & 0xff) as u8,
            (id & 0xff) as u8,
        )
    }

    pub const fn empty() -> Self {
        Self {
            framebuffer: FrameBufferInfo::empty(),
            framebuffer_present: 0,
            memory_regions: MemoryRegions::empty(),
            goes_present: 0,
            goes_flags: 0,
            goes_default_user: [0u8; 32],
            boot_mode: 0,
            goes_device_id: 0,
            goes_superblock_lba: 0,
            goes_system_ws_id: 0,
            mmu_strict: 1,
        }
    }

    pub const fn from_parts(
        framebuffer: Option<FrameBufferInfo>,
        memory_regions: MemoryRegions,
    ) -> Self {
        if let Some(fb) = framebuffer {
            Self {
                framebuffer: fb,
                framebuffer_present: 1,
                memory_regions,
                goes_present: 0,
                goes_flags: 0,
                goes_default_user: [0u8; 32],
                boot_mode: 0,
                goes_device_id: 0,
                goes_superblock_lba: 0,
                goes_system_ws_id: 0,
                mmu_strict: 1,
            }
        } else {
            Self {
                framebuffer: FrameBufferInfo::empty(),
                framebuffer_present: 0,
                memory_regions,
                goes_present: 0,
                goes_flags: 0,
                goes_default_user: [0u8; 32],
                boot_mode: 0,
                goes_device_id: 0,
                goes_superblock_lba: 0,
                goes_system_ws_id: 0,
                mmu_strict: 1,
            }
        }
    }

    pub const fn framebuffer(&self) -> Option<&FrameBufferInfo> {
        if self.framebuffer_present != 0 {
            Some(&self.framebuffer)
        } else {
            None
        }
    }

    pub const fn memory_regions_raw(&self) -> Option<(*const MemoryRegion, usize)> {
        if self.memory_regions.is_empty() {
            None
        } else {
            Some((
                self.memory_regions.ptr as *const MemoryRegion,
                self.memory_regions.len(),
            ))
        }
    }

    pub fn set_goes(&mut self, flags: u32, default_user: &[u8; 32]) {
        self.goes_present = 1;
        self.goes_flags = flags;
        self.goes_default_user = *default_user;
    }

    pub fn set_goes_location(&mut self, device_id: u32, superblock_lba: u64, system_ws_id: u64) {
        self.goes_device_id = device_id;
        self.goes_superblock_lba = superblock_lba;
        self.goes_system_ws_id = system_ws_id;
    }

    pub fn set_recovery_mode(&mut self, recovery: bool) {
        self.boot_mode = if recovery { 1 } else { 0 };
    }

    pub fn set_mmu_strict(&mut self, strict: bool) {
        self.mmu_strict = if strict { 1 } else { 0 };
    }

    pub const fn mmu_strict(&self) -> bool {
        self.mmu_strict != 0
    }

    pub const fn is_recovery_mode(&self) -> bool {
        self.boot_mode != 0
    }

    pub const fn goes_present(&self) -> bool {
        self.goes_present != 0
    }

    pub const fn goes_flags(&self) -> Option<u32> {
        if self.goes_present() {
            Some(self.goes_flags)
        } else {
            None
        }
    }

    pub const fn goes_device_id(&self) -> Option<u32> {
        if self.goes_present() {
            Some(self.goes_device_id)
        } else {
            None
        }
    }

    pub const fn goes_superblock_lba(&self) -> Option<u64> {
        if self.goes_present() {
            Some(self.goes_superblock_lba)
        } else {
            None
        }
    }

    pub const fn goes_system_ws_id(&self) -> Option<u64> {
        if self.goes_present() {
            Some(self.goes_system_ws_id)
        } else {
            None
        }
    }

    pub const fn goes_default_user_raw(&self) -> Option<&[u8; 32]> {
        if self.goes_present() {
            Some(&self.goes_default_user)
        } else {
            None
        }
    }
}

impl Default for BootInfo {
    fn default() -> Self {
        BootInfo::empty()
    }
}
