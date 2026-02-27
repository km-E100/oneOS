#![cfg(target_os = "none")]

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

#[inline(always)]
pub fn init() -> u32 {
    0xFFFF_FFFF
}

#[inline(always)]
pub fn update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &b in bytes {
        let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ TABLE[idx];
    }
    crc
}

#[inline(always)]
pub fn finalize(crc: u32) -> u32 {
    !crc
}
