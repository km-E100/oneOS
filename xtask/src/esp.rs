use anyhow::{Context, Result};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const BYTES_PER_SECTOR: u16 = 512;
const SECTORS_PER_CLUSTER: u8 = 1;
const RESERVED_SECTORS: u16 = 32;
const NUM_FATS: u8 = 2;
const ROOT_CLUSTER: u32 = 2;
const FSINFO_SECTOR: u16 = 1;
const BACKUP_BOOT_SECTOR: u16 = 6;

// oneOS-specific fixed layout (kept stable so host tools can patch these files in-place).
const CLUSTER_EFI_DIR: u32 = 3;
const CLUSTER_BOOT_DIR: u32 = 4;
const CLUSTER_ONEOS_DIR: u32 = 5;
pub const CLUSTER_BOOTFLAG: u32 = 6;
pub const CLUSTER_BOOTSTAT: u32 = 7;
pub const CLUSTER_SIP: u32 = 8;
const FIRST_FILE_CLUSTER: u32 = 9;

pub fn create_esp_image_fat32(
    out_img: &Path,
    bootx64: &Path,
    bootaa64: &Path,
    size_mb: u64,
) -> Result<()> {
    let bootx = fs::read(bootx64).with_context(|| format!("read {}", bootx64.display()))?;
    let boota = fs::read(bootaa64).with_context(|| format!("read {}", bootaa64.display()))?;

    if out_img.exists() {
        fs::remove_file(out_img).with_context(|| format!("remove {}", out_img.display()))?;
    }

    let size_bytes = size_mb * 1024 * 1024;
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(out_img)
        .with_context(|| format!("create {}", out_img.display()))?;
    f.set_len(size_bytes)
        .with_context(|| format!("set_len {} bytes", size_bytes))?;

    let total_sectors = (size_bytes / BYTES_PER_SECTOR as u64) as u32;
    let sectors_per_fat = calc_sectors_per_fat(total_sectors);

    let fat1_lba = RESERVED_SECTORS as u32;
    let fat2_lba = fat1_lba + sectors_per_fat;
    let data_lba = fat2_lba + sectors_per_fat;

    // Cluster allocation plan (fixed, simple, contiguous):
    // 2 root
    // 3 EFI dir
    // 4 BOOT dir
    // 5 oneOS dir
    // 6 BOOTFLAG.BIN (fixed 512 bytes)
    // 7 BOOTSTAT.BIN (fixed 512 bytes)
    // 8 SIP.BIN (fixed 512 bytes, mirror of SIP state)
    // 9..  BOOTX64.EFI clusters
    // next BOOTAA64.EFI clusters
    let bootflag = default_bootflag();
    let bootstat = default_bootstat();
    let sip = default_sip();
    let mut next_cluster: u32 = FIRST_FILE_CLUSTER;
    let (bootx_first, bootx_clusters) = alloc_clusters(&bootx, &mut next_cluster)?;
    let (boota_first, boota_clusters) = alloc_clusters(&boota, &mut next_cluster)?;

    // Build FAT table in memory (FAT32 entries, little-endian).
    let fat_entries = (clusters_count(total_sectors, data_lba) + 2) as usize;
    let mut fat = vec![0u32; fat_entries];
    fat[0] = 0x0FFF_FFF8; // media descriptor
    fat[1] = 0x0FFF_FFFF;
    mark_eoc(&mut fat, ROOT_CLUSTER);
    mark_eoc(&mut fat, CLUSTER_EFI_DIR);
    mark_eoc(&mut fat, CLUSTER_BOOT_DIR);
    mark_eoc(&mut fat, CLUSTER_ONEOS_DIR);
    mark_eoc(&mut fat, CLUSTER_BOOTFLAG);
    mark_eoc(&mut fat, CLUSTER_BOOTSTAT);
    mark_eoc(&mut fat, CLUSTER_SIP);
    chain_file(&mut fat, bootx_first, bootx_clusters);
    chain_file(&mut fat, boota_first, boota_clusters);

    // Write reserved region (boot sector + FSInfo + backup boot sector).
    write_boot_sector(&mut f, total_sectors, sectors_per_fat, "oneOS ESP")?;
    write_fsinfo(&mut f, total_sectors)?;
    write_boot_sector_backup(&mut f)?;

    // Write FATs.
    write_fat(&mut f, fat1_lba, sectors_per_fat, &fat)?;
    write_fat(&mut f, fat2_lba, sectors_per_fat, &fat)?;

    // Directories.
    write_dir_root(&mut f, data_lba, ROOT_CLUSTER, CLUSTER_EFI_DIR)?;
    write_dir_efi(
        &mut f,
        data_lba,
        CLUSTER_EFI_DIR,
        ROOT_CLUSTER,
        CLUSTER_BOOT_DIR,
        CLUSTER_ONEOS_DIR,
    )?;
    write_dir_boot(
        &mut f,
        data_lba,
        CLUSTER_BOOT_DIR,
        CLUSTER_EFI_DIR,
        bootx_first,
        bootx.len() as u32,
        boota_first,
        boota.len() as u32,
    )?;
    write_dir_oneos(
        &mut f,
        data_lba,
        CLUSTER_ONEOS_DIR,
        CLUSTER_EFI_DIR,
        CLUSTER_BOOTFLAG,
        bootflag.len() as u32,
        CLUSTER_BOOTSTAT,
        bootstat.len() as u32,
        CLUSTER_SIP,
        sip.len() as u32,
    )?;

    // Files (contiguous clusters).
    write_file_clusters(&mut f, data_lba, CLUSTER_BOOTFLAG, &bootflag)?;
    write_file_clusters(&mut f, data_lba, CLUSTER_BOOTSTAT, &bootstat)?;
    write_file_clusters(&mut f, data_lba, CLUSTER_SIP, &sip)?;
    write_file_clusters(&mut f, data_lba, bootx_first, &bootx)?;
    write_file_clusters(&mut f, data_lba, boota_first, &boota)?;

    f.flush().ok();
    Ok(())
}

fn calc_sectors_per_fat(total_sectors: u32) -> u32 {
    // Iterate to converge FAT size.
    //
    // 对某些参数组合（例如 64MiB、1-sector/cluster）会出现 2-cycle 振荡：
    // spf = 1008 -> next = 1009 -> next = 1008 -> ...
    // 这里检测到振荡时取较大值，保证有足够空间容纳 FAT 表。
    let mut spf = 1u32;
    let mut prev = 0u32;
    for _ in 0..1024 {
        let data_sectors =
            total_sectors.saturating_sub(RESERVED_SECTORS as u32 + (NUM_FATS as u32) * spf);
        let clusters = data_sectors / SECTORS_PER_CLUSTER as u32;
        let needed_bytes = (clusters + 2) * 4;
        let next = (needed_bytes + (BYTES_PER_SECTOR as u32 - 1)) / BYTES_PER_SECTOR as u32;

        if next == spf {
            return spf.max(1);
        }

        // 2-cycle oscillation: spf -> next, prev -> spf, and next == prev
        if next == prev {
            return spf.max(next).max(1);
        }

        prev = spf;
        spf = next.max(1);
    }

    // Fallback: return something safe.
    spf.max(1)
}

fn clusters_count(total_sectors: u32, data_lba: u32) -> u32 {
    let data_sectors = total_sectors.saturating_sub(data_lba);
    data_sectors / SECTORS_PER_CLUSTER as u32
}

fn alloc_clusters(data: &[u8], next: &mut u32) -> Result<(u32, u32)> {
    let bytes_per_cluster = BYTES_PER_SECTOR as usize * SECTORS_PER_CLUSTER as usize;
    let clusters = ((data.len() + bytes_per_cluster - 1) / bytes_per_cluster).max(1) as u32;
    let first = *next;
    *next = next.checked_add(clusters).context("cluster overflow")?;
    Ok((first, clusters))
}

fn mark_eoc(fat: &mut [u32], cluster: u32) {
    let idx = cluster as usize;
    if idx < fat.len() {
        fat[idx] = 0x0FFF_FFFF;
    }
}

fn chain_file(fat: &mut [u32], first: u32, clusters: u32) {
    for i in 0..clusters {
        let c = first + i;
        let idx = c as usize;
        if idx >= fat.len() {
            break;
        }
        if i + 1 == clusters {
            fat[idx] = 0x0FFF_FFFF;
        } else {
            fat[idx] = c + 1;
        }
    }
}

fn write_boot_sector(
    f: &mut fs::File,
    total_sectors: u32,
    sectors_per_fat: u32,
    label: &str,
) -> Result<()> {
    let mut bs = [0u8; 512];
    bs[0] = 0xEB;
    bs[1] = 0x58;
    bs[2] = 0x90;
    bs[3..11].copy_from_slice(b"MSWIN4.1");
    bs[11..13].copy_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
    bs[13] = SECTORS_PER_CLUSTER;
    bs[14..16].copy_from_slice(&RESERVED_SECTORS.to_le_bytes());
    bs[16] = NUM_FATS;
    bs[17..19].copy_from_slice(&0u16.to_le_bytes()); // root entries (FAT32 = 0)
    bs[19..21].copy_from_slice(&0u16.to_le_bytes()); // totsec16
    bs[21] = 0xF8; // fixed disk
    bs[22..24].copy_from_slice(&0u16.to_le_bytes()); // fatsz16
    bs[24..26].copy_from_slice(&63u16.to_le_bytes()); // sectors/track (dummy)
    bs[26..28].copy_from_slice(&255u16.to_le_bytes()); // heads (dummy)
    bs[28..32].copy_from_slice(&0u32.to_le_bytes()); // hidden sectors
    bs[32..36].copy_from_slice(&total_sectors.to_le_bytes());
    // FAT32 ext BPB
    bs[36..40].copy_from_slice(&sectors_per_fat.to_le_bytes());
    bs[40..42].copy_from_slice(&0u16.to_le_bytes()); // ext flags
    bs[42..44].copy_from_slice(&0u16.to_le_bytes()); // fsver
    bs[44..48].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
    bs[48..50].copy_from_slice(&FSINFO_SECTOR.to_le_bytes());
    bs[50..52].copy_from_slice(&BACKUP_BOOT_SECTOR.to_le_bytes());
    // reserved[12] zero
    bs[64] = 0x80; // drive number
    bs[66] = 0x29; // boot signature
    bs[67..71].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // vol id
    let mut lab = [b' '; 11];
    let l = label.as_bytes();
    let n = l.len().min(lab.len());
    lab[..n].copy_from_slice(&l[..n]);
    bs[71..82].copy_from_slice(&lab);
    bs[82..90].copy_from_slice(b"FAT32   ");
    bs[510] = 0x55;
    bs[511] = 0xAA;

    f.seek(SeekFrom::Start(0)).context("seek boot sector")?;
    f.write_all(&bs).context("write boot sector")?;

    // Zero the remaining reserved sectors (except those we write explicitly).
    let reserved_bytes = RESERVED_SECTORS as u64 * BYTES_PER_SECTOR as u64;
    let cur = f.stream_position().unwrap_or(0);
    if cur < reserved_bytes {
        let zero = vec![0u8; (reserved_bytes - cur) as usize];
        f.write_all(&zero).context("zero reserved")?;
    }

    Ok(())
}

fn write_boot_sector_backup(f: &mut fs::File) -> Result<()> {
    // Backup boot sector at BACKUP_BOOT_SECTOR.
    let lba = BACKUP_BOOT_SECTOR as u64;
    f.seek(SeekFrom::Start(lba * BYTES_PER_SECTOR as u64))
        .context("seek backup boot sector")?;
    let mut bs = [0u8; 512];
    f.seek(SeekFrom::Start(0))
        .context("seek primary boot sector")?;
    f.read_exact(&mut bs).context("read primary boot sector")?;
    f.seek(SeekFrom::Start(lba * BYTES_PER_SECTOR as u64))
        .context("seek backup boot sector (2)")?;
    f.write_all(&bs).context("write backup boot sector")?;
    Ok(())
}

fn write_fsinfo(f: &mut fs::File, _total_sectors: u32) -> Result<()> {
    let mut fsinfo = [0u8; 512];
    fsinfo[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    fsinfo[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    fsinfo[488..492].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // free clusters unknown
    fsinfo[492..496].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // next free unknown
    fsinfo[510] = 0x55;
    fsinfo[511] = 0xAA;
    f.seek(SeekFrom::Start(
        FSINFO_SECTOR as u64 * BYTES_PER_SECTOR as u64,
    ))
    .context("seek fsinfo")?;
    f.write_all(&fsinfo).context("write fsinfo")?;
    // Backup FSInfo at BACKUP_BOOT_SECTOR + 1 (common convention).
    f.seek(SeekFrom::Start(
        (BACKUP_BOOT_SECTOR as u64 + 1) * BYTES_PER_SECTOR as u64,
    ))
    .context("seek backup fsinfo")?;
    f.write_all(&fsinfo).context("write backup fsinfo")?;
    Ok(())
}

fn write_fat(f: &mut fs::File, fat_lba: u32, sectors_per_fat: u32, fat: &[u32]) -> Result<()> {
    let mut bytes = vec![0u8; (sectors_per_fat as usize) * (BYTES_PER_SECTOR as usize)];
    for (i, entry) in fat.iter().enumerate() {
        let off = i * 4;
        if off + 4 > bytes.len() {
            break;
        }
        bytes[off..off + 4].copy_from_slice(&entry.to_le_bytes());
    }
    f.seek(SeekFrom::Start(fat_lba as u64 * BYTES_PER_SECTOR as u64))
        .context("seek fat")?;
    f.write_all(&bytes).context("write fat")?;
    Ok(())
}

fn cluster_offset(data_lba: u32, cluster: u32) -> u64 {
    let cluster_index = cluster.saturating_sub(2) as u64;
    let lba = data_lba as u64 + cluster_index * SECTORS_PER_CLUSTER as u64;
    lba * BYTES_PER_SECTOR as u64
}

fn write_dir_root(f: &mut fs::File, data_lba: u32, root: u32, efi_cluster: u32) -> Result<()> {
    let mut buf = [0u8; 512];
    // EFI directory entry
    dir_entry_short(&mut buf[0..32], b"EFI     ", b"   ", 0x10, efi_cluster, 0);
    f.seek(SeekFrom::Start(cluster_offset(data_lba, root)))
        .context("seek root dir")?;
    f.write_all(&buf).context("write root dir")?;
    Ok(())
}

fn write_dir_efi(
    f: &mut fs::File,
    data_lba: u32,
    efi: u32,
    parent: u32,
    boot_cluster: u32,
    oneos_cluster: u32,
) -> Result<()> {
    let mut buf = [0u8; 512];
    // "." and ".."
    dir_entry_short(&mut buf[0..32], b".       ", b"   ", 0x10, efi, 0);
    dir_entry_short(&mut buf[32..64], b"..      ", b"   ", 0x10, parent, 0);
    // BOOT dir
    dir_entry_short(&mut buf[64..96], b"BOOT    ", b"   ", 0x10, boot_cluster, 0);
    // oneOS dir
    dir_entry_short(
        &mut buf[96..128],
        b"ONEOS   ",
        b"   ",
        0x10,
        oneos_cluster,
        0,
    );
    f.seek(SeekFrom::Start(cluster_offset(data_lba, efi)))
        .context("seek EFI dir")?;
    f.write_all(&buf).context("write EFI dir")?;
    Ok(())
}

fn write_dir_boot(
    f: &mut fs::File,
    data_lba: u32,
    boot: u32,
    parent: u32,
    bootx_first: u32,
    bootx_size: u32,
    boota_first: u32,
    boota_size: u32,
) -> Result<()> {
    let mut buf = [0u8; 512];
    dir_entry_short(&mut buf[0..32], b".       ", b"   ", 0x10, boot, 0);
    dir_entry_short(&mut buf[32..64], b"..      ", b"   ", 0x10, parent, 0);
    dir_entry_short(
        &mut buf[64..96],
        b"BOOTX64 ",
        b"EFI",
        0x20,
        bootx_first,
        bootx_size,
    );
    dir_entry_short(
        &mut buf[96..128],
        b"BOOTAA64",
        b"EFI",
        0x20,
        boota_first,
        boota_size,
    );
    f.seek(SeekFrom::Start(cluster_offset(data_lba, boot)))
        .context("seek BOOT dir")?;
    f.write_all(&buf).context("write BOOT dir")?;
    Ok(())
}

fn write_dir_oneos(
    f: &mut fs::File,
    data_lba: u32,
    oneos: u32,
    parent: u32,
    bootflag_cluster: u32,
    bootflag_size: u32,
    bootstat_cluster: u32,
    bootstat_size: u32,
    sip_cluster: u32,
    sip_size: u32,
) -> Result<()> {
    let mut buf = [0u8; 512];
    dir_entry_short(&mut buf[0..32], b".       ", b"   ", 0x10, oneos, 0);
    dir_entry_short(&mut buf[32..64], b"..      ", b"   ", 0x10, parent, 0);
    dir_entry_short(
        &mut buf[64..96],
        b"BOOTFLAG",
        b"BIN",
        0x20,
        bootflag_cluster,
        bootflag_size,
    );
    dir_entry_short(
        &mut buf[96..128],
        b"BOOTSTAT",
        b"BIN",
        0x20,
        bootstat_cluster,
        bootstat_size,
    );
    dir_entry_short(
        &mut buf[128..160],
        b"SIP     ",
        b"BIN",
        0x20,
        sip_cluster,
        sip_size,
    );
    f.seek(SeekFrom::Start(cluster_offset(data_lba, oneos)))
        .context("seek oneOS dir")?;
    f.write_all(&buf).context("write oneOS dir")?;
    Ok(())
}

fn dir_entry_short(
    dst: &mut [u8],
    name8: &[u8; 8],
    ext3: &[u8; 3],
    attr: u8,
    first_cluster: u32,
    size: u32,
) {
    dst.fill(0);
    dst[0..8].copy_from_slice(name8);
    dst[8..11].copy_from_slice(ext3);
    dst[11] = attr;
    let hi = ((first_cluster >> 16) & 0xFFFF) as u16;
    let lo = (first_cluster & 0xFFFF) as u16;
    dst[20..22].copy_from_slice(&hi.to_le_bytes());
    dst[26..28].copy_from_slice(&lo.to_le_bytes());
    dst[28..32].copy_from_slice(&size.to_le_bytes());
}

fn write_file_clusters(
    f: &mut fs::File,
    data_lba: u32,
    first_cluster: u32,
    data: &[u8],
) -> Result<()> {
    let bytes_per_cluster = BYTES_PER_SECTOR as usize * SECTORS_PER_CLUSTER as usize;
    let mut remaining = data;
    let mut cluster = first_cluster;
    while !remaining.is_empty() {
        let chunk_len = remaining.len().min(bytes_per_cluster);
        f.seek(SeekFrom::Start(cluster_offset(data_lba, cluster)))
            .context("seek file cluster")?;
        f.write_all(&remaining[..chunk_len])
            .context("write file cluster data")?;
        if chunk_len < bytes_per_cluster {
            let pad = vec![0u8; bytes_per_cluster - chunk_len];
            f.write_all(&pad).context("pad cluster")?;
        }
        remaining = &remaining[chunk_len..];
        cluster += 1;
    }
    Ok(())
}

pub fn read_bootflag_from_esp_image(esp_img: &Path) -> Result<[u8; 512]> {
    read_fixed_cluster_file(esp_img, CLUSTER_BOOTFLAG)
}

pub fn write_bootflag_to_esp_image(esp_img: &Path, bootflag: &[u8; 512]) -> Result<()> {
    write_fixed_cluster_file(esp_img, CLUSTER_BOOTFLAG, bootflag)
}

pub fn read_bootstat_from_esp_image(esp_img: &Path) -> Result<[u8; 512]> {
    read_fixed_cluster_file(esp_img, CLUSTER_BOOTSTAT)
}

pub fn write_bootstat_to_esp_image(esp_img: &Path, bootstat: &[u8; 512]) -> Result<()> {
    write_fixed_cluster_file(esp_img, CLUSTER_BOOTSTAT, bootstat)
}

pub fn read_sip_from_esp_image(esp_img: &Path) -> Result<[u8; 512]> {
    read_fixed_cluster_file(esp_img, CLUSTER_SIP)
}

pub fn write_sip_to_esp_image(esp_img: &Path, sip: &[u8; 512]) -> Result<()> {
    write_fixed_cluster_file(esp_img, CLUSTER_SIP, sip)
}

fn read_fixed_cluster_file(esp_img: &Path, cluster: u32) -> Result<[u8; 512]> {
    let mut f = OpenOptions::new()
        .read(true)
        .open(esp_img)
        .with_context(|| format!("open {}", esp_img.display()))?;
    let off = cluster_to_byte_offset(esp_img, cluster)?;
    f.seek(SeekFrom::Start(off))
        .with_context(|| format!("seek cluster {cluster}"))?;
    let mut buf = [0u8; 512];
    f.read_exact(&mut buf).context("read cluster")?;
    Ok(buf)
}

fn write_fixed_cluster_file(esp_img: &Path, cluster: u32, data: &[u8; 512]) -> Result<()> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(esp_img)
        .with_context(|| format!("open {}", esp_img.display()))?;
    let off = cluster_to_byte_offset(esp_img, cluster)?;
    f.seek(SeekFrom::Start(off))
        .with_context(|| format!("seek cluster {cluster}"))?;
    f.write_all(data).context("write cluster")?;
    f.flush().ok();
    Ok(())
}

fn cluster_to_byte_offset(esp_img: &Path, cluster: u32) -> Result<u64> {
    let size_bytes = fs::metadata(esp_img)
        .with_context(|| format!("metadata {}", esp_img.display()))?
        .len();
    let total_sectors = (size_bytes / BYTES_PER_SECTOR as u64) as u32;
    let sectors_per_fat = calc_sectors_per_fat(total_sectors);
    let data_lba = (RESERVED_SECTORS as u32) + (NUM_FATS as u32) * sectors_per_fat;
    let lba = data_lba + (cluster.saturating_sub(2)) * (SECTORS_PER_CLUSTER as u32);
    Ok(lba as u64 * BYTES_PER_SECTOR as u64)
}

fn default_bootflag() -> Vec<u8> {
    // 512 bytes fixed.
    // 0x00: "OBFL"
    // 0x04: version u32 = 1
    // 0x08: flags u32 (bit0=force_recovery, bit1=mark_success, bit2=mmu_strict_off)
    // 0x0c: reserved u32
    // 0x10: crc32 u32 (over full 512 with this field zeroed)
    let mut buf = [0u8; 512];
    buf[0..4].copy_from_slice(b"OBFL");
    buf[4..8].copy_from_slice(&1u32.to_le_bytes());
    buf[8..12].copy_from_slice(&0u32.to_le_bytes());
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());
    buf[16..20].copy_from_slice(&0u32.to_le_bytes());
    let crc = crc32_ieee(&buf, 16, 4);
    buf[16..20].copy_from_slice(&crc.to_le_bytes());
    buf.to_vec()
}

fn default_bootstat() -> Vec<u8> {
    // 512 bytes fixed.
    // 0x00: "OBST"
    // 0x04: version u32 = 1
    // 0x08: consecutive_failures u32
    // 0x0c: reserved u32
    // 0x10: last_boot_id u64
    // 0x18: last_panic_code u32
    // 0x1c: reserved u32
    // 0x20: crc32 u32 (over full 512 with this field zeroed)
    let mut buf = [0u8; 512];
    buf[0..4].copy_from_slice(b"OBST");
    buf[4..8].copy_from_slice(&1u32.to_le_bytes());
    buf[8..12].copy_from_slice(&0u32.to_le_bytes());
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());
    buf[16..24].copy_from_slice(&0u64.to_le_bytes());
    buf[24..28].copy_from_slice(&0u32.to_le_bytes());
    buf[28..32].copy_from_slice(&0u32.to_le_bytes());
    buf[32..36].copy_from_slice(&0u32.to_le_bytes());
    let crc = crc32_ieee(&buf, 32, 4);
    buf[32..36].copy_from_slice(&crc.to_le_bytes());
    buf.to_vec()
}

fn default_sip() -> Vec<u8> {
    // 512 bytes fixed.
    // 0x00: "OSIP"
    // 0x04: version u32 = 1
    // 0x08: sip_on u32 (1=on,0=off)
    // 0x0c: crc32 u32 (over full 512 with this field zeroed)
    let mut buf = [0u8; 512];
    buf[0..4].copy_from_slice(b"OSIP");
    buf[4..8].copy_from_slice(&1u32.to_le_bytes());
    buf[8..12].copy_from_slice(&1u32.to_le_bytes());
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());
    let crc = crc32_ieee(&buf, 12, 4);
    buf[12..16].copy_from_slice(&crc.to_le_bytes());
    buf.to_vec()
}

fn crc32_ieee(buf: &[u8], zero_off: usize, zero_len: usize) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for (i, &b) in buf.iter().enumerate() {
        let byte = if i >= zero_off && i < zero_off + zero_len {
            0
        } else {
            b
        };
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320u32 & mask);
        }
    }
    !crc
}
