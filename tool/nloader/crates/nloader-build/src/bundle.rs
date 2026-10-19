//! The release bundle: the programs a camera runs
//! with no card, and their defaults, placed in the firmware package.
//!
//! A bundle directory holds what a card's NLOADER directory would: programs
//! (`*.NLB`, each describing itself with an NPLD version 3 header, which is
//! how the loader knows what it is without a MANIFEST line) and, optionally,
//! `BOOT` and `ENABLED` in the card files' own formats. The bundle is the
//! layout core/include/nlr/platform.h describes (`NLBB`, version 1): a
//! 32-byte header, a 32-byte entry per file, then the files, each on a
//! 64-byte boundary.

use crate::{Error, Result};
use serde::Serialize;
use std::{fs, path::Path};

/// Files a bundle may hold (the loader's entry table bound).
pub const ENTRIES_MAX: usize = 64;
const HEADER: usize = 0x20;
const ENTRY: usize = 32;
const ALIGN: usize = 64;

/// One file of a built bundle, as the build report records it.
#[derive(Debug, Clone, Serialize)]
pub struct BundleEntry {
    pub name: String,
    pub offset: u32,
    pub bytes: u32,
    pub crc32: u32,
    pub sha256: String,
}

/// The bundle as it is placed: where, how much of its span it uses, and
/// each file.
#[derive(Debug, Clone, Serialize)]
pub struct BundleReport {
    pub address: u64,
    pub span: u32,
    pub bytes: u32,
    pub entries: Vec<BundleEntry>,
    /// Where the extended stock boot copy of the span's block now ends.
    pub copy_end: u64,
}

pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Object(message.into())
}

/// A name the loader can take: an 8.3 name of upper-case letters, digits
/// and `_-`, 1..=15 bytes.
fn valid_name(name: &str) -> bool {
    let (stem, ext) = name.split_once('.').unwrap_or((name, ""));
    let ok = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    };
    !name.is_empty()
        && name.len() < 16
        && !stem.is_empty()
        && stem.len() <= 8
        && ext.len() <= 3
        && ok(stem)
        && ok(ext)
}

/// A program the loader can list from the bundle: an NPLD header of
/// version 3 whose metadata block is whole and checks.
fn check_program(name: &str, bytes: &[u8]) -> Result<()> {
    let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    if bytes.len() < 64 || &bytes[..4] != b"NPLD" || u16::from_le_bytes([bytes[4], bytes[5]]) != 3 {
        return Err(invalid(format!(
            "{name}: a bundled program describes itself (NPLD header version 3, the \
             program .json's \"describe\": true)"
        )));
    }
    let meta = word(0x28) as usize;
    if meta == 0 || 64 + meta > bytes.len() || crc32(&bytes[64..64 + meta]) != word(0x2c) {
        return Err(invalid(format!(
            "{name}: its metadata block does not check"
        )));
    }
    Ok(())
}

/// The bundle's bytes from `dir`, files in name order.
pub fn build_bundle(dir: &Path) -> Result<(Vec<u8>, Vec<BundleEntry>)> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("a bundle file name is not UTF-8"))?;
        if name.starts_with('.') {
            continue;
        }
        if !valid_name(&name) {
            return Err(invalid(format!(
                "{name}: bundle files have 8.3 names of A-Z 0-9 _ -"
            )));
        }
        let bytes = fs::read(entry.path())?;
        if name.ends_with(".NLB") {
            check_program(&name, &bytes)?;
        } else if name != "BOOT" && name != "ENABLED" {
            return Err(invalid(format!(
                "{name}: a bundle holds programs (*.NLB), BOOT and ENABLED only"
            )));
        } else if bytes.len() > 4096 || !bytes.iter().all(|b| b.is_ascii()) {
            return Err(invalid(format!("{name}: ASCII text of at most 4096 bytes")));
        }
        files.push((name, bytes));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    if !files.iter().any(|(name, _)| name.ends_with(".NLB")) {
        return Err(invalid("a bundle holds at least one program"));
    }
    if files.len() > ENTRIES_MAX {
        return Err(invalid(format!("at most {ENTRIES_MAX} bundle files")));
    }
    let mut at = (HEADER + ENTRY * files.len()).div_ceil(ALIGN) * ALIGN;
    let mut table = Vec::new();
    let mut entries = Vec::new();
    let mut placed = Vec::new();
    for (name, bytes) in &files {
        let mut record = [0u8; ENTRY];
        record[..name.len()].copy_from_slice(name.as_bytes());
        let offset = u32::try_from(at).map_err(|_| invalid("bundle too large"))?;
        let size = u32::try_from(bytes.len()).map_err(|_| invalid("bundle file too large"))?;
        let crc = crc32(bytes);
        record[16..20].copy_from_slice(&offset.to_le_bytes());
        record[20..24].copy_from_slice(&size.to_le_bytes());
        record[24..28].copy_from_slice(&crc.to_le_bytes());
        table.extend_from_slice(&record);
        entries.push(BundleEntry {
            name: name.clone(),
            offset,
            bytes: size,
            crc32: crc,
            sha256: nloader_profile::sha256(bytes),
        });
        placed.push((at, bytes));
        at = (at + bytes.len()).div_ceil(ALIGN) * ALIGN;
    }
    let total = at;
    let mut out = vec![0u8; total];
    out[..4].copy_from_slice(b"NLBB");
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[6..8].copy_from_slice(&(ENTRY as u16).to_le_bytes());
    out[8..12].copy_from_slice(&(files.len() as u32).to_le_bytes());
    out[12..16].copy_from_slice(
        &u32::try_from(total)
            .map_err(|_| invalid("bundle too large"))?
            .to_le_bytes(),
    );
    out[16..20].copy_from_slice(&crc32(&table).to_le_bytes());
    out[HEADER..HEADER + table.len()].copy_from_slice(&table);
    for (offset, bytes) in placed {
        out[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    Ok((out, entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(id: &str) -> Vec<u8> {
        let meta = format!("id={id}\nkind=shell\nname=X\nmin_abi=7\n\0\0\0\0");
        let meta = &meta.as_bytes()[..meta.len() / 8 * 8];
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"NPLD");
        b[4..6].copy_from_slice(&3u16.to_le_bytes());
        b[6..8].copy_from_slice(&64u16.to_le_bytes());
        b[0x28..0x2c].copy_from_slice(&(meta.len() as u32).to_le_bytes());
        b[0x2c..0x30].copy_from_slice(&crc32(meta).to_le_bytes());
        b.extend_from_slice(meta);
        b.extend_from_slice(&[7u8; 100]);
        b
    }

    #[test]
    fn bundle_layout_matches_the_loader_reader() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("LVUI.NLB"), program("lvui")).unwrap();
        fs::write(dir.path().join("BOOT"), b"lvui\n").unwrap();
        let (bytes, entries) = build_bundle(dir.path()).unwrap();
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        assert_eq!(&bytes[..4], b"NLBB");
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 1);
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 32);
        assert_eq!(word(8), 2);
        assert_eq!(word(12) as usize, bytes.len());
        assert_eq!(word(16), crc32(&bytes[0x20..0x20 + 64]));
        assert!(bytes[0x14..0x20].iter().all(|b| *b == 0));
        // name order: BOOT before LVUI.NLB; each file on 64 bytes, checked
        assert_eq!(entries[0].name, "BOOT");
        assert_eq!(&bytes[0x20..0x24], b"BOOT");
        for (i, e) in entries.iter().enumerate() {
            let rec = 0x20 + 32 * i;
            assert_eq!(word(rec + 16), e.offset);
            assert_eq!(e.offset % 64, 0);
            let file = &bytes[e.offset as usize..(e.offset + e.bytes) as usize];
            assert_eq!(crc32(file), word(rec + 24));
        }
        assert_eq!(bytes.len() % 64, 0);
    }

    #[test]
    fn bundle_refuses_what_the_loader_could_not_use() {
        let dir = tempfile::tempdir().unwrap();
        // a program without its own description
        let mut plain = program("x");
        plain[4] = 2;
        fs::write(dir.path().join("X.NLB"), &plain).unwrap();
        assert!(build_bundle(dir.path()).is_err());
        fs::remove_file(dir.path().join("X.NLB")).unwrap();
        // a broken metadata block
        let mut broken = program("x");
        broken[70] ^= 1;
        fs::write(dir.path().join("X.NLB"), &broken).unwrap();
        assert!(build_bundle(dir.path()).is_err());
        fs::write(dir.path().join("X.NLB"), program("x")).unwrap();
        // names and files the bundle does not take
        fs::write(dir.path().join("readme.txt"), b"hi").unwrap();
        assert!(build_bundle(dir.path()).is_err());
        fs::remove_file(dir.path().join("readme.txt")).unwrap();
        fs::write(dir.path().join("SETTINGS"), b"x").unwrap();
        assert!(build_bundle(dir.path()).is_err());
        fs::remove_file(dir.path().join("SETTINGS")).unwrap();
        assert!(build_bundle(dir.path()).is_ok());
        // defaults alone are no bundle
        let empty = tempfile::tempdir().unwrap();
        fs::write(empty.path().join("BOOT"), b"x\n").unwrap();
        assert!(build_bundle(empty.path()).is_err());
    }

    /* The stock end pair (MOVZ x8,#lo; MOVK x8,#hi, LSL #16) moved to a span
     * end: only the immediates change, and a site that does not hold its
     * declared stock word is refused. */
    #[test]
    fn copy_end_patches_rewrite_only_the_immediates() {
        use nloader_profile::{BundleCopy, MemorySegment, MemorySegmentKind, PlatformBundle};
        let mut profile = nloader_profile::Profile::draft("Z8", "3.11");
        profile.memory.xip_base = Some(0x1000_0000);
        profile.memory.module_size = Some(0x2_0000);
        profile.memory.segments = vec![MemorySegment {
            file_offset: 0,
            runtime_start: 0x1000_0000,
            size: 0x2_0000,
            kind: MemorySegmentKind::Xip,
        }];
        // MOVZ x8,#0x2010 and MOVK x8,#0x1000, LSL #16: stock end 0x1000_2010.
        let stock = [0xd284_0208u32, 0xf2a2_0008u32];
        let span = PlatformBundle {
            address: 0x1000_3000,
            size: 0xd000,
            copy: Some(BundleCopy {
                source: 0x1000_1000,
                block_bytes: 0xf000,
                destination: 0xb_0000_0000,
                stock_end: 0x1000_2010,
                low_site: 0x1000_0100,
                high_site: 0x1000_0104,
                register: 8,
                stock: stock.iter().flat_map(|w| w.to_le_bytes()).collect(),
            }),
        };
        let mut payload = vec![0u8; 0x2_0000];
        payload[0x100..0x108].copy_from_slice(&span.copy.as_ref().unwrap().stock);
        let patches = crate::marker::bundle_copy_patches(&profile, &payload, &span).unwrap();
        assert_eq!(patches.len(), 2);
        // The span ends at 0x1001_0000: MOVZ x8,#0 and MOVK x8,#0x1001.
        assert_eq!(patches[0].file_offset, 0x100);
        assert_eq!(patches[0].stock, stock[0].to_le_bytes());
        assert_eq!(patches[0].new, 0xd280_0008u32.to_le_bytes());
        assert_eq!(patches[1].file_offset, 0x104);
        assert_eq!(patches[1].new, 0xf2a2_0028u32.to_le_bytes());
        payload[0x104] ^= 1;
        assert!(crate::marker::bundle_copy_patches(&profile, &payload, &span).is_err());
        let mut no_copy = span.clone();
        no_copy.copy = None;
        assert!(crate::marker::bundle_copy_patches(&profile, &payload, &no_copy).is_err());
    }
}
