//! General NPLD v2 packaging: the 64-byte M2-T4 execution header
//! (PLAN §6.3 "M2-T4 定案", 2026-10-11).
//!
//! File layout: header (64 bytes) → relocation table → image → data,
//! contiguous. Every declaration input is re-validated here against the
//! final bytes — the packager never trusts the linker's self-check, so a
//! caller may hand it independently produced bytes.

use crate::{Error, Result};

/// The general v2 header length (the probe subset uses 48).
pub const HEADER_SIZE: usize = 64;
pub const V2_HEADER_VERSION: u16 = 2;
/// General programs always use `flags` 0; 1 belongs to the diagnostic probe.
pub const GENERAL_FLAGS: u32 = 0;
pub const KIND_RESOURCE_EXTENSION: u32 = 1;
pub const KIND_FOREGROUND: u32 = 2;
pub const RELOCATION_ENTRY_BYTES: usize = 12;
/// Bounded independently of the execution segments, matching the loader's
/// temporary file buffer policy.
pub const MAX_RELOCATION_BYTES: usize = 1024 * 1024;
pub const RELOCATION_KIND_ADRP: u32 = 0;
pub const RELOCATION_KIND_ABS64: u32 = 1;
pub const RELOCATION_KIND_ABS64_DATA: u32 = 2;
/// Largest API-table version this packager can certify: the runtime's
/// `NLR_ABI_VERSION` (5 added card writing and the firmware-code channel,
/// 7 the platform: events, every control, the screen, the settings store;
/// 8 the firmware by name: hook points, tables, functions, devices; the
/// API table only grows). Version 3 had conflicting experimental layouts.
pub const MAX_ABI_VERSION: u32 = 9;
/// ABI 3 used incompatible surface, input and time definitions on the two
/// development branches. Rebuild those programs against ABI 4 or later.
pub const INCOMPATIBLE_ABI_VERSION: u32 = 3;
/// PLAN 6.3 load model: at most one 2 MiB block per segment.
pub const BLOCK_CAPACITY: u32 = 0x20_0000;

/// One 12-byte runtime relocation table entry: `{ u32 offset; u32 target;
/// u32 kind }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Relocation {
    pub offset: u32,
    pub target: u32,
    pub kind: u32,
}

/// A full program declaration ready for packaging. `kind` and the MANIFEST
/// metadata are carried by [`super::manifest::ManifestEntry`]/`ProgramMeta`;
/// this struct holds the file content inputs.
#[derive(Debug, Clone)]
pub struct ProgramDeclaration {
    pub image: Vec<u8>,
    pub data: Vec<u8>,
    pub bss_size: u32,
    /// File-relative image offset of the kind's entry.
    pub entry_offset: u32,
    pub relocations: Vec<Relocation>,
    pub abi_version: u32,
    /// The program's own description: with it the
    /// file is header version 3 and the block follows the header.
    pub metadata: Option<Vec<u8>>,
}

/// Header version 3 carries the metadata block (core/include/nlr/load.h).
pub const V3_HEADER_VERSION: u16 = 3;
/// Bytes a metadata block may have (NLR_META_MAX).
pub const META_MAX: usize = 4096;

fn crc32(bytes: &[u8]) -> u32 {
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

/// Validate the declaration and package it into the exact v2 file bytes.
/// Every check is derived from PLAN §6.3; a rejected declaration produces no
/// file.
pub fn package(kind: super::ProgramKind, declaration: &ProgramDeclaration) -> Result<Vec<u8>> {
    let image = declaration.image.as_slice();
    let data = declaration.data.as_slice();
    if image.is_empty() {
        return Err(invalid("a program needs a nonempty image"));
    }
    if image.len() > BLOCK_CAPACITY as usize {
        return Err(invalid("the image exceeds the 2 MiB code block budget"));
    }
    if data.len() + declaration.bss_size as usize > BLOCK_CAPACITY as usize {
        return Err(invalid("data plus BSS exceeds the 2 MiB data block budget"));
    }
    let entry = declaration.entry_offset as usize;
    if declaration.entry_offset % 4 != 0 || entry + 4 > image.len() {
        return Err(invalid(
            "entry_offset must be 4-byte aligned and hold an instruction inside the image",
        ));
    }
    if declaration.abi_version == 0 {
        return Err(invalid("abi_version must name an established API version"));
    }
    if declaration.abi_version == INCOMPATIBLE_ABI_VERSION {
        return Err(invalid(
            "ABI 3 has incompatible experimental layouts; rebuild for ABI 4",
        ));
    }
    if declaration.abi_version > MAX_ABI_VERSION {
        return Err(invalid(format!(
            "abi_version {} exceeds the runtime's API table version {MAX_ABI_VERSION}",
            declaration.abi_version
        )));
    }
    if declaration.relocations.len() > MAX_RELOCATION_BYTES / RELOCATION_ENTRY_BYTES {
        return Err(invalid(
            "the relocation table exceeds the 1 MiB file budget",
        ));
    }
    let table = relocation_table(&declaration.relocations);
    let mut image_claimed = std::collections::BTreeMap::<u64, u64>::new();
    let mut data_claimed = std::collections::BTreeMap::<u64, u64>::new();
    for relocation in &declaration.relocations {
        let (offset, target, kind) = (
            u64::from(relocation.offset),
            u64::from(relocation.target),
            relocation.kind,
        );
        match kind {
            RELOCATION_KIND_ADRP => {
                if offset % 4 != 0 || offset + 4 > image.len() as u64 {
                    return Err(invalid(
                        "ADRP relocation offset must be 4-byte aligned inside the image",
                    ));
                }
                let word = u32::from_le_bytes(
                    image[offset as usize..offset as usize + 4]
                        .try_into()
                        .unwrap(),
                );
                if word & 0x9f00_0000 != 0x9000_0000 {
                    return Err(invalid(
                        "kind-0 relocation must point at an ADRP instruction in the image",
                    ));
                }
                if target >= data.len() as u64 + u64::from(declaration.bss_size) {
                    return Err(invalid(
                        "ADRP relocation target must stay inside the data block",
                    ));
                }
                claim(&mut image_claimed, offset, 4)?;
            }
            RELOCATION_KIND_ABS64 => {
                if offset % 8 != 0 || offset + 8 > data.len() as u64 {
                    return Err(invalid(
                        "ABS64 relocation offset must be an 8-byte word inside the data",
                    ));
                }
                if target >= image.len() as u64 {
                    return Err(invalid(
                        "ABS64 relocation target must stay inside the image",
                    ));
                }
                claim(&mut data_claimed, offset, 8)?;
            }
            RELOCATION_KIND_ABS64_DATA => {
                if offset % 8 != 0 || offset + 8 > data.len() as u64 {
                    return Err(invalid(
                        "ABS64_DATA offset must be an 8-byte word inside initialized data",
                    ));
                }
                if target >= data.len() as u64 + u64::from(declaration.bss_size) {
                    return Err(invalid("ABS64_DATA target must stay inside data or BSS"));
                }
                claim(&mut data_claimed, offset, 8)?;
            }
            other => {
                return Err(invalid(format!(
                    "unknown relocation kind {other}; expected ADRP, ABS64 or ABS64_DATA"
                )));
            }
        }
    }
    let meta: &[u8] = declaration.metadata.as_deref().unwrap_or(&[]);
    if declaration.metadata.is_some()
        && (meta.is_empty() || meta.len() > META_MAX || meta.len() % 8 != 0)
    {
        return Err(invalid(
            "a metadata block is 8..=4096 bytes, a multiple of 8",
        ));
    }
    let mut bytes = vec![0u8; HEADER_SIZE + meta.len() + table.len() + image.len() + data.len()];
    bytes[..4].copy_from_slice(b"NPLD");
    let version = if declaration.metadata.is_some() {
        V3_HEADER_VERSION
    } else {
        V2_HEADER_VERSION
    };
    bytes[4..6].copy_from_slice(&version.to_le_bytes());
    bytes[6..8].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    for (offset, value) in [
        (0x08, GENERAL_FLAGS),
        (0x0C, image.len() as u32),
        (0x10, declaration.bss_size),
        (0x14, declaration.entry_offset),
        (0x18, declaration.abi_version),
        (0x1C, crc32(image)),
        (0x20, kind.code()),
        (0x24, table.len() as u32),
        (0x30, crc32(data)),
        (0x34, crc32(&table)),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    if declaration.metadata.is_some() {
        bytes[0x28..0x2C].copy_from_slice(&(meta.len() as u32).to_le_bytes());
        bytes[0x2C..0x30].copy_from_slice(&crc32(meta).to_le_bytes());
        bytes[HEADER_SIZE..HEADER_SIZE + meta.len()].copy_from_slice(meta);
    }
    let table_start = HEADER_SIZE + meta.len();
    let image_start = table_start + table.len();
    bytes[table_start..image_start].copy_from_slice(&table);
    bytes[image_start..image_start + image.len()].copy_from_slice(image);
    bytes[image_start + image.len()..].copy_from_slice(data);
    Ok(bytes)
}

fn claim(claimed: &mut std::collections::BTreeMap<u64, u64>, start: u64, width: u64) -> Result<()> {
    let end = start + width;
    if claimed
        .range(..end)
        .next_back()
        .is_some_and(|(_, previous_end)| *previous_end > start)
    {
        return Err(invalid("overlapping relocation table entries"));
    }
    claimed.insert(start, end);
    Ok(())
}

/// Assemble just the 12-byte relocation table records.
pub fn relocation_table(relocations: &[Relocation]) -> Vec<u8> {
    let mut table = Vec::with_capacity(relocations.len() * RELOCATION_ENTRY_BYTES);
    for relocation in relocations {
        table.extend_from_slice(&relocation.offset.to_le_bytes());
        table.extend_from_slice(&relocation.target.to_le_bytes());
        table.extend_from_slice(&relocation.kind.to_le_bytes());
    }
    table
}
