//! Firmware-derived marker slot. Static structure checks do not establish a
//! live execution path, installation support, or ownership in every camera mode.

use crate::{Error, Result};
use nloader_profile::{sha256, AddressRange, CaptureSlot, Memory, MemorySegmentKind, Slack};
use serde::Serialize;

const PAGE_SIZE: u64 = 4096;
const FLASH_RECORD_SIZE: u64 = 40;

#[derive(Debug, Clone, Serialize)]
pub struct SlotEvidenceFragment {
    pub name: String,
    pub file_offset: u64,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MarkerSlot {
    pub slack: Slack,
    pub link_base: u64,
    pub link_size: u64,
    pub evidence_fragments: Vec<SlotEvidenceFragment>,
    pub note: String,
}

#[derive(Debug)]
struct Region {
    name: String,
    range: AddressRange,
    physical_start: u64,
    flags: u64,
}

#[derive(Debug)]
struct Overlay {
    kind: u32,
    flags: u32,
    range: AddressRange,
    physical_start: u64,
}

fn reject(reason: &str) -> Error {
    Error::FirmwareMismatch(format!("static marker slot rejected: {reason}"))
}

fn bytes_at(payload: &[u8], offset: u64, length: u64) -> Result<&[u8]> {
    let start = usize::try_from(offset).map_err(|_| reject("offset exceeds host range"))?;
    let size = usize::try_from(length).map_err(|_| reject("length exceeds host range"))?;
    payload
        .get(
            start
                ..start
                    .checked_add(size)
                    .ok_or_else(|| reject("extent overflow"))?,
        )
        .ok_or_else(|| reject("extent exceeds payload"))
}

fn u32_at(bytes: &[u8], offset: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes_at(bytes, offset, 4)?
            .try_into()
            .expect("checked word length"),
    ))
}

fn u64_at(bytes: &[u8], offset: u64) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes_at(bytes, offset, 8)?
            .try_into()
            .expect("checked word length"),
    ))
}

fn checked_range(start: u64, size: u64) -> Result<AddressRange> {
    if size == 0 {
        return Err(reject("empty region"));
    }
    Ok(AddressRange {
        start,
        end: start
            .checked_add(size)
            .ok_or_else(|| reject("address overflow"))?,
    })
}

fn mapped_offset(memory: &Memory, address: u64, size: u64, kind: MemorySegmentKind) -> Result<u64> {
    let segment = memory
        .segment_for_address(address, size)
        .map_err(|_| reject("unmapped range"))?;
    if segment.kind != kind {
        return Err(reject("wrong mapped address space"));
    }
    memory
        .address_to_offset(address, size)
        .map_err(|_| reject("invalid mapping"))
}

fn fragment(payload: &[u8], name: &str, offset: u64, length: u64) -> Result<SlotEvidenceFragment> {
    Ok(SlotEvidenceFragment {
        name: name.into(),
        file_offset: offset,
        length,
        sha256: sha256(bytes_at(payload, offset, length)?),
    })
}

/// Accept only the reviewed stock payload. Addresses are extracted from its
/// descriptor, getters, region records, and copy sequence, not supplied by a
/// research checkout or copied from another model's profile.
pub(crate) fn inspect(payload: &[u8], memory: &Memory, config: &CaptureSlot) -> Result<MarkerSlot> {
    if config.flash_record_count != 39 || config.instruction_windows.len() != 4 {
        return Err(reject(
            "invalid flash table count or instruction window set",
        ));
    }
    if memory.module_size != Some(payload.len() as u64) {
        return Err(reject("module length differs from mapping"));
    }
    memory
        .validated_segments()
        .map_err(|_| reject("invalid memory segments"))?;
    let descriptor = bytes_at(payload, config.descriptor_offset, 0x160)?;
    let image_base = u64_at(descriptor, 0x128)?;
    let text_offset = u64_at(descriptor, 0x98)?;
    let text_size = u64_at(descriptor, 0xa0)?;
    let text_start = u64_at(descriptor, 0xa8)?;
    let text = checked_range(text_start, text_size)?;
    if memory.xip_base != Some(image_base)
        || image_base.checked_add(text_offset) != Some(text_start)
        || mapped_offset(memory, text_start, text_size, MemorySegmentKind::Xip)? != text_offset
    {
        return Err(reject("text descriptor and XIP mapping disagree"));
    }
    let data_offset = u64_at(descriptor, 0x148)?;
    let data_size = u64_at(descriptor, 0xd0)?;
    let data_start = u64_at(descriptor, 0xd8)?;
    if mapped_offset(memory, data_start, data_size, MemorySegmentKind::Ram)? != data_offset {
        return Err(reject("initialized-data descriptor and mapping disagree"));
    }
    let mut evidence = vec![fragment(
        payload,
        "startup_descriptor",
        config.descriptor_offset,
        0x160,
    )?];
    for (name, expected_length) in [
        ("bootstrap_text_mapping", 0x28),
        ("overlay_consumer", 0xc0),
        ("shutdown_copy", 0x40),
        ("late_data_copy", 0x40),
    ] {
        let windows: Vec<_> = config
            .instruction_windows
            .iter()
            .filter(|window| window.name == name)
            .collect();
        if windows.len() != 1 {
            return Err(reject("missing or duplicate instruction window"));
        }
        let window = windows[0];
        let item = fragment(payload, name, window.file_offset, window.length)?;
        if window.length != expected_length || item.sha256 != window.sha256 {
            return Err(reject("reviewed instruction window changed"));
        }
        evidence.push(item);
    }
    let (region_address, region_count) =
        getter(bytes_at(payload, config.region_getter_offset, 32)?)?;
    let (overlay_address, overlay_count) =
        getter(bytes_at(payload, config.overlay_getter_offset, 32)?)?;
    if region_count != config.region_count || overlay_count != config.overlay_count {
        return Err(reject("unexpected native table counts"));
    }
    let region_offset = mapped_offset(
        memory,
        region_address,
        region_count * 40,
        MemorySegmentKind::Ram,
    )?;
    let overlay_offset = mapped_offset(
        memory,
        overlay_address,
        overlay_count * 32,
        MemorySegmentKind::Ram,
    )?;
    let regions = parse_regions(
        payload,
        memory,
        bytes_at(payload, region_offset, region_count * 40)?,
    )?;
    let overlays = parse_overlays(bytes_at(payload, overlay_offset, overlay_count * 32)?)?;
    let solid = unique_region(&regions, "SOLID")?;
    let user = unique_region(&regions, "SNOR_USER")?;
    if solid.range.start != image_base
        || solid.physical_start != solid.range.start
        || solid.flags != 2
        || user.range.start != solid.range.end
        || user.flags != 4
    {
        return Err(reject(
            "SOLID flash region identity or user-region boundary differs",
        ));
    }
    let flash_offset = flash_region(payload, solid, config)?;
    let copy_window = config
        .instruction_windows
        .iter()
        .find(|window| window.name == "shutdown_copy")
        .expect("validated window");
    let copy = bytes_at(payload, copy_window.file_offset, copy_window.length)?;
    let destination = mov_wide(copy, [0, 8, 16, 28], 19)?;
    let destination_end = mov_wide(copy, [4, 12, 20, 32], 8)?;
    let source = mov_wide(copy, [24, 36, 44, 48], 2)?;
    let copy_length = destination_end
        .checked_sub(destination)
        .ok_or_else(|| reject("copy range is reversed"))?;
    if copy_length != PAGE_SIZE {
        return Err(reject("unexpected shutdown copy length"));
    }
    let protected = checked_range(source, copy_length)?;
    let matching: Vec<_> = overlays
        .iter()
        .filter(|row| {
            row.kind == 2
                && row.flags == 13
                && row.range == protected
                && row.physical_start == source
        })
        .collect();
    if matching.len() != 1
        || !overlays.iter().any(|row| {
            row.kind == 1
                && row.flags == 15
                && row.range.start == destination
                && row.range.end == destination_end
        })
    {
        return Err(reject(
            "shutdown source or destination is not declared uniquely",
        ));
    }
    let slack = zero_slot(
        payload,
        memory,
        protected.end,
        &text,
        &solid.range,
        &overlays,
    )?;
    let slot_offset = mapped_offset(
        memory,
        slack.start,
        slack.end - slack.start,
        MemorySegmentKind::Xip,
    )?;
    evidence.extend([
        fragment(payload, "region_getter", config.region_getter_offset, 32)?,
        fragment(payload, "overlay_getter", config.overlay_getter_offset, 32)?,
        fragment(
            payload,
            "native_region_table",
            region_offset,
            region_count * 40,
        )?,
        fragment(
            payload,
            "native_overlay_table",
            overlay_offset,
            overlay_count * 32,
        )?,
        fragment(payload, "flash_eg_region", flash_offset, FLASH_RECORD_SIZE)?,
        fragment(payload, "zero_slot", slot_offset, slack.end - slack.start)?,
    ]);
    Ok(MarkerSlot {
        link_base: slack.start,
        link_size: PAGE_SIZE,
        slack,
        evidence_fragments: evidence,
        note: "Static candidate for an unhooked local marker artifact only. Derived from the stock image's text mapping, SOLID flash region, protected shutdown-copy page, native mapping overlays, and the following complete zero pages. Historical device page-table research informed this rule, but no historical snapshot is read or promoted to a current runtime observation. The rule does not prove all indirect uses, mode-dependent remaps, current execution permissions, installation, or execution; no hook or version edit is authorized by this result.".into(),
    })
}

fn getter(bytes: &[u8]) -> Result<(u64, u64)> {
    let address = mov_wide(bytes, [0, 4, 8, 12], 8)?;
    let count = u32_at(bytes, 16)?;
    if count & 0xffe0_001f != 0x5280_0009
        || u32_at(bytes, 20)? != 0xf900_0008
        || u32_at(bytes, 24)? != 0xb900_0029
        || u32_at(bytes, 28)? != 0xd65f_03c0
    {
        return Err(reject("table getter instruction pattern differs"));
    }
    let count = u64::from((count >> 5) & 65535);
    if address == 0 || count == 0 || count > 64 {
        return Err(reject("invalid native table address or count"));
    }
    Ok((address, count))
}

pub(crate) fn mov_wide(bytes: &[u8], offsets: [u64; 4], register: u32) -> Result<u64> {
    let mut value = 0;
    for (index, offset) in offsets.into_iter().enumerate() {
        let word = u32_at(bytes, offset)?;
        let opcode = if index == 0 { 0xd280_0000 } else { 0xf280_0000 };
        if word & 0xff80_001f != opcode | register || ((word >> 21) & 3) as usize != index {
            return Err(reject("address construction instruction differs"));
        }
        value |= u64::from((word >> 5) & 65535) << (index * 16);
    }
    Ok(value)
}

fn parse_regions(payload: &[u8], memory: &Memory, records: &[u8]) -> Result<Vec<Region>> {
    if records.is_empty() || records.len() % 40 != 0 {
        return Err(reject("invalid native region table size"));
    }
    records
        .chunks_exact(40)
        .map(|record| {
            let range = checked_range(u64_at(record, 0)?, u64_at(record, 8)?)?;
            let name_address = u64_at(record, 24)?;
            let name_offset = mapped_offset(memory, name_address, 1, MemorySegmentKind::Ram)?;
            let mut name = Vec::new();
            for offset in 0..64 {
                let address = name_address
                    .checked_add(offset)
                    .ok_or_else(|| reject("name address overflow"))?;
                let mapped = mapped_offset(memory, address, 1, MemorySegmentKind::Ram)?;
                if name_offset.checked_add(offset) != Some(mapped) {
                    return Err(reject("discontinuous region name"));
                }
                let byte = bytes_at(payload, mapped, 1)?[0];
                if byte == 0 {
                    if name.is_empty() {
                        return Err(reject("empty region name"));
                    }
                    return Ok(Region {
                        name: String::from_utf8(name).map_err(|_| reject("invalid region name"))?,
                        range,
                        flags: u64_at(record, 16)?,
                        physical_start: u64_at(record, 32)?,
                    });
                }
                if !byte.is_ascii_alphanumeric() && byte != b'_' {
                    return Err(reject("invalid region name character"));
                }
                name.push(byte);
            }
            Err(reject("unterminated region name"))
        })
        .collect()
}

fn unique_region<'a>(regions: &'a [Region], name: &str) -> Result<&'a Region> {
    let mut found = regions.iter().filter(|region| region.name == name);
    let result = found
        .next()
        .ok_or_else(|| reject("required flash region is missing"))?;
    if found.next().is_some() {
        return Err(reject("duplicate flash region identity"));
    }
    Ok(result)
}

fn parse_overlays(records: &[u8]) -> Result<Vec<Overlay>> {
    if records.is_empty() || records.len() % 32 != 0 {
        return Err(reject("invalid overlay table size"));
    }
    records
        .chunks_exact(32)
        .map(|record| {
            let range = AddressRange {
                start: u64_at(record, 8)?,
                end: u64_at(record, 16)?,
            };
            let kind = u32_at(record, 0)?;
            if !(1..=4).contains(&kind) || range.start == 0 || range.end < range.start {
                return Err(reject("invalid overlay range or operation"));
            }
            Ok(Overlay {
                kind,
                range,
                flags: u32_at(record, 4)?,
                physical_start: u64_at(record, 24)?,
            })
        })
        .collect()
}

fn flash_region(payload: &[u8], solid: &Region, config: &CaptureSlot) -> Result<u64> {
    let records = bytes_at(
        payload,
        config.flash_table_offset,
        FLASH_RECORD_SIZE * config.flash_record_count,
    )?;
    let mut result = None;
    for (index, row) in records.chunks_exact(FLASH_RECORD_SIZE as usize).enumerate() {
        if u64_at(row, 0)? != solid.range.start {
            continue;
        }
        if result.is_some()
            || u64_at(row, 8)? != 0
            || u64::from(u32_at(row, 16)?) != solid.range.end - solid.range.start
            || u32_at(row, 20)? != u32_at(row, 16)?
            || u32_at(row, 24)? != 0
            || u32_at(row, 28)? != 0
            || row[32..] != [0, 0, 0, 0, 1, 0, 0, 0]
        {
            return Err(reject(
                "flash updater record is ambiguous or differs from SOLID region",
            ));
        }
        result = Some(config.flash_table_offset + index as u64 * FLASH_RECORD_SIZE);
    }
    result.ok_or_else(|| reject("SOLID has no matching flash updater region"))
}

fn zero_slot(
    payload: &[u8],
    memory: &Memory,
    start: u64,
    text: &AddressRange,
    solid: &AddressRange,
    overlays: &[Overlay],
) -> Result<Slack> {
    if start % PAGE_SIZE != 0
        || !text.contains(start, PAGE_SIZE)
        || !solid.contains(start, PAGE_SIZE)
    {
        return Err(reject(
            "protected-page end is not a complete text/flash page",
        ));
    }
    let available = text.end - start;
    let offset = mapped_offset(memory, start, available, MemorySegmentKind::Xip)?;
    let bytes = bytes_at(payload, offset, available)?;
    let length = bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or_else(|| reject("no nonzero boundary after zero run"))? as u64;
    let end = start
        .checked_add(length)
        .ok_or_else(|| reject("zero run overflows"))?
        & !(PAGE_SIZE - 1);
    if end <= start || end - start < PAGE_SIZE || !solid.contains(start, end - start) {
        return Err(reject("zero run contains no complete marker page"));
    }
    let range = AddressRange { start, end };
    if overlays
        .iter()
        .any(|overlay| overlay.range.start < overlay.range.end && range.overlaps(&overlay.range))
    {
        return Err(reject(
            "zero run overlaps an existing native mapping declaration",
        ));
    }
    mapped_offset(memory, start, end - start, MemorySegmentKind::Xip)?;
    Ok(Slack {
        start,
        end,
        require_zero: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nloader_profile::{MemorySegment, MemorySegmentKind};

    fn memory(size: u64) -> Memory {
        Memory {
            xip_base: Some(0x1000),
            module_size: Some(size),
            segments: vec![MemorySegment {
                file_offset: 0,
                runtime_start: 0x1000,
                size,
                kind: MemorySegmentKind::Xip,
            }],
            ..Memory::default()
        }
    }

    fn getter_bytes(address: u64, count: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        for index in 0..4 {
            let opcode = if index == 0 { 0xd280_0000 } else { 0xf280_0000 };
            let word =
                opcode | (index << 21) | ((((address >> (index * 16)) & 65535) as u32) << 5) | 8;
            bytes.extend(word.to_le_bytes());
        }
        for word in [
            0x5280_0009 | (count << 5),
            0xf900_0008,
            0xb900_0029,
            0xd65f_03c0,
        ] {
            bytes.extend(word.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn decodes_table_identity_and_rejects_changed_instructions() {
        let bytes = getter_bytes(0x1234_5678_abcd_0000, 13);
        assert_eq!(getter(&bytes).unwrap(), (0x1234_5678_abcd_0000, 13));
        for offset in [0, 4, 8, 12, 16, 20, 24, 28] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(getter(&changed).is_err());
        }
        assert!(getter(&getter_bytes(0x1000, 0)).is_err());
        assert!(getter(&getter_bytes(0x1000, 65)).is_err());
        assert!(getter(&bytes[..31]).is_err());
    }

    #[test]
    fn derives_pages_from_following_zero_run_and_rejects_unsafe_boundaries() {
        let mut payload = vec![0; 0x6000];
        payload[0x4801] = 1;
        let memory = memory(payload.len() as u64);
        let text = AddressRange {
            start: 0x1000,
            end: 0x7000,
        };
        let slot = zero_slot(&payload, &memory, 0x2000, &text, &text, &[]).unwrap();
        assert_eq!((slot.start, slot.end), (0x2000, 0x5000));
        assert!(zero_slot(&payload, &memory, 0x2001, &text, &text, &[]).is_err());
        assert!(zero_slot(&payload, &memory, 0x8000, &text, &text, &[]).is_err());
        let overlay = Overlay {
            kind: 2,
            flags: 13,
            range: AddressRange {
                start: 0x3000,
                end: 0x4000,
            },
            physical_start: 0x3000,
        };
        assert!(zero_slot(&payload, &memory, 0x2000, &text, &text, &[overlay]).is_err());
        payload[0x1800] = 1;
        assert!(zero_slot(&payload, &memory, 0x2000, &text, &text, &[]).is_err());
        payload.fill(0);
        assert!(zero_slot(&payload, &memory, 0x2000, &text, &text, &[]).is_err());
        assert!(bytes_at(&payload, u64::MAX, 2).is_err());
    }

    #[test]
    fn rejects_wrong_identity_mapping_and_malformed_overlay_records() {
        assert!(parse_overlays(&[0; 31]).is_err());
        let mut record = vec![0; 32];
        record[..4].copy_from_slice(&2_u32.to_le_bytes());
        record[8..16].copy_from_slice(&0x2000_u64.to_le_bytes());
        record[16..24].copy_from_slice(&0x1000_u64.to_le_bytes());
        assert!(parse_overlays(&record).is_err());
        let payload = vec![0; 0x4000];
        let mut invalid = memory(payload.len() as u64);
        invalid.segments[0].kind = MemorySegmentKind::Ram;
        let range = AddressRange {
            start: 0x1000,
            end: 0x5000,
        };
        assert!(zero_slot(&payload, &invalid, 0x2000, &range, &range, &[]).is_err());
    }
}
