//! Explicit read-only collection inputs; independent of build capabilities.
use crate::AddressRange;
use serde::{Deserialize, Serialize};

const SUB_W20_W8_W19: [u8; 4] = [0x14, 0x01, 0x13, 0x4b];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    pub family: String,
    pub windows: Vec<AddressRange>,
    pub requests: Vec<CaptureRequest>,
    pub range_check: CaptureFragment,
    pub slot: CaptureSlot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    pub label: String,
    pub address: u64,
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFragment {
    pub name: String,
    pub file_offset: u64,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSlot {
    pub descriptor_offset: u64,
    pub region_getter_offset: u64,
    pub overlay_getter_offset: u64,
    pub flash_table_offset: u64,
    pub flash_record_count: u64,
    pub region_count: u64,
    pub overlay_count: u64,
    pub instruction_windows: Vec<CaptureFragment>,
}

/// Read windows constructed only after checking the profile against module bytes.
#[derive(Debug, Clone)]
pub struct VerifiedReadWindows(Vec<AddressRange>);
impl VerifiedReadWindows {
    pub fn windows(&self) -> &[AddressRange] {
        &self.0
    }
}

impl crate::Profile {
    pub fn verify_read_windows(&self, payload: &[u8]) -> Result<VerifiedReadWindows, String> {
        let config = self
            .capture
            .as_ref()
            .ok_or("missing capture configuration")?;
        if self.identity.model != "Z8"
            || self.identity.firmware != "3.11"
            || config.family != "z8_readonly_v1"
        {
            return Err("unsupported read-only collection family or identity".into());
        }
        if self.checks.module_sha256.as_deref() != Some(crate::sha256(payload).as_str())
            || self.memory.module_size != Some(payload.len() as u64)
        {
            return Err("collection module fingerprint or length differs".into());
        }
        self.memory
            .validated_segments()
            .map_err(|error| error.to_string())?;
        let check = &config.range_check;
        let start =
            usize::try_from(check.file_offset).map_err(|_| "range check offset overflow")?;
        let length = usize::try_from(check.length).map_err(|_| "range check size overflow")?;
        let end = start
            .checked_add(length)
            .ok_or("range check span overflow")?;
        let bytes = payload
            .get(start..end)
            .ok_or("range check outside module")?;
        if crate::sha256(bytes) != check.sha256 || bytes.len() != 0xf0 {
            return Err("range check fingerprint differs".into());
        }
        let upper = protected_endpoint(bytes, [12, 16, 28, 32], 8)?;
        let lower = protected_endpoint(bytes, [44, 48, 52, 56], 8)?;
        for (offset, word) in [
            (36, 0xeb08029fu32),
            (40, 0x540000e8),
            (60, 0xeb08027f),
            (64, 0x54000302),
        ] {
            if bytes.get(offset..offset + 4) != Some(word.to_le_bytes().as_slice()) {
                return Err("range protection instruction relationship differs".into());
            }
        }
        let ram: Vec<_> = self
            .memory
            .segments
            .iter()
            .filter(|segment| segment.kind == crate::MemorySegmentKind::Ram)
            .collect();
        if ram.len() != 2
            || lower >= upper
            || ram[0].runtime_start >= lower
            || ram[0].runtime_start.checked_add(ram[0].size) != Some(upper)
            || ram[1].runtime_start != upper
        {
            return Err("initialized RAM mappings disagree with protected endpoints".into());
        }
        let descriptor = config.slot.descriptor_offset;
        let read_word = |offset: u64| -> Result<u64, String> {
            let start = usize::try_from(
                descriptor
                    .checked_add(offset)
                    .ok_or("descriptor overflow")?,
            )
            .map_err(|_| "descriptor overflow")?;
            let end = start.checked_add(8).ok_or("descriptor overflow")?;
            Ok(u64::from_le_bytes(
                payload
                    .get(start..end)
                    .ok_or("descriptor outside module")?
                    .try_into()
                    .expect("eight bytes"),
            ))
        };
        if read_word(0x148)? != ram[0].file_offset
            || read_word(0xd0)? != ram[0].size
            || read_word(0xd8)? != ram[0].runtime_start
        {
            return Err("early initialized-data mapping differs from descriptor".into());
        }
        let copies: Vec<_> = config
            .slot
            .instruction_windows
            .iter()
            .filter(|fragment| fragment.name == "late_data_copy")
            .collect();
        if copies.len() != 1 {
            return Err("missing or duplicate late-data copy window".into());
        }
        let copy = copies[0];
        let start = usize::try_from(copy.file_offset).map_err(|_| "copy offset overflow")?;
        let length = usize::try_from(copy.length).map_err(|_| "copy length overflow")?;
        let bytes = payload
            .get(start..start.checked_add(length).ok_or("copy span overflow")?)
            .ok_or("late-data copy outside module")?;
        if copy.length != 0x40 || crate::sha256(bytes) != copy.sha256 {
            return Err("late-data copy fingerprint differs".into());
        }
        let end = protected_endpoint(bytes, [0, 4, 12, 20], 8)?;
        let start = protected_endpoint(bytes, [8, 16, 24, 32], 19)?;
        let source = protected_endpoint(bytes, [28, 36, 44, 48], 2)?;
        if bytes.get(40..44) != Some(SUB_W20_W8_W19.as_slice())
            || bytes.get(52..56) != Some(0xaa1303e1u32.to_le_bytes().as_slice())
            || bytes.get(56..60) != Some(0x2a1403e3u32.to_le_bytes().as_slice())
            || start != ram[1].runtime_start
            || end.checked_sub(start) != Some(ram[1].size)
            || self
                .memory
                .xip_base
                .and_then(|base| base.checked_add(ram[1].file_offset))
                != Some(source)
        {
            return Err("late initialized-data mapping differs from copy instructions".into());
        }
        let windows = vec![
            AddressRange {
                start: ram[0].runtime_start,
                end: lower,
            },
            AddressRange {
                start: upper.checked_add(1).ok_or("protected range overflows")?,
                end: ram[1]
                    .runtime_start
                    .checked_add(ram[1].size)
                    .ok_or("RAM range overflows")?,
            },
        ];
        if config.windows != windows || windows.iter().any(|range| range.start >= range.end) {
            return Err("declared read windows differ from firmware-derived boundaries".into());
        }
        Ok(VerifiedReadWindows(windows))
    }
}

fn protected_endpoint(bytes: &[u8], offsets: [usize; 4], register: u32) -> Result<u64, String> {
    let mut value = 0;
    for (index, offset) in offsets.into_iter().enumerate() {
        let word = u32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or("truncated protection instruction")?
                .try_into()
                .expect("four bytes"),
        );
        let opcode = if index == 0 { 0xd280_0000 } else { 0xf280_0000 };
        if word & 0xff80_001f != opcode | register || ((word >> 21) & 3) as usize != index {
            return Err("protection endpoint instruction differs".into());
        }
        value |= u64::from((word >> 5) & 65535) << (index * 16);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256, MemorySegment, MemorySegmentKind, Profile};

    fn endpoint(bytes: &mut [u8], offsets: [usize; 4], register: u32, value: u64) {
        for (index, offset) in offsets.into_iter().enumerate() {
            let opcode = if index == 0 { 0xd280_0000 } else { 0xf280_0000 };
            let word = opcode
                | ((index as u32) << 21)
                | (((value >> (index * 16)) as u32 & 65535) << 5)
                | register;
            bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    fn fixture() -> (Profile, Vec<u8>) {
        let mut payload = vec![0; 0x4000];
        endpoint(&mut payload, [12, 16, 28, 32], 8, 0x4000);
        endpoint(&mut payload, [44, 48, 52, 56], 8, 0x3000);
        for (offset, word) in [
            (36, 0xeb08029fu32),
            (40, 0x540000e8),
            (60, 0xeb08027f),
            (64, 0x54000302),
        ] {
            payload[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
        let copy = &mut payload[0x100..0x140];
        endpoint(copy, [0, 4, 12, 20], 8, 0x5000);
        endpoint(copy, [8, 16, 24, 32], 19, 0x4000);
        endpoint(copy, [28, 36, 44, 48], 2, 0x13000);
        copy[40..44].copy_from_slice(&SUB_W20_W8_W19);
        for (offset, word) in [(52, 0xaa1303e1u32), (56, 0x2a1403e3)] {
            copy[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
        for (offset, value) in [(0x148, 0x1000u64), (0xd0, 0x2000), (0xd8, 0x2000)] {
            payload[0x200 + offset..0x208 + offset].copy_from_slice(&value.to_le_bytes());
        }
        let fragment = |name: &str, start: usize, length: usize| CaptureFragment {
            name: name.into(),
            file_offset: start as u64,
            length: length as u64,
            sha256: sha256(&payload[start..start + length]),
        };
        let mut profile = Profile::draft("Z8", "3.11");
        profile.memory.module_size = Some(payload.len() as u64);
        profile.memory.xip_base = Some(0x10000);
        profile.memory.segments = vec![
            MemorySegment {
                file_offset: 0,
                runtime_start: 0x10000,
                size: 0x1000,
                kind: MemorySegmentKind::Xip,
            },
            MemorySegment {
                file_offset: 0x1000,
                runtime_start: 0x2000,
                size: 0x2000,
                kind: MemorySegmentKind::Ram,
            },
            MemorySegment {
                file_offset: 0x3000,
                runtime_start: 0x4000,
                size: 0x1000,
                kind: MemorySegmentKind::Ram,
            },
        ];
        profile.checks.module_sha256 = Some(sha256(&payload));
        profile.capture = Some(CaptureConfig {
            family: "z8_readonly_v1".into(),
            windows: vec![
                AddressRange {
                    start: 0x2000,
                    end: 0x3000,
                },
                AddressRange {
                    start: 0x4001,
                    end: 0x5000,
                },
            ],
            requests: vec![CaptureRequest {
                label: "fixture".into(),
                address: 0x2000,
                length: 16,
            }],
            range_check: fragment("range_check", 0, 0xf0),
            slot: CaptureSlot {
                descriptor_offset: 0x200,
                region_getter_offset: 0,
                overlay_getter_offset: 0,
                flash_table_offset: 0,
                flash_record_count: 0,
                region_count: 0,
                overlay_count: 0,
                instruction_windows: vec![fragment("late_data_copy", 0x100, 0x40)],
            },
        });
        (profile, payload)
    }
    #[test]
    fn derives_windows_from_firmware_and_rejects_declaration_changes() {
        let (profile, payload) = fixture();
        let verified = profile.verify_read_windows(&payload).unwrap();
        assert_eq!(
            verified.windows(),
            profile.capture.as_ref().unwrap().windows
        );
        for case in 0..6 {
            let mut changed = profile.clone();
            match case {
                0 => changed.capture = None,
                1 => changed.capture.as_mut().unwrap().family = "unknown".into(),
                2 => changed.capture.as_mut().unwrap().windows[0].end += 1,
                3 => changed.memory.segments[2].runtime_start += 1,
                4 => changed
                    .capture
                    .as_mut()
                    .unwrap()
                    .slot
                    .instruction_windows
                    .clear(),
                _ => changed.checks.module_sha256 = Some(sha256(b"wrong")),
            }
            assert!(
                changed.verify_read_windows(&payload).is_err(),
                "accepted case {case}"
            );
        }
        for length in [0, 0x44, 0xef] {
            let mut changed = profile.clone();
            let fragment = &mut changed.capture.as_mut().unwrap().range_check;
            fragment.length = length;
            fragment.sha256 = sha256(&payload[..length as usize]);
            assert!(changed.verify_read_windows(&payload).is_err());
        }
        let mut changed = profile.clone();
        let fragment = &mut changed.capture.as_mut().unwrap().slot.instruction_windows[0];
        fragment.length = 0x3c;
        fragment.sha256 = sha256(&payload[0x100..0x13c]);
        assert!(changed.verify_read_windows(&payload).is_err());
        let mut changed = payload.clone();
        changed[36] ^= 1;
        let mut changed_profile = profile.clone();
        changed_profile.checks.module_sha256 = Some(sha256(&changed));
        changed_profile.capture.as_mut().unwrap().range_check.sha256 = sha256(&changed[..0xf0]);
        assert!(changed_profile.verify_read_windows(&changed).is_err());
        let mut changed_profile = profile;
        changed_profile.memory.segments[0].size -= 1;
        changed_profile.memory.segments[1].file_offset -= 1;
        assert!(changed_profile.verify_read_windows(&payload).is_err());
    }
}
