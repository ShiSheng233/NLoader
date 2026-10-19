use crate::{AddressRange, Memory};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySegmentKind {
    Xip,
    Ram,
}

/// A payload byte span and its load destination. RAM means initialized data,
/// not proof that a RAM allocation is owned or executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySegment {
    pub file_offset: u64,
    pub runtime_start: u64,
    pub size: u64,
    pub kind: MemorySegmentKind,
}
impl MemorySegment {
    pub fn runtime_range(&self) -> Option<AddressRange> {
        Some(AddressRange {
            start: self.runtime_start,
            end: self.runtime_start.checked_add(self.size)?,
        })
    }
    pub fn file_range(&self) -> Option<AddressRange> {
        Some(AddressRange {
            start: self.file_offset,
            end: self.file_offset.checked_add(self.size)?,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MappingError {
    #[error("explicit memory segments are missing")]
    MissingSegments,
    #[error("module size or XIP base is missing")]
    Missing,
    #[error("module size and aligned XIP base must be nonzero")]
    InvalidModule,
    #[error("segment {0} is empty or has an invalid runtime base")]
    InvalidSegment(usize),
    #[error("segment {0} address or file extent overflows")]
    Overflow(usize),
    #[error("segment {0} exceeds the module payload length")]
    OutsideModule(usize),
    #[error("segments {0} and {1} overlap in runtime addresses or file bytes")]
    Overlap(usize, usize),
    #[error("XIP base must match an XIP segment starting at payload offset zero")]
    XipBaseMismatch,
    #[error(
        "request must be nonempty, non-overflowing and entirely contained in one mapped segment"
    )]
    Unmapped,
}
impl Memory {
    /// Validate both coordinate spaces before exposing any mapping. Gaps are
    /// allowed; aliases and overlapping file bytes are deliberately unsupported.
    pub fn validated_segments(&self) -> Result<Vec<MemorySegment>, MappingError> {
        let size = self.module_size.ok_or(MappingError::Missing)?;
        let base = self.xip_base.ok_or(MappingError::Missing)?;
        if size == 0 || base == 0 || base % 4 != 0 {
            return Err(MappingError::InvalidModule);
        }
        if self.segments.is_empty() {
            return Err(MappingError::MissingSegments);
        }
        let segments = self.segments.clone();
        for (index, segment) in segments.iter().enumerate() {
            if segment.size == 0 || segment.runtime_start == 0 {
                return Err(MappingError::InvalidSegment(index));
            }
            let runtime = segment
                .runtime_range()
                .ok_or(MappingError::Overflow(index))?;
            let file = segment.file_range().ok_or(MappingError::Overflow(index))?;
            if file.end > size {
                return Err(MappingError::OutsideModule(index));
            }
            for (other_index, other) in segments[..index].iter().enumerate() {
                // Previous segments have already passed overflow validation.
                if runtime.overlaps(
                    &other
                        .runtime_range()
                        .ok_or(MappingError::Overflow(other_index))?,
                ) || file.overlaps(
                    &other
                        .file_range()
                        .ok_or(MappingError::Overflow(other_index))?,
                ) {
                    return Err(MappingError::Overlap(other_index, index));
                }
            }
        }
        if !segments.iter().any(|segment| {
            segment.kind == MemorySegmentKind::Xip
                && segment.file_offset == 0
                && segment.runtime_start == base
        }) {
            return Err(MappingError::XipBaseMismatch);
        }
        Ok(segments)
    }
    pub fn segment_for_address(
        &self,
        address: u64,
        length: u64,
    ) -> Result<MemorySegment, MappingError> {
        self.validated_segments()?
            .into_iter()
            .find(|segment| {
                segment
                    .runtime_range()
                    .is_some_and(|range| range.contains(address, length))
            })
            .ok_or(MappingError::Unmapped)
    }
    pub fn address_to_offset(&self, address: u64, length: u64) -> Result<u64, MappingError> {
        let segment = self.segment_for_address(address, length)?;
        segment
            .file_offset
            .checked_add(address - segment.runtime_start)
            .ok_or(MappingError::Unmapped)
    }
    pub fn offset_to_address(&self, offset: u64, length: u64) -> Result<u64, MappingError> {
        let segment = self
            .validated_segments()?
            .into_iter()
            .find(|segment| {
                segment
                    .file_range()
                    .is_some_and(|range| range.contains(offset, length))
            })
            .ok_or(MappingError::Unmapped)?;
        segment
            .runtime_start
            .checked_add(offset - segment.file_offset)
            .ok_or(MappingError::Unmapped)
    }
    pub fn is_xip_range(&self, address: u64, length: u64) -> bool {
        self.segment_for_address(address, length)
            .is_ok_and(|segment| segment.kind == MemorySegmentKind::Xip)
    }
}
