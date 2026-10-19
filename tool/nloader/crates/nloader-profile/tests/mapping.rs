use nloader_profile::*;

fn memory() -> Memory {
    Memory {
        xip_base: Some(4096),
        module_size: Some(512),
        segments: vec![
            MemorySegment {
                file_offset: 0,
                runtime_start: 4096,
                size: 256,
                kind: MemorySegmentKind::Xip,
            },
            MemorySegment {
                file_offset: 256,
                runtime_start: 65536,
                size: 128,
                kind: MemorySegmentKind::Ram,
            },
            MemorySegment {
                file_offset: 416,
                runtime_start: 69632,
                size: 96,
                kind: MemorySegmentKind::Ram,
            },
        ],
        ..Memory::default()
    }
}
#[test]
fn translates_both_directions_and_all_bytes_of_each_segment() {
    let memory = memory();
    for segment in &memory.segments {
        assert_eq!(
            memory.address_to_offset(segment.runtime_start, segment.size),
            Ok(segment.file_offset)
        );
        for index in 0..segment.size {
            assert_eq!(
                memory.offset_to_address(segment.file_offset + index, 1),
                Ok(segment.runtime_start + index)
            );
            assert_eq!(
                memory.address_to_offset(segment.runtime_start + index, 1),
                Ok(segment.file_offset + index)
            );
        }
    }
    assert!(memory.is_xip_range(4096, 256));
    assert!(!memory.is_xip_range(65536, 4));
}
#[test]
fn missing_maps_never_fall_back_to_linear_xip() {
    let mut memory = memory();
    memory.segments.clear();
    assert_eq!(
        memory.address_to_offset(4096, 1),
        Err(MappingError::MissingSegments)
    );
    assert_eq!(
        memory.offset_to_address(0, 1),
        Err(MappingError::MissingSegments)
    );
}
#[test]
fn gaps_boundaries_empty_overflow_and_cross_segment_reads_are_rejected() {
    let memory = memory();
    for (address, length) in [
        (4096, 0),
        (4352, 1),
        (4351, 2),
        (65664, 1),
        (69728, 1),
        (u64::MAX, 2),
    ] {
        assert_eq!(
            memory.address_to_offset(address, length),
            Err(MappingError::Unmapped)
        );
    }
    // File-adjacent segments have different runtime destinations; no read may
    // silently bridge them or use the unmapped padding before the final segment.
    for (offset, length) in [
        (255, 2),
        (384, 1),
        (415, 1),
        (512, 1),
        (0, 0),
        (u64::MAX, 2),
    ] {
        assert_eq!(
            memory.offset_to_address(offset, length),
            Err(MappingError::Unmapped)
        );
    }
}
#[test]
fn rejects_overlap_in_either_coordinate_space_before_any_lookup() {
    for runtime_overlap in [true, false] {
        let mut memory = memory();
        if runtime_overlap {
            memory.segments[1].runtime_start = 4224;
        } else {
            memory.segments[1].file_offset = 128;
        }
        assert_eq!(
            memory.validated_segments(),
            Err(MappingError::Overlap(0, 1))
        );
        // Even a request outside the overlap cannot use an invalid map.
        assert!(memory.address_to_offset(69632, 1).is_err());
        assert!(memory.offset_to_address(416, 1).is_err());
    }
}
#[test]
fn rejects_empty_overflowing_and_out_of_module_segments() {
    let mut map = memory();
    map.segments[1].size = 0;
    assert_eq!(
        map.validated_segments(),
        Err(MappingError::InvalidSegment(1))
    );
    map = memory();
    map.segments[1].runtime_start = u64::MAX - 4;
    assert_eq!(map.validated_segments(), Err(MappingError::Overflow(1)));
    map = memory();
    map.segments[1].file_offset = u64::MAX - 4;
    assert_eq!(map.validated_segments(), Err(MappingError::Overflow(1)));
    map = memory();
    map.segments[2].size = 97;
    assert_eq!(
        map.validated_segments(),
        Err(MappingError::OutsideModule(2))
    );
    map = memory();
    map.segments[0].kind = MemorySegmentKind::Ram;
    assert_eq!(map.validated_segments(), Err(MappingError::XipBaseMismatch));
    map = memory();
    map.xip_base = Some(8192);
    assert_eq!(map.validated_segments(), Err(MappingError::XipBaseMismatch));
}
