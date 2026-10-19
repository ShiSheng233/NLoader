//! General v2 program packaging tests (PLAN §6.3 M2-T4). Package bytes are
//! checked by an independent parser written from the PLAN table, not by
//! reusing the packager's code. Clang-dependent end-to-end coverage is
//! marked ignored.

use nloader_build::linker::ObjectInput;
use nloader_build::program::link::link;
use nloader_build::program::manifest::manifest_line;
use nloader_build::program::package::package;
use nloader_build::program::{
    ManifestEntry, ProgramDeclaration, ProgramKind, Relocation, HEADER_SIZE, KIND_FOREGROUND,
    KIND_RESOURCE_EXTENSION, MAX_ABI_VERSION, RELOCATION_ENTRY_BYTES, RELOCATION_KIND_ABS64,
    RELOCATION_KIND_ABS64_DATA, RELOCATION_KIND_ADRP,
};
use object::write::{
    Object as WriteObject, Relocation as ObjectRelocation, SectionId, Symbol, SymbolId,
};
use object::{
    elf, Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolFlags,
    SymbolKind, SymbolScope,
};

const ADRP: u32 = 0x9000_0000;
const ADD: u32 = 0x9100_0000;
const LDST64: u32 = 0xf940_0000;
const B: u32 = 0x1400_0000;

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn object() -> WriteObject<'static> {
    WriteObject::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little)
}

fn section(
    object: &mut WriteObject<'_>,
    name: &[u8],
    kind: SectionKind,
    data: &[u8],
    align: u64,
) -> SectionId {
    let id = object.add_section(Vec::new(), name.to_vec(), kind);
    if kind == SectionKind::UninitializedData {
        object.section_mut(id).append_bss(data.len() as u64, align);
    } else {
        object.section_mut(id).append_data(data, align);
    }
    id
}

fn symbol(
    object: &mut WriteObject<'_>,
    name: &str,
    section: SectionId,
    value: u64,
    size: u64,
    kind: SymbolKind,
) -> SymbolId {
    object.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value,
        size,
        kind,
        scope: SymbolScope::Linkage,
        weak: false,
        section: object::write::SymbolSection::Section(section),
        flags: SymbolFlags::None,
    })
}

fn add_reloc(
    object: &mut WriteObject<'_>,
    section: SectionId,
    offset: u64,
    r_type: u32,
    symbol: SymbolId,
    addend: i64,
) {
    object
        .add_relocation(
            section,
            ObjectRelocation {
                offset,
                symbol,
                addend,
                flags: RelocationFlags::Elf { r_type },
            },
        )
        .unwrap();
}

fn input(name: &str, object: WriteObject<'_>) -> ObjectInput {
    ObjectInput {
        name: name.into(),
        bytes: object.write().unwrap(),
    }
}

/// One object covering every supported relocation class:
/// .text references the data table (ADRP+ADD), the BSS buffer (ADRP+LDR),
/// its own read-only data (ADRP), and branches back to its entry (B);
/// .data holds a pointer to the entry (ABS64).
fn app_object() -> ObjectInput {
    let mut object = object();
    let code = [
        ADRP,   // 0x00: adrp x0, table+0x28 -> kind 0 entry
        ADD,    // 0x04: add x0, x0, :lo12: table+0x28
        ADRP,   // 0x08: adrp x1, buf -> kind 0 entry
        LDST64, // 0x0c: ldr x1, [x1, :lo12: buf]
        ADRP,   // 0x10: adrp x2, msg (same-block, link-time)
        B,      // 0x14: b entry
    ]
    .iter()
    .flat_map(|word| word.to_le_bytes())
    .collect::<Vec<u8>>();
    let code_section = section(&mut object, b".text", SectionKind::Text, &code, 4);
    let rodata = section(
        &mut object,
        b".rodata",
        SectionKind::ReadOnlyData,
        b"message\0",
        8,
    );
    let data = section(&mut object, b".data", SectionKind::Data, &[0u8; 16], 8);
    let bss = section(
        &mut object,
        b".bss",
        SectionKind::UninitializedData,
        &[0u8; 32],
        8,
    );
    let entry = symbol(&mut object, "entry", code_section, 0, 24, SymbolKind::Text);
    let table = symbol(&mut object, "table", data, 0, 16, SymbolKind::Data);
    let buf = symbol(&mut object, "buf", bss, 0, 32, SymbolKind::Data);
    let msg = symbol(&mut object, "msg", rodata, 0, 8, SymbolKind::Data);
    add_reloc(
        &mut object,
        code_section,
        0x00,
        elf::R_AARCH64_ADR_PREL_PG_HI21,
        table,
        0x28,
    );
    add_reloc(
        &mut object,
        code_section,
        0x04,
        elf::R_AARCH64_ADD_ABS_LO12_NC,
        table,
        0x28,
    );
    add_reloc(
        &mut object,
        code_section,
        0x08,
        elf::R_AARCH64_ADR_PREL_PG_HI21,
        buf,
        0,
    );
    add_reloc(
        &mut object,
        code_section,
        0x0c,
        elf::R_AARCH64_LDST64_ABS_LO12_NC,
        buf,
        0,
    );
    add_reloc(
        &mut object,
        code_section,
        0x10,
        elf::R_AARCH64_ADR_PREL_PG_HI21,
        msg,
        0,
    );
    add_reloc(
        &mut object,
        code_section,
        0x14,
        elf::R_AARCH64_JUMP26,
        entry,
        0,
    );
    add_reloc(&mut object, data, 0x08, elf::R_AARCH64_ABS64, entry, 0);
    input("app.o", object)
}

#[test]
fn links_two_segments_and_emits_the_two_table_kinds() {
    let linked = link(&[app_object()], "entry").unwrap();

    // Placement: .text at 0, .rodata right after, .data at 0, .bss after data.
    assert_eq!(linked.image.len(), 32); // 24 bytes code + 8 bytes rodata
    assert_eq!(linked.data.len(), 16);
    assert_eq!(linked.bss_size, 32);
    assert_eq!(linked.entry, 0);

    let table = &linked
        .relocations
        .iter()
        .map(|entry| (entry.kind, entry.offset, entry.target))
        .collect::<Vec<_>>();
    // ADRP page patches against the data block: table+0x28 and buf (which
    // sits 16 bytes past the data, where BSS is zeroed).
    assert_eq!(
        table,
        &[
            (RELOCATION_KIND_ADRP, 0x00, 0x28),
            (RELOCATION_KIND_ADRP, 0x08, 16),
            (RELOCATION_KIND_ABS64, 0x08, 0),
        ]
    );

    // The kind-0 ADRPs stay untouched; their paired constants are applied.
    assert_eq!(word(&linked.image, 0x00), ADRP);
    assert_eq!(word(&linked.image, 0x08), ADRP);
    assert_eq!(word(&linked.image, 0x04), ADD | (0x28 << 10));
    // Load-store imm12 is scaled by the 8-byte access width: 16/8 = 2.
    assert_eq!(word(&linked.image, 0x0c), LDST64 | (2 << 10));
    // Same-block ADRP: page difference is zero at this size.
    assert_eq!(word(&linked.image, 0x10), ADRP);
    // B back to the entry: delta -0x14 -> -5 instructions.
    assert_eq!(
        word(&linked.image, 0x14),
        B | (0x03ff_ffff & (-5i32 as u32))
    );
    // The data pointer is filled by the loader, so the bytes stay zero.
    assert_eq!(&linked.data[8..16], &[0u8; 8]);

    // The link is deterministic.
    let again = link(&[app_object()], "entry").unwrap();
    assert_eq!(linked.image, again.image);
    assert_eq!(linked.data, again.data);
    assert_eq!(linked.bss_size, again.bss_size);
    assert_eq!(linked.relocations, again.relocations);
}

#[test]
fn data_pointers_cover_initialized_data_and_bss_without_cross_segment_conflicts() {
    let mut object = object();
    let code = section(
        &mut object,
        b".text",
        SectionKind::Text,
        &[
            ADRP.to_le_bytes(),
            ADD.to_le_bytes(),
            0xd65f03c0u32.to_le_bytes(),
        ]
        .concat(),
        4,
    );
    let data = section(&mut object, b".data", SectionKind::Data, &[0u8; 24], 8);
    let bss = section(
        &mut object,
        b".bss",
        SectionKind::UninitializedData,
        &[0u8; 16],
        8,
    );
    let entry = symbol(&mut object, "entry", code, 0, 12, SymbolKind::Text);
    let table = symbol(&mut object, "table", data, 0, 24, SymbolKind::Data);
    let zeroes = symbol(&mut object, "zeroes", bss, 0, 16, SymbolKind::Data);
    add_reloc(
        &mut object,
        code,
        0,
        elf::R_AARCH64_ADR_PREL_PG_HI21,
        table,
        0,
    );
    add_reloc(
        &mut object,
        code,
        4,
        elf::R_AARCH64_ADD_ABS_LO12_NC,
        table,
        0,
    );
    add_reloc(&mut object, data, 0, elf::R_AARCH64_ABS64, table, 16);
    add_reloc(&mut object, data, 8, elf::R_AARCH64_ABS64, zeroes, 4);
    add_reloc(&mut object, data, 16, elf::R_AARCH64_ABS64, entry, 0);
    let linked = link(&[input("data_pointers.o", object)], "entry").unwrap();
    let entries: Vec<_> = linked
        .relocations
        .iter()
        .map(|r| (r.kind, r.offset, r.target))
        .collect();
    assert_eq!(entries, vec![(0, 0, 0), (2, 0, 16), (2, 8, 28), (1, 16, 0)]);
    let declaration = ProgramDeclaration {
        image: linked.image,
        data: linked.data,
        bss_size: linked.bss_size as u32,
        entry_offset: linked.entry as u32,
        relocations: linked.relocations,
        abi_version: 2,
        metadata: None,
    };
    let bytes = package(ProgramKind::Foreground, &declaration).unwrap();
    assert_eq!(
        bytes.len(),
        HEADER_SIZE + 4 * RELOCATION_ENTRY_BYTES + 12 + 24
    );
    for (record, expected) in bytes[HEADER_SIZE..HEADER_SIZE + 48]
        .chunks_exact(12)
        .zip(entries)
    {
        assert_eq!(word(record, 0), expected.1);
        assert_eq!(word(record, 4), expected.2);
        assert_eq!(word(record, 8), expected.0);
    }
    for (offset, target) in [(1, 0), (24, 0), (8, 40)] {
        let mut bad = declaration.clone();
        bad.relocations[2] = Relocation {
            kind: RELOCATION_KIND_ABS64_DATA,
            offset,
            target,
        };
        assert!(package(ProgramKind::Foreground, &bad).is_err());
    }
    // Different kinds still write the same data segment and cannot overlap.
    let mut overlapping = declaration.clone();
    overlapping.relocations.push(Relocation {
        kind: RELOCATION_KIND_ABS64,
        offset: 8,
        target: 0,
    });
    assert!(package(ProgramKind::Foreground, &overlapping).is_err());
}

#[test]
fn link_rejects_unsupported_relocation_classes() {
    let rejected = |build: fn() -> ObjectInput| {
        let error = link(&[build()], "entry").unwrap_err().to_string();
        assert!(!error.is_empty());
        error
    };

    // Absolute pointer inside the image cannot be relocated at load.
    rejected(|| {
        let mut object = object();
        let code = section(&mut object, b".text", SectionKind::Text, &[0u8; 8], 4);
        let data = section(&mut object, b".data", SectionKind::Data, &[0u8; 8], 8);
        symbol(&mut object, "entry", code, 0, 8, SymbolKind::Text);
        let table = symbol(&mut object, "table", data, 0, 8, SymbolKind::Data);
        add_reloc(&mut object, code, 0, elf::R_AARCH64_ABS64, table, 0);
        input("abs.o", object)
    });

    // Data storage only takes ABS64 pointers into the image.
    rejected(|| {
        let mut object = object();
        let code = section(
            &mut object,
            b".text",
            SectionKind::Text,
            &[ADRP.to_le_bytes(), 0u32.to_le_bytes()].concat(),
            4,
        );
        let data = section(&mut object, b".data", SectionKind::Data, &[0u8; 8], 8);
        let entry = symbol(&mut object, "entry", code, 0, 8, SymbolKind::Text);
        symbol(&mut object, "table", data, 0, 8, SymbolKind::Data);
        add_reloc(
            &mut object,
            data,
            0,
            elf::R_AARCH64_ADR_PREL_PG_HI21,
            entry,
            0,
        );
        input("adrp_data.o", object)
    });

    // A branch must stay inside the image.
    rejected(|| {
        let mut object = object();
        let code = section(
            &mut object,
            b".text",
            SectionKind::Text,
            &B.to_le_bytes(),
            4,
        );
        let data = section(&mut object, b".data", SectionKind::Data, &[0u8; 8], 8);
        symbol(&mut object, "entry", code, 0, 4, SymbolKind::Text);
        let table = symbol(&mut object, "table", data, 0, 8, SymbolKind::Data);
        add_reloc(&mut object, code, 0, elf::R_AARCH64_JUMP26, table, 0);
        input("branch_data.o", object)
    });

    // Undefined symbols have no firmware to fall back on.
    rejected(|| {
        let mut object = object();
        let code = section(
            &mut object,
            b".text",
            SectionKind::Text,
            &[ADRP.to_le_bytes(), 0u32.to_le_bytes()].concat(),
            4,
        );
        symbol(&mut object, "entry", code, 0, 8, SymbolKind::Text);
        let external = object.add_symbol(Symbol {
            name: b"firmware_only".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Unknown,
            scope: SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
        add_reloc(
            &mut object,
            code,
            0,
            elf::R_AARCH64_ADR_PREL_PG_HI21,
            external,
            0,
        );
        input("undef.o", object)
    });

    // BSS holds no file bytes, so nothing can be relocated into it.
    rejected(|| {
        let mut object = object();
        let code = section(
            &mut object,
            b".text",
            SectionKind::Text,
            &B.to_le_bytes(),
            4,
        );
        let bss = section(
            &mut object,
            b".bss",
            SectionKind::UninitializedData,
            &[0u8; 8],
            8,
        );
        symbol(&mut object, "entry", code, 0, 4, SymbolKind::Text);
        let buf = symbol(&mut object, "buf", bss, 0, 8, SymbolKind::Data);
        add_reloc(&mut object, code, 0, elf::R_AARCH64_JUMP26, buf, 0);
        input("bss_reloc.o", object)
    });

    // Unknown relocation kinds are refused, not skipped.
    rejected(|| {
        let mut object = object();
        let code = section(&mut object, b".text", SectionKind::Text, &[0u8; 8], 4);
        let data = section(&mut object, b".data", SectionKind::Data, &[0u8; 8], 8);
        symbol(&mut object, "entry", code, 0, 8, SymbolKind::Text);
        let table = symbol(&mut object, "table", data, 0, 8, SymbolKind::Data);
        add_reloc(&mut object, code, 0, elf::R_AARCH64_ABS32, table, 0);
        input("abs32.o", object)
    });

    // Two kind-0 entries at one offset would fight at load.
    rejected(|| {
        let mut object = object();
        let code = section(
            &mut object,
            b".text",
            SectionKind::Text,
            &[ADRP.to_le_bytes(), 0u32.to_le_bytes()].concat(),
            4,
        );
        let data = section(&mut object, b".data", SectionKind::Data, &[0u8; 8], 8);
        symbol(&mut object, "entry", code, 0, 8, SymbolKind::Text);
        let table = symbol(&mut object, "table", data, 0, 8, SymbolKind::Data);
        add_reloc(
            &mut object,
            code,
            0,
            elf::R_AARCH64_ADR_PREL_PG_HI21,
            table,
            0,
        );
        add_reloc(
            &mut object,
            code,
            0,
            elf::R_AARCH64_ADR_PREL_PG_HI21,
            table,
            0,
        );
        input("dup.o", object)
    });
}

/// Independent CRC32 written from the IEEE definition in the PLAN, used to
/// re-check the packager's fields.
fn reference_crc32(bytes: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (index, entry) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        for _ in 0..8 {
            value = if value & 1 != 0 {
                0xedb8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
        }
        *entry = value;
    }
    let mut crc = !0u32;
    for byte in bytes {
        crc = table[((crc ^ u32::from(*byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

fn sample() -> (ProgramDeclaration, ProgramKind) {
    // A 16-byte image whose first instruction is an ADRP, 8 bytes of data,
    // and the matching relocation pair of the table kinds.
    let mut image = vec![0u8; 16];
    image[..4].copy_from_slice(&ADRP.to_le_bytes());
    image[4..8].copy_from_slice(&ADD.to_le_bytes());
    let relocations = vec![
        Relocation {
            offset: 0,
            target: 0x20,
            kind: RELOCATION_KIND_ADRP,
        },
        Relocation {
            offset: 8,
            target: 0,
            kind: RELOCATION_KIND_ABS64,
        },
    ];
    (
        ProgramDeclaration {
            image,
            data: vec![0xa5; 16],
            bss_size: 32,
            entry_offset: 4,
            relocations,
            abi_version: 2,
            metadata: None,
        },
        ProgramKind::Foreground,
    )
}

/// A program that describes itself is header version
/// 3: the metadata block sits between the header and the relocation table,
/// 0x28 holds its length and 0x2C its CRC32, and everything after it is
/// laid out exactly as in version 2.
#[test]
fn a_described_program_is_version_3_with_its_block_after_the_header() {
    let (mut declaration, kind) = sample();
    let plain = package(kind, &declaration).unwrap();
    let meta = {
        let meta = nloader_build::program::ProgramMeta {
            id: "lvui".into(),
            kind: ProgramKind::Foreground,
            display_name: "New UI".into(),
            file: "APPS/LVUI.NLB".into(),
            min_abi: 5,
            abi_version: Some(5),
            entry_symbol: None,
            models: Some("z6iii/2.00".into()),
            settings: Vec::new(),
            describe: true,
            description: nloader_build::program::build::ProgramDescription {
                role: Some("shell".into()),
                memory: Some("6M".into()),
                ..Default::default()
            },
        };
        nloader_build::program::build::metadata_block(&meta).unwrap()
    };
    let text = String::from_utf8(meta.clone()).unwrap();
    assert!(text.starts_with("id=lvui\nkind=shell\nname=New UI\n"));
    assert!(text.contains("\nmin_abi=5\ntargets=z6iii/2.00\nmemory=6M\n"));
    assert_eq!(meta.len() % 8, 0);
    declaration.metadata = Some(meta.clone());
    let bytes = package(kind, &declaration).unwrap();
    let field = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 3);
    assert_eq!(field(0x28) as usize, meta.len());
    let mut crc = u32::MAX;
    for byte in &meta {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    assert_eq!(field(0x2C), !crc);
    assert_eq!(&bytes[64..64 + meta.len()], meta.as_slice());
    assert_eq!(&bytes[64 + meta.len()..], &plain[64..]);
    assert_eq!(&bytes[8..0x28], &plain[8..0x28]);
    assert_eq!(&bytes[0x30..64], &plain[0x30..64]);
    // a role that does not fit the kind is refused
    let bad = nloader_build::program::ProgramMeta {
        id: "x".into(),
        kind: ProgramKind::ResourceExtension,
        display_name: "X".into(),
        file: "APPS/X.NLB".into(),
        min_abi: 5,
        abi_version: None,
        entry_symbol: None,
        models: None,
        settings: Vec::new(),
        describe: true,
        description: nloader_build::program::build::ProgramDescription {
            role: Some("shell".into()),
            ..Default::default()
        },
    };
    assert!(nloader_build::program::build::metadata_block(&bad).is_err());
}

#[test]
fn packages_deterministic_bytes_matching_an_independent_parse() {
    let (declaration, kind) = sample();
    let bytes = package(kind, &declaration).unwrap();
    let again = package(kind, &declaration).unwrap();
    assert_eq!(bytes, again);

    // Independent parse straight from the PLAN §6.3 field table.
    let reloc_table = &bytes[HEADER_SIZE..HEADER_SIZE + RELOCATION_ENTRY_BYTES * 2];
    let image_start = HEADER_SIZE + reloc_table.len();
    let image = &bytes[image_start..image_start + 16];
    let data = &bytes[image_start + 16..];
    let field = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());

    assert_eq!(&bytes[..4], b"NPLD");
    assert_eq!(u16::from_le_bytes(bytes[4..6].try_into().unwrap()), 2);
    assert_eq!(u16::from_le_bytes(bytes[6..8].try_into().unwrap()), 64);
    assert_eq!(field(0x08), 0); // flags: general
    assert_eq!(field(0x0c), 16); // image_size
    assert_eq!(field(0x10), 32); // bss_size
    assert_eq!(field(0x14), 4); // entry_offset
    assert_eq!(field(0x18), 2); // abi_version
    assert_eq!(field(0x1c), reference_crc32(image));
    assert_eq!(field(0x20), KIND_FOREGROUND);
    assert_eq!(field(0x24), (RELOCATION_ENTRY_BYTES * 2) as u32);
    assert_eq!(field(0x28), 0); // reserved
    assert_eq!(field(0x2c), 0); // reserved
    assert_eq!(field(0x30), reference_crc32(data));
    assert_eq!(field(0x34), reference_crc32(reloc_table));
    assert_eq!(&bytes[0x38..0x40], &[0u8; 8]); // reserved
    assert_eq!(image, declaration.image.as_slice());
    assert_eq!(data, declaration.data.as_slice());
    for (index, entry) in [
        (0u32, 0x20u32, RELOCATION_KIND_ADRP),
        (8, 0, RELOCATION_KIND_ABS64),
    ]
    .iter()
    .enumerate()
    {
        let record = &reloc_table[index * 12..][..12];
        assert_eq!(u32::from_le_bytes(record[..4].try_into().unwrap()), entry.0);
        assert_eq!(
            u32::from_le_bytes(record[4..8].try_into().unwrap()),
            entry.1
        );
        assert_eq!(
            u32::from_le_bytes(record[8..12].try_into().unwrap()),
            entry.2
        );
    }

    // The resource-extension kind keeps the same layout with kind 1.
    let (declaration, _) = sample();
    let bytes = package(ProgramKind::ResourceExtension, &declaration).unwrap();
    assert_eq!(
        u32::from_le_bytes(bytes[0x20..0x24].try_into().unwrap()),
        KIND_RESOURCE_EXTENSION
    );
}

#[test]
fn packager_rejects_invalid_declarations() {
    let reject = |mutate: fn(&mut ProgramDeclaration)| {
        let (mut declaration, kind) = sample();
        mutate(&mut declaration);
        assert!(package(kind, &declaration).is_err());
    };

    reject(|declaration| declaration.entry_offset = 3); // misaligned
    reject(|declaration| declaration.entry_offset = 16); // past the image
    reject(|declaration| declaration.abi_version = MAX_ABI_VERSION + 1);
    reject(|declaration| declaration.abi_version = 0);
    reject(|declaration| declaration.abi_version = 3);
    reject(|declaration| declaration.image = Vec::new());
    reject(|declaration| declaration.bss_size = 0x20_0000 - 7); // data + BSS over the block
    reject(|declaration| {
        declaration.relocations.push(Relocation {
            offset: 0,
            target: 0,
            kind: 7,
        })
    });
    reject(|declaration| declaration.relocations[0].offset = 1); // misaligned ADRP
    reject(|declaration| declaration.relocations[0].offset = 16); // past the image
    reject(|declaration| declaration.relocations[0].target = 49); // past data + BSS
    reject(|declaration| {
        declaration.image[0..4].copy_from_slice(&0xd65f_03c0u32.to_le_bytes()) // not an ADRP
    });
    reject(|declaration| declaration.relocations[1].offset = 16); // word past the data
    reject(|declaration| declaration.relocations[1].offset = 4); // not 8-byte aligned
    reject(|declaration| declaration.relocations[1].target = 16); // past the image
    reject(|declaration| {
        declaration.relocations.push(declaration.relocations[0]);
    });
}

#[test]
fn excessive_relocation_count_is_refused_before_emitting_a_file() {
    use nloader_build::program::package::MAX_RELOCATION_BYTES;
    let (mut declaration, kind) = sample();
    declaration.relocations =
        vec![declaration.relocations[0]; MAX_RELOCATION_BYTES / RELOCATION_ENTRY_BYTES + 1];
    let error = package(kind, &declaration).unwrap_err();
    assert!(error
        .to_string()
        .contains("relocation table exceeds the 1 MiB"));
}

#[test]
fn manifest_lines_match_the_core_grammar() {
    let entry = ManifestEntry {
        id: "hello".into(),
        kind: ProgramKind::Foreground,
        display_name: "Hello".into(),
        file: "APPS/HELLO.NLB".into(),
        min_abi: 2,
        models: Some("z8/3.11".into()),
        shell: false,
    };
    assert_eq!(
        manifest_line(&entry).unwrap(),
        "hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11"
    );
    /* A shell is a foreground program with the shell mark; an extension
     * never is one. */
    let shell = ManifestEntry {
        shell: true,
        ..entry.clone()
    };
    assert_eq!(
        manifest_line(&shell).unwrap(),
        "hello | shell | Hello | APPS/HELLO.NLB | 2 | z8/3.11"
    );
    let no_models = ManifestEntry {
        models: None,
        ..entry.clone()
    };
    assert_eq!(
        manifest_line(&no_models).unwrap(),
        "hello | foreground | Hello | APPS/HELLO.NLB | 2"
    );
    let extension = ManifestEntry {
        id: "menu_extension".into(),
        kind: ProgramKind::ResourceExtension,
        display_name: "Menu extension".into(),
        file: "APPS/MENU.NLB".into(),
        min_abi: 2,
        models: Some("z8/3.11".into()),
        shell: false,
    };
    assert_eq!(
        manifest_line(&extension).unwrap(),
        "menu_extension | resource_extension | Menu extension | APPS/MENU.NLB | 2 | z8/3.11"
    );
    assert!(manifest_line(&ManifestEntry {
        shell: true,
        ..extension.clone()
    })
    .is_err());

    let reject = |mutate: fn(&mut ManifestEntry)| {
        let mut entry = entry.clone();
        mutate(&mut entry);
        assert!(manifest_line(&entry).is_err());
    };
    reject(|entry| entry.id = "has space".into());
    reject(|entry| entry.id = "bad|id".into());
    reject(|entry| entry.id = "#comment".into());
    reject(|entry| entry.id = String::from("a").repeat(33));
    reject(|entry| entry.display_name = String::from("x").repeat(25));
    reject(|entry| entry.display_name = "中文名".into());
    reject(|entry| entry.display_name = "Bad | name".into());
    reject(|entry| entry.display_name = "  ".into());
    reject(|entry| entry.display_name = " Hello".into());
    reject(|entry| entry.display_name = "Hello ".into());
    reject(|entry| entry.file = "DATA/HELLO.NLB".into());
    reject(|entry| entry.file = "APPS/".into());
    reject(|entry| entry.file = "APPS/HEL|LO.NLB".into());
    reject(|entry| entry.file = "APPS/..\\EVIL.NLB".into());
    reject(|entry| entry.min_abi = 0);
    reject(|entry| entry.min_abi = MAX_ABI_VERSION + 1);
    reject(|entry| entry.min_abi = 3);
    reject(|entry| entry.models = Some("z8".into()));
    reject(|entry| entry.models = Some("z8/3.11/2".into()));
    reject(|entry| entry.models = Some("z8/3.11|extra".into()));
}

#[test]
fn invalid_manifest_declaration_is_rejected_before_compilation_with_or_without_manifest_output() {
    use nloader_build::program::{build::build, ProgramBuildRequest, ProgramMeta};
    for with_manifest in [false, true] {
        let stage = tempfile::tempdir().unwrap();
        let mut declaration: ProgramMeta = serde_json::from_str(HELLO_DECL).unwrap();
        declaration.display_name = "invalid|name".into();
        let output = stage.path().join("APP.NLB");
        let manifest = stage.path().join("MANIFEST");
        let error = build(&ProgramBuildRequest {
            compiler: "compiler-must-not-run".into(),
            declaration,
            sources: vec![stage.path().join("not-created.c")],
            objects: Vec::new(),
            include_dirs: Vec::new(),
            output: output.clone(),
            manifest_output: with_manifest.then(|| manifest.clone()),
        })
        .unwrap_err();
        assert!(error.to_string().contains("display_name"), "{error}");
        assert!(!output.exists() && !manifest.exists());
    }
}

const HELLO_DECL: &str = r#"{
  "id": "hello",
  "kind": "foreground",
  "display_name": "Hello",
  "file": "APPS/HELLO.NLB",
  "min_abi": 2,
  "models": "z8/3.11"
}"#;

const CRT0: &str = include_str!("../../../../../sdk/crt0.s");
const HELLO_C: &str = include_str!("../../../../../sdk/examples/hello/hello.c");

#[test]
#[ignore = "requires clang with an AArch64 backend"]
fn builds_the_hello_example_end_to_end() {
    let stage = tempfile::tempdir().unwrap();
    std::fs::write(stage.path().join("crt0.s"), CRT0).unwrap();
    std::fs::write(stage.path().join("hello.c"), HELLO_C).unwrap();
    let declaration = stage.path().join("hello.json");
    std::fs::write(&declaration, HELLO_DECL).unwrap();
    let output = stage.path().join("HELLO.NLB");
    let manifest = stage.path().join("MANIFEST");

    let meta: nloader_build::program::ProgramMeta =
        serde_json::from_str(&std::fs::read_to_string(&declaration).unwrap()).unwrap();
    let report =
        nloader_build::program::build::build(&nloader_build::program::ProgramBuildRequest {
            compiler: "clang".into(),
            declaration: meta,
            sources: vec![stage.path().join("crt0.s"), stage.path().join("hello.c")],
            objects: Vec::new(),
            include_dirs: vec![
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../sdk")
            ],
            output: output.clone(),
            manifest_output: Some(manifest.clone()),
        })
        .unwrap_or_else(|error| panic!("hello build failed: {error}"));

    assert_eq!(report.kind, ProgramKind::Foreground);
    assert_eq!(report.id, "hello");
    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(report.sha256, nloader_profile::sha256(&bytes));

    // Independent parse, same semantics as the core loader's checks.
    let field = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let image_size = field(0x0c) as usize;
    let reloc_size = field(0x24) as usize;
    assert_eq!(&bytes[..4], b"NPLD");
    assert_eq!(u16::from_le_bytes(bytes[4..6].try_into().unwrap()), 2);
    assert_eq!(u16::from_le_bytes(bytes[6..8].try_into().unwrap()), 64);
    assert_eq!(field(0x08), 0);
    assert_eq!(field(0x20), KIND_FOREGROUND);
    assert_eq!(field(0x18), MAX_ABI_VERSION);
    assert_eq!(field(0x28), 0); // reserved
    assert_eq!(field(0x2c), 0); // reserved
    assert_eq!(&bytes[0x38..0x40], &[0u8; 8]); // reserved
    let image_start = HEADER_SIZE + reloc_size;
    let image = &bytes[image_start..image_start + image_size];
    let data = &bytes[image_start + image_size..];
    assert_eq!(field(0x1c), reference_crc32(image));
    assert_eq!(field(0x30), reference_crc32(data));
    assert_eq!(
        field(0x34),
        reference_crc32(&bytes[HEADER_SIZE..image_start])
    );

    // The file entry is the crt0 stub, a branch to the foreground entry.
    let entry_offset = field(0x14) as usize;
    assert_eq!(word(image, entry_offset) & 0xfc00_0000, B);

    // Every kind-0 entry points at a real ADRP inside the image; kind-1
    // entries stay inside the data.
    for record in bytes[HEADER_SIZE..image_start].chunks_exact(12) {
        let offset = u32::from_le_bytes(record[..4].try_into().unwrap()) as usize;
        let kind = u32::from_le_bytes(record[8..12].try_into().unwrap());
        match kind {
            RELOCATION_KIND_ADRP => {
                assert_eq!(word(image, offset) & 0x9f00_0000, ADRP);
            }
            RELOCATION_KIND_ABS64 => {
                assert!(offset % 8 == 0 && offset + 8 <= data.len());
            }
            other => panic!("unknown kind {other}"),
        }
    }

    let manifest_text = std::fs::read_to_string(&manifest).unwrap();
    assert_eq!(
        manifest_text,
        "# id | kind | 显示名 | 文件 | min_abi | 支持机型/固件（可省）\n\
         hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11\n"
    );

    // A second full build into a new file is byte-identical, and an existing
    // output is never replaced.
    let meta: nloader_build::program::ProgramMeta =
        serde_json::from_str(&std::fs::read_to_string(&declaration).unwrap()).unwrap();
    let rebuilt = stage.path().join("HELLO-2.NLB");
    let report =
        nloader_build::program::build::build(&nloader_build::program::ProgramBuildRequest {
            compiler: "clang".into(),
            declaration: meta.clone(),
            sources: vec![stage.path().join("crt0.s"), stage.path().join("hello.c")],
            objects: Vec::new(),
            include_dirs: vec![
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../sdk")
            ],
            output: rebuilt,
            manifest_output: None,
        })
        .unwrap_or_else(|error| panic!("deterministic rebuild failed: {error}"));
    assert_eq!(report.sha256, nloader_profile::sha256(&bytes));
    assert!(
        nloader_build::program::build::build(&nloader_build::program::ProgramBuildRequest {
            compiler: "clang".into(),
            declaration: meta,
            sources: vec![stage.path().join("crt0.s"), stage.path().join("hello.c")],
            objects: Vec::new(),
            include_dirs: vec![
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../sdk")
            ],
            output: output.clone(),
            manifest_output: None,
        })
        .is_err()
    );
}

/// The SDK and core tables must preserve every pre-existing AArch64 offset
/// when adding the deferred registration callback. Exercise the actual SDK
/// extension entry on the host as well, without firmware services.
#[test]
#[ignore = "requires clang on a 64-bit host"]
fn deferred_menu_extension_preserves_the_program_abi() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let stage = tempfile::tempdir().unwrap();
    let source = stage.path().join("menu_abi.c");
    let binary = stage.path().join("menu_abi");
    std::fs::write(
        &source,
        r#"
#include <stddef.h>
#include "nlr.h"
#undef NLR_ABI4_TYPES
#define nlr_api nlr_core_api
#define nlr_menu_test_item nlr_core_menu_test_item
#define nlr_surface nlr_core_surface
#define nlr_key_event nlr_core_key_event
#define nlr_dirent nlr_core_dirent
#define nlr_row nlr_core_row
#define nlr_app_main nlr_core_app_main
#define nlr_extension_init nlr_core_extension_init
#include "nlr/api.h"
#undef nlr_extension_init
#undef nlr_app_main
#undef nlr_menu_test_item
#undef nlr_surface
#undef nlr_key_event
#undef nlr_dirent
#undef nlr_row
#undef nlr_api

#define CHECK_OFFSET(field, offset) \
    _Static_assert(offsetof(struct nlr_api, field) == offset, "SDK " #field); \
    _Static_assert(offsetof(struct nlr_core_api, field) == offset, "core " #field)
CHECK_OFFSET(abi, 0);
CHECK_OFFSET(mem_alloc, 8);
CHECK_OFFSET(mem_free, 16);
CHECK_OFFSET(fs_open, 24);
CHECK_OFFSET(fs_read, 32);
CHECK_OFFSET(fs_seek, 40);
CHECK_OFFSET(fs_close, 48);
CHECK_OFFSET(ui_draw_text, 56);
CHECK_OFFSET(ui_present, 64);
CHECK_OFFSET(gfx_begin, 72);
CHECK_OFFSET(gfx_end, 80);
CHECK_OFFSET(input_poll, 88);
CHECK_OFFSET(input_raw, 96);
CHECK_OFFSET(log, 104);
CHECK_OFFSET(exit, 112);
CHECK_OFFSET(menu_register, 120);
CHECK_OFFSET(time_ms, 128);
CHECK_OFFSET(sleep_ms, 136);
CHECK_OFFSET(fs_dir, 144);
CHECK_OFFSET(ui_list, 152);
CHECK_OFFSET(setting, 160);
CHECK_OFFSET(fs_write, 168);
CHECK_OFFSET(code_patch, 176);
CHECK_OFFSET(code_hook, 184);
CHECK_OFFSET(code_unhook, 192);
CHECK_OFFSET(ui_rows, 200);
CHECK_OFFSET(ui_input, 208);
CHECK_OFFSET(ui_caution, 216);
CHECK_OFFSET(queue_wait, 224);
CHECK_OFFSET(timer_start, 232);
CHECK_OFFSET(timer_stop, 240);
CHECK_OFFSET(input_route, 248);
CHECK_OFFSET(input_held, 256);
CHECK_OFFSET(screen_claim, 264);
CHECK_OFFSET(screen_present, 272);
CHECK_OFFSET(screen_release, 280);
CHECK_OFFSET(prop_get, 288);
CHECK_OFFSET(prop_info, 296);
CHECK_OFFSET(prop_watch, 304);
CHECK_OFFSET(prop_set, 312);
CHECK_OFFSET(task_start, 320);
CHECK_OFFSET(mem_reserved, 328);
CHECK_OFFSET(card_present, 336);
CHECK_OFFSET(platform_caps, 344);
CHECK_OFFSET(named, 352);
CHECK_OFFSET(hook_attach, 360);
CHECK_OFFSET(hook_detach, 368);
CHECK_OFFSET(table_read, 376);
CHECK_OFFSET(table_write, 384);
CHECK_OFFSET(table_restore, 392);
CHECK_OFFSET(fw_fn, 400);
CHECK_OFFSET(bus_i2c, 408);
CHECK_OFFSET(queue_post, 416);
CHECK_OFFSET(fs_dir_names, 424);
_Static_assert(sizeof(struct nlr_api) == 432, "SDK table size");
_Static_assert(sizeof(struct nlr_core_api) == 432, "core table size");
_Static_assert(sizeof(struct nlr_named) == 16, "SDK named size");
_Static_assert(sizeof(struct nlr_event) == 16, "SDK event size");
_Static_assert(offsetof(struct nlr_event, value) == 4 &&
               offsetof(struct nlr_event, x) == 8 &&
               offsetof(struct nlr_event, t_ms) == 12, "SDK event layout");
_Static_assert(sizeof(struct nlr_rect) == 8 && sizeof(struct nlr_prop_info) == 8,
               "SDK rect and prop info");
_Static_assert(NLR_CTL_UP == 0 && NLR_CTL_FULL == 14 && NLR_CTL_SUB_UP == 15 &&
               NLR_CTL_REMOTE_FN == 29 && NLR_CTL_DIAL_MAIN == 40 &&
               NLR_CTL_TOUCH == 48, "control numbers");
_Static_assert(sizeof(struct nlr_row) == 24, "SDK row size");
_Static_assert(sizeof(struct nlr_core_row) == 24, "core row size");
_Static_assert(offsetof(struct nlr_row, label) == 8, "SDK row label");
_Static_assert(offsetof(struct nlr_core_row, label) == 8, "core row label");
_Static_assert(offsetof(struct nlr_row, value) == 16, "SDK row value");
_Static_assert(offsetof(struct nlr_core_row, value) == 16, "core row value");
_Static_assert(sizeof(struct nlr_key_event) == 8, "SDK key event size");
_Static_assert(sizeof(struct nlr_core_key_event) == 8, "core key event size");
_Static_assert(sizeof(struct nlr_dirent) == 80, "SDK directory entry size");
_Static_assert(sizeof(struct nlr_core_dirent) == 80, "core directory entry size");
_Static_assert(offsetof(struct nlr_key_event, key) == 0, "SDK key offset");
_Static_assert(offsetof(struct nlr_key_event, down) == 4, "SDK down offset");
_Static_assert(offsetof(struct nlr_core_key_event, key) == 0, "core key offset");
_Static_assert(offsetof(struct nlr_core_key_event, down) == 4, "core down offset");
_Static_assert(sizeof(struct nlr_surface) == 40, "SDK surface size");
_Static_assert(sizeof(struct nlr_core_surface) == 40, "core surface size");
#define CHECK_SURFACE(field, offset) \
    _Static_assert(offsetof(struct nlr_surface, field) == offset, "SDK surface " #field); \
    _Static_assert(offsetof(struct nlr_core_surface, field) == offset, "core surface " #field)
CHECK_SURFACE(format, 0);
CHECK_SURFACE(width, 4);
CHECK_SURFACE(height, 8);
CHECK_SURFACE(stride, 12);
CHECK_SURFACE(pixels, 16);
CHECK_SURFACE(alpha, 24);
CHECK_SURFACE(alpha_stride, 32);
CHECK_SURFACE(reserved, 36);
_Static_assert(_Generic(((struct nlr_api *)0)->time_ms,
    uint32_t (*)(void): 1, default: 0), "SDK time type");
_Static_assert(_Generic(((struct nlr_core_api *)0)->time_ms,
    uint32_t (*)(void): 1, default: 0), "core time type");
_Static_assert(_Generic(((struct nlr_api *)0)->sleep_ms,
    void (*)(uint32_t): 1, default: 0), "SDK sleep type");
_Static_assert(_Generic(((struct nlr_core_api *)0)->sleep_ms,
    void (*)(uint32_t): 1, default: 0), "core sleep type");
_Static_assert(sizeof(struct nlr_menu_test_item) == 8, "SDK item size");
_Static_assert(sizeof(struct nlr_core_menu_test_item) == 8, "core item size");
_Static_assert(offsetof(struct nlr_menu_test_item, label_id) == 0, "SDK label");
_Static_assert(offsetof(struct nlr_menu_test_item, item_id) == 4, "SDK item");
_Static_assert(offsetof(struct nlr_core_menu_test_item, label_id) == 0, "core label");
_Static_assert(offsetof(struct nlr_core_menu_test_item, item_id) == 4, "core item");
_Static_assert(_Generic(((struct nlr_api *)0)->menu_register,
    int (*)(const struct nlr_menu_test_item *): 1, default: 0), "SDK callback type");
_Static_assert(_Generic(((struct nlr_core_api *)0)->menu_register,
    int (*)(const struct nlr_core_menu_test_item *): 1, default: 0), "core callback type");
_Static_assert(NLR_API_EBUSY == 16, "busy errno");

static int calls;
static int registration_result;
static int register_item(const struct nlr_menu_test_item *item)
{
    calls++;
    if (!item || item->label_id != 0x379u || item->item_id != 0x7ffdu)
        return -NLR_API_EINVAL;
    return registration_result;
}

int main(void)
{
    struct nlr_api api = {.abi = NLR_ABI_VERSION, .menu_register = register_item};
    if (nlr_extension_init(0) != -NLR_API_EINVAL || calls)
        return 1;
    api.abi = NLR_ABI_VERSION + 1u;
    if (nlr_extension_init(&api) != 0 || calls != 1)
        return 2;
    api.abi = 2u;
    if (nlr_extension_init(&api) != 0 || calls != 2)
        return 3;
    api.abi = 1u;
    if (nlr_extension_init(&api) != -NLR_API_EINVAL || calls != 2)
        return 6;
    calls = 0;
    api.abi = NLR_ABI_VERSION;
    api.menu_register = 0;
    if (nlr_extension_init(&api) != -NLR_API_ENOSYS || calls)
        return 4;
    api.menu_register = register_item;
    const int results[] = {0, -NLR_API_EINVAL, -NLR_API_EBUSY,
                           -NLR_API_ENOSYS, -NLR_API_EIO, 1};
    for (unsigned int i = 0; i < sizeof results / sizeof results[0]; i++) {
        registration_result = results[i];
        int expected = results[i] <= 0 ? results[i] : -NLR_API_EIO;
        if (nlr_extension_init(&api) != expected || calls != (int)i + 1)
            return 5;
    }
    return 0;
}
"#,
    )
    .unwrap();
    let result = std::process::Command::new("clang")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(root.join("core/include"))
        .arg("-I")
        .arg(root.join("sdk"))
        .arg(&source)
        .arg(root.join("sdk/examples/menu_extension.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("clang should be available");
    assert!(
        result.status.success(),
        "menu ABI test compilation failed:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let run = std::process::Command::new(&binary).output().unwrap();
    assert!(
        run.status.success(),
        "menu extension host test failed: {:?}\n{}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
#[ignore = "requires clang with an AArch64 backend"]
fn builds_the_deferred_menu_extension_example() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let stage = tempfile::tempdir().unwrap();
    let output = stage.path().join("MENU.NLB");
    let manifest = stage.path().join("MANIFEST");
    let declaration = nloader_build::program::ProgramMeta {
        id: "menu_extension".into(),
        kind: ProgramKind::ResourceExtension,
        display_name: "Menu extension".into(),
        file: "APPS/MENU.NLB".into(),
        min_abi: 2,
        abi_version: Some(2),
        entry_symbol: None,
        models: Some("z8/3.11".into()),
        settings: Vec::new(),
        describe: false,
        description: Default::default(),
    };
    let report =
        nloader_build::program::build::build(&nloader_build::program::ProgramBuildRequest {
            compiler: "clang".into(),
            declaration,
            sources: vec![
                root.join("sdk/crt0.s"),
                root.join("sdk/examples/menu_extension.c"),
            ],
            objects: Vec::new(),
            include_dirs: vec![root.join("sdk")],
            output: output.clone(),
            manifest_output: Some(manifest.clone()),
        })
        .unwrap_or_else(|error| panic!("menu extension build failed: {error}"));
    assert_eq!(report.kind, ProgramKind::ResourceExtension);
    assert_eq!(report.id, "menu_extension");
    let bytes = std::fs::read(output).unwrap();
    assert_eq!(&bytes[..4], b"NPLD");
    assert_eq!(word(&bytes, 0x18), 2);
    assert_eq!(word(&bytes, 0x20), KIND_RESOURCE_EXTENSION);
    let image_start = HEADER_SIZE + word(&bytes, 0x24) as usize;
    let entry = image_start + word(&bytes, 0x14) as usize;
    assert_eq!(word(&bytes, entry) & 0xfc00_0000, B);
    assert_eq!(
        std::fs::read_to_string(manifest).unwrap(),
        "# id | kind | 显示名 | 文件 | min_abi | 支持机型/固件（可省）\n\
         menu_extension | resource_extension | Menu extension | APPS/MENU.NLB | 2 | z8/3.11\n"
    );
}

#[test]
fn settings_files_follow_the_core_grammar() {
    use nloader_build::program::build::{settings_file, ProgramSetting};
    let setting = |key: &str, label: &str, choices: &[&str], default: u32| ProgramSetting {
        key: key.into(),
        label: label.into(),
        choices: choices.iter().map(|c| c.to_string()).collect(),
        default,
    };
    assert_eq!(settings_file(&[]).unwrap(), None);
    let card = setting("card", "Start card", &["Choose", "A:", "B:"], 0);
    let sort = setting("sort_by", "Sort", &["Name", "Size"], 1);
    assert_eq!(
        settings_file(&[card.clone(), sort]).unwrap().as_deref(),
        Some("card|Start card|Choose,A:,B:|0\nsort_by|Sort|Name,Size|1\n")
    );
    let bad = [
        vec![card.clone(), card.clone()],
        vec![setting("Card", "Start card", &["A:", "B:"], 0)],
        vec![setting("", "Start card", &["A:", "B:"], 0)],
        vec![setting("card", "Start|card", &["A:", "B:"], 0)],
        vec![setting("card", "", &["A:", "B:"], 0)],
        vec![setting("card", "Start card", &["A:"], 0)],
        vec![setting("card", "Start card", &["A:", "B,C"], 0)],
        vec![setting("card", "Start card", &["A:", "B:"], 2)],
        vec![setting(
            "card",
            "A label of twenty-four ch",
            &["A:", "B:"],
            0,
        )],
        vec![setting(
            "card",
            "A label of twenty-four c",
            &["A:", "a choice too long!"],
            0,
        )],
        (0..9)
            .map(|i| setting(&format!("k{i}"), "Label", &["A", "B"], 0))
            .collect(),
    ];
    for settings in bad {
        assert!(settings_file(&settings).is_err(), "{settings:?}");
    }
    let longest = setting(
        "card",
        "A label of twenty-four c",
        &["sixteen chars ok", "B"],
        0,
    );
    assert!(settings_file(&[longest]).unwrap().is_some());
}
