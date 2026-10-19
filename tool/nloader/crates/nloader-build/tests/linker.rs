use nloader_build::linker::{link, ObjectInput};
use object::write::{Object as WriteObject, Relocation, SectionId, Symbol, SymbolId};
use object::{
    elf, Architecture, BinaryFormat, Endianness, Object, ObjectSection, ObjectSymbol,
    RelocationFlags, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

fn object() -> WriteObject<'static> {
    WriteObject::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little)
}

fn symbol(
    object: &mut WriteObject<'_>,
    name: &str,
    section: object::write::SymbolSection,
    value: u64,
    size: u64,
    kind: SymbolKind,
    scope: SymbolScope,
) -> SymbolId {
    object.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value,
        size,
        kind,
        scope,
        weak: false,
        section,
        flags: SymbolFlags::None,
    })
}

fn text(object: &mut WriteObject<'_>, data: &[u8], name: &str) -> SectionId {
    let section = object.add_section(Vec::new(), name.as_bytes().to_vec(), SectionKind::Text);
    object.section_mut(section).append_data(data, 4);
    section
}

fn entry(object: &mut WriteObject<'_>, section: SectionId, size: u64) -> SymbolId {
    symbol(
        object,
        "entry",
        object::write::SymbolSection::Section(section),
        0,
        size,
        SymbolKind::Text,
        SymbolScope::Linkage,
    )
}

fn input(name: &str, object: WriteObject<'_>) -> ObjectInput {
    ObjectInput {
        name: name.into(),
        bytes: object.write().unwrap(),
    }
}

fn basic(name: &str) -> ObjectInput {
    let mut object = object();
    let section = text(&mut object, &0xd65f_03c0_u32.to_le_bytes(), ".text");
    entry(&mut object, section, 4);
    input(name, object)
}

fn relocated(kind: u32, instruction: u32, address: u64, addend: i64) -> ObjectInput {
    let mut object = object();
    let mut code = instruction.to_le_bytes().to_vec();
    code.extend([0; 12]);
    let section = text(&mut object, &code, ".text");
    entry(&mut object, section, 16);
    let target = symbol(
        &mut object,
        "target",
        object::write::SymbolSection::Absolute,
        address,
        0,
        SymbolKind::Data,
        SymbolScope::Linkage,
    );
    object
        .add_relocation(
            section,
            Relocation {
                offset: 0,
                symbol: target,
                addend,
                flags: RelocationFlags::Elf { r_type: kind },
            },
        )
        .unwrap();
    input("test.o", object)
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn section_header(bytes: &[u8], name: &str) -> usize {
    let file = object::File::parse(bytes).unwrap();
    let index = file.section_by_name(name).unwrap().index().0;
    u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize + index * 64
}

fn section_data(bytes: &[u8], name: &str) -> usize {
    let header = section_header(bytes, name);
    u64::from_le_bytes(bytes[header + 24..header + 32].try_into().unwrap()) as usize
}

#[test]
fn applies_all_supported_relocations() {
    let base = 0x1000;
    let target = 0x2230;
    let cases = [
        (elf::R_AARCH64_ADR_PREL_PG_HI21, 0x9000_0000, 0xb000_0000),
        (
            elf::R_AARCH64_ADD_ABS_LO12_NC,
            0x9100_0000,
            0x9100_0000 | (0x230 << 10),
        ),
        (
            elf::R_AARCH64_JUMP26,
            0x1400_0000,
            0x1400_0000 | (0x1230 / 4),
        ),
        (
            elf::R_AARCH64_CALL26,
            0x9400_0000,
            0x9400_0000 | (0x1230 / 4),
        ),
        (
            elf::R_AARCH64_LDST8_ABS_LO12_NC,
            0x3940_0000,
            0x3940_0000 | (0x230 << 10),
        ),
        (
            elf::R_AARCH64_LDST16_ABS_LO12_NC,
            0x7940_0000,
            0x7940_0000 | ((0x230 / 2) << 10),
        ),
        (
            elf::R_AARCH64_LDST32_ABS_LO12_NC,
            0xb940_0000,
            0xb940_0000 | ((0x230 / 4) << 10),
        ),
        (
            elf::R_AARCH64_LDST64_ABS_LO12_NC,
            0xf940_0000,
            0xf940_0000 | ((0x230 / 8) << 10),
        ),
        (
            elf::R_AARCH64_LDST128_ABS_LO12_NC,
            0x3dc0_0000,
            0x3dc0_0000 | ((0x230 / 16) << 10),
        ),
    ];
    for (kind, instruction, expected) in cases {
        let result = link(
            &[relocated(kind, instruction, target, 0)],
            base,
            64,
            "entry",
        )
        .unwrap();
        assert_eq!(word(&result.bytes, 0), expected, "relocation {kind}");
        assert_eq!(result.entry, base);
    }
    let value = 0x1234_5678_9abc_def0;
    let result = link(
        &[relocated(elf::R_AARCH64_ABS64, 0, value, -16)],
        base,
        64,
        "entry",
    )
    .unwrap();
    assert_eq!(
        u64::from_le_bytes(result.bytes[..8].try_into().unwrap()),
        value - 16
    );
}

#[test]
fn checks_branch_and_page_range_boundaries() {
    let base = 1_u64 << 33;
    for (delta, valid) in [
        (-(1_i64 << 27), true),
        ((1 << 27) - 4, true),
        (-(1 << 27) - 4, false),
        (1 << 27, false),
        (2, false),
    ] {
        let target = base.checked_add_signed(delta).unwrap();
        assert_eq!(
            link(
                &[relocated(elf::R_AARCH64_JUMP26, 0x1400_0000, target, 0)],
                base,
                64,
                "entry"
            )
            .is_ok(),
            valid
        );
    }
    for (pages, valid) in [
        (-(1_i64 << 20), true),
        ((1 << 20) - 1, true),
        (-(1 << 20) - 1, false),
        (1 << 20, false),
    ] {
        let target = base.checked_add_signed(pages * 4096).unwrap();
        assert_eq!(
            link(
                &[relocated(
                    elf::R_AARCH64_ADR_PREL_PG_HI21,
                    0x9000_0000,
                    target,
                    0
                )],
                base,
                64,
                "entry"
            )
            .is_ok(),
            valid
        );
    }
    let backward = link(
        &[relocated(elf::R_AARCH64_JUMP26, 0x1400_0000, base - 4, 0)],
        base,
        64,
        "entry",
    )
    .unwrap();
    assert_eq!(word(&backward.bytes, 0), 0x17ff_ffff);
}

#[test]
fn rejects_bad_opcodes_scaling_and_arithmetic() {
    for (kind, instruction, target) in [
        (elf::R_AARCH64_CALL26, 0x1400_0000, 0x1000),
        (elf::R_AARCH64_JUMP26, 0x9400_0000, 0x1000),
        (elf::R_AARCH64_ADR_PREL_PG_HI21, 0x1000_0000, 0x1000),
        (elf::R_AARCH64_ADD_ABS_LO12_NC, 0x9140_0000, 0x1000),
        (elf::R_AARCH64_LDST64_ABS_LO12_NC, 0xf940_0000, 0x1004),
        (elf::R_AARCH64_LDST16_ABS_LO12_NC, 0x7940_0000, 0x1001),
        (elf::R_AARCH64_LDST32_ABS_LO12_NC, 0xb940_0000, 0x1002),
        (elf::R_AARCH64_LDST128_ABS_LO12_NC, 0x3dc0_0000, 0x1008),
        (elf::R_AARCH64_LDST64_ABS_LO12_NC, 0xb940_0000, 0x1000),
        (elf::R_AARCH64_LDST64_ABS_LO12_NC, 0xf980_0000, 0x1000),
        (elf::R_AARCH64_LDST128_ABS_LO12_NC, 0x7dc0_0000, 0x1000),
    ] {
        assert!(link(
            &[relocated(kind, instruction, target, 0)],
            0x1000,
            64,
            "entry"
        )
        .is_err());
    }
    for (address, addend) in [(0, -1), (u64::MAX, 1)] {
        assert!(link(
            &[relocated(elf::R_AARCH64_ABS64, 0, address, addend)],
            0x1000,
            64,
            "entry"
        )
        .is_err());
    }
    assert!(link(
        &[relocated(elf::R_AARCH64_PREL32, 0, 0x1000, 0)],
        0x1000,
        64,
        "entry"
    )
    .is_err());
}

#[test]
fn relocation_write_must_fit_its_section_not_just_image() {
    let mut fixture = relocated(elf::R_AARCH64_ABS64, 0, 0x1000, 0);
    let data = section_data(&fixture.bytes, ".rela.text");
    fixture.bytes[data..data + 8].copy_from_slice(&12_u64.to_le_bytes());
    assert!(link(&[fixture], 0x1000, 128, "entry").is_err());
    let mut fixture = relocated(elf::R_AARCH64_JUMP26, 0x1400_0000, 0x1000, 0);
    let data = section_data(&fixture.bytes, ".rela.text");
    fixture.bytes[data..data + 8].copy_from_slice(&1_u64.to_le_bytes());
    assert!(link(&[fixture], 0x1000, 128, "entry").is_err());
}

#[test]
fn rejects_malformed_tables_and_bad_symbol_indices() {
    for (section, field, value) in [
        (".rela.text", 56, 8_u64),
        (".rela.text", 32, 25),
        (".symtab", 56, 8),
        (".symtab", 32, 25),
    ] {
        let mut fixture = relocated(elf::R_AARCH64_ABS64, 0, 0x1000, 0);
        let header = section_header(&fixture.bytes, section);
        fixture.bytes[header + field..header + field + 8].copy_from_slice(&value.to_le_bytes());
        assert!(link(&[fixture], 0x1000, 128, "entry").is_err());
    }
    let mut fixture = relocated(elf::R_AARCH64_ABS64, 0, 0x1000, 0);
    let header = section_header(&fixture.bytes, ".rela.text");
    fixture.bytes[header + 4..header + 8].copy_from_slice(&elf::SHT_REL.to_le_bytes());
    assert!(link(&[fixture], 0x1000, 128, "entry").is_err());
    let mut fixture = relocated(elf::R_AARCH64_ABS64, 0, 0x1000, 0);
    let data = section_data(&fixture.bytes, ".rela.text");
    fixture.bytes[data + 12..data + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(link(&[fixture], 0x1000, 128, "entry").is_err());
    for length in [0, 4, 63, 80] {
        let fixture = basic("short.o");
        assert!(link(
            &[ObjectInput {
                name: fixture.name,
                bytes: fixture.bytes[..length].to_vec()
            }],
            0x1000,
            128,
            "entry"
        )
        .is_err());
    }
}

#[test]
fn rejects_writable_tls_nobits_common_and_invalid_alignment() {
    for kind in [
        SectionKind::Data,
        SectionKind::UninitializedData,
        SectionKind::Tls,
    ] {
        let mut object = object();
        let code = text(&mut object, &0xd65f_03c0_u32.to_le_bytes(), ".text");
        entry(&mut object, code, 4);
        let section = object.add_section(Vec::new(), b".state".to_vec(), kind);
        if kind == SectionKind::UninitializedData {
            object.section_mut(section).append_bss(8, 8);
        } else {
            object.section_mut(section).append_data(&[0; 8], 8);
        }
        assert!(link(&[input("state.o", object)], 0x1000, 128, "entry").is_err());
    }
    let mut object = object();
    let code = text(&mut object, &0xd65f_03c0_u32.to_le_bytes(), ".text");
    entry(&mut object, code, 4);
    symbol(
        &mut object,
        "common",
        object::write::SymbolSection::Common,
        8,
        8,
        SymbolKind::Data,
        SymbolScope::Linkage,
    );
    assert!(link(&[input("common.o", object)], 0x1000, 128, "entry").is_err());
    let mut fixture = basic("bad-align.o");
    let header = section_header(&fixture.bytes, ".text");
    fixture.bytes[header + 48..header + 56].copy_from_slice(&3_u64.to_le_bytes());
    assert!(link(&[fixture], 0x1000, 128, "entry").is_err());
    let mut fixture = basic("bad-type.o");
    let header = section_header(&fixture.bytes, ".text");
    fixture.bytes[header + 4..header + 8].copy_from_slice(&elf::SHT_NOTE.to_le_bytes());
    assert!(link(&[fixture], 0x1000, 128, "entry").is_err());
}

#[test]
fn layout_is_deterministic_and_checks_capacity_and_entry() {
    let first = basic("a.o");
    let mut object = object();
    let data = object.add_section(Vec::new(), b".rodata".to_vec(), SectionKind::ReadOnlyData);
    object.section_mut(data).append_data(&[1, 2, 3, 4], 16);
    symbol(
        &mut object,
        "constant",
        object::write::SymbolSection::Section(data),
        0,
        4,
        SymbolKind::Data,
        SymbolScope::Linkage,
    );
    let second = input("b.o", object);
    let left = link(&[first.clone(), second.clone()], 0x1000, 64, "entry").unwrap();
    let right = link(&[second, first.clone()], 0x1000, 64, "entry").unwrap();
    assert_eq!(left.bytes, right.bytes);
    assert_eq!(left.symbols, right.symbols);
    assert_eq!(left.sections[1].address, 0x1010);
    assert_eq!(&left.bytes[4..16], &[0; 12]);
    assert!(link(std::slice::from_ref(&first), 0x1000, 3, "entry").is_err());
    assert!(link(std::slice::from_ref(&first), u64::MAX - 3, 8, "entry").is_err());
    assert!(link(std::slice::from_ref(&first), 0x1001, 64, "entry").is_err());
    assert!(link(std::slice::from_ref(&first), 0x1000, 64, "missing").is_err());
    assert!(link(&[first.clone(), first], 0x1000, 64, "entry").is_err());
    let data_entry = relocated(elf::R_AARCH64_ABS64, 0, 0x1000, 0);
    assert!(link(&[data_entry], 0x1000, 64, "target").is_err());
}

#[test]
fn resolves_cross_object_symbols_and_rejects_missing_or_duplicate_definitions() {
    let mut a = object();
    let section = text(&mut a, &0x1400_0000_u32.to_le_bytes(), ".text");
    entry(&mut a, section, 4);
    let target = symbol(
        &mut a,
        "callee",
        object::write::SymbolSection::Undefined,
        0,
        0,
        SymbolKind::Text,
        SymbolScope::Linkage,
    );
    a.add_relocation(
        section,
        Relocation {
            offset: 0,
            symbol: target,
            addend: 0,
            flags: RelocationFlags::Elf {
                r_type: elf::R_AARCH64_JUMP26,
            },
        },
    )
    .unwrap();
    let a = input("a.o", a);
    let mut b = object();
    let section = text(&mut b, &0xd65f_03c0_u32.to_le_bytes(), ".text");
    symbol(
        &mut b,
        "callee",
        object::write::SymbolSection::Section(section),
        0,
        4,
        SymbolKind::Text,
        SymbolScope::Linkage,
    );
    let b = input("b.o", b);
    let linked = link(&[a.clone(), b.clone()], 0x1000, 64, "entry").unwrap();
    assert_eq!(word(&linked.bytes, 0), 0x1400_0001);
    assert!(link(&[a], 0x1000, 64, "entry").is_err());
    let mut duplicate = b.clone();
    duplicate.name = "c.o".into();
    assert!(link(&[basic("entry.o"), b, duplicate], 0x1000, 64, "entry").is_err());
}

#[test]
fn unplaced_local_never_resolves_to_same_named_global() {
    let mut a = object();
    let section = text(&mut a, &[0; 8], ".text");
    entry(&mut a, section, 8);
    let debug = a.add_section(Vec::new(), b".debug_info".to_vec(), SectionKind::Debug);
    a.section_mut(debug).append_data(&[0; 4], 1);
    let local = symbol(
        &mut a,
        "same",
        object::write::SymbolSection::Section(debug),
        0,
        4,
        SymbolKind::Data,
        SymbolScope::Compilation,
    );
    a.add_relocation(
        section,
        Relocation {
            offset: 0,
            symbol: local,
            addend: 0,
            flags: RelocationFlags::Elf {
                r_type: elf::R_AARCH64_ABS64,
            },
        },
    )
    .unwrap();
    let mut b = object();
    symbol(
        &mut b,
        "same",
        object::write::SymbolSection::Absolute,
        0x1234,
        0,
        SymbolKind::Data,
        SymbolScope::Linkage,
    );
    assert!(link(&[input("a.o", a), input("b.o", b)], 0x1000, 64, "entry").is_err());
}

#[test]
fn rejects_out_of_bounds_symbol_and_overlapping_relocations() {
    let mut fixture = basic("bad-symbol.o");
    let file = object::File::parse(fixture.bytes.as_slice()).unwrap();
    let index = file
        .symbols()
        .find(|symbol| symbol.name() == Ok("entry"))
        .unwrap()
        .index()
        .0;
    let offset = section_data(&fixture.bytes, ".symtab") + index * 24;
    fixture.bytes[offset + 8..offset + 16].copy_from_slice(&8_u64.to_le_bytes());
    assert!(link(&[fixture], 0x1000, 64, "entry").is_err());
    let mut object = object();
    let section = text(&mut object, &[0; 16], ".text");
    let symbol = entry(&mut object, section, 16);
    for offset in [0, 4] {
        object
            .add_relocation(
                section,
                Relocation {
                    offset,
                    symbol,
                    addend: 0,
                    flags: RelocationFlags::Elf {
                        r_type: elf::R_AARCH64_ABS64,
                    },
                },
            )
            .unwrap();
    }
    assert!(link(&[input("overlap.o", object)], 0x1000, 64, "entry").is_err());
}

#[test]
fn rejects_relocations_into_empty_storage_and_incomplete_entry_instruction() {
    let mut object = object();
    let section = text(&mut object, &0xd65f_03c0_u32.to_le_bytes(), ".text");
    let target = entry(&mut object, section, 4);
    let empty = text(&mut object, &[], ".text.empty");
    object
        .add_relocation(
            empty,
            Relocation {
                offset: 0,
                symbol: target,
                addend: 0,
                flags: RelocationFlags::Elf {
                    r_type: elf::R_AARCH64_ABS64,
                },
            },
        )
        .unwrap();
    assert!(link(&[input("empty.o", object)], 0x1000, 64, "entry").is_err());

    let mut object = self::object();
    let section = text(&mut object, &[0; 2], ".text");
    entry(&mut object, section, 0);
    assert!(link(&[input("short-entry.o", object)], 0x1000, 64, "entry").is_err());
}

#[test]
#[ignore = "requires clang with an AArch64 backend"]
fn links_real_clang_code_and_readonly_binding() {
    use std::{fs, process::Command};
    let directory = tempfile::tempdir().unwrap();
    let sources = [
        (
            "entry.S",
            ".text\n.global entry\n.type entry,%function\nentry:\n b probe\n.size entry,.-entry\n",
        ),
        (
            "probe.c",
            "extern const unsigned binding; unsigned probe(void) { return binding; }",
        ),
        ("binding.c", "const unsigned binding = 7;"),
    ];
    let mut objects = Vec::new();
    for (name, source) in sources {
        let path = directory.path().join(name);
        fs::write(&path, source).unwrap();
        let output = path.with_extension("o");
        let result = Command::new("clang")
            .args([
                "--target=aarch64-none-elf",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-pic",
                "-fno-stack-protector",
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-fno-common",
                "-Os",
                "-c",
            ])
            .arg(&path)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        objects.push(ObjectInput {
            name: output.file_name().unwrap().to_str().unwrap().into(),
            bytes: fs::read(output).unwrap(),
        });
    }
    let linked = link(&objects, 0x1000, 4096, "entry").unwrap();
    assert!(linked.symbols.contains_key("probe"));
    let binding = (linked.symbols["binding"] - 0x1000) as usize;
    assert_eq!(word(&linked.bytes, binding), 7);
    let branch = word(&linked.bytes, (linked.entry - 0x1000) as usize);
    let delta = (((branch & 0x03ff_ffff) << 6) as i32 >> 6) as i64 * 4;
    assert_eq!(
        linked.entry.checked_add_signed(delta),
        Some(linked.symbols["probe"])
    );
}

/// The prefill trampoline loads its tail-branch target with
/// `adrp x17, sym+0x48` + `ldr [x17, :lo12:sym+0x48]`. Both relocations
/// carry the FIELD addend: the ADRP must compute the page of the field
/// (which can differ from the symbol's page near a 4 KiB boundary) and the
/// LO12 the field's low bits. An addend-free page computation would pass
/// these tests only for page-aligned symbols — the bug the trampoline
/// shipped with.
#[test]
fn page_and_low_relocations_honour_the_field_addend() {
    /* The symbol sits 0xfc0 into its page: the field sym+0x48 crosses into
     * the next page. */
    let base = 0x1000;
    let symbol = base + 0xfc0;

    let adrp = link(
        &[relocated(
            elf::R_AARCH64_ADR_PREL_PG_HI21,
            0x9000_0000,
            symbol,
            0x48,
        )],
        base,
        64,
        "entry",
    )
    .unwrap();
    /* pages = (field_page - place_page) / 0x1000 = 1: immlo=1 (bits 29..30). */
    assert_eq!(word(&adrp.bytes, 0), 0x9000_0000 | (1 << 29));

    let ldr = link(
        &[relocated(
            elf::R_AARCH64_LDST64_ABS_LO12_NC,
            0xf940_0000,
            symbol,
            0x48,
        )],
        base,
        64,
        "entry",
    )
    .unwrap();
    /* low 12 bits of the FIELD, scaled by 8: 0x008 / 8 = 1. */
    assert_eq!(word(&ldr.bytes, 0), 0xf940_0000 | (1 << 10));

    /* Addend-free computations (the page of the symbol, the low bits of the
     * symbol) would produce different words — the assertions above already
     * distinguish the two behaviours. */
}
