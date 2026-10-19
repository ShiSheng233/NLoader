//! Position-independent program linking for general NPLD v2 programs.
//!
//! Unlike the restricted XIP linker ([`crate::linker`]), a program keeps
//! writable data: the link produces two file-relative segments, the
//! executable `image` (code and read-only data) and the writable `data`
//! (initialized data, followed by the BSS region), matching PLAN 6.3's
//! two-block load model. Both segments are linked at file-relative base 0;
//! every block base the loader can choose is 2 MiB aligned, so page-difference
//! arithmetic (ADRP) and low-12-bit offsets are invariant under the
//! load-time move.
//!
//! Relocation policy (PLAN 6.3 重定位表示):
//! - an ADRP inside the image that references a data/BSS symbol is *not*
//!   applied; it becomes a `kind=0` table entry (the loader patches immhi/
//!   immlo from the two block bases). Its paired `ADD`/load-store low-12
//!   offset stays a link-time constant and is applied here;
//! - an ABS64 inside `data` that references an image symbol becomes a
//!   `kind=1` table entry (the loader stores `code_base + target`);
//! - an ABS64 inside `data` that references initialized data or BSS becomes
//!   a `kind=2` table entry (the loader stores `data_base + target`);
//! - references that stay inside the image (BL/ADR/ADRP within the block)
//!   are applied at link time and never enter the table.
//!
//! The linked result is self-checked against the final bytes before it is
//! returned: every emitted entry must land inside its segment, be aligned,
//! and point at an actual ADRP instruction when it patches one.

use crate::linker::{
    checked_end, relocate_instruction, relocation_width, validate_tables, LinkedSection,
    ObjectInput,
};
use crate::{Error, Result};
use object::read::elf::{ElfFile64, SectionHeader};
use object::{elf, Object, ObjectSection, ObjectSymbol, SectionIndex, SymbolSection};
use std::collections::{BTreeMap, BTreeSet};

use super::package::{
    Relocation, RELOCATION_KIND_ABS64, RELOCATION_KIND_ABS64_DATA, RELOCATION_KIND_ADRP,
};

/// PLAN 6.3 load model: a program occupies at most one 2 MiB code block and
/// one 2 MiB data block, so neither file-relative segment may exceed that.
pub(crate) const SEGMENT_CAPACITY: u64 = 0x20_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Segment {
    Image,
    Data,
    Bss,
}

/// A linked general v2 program: file-relative segments plus the runtime
/// relocation table the loader applies when the blocks are placed.
#[derive(Debug)]
pub struct ProgramLink {
    pub image: Vec<u8>,
    pub data: Vec<u8>,
    pub bss_size: u64,
    /// File-relative image offset of the entry.
    pub entry: u64,
    pub relocations: Vec<Relocation>,
    pub sections: Vec<LinkedSection>,
    pub symbols: BTreeMap<String, u64>,
}

struct Placed {
    section: LinkedSection,
    segment: Segment,
}

#[derive(Clone)]
struct Definition {
    address: Option<u64>,
    segment: Option<Segment>,
    name: String,
    external: bool,
}

type Placements = BTreeMap<(usize, usize), Placed>;
type Definitions = BTreeMap<(usize, usize), Definition>;
type Globals = BTreeMap<String, Definition>;

struct Input<'a> {
    name: &'a str,
    file: ElfFile64<'a>,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Object(message.into())
}

/// Link in object-name and section-index order. Objects must be
/// self-contained: no firmware imports, no implicit addends, no COMMON or
/// TLS storage — a general program receives everything else through the
/// API table at run time.
pub fn link(objects: &[ObjectInput], entry: &str) -> Result<ProgramLink> {
    if objects.is_empty() || entry.is_empty() {
        return Err(invalid("program link needs objects and an entry name"));
    }
    let mut sorted: Vec<_> = objects.iter().collect();
    sorted.sort_by(|left, right| left.name.cmp(&right.name));
    let mut inputs = Vec::with_capacity(sorted.len());
    for (index, input) in sorted.iter().enumerate() {
        if input.name.is_empty()
            || input.name.contains(['/', '\\'])
            || index > 0 && input.name == sorted[index - 1].name
        {
            return Err(invalid("object names must be unique basenames"));
        }
        let file =
            ElfFile64::parse(input.bytes.as_slice()).map_err(|error| invalid(error.to_string()))?;
        if !file.is_little_endian()
            || !file.is_64()
            || file.architecture() != object::Architecture::Aarch64
            || file.kind() != object::ObjectKind::Relocatable
        {
            return Err(invalid("expected little-endian AArch64 ELF64 ET_REL"));
        }
        validate_tables(&file)?;
        inputs.push(Input {
            name: &input.name,
            file,
        });
    }
    let placements = place_sections(&inputs)?;
    let (definitions, globals) = resolve_definitions(&inputs, &placements)?;
    let entry_definition = globals
        .get(entry)
        .ok_or_else(|| invalid("entry is not a defined global"))?;
    let entry_address = entry_definition
        .address
        .ok_or_else(|| invalid("entry has no address"))?;
    if entry_definition.segment != Some(Segment::Image) || entry_address % 4 != 0 {
        return Err(invalid(
            "entry must be a 4-byte-aligned function inside the image",
        ));
    }
    let data_end = placements
        .values()
        .filter(|placed| placed.segment == Segment::Data)
        .map(|placed| placed.section.address + placed.section.size)
        .max()
        .unwrap_or(0);
    let bss_end = placements
        .values()
        .filter(|placed| placed.segment == Segment::Bss)
        .map(|placed| placed.section.address + placed.section.size)
        .max()
        .unwrap_or(0);
    let mut program = ProgramLink {
        image: write_segment(&inputs, &placements, Segment::Image)?,
        data: write_segment(&inputs, &placements, Segment::Data)?,
        bss_size: bss_end.saturating_sub(data_end),
        entry: entry_address,
        relocations: Vec::new(),
        sections: placements
            .values()
            .map(|placed| placed.section.clone())
            .collect(),
        symbols: BTreeMap::new(),
    };
    program.relocations =
        process_relocations(&mut program, &inputs, &placements, &definitions, &globals)?;
    program.symbols = globals
        .iter()
        .filter_map(|(name, definition)| definition.address.map(|address| (name.clone(), address)))
        .collect();
    self_check(&program)?;
    Ok(program)
}

/// Place every allocated section into its segment. Image sections (read-only
/// PROGBITS) come first, then writable PROGBITS (the data segment), then
/// NOBITS (BSS, zeroed at load after the data). Placement order is the
/// object-name/section-index order, so the result is deterministic.
fn place_sections(inputs: &[Input<'_>]) -> Result<Placements> {
    let mut result = BTreeMap::new();
    let mut data_end = 0u64;
    for pass in [Segment::Image, Segment::Data, Segment::Bss] {
        // BSS is zeroed after the initialized data at load, so its region
        // starts at the data segment's end, padding included.
        let mut cursor = if pass == Segment::Bss { data_end } else { 0 };
        for (object, input) in inputs.iter().enumerate() {
            for section in input.file.sections() {
                let raw = section.elf_section_header();
                let kind = raw.sh_type(input.file.endian());
                let flags = raw.sh_flags(input.file.endian());
                if flags & u64::from(elf::SHF_ALLOC) == 0 {
                    continue;
                }
                if flags & u64::from(elf::SHF_TLS | elf::SHF_COMPRESSED | elf::SHF_GROUP) != 0 {
                    return Err(invalid(
                        "TLS, compressed, and grouped allocated sections are unsupported",
                    ));
                }
                let writable = flags & u64::from(elf::SHF_WRITE) != 0;
                let executable = flags & u64::from(elf::SHF_EXECINSTR) != 0;
                let segment = match (kind, writable) {
                    (elf::SHT_PROGBITS, false) => Segment::Image,
                    (elf::SHT_PROGBITS, true) => Segment::Data,
                    (elf::SHT_NOBITS, true) => Segment::Bss,
                    (elf::SHT_NOBITS, false) => {
                        return Err(invalid(
                            "NOBITS storage is zero-initialized and must be writable",
                        ));
                    }
                    _ => {
                        let name = section.name().unwrap_or("<unnamed>");
                        return Err(invalid(format!(
                            "unsupported allocated section type {kind:#x} on {name}"
                        )));
                    }
                };
                if segment != pass {
                    continue;
                }
                if section.size() == 0 {
                    continue;
                }
                if executable && writable {
                    return Err(invalid(
                        "the data block stays non-executable: writable code is unsupported",
                    ));
                }
                let allowed = u64::from(
                    elf::SHF_ALLOC
                        | elf::SHF_WRITE
                        | elf::SHF_EXECINSTR
                        | elf::SHF_MERGE
                        | elf::SHF_STRINGS,
                );
                if flags & !allowed != 0 {
                    let name = section.name().unwrap_or("<unnamed>");
                    return Err(invalid(format!(
                        "unsupported allocated section flags {flags:#x} on {name}"
                    )));
                }
                let alignment = section.align().max(1);
                if !alignment.is_power_of_two() {
                    return Err(invalid("section alignment is not a power of two"));
                }
                cursor = checked_end(cursor, alignment - 1)? & !(alignment - 1);
                let end = checked_end(cursor, section.size())?;
                if end > SEGMENT_CAPACITY {
                    return Err(invalid("program segment exceeds the 2 MiB block budget"));
                }
                if segment == Segment::Image {
                    let data = section.data().map_err(|error| invalid(error.to_string()))?;
                    if data.len() as u64 != section.size() {
                        return Err(invalid("truncated allocated section"));
                    }
                }
                result.insert(
                    (object, section.index().0),
                    Placed {
                        section: LinkedSection {
                            object: input.name.into(),
                            name: section
                                .name()
                                .map_err(|error| invalid(error.to_string()))?
                                .into(),
                            address: cursor,
                            size: section.size(),
                            alignment,
                            executable: segment == Segment::Image && executable,
                        },
                        segment,
                    },
                );
                cursor = end;
                if segment == Segment::Data {
                    data_end = end;
                }
            }
        }
    }
    if !result
        .values()
        .any(|placed| placed.segment == Segment::Image)
    {
        return Err(invalid("no allocated code or read-only data"));
    }
    Ok(result)
}

fn write_segment(
    inputs: &[Input<'_>],
    placements: &Placements,
    segment: Segment,
) -> Result<Vec<u8>> {
    let length = placements
        .values()
        .filter(|placed| placed.segment == segment)
        .map(|placed| placed.section.address + placed.section.size)
        .max()
        .unwrap_or(0);
    let length = usize::try_from(length).map_err(|_| invalid("segment is too large"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| invalid("cannot allocate segment"))?;
    bytes.resize(length, 0);
    for ((object, section_index), placed) in placements {
        if placed.segment != segment {
            continue;
        }
        let source = inputs[*object]
            .file
            .section_by_index(SectionIndex(*section_index))
            .map_err(|error| invalid(error.to_string()))?;
        let data = source.data().map_err(|error| invalid(error.to_string()))?;
        let start = placed.section.address as usize;
        bytes[start..start + data.len()].copy_from_slice(data);
    }
    Ok(bytes)
}

fn resolve_definitions(
    inputs: &[Input<'_>],
    placements: &Placements,
) -> Result<(Definitions, Globals)> {
    let mut definitions = BTreeMap::new();
    let mut globals = BTreeMap::new();
    for (object, input) in inputs.iter().enumerate() {
        for symbol in input.file.symbols() {
            if symbol.is_common() || symbol.kind() == object::SymbolKind::Tls {
                return Err(invalid("programs forbid COMMON and TLS symbols"));
            }
            let binding = symbol.elf_symbol().st_bind();
            if !matches!(binding, elf::STB_LOCAL | elf::STB_GLOBAL | elf::STB_WEAK) {
                return Err(invalid("unsupported symbol binding"));
            }
            if !matches!(
                symbol.elf_symbol().st_type(),
                elf::STT_NOTYPE
                    | elf::STT_OBJECT
                    | elf::STT_FUNC
                    | elf::STT_SECTION
                    | elf::STT_FILE
            ) {
                return Err(invalid("unsupported symbol type"));
            }
            let name = symbol
                .name()
                .map_err(|error| invalid(error.to_string()))?
                .to_owned();
            let global = binding != elf::STB_LOCAL;
            let mut placed_segment = None;
            let address = match symbol.section() {
                SymbolSection::Absolute => Some(symbol.address()),
                SymbolSection::Section(index) => {
                    let section = input
                        .file
                        .section_by_index(index)
                        .map_err(|error| invalid(error.to_string()))?;
                    if checked_end(symbol.address(), symbol.size())? > section.size() {
                        return Err(invalid("symbol exceeds its section"));
                    }
                    match placements.get(&(object, index.0)) {
                        Some(placed) => {
                            placed_segment = Some(placed.segment);
                            Some(checked_end(placed.section.address, symbol.address())?)
                        }
                        // Debug and metadata sections are not allocated; their
                        // symbols stay unusable for relocations.
                        None => None,
                    }
                }
                SymbolSection::Undefined | SymbolSection::None => None,
                _ => return Err(invalid("unsupported symbol section")),
            };
            let definition = Definition {
                address,
                segment: placed_segment,
                name: name.clone(),
                external: global && symbol.is_undefined(),
            };
            if global
                && address.is_some()
                && (name.is_empty() || globals.insert(name, definition.clone()).is_some())
            {
                return Err(invalid("empty or duplicate global symbol definition"));
            }
            definitions.insert((object, symbol.index().0), definition);
        }
    }
    Ok((definitions, globals))
}

fn resolve_symbol(
    definitions: &Definitions,
    globals: &Globals,
    object: usize,
    symbol_index: usize,
) -> Result<(u64, Segment)> {
    let definition = definitions
        .get(&(object, symbol_index))
        .ok_or_else(|| invalid("relocation refers to invalid symbol index"))?;
    let resolved = match definition.address {
        Some(address) => Some((address, definition.segment)),
        // An undefined global falls back to the same-named definition in
        // another object, which also carries the segment.
        None if definition.external => globals
            .get(&definition.name)
            .and_then(|other| other.address.map(|address| (address, other.segment))),
        None => None,
    };
    let (address, segment) = resolved
        .ok_or_else(|| invalid(format!("undefined or unplaced symbol: {}", definition.name)))?;
    let segment = segment.ok_or_else(|| {
        invalid(format!(
            "relocation against a symbol outside both segments: {}",
            definition.name
        ))
    })?;
    Ok((address, segment))
}

/// Walk every RELA record once, either patching link-time constants into the
/// image bytes or emitting loader table entries. Link-time patches only ever
/// target the image (data records only emit ABS64 entries), so overlap
/// tracking uses one address space.
fn process_relocations(
    program: &mut ProgramLink,
    inputs: &[Input<'_>],
    placements: &Placements,
    definitions: &Definitions,
    globals: &Globals,
) -> Result<Vec<Relocation>> {
    let mut table = Vec::new();
    let mut writes = BTreeMap::<u64, u64>::new();
    let mut emitted = BTreeSet::<(u32, u32)>::new();
    for (object, input) in inputs.iter().enumerate() {
        for section in input.file.sections() {
            let raw = section.elf_section_header();
            if raw.sh_type(input.file.endian()) != elf::SHT_RELA {
                continue;
            }
            let target_index = raw.sh_info(input.file.endian()) as usize;
            let Some(placed) = placements.get(&(object, target_index)) else {
                let target = input
                    .file
                    .section_by_index(SectionIndex(target_index))
                    .map_err(|error| invalid(error.to_string()))?;
                if target.elf_section_header().sh_flags(input.file.endian())
                    & u64::from(elf::SHF_ALLOC)
                    != 0
                    && section.size() != 0
                {
                    return Err(invalid("relocations target unplaced allocated storage"));
                }
                continue;
            };
            if placed.segment == Segment::Bss {
                return Err(invalid(
                    "relocations cannot target BSS storage: it holds no file bytes",
                ));
            }
            let records = section.data().map_err(|error| invalid(error.to_string()))?;
            for record in records.chunks_exact(24) {
                let offset = u64::from_le_bytes(record[..8].try_into().unwrap());
                let info = u64::from_le_bytes(record[8..16].try_into().unwrap());
                let addend = i64::from_le_bytes(record[16..24].try_into().unwrap());
                let kind = info as u32;
                let width = relocation_width(kind)?;
                let place = checked_end(placed.section.address, offset)?;
                if checked_end(place, width)? > placed.section.address + placed.section.size {
                    return Err(invalid("relocation write exceeds its section"));
                }
                let (symbol_address, symbol_segment) =
                    resolve_symbol(definitions, globals, object, (info >> 32) as usize)?;
                let effective = i128::from(symbol_address) + i128::from(addend);
                match (placed.segment, kind, symbol_segment) {
                    (Segment::Image, elf::R_AARCH64_ADR_PREL_PG_HI21, Segment::Image) => {
                        // Same-block ADRP: the page difference survives the
                        // block move, so patch the constant now.
                        patch_word(&mut program.image, &mut writes, place, kind, effective)?;
                    }
                    (Segment::Image, elf::R_AARCH64_ADR_PREL_PG_HI21, _) => {
                        // The page difference depends on both block bases, so
                        // the ADRP stays untouched and enters the table; its
                        // paired low-12 offset is patched by this record's
                        // ADD/load-store sibling.
                        check_adrp_opcode(&program.image, place)?;
                        emit_entry(
                            &mut table,
                            &mut emitted,
                            place,
                            effective,
                            RELOCATION_KIND_ADRP,
                        )?;
                    }
                    (
                        Segment::Image,
                        elf::R_AARCH64_ADD_ABS_LO12_NC
                        | elf::R_AARCH64_LDST8_ABS_LO12_NC
                        | elf::R_AARCH64_LDST16_ABS_LO12_NC
                        | elf::R_AARCH64_LDST32_ABS_LO12_NC
                        | elf::R_AARCH64_LDST64_ABS_LO12_NC
                        | elf::R_AARCH64_LDST128_ABS_LO12_NC,
                        _,
                    ) => {
                        // Low-12 offsets are invariant under a 2 MiB-aligned
                        // move for both segments, so these are link-time
                        // constants whatever the symbol's segment is.
                        patch_word(&mut program.image, &mut writes, place, kind, effective)?;
                    }
                    (
                        Segment::Image,
                        elf::R_AARCH64_JUMP26 | elf::R_AARCH64_CALL26,
                        Segment::Image,
                    ) => {
                        patch_word(&mut program.image, &mut writes, place, kind, effective)?;
                    }
                    (Segment::Image, elf::R_AARCH64_JUMP26 | elf::R_AARCH64_CALL26, _) => {
                        return Err(invalid("branches must stay inside the executable image"));
                    }
                    (Segment::Image, _, _) => {
                        return Err(invalid(format!(
                            "relocation {kind} cannot be relocated inside the image"
                        )));
                    }
                    (Segment::Data, elf::R_AARCH64_ABS64, Segment::Image) => {
                        emit_entry(
                            &mut table,
                            &mut emitted,
                            place,
                            effective,
                            RELOCATION_KIND_ABS64,
                        )?;
                    }
                    (Segment::Data, elf::R_AARCH64_ABS64, Segment::Data | Segment::Bss) => {
                        emit_entry(
                            &mut table,
                            &mut emitted,
                            place,
                            effective,
                            RELOCATION_KIND_ABS64_DATA,
                        )?;
                    }
                    (Segment::Data, _, _) => {
                        return Err(invalid(format!(
                            "relocation {kind} in data storage: only ABS64 pointers into program segments are supported"
                        )));
                    }
                    (Segment::Bss, _, _) => unreachable!("BSS records are rejected above"),
                }
            }
        }
    }
    Ok(table)
}

fn check_adrp_opcode(image: &[u8], place: u64) -> Result<()> {
    let start = usize::try_from(place).map_err(|_| invalid("relocation offset overflow"))?;
    if start + 4 > image.len() {
        return Err(invalid("ADRP relocation outside the image"));
    }
    let word = u32::from_le_bytes(image[start..start + 4].try_into().unwrap());
    if word & 0x9f00_0000 != 0x9000_0000 {
        return Err(invalid("ADRP relocation opcode mismatch"));
    }
    Ok(())
}

fn check_u32(value: i128) -> Result<u32> {
    u32::try_from(value).map_err(|_| invalid("relocation target does not fit the table"))
}

fn emit_entry(
    table: &mut Vec<Relocation>,
    emitted: &mut BTreeSet<(u32, u32)>,
    place: u64,
    effective: i128,
    kind: u32,
) -> Result<()> {
    let offset = u32::try_from(place).map_err(|_| invalid("table offset does not fit"))?;
    let target = check_u32(effective)?;
    if !emitted.insert((kind, offset)) {
        return Err(invalid("duplicate relocation table entry"));
    }
    table.push(Relocation {
        offset,
        target,
        kind,
    });
    Ok(())
}

/// Patch one 4-byte link-time constant into the image, with the XIP linker's
/// opcode, range, and alignment checks.
fn patch_word(
    image: &mut [u8],
    writes: &mut BTreeMap<u64, u64>,
    place: u64,
    kind: u32,
    effective: i128,
) -> Result<()> {
    let width = relocation_width(kind)?;
    let start = usize::try_from(place).map_err(|_| invalid("relocation offset overflow"))?;
    if place % 4 != 0 || width != 4 {
        return Err(invalid("link-time relocations must be 4-byte instructions"));
    }
    if start + 4 > image.len() {
        return Err(invalid("relocation write exceeds the image"));
    }
    let end = place + 4;
    if writes
        .range(..end)
        .next_back()
        .is_some_and(|(_, previous_end)| *previous_end > place)
    {
        return Err(invalid("overlapping relocation writes"));
    }
    writes.insert(place, end);
    let target = u64::try_from(effective).map_err(|_| invalid("negative link-time target"))?;
    let word = u32::from_le_bytes(image[start..start + 4].try_into().unwrap());
    let patched = relocate_instruction(kind, word, place, target)?;
    image[start..start + 4].copy_from_slice(&patched.to_le_bytes());
    Ok(())
}

/// Independent re-validation of the assembled program against its own bytes:
/// every table entry must land inside its segment, be aligned, and point at
/// an actual ADRP instruction when it patches one. This runs on the finished
/// segments, not on linker bookkeeping, so a placement or bookkeeping bug
/// cannot survive into a package.
fn self_check(program: &ProgramLink) -> Result<()> {
    // Image and data are separate address spaces that both start at zero,
    // so their table entries are overlap-checked separately.
    let mut image_entries = BTreeMap::<u64, u64>::new();
    let mut data_entries = BTreeMap::<u64, u64>::new();
    for relocation in &program.relocations {
        match relocation.kind {
            RELOCATION_KIND_ADRP => {
                let offset = u64::from(relocation.offset);
                if offset % 4 != 0 || offset + 4 > program.image.len() as u64 {
                    return Err(invalid("ADRP table entry outside the image"));
                }
                check_adrp_opcode(&program.image, offset)?;
                if u64::from(relocation.target) >= program.data.len() as u64 + program.bss_size {
                    return Err(invalid("ADRP table target outside the data block"));
                }
                claim_range(&mut image_entries, offset, 4)?;
            }
            RELOCATION_KIND_ABS64 => {
                let offset = u64::from(relocation.offset);
                if offset % 8 != 0 || offset + 8 > program.data.len() as u64 {
                    return Err(invalid("ABS64 table entry outside the data block"));
                }
                if u64::from(relocation.target) >= program.image.len() as u64 {
                    return Err(invalid("ABS64 table target outside the image"));
                }
                claim_range(&mut data_entries, offset, 8)?;
            }
            RELOCATION_KIND_ABS64_DATA => {
                let offset = u64::from(relocation.offset);
                if offset % 8 != 0 || offset + 8 > program.data.len() as u64 {
                    return Err(invalid("ABS64_DATA entry outside initialized data"));
                }
                if u64::from(relocation.target) >= program.data.len() as u64 + program.bss_size {
                    return Err(invalid("ABS64_DATA target outside data or BSS"));
                }
                claim_range(&mut data_entries, offset, 8)?;
            }
            _ => return Err(invalid("unknown relocation kind in the linked table")),
        }
    }
    Ok(())
}

fn claim_range(entries: &mut BTreeMap<u64, u64>, start: u64, width: u64) -> Result<()> {
    let end = checked_end(start, width)?;
    if entries
        .range(..end)
        .next_back()
        .is_some_and(|(_, previous_end)| *previous_end > start)
    {
        return Err(invalid("overlapping relocation table entries"));
    }
    entries.insert(start, end);
    Ok(())
}
