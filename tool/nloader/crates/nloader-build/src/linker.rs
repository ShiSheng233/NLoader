//! Strict, deterministic linking of freestanding read-only AArch64 objects.

use crate::{Error, Result};
use object::read::elf::{ElfFile64, SectionHeader};
use object::{elf, Object, ObjectSection, ObjectSymbol, SectionIndex, SymbolSection};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ObjectInput {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkedSection {
    pub object: String,
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub alignment: u64,
    pub executable: bool,
}

#[derive(Debug, Serialize)]
pub struct LinkedImage {
    #[serde(skip)]
    pub bytes: Vec<u8>,
    pub entry: u64,
    pub sections: Vec<LinkedSection>,
    pub symbols: BTreeMap<String, u64>,
}

struct Input<'a> {
    name: &'a str,
    file: ElfFile64<'a>,
}

#[derive(Clone)]
struct Definition {
    address: Option<u64>,
    name: String,
    external: bool,
    executable_function: bool,
}

type Placements = BTreeMap<(usize, usize), LinkedSection>;
type Definitions = BTreeMap<(usize, usize), Definition>;

fn invalid(message: impl Into<String>) -> Error {
    Error::Object(message.into())
}

pub(crate) fn checked_end(start: u64, size: u64) -> Result<u64> {
    start
        .checked_add(size)
        .ok_or_else(|| invalid("address or size overflow"))
}

/// Link in object-name and section-index order. No dynamic linking, writable
/// storage, COMDAT selection, or implicit-addend relocations are supported.
pub fn link(objects: &[ObjectInput], base: u64, capacity: u64, entry: &str) -> Result<LinkedImage> {
    if objects.is_empty() || capacity == 0 || base % 4 != 0 || entry.is_empty() {
        return Err(invalid(
            "link needs objects, aligned base, capacity, and entry name",
        ));
    }
    let limit = checked_end(base, capacity)?;
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
    let (placements, end) = place_sections(&inputs, base, limit)?;
    let (definitions, globals) = resolve_definitions(&inputs, &placements)?;
    let entry_definition = globals
        .get(entry)
        .ok_or_else(|| invalid("entry is not a defined global"))?;
    let entry_address = entry_definition
        .address
        .ok_or_else(|| invalid("entry has no address"))?;
    if !entry_definition.executable_function || entry_address % 4 != 0 {
        return Err(invalid(
            "entry must be an aligned function inside executable storage",
        ));
    }
    let length = usize::try_from(end - base).map_err(|_| invalid("linked image is too large"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| invalid("cannot allocate linked image"))?;
    bytes.resize(length, 0);
    for ((object, section), placed) in &placements {
        let source = inputs[*object]
            .file
            .section_by_index(SectionIndex(*section))
            .map_err(|error| invalid(error.to_string()))?;
        let data = source.data().map_err(|error| invalid(error.to_string()))?;
        let start = (placed.address - base) as usize;
        bytes[start..start + data.len()].copy_from_slice(data);
    }
    apply_relocations(
        &inputs,
        &placements,
        &definitions,
        &globals,
        base,
        &mut bytes,
    )?;
    Ok(LinkedImage {
        bytes,
        entry: entry_address,
        sections: placements.into_values().collect(),
        symbols: globals
            .into_iter()
            .filter_map(|(name, definition)| definition.address.map(|address| (name, address)))
            .collect(),
    })
}

/// Validate ELF table structure (one symtab, well-formed RELA) for any
/// AArch64 relocatable object, independent of the XIP placement rules.
pub(crate) fn validate_tables(file: &ElfFile64<'_>) -> Result<()> {
    let mut symbol_tables = 0;
    for section in file.sections() {
        let raw = section.elf_section_header();
        let kind = raw.sh_type(file.endian());
        let entry_size = raw.sh_entsize(file.endian());
        match kind {
            elf::SHT_GROUP | elf::SHT_DYNSYM | elf::SHT_DYNAMIC | elf::SHT_REL | elf::SHT_RELR => {
                return Err(invalid(
                    "COMDAT, dynamic linking, and REL sections are unsupported",
                ));
            }
            elf::SHT_SYMTAB | elf::SHT_RELA => {
                if entry_size != 24 || section.size() % 24 != 0 {
                    return Err(invalid("malformed symbol or RELA table"));
                }
                let data = section.data().map_err(|error| invalid(error.to_string()))?;
                if data.len() as u64 != section.size() {
                    return Err(invalid("truncated symbol or RELA table"));
                }
                let linked = file
                    .section_by_index(SectionIndex(raw.sh_link(file.endian()) as usize))
                    .map_err(|error| invalid(error.to_string()))?;
                let expected = if kind == elf::SHT_SYMTAB {
                    elf::SHT_STRTAB
                } else {
                    elf::SHT_SYMTAB
                };
                if linked.elf_section_header().sh_type(file.endian()) != expected {
                    return Err(invalid(
                        "symbol or relocation table has invalid linked section",
                    ));
                }
                if kind == elf::SHT_SYMTAB {
                    symbol_tables += 1;
                } else {
                    let target = file
                        .section_by_index(SectionIndex(raw.sh_info(file.endian()) as usize))
                        .map_err(|error| invalid(error.to_string()))?;
                    if matches!(
                        target.elf_section_header().sh_type(file.endian()),
                        elf::SHT_REL | elf::SHT_RELA
                    ) {
                        return Err(invalid(
                            "relocation target cannot be another relocation table",
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    if symbol_tables != 1 {
        return Err(invalid(
            "exactly one static symbol table is required per object",
        ));
    }
    Ok(())
}

fn place_sections(inputs: &[Input<'_>], base: u64, limit: u64) -> Result<(Placements, u64)> {
    let mut result = BTreeMap::new();
    let mut cursor = base;
    for (object, input) in inputs.iter().enumerate() {
        for section in input.file.sections() {
            let raw = section.elf_section_header();
            let flags = raw.sh_flags(input.file.endian());
            if flags & u64::from(elf::SHF_ALLOC) == 0 {
                continue;
            }
            if flags & u64::from(elf::SHF_TLS | elf::SHF_COMPRESSED | elf::SHF_GROUP) != 0 {
                return Err(invalid(
                    "TLS, compressed, and grouped allocated sections are unsupported",
                ));
            }
            if section.size() == 0 {
                continue;
            }
            let allowed =
                u64::from(elf::SHF_ALLOC | elf::SHF_EXECINSTR | elf::SHF_MERGE | elf::SHF_STRINGS);
            if flags & !allowed != 0 {
                let name = section.name().unwrap_or("<unnamed>");
                return Err(invalid(format!(
                    "unsupported allocated section flags {flags:#x} on {name}"
                )));
            }
            if flags & u64::from(elf::SHF_WRITE) != 0
                || raw.sh_type(input.file.endian()) != elf::SHT_PROGBITS
            {
                return Err(invalid(
                    "XIP requires read-only allocated PROGBITS sections",
                ));
            }
            let alignment = section.align().max(1);
            if !alignment.is_power_of_two() {
                return Err(invalid("section alignment is not a power of two"));
            }
            cursor = checked_end(cursor, alignment - 1)? & !(alignment - 1);
            let end = checked_end(cursor, section.size())?;
            if end > limit {
                return Err(invalid("linked image exceeds reserved capacity"));
            }
            let data = section.data().map_err(|error| invalid(error.to_string()))?;
            if data.len() as u64 != section.size() {
                return Err(invalid("truncated allocated section"));
            }
            result.insert(
                (object, section.index().0),
                LinkedSection {
                    object: input.name.into(),
                    name: section
                        .name()
                        .map_err(|error| invalid(error.to_string()))?
                        .into(),
                    address: cursor,
                    size: section.size(),
                    alignment,
                    executable: flags & u64::from(elf::SHF_EXECINSTR) != 0,
                },
            );
            cursor = end;
        }
    }
    if cursor == base {
        return Err(invalid("no allocated code or data"));
    }
    Ok((result, cursor))
}

fn resolve_definitions(
    inputs: &[Input<'_>],
    placements: &Placements,
) -> Result<(Definitions, BTreeMap<String, Definition>)> {
    let mut definitions = BTreeMap::new();
    let mut globals = BTreeMap::new();
    for (object, input) in inputs.iter().enumerate() {
        for symbol in input.file.symbols() {
            if symbol.is_common() || symbol.kind() == object::SymbolKind::Tls {
                return Err(invalid("XIP forbids COMMON and TLS symbols"));
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
            let mut executable_function = false;
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
                    if let Some(placed) = placements.get(&(object, index.0)) {
                        executable_function = placed.executable
                            && symbol.kind() == object::SymbolKind::Text
                            && symbol
                                .address()
                                .checked_add(4)
                                .is_some_and(|end| end <= placed.size);
                        Some(checked_end(placed.address, symbol.address())?)
                    } else {
                        None
                    }
                }
                SymbolSection::Undefined | SymbolSection::None => None,
                _ => return Err(invalid("unsupported symbol section")),
            };
            let definition = Definition {
                address,
                name: name.clone(),
                external: global && symbol.is_undefined(),
                executable_function,
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

fn apply_relocations(
    inputs: &[Input<'_>],
    placements: &Placements,
    definitions: &Definitions,
    globals: &BTreeMap<String, Definition>,
    base: u64,
    bytes: &mut [u8],
) -> Result<()> {
    let mut writes = BTreeMap::<u64, u64>::new();
    for (object, input) in inputs.iter().enumerate() {
        for section in input.file.sections() {
            let raw = section.elf_section_header();
            if raw.sh_type(input.file.endian()) != elf::SHT_RELA {
                continue;
            }
            let target_index = raw.sh_info(input.file.endian()) as usize;
            let Some(target_section) = placements.get(&(object, target_index)) else {
                let target = input
                    .file
                    .section_by_index(SectionIndex(target_index))
                    .map_err(|error| invalid(error.to_string()))?;
                if target.elf_section_header().sh_flags(input.file.endian())
                    & u64::from(elf::SHF_ALLOC)
                    != 0
                    && section.size() != 0
                {
                    return Err(invalid("relocations cannot target empty allocated storage"));
                }
                continue;
            };
            let data = section.data().map_err(|error| invalid(error.to_string()))?;
            // Reading explicit records avoids silently skipping malformed entries.
            for record in data.chunks_exact(24) {
                let offset = u64::from_le_bytes(record[..8].try_into().unwrap());
                let info = u64::from_le_bytes(record[8..16].try_into().unwrap());
                let addend = i64::from_le_bytes(record[16..24].try_into().unwrap());
                let kind = info as u32;
                let width = relocation_width(kind)?;
                if checked_end(offset, width)? > target_section.size {
                    return Err(invalid("relocation write exceeds its section"));
                }
                let place = checked_end(target_section.address, offset)?;
                let end = checked_end(place, width)?;
                if writes
                    .range(..end)
                    .next_back()
                    .is_some_and(|(_, previous_end)| *previous_end > place)
                {
                    return Err(invalid("overlapping relocation writes"));
                }
                writes.insert(place, end);
                let definition = definitions
                    .get(&(object, (info >> 32) as usize))
                    .ok_or_else(|| invalid("relocation refers to invalid symbol index"))?;
                let address = definition
                    .address
                    .or_else(|| {
                        definition
                            .external
                            .then(|| {
                                globals
                                    .get(&definition.name)
                                    .and_then(|other| other.address)
                            })
                            .flatten()
                    })
                    .ok_or_else(|| {
                        invalid(format!("undefined or unplaced symbol: {}", definition.name))
                    })?;
                let target = u64::try_from(i128::from(address) + i128::from(addend))
                    .map_err(|_| invalid("symbol plus addend overflows address space"))?;
                let start = usize::try_from(place - base)
                    .map_err(|_| invalid("relocation offset overflow"))?;
                if width == 8 {
                    bytes[start..start + 8].copy_from_slice(&target.to_le_bytes());
                } else {
                    if !target_section.executable || place % 4 != 0 {
                        return Err(invalid(
                            "instruction relocation must address aligned executable storage",
                        ));
                    }
                    let word = u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap());
                    let value = relocate_instruction(kind, word, place, target)?;
                    bytes[start..start + 4].copy_from_slice(&value.to_le_bytes());
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn relocation_width(kind: u32) -> Result<u64> {
    match kind {
        elf::R_AARCH64_ABS64 => Ok(8),
        elf::R_AARCH64_ADR_PREL_PG_HI21
        | elf::R_AARCH64_ADD_ABS_LO12_NC
        | elf::R_AARCH64_JUMP26
        | elf::R_AARCH64_CALL26
        | elf::R_AARCH64_LDST8_ABS_LO12_NC
        | elf::R_AARCH64_LDST16_ABS_LO12_NC
        | elf::R_AARCH64_LDST32_ABS_LO12_NC
        | elf::R_AARCH64_LDST64_ABS_LO12_NC
        | elf::R_AARCH64_LDST128_ABS_LO12_NC => Ok(4),
        _ => Err(invalid(format!("unsupported AArch64 relocation {kind}"))),
    }
}

pub(crate) fn relocate_instruction(kind: u32, word: u32, place: u64, target: u64) -> Result<u32> {
    match kind {
        elf::R_AARCH64_JUMP26 | elf::R_AARCH64_CALL26 => {
            let opcode = if kind == elf::R_AARCH64_JUMP26 {
                0x1400_0000
            } else {
                0x9400_0000
            };
            if word & 0xfc00_0000 != opcode {
                return Err(invalid("branch relocation opcode mismatch"));
            }
            let delta = i128::from(target) - i128::from(place);
            if delta % 4 != 0 || !(-(1 << 27)..(1 << 27)).contains(&delta) {
                return Err(invalid("branch relocation range or alignment"));
            }
            Ok((word & 0xfc00_0000) | (((delta / 4) as u32) & 0x03ff_ffff))
        }
        elf::R_AARCH64_ADR_PREL_PG_HI21 => {
            if word & 0x9f00_0000 != 0x9000_0000 {
                return Err(invalid("ADRP relocation opcode mismatch"));
            }
            let pages = (i128::from(target & !4095) - i128::from(place & !4095)) / 4096;
            if !(-(1 << 20)..(1 << 20)).contains(&pages) {
                return Err(invalid("ADRP relocation range"));
            }
            Ok((word & !((3 << 29) | (0x7ffff << 5)))
                | (((pages as u32) & 3) << 29)
                | ((((pages as u32) >> 2) & 0x7ffff) << 5))
        }
        elf::R_AARCH64_ADD_ABS_LO12_NC => {
            if word & 0x7fc0_0000 != 0x1100_0000 {
                return Err(invalid("ADD relocation opcode mismatch"));
            }
            Ok((word & !(0xfff << 10)) | (((target as u32) & 0xfff) << 10))
        }
        _ => {
            let scale = match kind {
                elf::R_AARCH64_LDST8_ABS_LO12_NC => 0,
                elf::R_AARCH64_LDST16_ABS_LO12_NC => 1,
                elf::R_AARCH64_LDST32_ABS_LO12_NC => 2,
                elf::R_AARCH64_LDST64_ABS_LO12_NC => 3,
                elf::R_AARCH64_LDST128_ABS_LO12_NC => 4,
                _ => return Err(invalid("unsupported instruction relocation")),
            };
            let vector = word & (1 << 26) != 0;
            let size = word >> 30;
            let operation = (word >> 22) & 3;
            let instruction_scale = if vector && operation >= 2 { 4 } else { size };
            if word & 0x3b00_0000 != 0x3900_0000
                || instruction_scale != scale
                || vector && operation >= 2 && size != 0
                || !vector && (size == 3 && operation >= 2 || size == 2 && operation == 3)
            {
                return Err(invalid("load/store relocation opcode or width mismatch"));
            }
            let low = target & 4095;
            if low % (1 << scale) != 0 {
                return Err(invalid("load/store relocation alignment"));
            }
            Ok((word & !(0xfff << 10)) | (((low >> scale) as u32) << 10))
        }
    }
}
