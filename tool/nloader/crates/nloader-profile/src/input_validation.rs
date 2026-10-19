//! Original switch banks, callback ownership, and worker identity evidence.
use crate::{sha256, InputServices, IssueKind, Profile, ValidationIssue, ValidationReport};
use std::collections::{BTreeMap, BTreeSet};

pub const INPUT_BODIES: &[(&str, u32)] = &[
    ("input_decoder", 1916),
    ("input_bank", 28),
    ("input_worker", 1912),
    ("input_register", 44),
    ("current_task", 144),
];
fn issue(report: &mut ValidationReport, field: impl Into<String>, message: &str) {
    report.issues.push(ValidationIssue {
        field: field.into(),
        kind: IssueKind::Conflict,
        message: message.into(),
    });
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn word(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}
fn branch(bytes: &[u8], offset: usize, base: u64, target: u64) -> bool {
    word(bytes, offset).is_some_and(|w| {
        w & 0xfc000000 == 0x94000000
            && base.checked_add(offset as u64).and_then(|site| {
                site.checked_add_signed(i64::from(((w & 0x03ffffff) as i32) << 6 >> 6) * 4)
            }) == Some(target)
    })
}
fn materializes(bytes: &[u8], offset: usize, register: u32, value: u64) -> bool {
    (0..4).all(|n| {
        word(bytes, offset + n * 4)
            == Some(
                (if n == 0 { 0xd2800000 } else { 0xf2800000 })
                    | ((n as u32) << 21)
                    | (((value >> (n * 16)) as u32 & 65535) << 5)
                    | register,
            )
    })
}

pub fn validate_input(profile: &Profile, input: &InputServices, report: &mut ValidationReport) {
    if profile.identity.model != "Z8"
        || profile.identity.firmware != "3.11"
        || input.reserved != [0, 0xc000, 0]
    {
        issue(
            report,
            "services.input",
            "only the verified Z8 C3.11 banks and reserved MENU/DELETE controls are supported",
        );
    }
    if !profile.services.exit.as_ref().is_some_and(|exit| {
        exit.input_callback == input.callback_slot && exit.bank == 1 && exit.mask == 0xc000
    }) {
        issue(
            report,
            "services.input.callback_slot",
            "input must share the verified loader exit callback owner",
        );
    }
    if input.entry("current_task") != Some(input.current_task) {
        issue(
            report,
            "services.input.current_task",
            "worker identity must name its complete original function",
        );
    }
    let mut banks = BTreeSet::new();
    for table in &input.key_tables {
        if table.bank >= 3
            || !banks.insert(table.bank)
            || !valid_hash(&table.sha256)
            || table.address % 4 != 0
            || !profile.memory.is_xip_range(table.address, 32 * 40)
        {
            issue(
                report,
                "services.input.key_tables",
                "all three complete original bank tables must be mapped and distinct",
            );
        }
    }
    if input.key_tables.len() != 3 || banks.len() != 3 {
        issue(
            report,
            "services.input.key_tables",
            "exactly three 32-record name/mask tables are required",
        );
    }
    let mut keys = BTreeSet::new();
    if input.bindings.is_empty() || input.bindings.len() > 12 {
        issue(
            report,
            "services.input.bindings",
            "declare one to twelve stable application keys",
        );
    }
    for binding in &input.bindings {
        let (bank, names) = binding.key.sources();
        let sources: BTreeSet<_> = binding.sources.iter().map(String::as_str).collect();
        let expected: BTreeSet<_> = names.iter().copied().collect();
        if !keys.insert(binding.key)
            || binding.bank != bank
            || sources != expected
            || sources.len() != binding.sources.len()
            || binding.mask == 0
            || (binding.bank < 3 && binding.mask & input.reserved[binding.bank as usize] != 0)
        {
            issue(report, "services.input.bindings", "keys must use their reviewed native sources, with no duplicate key or reserved exit bit");
        }
    }
    let mut names = BTreeSet::new();
    for body in &input.bodies {
        if !names.insert(body.name.as_str())
            || !valid_hash(&body.sha256)
            || INPUT_BODIES
                .iter()
                .find(|(name, _)| *name == body.name)
                .is_none_or(|(_, bytes)| *bytes != body.length)
            || body.address % 4 != 0
            || !profile
                .memory
                .is_xip_range(body.address, u64::from(body.length))
        {
            issue(
                report,
                format!("services.input.bodies.{}", body.name),
                "complete original input functions are required",
            );
        }
        if body.name != "input_decoder"
            && body.name != "current_task"
            && !profile.services.exit.as_ref().is_some_and(|exit| {
                exit.bodies
                    .iter()
                    .any(|existing| existing.name == body.name && existing == body)
            })
        {
            issue(
                report,
                format!("services.input.bodies.{}", body.name),
                "shared input evidence must exactly match the exit owner evidence",
            );
        }
    }
    for (name, _) in INPUT_BODIES {
        if !names.contains(name) {
            issue(
                report,
                format!("services.input.bodies.{name}"),
                "missing original input function",
            );
        }
    }
}

pub fn validate_input_bytes(
    profile: &Profile,
    input: &InputServices,
    module: &[u8],
    report: &mut ValidationReport,
) {
    let slice = |address, size| {
        let offset = usize::try_from(profile.memory.address_to_offset(address, size).ok()?).ok()?;
        module.get(offset..offset.checked_add(size as usize)?)
    };
    let mut native = BTreeMap::new();
    for table in &input.key_tables {
        let Some(bytes) = slice(table.address, 1280) else {
            issue(
                report,
                "services.input.key_tables",
                "original key table bytes are unavailable",
            );
            continue;
        };
        if !sha256(bytes).eq_ignore_ascii_case(&table.sha256) {
            issue(
                report,
                "services.input.key_tables",
                "complete key table differs from the original image",
            );
        }
        let mut bits = 0u32;
        for row in bytes.chunks_exact(40) {
            let end = row[..36].iter().position(|b| *b == 0).unwrap_or(36);
            let name = std::str::from_utf8(&row[..end]).unwrap_or("");
            let mask = word(row, 36).unwrap_or(0);
            if end == 36
                || !name.starts_with(&format!("ID_SW{}_", table.bank))
                || !mask.is_power_of_two()
                || bits & mask != 0
                || native.insert(name.to_owned(), (table.bank, mask)).is_some()
            {
                issue(
                    report,
                    "services.input.key_tables",
                    "original key names and single-bit masks must be unique",
                );
            }
            bits |= mask;
        }
        if bits != u32::MAX {
            issue(
                report,
                "services.input.key_tables",
                "original table must account for every bank bit",
            );
        }
    }
    for binding in &input.bindings {
        let mut mask = 0u32;
        for name in &binding.sources {
            match native.get(name) {
                Some((bank, bit)) if *bank == binding.bank && !name.contains("BLANK") => {
                    mask |= bit
                }
                _ => issue(
                    report,
                    "services.input.bindings",
                    "declared source is not an original named control in this bank",
                ),
            }
        }
        if mask != binding.mask {
            issue(
                report,
                "services.input.bindings",
                "declared physical mask differs from the actual original source masks",
            );
        }
    }
    for body in &input.bodies {
        if !slice(body.address, u64::from(body.length))
            .is_some_and(|b| sha256(b).eq_ignore_ascii_case(&body.sha256))
        {
            issue(
                report,
                format!("services.input.bodies.{}", body.name),
                "complete input function differs from the original image",
            );
        }
    }
    let body = |name: &str| {
        input
            .bodies
            .iter()
            .find(|b| b.name == name)
            .and_then(|b| slice(b.address, u64::from(b.length)))
    };
    let bank_words = [
        u32::from_le_bytes([0x48, 0, 1, 0x4a]),
        0x29000801,
        0x0a010109,
        0x0a02010a,
        0x29012408,
        0xb900100a,
        0xd65f03c0,
    ];
    if !body("current_task").is_some_and(|b| {
        [
            (0x00, 0xd53b4228),
            (0x10, 0xd538d089),
            (0x14, 0xb9405129),
            (0x4c, 0xd538d089),
            (0x54, 0xf9400129),
            (0x70, 0xb9000009),
            (0x74, 0x2a1f03e0),
            (0x84, 0xd65f03c0),
            (0x88, 0x321b77e0),
            (0x8c, 0xd65f03c0),
        ]
        .iter()
        .all(|(offset, value)| word(b, *offset) == Some(*value))
    }) {
        issue(
            report,
            "services.input.bodies.current_task",
            "current task query must write its output and preserve native failure",
        );
    }
    if !body("input_bank").is_some_and(|b| {
        bank_words
            .iter()
            .enumerate()
            .all(|(n, v)| word(b, n * 4) == Some(*v))
    }) {
        issue(
            report,
            "services.input.bodies.input_bank",
            "current/previous/changed/pressed/released semantics differ",
        );
    }
    let worker_address = input.entry("input_worker").unwrap_or(0);
    let bank_address = input.entry("input_bank").unwrap_or(0);
    if !body("input_worker").is_some_and(|b| {
        word(b, 0x44) == Some(0x91002280)
            && word(b, 0x58) == Some(0x91007280)
            && word(b, 0x6c) == Some(0x9100c280)
            && [0x50, 0x64, 0x78]
                .iter()
                .all(|offset| branch(b, *offset, worker_address, bank_address))
            && materializes(b, 0x61c, 8, input.callback_slot)
            && word(b, 0x65c) == Some(0xaa1403e0)
            && word(b, 0x668) == Some(0xd63f0100)
    }) {
        issue(
            report,
            "services.input.bodies.input_worker",
            "original three-bank layout and callback handoff differ",
        );
    }
    if !body("input_decoder").is_some_and(|b| {
        word(b, 0) == Some(0xd102c3ff)
            && word(b, 0x63c) == Some(0x29017ea8)
            && word(b, 0x73c) == Some(0x290022ab)
            && word(b, 0x778) == Some(0xd65f03c0)
    }) {
        issue(
            report,
            "services.input.bodies.input_decoder",
            "original report decoder bank outputs differ",
        );
    }
}
