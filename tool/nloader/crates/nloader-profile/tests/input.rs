//! Exercise the public profile types and the same validation used by builds.
use nloader_profile::{
    sha256, validate_input, validate_input_bytes, ExecutionBody, InputBinding, InputFamily,
    InputKey, InputKeyTable, InputServices, Profile, ValidationReport, INPUT_BODIES,
};
use nloader_profile::{ExecutionTable, ExitServices, MemorySegment, MemorySegmentKind};

fn put(module: &mut [u8], address: u64, offset: usize, words: &[u32]) {
    let at = (address - 0x1000) as usize + offset;
    for (n, word) in words.iter().enumerate() {
        module[at + n * 4..at + n * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}
fn materialize(value: u64, register: u32) -> Vec<u32> {
    (0..4)
        .map(|n| {
            (if n == 0 { 0xd2800000 } else { 0xf2800000 })
                | (n << 21)
                | (((value >> (n * 16)) as u32 & 65535) << 5)
                | register
        })
        .collect()
}
fn fixture() -> (Profile, InputServices, Vec<u8>) {
    let mut profile = Profile::default();
    profile.identity.model = "Z8".into();
    profile.identity.firmware = "3.11".into();
    let mut module = vec![0u8; 0x9000];
    profile.memory.xip_base = Some(0x1000);
    profile.memory.module_size = Some(module.len() as u64);
    profile.memory.segments = vec![MemorySegment {
        file_offset: 0,
        runtime_start: 0x1000,
        size: module.len() as u64,
        kind: MemorySegmentKind::Xip,
    }];
    let mut input = InputServices {
        family: InputFamily::Z8SwitchBanksV1,
        callback_slot: 0xb0000,
        current_task: 0x5000,
        reserved: [0, 0xc000, 0],
        key_tables: vec![],
        bindings: vec![InputBinding {
            key: InputKey::Up,
            bank: 0,
            mask: 0x2a,
            sources: InputKey::Up
                .sources()
                .1
                .iter()
                .map(|s| (*s).into())
                .collect(),
        }],
        bodies: INPUT_BODIES
            .iter()
            .enumerate()
            .map(|(n, (name, length))| ExecutionBody {
                name: (*name).into(),
                address: 0x1000 + n as u64 * 0x1000,
                length: *length,
                sha256: String::new(),
            })
            .collect(),
    };
    put(&mut module, 0x1000, 0, &[0xd102c3ff]);
    put(&mut module, 0x1000, 0x63c, &[0x29017ea8]);
    put(&mut module, 0x1000, 0x73c, &[0x290022ab]);
    put(&mut module, 0x1000, 0x778, &[0xd65f03c0]);
    put(
        &mut module,
        0x2000,
        0,
        &[
            u32::from_le_bytes([0x48, 0, 1, 0x4a]),
            0x29000801,
            0x0a010109,
            0x0a02010a,
            0x29012408,
            0xb900100a,
            0xd65f03c0,
        ],
    );
    for (offset, instruction) in [
        (0x44, 0x91002280),
        (0x58, 0x91007280),
        (0x6c, 0x9100c280),
        (0x65c, 0xaa1403e0),
        (0x668, 0xd63f0100),
    ] {
        put(&mut module, 0x3000, offset, &[instruction]);
    }
    for offset in [0x50, 0x64, 0x78] {
        let distance = (0x2000i64 - (0x3000 + offset) as i64) / 4;
        put(
            &mut module,
            0x3000,
            offset,
            &[0x94000000 | (distance as u32 & 0x3ffffff)],
        );
    }
    put(
        &mut module,
        0x3000,
        0x61c,
        &materialize(input.callback_slot, 8),
    );
    for (offset, instruction) in [
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
    ] {
        put(&mut module, 0x5000, offset, &[instruction]);
    }
    for body in &mut input.bodies {
        let at = (body.address - 0x1000) as usize;
        body.sha256 = sha256(&module[at..at + body.length as usize]);
    }
    for bank in 0..3u32 {
        let address = 0x6000 + u64::from(bank) * 0x500;
        let at = (address - 0x1000) as usize;
        for bit in 0..32usize {
            let suffix = match (bank, bit) {
                (0, 5) => "UP".into(),
                (0, 3) => "RIGHT_UP".into(),
                (0, 1) => "LEFT_UP".into(),
                _ => format!("BLANK_{bit}"),
            };
            let name = format!("ID_SW{bank}_{suffix}");
            module[at + bit * 40..at + bit * 40 + name.len()].copy_from_slice(name.as_bytes());
            put(&mut module, address, bit * 40 + 36, &[1u32 << bit]);
        }
        input.key_tables.push(InputKeyTable {
            bank,
            address,
            sha256: sha256(&module[at..at + 1280]),
        });
    }
    profile.services.exit = Some(ExitServices {
        input_callback: input.callback_slot,
        bank: 1,
        mask: 0xc000,
        release_mask: 0x8000,
        menu_release_code: 0x279,
        menu_release_mapping: ExecutionTable {
            name: "release".into(),
            address: 0,
            element_bytes: 4,
            values: vec![0, 0x279],
        },
        suspend: 0,
        resume: 0,
        terminate: 0,
        restart: 0,
        bodies: input
            .bodies
            .iter()
            .filter(|b| b.name != "input_decoder" && b.name != "current_task")
            .cloned()
            .collect(),
    });
    (profile, input, module)
}
fn report(profile: &Profile, input: &InputServices, module: &[u8]) -> ValidationReport {
    let mut report = ValidationReport::default();
    validate_input(profile, input, &mut report);
    validate_input_bytes(profile, input, module, &mut report);
    report
}

#[test]
fn original_bank_mapping_and_forwarded_owner_are_checked() {
    let (profile, input, module) = fixture();
    let checked = report(&profile, &input, &module);
    assert!(checked.is_valid(), "{checked:?}");
    assert_eq!(InputKey::Up.bit(), 1);
    assert_eq!(InputKey::ZoomOut.bit(), 2048);
    let serialized = toml::to_string(&input).unwrap();
    assert_eq!(toml::from_str::<InputServices>(&serialized).unwrap(), input);
    let mut registered = profile.clone();
    registered.services.input = Some(input.clone());
    assert_eq!(
        Profile::from_toml(&toml::to_string(&registered).unwrap())
            .unwrap()
            .services
            .input,
        Some(input.clone())
    );
    for case in 0..9 {
        let mut changed = input.clone();
        match case {
            0 => changed.bindings[0].mask ^= 1,
            1 => changed.bindings[0].sources = vec!["ID_SW1_MENU".into()],
            2 => changed.reserved = [0; 3],
            3 => changed.callback_slot += 8,
            4 => changed.key_tables[0].bank = 1,
            5 => changed.bindings.push(changed.bindings[0].clone()),
            6 => {
                changed.bodies.pop();
            }
            7 => changed.bodies[2].address += 4,
            _ => changed.current_task += 4,
        }
        assert!(!report(&profile, &changed, &module).is_valid(), "{case}");
    }
}

#[test]
fn recomputed_hash_does_not_hide_changed_bank_or_callback_semantics() {
    let (profile, input, module) = fixture();
    for (index, offset) in [
        (0, 0x63c),
        (1, 8),
        (2, 0x44),
        (2, 0x668),
        (4, 0x70),
        (4, 0x88),
    ] {
        let mut bytes = module.clone();
        let mut changed = input.clone();
        let body = &mut changed.bodies[index];
        let at = (body.address - 0x1000) as usize;
        bytes[at + offset] ^= 1;
        body.sha256 = sha256(&bytes[at..at + body.length as usize]);
        let mut matching_profile = profile.clone();
        if let Some(shared) = matching_profile
            .services
            .exit
            .as_mut()
            .unwrap()
            .bodies
            .iter_mut()
            .find(|b| b.name == body.name)
        {
            shared.sha256 = body.sha256.clone();
        }
        assert!(!report(&matching_profile, &changed, &bytes).is_valid());
    }
}

#[test]
#[ignore = "requires explicit local original firmware evidence paths"]
fn reviewed_local_input_declaration_matches_original_firmware() {
    let profile_path = std::env::var("NLR_INPUT_PROFILE").expect("set NLR_INPUT_PROFILE");
    let declaration_path =
        std::env::var("NLR_INPUT_DECLARATION").expect("set NLR_INPUT_DECLARATION");
    let module_path = std::env::var("NLR_INPUT_MODULE").expect("set NLR_INPUT_MODULE");
    let profile = Profile::from_toml(&std::fs::read_to_string(profile_path).unwrap()).unwrap();
    let input: InputServices =
        toml::from_str(&std::fs::read_to_string(declaration_path).unwrap()).unwrap();
    assert_eq!(profile.services.input.as_ref(), Some(&input));
    let declaration = profile.validate(nloader_profile::BuildMode::Exec);
    assert!(declaration.is_valid(), "{declaration:?}");
    let module = std::fs::read(module_path).unwrap();
    let checked = report(&profile, &input, &module);
    assert!(checked.is_valid(), "{checked:?}");
}
