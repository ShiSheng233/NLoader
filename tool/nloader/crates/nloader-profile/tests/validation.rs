use nloader_profile::*;

fn fixture() -> (Profile, Vec<u8>, Vec<u8>) {
    let module = vec![0; 512];
    let package = b"synthetic package, not Nikon firmware".to_vec();
    let mut profile = Profile::draft("Z8", "3.11");
    profile.identity.container = Some(ContainerKind::LegacyXor);
    profile.identity.stock_pkg = Some("synthetic.bin".into());
    profile.identity.eg_module = Some("synthetic.bi".into());
    profile.checks.package_sha256 = Some(sha256(&package));
    profile.checks.module_sha256 = Some(sha256(&module));
    profile.memory = Memory {
        segments: vec![MemorySegment {
            file_offset: 0,
            runtime_start: 4096,
            size: 512,
            kind: MemorySegmentKind::Xip,
        }],
        xip_base: Some(4096),
        module_size: Some(512),
        slack: Some(Slack {
            start: 4352,
            end: 4608,
            require_zero: true,
        }),
        link_base: Some(4352),
        link_size: Some(256),
        ram_pool: None,
        program_budget_blocks: None,
        program_max_resident: None,
        program_arena_bytes: None,
    };
    (profile, package, module)
}
fn issue(profile: &Profile, kind: IssueKind, field: &str) -> bool {
    profile
        .validate(BuildMode::Marker)
        .issues
        .iter()
        .any(|issue| issue.kind == kind && issue.field == field)
}
fn validate_input(profile: &Profile, package: &[u8], module: &[u8]) -> ValidationReport {
    profile.validate_for(
        BuildMode::Marker,
        &ValidationContext {
            model: "Z8",
            firmware: "3.11",
            package: Some(package),
            module_name: "synthetic.bi",
            module,
        },
    )
}
#[test]
fn draft_round_trip_is_deterministic_but_not_buildable() {
    let draft = Profile::draft("Z8", "3.11");
    let serialized = draft.to_toml().unwrap();
    assert_eq!(Profile::from_toml(&serialized).unwrap(), draft);
    assert_eq!(draft.to_toml().unwrap(), serialized);
    for mode in [
        BuildMode::Marker,
        BuildMode::HookOnly,
        BuildMode::Page,
        BuildMode::LoadOnly,
        BuildMode::PrepareOnly,
        BuildMode::Exec,
    ] {
        assert!(!draft.validate(mode).is_valid());
    }
}
#[test]
fn complete_synthetic_marker_validates_declared_and_actual_data() {
    let (profile, package, module) = fixture();
    assert!(
        profile.validate(BuildMode::Marker).is_valid(),
        "{:?}",
        profile.validate(BuildMode::Marker)
    );
    assert!(validate_input(&profile, &package, &module).is_valid());
    let encoded = profile.to_toml().unwrap();
    assert_eq!(Profile::from_toml(&encoded).unwrap(), profile);
}

#[test]
fn declared_program_services_require_target_entry_evidence() {
    let (mut profile, package, module) = fixture();
    profile.services.program = Some(ProgramServices {
        task_delay: Some(4096),
        ..ProgramServices::default()
    });
    assert!(profile
        .validate(BuildMode::Exec)
        .issues
        .iter()
        .any(|i| i.field == "service_fingerprints.program.task_delay"
            && i.kind == IssueKind::Missing));
    profile.service_fingerprints.insert(
        "program.task_delay".into(),
        ServiceFingerprint {
            eg_off: 0,
            stock: vec![0; 4],
        },
    );
    assert!(!profile
        .validate(BuildMode::Exec)
        .issues
        .iter()
        .any(|i| i.field == "service_fingerprints.program.task_delay"));
    assert!(!validate_input(&profile, &package, &module)
        .issues
        .iter()
        .any(|i| i.field == "service_fingerprints.program.task_delay"));
    profile
        .service_fingerprints
        .get_mut("program.task_delay")
        .unwrap()
        .stock[0] = 1;
    assert!(validate_input(&profile, &package, &module)
        .issues
        .iter()
        .any(|i| i.field == "service_fingerprints.program.task_delay"));
    profile.services.program.as_mut().unwrap().task_delay = Some(4352);
    assert!(issue(
        &profile,
        IssueKind::Conflict,
        "services.program.task_delay"
    ));
}

#[test]
fn program_input_rejects_unmapped_slots_and_exit_key_capture() {
    let (mut profile, package, mut module) = fixture();
    profile.services.program = Some(ProgramServices {
        input_slot: Some(4096),
        input_original: Some(4096),
        banks: 3,
        bank_stride: 20,
        keep_bank: 1,
        keep_mask: 0xc000,
        keys: vec![[0, 1], [1, 0x4000]],
        ..ProgramServices::default()
    });
    assert!(issue(
        &profile,
        IssueKind::OutOfBounds,
        "services.program.input_slot"
    ));
    assert!(issue(
        &profile,
        IssueKind::Conflict,
        "services.program.keys"
    ));
    profile.memory.segments.push(MemorySegment {
        file_offset: 384,
        runtime_start: 8192,
        size: 128,
        kind: MemorySegmentKind::Ram,
    });
    profile.memory.segments[0].size = 384;
    let program = profile.services.program.as_mut().unwrap();
    program.input_slot = Some(8192);
    program.keys = vec![[0, 1], [2, 4]];
    assert!(!issue(
        &profile,
        IssueKind::OutOfBounds,
        "services.program.input_slot"
    ));
    assert!(!issue(
        &profile,
        IssueKind::Conflict,
        "services.program.keys"
    ));
    module[384..392].copy_from_slice(&4096u64.to_le_bytes());
    profile.checks.module_sha256 = Some(sha256(&module));
    assert!(!validate_input(&profile, &package, &module)
        .issues
        .iter()
        .any(|i| i.field == "services.program.input_slot"));
    module[384] ^= 1;
    assert!(validate_input(&profile, &package, &module)
        .issues
        .iter()
        .any(|i| i.field == "services.program.input_slot" && i.kind == IssueKind::Conflict));
    profile.services.program.as_mut().unwrap().keys = vec![[3, 1]];
    assert!(issue(
        &profile,
        IssueKind::Conflict,
        "services.program.keys"
    ));
    profile.services.program.as_mut().unwrap().banks = u32::MAX;
    assert!(issue(
        &profile,
        IssueKind::Invalid,
        "services.program.banks"
    ));
}

/// A body whose scan callback is registered at run time (the Z 6III) has no
/// slot inside the loaded image: the declaration says so, and the stock
/// occupant is then core's to check before it installs its own.
#[test]
fn run_time_callback_slots_are_declared_and_left_to_the_run_time_check() {
    let (mut profile, package, module) = fixture();
    profile.services.program = Some(ProgramServices {
        input_slot: Some(4096),
        input_original: Some(0x1234),
        input_slot_dynamic: true,
        banks: 4,
        bank_stride: 20,
        keep_bank: 0,
        keep_mask: 0x200,
        keys: vec![[3, 1]],
        ..ProgramServices::default()
    });
    // Mapped storage is where a run-time slot must not be.
    assert!(issue(
        &profile,
        IssueKind::OutOfBounds,
        "services.program.input_slot"
    ));
    let program = profile.services.program.as_mut().unwrap();
    program.input_slot = Some(0x10000); // DRAM no segment covers
    assert!(!issue(
        &profile,
        IssueKind::OutOfBounds,
        "services.program.input_slot"
    ));
    // Four banks are a body's layout, not a mistake; the fifth is past
    // what core copies.
    assert!(!issue(
        &profile,
        IssueKind::Invalid,
        "services.program.banks"
    ));
    assert!(!validate_input(&profile, &package, &module)
        .issues
        .iter()
        .any(|i| i.field == "services.program.input_slot"));
    let program = profile.services.program.as_mut().unwrap();
    program.banks = 5;
    assert!(issue(
        &profile,
        IssueKind::Invalid,
        "services.program.banks"
    ));
    let program = profile.services.program.as_mut().unwrap();
    program.banks = 4;
    // Without the declaration the same slot is unmapped storage again.
    program.input_slot_dynamic = false;
    assert!(issue(
        &profile,
        IssueKind::OutOfBounds,
        "services.program.input_slot"
    ));
    assert!(validate_input(&profile, &package, &module)
        .issues
        .iter()
        .any(|i| i.field == "services.program.input_slot"));
}

#[test]
fn program_screen_rejects_partial_pixel_pairs() {
    let (mut profile, _, _) = fixture();
    profile.services.program = Some(ProgramServices {
        scanout_colour: Some(0x10000),
        width: 3,
        height: 2,
        stride: 8,
        plane_lo: 0x20000,
        plane_hi: 0x20100,
        ..ProgramServices::default()
    });
    assert!(issue(
        &profile,
        IssueKind::Invalid,
        "services.program.width"
    ));
    profile.services.program.as_mut().unwrap().width = 4;
    assert!(!issue(
        &profile,
        IssueKind::Invalid,
        "services.program.width"
    ));
}
#[test]
fn unknown_fields_and_types_are_not_silently_ignored() {
    assert!(Profile::from_toml("[identity]\nmodel = 'Z8'").is_err());
    assert!(Profile::from_toml("schema = 1\nunknown = true").is_err());
    assert!(Profile::from_toml("schema = 1\n[memory]\nlink_bsae = 12").is_err());
    assert!(Profile::from_toml("schema = 1\n[graphics]\nbitmap_blit = 12").is_err());
    assert!(Profile::from_toml("schema = 1\n[identity]\ncontainer = 'guess'").is_err());
    // The Battery info diagnostic hooks and their status line were removed;
    // an old profile that still declares them is refused, not half-read.
    assert!(Profile::from_toml(
        "schema = 1\n[hooks.battery_entry]\ntarget = 'screen_entry'\nsite = 1\nstock = [0]"
    )
    .is_err());
    for field in ["screen_entry = 1", "status_slot = 0", "status_text = 'x'"] {
        assert!(Profile::from_toml(&format!("schema = 1\n[ui]\n{field}")).is_err());
    }
    assert!(Profile::from_toml("schema = 1\n[memory]\nxip_base = -1").is_err());
    assert!("execution".parse::<BuildMode>().is_err());
}
#[test]
fn wrong_identity_schema_and_container_are_rejected() {
    let (mut profile, package, module) = fixture();
    profile.schema = 2;
    assert!(issue(&profile, IssueKind::Unsupported, "schema"));
    profile.identity.model = "Z6III".into();
    assert!(validate_input(&profile, &package, &module)
        .issues
        .iter()
        .any(|issue| issue.kind == IssueKind::IdentityMismatch));
    // aes-ctr is recordable, and a module-only build never writes a
    // container; only a build that reseals a package is refused.
    profile.identity.container = Some(ContainerKind::AesCtr);
    assert!(!issue(
        &profile,
        IssueKind::Unsupported,
        "identity.container"
    ));
    assert!(profile
        .validate_package_output()
        .issues
        .iter()
        .any(|issue| issue.kind == IssueKind::Unsupported && issue.field == "identity.container"));
    profile.identity.container = None;
    assert!(profile
        .validate_package_output()
        .issues
        .iter()
        .any(|issue| issue.kind == IssueKind::Missing && issue.field == "identity.container"));
}
#[test]
fn half_open_ranges_and_integer_overflow_are_rejected() {
    assert!(AddressRange { start: 16, end: 32 }.contains(16, 16));
    assert!(!AddressRange { start: 16, end: 32 }.contains(32, 1));
    assert!(!AddressRange { start: 16, end: 32 }.contains(16, 0));
    assert!(!AddressRange {
        start: 16,
        end: u64::MAX
    }
    .contains(u64::MAX - 1, 4));
    let (mut profile, _, _) = fixture();
    profile.memory.xip_base = Some(u64::MAX - 3);
    profile.memory.segments[0].runtime_start = u64::MAX - 3;
    assert!(issue(&profile, IssueKind::OutOfBounds, "memory.segments"));
}
#[test]
fn link_must_fit_completely_in_slack() {
    for (base, size) in [
        (4352, 257),
        (4353, 16),
        (4608, 1),
        (4352, 0),
        (u64::MAX - 3, 8),
    ] {
        let (mut profile, _, _) = fixture();
        profile.memory.link_base = Some(base);
        profile.memory.link_size = Some(size);
        assert!(issue(&profile, IssueKind::OutOfBounds, "memory.link_base"));
    }
}
#[test]
fn invalid_slack_is_rejected() {
    let (mut profile, _, _) = fixture();
    profile.memory.slack.as_mut().unwrap().require_zero = false;
    assert!(issue(
        &profile,
        IssueKind::Unsupported,
        "memory.slack.require_zero"
    ));
    profile.memory.slack.as_mut().unwrap().end = 4352;
    assert!(issue(&profile, IssueKind::OutOfBounds, "memory.slack"));
}
#[test]
fn actual_fingerprints_and_stock_are_checked() {
    let (profile, package, mut module) = fixture();
    module[0] = 1;
    let report = validate_input(&profile, &package, &module);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.kind == IssueKind::FingerprintMismatch));
    module[256] = 1;
    assert!(validate_input(&profile, &package, &module)
        .issues
        .iter()
        .any(|issue| issue.field == "memory.slack" && issue.kind == IssueKind::Conflict));
    assert!(!validate_input(&profile, b"wrong package", &module).is_valid());
}
#[test]
fn external_identity_cannot_be_replaced_by_profile_identity() {
    let (profile, package, module) = fixture();
    let report = profile.validate_for(
        BuildMode::Marker,
        &ValidationContext {
            model: "Z8",
            firmware: "3.01",
            package: Some(&package),
            module_name: "wrong.bi",
            module: &module,
        },
    );
    assert!(
        report
            .issues
            .iter()
            .filter(|issue| issue.kind == IssueKind::IdentityMismatch)
            .count()
            >= 2
    );
}
#[test]
fn malformed_configuration_fingerprint_is_rejected() {
    let (mut profile, _, _) = fixture();
    profile.checks.package_sha256 = Some("abc".into());
    assert!(issue(&profile, IssueKind::Invalid, "checks.package_sha256"));
}
#[test]
fn execution_requires_its_own_services_and_single_core_worker() {
    let (mut profile, _, _) = fixture();
    profile.abi.mmu = Some(MmuFamily::Z8BlockV1);
    for mode in [BuildMode::PrepareOnly, BuildMode::Exec] {
        assert!(profile
            .validate(mode)
            .issues
            .iter()
            .any(|issue| issue.kind == IssueKind::Missing
                && issue.field == "services.exec.page_query"));
        assert!(profile
            .validate(mode)
            .issues
            .iter()
            .any(|issue| issue.field == "task.core"));
    }
    // The page rung is implemented, so it fails on its own requirements.
    let page = profile.validate(BuildMode::Page);
    assert!(!page.is_valid());
    assert!(!page.issues.iter().any(|issue| issue.field == "mode"));
}

#[test]
fn service_boundaries_and_unknown_abis_are_rejected() {
    let (mut profile, _, _) = fixture();
    for address in [0, 4097, 4608, 4352] {
        profile.services.fs_open = Some(address);
        assert!(!profile.validate(BuildMode::Marker).is_valid());
    }
}
#[test]
fn version_offsets_are_module_relative_and_cannot_overlap() {
    let (mut profile, package, module) = fixture();
    profile.updater.version_literals.push(VersionLiteral {
        eg_off: 0,
        stock: "ABCD".into(),
        patched: "WXYZ".into(),
    });
    assert!(profile.validate(BuildMode::Marker).is_valid());
    assert!(!validate_input(&profile, &package, &module).is_valid());
    profile.updater.version_literals[0].eg_off = 256;
    assert!(issue(
        &profile,
        IssueKind::Conflict,
        "updater.version_literals[0]"
    ));
    profile.updater.version_literals[0].eg_off = u64::MAX;
    assert!(issue(
        &profile,
        IssueKind::OutOfBounds,
        "updater.version_literals[0]"
    ));
    profile.updater.version_literals[0].patched = "too long".into();
    assert!(issue(
        &profile,
        IssueKind::Invalid,
        "updater.version_literals[0]"
    ));
}

fn mapped_fixture() -> (Profile, Vec<u8>, Vec<u8>) {
    let (mut profile, package, mut module) = fixture();
    profile.memory.segments = vec![
        MemorySegment {
            file_offset: 0,
            runtime_start: 4096,
            size: 256,
            kind: MemorySegmentKind::Xip,
        },
        MemorySegment {
            file_offset: 256,
            runtime_start: 65536,
            size: 256,
            kind: MemorySegmentKind::Ram,
        },
    ];
    profile.memory.slack = Some(Slack {
        start: 4224,
        end: 4352,
        require_zero: true,
    });
    profile.memory.link_base = Some(4224);
    profile.memory.link_size = Some(128);
    module[260..264].copy_from_slice(b"DATA");
    profile.checks.module_sha256 = Some(sha256(&module));
    (profile, package, module)
}
#[test]
fn all_actual_byte_lookups_reject_absent_maps() {
    let (mut profile, package, module) = mapped_fixture();
    profile.memory.segments.clear();
    assert!(issue(&profile, IssueKind::Missing, "memory.segments"));
    assert!(!validate_input(&profile, &package, &module).is_valid());
}
#[test]
fn ram_and_unmapped_file_tail_are_not_executable_or_loader_space() {
    let (mut profile, _, _) = mapped_fixture();
    profile.services.fs_open = Some(65536);
    assert!(issue(&profile, IssueKind::OutOfBounds, "services.fs_open"));
    profile.services.fs_open = Some(4352); // Old linear mapping incorrectly admitted this.
    assert!(issue(&profile, IssueKind::OutOfBounds, "services.fs_open"));
    profile.memory.slack = Some(Slack {
        start: 65536,
        end: 65664,
        require_zero: true,
    });
    profile.memory.link_base = Some(65536);
    assert!(issue(&profile, IssueKind::OutOfBounds, "memory.slack"));
    assert!(issue(&profile, IssueKind::OutOfBounds, "memory.link_base"));
}
#[test]
fn version_literals_are_module_relative_and_may_stay_unmapped() {
    let (mut profile, package, module) = mapped_fixture();
    profile.updater.version_literals.push(VersionLiteral {
        eg_off: 260,
        stock: "DATA".into(),
        patched: "NEXT".into(),
    });
    assert!(validate_input(&profile, &package, &module).is_valid());
    // A literal that maps into the reserved loader area would be overwritten
    // by the blob, or overwrite it.
    profile.updater.version_literals[0].eg_off = 130;
    assert!(issue(
        &profile,
        IssueKind::Conflict,
        "updater.version_literals[0]"
    ));
    profile.updater.version_literals[0].eg_off = 260;
    profile.memory.segments[1].file_offset = 272;
    profile.memory.segments[1].size = 240;
    // The literal no longer maps to memory: file-only edits like the eg
    // trailer are legal, so the runtime overlap conflict disappears.
    assert!(!issue(
        &profile,
        IssueKind::Conflict,
        "updater.version_literals[0]"
    ));
}
#[test]
fn mapped_firmware_data_does_not_grant_ram_pool_ownership() {
    let (mut profile, _, _) = mapped_fixture();
    profile.memory.ram_pool = Some(AddressRange {
        start: 65536,
        end: 65664,
    });
    assert!(issue(&profile, IssueKind::OutOfBounds, "memory.ram_pool"));
}

/* A file wrapper is identified by the request operation it stores, not by
 * its address or its entry bytes: a fingerprint only proves the bytes are
 * the declared ones. Decoding the stored operation is what tells a close
 * wrapper from a different request. */
/// Whatever the loader writes has to leave the data cache before another
/// master reads it -- the card's DMA behind a file write, instruction
/// fetch after a code patch -- and only the profile knows which of a
/// body's cache entries writes back instead of discarding. A profile that
/// writes without naming it is refused rather than silently losing the
/// write on a model where the other entry is an invalidate.
#[test]
fn writing_requires_the_entry_that_writes_back() {
    let (mut profile, _package, _module) = fixture();
    assert!(!issue(
        &profile,
        IssueKind::Invalid,
        "services.dcache_clean"
    ));
    profile.services.fs_write = Some(4096 + 0x40);
    assert!(issue(&profile, IssueKind::Invalid, "services.dcache_clean"));
    profile.services.dcache_clean = Some(4096 + 0x80);
    assert!(!issue(
        &profile,
        IssueKind::Invalid,
        "services.dcache_clean"
    ));

    let (mut profile, _package, _module) = fixture();
    profile.services.code = Some(CodeServices {
        text_lo: Some(4096),
        text_hi: Some(4096 + 512),
        alias_lo: Some(0x100000),
        alias_hi: Some(0x101000),
        unaligned_literals: Some(true),
    });
    assert!(issue(&profile, IssueKind::Invalid, "services.dcache_clean"));
    profile.services.dcache_clean = Some(4096 + 0x80);
    assert!(!issue(
        &profile,
        IssueKind::Invalid,
        "services.dcache_clean"
    ));
}

#[test]
fn file_wrappers_must_submit_their_declared_operation() {
    let (mut profile, package, mut module) = fixture();
    // MOVZ W9, #op ; STR W9, [SP, #0x114]  (and the ORR spelling for close).
    let wrapper = |first: u32| -> Vec<u8> {
        [first, 0xb901_17e9]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect()
    };
    for (offset, first) in [
        (0x40usize, 0x5280_0089u32), /* open: movz w9, #4 */
        (0x60, 0x5280_00e9),         /* read: movz w9, #7 */
        (0x80, 0x5280_0129),         /* seek: movz w9, #9 */
        (0xa0, 0x5280_00a9),         /* close: movz w9, #5 */
        (0xc0, 0x3200_03e9),         /* other op: orr w9, wzr, #1 */
        (0xe0, 0x5280_0109),         /* write: movz w9, #8 */
    ] {
        module[offset..offset + 8].copy_from_slice(&wrapper(first));
    }
    profile.checks.module_sha256 = Some(sha256(&module));
    profile.services.fs_open = Some(4096 + 0x40);
    profile.services.fs_read = Some(4096 + 0x60);
    profile.services.fs_seek = Some(4096 + 0x80);
    profile.services.fs_close = Some(4096 + 0xa0);
    profile.services.fs_write = Some(4096 + 0xe0);
    profile.services.file_ops = FileOperations {
        op_slot: Some(0x114),
        open: Some(4),
        read: Some(7),
        seek: Some(9),
        close: Some(5),
        write: Some(8),
        open_read_write: Some(2),
        open_write_create: None,
        create_attributes: None,
    };
    let ops_issues = |profile: &Profile| -> Vec<String> {
        validate_input(profile, &package, &module)
            .issues
            .into_iter()
            .filter(|issue| issue.field.starts_with("services.file_ops"))
            .map(|issue| format!("{}: {}", issue.field, issue.message))
            .collect()
    };
    assert_eq!(ops_issues(&profile), Vec::<String>::new());

    // A close declared at a wrapper for a different request is rejected
    // even though its address is mapped and aligned.
    let mut wrong = profile.clone();
    wrong.services.fs_close = Some(4096 + 0xc0);
    assert!(ops_issues(&wrong)
        .iter()
        .any(|issue| issue.contains("services.file_ops.close") && issue.contains("operation 1")));
    // A wrong declared operation is rejected the same way.
    let mut wrong = profile.clone();
    wrong.services.file_ops.seek = Some(7);
    assert!(ops_issues(&wrong)
        .iter()
        .any(|issue| issue.starts_with("services.file_ops.seek")));
    let mut wrong = profile.clone();
    wrong.services.file_ops.write = Some(7);
    assert!(ops_issues(&wrong)
        .iter()
        .any(|issue| issue.starts_with("services.file_ops.write")));
    // A write service needs its operation and the read-write open flags.
    let mut wrong = profile.clone();
    wrong.services.file_ops.open_read_write = None;
    assert!(validate_input(&wrong, &package, &module)
        .issues
        .iter()
        .any(|issue| issue.field == "services.fs_write"));
    // A function that stores no operation at the slot is not a wrapper.
    let mut wrong = profile.clone();
    wrong.services.file_ops.op_slot = Some(0x118);
    assert_eq!(ops_issues(&wrong).len(), 5);
}

#[test]
fn family_selectors_are_explicit_and_unknown_names_are_rejected() {
    for field in ["ui", "task", "fs", "mmu"] {
        assert!(Profile::from_toml(&format!("schema = 1\n[abi]\n{field} = 'unknown'")).is_err());
    }
    let (profile, _, _) = fixture();
    for (mode, required) in [
        (BuildMode::HookOnly, vec!["abi.ui"]),
        (BuildMode::LoadOnly, vec!["abi.ui", "abi.task", "abi.fs"]),
        (
            BuildMode::Exec,
            vec!["abi.ui", "abi.task", "abi.fs", "abi.mmu"],
        ),
    ] {
        let report = profile.validate(mode);
        for field in required {
            assert!(report
                .issues
                .iter()
                .any(|issue| issue.field == field && issue.kind == IssueKind::Missing));
        }
    }
}

#[test]
fn another_identity_still_requires_matching_observed_image_identity() {
    let (mut profile, package, module) = fixture();
    profile.identity.model = "SyntheticCamera".into();
    profile.identity.firmware = "9.99".into();
    assert!(profile.validate(BuildMode::Marker).is_valid());
    assert!(!validate_input(&profile, &package, &module).is_valid());
    assert!(profile
        .validate_for(
            BuildMode::Marker,
            &ValidationContext {
                model: "SyntheticCamera",
                firmware: "9.99",
                package: Some(&package),
                module_name: "synthetic.bi",
                module: &module,
            }
        )
        .is_valid());
}
