//! Family B's scan declaration: the platform's own scan geometry carries the
//! controls when a body's input hook is not the program input slot (the
//! Z 8's exit callback), and both carriers keep the same checks.
use nloader_profile::*;

fn carrier_slot() -> ProgramServices {
    ProgramServices {
        input_slot: Some(0x4000),
        input_original: Some(0x5000),
        bank_base: 8,
        bank_stride: 20,
        banks: 3,
        keep_bank: 0,
        keep_mask: 0x1,
        dial_offset: 0x58,
        dial_bytes: 16,
        ..Default::default()
    }
}

fn exit_carrier() -> ExitServices {
    ExitServices {
        input_callback: 0x4000,
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
        suspend: 0x1000,
        resume: 0x1000,
        terminate: 0x1000,
        restart: 0x1000,
        bodies: vec![],
    }
}

fn scan() -> PlatformScan {
    PlatformScan {
        bank_base: 8,
        bank_stride: 20,
        banks: 3,
        keep_bank: 0,
        keep_mask: 0x200,
        dial_offset: 0x58,
        dial_bytes: 16,
        activity: None,
        object: Some(0x6000),
    }
}

fn controls() -> Vec<(String, u32, u32)> {
    vec![
        ("up".into(), 0, 0x20),
        ("ok".into(), 1, 0x1),
        ("sub_press".into(), 2, 0x8000),
    ]
}

fn profile(program: bool, exit: bool, platform: Option<PlatformServices>) -> Profile {
    let mut profile = Profile::draft("Z8", "3.11");
    if program {
        profile.services.program = Some(carrier_slot());
    }
    if exit {
        profile.services.exit = Some(exit_carrier());
    }
    profile.services.platform = platform;
    profile
}

fn issue(profile: &Profile, kind: IssueKind, field: &str) -> bool {
    profile
        .validate(BuildMode::Marker)
        .issues
        .iter()
        .any(|issue| issue.kind == kind && issue.field == field)
}

#[test]
fn controls_run_on_either_carrier_and_keep_their_checks() {
    /* The program input slot's geometry, without a scan of its own. */
    let program = profile(
        true,
        false,
        Some(PlatformServices {
            controls: controls(),
            dial_words: [1, 0, 0],
            dial_signs: [1, 1, 1],
            ..Default::default()
        }),
    );
    assert!(!issue(
        &program,
        IssueKind::Missing,
        "services.platform.controls"
    ));
    assert!(!issue(
        &program,
        IssueKind::Missing,
        "services.platform.scan"
    ));

    /* The exit callback's carrier with the platform's own scan. */
    let exit = profile(
        false,
        true,
        Some(PlatformServices {
            controls: controls(),
            dial_words: [1, 2, 0],
            dial_alt_words: [3, 4, 0],
            dial_signs: [1, 1, 1],
            scan: Some(scan()),
            ..Default::default()
        }),
    );
    assert!(!issue(
        &exit,
        IssueKind::Missing,
        "services.platform.controls"
    ));
    assert!(!issue(&exit, IssueKind::Missing, "services.platform.scan"));

    /* A control beyond the declared banks, and one on the keep bit. */
    let mut outside = scan();
    outside.banks = 2;
    let bad_bank = profile(
        false,
        true,
        Some(PlatformServices {
            controls: vec![("ok".into(), 2, 0x1)],
            scan: Some(outside),
            ..Default::default()
        }),
    );
    assert!(issue(
        &bad_bank,
        IssueKind::Conflict,
        "services.platform.controls.ok"
    ));

    /* A bit the camera always sees (a resting state switch such as the
     * Z 8's F_MIN) is never a program's control. */
    let mut kept = scan();
    kept.keep_mask = 0x200;
    let on_keep = profile(
        false,
        true,
        Some(PlatformServices {
            controls: vec![("fn1".into(), 0, 0x200)],
            scan: Some(kept.clone()),
            ..Default::default()
        }),
    );
    assert!(issue(
        &on_keep,
        IssueKind::Conflict,
        "services.platform.controls.fn1"
    ));
    let beside_keep = profile(
        false,
        true,
        Some(PlatformServices {
            controls: vec![("fn1".into(), 0, 0x4000)],
            scan: Some(kept),
            ..Default::default()
        }),
    );
    assert!(!issue(
        &beside_keep,
        IssueKind::Conflict,
        "services.platform.controls.fn1"
    ));

    /* The exit callback forwards three banks: a scan over more is never
     * restored to the stock occupant. */
    let mut four = scan();
    four.banks = 4;
    let over = profile(
        false,
        true,
        Some(PlatformServices {
            controls: controls(),
            scan: Some(four),
            ..Default::default()
        }),
    );
    assert!(issue(&over, IssueKind::Conflict, "services.platform.scan"));

    /* Controls with an exit carrier but no scan at all: the geometry is not
     * named and nothing is guessed. */
    let unscanned = profile(
        false,
        true,
        Some(PlatformServices {
            controls: controls(),
            ..Default::default()
        }),
    );
    assert!(issue(
        &unscanned,
        IssueKind::Missing,
        "services.platform.controls"
    ));

    /* A scan without any hook carrying it never runs. */
    let carrierless = profile(
        false,
        false,
        Some(PlatformServices {
            controls: controls(),
            scan: Some(scan()),
            ..Default::default()
        }),
    );
    assert!(issue(
        &carrierless,
        IssueKind::Missing,
        "services.platform.scan"
    ));

    /* The activity entry is firmware text with its own fingerprint. */
    let mut with_activity = scan();
    with_activity.activity = Some(0x7000);
    let unproven = profile(
        false,
        true,
        Some(PlatformServices {
            controls: controls(),
            scan: Some(with_activity),
            ..Default::default()
        }),
    );
    assert!(issue(
        &unproven,
        IssueKind::Missing,
        "services.platform.scan.activity"
    ));

    /* A scan object in firmware text is not RAM. */
    let mut bad_object = scan();
    bad_object.object = Some(0x6001);
    let misplaced = profile(
        false,
        true,
        Some(PlatformServices {
            controls: controls(),
            scan: Some(bad_object),
            ..Default::default()
        }),
    );
    assert!(issue(
        &misplaced,
        IssueKind::Invalid,
        "services.platform.scan.object"
    ));

    /* Both hooks on one slot: whichever installs last would replace the
     * other, so the profile is refused rather than ordered. */
    let shared = profile(true, true, None);
    assert!(issue(
        &shared,
        IssueKind::Conflict,
        "services.program.input_slot"
    ));
    let mut apart = profile(true, true, None);
    apart.services.program.as_mut().unwrap().input_slot = Some(0x4008);
    assert!(!issue(
        &apart,
        IssueKind::Conflict,
        "services.program.input_slot"
    ));

    /* Dial words are indexed into whichever carrier declares the words. */
    let wrong_dial = profile(
        false,
        true,
        Some(PlatformServices {
            controls: controls(),
            dial_words: [5, 0, 0],
            dial_signs: [1, 1, 1],
            scan: Some(scan()),
            ..Default::default()
        }),
    );
    assert!(issue(
        &wrong_dial,
        IssueKind::OutOfBounds,
        "services.platform.dial_words[0]"
    ));
}

/* GUI turns: a BL in firmware text whose declared stock word calls the
 * declared callee, distinct sites, never the native card's menu
 * checkpoint, at most eight, and the module must hold that word. */
fn bl(site: u64, target: u64) -> Vec<u8> {
    let delta = ((target as i64 - site as i64) / 4) as u32 & 0x03ff_ffff;
    (0x9400_0000u32 | delta).to_le_bytes().to_vec()
}

fn turn(name: &str, site: u64, callee: u64) -> PlatformGuiTurn {
    PlatformGuiTurn {
        name: name.into(),
        site,
        callee,
        stock: bl(site, callee),
    }
}

fn turns_profile(turns: Vec<PlatformGuiTurn>) -> Profile {
    let mut profile = profile(
        false,
        false,
        Some(PlatformServices {
            gui_turns: turns,
            ..Default::default()
        }),
    );
    profile.memory.xip_base = Some(0x1000);
    profile.memory.module_size = Some(0x1000);
    profile.memory.segments = vec![MemorySegment {
        file_offset: 0,
        runtime_start: 0x1000,
        size: 0x1000,
        kind: MemorySegmentKind::Xip,
    }];
    profile
}

fn turn_issue(profile: &Profile, kind: IssueKind, name: &str) -> bool {
    issue(
        profile,
        kind,
        &format!("services.platform.gui_turns.{name}"),
    )
}

#[test]
fn gui_turns_are_stock_calls_to_their_callee() {
    let good = turns_profile(vec![
        turn("idle", 0x1100, 0x1800),
        turn("lv", 0x1200, 0x1800),
    ]);
    let report = good.validate(BuildMode::Marker);
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.field.starts_with("services.platform.gui_turns.")),
        "{:?}",
        report.issues
    );
    /* GUI turns are hold points: when the hold is taken is declared, never
     * defaulted. */
    assert!(issue(&good, IssueKind::Missing, "services.platform.hold"));

    /* The stock word calls something else, or is no call at all. */
    let mut other = turn("idle", 0x1100, 0x1800);
    other.stock = bl(0x1100, 0x1804);
    assert!(turn_issue(
        &turns_profile(vec![other]),
        IssueKind::Invalid,
        "idle"
    ));
    let mut branch = turn("idle", 0x1100, 0x1800);
    branch.stock = (0x1400_01c0u32).to_le_bytes().to_vec();
    assert!(turn_issue(
        &turns_profile(vec![branch]),
        IssueKind::Invalid,
        "idle"
    ));
    let mut short = turn("idle", 0x1100, 0x1800);
    short.stock.truncate(3);
    assert!(turn_issue(
        &turns_profile(vec![short]),
        IssueKind::Invalid,
        "idle"
    ));

    /* Unaligned, or outside firmware text; a callee outside text. */
    assert!(turn_issue(
        &turns_profile(vec![turn("idle", 0x1102, 0x1802)]),
        IssueKind::OutOfBounds,
        "idle"
    ));
    assert!(turn_issue(
        &turns_profile(vec![turn("idle", 0x3000, 0x1800)]),
        IssueKind::OutOfBounds,
        "idle"
    ));
    assert!(turn_issue(
        &turns_profile(vec![turn("idle", 0x1100, 0x4000)]),
        IssueKind::OutOfBounds,
        "idle"
    ));

    /* A declared code window bounds the sites too. */
    let mut windowed = turns_profile(vec![turn("idle", 0x1100, 0x1800)]);
    windowed.services.code = Some(CodeServices {
        text_lo: Some(0x1200),
        text_hi: Some(0x1f00),
        ..Default::default()
    });
    assert!(turn_issue(&windowed, IssueKind::OutOfBounds, "idle"));

    /* Two turns on one site; a name used twice. */
    assert!(turn_issue(
        &turns_profile(vec![
            turn("idle", 0x1100, 0x1800),
            turn("lv", 0x1100, 0x1800)
        ]),
        IssueKind::Conflict,
        "lv"
    ));
    assert!(turn_issue(
        &turns_profile(vec![
            turn("idle", 0x1100, 0x1800),
            turn("idle", 0x1200, 0x1800)
        ]),
        IssueKind::Invalid,
        "idle"
    ));

    /* More than eight. */
    let many: Vec<_> = (0..9)
        .map(|n| turn(&format!("t{n}"), 0x1100 + 4 * n, 0x1800))
        .collect();
    assert!(issue(
        &turns_profile(many),
        IssueKind::Invalid,
        "services.platform.gui_turns"
    ));
}

/* The GUI hold (services.platform.hold) and its commit observer
 * (services.platform.commit): required where a hold point exists and only
 * there, waits in bounds, "settle" only with the observer, the observer
 * only with a reader, its calls BLs to the one callee on their own sites. */
fn hold(when: HoldWhen, wait_ms: u32, scanout_stable_ms: u32) -> Option<PlatformHold> {
    Some(PlatformHold {
        when,
        wait_ms,
        scanout_stable_ms,
    })
}

fn commit(sites: &[u64], callee: u64) -> Option<PlatformCommit> {
    Some(PlatformCommit {
        callee,
        sites: sites.to_vec(),
        stock: sites.iter().map(|s| bl(*s, callee)).collect(),
    })
}

fn held(hold: Option<PlatformHold>, commit: Option<PlatformCommit>) -> Profile {
    let mut p = turns_profile(vec![turn("idle", 0x1100, 0x1800)]);
    let platform = p.services.platform.as_mut().unwrap();
    platform.hold = hold;
    platform.commit = commit;
    p
}

fn hold_issues(p: &Profile) -> Vec<(IssueKind, String)> {
    p.validate(BuildMode::Marker)
        .issues
        .into_iter()
        .filter(|i| {
            i.field.starts_with("services.platform.hold")
                || i.field.starts_with("services.platform.commit")
        })
        .map(|i| (i.kind, i.field))
        .collect()
}

#[test]
fn hold_is_declared_bounded_and_settle_has_its_observer() {
    /* Both modes, as the two bodies declare them. */
    let immediate = held(hold(HoldWhen::Immediate, 5000, 300), None);
    assert!(
        hold_issues(&immediate).is_empty(),
        "{:?}",
        hold_issues(&immediate)
    );
    let settle = held(
        hold(HoldWhen::Settle, 5000, 300),
        commit(&[0x1300, 0x1400], 0x1900),
    );
    assert!(
        hold_issues(&settle).is_empty(),
        "{:?}",
        hold_issues(&settle)
    );
    /* "settle" without the observer it waits on. */
    assert!(issue(
        &held(hold(HoldWhen::Settle, 5000, 300), None),
        IssueKind::Missing,
        "services.platform.commit"
    ));
    /* A hold point without the declaration; a declaration without one
     * (the boot checkpoint counts as a hold point too). */
    assert!(issue(
        &held(None, None),
        IssueKind::Missing,
        "services.platform.hold"
    ));
    let mut no_point = held(hold(HoldWhen::Immediate, 5000, 300), None);
    no_point
        .services
        .platform
        .as_mut()
        .unwrap()
        .gui_turns
        .clear();
    assert!(issue(
        &no_point,
        IssueKind::Conflict,
        "services.platform.hold"
    ));
    no_point.boot_hooks.autoload = Some(BootCall {
        call_site: 0x1500,
        callee: 0x1800,
    });
    assert!(!issue(
        &no_point,
        IssueKind::Conflict,
        "services.platform.hold"
    ));
    no_point.services.platform.as_mut().unwrap().hold = None;
    assert!(issue(
        &no_point,
        IssueKind::Missing,
        "services.platform.hold"
    ));
    /* The waits' bounds and step. */
    for (wait, stable, field) in [
        (490, 300, "services.platform.hold.wait_ms"),
        (10_010, 300, "services.platform.hold.wait_ms"),
        (5005, 300, "services.platform.hold.wait_ms"),
        (5000, 1010, "services.platform.hold.scanout_stable_ms"),
        (5000, 305, "services.platform.hold.scanout_stable_ms"),
    ] {
        assert!(
            issue(
                &held(hold(HoldWhen::Immediate, wait, stable), None),
                IssueKind::OutOfBounds,
                field
            ),
            "{wait} {stable}"
        );
    }
    assert!(hold_issues(&held(hold(HoldWhen::Immediate, 500, 0), None)).is_empty());
    assert!(hold_issues(&held(hold(HoldWhen::Immediate, 10_000, 1000), None)).is_empty());
}

#[test]
fn commit_observer_calls_are_checked() {
    let settle = |c: Option<PlatformCommit>| held(hold(HoldWhen::Settle, 5000, 300), c);
    /* An observer nobody reads: an immediate hold and no canvas. */
    assert!(issue(
        &held(
            hold(HoldWhen::Immediate, 5000, 300),
            commit(&[0x1300], 0x1900)
        ),
        IssueKind::Conflict,
        "services.platform.commit"
    ));
    /* No calls, more than four, or stock words that do not match. */
    assert!(issue(
        &settle(commit(&[], 0x1900)),
        IssueKind::Invalid,
        "services.platform.commit.sites"
    ));
    assert!(issue(
        &settle(commit(&[0x1300, 0x1304, 0x1308, 0x130c, 0x1310], 0x1900)),
        IssueKind::Invalid,
        "services.platform.commit.sites"
    ));
    let mut other = commit(&[0x1300, 0x1400], 0x1900).unwrap();
    other.stock[1] = bl(0x1400, 0x1904);
    assert!(issue(
        &settle(Some(other)),
        IssueKind::Invalid,
        "services.platform.commit.sites[1]"
    ));
    let mut short = commit(&[0x1300], 0x1900).unwrap();
    short.stock.clear();
    assert!(issue(
        &settle(Some(short)),
        IssueKind::Invalid,
        "services.platform.commit.sites"
    ));
    /* Outside text, unaligned, or a callee outside text. */
    assert!(issue(
        &settle(commit(&[0x3000], 0x1900)),
        IssueKind::OutOfBounds,
        "services.platform.commit.sites[0]"
    ));
    assert!(issue(
        &settle(commit(&[0x1302], 0x1902)),
        IssueKind::OutOfBounds,
        "services.platform.commit.sites[0]"
    ));
    assert!(issue(
        &settle(commit(&[0x1300], 0x4000)),
        IssueKind::OutOfBounds,
        "services.platform.commit.callee"
    ));
    /* A site used twice, or one a GUI turn already owns. */
    assert!(issue(
        &settle(commit(&[0x1300, 0x1300], 0x1900)),
        IssueKind::Conflict,
        "services.platform.commit.sites[1]"
    ));
    assert!(issue(
        &settle(commit(&[0x1100], 0x1800)),
        IssueKind::Conflict,
        "services.platform.commit.sites[0]"
    ));
}

#[test]
fn commit_bytes_are_checked_against_the_module() {
    let mut profile = held(hold(HoldWhen::Settle, 5000, 300), commit(&[0x1300], 0x1900));
    profile.identity.eg_module = Some("eg.bin".into());
    let mut module = vec![0u8; 0x1000];
    module[0x100..0x104].copy_from_slice(&bl(0x1100, 0x1800));
    let mismatch = |module: &[u8]| -> bool {
        profile
            .validate_for(
                BuildMode::Marker,
                &ValidationContext {
                    model: "Z8",
                    firmware: "3.11",
                    package: None,
                    module_name: "eg.bin",
                    module,
                },
            )
            .issues
            .iter()
            .any(|i| {
                i.kind == IssueKind::FingerprintMismatch
                    && i.field == "services.platform.commit.sites[0]"
            })
    };
    assert!(mismatch(&module));
    module[0x300..0x304].copy_from_slice(&bl(0x1300, 0x1900));
    assert!(!mismatch(&module));
}

#[test]
fn gui_turn_bytes_are_checked_against_the_module() {
    let mut profile = turns_profile(vec![turn("idle", 0x1100, 0x1800)]);
    profile.identity.eg_module = Some("eg.bin".into());
    let mut module = vec![0u8; 0x1000];
    let context = |module: &[u8]| -> bool {
        profile
            .validate_for(
                BuildMode::Marker,
                &ValidationContext {
                    model: "Z8",
                    firmware: "3.11",
                    package: None,
                    module_name: "eg.bin",
                    module,
                },
            )
            .issues
            .iter()
            .any(|i| {
                i.kind == IssueKind::FingerprintMismatch
                    && i.field == "services.platform.gui_turns.idle"
            })
    };
    assert!(context(&module));
    module[0x100..0x104].copy_from_slice(&bl(0x1100, 0x1800));
    assert!(!context(&module));
}

/* The release bundle's stock boot copy: a MOVZ/MOVK pair building the
 * declared stock end, a span inside the copied block (so the extended copy
 * never writes the next block's DRAM copy), a destination on the code
 * window's own alias, clear of the module's image and of every other
 * address the profile names; the module must hold the stock words. */
fn movz(reg: u32, imm: u32) -> u32 {
    0xd280_0000 | imm << 5 | reg
}

fn movk16(reg: u32, imm: u32) -> u32 {
    0xf2a0_0000 | imm << 5 | reg
}

fn copy_pair(reg: u32, value: u32) -> Vec<u8> {
    let mut v = movz(reg, value & 0xffff).to_le_bytes().to_vec();
    v.extend_from_slice(&movk16(reg, value >> 16).to_le_bytes());
    v
}

const ALIAS: u64 = 0xb_1000_0000;

fn bundle() -> PlatformBundle {
    PlatformBundle {
        address: 0x1000_3000,
        size: 0x2000,
        copy: Some(BundleCopy {
            source: 0x1000_1000,
            block_bytes: 0x4000,
            destination: ALIAS,
            stock_end: 0x1000_2010,
            low_site: 0x1000_8000,
            high_site: 0x1000_8004,
            register: 8,
            stock: copy_pair(8, 0x1000_2010),
        }),
    }
}

fn bundle_profile(bundle: PlatformBundle) -> Profile {
    let mut profile = profile(
        false,
        false,
        Some(PlatformServices {
            bundle: Some(bundle),
            ..Default::default()
        }),
    );
    profile.memory.xip_base = Some(0x1000_0000);
    profile.memory.module_size = Some(0x1_1000);
    profile.memory.segments = vec![
        MemorySegment {
            file_offset: 0,
            runtime_start: 0x1000_0000,
            size: 0x1_0000,
            kind: MemorySegmentKind::Xip,
        },
        MemorySegment {
            file_offset: 0x1_0000,
            runtime_start: 0xb_0000_0000,
            size: 0x1000,
            kind: MemorySegmentKind::Ram,
        },
    ];
    profile.services.code = Some(CodeServices {
        text_lo: Some(0x1000_1000),
        text_hi: Some(0x1000_c000),
        alias_lo: Some(ALIAS),
        alias_hi: Some(ALIAS + 0xb000),
        ..Default::default()
    });
    profile
}

fn bundle_issues(profile: &Profile) -> Vec<ValidationIssue> {
    profile
        .validate(BuildMode::Marker)
        .issues
        .into_iter()
        .filter(|i| i.field.starts_with("services.platform.bundle"))
        .collect()
}

fn copy_issue(profile: &Profile, kind: IssueKind, words: &str) -> bool {
    bundle_issues(profile).iter().any(|i| {
        i.field == "services.platform.bundle.copy" && i.kind == kind && i.message.contains(words)
    })
}

#[test]
fn bundle_copy_reaches_the_span_inside_its_block() {
    let good = bundle_profile(bundle());
    assert!(
        bundle_issues(&good).is_empty(),
        "{:?}",
        bundle_issues(&good)
    );

    /* The extended end is the span's end, encoded in the stock words'
     * immediates only. */
    let copy = bundle().copy.unwrap();
    assert_eq!(copy.stock_value(), Some(0x1000_2010));
    assert_eq!(
        copy.patched_words(0x1000_5000),
        Some([movz(8, 0x5000), movk16(8, 0x1000)])
    );
    assert_eq!(copy.patched_words(0x1_0000_0000), None);

    /* No copy at all. */
    let mut missing = bundle();
    missing.copy = None;
    assert!(bundle_issues(&bundle_profile(missing))
        .iter()
        .any(|i| { i.field == "services.platform.bundle.copy" && i.kind == IssueKind::Missing }));

    /* The span runs past the block the routine maps: the copy would write
     * the next block's DRAM copy. */
    let mut past = bundle();
    past.size = 0x3000;
    assert!(copy_issue(
        &bundle_profile(past),
        IssueKind::Conflict,
        "next block"
    ));

    /* The span starts before the stock end, or the block leaves the code
     * window. */
    let mut early = bundle();
    early.copy.as_mut().unwrap().stock_end = 0x1000_3040;
    early.copy.as_mut().unwrap().stock = copy_pair(8, 0x1000_3040);
    assert!(copy_issue(
        &bundle_profile(early),
        IssueKind::Invalid,
        "stops at or before the span"
    ));
    let mut outside = bundle();
    outside.copy.as_mut().unwrap().block_bytes = 0x10_0000;
    assert!(copy_issue(
        &bundle_profile(outside),
        IssueKind::OutOfBounds,
        "inside the code window"
    ));

    /* Stock words that do not build the stock end, or name another
     * register, or are not a MOVZ/MOVK pair. */
    let mut value = bundle();
    value.copy.as_mut().unwrap().stock = copy_pair(8, 0x1000_2020);
    assert!(copy_issue(
        &bundle_profile(value),
        IssueKind::Invalid,
        "MOVZ"
    ));
    let mut register = bundle();
    register.copy.as_mut().unwrap().stock = copy_pair(9, 0x1000_2010);
    assert!(copy_issue(
        &bundle_profile(register),
        IssueKind::Invalid,
        "MOVZ"
    ));
    let mut swapped = bundle();
    let mut words = copy_pair(8, 0x1000_2010);
    words.rotate_left(4);
    swapped.copy.as_mut().unwrap().stock = words;
    assert!(copy_issue(
        &bundle_profile(swapped),
        IssueKind::Invalid,
        "MOVZ"
    ));

    /* A site inside the span or off the instruction grid. */
    let mut inside = bundle();
    inside.copy.as_mut().unwrap().high_site = 0x1000_3004;
    assert!(copy_issue(
        &bundle_profile(inside),
        IssueKind::OutOfBounds,
        "outside the span"
    ));
    let mut odd = bundle();
    odd.copy.as_mut().unwrap().low_site = 0x1000_8002;
    assert!(copy_issue(
        &bundle_profile(odd),
        IssueKind::OutOfBounds,
        "outside the span"
    ));
}

#[test]
fn bundle_copy_destination_has_no_other_user() {
    /* Not the window's own alias of the copied bytes. */
    let mut shifted = bundle();
    shifted.copy.as_mut().unwrap().destination = ALIAS + 0x1000;
    assert!(copy_issue(
        &bundle_profile(shifted),
        IssueKind::Conflict,
        "own DRAM alias"
    ));

    /* Over the module's mapped image. */
    let mut over_image = bundle_profile(bundle());
    over_image.memory.segments[1].runtime_start = ALIAS + 0x800;
    assert!(copy_issue(&over_image, IssueKind::Conflict, "mapped image"));

    /* Another address the profile names falls where the copy writes. */
    let mut user = bundle_profile(bundle());
    user.services.platform.as_mut().unwrap().eye_state = Some(ALIAS + 0x3800);
    assert!(copy_issue(&user, IssueKind::Conflict, "eye_state"));
    /* ... but one past the copy's end does not. */
    let mut beyond = bundle_profile(bundle());
    beyond.services.platform.as_mut().unwrap().eye_state = Some(ALIAS + 0x4000);
    assert!(
        bundle_issues(&beyond).is_empty(),
        "{:?}",
        bundle_issues(&beyond)
    );
}

#[test]
fn bundle_copy_stock_words_are_checked_against_the_module() {
    let mut profile = bundle_profile(bundle());
    profile.identity.eg_module = Some("eg.bin".into());
    let mut module = vec![0u8; 0x1_1000];
    let mismatch = |module: &[u8]| -> bool {
        profile
            .validate_for(
                BuildMode::Marker,
                &ValidationContext {
                    model: "Z8",
                    firmware: "3.11",
                    package: None,
                    module_name: "eg.bin",
                    module,
                },
            )
            .issues
            .iter()
            .any(|i| {
                i.kind == IssueKind::FingerprintMismatch
                    && i.field == "services.platform.bundle.copy"
            })
    };
    assert!(mismatch(&module));
    module[0x8000..0x8008].copy_from_slice(&copy_pair(8, 0x1000_2010));
    assert!(!mismatch(&module));
    module[0x3100] = 1;
    assert!(profile
        .validate_for(
            BuildMode::Marker,
            &ValidationContext {
                model: "Z8",
                firmware: "3.11",
                package: None,
                module_name: "eg.bin",
                module: &module,
            },
        )
        .issues
        .iter()
        .any(|i| i.kind == IssueKind::Conflict && i.field == "services.platform.bundle"));
}

/* Touch and the eye sensor (B3/B4): the touch slot is aligned run-time RAM
 * outside every image segment, declared together with its stock occupant
 * and a record of 14..=64 bytes; the occupant is firmware text with a
 * fingerprint that sits at its address and matches the module; the eye
 * state is an aligned word that is never firmware text. Addresses are
 * synthetic. */
fn touch_profile(slot: u64, original: u64, bytes: u32, eye: Option<u64>) -> Profile {
    let mut profile = turns_profile(vec![]);
    let platform = profile.services.platform.as_mut().unwrap();
    platform.touch_slot = Some(slot);
    platform.touch_original = Some(original);
    platform.touch_record_bytes = bytes;
    platform.eye_state = eye;
    profile.service_fingerprints.insert(
        "platform.touch_original".into(),
        ServiceFingerprint {
            eg_off: original.wrapping_sub(0x1000),
            stock: vec![0xf5, 0x53, 0xbe, 0xa9],
        },
    );
    profile
}

fn touch_issues(profile: &Profile) -> Vec<ValidationIssue> {
    profile
        .validate(BuildMode::Marker)
        .issues
        .into_iter()
        .filter(|i| {
            i.field.starts_with("services.platform.touch")
                || i.field == "services.platform.eye_state"
                || i.field == "service_fingerprints.platform.touch_original"
        })
        .collect()
}

#[test]
fn touch_and_eye_are_declared_with_their_checks() {
    let good = touch_profile(0x9118, 0x1f94, 28, Some(0xa240));
    assert!(touch_issues(&good).is_empty(), "{:?}", touch_issues(&good));

    /* The slot: unaligned, inside an image segment, or without occupant. */
    for slot in [0x911c, 0x1100] {
        assert!(issue(
            &touch_profile(slot, 0x1f94, 28, None),
            IssueKind::Invalid,
            "services.platform.touch_slot"
        ));
    }
    let mut alone = touch_profile(0x9118, 0x1f94, 28, None);
    alone.services.platform.as_mut().unwrap().touch_original = None;
    assert!(issue(
        &alone,
        IssueKind::Invalid,
        "services.platform.touch_slot"
    ));

    /* The record: fewer bytes than finger 0's y, or more than core copies. */
    for bytes in [13, 65, 0] {
        assert!(issue(
            &touch_profile(0x9118, 0x1f94, bytes, None),
            IssueKind::Invalid,
            "services.platform.touch_slot"
        ));
    }
    assert!(touch_issues(&touch_profile(0x9118, 0x1f94, 14, None)).is_empty());
    assert!(touch_issues(&touch_profile(0x9118, 0x1f94, 64, None)).is_empty());

    /* The occupant: outside firmware text, without its fingerprint, or with
     * a fingerprint at another address. */
    assert!(issue(
        &touch_profile(0x9118, 0x8f94, 28, None),
        IssueKind::Missing,
        "services.platform.touch_original"
    ));
    let mut bare = touch_profile(0x9118, 0x1f94, 28, None);
    bare.service_fingerprints.clear();
    assert!(issue(
        &bare,
        IssueKind::Missing,
        "services.platform.touch_original"
    ));
    let mut moved = touch_profile(0x9118, 0x1f94, 28, None);
    moved
        .service_fingerprints
        .get_mut("platform.touch_original")
        .unwrap()
        .eg_off = 0xf98;
    assert!(issue(
        &moved,
        IssueKind::Conflict,
        "service_fingerprints.platform.touch_original"
    ));

    /* The eye state: unaligned, or a word of firmware text. */
    for eye in [0xa242, 0x1240] {
        assert!(issue(
            &touch_profile(0x9118, 0x1f94, 28, Some(eye)),
            IssueKind::Invalid,
            "services.platform.eye_state"
        ));
    }
}

#[test]
fn touch_occupant_bytes_are_checked_against_the_module() {
    let mut profile = touch_profile(0x9118, 0x1f94, 28, None);
    profile.identity.eg_module = Some("eg.bin".into());
    let mut module = vec![0u8; 0x1000];
    let conflict = |module: &[u8]| -> bool {
        profile
            .validate_for(
                BuildMode::Marker,
                &ValidationContext {
                    model: "Z8",
                    firmware: "3.11",
                    package: None,
                    module_name: "eg.bin",
                    module,
                },
            )
            .issues
            .iter()
            .any(|i| {
                i.kind == IssueKind::Conflict
                    && i.field == "service_fingerprints.platform.touch_original"
            })
    };
    assert!(conflict(&module));
    module[0xf94..0xf98].copy_from_slice(&[0xf5, 0x53, 0xbe, 0xa9]);
    assert!(!conflict(&module));
    module[0xf97] ^= 1;
    assert!(conflict(&module));
}

/// The start-up escape (DISP) on a body whose scan callback is the exit
/// service's: `services.program.keys` is read from
/// `services.platform.scan.object`, so it is checked against that scan's
/// banks and kept bits, and a key with no object to read is refused.
#[test]
fn escape_keys_are_checked_against_the_scan_they_are_read_from() {
    // The Z8 shape: no program input slot, the exit callback carries the
    // scan, the escape key is the tenth entry (NLR_KEY_DISP).
    let mut keys = vec![[0u32, 0u32]; 9];
    keys.push([2, 0x0010_0000]);
    let mut kept = scan();
    kept.keep_bank = 0;
    kept.keep_mask = 0x200;
    let platform = PlatformServices {
        scan: Some(kept.clone()),
        ..Default::default()
    };
    let mut z8 = profile(false, true, Some(platform));
    z8.services.program = Some(ProgramServices {
        keys: keys.clone(),
        ..Default::default()
    });
    assert!(!issue(&z8, IssueKind::Invalid, "services.program.keys"));
    assert!(!issue(&z8, IssueKind::Conflict, "services.program.keys"));

    // A bank the scan does not have, and the camera's kept bit.
    z8.services.program.as_mut().unwrap().keys[9] = [3, 0x1];
    assert!(issue(&z8, IssueKind::Conflict, "services.program.keys"));
    z8.services.program.as_mut().unwrap().keys[9] = [0, 0x200];
    assert!(issue(&z8, IssueKind::Conflict, "services.program.keys"));
    z8.services.program.as_mut().unwrap().keys[9] = [0, 0x400];
    assert!(!issue(&z8, IssueKind::Conflict, "services.program.keys"));

    // No object under the scan: nothing to read the key from.
    let mut no_object = kept.clone();
    no_object.object = None;
    z8.services.platform.as_mut().unwrap().scan = Some(no_object);
    assert!(issue(&z8, IssueKind::Invalid, "services.program.keys"));
    z8.services.platform = None;
    assert!(issue(&z8, IssueKind::Invalid, "services.program.keys"));

    // Keys that are all zero declare nothing and need nothing.
    z8.services.program.as_mut().unwrap().keys = vec![[0, 0]; 10];
    assert!(!issue(&z8, IssueKind::Invalid, "services.program.keys"));

    // The program input slot's own object keeps its own checks.
    let mut slot = profile(true, false, None);
    let program = slot.services.program.as_mut().unwrap();
    program.input_object = Some(0x6000);
    program.keys = keys;
    assert!(!issue(&slot, IssueKind::Invalid, "services.program.keys"));
}

/* Tables: the declared CRC must be the CRC-32 of the stock bytes in the
 * module -- a pointer table's read-only data, a code or repack table's own
 * bytes -- and a slot the module loads must start null or at the data. */
fn tables_profile(tables: Vec<PlatformTable>) -> Profile {
    let mut profile = profile(
        false,
        false,
        Some(PlatformServices {
            tables,
            ..Default::default()
        }),
    );
    profile.identity.eg_module = Some("eg.bin".into());
    profile.memory.xip_base = Some(0x1000);
    profile.memory.module_size = Some(0x2000);
    profile.memory.segments = vec![
        MemorySegment {
            file_offset: 0,
            runtime_start: 0x1000,
            size: 0x1000,
            kind: MemorySegmentKind::Xip,
        },
        MemorySegment {
            file_offset: 0x1000,
            runtime_start: 0xa000_0000,
            size: 0x1000,
            kind: MemorySegmentKind::Ram,
        },
    ];
    profile
}

fn table_issues(profile: &Profile, module: &[u8]) -> Vec<(IssueKind, String)> {
    profile
        .validate_for(
            BuildMode::Marker,
            &ValidationContext {
                model: "Z8",
                firmware: "3.11",
                package: None,
                module_name: "eg.bin",
                module,
            },
        )
        .issues
        .into_iter()
        .filter(|i| i.field.starts_with("services.platform.tables."))
        .map(|i| (i.kind, i.field))
        .collect()
}

fn table(name: &str, address: u64, class: &str, crc: u32, pointer: Option<u64>) -> PlatformTable {
    PlatformTable {
        name: name.into(),
        address,
        size: 0x40,
        class: class.into(),
        crc,
        stock_pointer: pointer,
    }
}

#[test]
fn table_crcs_are_checked_against_the_module() {
    let mut module = vec![0u8; 0x2000];
    for (n, b) in module[0x800..0x840].iter_mut().enumerate() {
        *b = n as u8 ^ 0x5a;
    }
    let crc = table_crc32(&module[0x800..0x840]);
    /* A pointer table in BSS (outside every loaded segment), a repack
     * table on the same bytes, a RAM table outside the image. */
    let good = tables_profile(vec![
        table("gui.palette", 0xa010_0000, "pointer", crc, Some(0x1800)),
        table("isp.lut1.nlog", 0x1800, "repack", crc, None),
        table("ram.free", 0xa020_0000, "ram", 0x1234, None),
    ]);
    assert_eq!(table_issues(&good, &module), vec![]);
    /* A wrong CRC, in either class. */
    let bad = tables_profile(vec![
        table("gui.palette", 0xa010_0000, "pointer", crc ^ 1, Some(0x1800)),
        table("isp.lut1.nlog", 0x1800, "repack", crc ^ 1, None),
    ]);
    let palette = "services.platform.tables.gui.palette".to_string();
    let lut = "services.platform.tables.isp.lut1.nlog".to_string();
    assert_eq!(
        table_issues(&bad, &module),
        vec![
            (IssueKind::FingerprintMismatch, palette.clone()),
            (IssueKind::FingerprintMismatch, lut),
        ]
    );
    /* A pointer whose data is not in the module at all. */
    let outside = tables_profile(vec![table(
        "gui.palette",
        0xa010_0000,
        "pointer",
        crc,
        Some(0x5000),
    )]);
    assert_eq!(
        table_issues(&outside, &module),
        vec![(IssueKind::OutOfBounds, palette.clone())]
    );
    /* A slot in initialized RAM: null or the stock data, nothing else. */
    let loaded = tables_profile(vec![table(
        "gui.palette",
        0xa000_0100,
        "pointer",
        crc,
        Some(0x1800),
    )]);
    assert_eq!(table_issues(&loaded, &module), vec![]);
    module[0x1100..0x1108].copy_from_slice(&0x1800u64.to_le_bytes());
    assert_eq!(table_issues(&loaded, &module), vec![]);
    module[0x1100..0x1108].copy_from_slice(&0x1840u64.to_le_bytes());
    assert_eq!(
        table_issues(&loaded, &module),
        vec![(IssueKind::Conflict, palette)]
    );
}

/// What the camera always sees while a program holds the controls: core
/// hides every scan bit except the declared keep bits (core/platform.c
/// nlr_platform_input_pass), whichever carrier runs the scan. A declared
/// scan with no keep bit would hide the main switch too -- the old "black
/// screen after the shutter is released" -- so it is refused, exactly as
/// the program input slot's `keep_mask = 0` is.
#[test]
fn a_declared_scan_keeps_a_bit_for_the_camera() {
    let mut none = scan();
    none.keep_mask = 0;
    let exit = profile(
        false,
        true,
        Some(PlatformServices {
            controls: controls(),
            scan: Some(none.clone()),
            ..Default::default()
        }),
    );
    assert!(issue(
        &exit,
        IssueKind::Invalid,
        "services.platform.scan.keep_mask"
    ));
    /* The same rule on the program input slot's carrier: the scan's own
     * geometry is what core reads whenever the table is declared. */
    let mut slot = profile(
        true,
        false,
        Some(PlatformServices {
            controls: controls(),
            scan: Some(none),
            ..Default::default()
        }),
    );
    assert!(issue(
        &slot,
        IssueKind::Invalid,
        "services.platform.scan.keep_mask"
    ));
    slot.services.platform.as_mut().unwrap().scan = Some(scan());
    assert!(!issue(
        &slot,
        IssueKind::Invalid,
        "services.platform.scan.keep_mask"
    ));
    /* The Z 6III shape -- no scan table, geometry from the program input
     * slot -- keeps its own keep_mask check and stays valid. */
    let program = profile(
        true,
        false,
        Some(PlatformServices {
            controls: controls(),
            ..Default::default()
        }),
    );
    assert!(!issue(
        &program,
        IssueKind::Invalid,
        "services.platform.scan.keep_mask"
    ));
    assert!(!issue(
        &program,
        IssueKind::Invalid,
        "services.program.banks"
    ));
}

fn has(issues: &[ValidationIssue], kind: IssueKind, field: &str) -> bool {
    issues.iter().any(|i| i.kind == kind && i.field == field)
}

/// Bank numbers come from the profile: any of them beyond the declared
/// banks, or beyond core's four, is a reported issue and never an index
/// out of range in the validator.
#[test]
fn bank_numbers_past_four_are_reported_not_indexed() {
    let all = |profile: &Profile| profile.validate(BuildMode::Marker).issues;
    /* A scan over five banks with controls on banks 4 and 7. */
    let mut five = scan();
    five.banks = 5;
    let wide = profile(
        false,
        true,
        Some(PlatformServices {
            controls: vec![("ok".into(), 4, 0x1), ("up".into(), 7, 0x2)],
            scan: Some(five),
            ..Default::default()
        }),
    );
    let issues = all(&wide);
    assert!(has(&issues, IssueKind::Invalid, "services.platform.scan"));
    assert!(has(
        &issues,
        IssueKind::Conflict,
        "services.platform.controls.ok"
    ));
    assert!(has(
        &issues,
        IssueKind::Conflict,
        "services.platform.controls.up"
    ));

    /* keep_bank, a huge bank count, huge dial words and key banks. */
    let mut huge = scan();
    huge.banks = u32::MAX;
    huge.keep_bank = u32::MAX - 1;
    let mut keys = vec![[0u32, 0u32]; 9];
    keys.push([u32::MAX, 0x1]);
    let mut wild = profile(
        false,
        true,
        Some(PlatformServices {
            controls: vec![("ok".into(), u32::MAX - 1, 0x1)],
            dial_words: [255, 0, 0],
            dial_alt_words: [0, 255, 0],
            dial_signs: [1, 1, 1],
            scan: Some(huge),
            ..Default::default()
        }),
    );
    wild.services.program = Some(ProgramServices {
        keys,
        ..Default::default()
    });
    let issues = all(&wild);
    assert!(has(&issues, IssueKind::Invalid, "services.platform.scan"));
    assert!(has(
        &issues,
        IssueKind::Conflict,
        "services.platform.controls.ok"
    ));
    assert!(has(&issues, IssueKind::Conflict, "services.program.keys"));
    assert!(has(
        &issues,
        IssueKind::OutOfBounds,
        "services.platform.dial_words[0]"
    ));
    assert!(has(
        &issues,
        IssueKind::OutOfBounds,
        "services.platform.dial_words[1]"
    ));

    /* The program input slot's geometry over five banks. */
    let mut slot = profile(
        true,
        false,
        Some(PlatformServices {
            controls: vec![("ok".into(), 4, 0x1)],
            ..Default::default()
        }),
    );
    slot.services.program.as_mut().unwrap().banks = 5;
    slot.services.program.as_mut().unwrap().keys = vec![[6, 0x1]];
    let issues = all(&slot);
    assert!(has(&issues, IssueKind::Invalid, "services.program.banks"));
    assert!(has(
        &issues,
        IssueKind::Conflict,
        "services.platform.controls.ok"
    ));
    assert!(has(&issues, IssueKind::Conflict, "services.program.keys"));
}
