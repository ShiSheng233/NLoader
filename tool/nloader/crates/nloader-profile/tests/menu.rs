mod common;
use nloader_profile::*;

const LAYOUT: u64 = 5120;
const SETUP_ITEMS: u64 = 5376;

fn write(bytes: &mut [u8], memory: &Memory, address: u64, data: &[u8]) {
    let start = memory
        .address_to_offset(address, data.len() as u64)
        .unwrap() as usize;
    bytes[start..start + data.len()].copy_from_slice(data);
}
fn fixture() -> (Profile, Vec<u8>, Vec<u8>) {
    let mut profile = Profile::draft("Z8", "3.11");
    profile.identity.container = Some(ContainerKind::LegacyXor);
    profile.identity.stock_pkg = Some("synthetic.bin".into());
    profile.identity.eg_module = Some("synthetic.bi".into());
    profile.memory = Memory {
        xip_base: Some(4096),
        module_size: Some(8192),
        segments: vec![
            MemorySegment {
                file_offset: 0,
                runtime_start: 4096,
                size: 4096,
                kind: MemorySegmentKind::Xip,
            },
            MemorySegment {
                file_offset: 4096,
                runtime_start: 65536,
                size: 4096,
                kind: MemorySegmentKind::Ram,
            },
        ],
        slack: Some(Slack {
            start: 7680,
            end: 8192,
            require_zero: true,
        }),
        link_base: Some(7680),
        link_size: Some(512),
        ram_pool: None,
        program_budget_blocks: None,
        program_max_resident: None,
        program_arena_bytes: None,
    };
    profile.menu.window_table = Some(65536);
    profile.menu.record_sizes = Some(MenuRecordSizes {
        window: 96,
        page: 80,
        item: 44,
        event: 32,
    });
    let mut bytes = vec![0; 8192];
    let page = MenuPage {
        entry: None,
        apps: None,
        cursor: None,
        window_id: 1,
        page_address: 66048,
        items: SETUP_ITEMS,
        item_count: 3,
        event_table: 5632,
        layout: LAYOUT,
        firmware_version: None,
    };
    let window = 65536 + u64::from(page.window_id) * 96;
    write(
        &mut bytes,
        &profile.memory,
        window + 2,
        &(page.window_id as u16).to_le_bytes(),
    );
    for (field, value) in [
        (window + 0x50, page.page_address),
        (page.page_address + 0x10, page.items),
        (page.page_address + 0x18, page.event_table),
        (page.page_address + 0x40, LAYOUT),
    ] {
        write(&mut bytes, &profile.memory, field, &value.to_le_bytes());
    }
    write(
        &mut bytes,
        &profile.memory,
        page.page_address + 0x20,
        &(page.item_count as u16).to_le_bytes(),
    );
    write(
        &mut bytes,
        &profile.memory,
        page.page_address + 0x48,
        &5u32.to_le_bytes(),
    );
    profile.menu.setup = Some(page);
    write(&mut bytes, &profile.memory, LAYOUT, &5u16.to_le_bytes());
    write(
        &mut bytes,
        &profile.memory,
        SETUP_ITEMS + 44 + 0x18,
        &123u32.to_le_bytes(),
    );
    setup(&mut profile).firmware_version = Some(MenuItemRef {
        index: 1,
        item_id: 123,
    });
    let package = b"synthetic menu package".to_vec();
    profile.checks.package_sha256 = Some(sha256(&package));
    profile.checks.module_sha256 = Some(sha256(&bytes));
    (profile, package, bytes)
}
fn setup(profile: &mut Profile) -> &mut MenuPage {
    profile.menu.setup.as_mut().unwrap()
}
fn actual(profile: &Profile, package: &[u8], bytes: &[u8]) -> ValidationReport {
    profile.validate_for(
        BuildMode::Marker,
        &ValidationContext {
            model: "Z8",
            firmware: "3.11",
            package: Some(package),
            module_name: "synthetic.bi",
            module: bytes,
        },
    )
}
fn has_issue(report: &ValidationReport, field: &str) -> bool {
    report.issues.iter().any(|issue| issue.field == field)
}
#[test]
fn setup_roundtrips_and_matches_stock_bytes() {
    let (profile, package, bytes) = fixture();
    assert!(
        profile.validate(BuildMode::Marker).is_valid(),
        "{:?}",
        profile.validate(BuildMode::Marker)
    );
    assert!(
        actual(&profile, &package, &bytes).is_valid(),
        "{:?}",
        actual(&profile, &package, &bytes)
    );
    let text = profile.to_toml().unwrap();
    assert_eq!(Profile::from_toml(&text).unwrap(), profile);
    assert!(text.contains("[menu.setup.firmware_version]"));
    assert_eq!(text.matches("firmware_version").count(), 1);
    // Every flashable rung consists of the entry row and NLoader's page, so
    // a Setup-only profile fails on those missing records rather than on an
    // unsupported mode.
    for mode in [
        BuildMode::HookOnly,
        BuildMode::Page,
        BuildMode::LoadOnly,
        BuildMode::PrepareOnly,
        BuildMode::Exec,
    ] {
        let report = profile.validate(mode);
        assert!(!report.issues.iter().any(|issue| issue.field == "mode"));
        for field in ["menu.setup.entry", "menu.text_platform", "menu.page"] {
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.field == field && issue.kind == IssueKind::Missing),
                "{field} should be required by {mode}"
            );
        }
    }
}
#[test]
fn hand_written_hex_profile_is_accepted() {
    let (profile, _, _) = fixture();
    let text = "schema = 1\n\
        [menu]\n\
        window_table = 0x10000 # comments carry the manual source\n\
        record_sizes = { window = 96, page = 80, item = 44, event = 32 }\n\
        [menu.setup]\n\
        window_id = 1\n\
        page_address = 0x10200\n\
        items = 0x1500\n\
        item_count = 3\n\
        event_table = 0x1600\n\
        layout = 0x1400\n\
        firmware_version = { index = 1, item_id = 123 }\n";
    let parsed = Profile::from_toml(text).unwrap();
    assert_eq!(parsed.menu.setup, profile.menu.setup);
    assert_eq!(parsed.menu.window_table, profile.menu.window_table);
}
#[test]
fn page_records_must_use_their_address_space_and_count() {
    let (profile, _, _) = fixture();
    for (mutation, field) in [
        (0, "menu.setup"),
        (1, "menu.setup"),
        (2, "menu.setup"),
        (3, "menu.setup.item_count"),
        (4, "menu.setup.window_id"),
        (5, "menu.setup"),
    ] {
        let mut changed = profile.clone();
        let page = setup(&mut changed);
        match mutation {
            0 => page.page_address = 4096,
            1 => page.items = 65536,
            2 => page.event_table += 4,
            3 => page.item_count = 0,
            4 => page.window_id = 70000,
            _ => page.layout = 7680,
        }
        assert!(
            has_issue(&changed.validate(BuildMode::Marker), field),
            "mutation {mutation}"
        );
    }
}
#[test]
fn image_check_rejects_in_bounds_but_wrong_record_fields() {
    let (profile, package, bytes) = fixture();
    let page = profile.menu.setup.clone().unwrap();
    for (address, value) in [
        (65536 + 96 + 2, vec![9, 0]),
        (65536 + 96 + 0x50, 66128u64.to_le_bytes().to_vec()),
        (page.page_address + 0x10, 5440u64.to_le_bytes().to_vec()),
        (page.page_address + 0x18, 5640u64.to_le_bytes().to_vec()),
        (page.page_address + 0x20, vec![2, 0]),
        (page.page_address + 0x40, 5128u64.to_le_bytes().to_vec()),
        (page.page_address + 0x48, 4u32.to_le_bytes().to_vec()),
    ] {
        let mut changed = bytes.clone();
        write(&mut changed, &profile.memory, address, &value);
        let mut declared = profile.clone();
        declared.checks.module_sha256 = Some(sha256(&changed));
        assert!(declared.validate(BuildMode::Marker).is_valid());
        assert!(
            has_issue(&actual(&declared, &package, &changed), "menu.setup"),
            "address {address:#x}"
        );
    }
}
#[test]
fn firmware_version_anchor_is_bounded_and_matches_the_stock_item() {
    let (profile, package, bytes) = fixture();
    let mut changed = profile.clone();
    setup(&mut changed).firmware_version = Some(MenuItemRef {
        index: 3,
        item_id: 123,
    });
    assert!(has_issue(
        &changed.validate(BuildMode::Marker),
        "menu.setup.firmware_version"
    ));
    let mut changed = profile.clone();
    setup(&mut changed).firmware_version = Some(MenuItemRef {
        index: 1,
        item_id: 124,
    });
    assert!(changed.validate(BuildMode::Marker).is_valid());
    assert!(has_issue(
        &actual(&changed, &package, &bytes),
        "menu.setup.firmware_version"
    ));
}
#[test]
fn table_and_supported_layout_are_required() {
    let (profile, _, _) = fixture();
    let mut changed = profile.clone();
    changed.menu.window_table = None;
    assert!(has_issue(
        &changed.validate(BuildMode::Marker),
        "menu.window_table"
    ));
    let mut changed = profile.clone();
    changed.menu.record_sizes.as_mut().unwrap().item = 48;
    assert!(changed
        .validate(BuildMode::Marker)
        .issues
        .iter()
        .any(|issue| issue.field == "menu.record_sizes" && issue.kind == IssueKind::Unsupported));
}
#[test]
fn obsolete_and_unknown_menu_fields_are_rejected() {
    let (profile, _, _) = fixture();
    let text = profile.to_toml().unwrap();
    let obsolete = format!("{text}\n[menu.playback]\nwindow_id = 2\n");
    let error = Profile::from_toml(&obsolete).unwrap_err().to_string();
    assert!(error.contains("unknown field `playback`"), "{error}");
    for obsolete in [
        "schema = 1\n[menu]\nwindow_tabel = 42",
        "schema = 1\n[menu]\ninjection_position = 3",
        "schema = 1\n[menu.pages.setup]\nwindow_id = 1",
        "schema = 1\n[menu.category_index]\nwindow_id = 2",
        "schema = 1\n[menu.my_menu]\nwindow_id = 968",
    ] {
        assert!(Profile::from_toml(obsolete).is_err(), "{obsolete}");
    }
    for (current, obsolete) in [
        ("event = 32", "event = 32\ncallbacks = 40"),
        ("window_id = 1", "window_id = 1\nwindow_address = 65632"),
        ("window_id = 1", "window_id = 1\nentry_callback = 6144"),
        ("window_id = 1", "window_id = 1\ndynamic_items = false"),
        (
            "[menu.setup.firmware_version]",
            "[menu.setup.navigation.open]",
        ),
    ] {
        let changed = text.replacen(current, obsolete, 1);
        assert_ne!(changed, text);
        assert!(Profile::from_toml(&changed).is_err(), "{obsolete}");
    }
}
#[test]
fn manual_menu_needs_no_extraction_evidence_but_keeps_byte_checks() {
    let (profile, package, bytes) = fixture();
    let evidence = common::evidence_for(&profile);
    assert!(profile
        .validate_extraction(BuildMode::Marker, &evidence, &[])
        .is_valid());
    let mut changed = bytes.clone();
    write(
        &mut changed,
        &profile.memory,
        SETUP_ITEMS + 44 + 0x18,
        &[0; 4],
    );
    let mut declared = profile.clone();
    declared.checks.module_sha256 = Some(sha256(&changed));
    assert!(has_issue(
        &actual(&declared, &package, &changed),
        "menu.setup.firmware_version"
    ));
}

/* NLoader's own page: a stock list page to clone (window 10), two all-zero
 * holes (11 for the window, 12 borrowed for the page record), a
 * page-specific handler block on the template and a stock footer-only block,
 * the stock row table the page row reuses (it only returns), and the Setup
 * row table that opens the template. */
const OWN_TEMPLATE_PAGE: u64 = 67000;
const OWN_TEMPLATE_HANDLERS: u64 = 67200;
const OWN_ELEMENTS: u64 = 6000;
const OWN_ITEMS: u64 = 6400;
const OWN_ROW_TABLE: u64 = 7488;
const OWN_ROW_TEMPLATE: u64 = 6528;
const FOOTER: u64 = 0x1234;
const WIDGET_FIND: u64 = 0x1300;
const TEXT_BIND: u64 = 0x1340;
const TEXT_STORE: u64 = 0x1380;
const WIDGET_SHOW: u64 = 0x13c0;
const TITLE_CHAIN: u64 = 6800;

/* A stock title chain: container = x19 + 0x18, format 3 via ORR, then
 * lookup, store, bind, show. */
fn title_chain(calls: [u64; 4]) -> Vec<u8> {
    let bl = |at: u64, target: u64| {
        let delta = ((target as i64 - at as i64) / 4) as u32 & 0x03ff_ffff;
        0x9400_0000u32 | delta
    };
    let mut words = vec![0x9100_6273u32, 0x3200_07e2];
    for (index, target) in calls.into_iter().enumerate() {
        words.push(bl(TITLE_CHAIN + 8 + index as u64 * 4, target));
    }
    words.into_iter().flat_map(u32::to_le_bytes).collect()
}

fn own_page_fixture() -> (Profile, Vec<u8>, Vec<u8>) {
    let (mut profile, package, mut bytes) = fixture();
    let (events, navigation) = menu_events(4160);
    profile.menu.events = Some(events);
    write(&mut bytes, &profile.memory, 4160, &navigation);
    let memory = profile.memory.clone();
    let window = 65536 + 10 * 96;
    write(&mut bytes, &memory, window, &2u16.to_le_bytes());
    write(&mut bytes, &memory, window + 2, &10u16.to_le_bytes());
    write(
        &mut bytes,
        &memory,
        window + 0x28,
        &OWN_TEMPLATE_HANDLERS.to_le_bytes(),
    );
    write(
        &mut bytes,
        &memory,
        window + 0x50,
        &OWN_TEMPLATE_PAGE.to_le_bytes(),
    );
    write(
        &mut bytes,
        &memory,
        OWN_TEMPLATE_PAGE,
        &0x8000_1008u32.to_le_bytes(),
    );
    write(
        &mut bytes,
        &memory,
        OWN_TEMPLATE_PAGE + 0x08,
        &OWN_ELEMENTS.to_le_bytes(),
    );
    write(
        &mut bytes,
        &memory,
        OWN_TEMPLATE_PAGE + 0x10,
        &OWN_ITEMS.to_le_bytes(),
    );
    write(
        &mut bytes,
        &memory,
        OWN_TEMPLATE_PAGE + 0x20,
        &2u16.to_le_bytes(),
    );
    for (slot, handler) in [0x11u64, 0x22, FOOTER, 0x33, 0x44].into_iter().enumerate() {
        write(
            &mut bytes,
            &memory,
            OWN_TEMPLATE_HANDLERS + slot as u64 * 8,
            &handler.to_le_bytes(),
        );
    }
    for (index, kind) in [6u32, 1, 4].into_iter().enumerate() {
        write(
            &mut bytes,
            &memory,
            OWN_ELEMENTS + index as u64 * 0x44 + 4,
            &kind.to_le_bytes(),
        );
    }
    let record = |code: u32, next: u32| {
        let mut record = [0u8; 32];
        record[0..4].copy_from_slice(&code.to_le_bytes());
        record[8..16].copy_from_slice(&0x4000u64.to_le_bytes());
        record[0x18..0x1c].copy_from_slice(&next.to_le_bytes());
        record
    };
    for (index, (code, next)) in [
        (0x286u32, 0x68d),
        (0x285, 0x68d),
        (0x2a0, 0x68d),
        (0x306, 0x68d),
        (0x3bb, 0x68c),
    ]
    .into_iter()
    .enumerate()
    {
        write(
            &mut bytes,
            &memory,
            OWN_ROW_TABLE + index as u64 * 32,
            &record(code, next),
        );
    }
    for (index, (code, next)) in [
        (0x100u32, 0x68c),
        (0x286, 10),
        (0x28b, 10),
        (0x29f, 10),
        (0x2ae, 10),
        (0x3bb, 0x68c),
    ]
    .into_iter()
    .enumerate()
    {
        write(
            &mut bytes,
            &memory,
            OWN_ROW_TEMPLATE + index as u64 * 32,
            &record(code, next),
        );
    }
    profile.menu.page = Some(MenuOwnPage {
        refresh: None,
        window_id: 11,
        page_record: 65536 + 12 * 96,
        template_window: 10,
        template_page: OWN_TEMPLATE_PAGE,
        row_event_table: OWN_ROW_TABLE,
        row_template_event_table: OWN_ROW_TEMPLATE,
        title_slot: 297,
        title_format: 3,
        item_id: 0x38c5,
        item_flags: 0x10_1240,
        item_slot: 298,
        item_style: 4,
        item_text: "NLoader page".into(),
        row_slots: Vec::new(),
        row_hide: None,
        row_hide_stock: Vec::new(),
        selected_offset: Some(0x32),
        viewport_bottom: None,
        row_words: Vec::new(),
        style_page: None,
        dynamic_rows: false,
        detail_window_id: None,
        rows: None,
        keyboard: None,
        rebuild: None,
        caution: None,
    });
    profile.ui.widget_find = Some(WIDGET_FIND);
    profile.ui.text_bind = Some(TEXT_BIND);
    profile.ui.text_store = Some(TEXT_STORE);
    profile.ui.widget_show = Some(WIDGET_SHOW);
    profile.ui.widget_container_offset = Some(0x18);
    let chain = title_chain([WIDGET_FIND, TEXT_STORE, TEXT_BIND, WIDGET_SHOW]);
    write(&mut bytes, &memory, TITLE_CHAIN, &chain);
    profile.ui.title_chain = Some(ServiceFingerprint {
        eg_off: memory
            .address_to_offset(TITLE_CHAIN, chain.len() as u64)
            .unwrap(),
        stock: chain,
    });
    profile.checks.module_sha256 = Some(sha256(&bytes));
    (profile, package, bytes)
}

/* Issues on the page's own fields. The bare `menu.page` field is left out:
 * it reports the undeclared Setup entry, which this fixture does not need. */
fn page_issues(report: &ValidationReport) -> Vec<String> {
    report
        .issues
        .iter()
        .filter(|issue| issue.field.starts_with("menu.page."))
        .map(|issue| format!("{}: {}", issue.field, issue.message))
        .collect()
}

#[test]
fn own_page_accepts_a_list_template_and_rejects_each_wrong_record() {
    let (profile, package, bytes) = own_page_fixture();
    assert_eq!(
        page_issues(&actual(&profile, &package, &bytes)),
        Vec::<String>::new()
    );
    let memory = profile.memory.clone();
    let rejected = |bytes: &[u8], profile: &Profile, field: &str| {
        let mut profile = profile.clone();
        profile.checks.module_sha256 = Some(sha256(bytes));
        let report = actual(&profile, &package, bytes);
        assert!(
            has_issue(&report, field),
            "{field} not reported: {:?}",
            page_issues(&report)
        );
    };

    /* An occupied hole may belong to a window in use. */
    let mut changed = bytes.clone();
    write(&mut changed, &memory, 65536 + 11 * 96 + 0x40, &[1]);
    rejected(&changed, &profile, "menu.page.window_id");
    let mut changed = bytes.clone();
    write(&mut changed, &memory, 65536 + 12 * 96 + 0x58, &[1]);
    rejected(&changed, &profile, "menu.page.page_record");

    /* A page whose rows the generic builder does not lay out. */
    let mut changed = bytes.clone();
    write(
        &mut changed,
        &memory,
        OWN_TEMPLATE_PAGE,
        &0x1008u32.to_le_bytes(),
    );
    rejected(&changed, &profile, "menu.page.template_page");
    /* A title bar with two titles. */
    let mut changed = bytes.clone();
    write(
        &mut changed,
        &memory,
        OWN_ELEMENTS + 2 * 0x44 + 4,
        &1u32.to_le_bytes(),
    );
    rejected(&changed, &profile, "menu.page.template_page");

    /* A template without a footer handler leaves nothing to carry over into
     * the generated handler block. */
    let mut changed = bytes.clone();
    write(
        &mut changed,
        &memory,
        OWN_TEMPLATE_HANDLERS + 16,
        &0u64.to_le_bytes(),
    );
    rejected(&changed, &profile, "menu.page.template_window");

    /* The page entry calls the stock lookup and bind in the stock container. */
    for field in [
        "ui.widget_find",
        "ui.text_bind",
        "ui.widget_show",
        "ui.title_chain",
        "ui.widget_container_offset",
    ] {
        let mut missing = profile.clone();
        match field {
            "ui.widget_find" => missing.ui.widget_find = None,
            "ui.text_bind" => missing.ui.text_bind = None,
            "ui.widget_show" => missing.ui.widget_show = None,
            "ui.title_chain" => missing.ui.title_chain = None,
            _ => missing.ui.widget_container_offset = None,
        }
        rejected(&bytes, &missing, field);
    }

    /* The title follows the stock title chain: its format, and the lookup,
     * store, bind, show order, must be what those bytes do. */
    let mut wrong = profile.clone();
    wrong.menu.page.as_mut().unwrap().title_format = 4;
    rejected(&bytes, &wrong, "menu.page.title_format");
    for (calls, field) in [
        (
            [WIDGET_FIND, TEXT_BIND, TEXT_STORE, WIDGET_SHOW],
            "ui.text_bind",
        ),
        (
            [WIDGET_FIND, TEXT_STORE, TEXT_BIND, TEXT_BIND],
            "ui.widget_show",
        ),
    ] {
        let chain = title_chain(calls);
        let mut changed = bytes.clone();
        write(&mut changed, &memory, TITLE_CHAIN, &chain);
        let mut declared = profile.clone();
        declared.ui.title_chain.as_mut().unwrap().stock = chain;
        rejected(&changed, &declared, field);
    }
    /* The title needs a slot of its own. */
    let mut wrong = profile.clone();
    wrong.menu.page.as_mut().unwrap().title_slot = 298;
    rejected(&bytes, &wrong, "menu.page.title_slot");

    /* A page row whose OK would open a stock page. */
    let mut changed = bytes.clone();
    write(
        &mut changed,
        &memory,
        OWN_ROW_TABLE + 0x18,
        &10u32.to_le_bytes(),
    );
    rejected(&changed, &profile, "menu.page.row_event_table");

    /* A Setup row template that opens some other window. */
    let mut changed = bytes.clone();
    write(
        &mut changed,
        &memory,
        OWN_ROW_TEMPLATE + 32 + 0x18,
        &9u32.to_le_bytes(),
    );
    rejected(&changed, &profile, "menu.page.row_template_event_table");
}

#[test]
fn list_rungs_require_the_list_rows() {
    // The fixture declares a one-row page: enough for the lower rungs, but
    // from load-only on the page is the program list and its details, which
    // one row cannot show, so the rows are required there.
    let (profile, _, _) = own_page_fixture();
    assert!(profile.menu.page.as_ref().unwrap().row_slots.is_empty());
    for mode in [BuildMode::LoadOnly, BuildMode::PrepareOnly, BuildMode::Exec] {
        assert!(
            profile.validate(mode).issues.iter().any(|issue| {
                issue.field == "menu.page.row_slots" && issue.kind == IssueKind::Missing
            }),
            "{mode} must require the list rows"
        );
    }
    for mode in [BuildMode::HookOnly, BuildMode::Page] {
        assert!(
            !profile
                .validate(mode)
                .issues
                .iter()
                .any(|issue| issue.field == "menu.page.row_slots"),
            "{mode} keeps one row"
        );
    }
}

#[test]
fn list_profile_rejects_slot_collisions_and_mismatched_hide_function() {
    let (mut profile, package, bytes) = own_page_fixture();
    let memory = profile.memory.clone();
    let page = profile.menu.page.as_mut().unwrap();
    page.item_id = 0x7f80;
    page.item_slot = 251;
    page.row_slots = (251..=296).chain(232..=249).collect();
    page.selected_offset = Some(0x32);
    page.row_hide = Some(WIDGET_SHOW);
    let offset = memory.address_to_offset(WIDGET_SHOW, 16).unwrap() as usize;
    page.row_hide_stock = bytes[offset..offset + 16].to_vec();
    assert_eq!(
        page_issues(&actual(&profile, &package, &bytes)),
        Vec::<String>::new()
    );
    for (index, slot) in [(1, 251), (1, 297), (1, 300), (1, 0)] {
        let mut bad = profile.clone();
        bad.menu.page.as_mut().unwrap().row_slots[index] = slot;
        assert!(has_issue(
            &actual(&bad, &package, &bytes),
            "menu.page.row_slots"
        ));
    }
    let mut bad = profile.clone();
    bad.menu.page.as_mut().unwrap().row_slots.pop();
    assert!(has_issue(
        &actual(&bad, &package, &bytes),
        "menu.page.row_slots"
    ));
    let mut bad = profile.clone();
    bad.menu.page.as_mut().unwrap().selected_offset = Some(0x58);
    assert!(has_issue(
        &actual(&bad, &package, &bytes),
        "menu.page.selected_offset"
    ));
    bad.menu.page.as_mut().unwrap().selected_offset = None;
    assert!(has_issue(
        &actual(&bad, &package, &bytes),
        "menu.page.selected_offset"
    ));
    let mut bad = profile.clone();
    bad.menu.page.as_mut().unwrap().row_hide_stock[0] ^= 1;
    assert!(has_issue(
        &actual(&bad, &package, &bytes),
        "menu.page.row_hide_stock"
    ));
}

fn menu_events(address: u64) -> (nloader_profile::MenuEvents, Vec<u8>) {
    // Synthetic dispatcher instructions, without any camera address or body.
    let mut body = vec![0u8; 0x204];
    for (offset, word) in [
        (0x08, 0x710eed3fu32),
        (0x34, 0x710eed7f),
        (0x6c, 0x710eed3f),
        (0x94, 0x710eed3f),
    ] {
        body[0x154 + offset..0x158 + offset].copy_from_slice(&word.to_le_bytes());
    }
    for (offset, word) in [
        (0x34, 0x5280_d188u32),
        (0x50, 0x511a_3688),
        (0xbc, 0x711a_5a9f),
        (0xc4, 0x711a_5e9f),
    ] {
        body[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
    (
        nloader_profile::MenuEvents {
            activation: [0x286, 0x28b, 0x29f, 0x2ae],
            back: [0x285, 0x2a0, 0x306],
            ok: 0x286,
            terminator: 0x3bb,
            nav_first: 0x68c,
            nav_back: 0x68d,
            nav_reenter: 0x696,
            nav_last: 0x697,
            navigation_address: address,
            navigation_sha256: nloader_profile::sha256(&body[..0x154]),
            lookup_address: address + 0x154,
            lookup_sha256: nloader_profile::sha256(&body[0x154..]),
        },
        body,
    )
}

#[test]
fn menu_event_values_require_matching_navigation_evidence() {
    let (profile, package, bytes) = own_page_fixture();
    assert!(!has_issue(
        &actual(&profile, &package, &bytes),
        "menu.events"
    ));
    let mut wrong = profile.clone();
    wrong.menu.events.as_mut().unwrap().nav_reenter += 1;
    assert!(has_issue(&actual(&wrong, &package, &bytes), "menu.events"));
    let mut wrong = profile.clone();
    wrong.menu.events.as_mut().unwrap().terminator = 0x286;
    assert!(has_issue(&actual(&wrong, &package, &bytes), "menu.events"));
    let mut wrong = profile.clone();
    wrong.menu.page.as_mut().unwrap().row_slots = vec![298];
    wrong.menu.events.as_mut().unwrap().back[1] = 0x777;
    assert!(has_issue(
        &actual(&wrong, &package, &bytes),
        "menu.page.row_event_table"
    ));
    let mut wrong = profile.clone();
    wrong.menu.events.as_mut().unwrap().navigation_sha256 = "0".repeat(64);
    assert!(has_issue(&actual(&wrong, &package, &bytes), "menu.events"));
    let mut wrong = profile.clone();
    wrong.menu.events.as_mut().unwrap().activation[1] = 0x777;
    assert!(has_issue(
        &actual(&wrong, &package, &bytes),
        "menu.page.row_template_event_table"
    ));
    let mut wrong = profile.clone();
    wrong.menu.events = None;
    assert!(has_issue(
        &wrong.validate(BuildMode::HookOnly),
        "menu.events"
    ));
}

/// The NLoader row may also follow every stock row,
/// and the Apps row needs an index within the page, an item id and a label
/// slot of its own, the runtime-text label flags and a printable label.
#[test]
fn entry_may_follow_every_row_and_apps_needs_its_own_id_and_slot() {
    let (profile, _, _) = fixture();
    let mut changed = profile.clone();
    {
        let page = setup(&mut changed);
        page.firmware_version = Some(nloader_profile::MenuItemRef {
            index: 1,
            item_id: 123,
        });
        page.entry = Some(nloader_profile::MenuEntrySpec {
            index: 3,
            item_id: 0x7ffe,
            flags: 0x101240,
        });
        page.apps = Some(nloader_profile::MenuAppsSpec {
            index: 0,
            item_id: 0x7ffd,
            flags: 0x101240,
            slot: 249,
            text: "Apps".into(),
        });
    }
    let report = changed.validate(BuildMode::Marker);
    assert!(!report.issues.iter().any(|i| i.field == "menu.setup.entry"));
    assert!(!report.issues.iter().any(|i| i.field == "menu.setup.apps"));
    for mutation in 0..6 {
        let mut bad = changed.clone();
        let page = setup(&mut bad);
        let apps = page.apps.as_mut().unwrap();
        match mutation {
            0 => apps.index = 4,
            1 => apps.item_id = 0x7ffe,
            2 => apps.flags = 0x101250,
            3 => apps.slot = 300,
            4 => apps.text = String::new(),
            _ => apps.text = "Apps\u{7f}".into(),
        }
        assert!(
            has_issue(&bad.validate(BuildMode::Marker), "menu.setup.apps"),
            "mutation {mutation}"
        );
    }
    let mut bad = changed.clone();
    setup(&mut bad).entry.as_mut().unwrap().index = 2; /* neither anchor nor end */
    assert!(has_issue(
        &bad.validate(BuildMode::Marker),
        "menu.setup.entry"
    ));
}

/// With private text the Apps label is the family's exact Apps token
/// (base + 67), never a stock slot and never another private token; the
/// namespace check also ties the row to the family's Apps item ID.
#[test]
fn private_apps_row_takes_exactly_the_family_apps_token() {
    let (profile, _, _) = fixture();
    let mut changed = profile.clone();
    let base = u32::from_be_bytes(*b"NL\0\0");
    {
        let page = setup(&mut changed);
        page.firmware_version = Some(nloader_profile::MenuItemRef {
            index: 1,
            item_id: 123,
        });
        page.entry = Some(nloader_profile::MenuEntrySpec {
            index: 3,
            item_id: 0x7ffe,
            flags: 0x101240,
        });
        page.apps = Some(nloader_profile::MenuAppsSpec {
            index: 0,
            item_id: 0x7ffd,
            flags: 0x101240,
            slot: base + 67,
            text: "Apps".into(),
        });
    }
    changed.menu.private_text = Some(PrivateText {
        family: PrivateTextFamily::Z8PrivateAsciiNamespaceV1,
        token_base: base,
        token_count: 68,
        title_index: 64,
        status_index: 65,
        entry_index: 66,
        apps_index: 67,
        row_first_item: 0x7f80,
        entry_item_id: 0x7ffe,
        apps_item_id: 0x7ffd,
        ascii_flags: 0x200,
        styles: vec![3, 4],
        getter_call_sites: vec![],
        item_clamp: 0,
        value_clamp: None,
        strlen: 0,
        memcpy: 0,
        fallback_text: "unavailable".into(),
        gui_task_name: "APPMENU".into(),
        gui_task_config: 0,
        registry_cases: ExecutionTable {
            name: "registry_cases".into(),
            address: 0,
            element_bytes: 8,
            values: vec![],
        },
        bodies: vec![],
    });
    let apps_message =
        "Setup Apps row must use the exact private Apps token, item ID and ASCII path";
    let report = changed.validate(BuildMode::Marker);
    assert!(!report.issues.iter().any(|i| i.field == "menu.setup.apps"));
    assert!(!report.issues.iter().any(|i| i.message == apps_message));
    for slot in [249, base + 66, base + 68] {
        let mut bad = changed.clone();
        setup(&mut bad).apps.as_mut().unwrap().slot = slot;
        assert!(
            has_issue(&bad.validate(BuildMode::Marker), "menu.setup.apps"),
            "slot {slot:#x}"
        );
    }
    let mut bad = changed.clone();
    setup(&mut bad).apps.as_mut().unwrap().item_id = 0x7ffc;
    assert!(bad
        .validate(BuildMode::Marker)
        .issues
        .iter()
        .any(|i| i.field == "menu.private_text" && i.message == apps_message));
    let mut bad = changed.clone();
    bad.menu.private_text.as_mut().unwrap().token_count = 67;
    assert!(bad.validate(BuildMode::Marker).issues.iter().any(|i| {
        i.field == "menu.private_text" && i.message.starts_with("namespace, exact item mapping")
    }));
    // The value clamp route is declared exactly when the page has row kinds:
    // a private row's value slot is otherwise dropped by the stock builder.
    let route = "the value clamp route is declared exactly when the page has row kinds";
    let routed = |p: &Profile| {
        p.validate(BuildMode::Marker)
            .issues
            .iter()
            .any(|i| i.field == "menu.private_text" && i.message == route)
    };
    assert!(!routed(&changed));
    let mut bad = changed.clone();
    bad.menu.private_text.as_mut().unwrap().value_clamp = Some(0x100f40);
    assert!(routed(&bad));
}

#[test]
fn private_caution_text_takes_exactly_the_family_status_token() {
    let (mut profile, _, _) = own_page_fixture();
    let base = u32::from_be_bytes(*b"NL\0\0");
    {
        let page = profile.menu.page.as_mut().unwrap();
        page.keyboard = Some(MenuKeyboard {
            window_id: 12,
            template_window: 13,
            save_event: 687,
            menu_event: 638,
            back_event: 774,
            help_event: 688,
            open: 0x1000,
            open_stock: vec![0; 16],
            take: 0x1010,
            take_stock: vec![0; 16],
            shown: 0x1020,
            shown_stock: vec![0; 16],
        });
        page.caution = Some(MenuCaution {
            template_window: 14,
            yes_action: 0x2000,
            no_action: 0x2010,
            panel: 0x4bac,
            text_slot: 249,
            text_format: 3,
            ok_label: 0x895,
            panel_text: 0x2020,
            panel_text_stock: vec![0; 16],
            cursor_set: 0x2030,
            cursor_set_stock: vec![0; 16],
        });
    }
    let slot_issue = |p: &Profile| {
        p.validate(BuildMode::Marker).issues.iter().any(|i| {
            i.field == "menu.page.caution" && i.message.starts_with("the caution box needs")
        })
    };
    let set_slot = |p: &mut Profile, slot: u32| {
        p.menu
            .page
            .as_mut()
            .unwrap()
            .caution
            .as_mut()
            .unwrap()
            .text_slot = slot;
    };
    // Without private text: a stock slot below 300, never 0 or a token.
    assert!(!slot_issue(&profile));
    for slot in [0, 300, base + 65] {
        let mut bad = profile.clone();
        set_slot(&mut bad, slot);
        assert!(slot_issue(&bad), "stock slot {slot:#x}");
    }
    // With private text: exactly the family's status token, in its styles.
    profile.menu.private_text = Some(PrivateText {
        family: PrivateTextFamily::Z8PrivateAsciiNamespaceV1,
        token_base: base,
        token_count: 68,
        title_index: 64,
        status_index: 65,
        entry_index: 66,
        apps_index: 67,
        row_first_item: 0x7f80,
        entry_item_id: 0x7ffe,
        apps_item_id: 0x7ffd,
        ascii_flags: 0x200,
        styles: vec![3, 4],
        getter_call_sites: vec![],
        item_clamp: 0,
        value_clamp: None,
        strlen: 0,
        memcpy: 0,
        fallback_text: "unavailable".into(),
        gui_task_name: "APPMENU".into(),
        gui_task_config: 0,
        registry_cases: ExecutionTable {
            name: "registry_cases".into(),
            address: 0,
            element_bytes: 8,
            values: vec![],
        },
        bodies: vec![],
    });
    let message = "private caution text must use the exact status token and a family style";
    let private_issue = |p: &Profile| {
        p.validate(BuildMode::Marker)
            .issues
            .iter()
            .any(|i| i.field == "menu.private_text" && i.message == message)
    };
    set_slot(&mut profile, base + 65);
    assert!(!slot_issue(&profile));
    assert!(!private_issue(&profile));
    for slot in [249, base + 64, base + 66, base + 68] {
        let mut bad = profile.clone();
        set_slot(&mut bad, slot);
        assert!(slot_issue(&bad), "private slot {slot:#x}");
        assert!(private_issue(&bad), "private slot {slot:#x}");
    }
    let mut bad = profile.clone();
    bad.menu
        .page
        .as_mut()
        .unwrap()
        .caution
        .as_mut()
        .unwrap()
        .text_format = 5;
    assert!(private_issue(&bad));
}
