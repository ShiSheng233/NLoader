//! End-to-end menu package verification. The build compiles the menu data,
//! links it, applies every patch and repacks; this test then UNPACKS the
//! final package and derives every expectation from the stock payload and
//! the profile spec — never from the build's own patch manifest. A patch
//! manifest that named the wrong site would still match its own edits; a
//! search for the expected bytes in the final image cannot.

use nloader_build::{build, BuildRequest, BuildSource};
use nloader_firmware::{crc16, FirmwareIdentity, KeyFile};
use nloader_profile::BuildMode;
use nloader_profile::{
    sha256, FileOperations, Memory, MemorySegment, MemorySegmentKind, Menu, MenuEntrySpec,
    MenuItemRef, MenuOwnPage, MenuPage, MenuRecordSizes, MenuTextPlatform, Profile,
    ServiceFingerprint, Slack,
};
use sha1::{Digest, Sha1};
use std::fs;

const XIP_BASE: u64 = 0x1000;
const RAM_BASE: u64 = 0x2000_0000;
const ITEMS_OFF: u64 = 0x200;
const POINTERS_OFF: u64 = ITEMS_OFF + 44 * 0x2c; /* 0x8f0 */
const TABLE_OFF: u64 = POINTERS_OFF + 44 * 8; /* 0xa10 */
const LAYOUT_OFF: u64 = TABLE_OFF + 7 * 0x20; /* 0xaf0 */
const CALL_OFF: u64 = LAYOUT_OFF + 48; /* 0xb20 */
const MODULE_SIZE: usize = 0x20400;
const RAM_FILE_OFF: usize = 0x20000;
/* The NLoader page's templates (XIP) and its window-table slots (RAM). */
const PAGE_ITEM_OFF: u64 = 0x0e00;
const PAGE_TABLE_OFF: u64 = 0x0ec0;
const PAGE_ELEMENT_OFF: u64 = 0x1000;
const ROW_TEMPLATE_OFF: u64 = 0x1200;
/* The template's page-specific handler block in the RAM mirror; only its
 * footer handler may reach the NLoader page's generated block. */
const TEMPLATE_HANDLERS_OFF: usize = 0x300;
const FOOTER_HANDLER: u64 = XIP_BASE + 0x220;
/* File wrappers (name, address, request operation). */
const FILE_WRAPPERS: [(&str, u64, u32); 4] = [
    ("fs_open", XIP_BASE + 0x1d8, 4),
    ("fs_read", XIP_BASE + 0x1e0, 7),
    ("fs_seek", XIP_BASE + 0x1e8, 9),
    ("fs_close", XIP_BASE + 0x1f0, 5),
];

/* MOVZ W9, #op ; STR W9, [SP, #0x114] */
fn file_wrapper(op: u32) -> Vec<u8> {
    [0x5280_0009u32 | (op << 5), 0xb901_17e9]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
}

/* The stock title chain and the visibility setter it ends with. */
const TITLE_CHAIN_OFF: usize = 0x1400;
const WIDGET_SHOW: u64 = XIP_BASE + 0x1c0;

fn title_chain_bytes(at: u64) -> Vec<u8> {
    let bl = |pc: u64, target: u64| {
        0x9400_0000u32 | (((target as i64 - pc as i64) / 4) as u32 & 0x03ff_ffff)
    };
    let mut words = vec![0x9100_6273u32, 0x3200_07e2];
    for (index, target) in [
        XIP_BASE + 0x180,
        XIP_BASE + 0x160,
        XIP_BASE + 0x1a0,
        WIDGET_SHOW,
    ]
    .into_iter()
    .enumerate()
    {
        words.push(bl(at + 8 + index as u64 * 4, target));
    }
    words.into_iter().flat_map(u32::to_le_bytes).collect()
}
const TEMPLATE_WINDOW_OFF: usize = 2 * 0x60;
const OWN_WINDOW_OFF: usize = 3 * 0x60;
const OWN_PAGE_OFF: usize = 4 * 0x60;
const TEMPLATE_PAGE_OFF: usize = 6 * 0x60;
const OWN_TEMPLATE_WINDOW: u32 = 2;
const OWN_WINDOW_ID: u32 = 3;
/* The list's first row: 64 consecutive unused ids from here, and the first
 * of the 64 row slots (251-296, then 232-249). */
const OWN_ITEM_ID: u32 = 0x7f80;
const OWN_ITEM_FLAGS: u32 = 0x10_1240;
const OWN_ITEM_SLOT: u32 = 251;
const SLACK_START: usize = 0x4000;
const LINK_BASE: u64 = XIP_BASE + SLACK_START as u64;
const ANCHOR_INDEX: u32 = 42;
const ANCHOR_ID: u32 = 0x22a;
const ENTRY_ID: u32 = 0x2f9;
const ENTRY_FLAGS: u32 = 0x101_24d;
const ACTIVATION_CODES: [u32; 4] = [0x286, 0x28b, 0x29f, 0x2ae];

fn record_bytes(index: u32) -> Vec<u8> {
    let mut record = vec![index as u8; 0x2c];
    record[0..4].copy_from_slice(&index.to_le_bytes());
    record[0x10..0x14].copy_from_slice(&(0x100 + index).to_le_bytes());
    record[0x18..0x1c].copy_from_slice(&(0x200 + index).to_le_bytes());
    record
}

fn element(kind: u32, resource: u32, control: u32) -> Vec<u8> {
    let mut record = vec![0x11u8 ^ kind as u8; 0x44];
    u32_into(&mut record, 0, resource);
    u32_into(&mut record, 4, kind);
    u32_into(&mut record, 0x38, control);
    record
}

/* A stock list page's title bar: fill, the title string, an icon, end. */
fn template_elements() -> Vec<u8> {
    [
        element(6, 0, 0x3),
        element(1, 1085, 0x15ad),
        element(4, 933, 0x6),
        vec![0u8; 0x44],
    ]
    .concat()
}

fn table_record(code: u32) -> Vec<u8> {
    let mut record = vec![(code as u8) ^ 0x5a; 0x20];
    record[0..4].copy_from_slice(&code.to_le_bytes());
    record
}

/* The stock row table NLoader's page row reuses: a back record, the three
 * open codes of an information page (each returning one level through the
 * stock stub, unguarded) and the terminator. The filler words make each
 * record unique in the blob. */
const PAGE_ROW_CODES: [u32; 7] = [0x285, 0x286, 0x28b, 0x2ae, 0x2a0, 0x306, 0x3bb];
const STOCK_STUB: u64 = XIP_BASE + 0x200;

fn page_row_record(code: u32) -> Vec<u8> {
    let mut record = vec![0u8; 0x20];
    u32_into(&mut record, 0, code);
    u32_into(&mut record, 4, 0xa500 + code);
    u64_into(
        &mut record,
        8,
        if code == 0x3bb || [0x285, 0x2a0, 0x306].contains(&code) {
            0
        } else {
            STOCK_STUB
        },
    );
    u32_into(&mut record, 0x18, if code == 0x3bb { 0x68c } else { 0x68d });
    u32_into(&mut record, 0x1c, 0x5a00 + code);
    record
}

fn find(haystack: &[u8], needle: &[u8], what: &str) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap_or_else(|| panic!("{what} not found in the linked blob"))
}

#[test]
#[ignore = "requires clang with AArch64 code generation"]
fn complete_menu_package_matches_independently_derived_content() {
    let directory = tempfile::tempdir().unwrap();

    // ---- stock module with menu structures --------------------------------
    let mut payload = vec![0u8; MODULE_SIZE];
    for index in 0..44u32 {
        let start = ITEMS_OFF as usize + index as usize * 0x2c;
        payload[start..start + 0x2c].copy_from_slice(&record_bytes(index));
    }
    let mut stock_pointers = Vec::new();
    for index in 0..44u32 {
        let pointer = if index == ANCHOR_INDEX {
            XIP_BASE + TABLE_OFF
        } else {
            0x5000_0000 + u64::from(index) * 8
        };
        stock_pointers.extend_from_slice(&pointer.to_le_bytes());
    }
    let pointers_start = POINTERS_OFF as usize;
    payload[pointers_start..pointers_start + stock_pointers.len()].copy_from_slice(&stock_pointers);
    let codes = [0x100u32, 0x286, 0x28b, 0x29f, 0x2ae, 0x101, 0x3bb];
    for (position, code) in codes.iter().enumerate() {
        let start = TABLE_OFF as usize + position * 0x20;
        payload[start..start + 0x20].copy_from_slice(&table_record(*code));
    }
    let mut layout = vec![0x71u8; 48];
    u32_into(&mut layout, 0, 0x5151); /* the page links this as a u16 */
    payload[LAYOUT_OFF as usize..LAYOUT_OFF as usize + 48].copy_from_slice(&layout);
    /* the page record links the layout's first u16, zero-extended, at +0x48 */
    let site = XIP_BASE + CALL_OFF;
    let return_target = XIP_BASE + 0x1800;
    let delta = ((return_target as i64 - site as i64) / 4) as u32;
    payload[CALL_OFF as usize..CALL_OFF as usize + 4]
        .copy_from_slice(&(0x9400_0000u32 | (delta & 0x03ff_ffff)).to_le_bytes());
    // A stock title chain for the NLoader page to follow: container at
    // +0x18, format 3 via ORR, then lookup, store, bind and show.
    let title_chain = title_chain_bytes(XIP_BASE + TITLE_CHAIN_OFF as u64);
    payload[TITLE_CHAIN_OFF..TITLE_CHAIN_OFF + title_chain.len()].copy_from_slice(&title_chain);
    // The file wrappers: each stores its request operation the way the
    // stock ones do, after the other services' fingerprint windows.
    for (_, address, op) in FILE_WRAPPERS {
        let start = (address - XIP_BASE) as usize;
        payload[start..start + 8].copy_from_slice(&file_wrapper(op));
    }

    // The NLoader page's templates: a stock information page with one row,
    // its row event table, and the parent row table that opens it.
    let template_item = {
        let mut item = vec![0x77u8; 0x2c];
        u32_into(&mut item, 0, 0);
        u32_into(&mut item, 0x10, 0x400);
        u32_into(&mut item, 0x18, 0x38c3);
        item
    };
    for row in 0..3 {
        let start = PAGE_ITEM_OFF as usize + row * 0x2c;
        payload[start..start + 0x2c].copy_from_slice(&template_item);
    }
    payload[PAGE_ELEMENT_OFF as usize..PAGE_ELEMENT_OFF as usize + 4 * 0x44]
        .copy_from_slice(&template_elements());
    let stock_page_table: Vec<u8> = PAGE_ROW_CODES
        .iter()
        .flat_map(|code| page_row_record(*code))
        .collect();
    payload[PAGE_TABLE_OFF as usize..PAGE_TABLE_OFF as usize + stock_page_table.len()]
        .copy_from_slice(&stock_page_table);
    for (position, code) in codes.iter().enumerate() {
        let mut record = table_record(*code);
        if ACTIVATION_CODES.contains(code) {
            u64_into(&mut record, 8, XIP_BASE + 0x200); /* the stock stub */
            u32_into(&mut record, 0x18, OWN_TEMPLATE_WINDOW);
        }
        let start = ROW_TEMPLATE_OFF as usize + position * 0x20;
        payload[start..start + 0x20].copy_from_slice(&record);
    }

    // RAM mirror: the window record points at the page record; the page
    // record carries the pointer pair, the count and the layout link.
    let mut ram = vec![0u8; 0x400];
    let window_off = 0x00usize;
    let page_off = 0x60usize;
    u16_into(&mut ram, window_off + 2, 0); /* window id */
    u64_into(&mut ram, window_off + 0x50, RAM_BASE + page_off as u64);
    u16_into(&mut ram, page_off + 2, 0); /* the page's own window id field */
    u64_into(&mut ram, page_off + 0x10, XIP_BASE + ITEMS_OFF);
    u64_into(&mut ram, page_off + 0x18, XIP_BASE + POINTERS_OFF);
    u16_into(&mut ram, page_off + 0x20, 44);
    u64_into(&mut ram, page_off + 0x40, XIP_BASE + LAYOUT_OFF);
    u32_into(&mut ram, page_off + 0x48, 0x5151);
    // The page's templates and holes in the same window table: window 2 is
    // the information page to clone, 3 and 4 are untouched all-zero slots.
    u16_into(&mut ram, TEMPLATE_WINDOW_OFF, 2); /* kind */
    u16_into(
        &mut ram,
        TEMPLATE_WINDOW_OFF + 2,
        OWN_TEMPLATE_WINDOW as u16,
    );
    u64_into(
        &mut ram,
        TEMPLATE_WINDOW_OFF + 0x28,
        RAM_BASE + TEMPLATE_HANDLERS_OFF as u64,
    );
    for (slot, handler) in [0x51u64, 0x52, FOOTER_HANDLER, 0x53, 0x54]
        .into_iter()
        .enumerate()
    {
        u64_into(&mut ram, TEMPLATE_HANDLERS_OFF + slot * 8, handler);
    }
    u32_into(&mut ram, TEMPLATE_PAGE_OFF, 0x8000_1008); /* list page */
    u64_into(
        &mut ram,
        TEMPLATE_WINDOW_OFF + 0x50,
        RAM_BASE + TEMPLATE_PAGE_OFF as u64,
    );
    u64_into(
        &mut ram,
        TEMPLATE_PAGE_OFF + 0x08,
        XIP_BASE + PAGE_ELEMENT_OFF,
    );
    u64_into(&mut ram, TEMPLATE_PAGE_OFF + 0x10, XIP_BASE + PAGE_ITEM_OFF);
    u64_into(
        &mut ram,
        TEMPLATE_PAGE_OFF + 0x18,
        XIP_BASE + PAGE_TABLE_OFF,
    );
    u16_into(&mut ram, TEMPLATE_PAGE_OFF + 0x20, 3);
    u16_into(&mut ram, TEMPLATE_PAGE_OFF + 0x28, 424);
    u16_into(&mut ram, TEMPLATE_PAGE_OFF + 0x30, 424);
    u64_into(&mut ram, TEMPLATE_PAGE_OFF + 0x40, XIP_BASE + LAYOUT_OFF);
    payload[RAM_FILE_OFF..RAM_FILE_OFF + ram.len()].copy_from_slice(&ram);

    let (events, navigation) = menu_events(XIP_BASE + 0x1800);
    payload[0x1800..0x1800 + navigation.len()].copy_from_slice(&navigation);

    // ---- package container ------------------------------------------------
    let mut body = vec![0; 80];
    body[..32].fill(b' ');
    body[32..36].copy_from_slice(&1_u32.to_be_bytes());
    body[36..40].copy_from_slice(&80_u32.to_be_bytes());
    let name = "eg2070_test.bi";
    body[48..48 + name.len()].copy_from_slice(name.as_bytes());
    body[64..68].copy_from_slice(&80_u32.to_be_bytes());
    body[68..72].copy_from_slice(&((payload.len() + 2) as u32).to_be_bytes());
    body.extend(&payload);
    body.extend(crc16(&payload).to_be_bytes());
    body.extend(crc16(&body).to_be_bytes());
    body.extend([0; 14]);
    let mut digest = Sha1::new_with_prefix(&body);
    digest.update([0; 8]);
    let mut stock = digest.finalize().to_vec();
    stock.extend([0; 12]);
    stock.extend(body);
    let keys = serde_json::json!({"schema":1,"materials":{"legacy-xor":{
        "t1":"00".repeat(256),"t2":"00".repeat(256),"t3":"00".repeat(256),
        "self_check":{"t1":sha256(&[0;256]),"t2":sha256(&[0;256]),"t3":sha256(&[0;256])}
    }},"keys":[{"scheme":"legacy-xor","model":"Z8","firmware":["3.11"],
        "firmware_sha256":{"3.11":sha256(&stock)},"k8":"00".repeat(8),
        "self_check":{"k8":sha256(&[0;8])}}]});

    let mut profile = Profile::draft("Z8", "3.11");
    profile.storage.root = Some("B:\\NLOADER\\".into());
    profile.abi.ui = Some(nloader_profile::UiFamily::Z8MenuV1);
    profile.abi.task = Some(nloader_profile::TaskFamily::Z8WorkerV1);
    profile.abi.fs = Some(nloader_profile::FsFamily::Z8FileV1);
    profile.abi.mem = Some(nloader_profile::MemFamily::Z8HeapV1);
    profile.identity.container = Some(nloader_profile::ContainerKind::LegacyXor);
    profile.identity.stock_pkg = Some("synthetic.bin".into());
    profile.identity.eg_module = Some(name.into());
    profile.checks.package_sha256 = Some(sha256(&stock));
    profile.checks.module_sha256 = Some(sha256(&payload));
    profile.memory = Memory {
        xip_base: Some(XIP_BASE),
        module_size: Some(payload.len() as u64),
        segments: vec![
            MemorySegment {
                file_offset: 0,
                runtime_start: XIP_BASE,
                size: RAM_FILE_OFF as u64,
                kind: MemorySegmentKind::Xip,
            },
            MemorySegment {
                file_offset: RAM_FILE_OFF as u64,
                runtime_start: RAM_BASE,
                size: ram.len() as u64,
                kind: MemorySegmentKind::Ram,
            },
        ],
        slack: Some(Slack {
            start: SLACK_START as u64,
            end: XIP_BASE + RAM_FILE_OFF as u64,
            require_zero: true,
        }),
        link_base: Some(LINK_BASE),
        link_size: Some((RAM_FILE_OFF - SLACK_START) as u64),
        ram_pool: None,
        program_budget_blocks: None,
        program_max_resident: None,
        program_arena_bytes: None,
    };
    for (name, base) in [
        ("dcache_inv_pre", 4368u64),
        ("dcache_inv_post", 4372),
        ("worker_init", 4376),
        ("worker_start", 4380),
        ("flag_set", 4384),
        ("registry_lookup", 4388),
        ("mem_alloc", 4392),
        ("mem_free", 4396),
    ] {
        match name {
            "dcache_inv_pre" => profile.services.dcache_inv_pre = Some(base),
            "dcache_inv_post" => profile.services.dcache_inv_post = Some(base),
            "worker_init" => profile.services.worker_init = Some(base),
            "worker_start" => profile.services.worker_start = Some(base),
            "flag_set" => profile.services.flag_set = Some(base),
            "registry_lookup" => profile.services.registry_lookup = Some(base),
            "mem_alloc" => profile.services.mem_alloc = Some(base),
            _ => profile.services.mem_free = Some(base),
        }
        profile.service_fingerprints.insert(
            name.into(),
            ServiceFingerprint {
                eg_off: base - XIP_BASE,
                stock: vec![0; 24],
            },
        );
    }
    for (name, address, op) in FILE_WRAPPERS {
        match name {
            "fs_open" => profile.services.fs_open = Some(address),
            "fs_read" => profile.services.fs_read = Some(address),
            "fs_seek" => profile.services.fs_seek = Some(address),
            _ => profile.services.fs_close = Some(address),
        }
        profile.service_fingerprints.insert(
            name.into(),
            ServiceFingerprint {
                eg_off: address - XIP_BASE,
                stock: file_wrapper(op),
            },
        );
    }
    profile.services.file_ops = FileOperations {
        op_slot: Some(0x114),
        open: Some(4),
        read: Some(7),
        seek: Some(9),
        close: Some(5),
        write: None,
        open_read_write: None,
        open_write_create: None,
        create_attributes: None,
    };
    profile.task.core = Some(3);
    profile.task.priority = Some(20);
    profile.task.stack = Some(0x8000);
    profile.task.name = Some("NLOADER".into());
    profile.menu = Menu {
        private_text: None,
        events: Some(events),
        window_table: Some(RAM_BASE),
        record_sizes: Some(MenuRecordSizes {
            window: 96,
            page: 80,
            item: 44,
            event: 32,
        }),
        page: Some(MenuOwnPage {
            refresh: None,
            window_id: OWN_WINDOW_ID,
            page_record: RAM_BASE + OWN_PAGE_OFF as u64,
            template_window: OWN_TEMPLATE_WINDOW,
            template_page: RAM_BASE + TEMPLATE_PAGE_OFF as u64,
            row_event_table: XIP_BASE + PAGE_TABLE_OFF,
            row_template_event_table: XIP_BASE + ROW_TEMPLATE_OFF,
            title_slot: 297,
            title_format: 3,
            item_id: OWN_ITEM_ID,
            item_flags: OWN_ITEM_FLAGS,
            item_slot: OWN_ITEM_SLOT,
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
        }),
        setup: Some(MenuPage {
            window_id: 0,
            page_address: RAM_BASE + page_off as u64,
            items: XIP_BASE + ITEMS_OFF,
            item_count: 44,
            event_table: XIP_BASE + POINTERS_OFF,
            layout: XIP_BASE + LAYOUT_OFF,
            firmware_version: Some(MenuItemRef {
                index: ANCHOR_INDEX,
                item_id: ANCHOR_ID,
            }),
            entry: Some(MenuEntrySpec {
                index: ANCHOR_INDEX,
                item_id: ENTRY_ID,
                flags: ENTRY_FLAGS,
            }),
            apps: None,
            cursor: None,
        }),
        text_platform: Some(MenuTextPlatform {
            descriptor_base: 0x1000_a000,
            slot_stride: 0x18,
            buffer_base: 0x1100_b000,
            buffer_stride: 0x20,
            font_cache_base: 0x1200_c000,
            font_record_base: 0x1300_d000,
            entry_slot: 299,
            entry_style: 4,
            entry_text: "NLoader".into(),
            prefill_call_site: site,
            prefill_return: return_target,
        }),
    };
    profile.updater.bump_version = false;
    let text_store = XIP_BASE + 0x160;
    profile.ui.text_store = Some(text_store);
    profile.ui.widget_find = Some(XIP_BASE + 0x180);
    profile.ui.text_bind = Some(XIP_BASE + 0x1a0);
    profile.ui.widget_show = Some(WIDGET_SHOW);
    profile.ui.title_chain = Some(ServiceFingerprint {
        eg_off: TITLE_CHAIN_OFF as u64,
        stock: title_chain.clone(),
    });
    profile.ui.widget_container_offset = Some(0x18);
    for (name, eg_off) in [
        ("text_store", 0x160u64),
        ("widget_find", 0x180),
        ("text_bind", 0x1a0),
        ("widget_show", 0x1c0),
    ] {
        profile.service_fingerprints.insert(
            name.into(),
            ServiceFingerprint {
                eg_off,
                stock: payload[eg_off as usize..eg_off as usize + 0x18].to_vec(),
            },
        );
    }

    let firmware = directory.path().join("synthetic.bin");
    let key_file = directory.path().join("keys.json");
    let package = || BuildSource::Package {
        firmware: firmware.clone(),
        key_file: key_file.clone(),
    };
    let request = BuildRequest {
        profile: directory.path().join("profile.toml"),
        source: package(),
        compiler: "clang".into(),
        mode: BuildMode::LoadOnly,
        output: directory.path().join("result.bin"),
        bundle: None,
    };
    fs::write(&firmware, &stock).unwrap();
    fs::write(&key_file, serde_json::to_vec(&keys).unwrap()).unwrap();
    fs::write(&request.profile, profile.to_toml().unwrap()).unwrap();

    // A complete card-reading request never falls back to a drive when its
    // root is omitted. Refuse it before an unavailable compiler can run.
    let mut missing_root = profile.clone();
    missing_root.storage.root = None;
    let missing_profile = directory.path().join("missing-storage.toml");
    fs::write(&missing_profile, missing_root.to_toml().unwrap()).unwrap();
    for mode in [BuildMode::LoadOnly, BuildMode::PrepareOnly, BuildMode::Exec] {
        let rejected = BuildRequest {
            profile: missing_profile.clone(),
            source: package(),
            compiler: "nloader-no-such-compiler".into(),
            mode,
            output: directory.path().join(format!("missing-storage-{mode}.bin")),
            bundle: None,
        };
        match build(&rejected) {
            Err(nloader_build::Error::Validation(report)) => assert!(
                report.issues.iter().any(|issue| {
                    issue.field == "storage.root"
                        && issue.kind == nloader_profile::IssueKind::Missing
                }),
                "{mode}: {report:?}",
            ),
            other => panic!("{mode}: expected a missing root refusal, got {other:?}"),
        }
        for path in [
            rejected.output.clone(),
            rejected.output.with_extension("patch.json"),
            rejected.output.with_extension("build.json"),
        ] {
            assert!(!path.exists(), "{}", path.display());
        }
    }

    for mode in [BuildMode::HookOnly, BuildMode::LoadOnly] {
        let mut missing_writer = profile.clone();
        missing_writer.ui.text_store = None;
        assert!(missing_writer
            .validate(mode)
            .issues
            .iter()
            .any(|issue| issue.field == "ui.text_store"
                && issue.kind == nloader_profile::IssueKind::Missing));
        let mut missing_fingerprint = profile.clone();
        missing_fingerprint
            .service_fingerprints
            .remove("text_store");
        assert!(missing_fingerprint
            .validate(mode)
            .issues
            .iter()
            .any(|issue| issue.field == "service_fingerprints.text_store"
                && issue.kind == nloader_profile::IssueKind::Missing));
    }

    /* One row is all the lower rungs show, but from load-only on the page
     * is the program list: without its rows the details could never be
     * drawn, so such a profile is refused and nothing is published. */
    for mode in [BuildMode::LoadOnly, BuildMode::PrepareOnly, BuildMode::Exec] {
        assert!(
            profile.validate(mode).issues.iter().any(|issue| {
                issue.field == "menu.page.row_slots"
                    && issue.kind == nloader_profile::IssueKind::Missing
            }),
            "{mode} must require the list rows"
        );
    }
    assert!(
        build(&request).is_err(),
        "one-row load-only must be refused"
    );
    assert!(!request.output.exists());
    let list = profile.menu.page.as_mut().unwrap();
    list.row_slots = (251..=296).chain(232..=249).collect();
    list.row_hide = Some(WIDGET_SHOW);
    list.row_hide_stock =
        payload[(WIDGET_SHOW - XIP_BASE) as usize..(WIDGET_SHOW - XIP_BASE) as usize + 16].to_vec();
    list.viewport_bottom = Some(480);
    fs::write(&request.profile, profile.to_toml().unwrap()).unwrap();

    /* The stock relations the profile validation demands, spelled out so a
     * mismatch names its field instead of failing the whole page. */
    let u16_at = |bytes: &[u8], offset: usize| {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    };
    let u32_at = |bytes: &[u8], offset: usize| {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    };
    let u64_at = |bytes: &[u8], offset: usize| {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    };
    let window_record = &ram[window_off..window_off + 96];
    let page_record = &ram[page_off..page_off + 80];
    assert_eq!(u16_at(window_record, 2), 0, "window id");
    assert_eq!(
        u64_at(window_record, 0x50),
        RAM_BASE + page_off as u64,
        "window points at the page"
    );
    assert_eq!(u16_at(page_record, 0x20), 44, "page count");
    assert_eq!(
        u64_at(page_record, 0x10),
        XIP_BASE + ITEMS_OFF,
        "page items"
    );
    assert_eq!(
        u64_at(page_record, 0x18),
        XIP_BASE + POINTERS_OFF,
        "page pointers"
    );
    assert_eq!(
        u64_at(page_record, 0x40),
        XIP_BASE + LAYOUT_OFF,
        "page layout"
    );
    let layout_record = &payload[LAYOUT_OFF as usize..LAYOUT_OFF as usize + 48];
    assert_eq!(
        u32_at(page_record, 0x48),
        u32::from(u16_at(layout_record, 0)),
        "page links the layout's first u16, zero-extended"
    );
    let anchor_item = ITEMS_OFF as usize + ANCHOR_INDEX as usize * 0x2c;
    assert_eq!(
        u32_at(&payload[anchor_item..anchor_item + 0x2c], 0x18),
        ANCHOR_ID,
        "anchor item id"
    );

    let report = build(&request).expect("menu package build");
    assert!(report.installable);

    // ---- independent verification ----------------------------------------
    let key = KeyFile::load(&key_file)
        .unwrap()
        .for_identity(&FirmwareIdentity {
            model: "Z8".into(),
            firmware: "3.11".into(),
        })
        .unwrap();
    let image = key.unpack(&fs::read(&request.output).unwrap()).unwrap();
    let module = image.payload(name).unwrap();

    /* Expectations derived from the STOCK payload, never from the build. */
    let mut expected_items: Vec<u8> = Vec::new();
    for index in 0..44u32 {
        if index == ANCHOR_INDEX {
            let mut new = record_bytes(ANCHOR_INDEX);
            new[0..4].copy_from_slice(&299u32.to_le_bytes());
            new[0x10..0x14].copy_from_slice(&ENTRY_FLAGS.to_le_bytes());
            new[0x18..0x1c].copy_from_slice(&ENTRY_ID.to_le_bytes());
            expected_items.extend_from_slice(&new);
        }
        expected_items.extend_from_slice(&record_bytes(index));
    }
    let mut expected_pointers = Vec::new();
    expected_pointers.extend_from_slice(&stock_pointers[..42 * 8]);
    expected_pointers.extend_from_slice(&[0; 8]);
    expected_pointers.extend_from_slice(&stock_pointers[42 * 8..]);

    let blob = &module[SLACK_START..RAM_FILE_OFF];
    /* Load-only reads the card from the page: the texts the row shows for
     * the directory's outcomes are part of the linked blob. */
    for text in [
        &b"DISABLED (SAFE_MODE)\0"[..],
        b"Cannot read MANIFEST\0",
        b"CRC mismatch\0",
    ] {
        find(blob, text, "card outcome text");
    }
    let items_found = find(blob, &expected_items[..0x80], "item records") as u64;
    let items_va = LINK_BASE + items_found;
    let pointers_found = find(blob, &expected_pointers[..0x80], "event pointer array") as u64;
    let pointers_va = LINK_BASE + pointers_found;

    /* Alignment as the generated declarations request it. */
    assert_eq!(items_va % 4, 0, "items must be 4-byte aligned");
    assert_eq!(pointers_va % 8, 0, "pointers must be 8-byte aligned");

    /* The full arrays really sit at the found addresses. The pointer
     * array's entry slot no longer holds the generated zero placeholder:
     * the build filled it with the row table's address after linking, so
     * the stock halves are compared separately and the slot is checked
     * against the table the search finds below. */
    assert_eq!(
        &blob[items_found as usize..items_found as usize + expected_items.len()],
        &expected_items[..]
    );
    let pointers_at = pointers_found as usize;
    assert_eq!(
        &blob[pointers_at..pointers_at + 42 * 8],
        &expected_pointers[..42 * 8]
    );
    assert_eq!(
        &blob[pointers_at + 43 * 8..pointers_at + expected_pointers.len()],
        &expected_pointers[43 * 8..]
    );

    /* The entry row's placeholder now carries the row table's address, and
     * the table sits at that address: with a page of our own declared it is
     * the stock table with the open records retargeted at our window. */
    let slot = pointers_found as usize + 42 * 8;
    let row_table_va = u64::from_le_bytes(blob[slot..slot + 8].try_into().expect("8 bytes"));
    assert!(row_table_va >= LINK_BASE && row_table_va < LINK_BASE + blob.len() as u64);
    assert_eq!(row_table_va % 8, 0, "the row table must be 8-byte aligned");
    let table_found = find(blob, &table_record(0x100), "row table") as u64;
    assert_eq!(LINK_BASE + table_found, row_table_va);
    let expected_table: Vec<u8> = codes
        .iter()
        .flat_map(|code| {
            let mut record = table_record(*code);
            if ACTIVATION_CODES.contains(code) {
                u64_into(&mut record, 8, XIP_BASE + 0x200);
                u32_into(&mut record, 0x18, OWN_WINDOW_ID);
            }
            record
        })
        .collect();
    assert_eq!(
        &blob[table_found as usize..table_found as usize + expected_table.len()],
        &expected_table[..]
    );

    /* The page record points at the new arrays with count 45; every other
     * byte of the record survives unchanged. */
    let mut expected_page = ram[page_off..page_off + 80].to_vec();
    u64_into(&mut expected_page, 0x10, items_va);
    u64_into(&mut expected_page, 0x18, pointers_va);
    u16_into(&mut expected_page, 0x20, 45);
    let final_page = &module[RAM_FILE_OFF + page_off..RAM_FILE_OFF + page_off + 80];
    assert_eq!(final_page, &expected_page[..]);

    /* The Setup window record is untouched. */
    assert_eq!(&module[RAM_FILE_OFF..RAM_FILE_OFF + 96], &ram[..96]);

    /* NLoader's own page. Its first row is the template row with the first
     * list slot, our flags and the first list id; it is found in the blob
     * by searching for it, not by reading the build's own report. */
    let mut expected_row = template_item.clone();
    u32_into(&mut expected_row, 0, OWN_ITEM_SLOT);
    u32_into(&mut expected_row, 0x10, OWN_ITEM_FLAGS);
    u32_into(&mut expected_row, 0x18, OWN_ITEM_ID);
    let row_found = find(blob, &expected_row, "page row record") as u64;
    let page_items_va = XIP_BASE + SLACK_START as u64 + row_found;
    /* Its event table is the stock row table cloned: the terminator byte
     * for byte, the open records re-entering the page (0x696) and running
     * one function inside the blob, the back record (stock action empty)
     * running another one and still returning one level. */
    let back = page_row_record(0x285);
    let row_table_found = find(blob, &back[..8], "page row table");
    let row_table_va = LINK_BASE + row_table_found as u64;
    assert_eq!(row_table_va % 8, 0, "event records are read as u64");
    let row_table = &blob[row_table_found..row_table_found + stock_page_table.len()];
    let mut row_action = None;
    let mut back_action = None;
    for (record, code) in row_table.chunks(0x20).zip(PAGE_ROW_CODES) {
        let stock = page_row_record(code);
        if [0x285, 0x2a0, 0x306].contains(&code) {
            let action = u64::from_le_bytes(record[8..16].try_into().unwrap());
            assert!(
                action >= LINK_BASE && action < LINK_BASE + blob.len() as u64 && action % 4 == 0,
                "back record must run code in the blob: {action:#x}"
            );
            back_action = Some(action);
            assert_eq!(&record[..8], &stock[..8]);
            assert_eq!(&record[16..], &stock[16..], "back keeps guard and target");
        } else if ACTIVATION_CODES.contains(&code) {
            let action = u64::from_le_bytes(record[8..16].try_into().unwrap());
            assert!(
                action >= LINK_BASE && action < LINK_BASE + blob.len() as u64 && action % 4 == 0,
                "open record {code:#x} must run code in the blob: {action:#x}"
            );
            assert_eq!(*row_action.get_or_insert(action), action);
            assert_eq!(&record[..8], &stock[..8]);
            assert_eq!(&record[16..0x18], &stock[16..0x18], "no guard");
            assert_eq!(&record[0x18..0x1c], &0x696u32.to_le_bytes(), "re-enters");
            assert_eq!(&record[0x1c..], &stock[0x1c..]);
        } else {
            assert_eq!(record, stock.as_slice(), "record {code:#x} must be stock");
        }
    }
    assert_ne!(back_action, row_action, "back and OK are two functions");
    /* The page's event pointer array names that table once per list row. */
    let pointers_found = find(
        blob,
        &row_table_va.to_le_bytes().repeat(64),
        "page event pointers",
    ) as u64;
    let page_pointers_va = XIP_BASE + SLACK_START as u64 + pointers_found;
    find(blob, b"NLoader page\0", "page row text");
    /* The title bar: the template's elements with the title string turned
     * into runtime text reading the title's own slot (297). */
    let mut expected_elements = template_elements();
    u32_into(&mut expected_elements, 0x44, 297);
    u32_into(&mut expected_elements, 0x48, 2);
    let elements_found = find(blob, &expected_elements, "page title bar") as u64;
    let page_elements_va = XIP_BASE + SLACK_START as u64 + elements_found;
    assert_eq!(page_elements_va % 4, 0, "element records are read as u32");

    /* The generated handler block: slot 0 is a function inside the blob
     * (the page entry), slot 2 the template's footer handler, the rest
     * empty. Found by searching for the slots 1..4 built here. */
    let mut handler_tail = vec![0u8; 8];
    handler_tail.extend_from_slice(&FOOTER_HANDLER.to_le_bytes());
    handler_tail.extend_from_slice(&[0u8; 16]);
    let tail_found = find(blob, &handler_tail, "page handler block");
    assert!(tail_found >= 8);
    let handlers_va = XIP_BASE + SLACK_START as u64 + tail_found as u64 - 8;
    assert_eq!(handlers_va % 8, 0, "handler slots are read as u64");
    let entry = u64::from_le_bytes(blob[tail_found - 8..tail_found].try_into().unwrap());
    assert!(
        entry >= LINK_BASE && entry < LINK_BASE + blob.len() as u64 && entry % 4 == 0,
        "slot 0 must be code in the blob, not a stock handler: {entry:#x}"
    );
    assert_ne!(
        Some(entry),
        row_action,
        "entry and row action are two functions"
    );
    /* The page entry's table: the title element's control id, the title's
     * slot and format, the row's id, slot and style, the container offset;
     * then pointers to the entry text and the row's label and the profile's
     * lookup, store, bind and show functions. */
    let mut page_table = Vec::new();
    for word in [0x15ad_u32, 297, 3, OWN_ITEM_ID, OWN_ITEM_SLOT, 4, 0x18, 0] {
        page_table.extend_from_slice(&word.to_le_bytes());
    }
    let table_found = find(blob, &page_table, "page entry table");
    let field = |index: usize| {
        let start = table_found + 32 + index * 8;
        u64::from_le_bytes(blob[start..start + 8].try_into().unwrap())
    };
    let title_text = (field(0) - LINK_BASE) as usize;
    assert_eq!(&blob[title_text..title_text + 8], b"NLoader\0");
    /* Then the list: 64 rows, the selected-row offset, the stock row hide
     * function and the navigation code that enters the page again, which
     * is the value the open records above carry (0x696). */
    let word_at = |offset: usize| {
        u32::from_le_bytes(
            blob[table_found + offset..table_found + offset + 4]
                .try_into()
                .unwrap(),
        )
    };
    assert_eq!(word_at(80), 64, "row count");
    assert_eq!(word_at(96), 0x32, "selected offset");
    assert_eq!(field(9), WIDGET_SHOW, "row hide function");
    assert_eq!(word_at(112), 0x696, "re-enter code");
    let row_text = (field(1) - LINK_BASE) as usize;
    assert_eq!(&blob[row_text..row_text + 13], b"NLoader page\0");
    assert_eq!(
        [field(2), field(3), field(4), field(5)],
        [
            XIP_BASE + 0x180,
            XIP_BASE + 0x160,
            XIP_BASE + 0x1a0,
            WIDGET_SHOW
        ]
    );

    /* The window hole now holds the template window with our id, our page
     * record and the generated handler block; nothing else changed. */
    let mut expected_window = ram[TEMPLATE_WINDOW_OFF..TEMPLATE_WINDOW_OFF + 96].to_vec();
    u16_into(&mut expected_window, 2, OWN_WINDOW_ID as u16);
    u64_into(&mut expected_window, 0x28, handlers_va);
    u64_into(&mut expected_window, 0x50, RAM_BASE + OWN_PAGE_OFF as u64);
    assert_eq!(
        &module[RAM_FILE_OFF + OWN_WINDOW_OFF..RAM_FILE_OFF + OWN_WINDOW_OFF + 96],
        &expected_window[..]
    );
    /* The page hole holds the template page with the three array pointers
     * moved to the arrays found above, 64 rows and both viewport bottoms
     * at 480; flags, the other rectangle edges and layout stay the
     * template's. */
    let mut expected_own_page = ram[TEMPLATE_PAGE_OFF..TEMPLATE_PAGE_OFF + 80].to_vec();
    u64_into(&mut expected_own_page, 0x08, page_elements_va);
    u64_into(&mut expected_own_page, 0x10, page_items_va);
    u64_into(&mut expected_own_page, 0x18, page_pointers_va);
    u16_into(&mut expected_own_page, 0x20, 64);
    u16_into(&mut expected_own_page, 0x28, 480);
    u16_into(&mut expected_own_page, 0x30, 480);
    assert_eq!(
        &module[RAM_FILE_OFF + OWN_PAGE_OFF..RAM_FILE_OFF + OWN_PAGE_OFF + 80],
        &expected_own_page[..]
    );
    /* The templates themselves are untouched. */
    assert_eq!(
        &module[RAM_FILE_OFF + TEMPLATE_WINDOW_OFF..RAM_FILE_OFF + TEMPLATE_WINDOW_OFF + 96],
        &ram[TEMPLATE_WINDOW_OFF..TEMPLATE_WINDOW_OFF + 96]
    );
    assert_eq!(
        &module[RAM_FILE_OFF + TEMPLATE_PAGE_OFF..RAM_FILE_OFF + TEMPLATE_PAGE_OFF + 80],
        &ram[TEMPLATE_PAGE_OFF..TEMPLATE_PAGE_OFF + 80]
    );

    /* The prefill struct: its leading constants identify it (the u64 fields
     * need 4 bytes of zero padding after each u32, giving the layout the
     * static assert in menu.h pins: return_target at +0x48). The probe
     * covers the constants through the entry style. */
    let mut struct_probe = Vec::new();
    struct_probe.extend_from_slice(&0x1000_a000u64.to_le_bytes()); /* 0x00 */
    struct_probe.extend_from_slice(&0x18u32.to_le_bytes()); /* 0x08 */
    struct_probe.extend_from_slice(&[0; 4]); /* 0x0c pad */
    struct_probe.extend_from_slice(&0x1100_b000u64.to_le_bytes()); /* 0x10 */
    struct_probe.extend_from_slice(&0x20u32.to_le_bytes()); /* 0x18 */
    struct_probe.extend_from_slice(&[0; 4]); /* 0x1c pad */
    struct_probe.extend_from_slice(&0x1200_c000u64.to_le_bytes()); /* 0x20 */
    struct_probe.extend_from_slice(&0x1300_d000u64.to_le_bytes()); /* 0x28 */
    struct_probe.extend_from_slice(&299u32.to_le_bytes()); /* 0x30 */
    struct_probe.extend_from_slice(&4u32.to_le_bytes()); /* 0x34 */
    let struct_found = find(blob, &struct_probe, "prefill struct") as u64;
    let struct_va = LINK_BASE + struct_found;
    assert_eq!(struct_va % 8, 0, "the struct must be 8-byte aligned");
    /* With the alignment padding the layout ends text at +0x38, the call
     * site at +0x40 and the return target at +0x48 — the offset the
     * trampoline's static assert pins. */
    let call_site_value = u64::from_le_bytes(
        blob[struct_found as usize + 0x40..struct_found as usize + 0x48]
            .try_into()
            .expect("8 bytes"),
    );
    let return_value = u64::from_le_bytes(
        blob[struct_found as usize + 0x48..struct_found as usize + 0x50]
            .try_into()
            .expect("8 bytes"),
    );
    assert_eq!(call_site_value, site);
    assert_eq!(
        return_value, return_target,
        "the field at struct+0x48 must carry the configured return target"
    );
    assert_eq!(
        u64::from_le_bytes(
            blob[struct_found as usize + 0x50..struct_found as usize + 0x58]
                .try_into()
                .expect("8 bytes")
        ),
        text_store,
        "the menu must call the configured original text writer"
    );

    /* The retargeted branch must land inside the blob (the trampoline). */
    let word = u32::from_le_bytes(
        module[CALL_OFF as usize..CALL_OFF as usize + 4]
            .try_into()
            .expect("4 bytes"),
    );
    assert_eq!(word >> 26, 0b100101, "the site still holds a bl");
    let imm = (word & 0x03ff_ffff) as i32;
    let branch_target = site as i64 + ((imm << 6) >> 6) as i64 * 4;
    assert!(
        branch_target >= LINK_BASE as i64 && branch_target < (LINK_BASE + blob.len() as u64) as i64,
        "the retargeted branch must land in the blob, got {branch_target:#x}"
    );

    /* Every module byte below the slack except the branch call site stays
     * stock: no stock page, table or pointer is repointed, and the module's
     * own menu arrays survive untouched (the generated copies live in the
     * blob). */
    assert_eq!(&module[..CALL_OFF as usize], &payload[..CALL_OFF as usize]);
    assert_eq!(
        &module[CALL_OFF as usize + 4..SLACK_START],
        &payload[CALL_OFF as usize + 4..SLACK_START]
    );
    /* RAM mirror as a whole: exactly three records differ from stock — the
     * Setup page record's 18 edited bytes and the two holes the NLoader
     * page claims. Every other byte, the templates included, is stock. */
    let mut expected_ram = ram.clone();
    expected_ram[page_off + 0x10..page_off + 0x22].copy_from_slice(&expected_page[0x10..0x22]);
    expected_ram[OWN_WINDOW_OFF..OWN_WINDOW_OFF + 96].copy_from_slice(&expected_window);
    expected_ram[OWN_PAGE_OFF..OWN_PAGE_OFF + 80].copy_from_slice(&expected_own_page);
    assert_eq!(
        &module[RAM_FILE_OFF..RAM_FILE_OFF + ram.len()],
        &expected_ram[..]
    );

    /* The lower rungs from the same profile change the same sites and no
     * others; their one row gets the stock table cloned with the open
     * actions cleared, returning one level, and only load-only carries the
     * card path. */
    let mut blobs = vec![report.blob_sha256.clone()];
    for mode in [BuildMode::HookOnly, BuildMode::Page] {
        let request = BuildRequest {
            profile: request.profile.clone(),
            source: package(),
            compiler: request.compiler.clone(),
            mode,
            output: directory.path().join(format!("result-{mode}.bin")),
            bundle: None,
        };
        let report = build(&request).expect("lower rung build");
        assert!(report.installable);
        assert!(!blobs.contains(&report.blob_sha256), "{mode} must differ");
        blobs.push(report.blob_sha256.clone());
        let image = key.unpack(&fs::read(&request.output).unwrap()).unwrap();
        let module = image.payload(name).unwrap();
        let blob = &module[SLACK_START..RAM_FILE_OFF];
        assert_eq!(&module[..CALL_OFF as usize], &payload[..CALL_OFF as usize]);
        assert_eq!(
            &module[CALL_OFF as usize + 4..SLACK_START],
            &payload[CALL_OFF as usize + 4..SLACK_START]
        );
        let ram_now = &module[RAM_FILE_OFF..RAM_FILE_OFF + ram.len()];
        for (start, end) in [
            (0, page_off + 0x10),
            (page_off + 0x22, OWN_WINDOW_OFF),
            (OWN_PAGE_OFF + 80, ram.len()),
        ] {
            assert_eq!(
                &ram_now[start..end],
                &ram[start..end],
                "{mode}: RAM {start:#x}"
            );
        }
        let own_page = &ram_now[OWN_PAGE_OFF..OWN_PAGE_OFF + 80];
        assert_eq!(
            u16::from_le_bytes([own_page[0x20], own_page[0x21]]),
            1,
            "{mode}: one row"
        );
        let pointers_va = u64::from_le_bytes(own_page[0x18..0x20].try_into().unwrap());
        let at = (pointers_va - LINK_BASE) as usize;
        let table_va = u64::from_le_bytes(blob[at..at + 8].try_into().unwrap());
        assert_eq!(table_va % 8, 0, "{mode}: event records are read as u64");
        let table_at = (table_va - LINK_BASE) as usize;
        for (index, code) in PAGE_ROW_CODES.into_iter().enumerate() {
            let record = &blob[table_at + index * 32..table_at + (index + 1) * 32];
            let mut expected = page_row_record(code);
            if ACTIVATION_CODES.contains(&code) {
                expected[8..16].fill(0);
            }
            assert_eq!(record, expected.as_slice(), "{mode}: record {code:#x}");
        }
        assert!(
            !blob
                .windows(21)
                .any(|window| window == b"Cannot read MANIFEST\0"),
            "{mode} must not read the card"
        );
    }
    // The 64 list rows of the load-only package, item by item. Expectations
    // are constructed directly from the stock template, then found in the
    // unpacked image, independently of build reports and patch manifests.
    let image = key.unpack(&fs::read(&request.output).unwrap()).unwrap();
    let module = image.payload(name).unwrap();
    let blob = &module[SLACK_START..RAM_FILE_OFF];
    assert_eq!(report.storage_root.as_deref(), Some("B:\\NLOADER\\"));
    for path in [
        b"B:\\NLOADER\\MANIFEST\0".as_slice(),
        b"B:\\NLOADER\\SAFE_MODE\0".as_slice(),
        b"B:\\NLOADER\\ENABLED\0".as_slice(),
        b"B:\\NLOADER\\AUTOLOAD_PENDING\0".as_slice(),
    ] {
        find(blob, path, "configured B: card file");
    }
    assert!(!blob.windows(3).any(|window| window == b"A:\\"));
    assert!(!blob.windows(3).any(|window| window == b"?:\\"));

    // Check the actual unpacked output from another profile. This expectation
    // is independently constructed rather than copied from generated headers
    // or the build's patch list.
    let mut alternate = profile.clone();
    alternate.storage.root = Some("A:\\CUSTOM_LOADER\\FILES\\".into());
    let alternate_profile = directory.path().join("alternate-storage.toml");
    fs::write(&alternate_profile, alternate.to_toml().unwrap()).unwrap();
    let mut alternate_hashes = Vec::new();
    for sequence in 0..2 {
        let alternate_request = BuildRequest {
            profile: alternate_profile.clone(),
            source: package(),
            compiler: request.compiler.clone(),
            mode: BuildMode::LoadOnly,
            output: directory
                .path()
                .join(format!("alternate-storage-{sequence}.bin")),
            bundle: None,
        };
        let alternate_report = build(&alternate_request).expect("alternate A: root build");
        assert_eq!(
            alternate_report.storage_root.as_deref(),
            Some("A:\\CUSTOM_LOADER\\FILES\\")
        );
        assert_ne!(alternate_report.blob_sha256, report.blob_sha256);
        let candidate = key
            .unpack(&fs::read(&alternate_request.output).unwrap())
            .unwrap();
        let candidate_blob = &candidate.payload(name).unwrap()[SLACK_START..RAM_FILE_OFF];
        for suffix in ["MANIFEST", "SAFE_MODE", "ENABLED", "AUTOLOAD_PENDING"] {
            let path = format!("A:\\CUSTOM_LOADER\\FILES\\{suffix}\0");
            find(candidate_blob, path.as_bytes(), "configured A: card file");
        }
        assert!(!candidate_blob.windows(3).any(|window| window == b"B:\\"));
        assert!(!candidate_blob.windows(3).any(|window| window == b"?:\\"));
        alternate_hashes.push(alternate_report.output_sha256);
    }
    assert_eq!(alternate_hashes[0], alternate_hashes[1]);
    let mut expected_rows = Vec::new();
    for index in 0..64u32 {
        let slot = if index < 46 {
            251 + index
        } else {
            232 + index - 46
        };
        let mut row = template_item.clone();
        u32_into(&mut row, 0, slot);
        u32_into(&mut row, 0x10, OWN_ITEM_FLAGS);
        u32_into(&mut row, 0x18, 0x7f80 + index);
        expected_rows.extend_from_slice(&row);
    }
    let rows_at = find(blob, &expected_rows, "64 list rows");
    let page = &module[RAM_FILE_OFF + OWN_PAGE_OFF..RAM_FILE_OFF + OWN_PAGE_OFF + 80];
    assert_eq!(u16_at(page, 0x20), 64);
    assert_eq!(u16_at(page, 0x28), 480);
    assert_eq!(u16_at(page, 0x30), 480);
    assert_eq!(u64_at(page, 0x10), LINK_BASE + rows_at as u64);
    let table_at = find(blob, &page_row_record(0x285)[..8], "list event table");
    let table_va = LINK_BASE + table_at as u64;
    let expected_pointers = table_va.to_le_bytes().repeat(64);
    let pointers_at = find(blob, &expected_pointers, "64 list event pointers");
    assert_eq!(u64_at(page, 0x18), LINK_BASE + pointers_at as u64);
    for (index, code) in PAGE_ROW_CODES.into_iter().enumerate() {
        let record = &blob[table_at + index * 32..table_at + (index + 1) * 32];
        let stock = page_row_record(code);
        assert_eq!(&record[..8], &stock[..8]);
        assert_eq!(&record[16..24], &stock[16..24]);
        assert_eq!(&record[28..], &stock[28..]);
        if code == 0x3bb {
            assert_eq!(record, stock);
        } else {
            let action = u64_at(record, 8);
            assert!((LINK_BASE..LINK_BASE + blob.len() as u64).contains(&action));
            assert_eq!(
                u32_at(record, 24),
                if [0x285, 0x2a0, 0x306].contains(&code) {
                    0x68d
                } else {
                    0x696
                }
            );
        }
    }
}

fn u16_into(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn u32_into(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn u64_into(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
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
