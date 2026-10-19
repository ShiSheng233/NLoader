//! Pure host checks for profile-derived deferred resource bindings.
use nloader_build::menubuild::render_resource_source;
use nloader_profile::{
    Memory, MemorySegment, MemorySegmentKind, MenuEntrySpec, MenuEvents, MenuItemRef, MenuPage,
    Profile,
};

const XIP: u64 = 0x1000_0000;
const RAM: u64 = 0x2000_0000;
const WINDOW: usize = 0x860;
const PAGE: usize = 0xa00;
const ITEMS: usize = 0x200;
const LAYOUT: usize = 0x300;
const ELEMENTS: usize = 0x400;

fn u16_at(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn u32_at(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn u64_at(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn fixture() -> (Profile, Vec<u8>) {
    let mut profile = Profile::draft("injected-test", "test");
    profile.memory = Memory {
        module_size: Some(0x1000),
        xip_base: Some(XIP),
        segments: vec![
            MemorySegment {
                file_offset: 0,
                runtime_start: XIP,
                size: 0x800,
                kind: MemorySegmentKind::Xip,
            },
            MemorySegment {
                file_offset: 0x800,
                runtime_start: RAM,
                size: 0x800,
                kind: MemorySegmentKind::Ram,
            },
        ],
        ..Default::default()
    };
    profile.menu.window_table = Some(RAM);
    profile.menu.setup = Some(MenuPage {
        window_id: 1,
        page_address: RAM + 0x200,
        items: XIP + ITEMS as u64,
        item_count: 2,
        event_table: XIP + 0x260,
        layout: XIP + LAYOUT as u64,
        firmware_version: Some(MenuItemRef {
            index: 1,
            item_id: 0x3894,
        }),
        entry: Some(MenuEntrySpec {
            index: 1,
            item_id: 0x7ffc,
            flags: 0x10124d,
        }),
        apps: None,
        cursor: None,
    });
    profile.menu.events = Some(MenuEvents {
        activation: [0x286, 0x28b, 0x29f, 0x2ae],
        back: [0x285, 0x2a0, 0x306],
        ok: 0x286,
        terminator: 0x3bb,
        nav_first: 0x68c,
        nav_back: 0x68d,
        nav_reenter: 0x696,
        nav_last: 0x697,
        navigation_address: XIP,
        navigation_sha256: String::new(),
        lookup_address: XIP,
        lookup_sha256: String::new(),
    });
    let mut bytes = vec![0; 0x1000];
    u16_at(&mut bytes, WINDOW, 2);
    u16_at(&mut bytes, WINDOW + 2, 1);
    u64_at(&mut bytes, WINDOW + 0x50, RAM + 0x200);
    u32_at(&mut bytes, PAGE, 0x80000000);
    u64_at(&mut bytes, PAGE + 8, XIP + ELEMENTS as u64);
    u64_at(&mut bytes, PAGE + 0x10, XIP + ITEMS as u64);
    u64_at(&mut bytes, PAGE + 0x18, XIP + 0x260);
    u16_at(&mut bytes, PAGE + 0x20, 2);
    u64_at(&mut bytes, PAGE + 0x40, XIP + LAYOUT as u64);
    u32_at(&mut bytes, PAGE + 0x48, 8);
    u16_at(&mut bytes, LAYOUT, 8);
    for offset in [8, 0x10, 0x18] {
        u64_at(&mut bytes, LAYOUT + offset, XIP + 0x500);
    }
    u32_at(&mut bytes, ELEMENTS + 4, 1);
    // The second element is the native type-zero terminator.
    let template = ITEMS + 0x2c;
    u32_at(&mut bytes, template, 0x379);
    u32_at(&mut bytes, template + 0x10, 0x101040);
    u32_at(&mut bytes, template + 0x18, 0x3894);
    u64_at(&mut bytes, 0x268, XIP + 0x600);
    let codes = [
        0x283, 0x284, 0x285, 0x27e, 0x286, 0x28b, 0x29f, 0x2ae, 0x3bb,
    ];
    for (index, code) in codes.into_iter().enumerate() {
        let at = 0x600 + index * 0x20;
        u32_at(&mut bytes, at, code);
        let opening = (4..8).contains(&index);
        u64_at(&mut bytes, at + 8, if index == 8 { 0 } else { XIP + 0x780 });
        u64_at(&mut bytes, at + 0x10, if opening { XIP + 0x784 } else { 0 });
        let next = match index {
            2 => 0x68d,
            3 => 1,
            4..=7 => 3,
            _ => 0x68c,
        };
        u32_at(&mut bytes, at + 0x18, next);
    }
    (profile, bytes)
}

#[test]
fn resource_binding_uses_mapped_setup_and_runtime_owned_storage() {
    let (profile, bytes) = fixture();
    let source = render_resource_source(&profile, &bytes).unwrap();
    assert!(source.contains(".window = (struct nlr_resource_window *)0x20000060UL"));
    assert!(source.contains(".original_page = (const struct nlr_resource_page *)0x20000200UL"));
    assert!(source.contains(".items_bytes = 132, .event_pointers_bytes = 24"));
    // With the Setup Apps row the live page has one more row to copy: the
    // stock rows, NLoader's and Apps'. One row short, core refuses the page
    // and the boot's pass never opens (Z8 QEMU, K1).
    let mut with_apps = profile.clone();
    with_apps.menu.setup.as_mut().unwrap().apps = Some(nloader_profile::MenuAppsSpec {
        index: 0,
        item_id: 0x7ffd,
        flags: 0,
        slot: 0,
        text: "Apps".into(),
    });
    let apps_source = render_resource_source(&with_apps, &bytes).unwrap();
    assert!(apps_source.contains(".items_bytes = 176, .event_pointers_bytes = 32"));
    assert!(source.contains(".elements_bytes = 136, .layout_bytes = 0x30"));
    assert!(source.contains(".string_count = 890"));
    assert!(source.contains(".event_terminator = 0x3bb, .no_jump = 0x68c"));
    assert!(source.contains(".event_template = (const struct nlr_resource_event *)0x10000600UL"));
    assert!(source.contains(".event_template_bytes = 288"));
    assert!(source.contains(".open_events = nlr_resource_open_events, .open_event_count = 4"));
    assert!(source.contains("{ 0x286u, 0x28bu, 0x29fu, 0x2aeu }"));
    assert!(source.contains("0x379u"));
    assert!(source.contains("0x101040u"));
    assert!(source.contains("0x3894u"));
    assert!(source.contains("nlr_runtime_find(&nlr_services, 0)"));
    assert!(source.contains("nlr_resource_clone_publish(&runtime->resource_clone, item)"));
    assert!(source.contains("static const struct nlr_resource_clone_config"));
    assert!(source.contains("const struct nlr_resource_services nlr_resource_services"));
    assert!(!source.contains("static struct nlr_resource_clone"));
}

#[test]
fn resource_binding_refuses_unproven_native_layouts_and_ranges() {
    let (profile, bytes) = fixture();
    let corruptions: &[(usize, usize, u64)] = &[
        (WINDOW, 2, 5),
        (WINDOW + 0x50, 8, RAM + 0x300),
        (PAGE, 4, 0),
        (PAGE + 0x38, 8, XIP),
        (PAGE + 0x20, 2, 3),
        (PAGE + 0x48, 4, 7),
        (LAYOUT, 2, 0),
        (LAYOUT + 8, 8, XIP + 0x7f8),
        (ITEMS + 0x2c + 0x10, 4, 0x200),
        (0x268, 8, XIP + 0x601),
        (0x680, 4, 0x123),
        (0x688, 8, 0),
        (0x690, 8, XIP + 0x801),
        (0x698, 4, 0x68c),
        (0x708, 8, XIP + 0x780),
        (0x718, 4, 0x68d),
        (ITEMS + 0x2c + 0x18, 4, 0xdead),
    ];
    for &(offset, size, value) in corruptions {
        let mut corrupted = bytes.clone();
        match size {
            2 => u16_at(&mut corrupted, offset, value as u16),
            4 => u32_at(&mut corrupted, offset, value as u32),
            8 => u64_at(&mut corrupted, offset, value),
            _ => unreachable!(),
        }
        assert!(
            render_resource_source(&profile, &corrupted).is_err(),
            "offset {offset:#x}"
        );
    }
    let mut corrupted = bytes.clone();
    for index in 0..((corrupted.len() - ELEMENTS) / 0x44) {
        u32_at(&mut corrupted, ELEMENTS + index * 0x44 + 4, 1);
    }
    assert!(render_resource_source(&profile, &corrupted).is_err());
    let mut absent = profile.clone();
    absent.menu.window_table = None;
    assert!(render_resource_source(&absent, &bytes).is_err());
}
