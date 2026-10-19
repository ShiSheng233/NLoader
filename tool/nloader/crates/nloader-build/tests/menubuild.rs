//! Byte-level tests for the menu generation. They exist because a generation
//! bug that passes byte-blind self-consistency checks shipped before: the
//! entry row replaced the Firmware version record, the page edit landed at
//! the record start instead of its pointer fields, and a zero-filled tail
//! record papered over the missing count. Every expectation here is derived
//! independently from the synthetic module payload, not from the generator's
//! own output.

use nloader_build::menubuild::{
    build_menu_data, menu_branch_patch, menu_page_patch, own_page_record_patch,
    own_page_window_patch, render_menu_source, MenuSpec, OwnPageSpec,
};

const XIP_BASE: u64 = 0x1000_0000;
const ITEMS_OFF: u64 = 0x0;
const POINTERS_OFF: u64 = 44 * 0x2c; /* 0x6f0 */
const TABLE_OFF: u64 = POINTERS_OFF + 44 * 8; /* 0x850 */
const PAGE_OFF: u64 = 0x0a00;
const CALL_OFF: u64 = 0x0b00;

const ITEM_COUNT: u32 = 44;
const ANCHOR_INDEX: u32 = 42; /* Firmware version */
const ENTRY_INDEX: u32 = 42; /* the NLoader row goes before it */

fn record_bytes(index: u32) -> Vec<u8> {
    let mut record = vec![index as u8; 0x2c];
    record[0..4].copy_from_slice(&index.to_le_bytes()); /* label slot */
    record[0x10..0x14].copy_from_slice(&(0x100 + index).to_le_bytes()); /* flags */
    record[0x18..0x1c].copy_from_slice(&(0x200 + index).to_le_bytes()); /* item id */
    record
}

fn table_record(code: u32) -> Vec<u8> {
    let mut record = vec![(code as u8) ^ 0x5a; 0x20];
    record[0..4].copy_from_slice(&code.to_le_bytes());
    record
}

fn synthetic_payload() -> Vec<u8> {
    let mut payload = vec![0u8; 0x1000];
    for index in 0..ITEM_COUNT {
        let start = (ITEMS_OFF + u64::from(index) * 0x2c) as usize;
        payload[start..start + 0x2c].copy_from_slice(&record_bytes(index));
    }
    for index in 0..ITEM_COUNT {
        let pointer = if index == ANCHOR_INDEX {
            XIP_BASE + TABLE_OFF /* the anchor's table must be readable */
        } else {
            0x5000_0000 + u64::from(index) * 8
        };
        let start = (POINTERS_OFF + u64::from(index) * 8) as usize;
        payload[start..start + 8].copy_from_slice(&pointer.to_le_bytes());
    }
    /* The anchor's table: two ordinary records, the four activation codes
     * the generator must drop, two more ordinary records, the terminator. */
    let codes = [0x100u32, 0x286, 0x28b, 0x29f, 0x2ae, 0x101, 0x3bb];
    for (position, code) in codes.iter().enumerate() {
        let start = (TABLE_OFF + position as u64 * 0x20) as usize;
        payload[start..start + 0x20].copy_from_slice(&table_record(*code));
    }
    /* The page record: the fields the edit must touch sit at +0x10; the
     * front bytes belong to other fields and must survive untouched. */
    let page_items = XIP_BASE + ITEMS_OFF;
    let page_pointers = XIP_BASE + POINTERS_OFF;
    payload[PAGE_OFF as usize..PAGE_OFF as usize + 0x10].copy_from_slice(&[0xa7u8; 0x10]);
    payload[PAGE_OFF as usize + 0x10..PAGE_OFF as usize + 0x18]
        .copy_from_slice(&page_items.to_le_bytes());
    payload[PAGE_OFF as usize + 0x18..PAGE_OFF as usize + 0x20]
        .copy_from_slice(&page_pointers.to_le_bytes());
    payload[PAGE_OFF as usize + 0x20..PAGE_OFF as usize + 0x22]
        .copy_from_slice(&(ITEM_COUNT as u16).to_le_bytes());
    /* The init-tail call site: a bl to the declared return target. */
    let site = XIP_BASE + CALL_OFF;
    let return_target = XIP_BASE + 0x0f00;
    let delta = ((return_target as i64 - site as i64) / 4) as u32;
    let word = 0x9400_0000u32 | (delta & 0x03ff_ffff);
    payload[CALL_OFF as usize..CALL_OFF as usize + 4].copy_from_slice(&word.to_le_bytes());
    payload
}

fn synthetic_spec() -> MenuSpec {
    MenuSpec {
        events: menu_events(0x1800).0,
        memory: nloader_profile::Memory {
            module_size: Some(0x2000),
            xip_base: Some(XIP_BASE),
            segments: vec![nloader_profile::MemorySegment {
                file_offset: 0,
                runtime_start: XIP_BASE,
                size: 0x2000,
                kind: nloader_profile::MemorySegmentKind::Xip,
            }],
            ..Default::default()
        },
        xip_base: XIP_BASE,
        items_va: XIP_BASE + ITEMS_OFF,
        pointers_va: XIP_BASE + POINTERS_OFF,
        item_count: ITEM_COUNT,
        anchor_index: ANCHOR_INDEX,
        anchor_item_id: 0x200 + ANCHOR_INDEX,
        entry_index: ENTRY_INDEX,
        entry_item_id: 0x2f9,
        entry_flags: 0x0010_124d,
        entry_slot: 299,
        entry_style: 4,
        entry_text: "NLoader".into(),
        page_address: XIP_BASE + PAGE_OFF,
        page_field_offset: PAGE_OFF + 0x10,
        prefill_call_site: XIP_BASE + CALL_OFF,
        prefill_return: XIP_BASE + 0x0f00,
        own_page: None,
        exit_menu_release_code: None,
        apps: None,
    }
}

/* The NLoader page fixture: a stock single-row information page to clone,
 * the Setup row table that opens it, and two all-zero window-table holes.
 * The window records live in the RAM mirror, which this payload models as a
 * separate region; only file offsets reach the generator. */
const TEMPLATE_WINDOW_OFF: u64 = 0x1000;
const HOLE_WINDOW_OFF: u64 = 0x1060;
const HOLE_PAGE_OFF: u64 = 0x10c0;
const TEMPLATE_PAGE_OFF: u64 = 0x1200;
const TEMPLATE_ITEM_OFF: u64 = 0x1300;
const TEMPLATE_ELEMENT_OFF: u64 = 0x1400;
/* Where the generated handler block was linked. */
const HANDLER_BLOCK: u64 = 0x1003_8f80;
const FOOTER_HANDLER: u64 = 0x1008_2200;
const PAGE_TABLE_OFF: u64 = 0x1540;
const ROW_TEMPLATE_OFF: u64 = 0x1600;
const TEMPLATE_WINDOW_ID: u32 = 1272;
const OWN_WINDOW_ID: u32 = 1493;

fn element(kind: u32, resource: u32, control: u32) -> Vec<u8> {
    let mut record = vec![0x11u8 ^ kind as u8; 0x44];
    record[0..4].copy_from_slice(&resource.to_le_bytes());
    record[4..8].copy_from_slice(&kind.to_le_bytes());
    record[0x38..0x3c].copy_from_slice(&control.to_le_bytes());
    record
}

fn template_elements() -> Vec<u8> {
    [
        element(6, 0, 0x3),
        element(1, 1085, 0x15ad),
        element(4, 933, 0x6),
        vec![0u8; 0x44],
    ]
    .concat()
}

fn own_page_payload() -> Vec<u8> {
    let mut payload = synthetic_payload();
    payload.resize(0x2000, 0);
    let put = |payload: &mut Vec<u8>, offset: u64, bytes: &[u8]| {
        let start = offset as usize;
        payload[start..start + bytes.len()].copy_from_slice(bytes);
    };
    /* Template window record: filler everywhere, so a clone that drops a
     * field is visible. */
    let mut window = vec![0x5au8; 0x60];
    window[0..2].copy_from_slice(&2u16.to_le_bytes()); /* kind */
    window[2..4].copy_from_slice(&(TEMPLATE_WINDOW_ID as u16).to_le_bytes());
    window[0x28..0x30].copy_from_slice(&0x1234_5678u64.to_le_bytes()); /* cbtab */
    window[0x50..0x58].copy_from_slice(&(XIP_BASE + TEMPLATE_PAGE_OFF).to_le_bytes());
    put(&mut payload, TEMPLATE_WINDOW_OFF, &window);
    /* Template page record: three rows, a title bar and a layout that the
     * clone has to keep. */
    let mut page = vec![0x3cu8; 0x50];
    page[0..4].copy_from_slice(&0x8000_1008u32.to_le_bytes());
    page[0x08..0x10].copy_from_slice(&(XIP_BASE + TEMPLATE_ELEMENT_OFF).to_le_bytes());
    page[0x10..0x18].copy_from_slice(&(XIP_BASE + TEMPLATE_ITEM_OFF).to_le_bytes());
    page[0x18..0x20].copy_from_slice(&(XIP_BASE + PAGE_TABLE_OFF).to_le_bytes());
    page[0x20..0x22].copy_from_slice(&3u16.to_le_bytes());
    put(&mut payload, TEMPLATE_PAGE_OFF, &page);
    /* Title bar: fill, the title string, an icon, the terminator. */
    put(&mut payload, TEMPLATE_ELEMENT_OFF, &template_elements());
    /* The stock row table the page row reuses: it only returns. */
    put(&mut payload, PAGE_TABLE_OFF, &table_record(0x3bb));
    /* Template row item. */
    let mut item = vec![0x77u8; 0x2c];
    item[0..4].copy_from_slice(&0u32.to_le_bytes());
    item[0x10..0x14].copy_from_slice(&0x400u32.to_le_bytes());
    item[0x18..0x1c].copy_from_slice(&0x38c3u32.to_le_bytes());
    put(&mut payload, TEMPLATE_ITEM_OFF, &item);
    /* The Setup row table that opens the template window. */
    let codes = [0x100u32, 0x286, 0x28b, 0x29f, 0x2ae, 0x101, 0x3bb];
    for (position, code) in codes.iter().enumerate() {
        let mut record = table_record(*code);
        if [0x286, 0x28b, 0x29f, 0x2ae].contains(code) {
            record[8..16].copy_from_slice(&0x1008_1b00u64.to_le_bytes());
            record[0x18..0x1c].copy_from_slice(&TEMPLATE_WINDOW_ID.to_le_bytes());
        }
        put(
            &mut payload,
            ROW_TEMPLATE_OFF + position as u64 * 0x20,
            &record,
        );
    }
    payload
}

fn own_page_spec() -> MenuSpec {
    MenuSpec {
        own_page: Some(OwnPageSpec {
            window_id: OWN_WINDOW_ID,
            window_record_offset: HOLE_WINDOW_OFF,
            page_record_address: XIP_BASE + HOLE_PAGE_OFF,
            page_record_offset: HOLE_PAGE_OFF,
            template_window: TEMPLATE_WINDOW_ID,
            template_window_offset: TEMPLATE_WINDOW_OFF,
            template_page_address: XIP_BASE + TEMPLATE_PAGE_OFF,
            template_page_offset: TEMPLATE_PAGE_OFF,
            footer_handler: FOOTER_HANDLER,
            widget_find: 0x1004_1000,
            text_store: 0x1004_2000,
            text_bind: 0x1004_3000,
            widget_show: 0x1004_4000,
            container_offset: 0x18,
            title_slot_in_element: true,
            title_slot: 297,
            title_format: 3,
            row_event_table: XIP_BASE + PAGE_TABLE_OFF,
            row_template_event_table: XIP_BASE + ROW_TEMPLATE_OFF,
            item_id: 0x38c5,
            item_flags: 0x101240,
            item_slot: 298,
            item_style: 4,
            item_text: "NLoader page".into(),
            row_slots: Vec::new(),
            row_hide: 0,
            page_refresh: 0,
            selected_offset: 0x32,
            viewport_bottom: None,
            row_words: Vec::new(),
            style_page_offset: None,
            dynamic_rows: false,
            detail_window: None,
            rows: None,
            keyboard: None,
            rebuild: None,
            caution: None,
            row_action: false,
        }),
        ..synthetic_spec()
    }
}

#[test]
fn native_refresh_injection_preserves_legacy_reenter_and_uses_stay_after_refresh() {
    let mut spec = own_page_spec();
    spec.own_page.as_mut().unwrap().page_refresh = 0x10041800;
    let data = build_menu_data(&spec, &own_page_payload()).unwrap();
    let table = data.page_table.as_ref().unwrap();
    assert_eq!(table.page_refresh, 0x10041800);
    assert_eq!(table.refresh_next, spec.events.nav_first);
    assert_eq!(table.reenter_next, spec.events.nav_reenter);
    let generated = render_menu_source(&data);
    assert!(generated.contains(".page_refresh = (void (*)(void *))0x10041800"));
    spec.own_page.as_mut().unwrap().page_refresh = 0;
    let data = build_menu_data(&spec, &own_page_payload()).unwrap();
    assert_eq!(data.page_table.as_ref().unwrap().refresh_next, 0);
}

/* The page row table with an OK record that only returns, as the stock
 * information pages carry it, at a free spot of the own-page payload. */
const ACTION_TABLE_OFF: u64 = 0x1c00;

fn action_table_record(code: u32, guard: u64) -> Vec<u8> {
    let mut record = vec![0u8; 0x20];
    record[0..4].copy_from_slice(&code.to_le_bytes());
    record[4..8].copy_from_slice(&(0xa500 + code).to_le_bytes());
    record[8..16].copy_from_slice(&0x1008_1b00u64.to_le_bytes());
    record[16..24].copy_from_slice(&guard.to_le_bytes());
    let next: u32 = if code == 0x3bb { 0x68c } else { 0x68d };
    record[0x18..0x1c].copy_from_slice(&next.to_le_bytes());
    record[0x1c..0x20].copy_from_slice(&(0x5a00 + code).to_le_bytes());
    record
}

fn action_payload(codes: &[u32], guard: u64) -> Vec<u8> {
    let mut payload = own_page_payload();
    for (position, code) in codes.iter().enumerate() {
        let start = ACTION_TABLE_OFF as usize + position * 0x20;
        payload[start..start + 0x20].copy_from_slice(&action_table_record(*code, guard));
    }
    payload
}

fn action_spec() -> MenuSpec {
    let mut spec = own_page_spec();
    let page = spec.own_page.as_mut().expect("page");
    page.row_event_table = XIP_BASE + ACTION_TABLE_OFF;
    page.row_action = true;
    spec
}

#[test]
fn row_action_table_keeps_stock_records_and_reenters_on_open() {
    let codes = [0x285u32, 0x286, 0x28b, 0x2ae, 0x3bb];
    let payload = action_payload(&codes, 0);
    let data = build_menu_data(&action_spec(), &payload).expect("menu data");
    /* With the action the pointer array is rendered to our table, so the
     * stock pointer is not used at all. */
    assert!(data.page_pointers.is_empty());
    assert_eq!(data.page_row_actions, vec![1, 2, 3]);
    assert_eq!(data.page_row_table.len(), codes.len() * 0x20);
    for (index, (record, code)) in data.page_row_table.chunks(0x20).zip(codes).enumerate() {
        let stock = action_table_record(code, 0);
        if data.page_row_actions.contains(&index) {
            /* Only the next field changes before rendering: re-enter. */
            assert_eq!(&record[..0x18], &stock[..0x18]);
            assert_eq!(&record[0x18..0x1c], &0x696u32.to_le_bytes());
            assert_eq!(&record[0x1c..], &stock[0x1c..]);
        } else {
            assert_eq!(record, stock.as_slice(), "record {code:#x}");
        }
    }
    /* Rendered: the open records reference the row action, the others keep
     * the stock action, and the page's pointer array names the table. */
    let source = render_menu_source(&data);
    assert!(source.contains(
        "{ 0x286, 0xa786, (const void *)nlr_page_row_action, (const void *)0x0, 0x696, 0x5c86 },"
    ));
    assert!(source.contains(
        "{ 0x285, 0xa785, (const void *)0x10081b00, (const void *)0x0, 0x68d, 0x5c85 },"
    ));
    assert!(source.contains("nlr_page_row_table,"));
    assert!(!source.contains("nlr_page_evptrs[0x8]"));
    assert!(source.contains(".row_text = nlr_page_row_text,"));
}

#[test]
fn row_action_preserves_guards_and_refuses_a_table_without_ok() {
    let codes = [0x285u32, 0x286, 0x3bb];
    let guarded = action_payload(&codes, 0x1008_1c00);
    let guarded_data = build_menu_data(&action_spec(), &guarded).expect("preserved guard");
    assert_eq!(
        &guarded_data.page_row_table[0x30..0x38],
        &0x1008_1c00u64.to_le_bytes()
    );
    let without_ok = action_payload(&[0x285, 0x2ae, 0x3bb], 0);
    assert!(build_menu_data(&action_spec(), &without_ok).is_err());
    /* Without the action the same stock table is used as it is. */
    let mut spec = action_spec();
    spec.own_page.as_mut().unwrap().row_action = false;
    let data = build_menu_data(&spec, &guarded).expect("stock table");
    assert!(data.page_row_table.is_empty());
    assert_eq!(
        data.page_pointers,
        (XIP_BASE + ACTION_TABLE_OFF).to_le_bytes().to_vec()
    );
}

#[test]
fn own_page_clones_the_stock_list_page_and_opens_from_the_row() {
    let payload = own_page_payload();
    let spec = own_page_spec();
    let page = spec.own_page.clone().expect("page");
    let data = build_menu_data(&spec, &payload).expect("menu data");

    /* The row table is the stock table, byte for byte, except that the four
     * open records now name our window. */
    let stock_table = &payload[ROW_TEMPLATE_OFF as usize..ROW_TEMPLATE_OFF as usize + 7 * 0x20];
    assert_eq!(data.row_table.len(), stock_table.len());
    for (index, (generated, stock)) in data
        .row_table
        .chunks(0x20)
        .zip(stock_table.chunks(0x20))
        .enumerate()
    {
        let code = u32::from_le_bytes(stock[0..4].try_into().unwrap());
        if [0x286u32, 0x28b, 0x29f, 0x2ae].contains(&code) {
            assert_eq!(
                u32::from_le_bytes(generated[0x18..0x1c].try_into().unwrap()),
                OWN_WINDOW_ID,
                "record {index} must open our window"
            );
            /* Only the next field changed; the action stays the stock stub. */
            assert_eq!(&generated[..0x18], &stock[..0x18]);
            assert_eq!(&generated[0x1c..], &stock[0x1c..]);
        } else {
            assert_eq!(generated, stock, "record {index} must be untouched");
        }
    }

    /* The page's own row: the template item with the label moved onto our
     * text slot, our flags and our item id; everything else identical. */
    let template_item = &payload[TEMPLATE_ITEM_OFF as usize..TEMPLATE_ITEM_OFF as usize + 0x2c];
    assert_eq!(data.page_items.len(), 0x2c);
    assert_eq!(
        u32::from_le_bytes(data.page_items[0..4].try_into().unwrap()),
        298
    );
    assert_eq!(
        u32::from_le_bytes(data.page_items[0x10..0x14].try_into().unwrap()),
        0x101240
    );
    assert_eq!(
        u32::from_le_bytes(data.page_items[0x18..0x1c].try_into().unwrap()),
        0x38c5
    );
    for range in [4..0x10, 0x14..0x18, 0x1c..0x2c] {
        assert_eq!(&data.page_items[range.clone()], &template_item[range]);
    }
    /* One event pointer, reusing the declared stock row table. */
    assert_eq!(
        data.page_pointers,
        (XIP_BASE + PAGE_TABLE_OFF).to_le_bytes().to_vec()
    );

    /* The window record: the stock hole is untouched zeros, and the new
     * record is the template with only id, handler block and page pointer
     * replaced. */
    let (offset, stock, new) =
        own_page_window_patch(&page, &payload, HANDLER_BLOCK).expect("window patch");
    assert_eq!(offset, HOLE_WINDOW_OFF);
    assert!(stock.iter().all(|byte| *byte == 0));
    let template_window =
        &payload[TEMPLATE_WINDOW_OFF as usize..TEMPLATE_WINDOW_OFF as usize + 0x60];
    assert_eq!(
        u32::from(u16::from_le_bytes(new[2..4].try_into().unwrap())),
        OWN_WINDOW_ID
    );
    /* The handler block is the generated one, never the template's
     * page-specific block. */
    assert_eq!(
        u64::from_le_bytes(new[0x28..0x30].try_into().unwrap()),
        HANDLER_BLOCK
    );
    assert_eq!(
        u64::from_le_bytes(new[0x50..0x58].try_into().unwrap()),
        XIP_BASE + HOLE_PAGE_OFF
    );
    for range in [0..2, 4..0x28, 0x30..0x50, 0x58..0x60] {
        assert_eq!(&new[range.clone()], &template_window[range]);
    }

    /* The title bar: the template's elements byte for byte, except that
     * the title string became runtime text reading the title's own slot. */
    let stock_elements = template_elements();
    assert_eq!(data.page_elements.len(), stock_elements.len());
    let mut expected_elements = stock_elements.clone();
    expected_elements[0x44..0x48].copy_from_slice(&297u32.to_le_bytes());
    expected_elements[0x48..0x4c].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(data.page_elements, expected_elements);

    /* The page entry's table: the title element's control id, the title's
     * slot and format, the row item's id, slot and style, and the stock
     * functions and container offset from the profile. */
    let table = data.page_table.clone().expect("page table");
    assert_eq!(table.title_widget, 0x15ad);
    assert_eq!((table.title_slot, table.title_format), (297, 3));
    assert_eq!(
        (table.text_store, table.widget_show),
        (0x1004_2000, 0x1004_4000)
    );
    assert_eq!(
        (table.row_widget, table.row_slot, table.row_style),
        (0x38c5, 298, 4)
    );
    assert_eq!(table.container_offset, 0x18);
    assert_eq!(
        (table.widget_find, table.text_bind),
        (0x1004_1000, 0x1004_3000)
    );
    /* The rendered handler block carries the page entry and the template's
     * footer handler, nothing else. */
    let source = render_menu_source(&data);
    assert!(source.contains(concat!(
        "(void *)nlr_page_enter,\n",
        "#if NLR_HAS_GRAPHICS\n    (void *)nlr_graphics_page_leave,\n",
        "#else\n    0,\n#endif\n",
        "    (void *)0x10082200, 0,\n",
        "#if NLR_HAS_GRAPHICS\n    (void *)nlr_graphics_page_install,\n",
        "#else\n    0,\n#endif\n",
    )));
    assert!(source.contains(".title_widget = 0x15ad,"));
    assert!(source.contains(".title_text = nlr_menu_entry_text,"));

    /* The page record: the template with the three array pointers moved to
     * the linked arrays and one row; flags, rectangles and layout survive. */
    let (offset, stock, new) =
        own_page_record_patch(&page, &payload, 0x1003_8f00, 0x1003_9000, 0x1003_9100)
            .expect("page patch");
    assert_eq!(offset, HOLE_PAGE_OFF);
    assert!(stock.iter().all(|byte| *byte == 0));
    let template_page = &payload[TEMPLATE_PAGE_OFF as usize..TEMPLATE_PAGE_OFF as usize + 0x50];
    assert_eq!(
        u64::from_le_bytes(new[0x08..0x10].try_into().unwrap()),
        0x1003_8f00
    );
    assert_eq!(
        u64::from_le_bytes(new[0x10..0x18].try_into().unwrap()),
        0x1003_9000
    );
    assert_eq!(
        u64::from_le_bytes(new[0x18..0x20].try_into().unwrap()),
        0x1003_9100
    );
    assert_eq!(u16::from_le_bytes(new[0x20..0x22].try_into().unwrap()), 1);
    for range in [0..0x08, 0x22..0x50] {
        assert_eq!(&new[range.clone()], &template_page[range]);
    }
}

#[test]
fn own_page_refuses_an_occupied_hole_or_a_row_template_that_opens_elsewhere() {
    let spec = own_page_spec();
    let page = spec.own_page.clone().expect("page");

    /* A hole that is not zero may belong to a window in use. */
    let mut payload = own_page_payload();
    payload[HOLE_WINDOW_OFF as usize] = 1;
    assert!(own_page_window_patch(&page, &payload, HANDLER_BLOCK).is_err());
    let mut payload = own_page_payload();
    payload[HOLE_PAGE_OFF as usize + 0x20] = 1;
    assert!(own_page_record_patch(&page, &payload, 0x1003_8f00, 0x1003_9000, 0x1003_9100).is_err());

    /* A row template whose open records name a different window would move
     * a stock row's destination. */
    let mut payload = own_page_payload();
    let record = ROW_TEMPLATE_OFF as usize + 0x20; /* the 0x286 record */
    payload[record + 0x18..record + 0x1c].copy_from_slice(&999u32.to_le_bytes());
    assert!(build_menu_data(&spec, &payload).is_err());

    /* A template page without rows has no row style to clone. */
    let mut payload = own_page_payload();
    payload[TEMPLATE_PAGE_OFF as usize + 0x20..TEMPLATE_PAGE_OFF as usize + 0x22]
        .copy_from_slice(&0u16.to_le_bytes());
    assert!(build_menu_data(&spec, &payload).is_err());

    /* A title bar with two string elements, or none, has no single title
     * to replace. */
    let mut payload = own_page_payload();
    let icon = TEMPLATE_ELEMENT_OFF as usize + 2 * 0x44;
    payload[icon + 4..icon + 8].copy_from_slice(&1u32.to_le_bytes());
    assert!(build_menu_data(&spec, &payload).is_err());
    let mut payload = own_page_payload();
    let title = TEMPLATE_ELEMENT_OFF as usize + 0x44;
    payload[title + 4..title + 8].copy_from_slice(&4u32.to_le_bytes());
    assert!(build_menu_data(&spec, &payload).is_err());

    /* An element list without its terminator would be read past its end. */
    let mut payload = own_page_payload();
    for index in 3..20 {
        let start = TEMPLATE_ELEMENT_OFF as usize + index * 0x44;
        if start + 0x44 > payload.len() {
            break;
        }
        payload[start + 4..start + 8].copy_from_slice(&6u32.to_le_bytes());
    }
    assert!(build_menu_data(&spec, &payload).is_err());
}

#[test]
fn entry_row_is_inserted_not_substituted() {
    let payload = synthetic_payload();
    let data = build_menu_data(&synthetic_spec(), &payload).expect("menu data");

    assert_eq!(data.items.len(), 45 * 0x2c);
    assert_eq!(data.pointers.len(), 45 * 8);

    /* Records 0..42 are the untouched stock records. */
    assert_eq!(&data.items[..42 * 0x2c], &payload[..42 * 0x2c]);

    /* Record 42 is the NLoader row: the anchor's record with the label
     * slot, flags and item id replaced. */
    let mut expected_new = record_bytes(ANCHOR_INDEX);
    expected_new[0..4].copy_from_slice(&299u32.to_le_bytes());
    expected_new[0x10..0x14].copy_from_slice(&0x0010_124du32.to_le_bytes());
    expected_new[0x18..0x1c].copy_from_slice(&0x2f9u32.to_le_bytes());
    assert_eq!(&data.items[42 * 0x2c..43 * 0x2c], &expected_new[..]);

    /* Records 43 and 44 are the DISPLACED stock records: Firmware version
     * and Special shooting, byte-identical to their module content. */
    assert_eq!(
        &data.items[43 * 0x2c..44 * 0x2c],
        &record_bytes(ANCHOR_INDEX)[..]
    );
    assert_eq!(
        &data.items[44 * 0x2c..45 * 0x2c],
        &record_bytes(ANCHOR_INDEX + 1)[..]
    );
    /* No zero-filled tail record: the last row carries real content. */
    assert!(data.items[44 * 0x2c..45 * 0x2c].iter().any(|b| *b != 0));

    /* Pointers move with their records; the new row's slot is the
     * placeholder the build fills after linking. */
    assert_eq!(
        &data.pointers[..42 * 8],
        &payload[POINTERS_OFF as usize..(POINTERS_OFF + 42 * 8) as usize]
    );
    assert!(data.pointers[42 * 8..43 * 8].iter().all(|b| *b == 0));
    assert_eq!(
        &data.pointers[43 * 8..45 * 8],
        &payload[(POINTERS_OFF + 42 * 8) as usize..(POINTERS_OFF + 44 * 8) as usize]
    );

    /* The audit's acceptance standard: removing the NLoader row and its
     * pointer reproduces the stock arrays byte for byte. */
    let mut stock_items = data.items.clone();
    stock_items.drain(42 * 0x2c..43 * 0x2c);
    assert_eq!(stock_items, &payload[..(44 * 0x2c) as usize]);
    let mut stock_pointers = data.pointers.clone();
    stock_pointers.drain(42 * 8..43 * 8);
    assert_eq!(
        stock_pointers,
        &payload[POINTERS_OFF as usize..(POINTERS_OFF + 44 * 8) as usize]
    );
}

#[test]
fn row_table_drops_activation_codes_and_keeps_terminator() {
    let payload = synthetic_payload();
    let data = build_menu_data(&synthetic_spec(), &payload).expect("menu data");

    assert_eq!(data.row_table.len(), 3 * 0x20);
    assert_eq!(&data.row_table[..0x20], &table_record(0x100)[..]);
    assert_eq!(&data.row_table[0x20..0x40], &table_record(0x101)[..]);
    assert_eq!(&data.row_table[0x40..0x60], &table_record(0x3bb)[..]);
    for code in [0x286u32, 0x28b, 0x29f, 0x2ae] {
        let needle = code.to_le_bytes();
        assert!(
            !data.row_table.windows(4).any(|w| w == needle),
            "activation code {code:#x} must be dropped"
        );
    }
}

#[test]
fn rendering_declares_required_alignment() {
    let payload = synthetic_payload();
    let data = build_menu_data(&synthetic_spec(), &payload).expect("menu data");
    let source = nloader_build::menubuild::render_menu_source(&data);
    assert!(
        source.contains("nlr_menu_items[45 * 0x2c] __attribute__((aligned(4)))"),
        "item records need 4-byte alignment"
    );
    assert!(
        source.contains("nlr_menu_row_table[") && source.contains("aligned(8))"),
        "event tables need 8-byte alignment"
    );
    let pointer_declaration = source
        .lines()
        .find(|line| line.contains("nlr_menu_evptrs"))
        .expect("pointer array declaration");
    assert!(
        pointer_declaration.contains("aligned(8))"),
        "the pointer array is read as 8-byte words: {pointer_declaration}"
    );
}

#[test]
fn page_edit_targets_pointer_fields_and_verifies_semantics() {
    let payload = synthetic_payload();
    let (offset, stock, new_count) =
        menu_page_patch(&synthetic_spec(), &payload).expect("page patch");

    /* The edit covers the pointer pair and the count at +0x10..+0x22, not
     * the record head. */
    assert_eq!(offset, PAGE_OFF + 0x10);
    assert_eq!(stock.len(), 0x12);
    assert_eq!(
        stock,
        &payload[(PAGE_OFF + 0x10) as usize..(PAGE_OFF + 0x22) as usize]
    );
    assert_eq!(new_count, 45);

    /* A count that disagrees with the module must stop generation. */
    let mut corrupted = payload.clone();
    corrupted[(PAGE_OFF + 0x20) as usize] = 43;
    assert!(menu_page_patch(&synthetic_spec(), &corrupted).is_err());

    /* An items pointer that does not reference the module array must stop
     * generation: this is what a wrong field offset would look like. */
    let mut corrupted = payload.clone();
    corrupted[(PAGE_OFF + 0x10) as usize] = 0x99;
    assert!(menu_page_patch(&synthetic_spec(), &corrupted).is_err());

    /* Same for the event-pointer reference. */
    let mut corrupted = payload.clone();
    corrupted[(PAGE_OFF + 0x18) as usize] = 0x77;
    assert!(menu_page_patch(&synthetic_spec(), &corrupted).is_err());
}

#[test]
fn branch_patch_verifies_call_target() {
    let payload = synthetic_payload();
    let (offset, stock, return_target) =
        menu_branch_patch(&synthetic_spec(), &payload).expect("branch patch");
    assert_eq!(offset, CALL_OFF);
    assert_eq!(stock.len(), 4);
    assert_eq!(return_target, XIP_BASE + 0x0f00);

    /* A call site that targets somewhere else must be rejected. */
    let mut corrupted = payload.clone();
    let word = u32::from_le_bytes(
        corrupted[CALL_OFF as usize..CALL_OFF as usize + 4]
            .try_into()
            .expect("4 bytes"),
    );
    let drifted = word ^ 0x40; /* shift the encoded target */
    corrupted[CALL_OFF as usize..CALL_OFF as usize + 4].copy_from_slice(&drifted.to_le_bytes());
    assert!(menu_branch_patch(&synthetic_spec(), &corrupted).is_err());
}

#[test]
fn entry_index_out_of_range_is_refused() {
    let payload = synthetic_payload();
    let mut spec = synthetic_spec();
    spec.entry_index = ITEM_COUNT + 1;
    assert!(build_menu_data(&spec, &payload).is_err());
    /* the item count itself appends the row after every stock row */
    spec.entry_index = ITEM_COUNT;
    assert!(build_menu_data(&spec, &payload).is_ok());
}

/* The Apps row first and the NLoader row after every
 * stock row. Both are the anchor's record with their own slot, flags and
 * id; every stock record keeps its order and its pointer; the two new
 * pointers are placeholders at the rows' final positions; the page counts
 * two more rows; and the Apps row's table runs the Apps open action where
 * the NLoader row's runs the NLoader one. */
#[test]
fn apps_first_and_nloader_last_land_where_declared() {
    let payload = synthetic_payload();
    let mut spec = synthetic_spec();
    spec.entry_index = ITEM_COUNT;
    spec.apps = Some(nloader_build::menubuild::AppsSpec {
        index: 0,
        item_id: 0x2fd,
        flags: 0x0010_1240,
        slot: 249,
        text: "Apps".into(),
    });
    assert_eq!(spec.apps_position(), Some(0));
    assert_eq!(spec.entry_position(), ITEM_COUNT + 1);
    assert_eq!(spec.new_count(), ITEM_COUNT + 2);
    let data = build_menu_data(&spec, &payload).expect("menu data");
    let total = (ITEM_COUNT + 2) as usize;
    assert_eq!(data.new_count, ITEM_COUNT + 2);
    assert_eq!(data.items.len(), total * 0x2c);
    assert_eq!(data.pointers.len(), total * 8);
    let mut apps = record_bytes(ANCHOR_INDEX);
    apps[0..4].copy_from_slice(&249u32.to_le_bytes());
    apps[0x10..0x14].copy_from_slice(&0x0010_1240u32.to_le_bytes());
    apps[0x18..0x1c].copy_from_slice(&0x2fdu32.to_le_bytes());
    assert_eq!(&data.items[..0x2c], &apps[..]);
    let mut nloader = record_bytes(ANCHOR_INDEX);
    nloader[0..4].copy_from_slice(&299u32.to_le_bytes());
    nloader[0x10..0x14].copy_from_slice(&0x0010_124du32.to_le_bytes());
    nloader[0x18..0x1c].copy_from_slice(&0x2f9u32.to_le_bytes());
    assert_eq!(&data.items[(total - 1) * 0x2c..], &nloader[..]);
    assert_eq!(
        &data.items[0x2c..(total - 1) * 0x2c],
        &payload[..(ITEM_COUNT * 0x2c) as usize]
    );
    assert!(data.pointers[..8].iter().all(|b| *b == 0));
    assert!(data.pointers[(total - 1) * 8..].iter().all(|b| *b == 0));
    assert_eq!(
        &data.pointers[8..(total - 1) * 8],
        &payload[POINTERS_OFF as usize..(POINTERS_OFF + u64::from(ITEM_COUNT) * 8) as usize]
    );
    let (_, _, count) = menu_page_patch(&spec, &payload).expect("page edit");
    assert_eq!(count, ITEM_COUNT + 2);
    let source = render_menu_source(&data);
    assert!(source.contains("nlr_menu_apps_row_table"));
    assert!(source.contains("const char nlr_menu_apps_text[] = \"Apps\";"));
    /* the same index for both: Apps goes first */
    spec.entry_index = 0;
    assert_eq!(spec.apps_position(), Some(0));
    assert_eq!(spec.entry_position(), 1);
    /* one id for two rows is refused */
    spec.apps.as_mut().unwrap().item_id = spec.entry_item_id;
    assert!(build_menu_data(&spec, &payload).is_err());
}

#[test]
fn directory_list_builds_all_rows_and_preserves_stock_navigation() {
    let codes = [
        0x283u32, 0x284, 0x285, 0x286, 0x28b, 0x29d, 0x29e, 0x29f, 0x2a0, 0x2ae, 0x306, 0x3bb,
    ];
    let mut payload = action_payload(&codes, 0x1008_1c00);
    for (index, code) in codes.iter().enumerate() {
        if [0x285, 0x2a0, 0x306].contains(code) {
            payload[ACTION_TABLE_OFF as usize + index * 32 + 8
                ..ACTION_TABLE_OFF as usize + index * 32 + 16]
                .fill(0);
        }
    }
    let mut spec = action_spec();
    let page = spec.own_page.as_mut().unwrap();
    page.item_id = 0x7f80;
    page.item_slot = 251;
    page.row_slots = (251..=296).chain(232..=249).collect();
    page.selected_offset = 0x32;
    let data = build_menu_data(&spec, &payload).unwrap();
    assert_eq!(data.page_items.len(), 64 * 44);
    for (index, row) in data.page_items.chunks_exact(44).enumerate() {
        let slot = if index < 46 {
            251 + index
        } else {
            232 + index - 46
        } as u32;
        let mut expected =
            payload[TEMPLATE_ITEM_OFF as usize..TEMPLATE_ITEM_OFF as usize + 44].to_vec();
        expected[..4].copy_from_slice(&slot.to_le_bytes());
        expected[0x10..0x14].copy_from_slice(&0x101240u32.to_le_bytes());
        expected[0x18..0x1c].copy_from_slice(&(0x7f80 + index as u32).to_le_bytes());
        assert_eq!(row, expected, "row {index}");
    }
    assert_eq!(data.page_row_back_actions, [2, 8, 10]);
    for (index, code) in codes.iter().enumerate() {
        let start = index * 32;
        let stock_start = ACTION_TABLE_OFF as usize + start;
        let record = &data.page_row_table[start..start + 32];
        let stock = &payload[stock_start..stock_start + 32];
        assert_eq!(&record[..24], &stock[..24], "action and guard {code:#x}");
        if ![0x286, 0x28b, 0x29f, 0x2ae].contains(code) {
            assert_eq!(record, stock, "navigation {code:#x}");
        }
    }
    let source = render_menu_source(&data);
    assert!(source.contains("nlr_page_evptrs[64]"));
    assert_eq!(source.matches("    nlr_page_row_table,").count(), 64);
    assert_eq!(
        source.matches("(const void *)nlr_page_back_action").count(),
        3
    );
    let page = spec.own_page.as_ref().unwrap();
    let (_, _, record) = own_page_record_patch(page, &payload, 0x1000, 0x2000, 0x3000).unwrap();
    assert_eq!(&record[0x20..0x22], &64u16.to_le_bytes());
    let mut diagnostic = spec.clone();
    let diagnostic_page = diagnostic.own_page.as_mut().unwrap();
    diagnostic_page.row_slots.truncate(1);
    diagnostic_page.row_action = false;
    let diagnostic_data = build_menu_data(&diagnostic, &payload).unwrap();
    assert_eq!(diagnostic_data.page_items.len(), 44);
    assert!(diagnostic_data.page_row_actions.is_empty());
    assert!(diagnostic_data.page_row_back_actions.is_empty());
    for record in diagnostic_data.page_row_table.chunks_exact(32) {
        let code = u32::from_le_bytes(record[..4].try_into().unwrap());
        if [0x286, 0x28b, 0x29f, 0x2ae].contains(&code) {
            assert_eq!(&record[8..16], &[0; 8]);
            assert_eq!(&record[24..28], &0x68du32.to_le_bytes());
        }
    }
    // A back action with real work cannot silently be discarded.
    let action = XIP_BASE + 0x100;
    payload[ACTION_TABLE_OFF as usize + 2 * 32 + 8..ACTION_TABLE_OFF as usize + 2 * 32 + 16]
        .copy_from_slice(&action.to_le_bytes());
    assert!(build_menu_data(&spec, &payload).is_err());
    payload[0x100..0x104].copy_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
    assert!(build_menu_data(&spec, &payload).is_ok());
}

#[test]
fn viewport_extension_changes_only_verified_rectangle_bottoms() {
    let mut payload = own_page_payload();
    for offset in [0x28, 0x30] {
        let at = TEMPLATE_PAGE_OFF as usize + offset;
        payload[at..at + 2].copy_from_slice(&424u16.to_le_bytes());
    }
    let mut page = own_page_spec().own_page.unwrap();
    let (_, _, original) = own_page_record_patch(&page, &payload, 0x1000, 0x2000, 0x3000).unwrap();
    page.viewport_bottom = Some(480);
    let (_, _, expanded) = own_page_record_patch(&page, &payload, 0x1000, 0x2000, 0x3000).unwrap();
    let mut expected = original;
    for offset in [0x28, 0x30] {
        expected[offset..offset + 2].copy_from_slice(&480u16.to_le_bytes());
    }
    assert_eq!(expanded, expected);
    page.viewport_bottom = Some(481);
    assert!(own_page_record_patch(&page, &payload, 0x1000, 0x2000, 0x3000).is_err());
    page.viewport_bottom = Some(480);
    payload[TEMPLATE_PAGE_OFF as usize + 0x30] ^= 1;
    assert!(own_page_record_patch(&page, &payload, 0x1000, 0x2000, 0x3000).is_err());
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
fn profile_event_codes_drive_activation_and_navigation() {
    let mut spec = action_spec();
    let mut payload = action_payload(&[0x285, 0x286, 0x28b, 0x2ae, 0x3bb], 0);
    let old = spec.events.clone();
    let remap = |code: u32| code + 0x1000;
    spec.events.activation = old.activation.map(remap);
    spec.events.back = old.back.map(remap);
    spec.events.ok = remap(old.ok);
    spec.events.terminator = remap(old.terminator);
    spec.events.nav_reenter = 0x123;
    for offset in [ROW_TEMPLATE_OFF, ACTION_TABLE_OFF] {
        let mut at = offset as usize;
        loop {
            let code = u32::from_le_bytes(payload[at..at + 4].try_into().unwrap());
            payload[at..at + 4].copy_from_slice(&remap(code).to_le_bytes());
            if code == old.terminator {
                break;
            }
            at += 0x20;
        }
    }
    let data = build_menu_data(&spec, &payload).unwrap();
    assert_eq!(data.page_row_actions, vec![1, 2, 3]);
    for index in data.page_row_actions.iter().copied() {
        let at = index * 0x20 + 0x18;
        assert_eq!(&data.page_row_table[at..at + 4], &0x123u32.to_le_bytes());
    }
    assert!(render_menu_source(&data).contains(".reenter_next = 0x123"));
}

#[test]
fn back_action_uses_segment_mapping_for_the_stock_return_stub() {
    let mut spec = action_spec();
    spec.own_page.as_mut().unwrap().row_slots = vec![298];
    let mut payload = action_payload(&[0x285, 0x286, 0x3bb], 0);
    let action_address = 0x3000_0000u64;
    let file_offset = 0x1f00;
    payload[file_offset..file_offset + 4].copy_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
    payload[ACTION_TABLE_OFF as usize + 8..ACTION_TABLE_OFF as usize + 16]
        .copy_from_slice(&action_address.to_le_bytes());
    // The stub lives in a separately mapped XIP segment, not at address - xip_base.
    spec.memory.segments[0].size = file_offset as u64;
    spec.memory.segments.push(nloader_profile::MemorySegment {
        file_offset: file_offset as u64,
        runtime_start: action_address,
        size: 0x100,
        kind: nloader_profile::MemorySegmentKind::Xip,
    });
    assert!(build_menu_data(&spec, &payload).is_ok());
    payload[file_offset] ^= 1;
    assert!(build_menu_data(&spec, &payload).is_err());
}

#[test]
fn profile_back_codes_and_return_target_drive_list_navigation() {
    let mut spec = action_spec();
    spec.own_page.as_mut().unwrap().row_slots = vec![298];
    spec.events.back = [0x31, 0x32, 0x33];
    spec.events.nav_back = 0x44;
    let mut payload = action_payload(&[0x31, 0x32, 0x33, 0x286, 0x3bb], 0);
    for index in 0..3 {
        let at = ACTION_TABLE_OFF as usize + index * 32;
        payload[at + 8..at + 16].fill(0);
        payload[at + 24..at + 28].copy_from_slice(&0x44u32.to_le_bytes());
    }
    let data = build_menu_data(&spec, &payload).unwrap();
    assert_eq!(data.page_row_back_actions, vec![0, 1, 2]);
    let source = render_menu_source(&data);
    assert_eq!(
        source.matches("(const void *)nlr_page_back_action").count(),
        3
    );
    payload[ACTION_TABLE_OFF as usize + 24..ACTION_TABLE_OFF as usize + 28]
        .copy_from_slice(&0x45u32.to_le_bytes());
    assert!(build_menu_data(&spec, &payload).is_err());
}

#[test]
fn optional_physical_exit_adds_only_guarded_exec_release_before_terminator() {
    let codes = [0x285u32, 0x286, 0x28b, 0x2ae, 0x3bb];
    let payload = action_payload(&codes, 0);
    let mut spec = action_spec();
    let ordinary = render_menu_source(&build_menu_data(&spec, &payload).unwrap());
    assert!(!ordinary.contains("nlr_page_exit_action"));
    spec.exit_menu_release_code = Some(0x279);
    let data = build_menu_data(&spec, &payload).unwrap();
    assert_eq!(data.page_row_table.len(), codes.len() * 0x20);
    let source = render_menu_source(&data);
    let release = "#if defined(NLR_STAGE_EXEC)\n    { 0x279, 0, (const void *)nlr_page_exit_action, (const void *)nlr_page_exit_guard, 0x696, 0 },\n#endif";
    assert!(source.contains(release));
    assert!(source.find(release).unwrap() < source.find("    { 0x3bb,").unwrap());
    assert_eq!(source.matches("nlr_page_exit_action").count(), 1);
    spec.own_page.as_mut().unwrap().row_action = false;
    let diagnostic = render_menu_source(&build_menu_data(&spec, &payload).unwrap());
    assert!(!diagnostic.contains("nlr_page_exit_action"));
}
