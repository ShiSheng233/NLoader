//! Menu entry-row generation (M1): from the profile's `[menu.setup]` entry
//! spec and the module payload, produces the menu data translation unit (the
//! stock records with the NLoader row INSERTED before the Firmware version
//! anchor, and the entry row's event table) plus the two payload patches the
//! build applies: the page record edit (count and both array pointers) and
//! the init-tail branch retarget for the text-slot prefill trampoline.
//!
//! Uses native item/event record layouts, dispatch semantics, slot
//! ownership and the label combination supported by C3.01.

use crate::Error;
use nloader_profile::{MenuEvents, Profile};

const ITEM_SIZE: u64 = 0x2c;
const EVENT_SIZE: u64 = 0x20;
const PAGE_SIZE: u64 = 0x50;
const WINDOW_SIZE: u64 = 0x60;

/// Window record fields the clone replaces: the window's own id, its
/// callback block pointer and its page record pointer.
const WINDOW_ID_OFFSET: usize = 0x02;
const WINDOW_CBTAB_OFFSET: usize = 0x28;
const WINDOW_PAGE_OFFSET: usize = 0x50;
/// Page record fields: element array, item array, event-pointer array and
/// the item count.
const PAGE_ELEMENT_OFFSET: usize = 0x08;
const PAGE_ITEMS_OFFSET: usize = 0x10;
const PAGE_POINTERS_OFFSET: usize = 0x18;
const PAGE_COUNT_OFFSET: usize = 0x20;
/// The page record's flags word and row layout pointer, which a style page
/// lends.
const PAGE_FLAGS_OFFSET: usize = 0x00;
const PAGE_LAYOUT_OFFSET: usize = 0x40;
/// Handler block: five pointers; the footer handler sits in slot 2 and the
/// page entry in slot 0.
const HANDLER_BLOCK_SIZE: usize = nloader_profile::MENU_HANDLER_SLOTS * 8;
const FOOTER_SLOT: usize = nloader_profile::MENU_HANDLER_FOOTER_SLOT;
/// Element records of the page's title bar; a zero type ends the list.
const ELEMENT_SIZE: usize = nloader_profile::MENU_ELEMENT_SIZE as usize;
const ELEMENT_TYPE_OFFSET: usize = 0x04;
const ELEMENT_CONTROL_OFFSET: usize = 0x38;
/// Event record fields: the code, the action, the guard the dispatcher asks
/// before the action, and the window the record opens.
const EVENT_ACTION_OFFSET: usize = 0x08;
const EVENT_GUARD_OFFSET: usize = 0x10;
const EVENT_NEXT_OFFSET: usize = 0x18;
/// The page record fields the edit replaces: the items pointer at +0x10,
/// the event-pointer array at +0x18 and the item count (u16) at +0x20.
const PAGE_FIELD_OFFSET: u64 = 0x10;
const PAGE_FIELD_SIZE: u64 = 0x12;

/// Everything the menu generation needs, extracted from the profile. Tests
/// construct this directly; the production path fills it from `Profile`.
#[derive(Clone, Debug)]
pub struct MenuSpec {
    pub events: MenuEvents,
    pub memory: nloader_profile::Memory,
    pub xip_base: u64,
    /// The module's item-record array address (the page record must point
    /// here before the edit).
    pub items_va: u64,
    /// The module's per-row event pointer array address.
    pub pointers_va: u64,
    pub item_count: u32,
    pub anchor_index: u32,
    pub anchor_item_id: u32,
    pub entry_index: u32,
    pub entry_item_id: u32,
    pub entry_flags: u32,
    pub entry_slot: u32,
    pub entry_style: u32,
    pub entry_text: String,
    /// The Apps row, inserted like the entry row with
    /// a label slot of its own; None keeps the page at one new row.
    pub apps: Option<AppsSpec>,
    pub page_address: u64,
    /// File offset of the page record's pointer/count field block
    /// (page_address + 0x10), resolved through the segment mapping: the
    /// page record lives in the RAM mirror, so subtracting the XIP base
    /// would be meaningless.
    pub page_field_offset: u64,
    pub prefill_call_site: u64,
    pub prefill_return: u64,
    /// NLoader's own page, when the profile declares one. Without it the
    /// entry row stays a no-op.
    pub own_page: Option<OwnPageSpec>,
    /// Native release action, present only with the optional physical exit profile.
    pub exit_menu_release_code: Option<u32>,
}

/// The Apps row: the stock index it goes before (the item count to follow
/// every row), its item id, label flags, label slot and label.
#[derive(Clone, Debug)]
pub struct AppsSpec {
    pub index: u32,
    pub item_id: u32,
    pub flags: u32,
    pub slot: u32,
    pub text: String,
}

impl MenuSpec {
    /// Where the NLoader row lands in the new arrays: its stock index, one
    /// further when the Apps row goes at or before it (the Apps row is put
    /// first when both take one index).
    pub fn entry_position(&self) -> u32 {
        self.entry_index
            + u32::from(
                self.apps
                    .as_ref()
                    .is_some_and(|a| a.index <= self.entry_index),
            )
    }

    /// Where the Apps row lands, when there is one.
    pub fn apps_position(&self) -> Option<u32> {
        self.apps
            .as_ref()
            .map(|a| a.index + u32::from(self.entry_index < a.index))
    }

    /// The rows the page has after the build: the stock ones and ours.
    pub fn new_count(&self) -> u32 {
        self.item_count + 1 + u32::from(self.apps.is_some())
    }
}

/// NLoader's own second-level page, resolved from the profile. Every record
/// is cloned from the stock list page the profile names; what differs from
/// the clone is the window id, the handler block (generated: the template's
/// footer handler plus NLoader's page entry), the page pointer, the three
/// array pointers, the row count, the title (moved onto the entry row's text
/// slot) and the row's label, flags and item id.
#[derive(Clone, Debug)]
pub struct OwnPageSpec {
    pub window_id: u32,
    /// File offsets of the two all-zero window-table holes this page takes.
    pub window_record_offset: u64,
    pub page_record_address: u64,
    pub page_record_offset: u64,
    /// The stock records cloned, as file offsets plus the addresses needed
    /// to verify them.
    pub template_window: u32,
    pub template_window_offset: u64,
    pub template_page_address: u64,
    pub template_page_offset: u64,
    /// The template's footer handler, copied into the generated block.
    pub footer_handler: u64,
    /// Stock widget lookup and slot binding the page entry calls, and the
    /// widget container's offset in the window record.
    pub widget_find: u64,
    pub text_store: u64,
    pub text_bind: u64,
    pub widget_show: u64,
    pub container_offset: u32,
    /// Whether the title element names its slot; where it does not, the
    /// word stays zero and the runtime bind supplies the slot.
    pub title_slot_in_element: bool,
    /// The title's own slot and the format the stock title chain uses.
    pub title_slot: u32,
    pub title_format: u32,
    pub row_event_table: u64,
    pub row_template_event_table: u64,
    pub item_id: u32,
    pub item_flags: u32,
    pub item_slot: u32,
    pub item_style: u32,
    pub item_text: String,
    pub row_slots: Vec<u32>,
    pub row_hide: u64,
    pub page_refresh: u64,
    pub selected_offset: u32,
    pub viewport_bottom: Option<u16>,
    /// From load-only on, OK on the row runs NLoader's row action: the row
    /// gets a clone of `row_event_table` whose open records call it and
    /// then enter the page again. Lower diagnostic stages retain one row
    /// and replace open actions with a plain return to the parent.
    pub row_action: bool,
    /// `[offset, value]` words every row record takes in place of the
    /// template's (the profile's `menu.page.row_words`).
    pub row_words: Vec<[u32; 2]>,
    /// File offset of the stock page record whose flags and layout the page
    /// takes, when the profile names one.
    pub style_page_offset: Option<u64>,
    /// The core sizes the page before every build; the Setup row's open
    /// records run its open action.
    pub dynamic_rows: bool,
    /// The details' window id, its record's address and file offset.
    pub detail_window: Option<(u32, u64, u64)>,
    /// The camera's own row kinds (`menu.page.rows`); only with dynamic
    /// rows, whose builds the core prepares.
    pub rows: Option<nloader_profile::MenuRows>,
    /// The camera's keyboard (`menu.page.keyboard`); only with dynamic rows.
    pub keyboard: Option<KeyboardSpec>,
    /// The stock in-place rebuild (`menu.page.rebuild`); only with dynamic
    /// rows, whose actions have the stay navigation.
    pub rebuild: Option<nloader_profile::MenuRebuild>,
    /// The camera's caution box (`menu.page.caution`) and the stock popup
    /// it clones; only with the keyboard.
    pub caution: Option<(
        nloader_profile::MenuCaution,
        nloader_profile::CautionTemplate,
    )>,
}

/// The camera's keyboard as the core builds it: the profile's table, the
/// stock window it clones (resolved in the module), and the list window
/// whose page pointer follows the page record when the core moves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyboardSpec {
    pub keyboard: nloader_profile::MenuKeyboard,
    pub template: nloader_profile::KeyboardTemplate,
    pub page_window: u64,
}

impl MenuSpec {
    pub(crate) fn from_profile(
        profile: &Profile,
        payload: &[u8],
        row_action: bool,
    ) -> Result<Self, Error> {
        let setup = profile
            .menu
            .setup
            .as_ref()
            .ok_or_else(|| Error::Object("menu setup page is not declared".into()))?;
        let entry = setup
            .entry
            .as_ref()
            .ok_or_else(|| Error::Object("menu entry row is not declared".into()))?;
        let anchor = setup
            .firmware_version
            .as_ref()
            .ok_or_else(|| Error::Object("menu setup lacks the Firmware version anchor".into()))?;
        let platform = profile
            .menu
            .text_platform
            .as_ref()
            .ok_or_else(|| Error::Object("menu text platform is not declared".into()))?;
        let xip_base = profile
            .memory
            .xip_base
            .ok_or_else(|| Error::Object("profile lacks the XIP base".into()))?;
        let events = profile
            .menu
            .events
            .clone()
            .ok_or_else(|| Error::Object("menu.events is not declared".into()))?;
        Ok(Self {
            events,
            exit_menu_release_code: profile
                .services
                .exit
                .as_ref()
                .map(|exit| exit.menu_release_code),
            memory: profile.memory.clone(),
            xip_base,
            items_va: setup.items,
            pointers_va: setup.event_table,
            item_count: setup.item_count,
            anchor_index: anchor.index,
            anchor_item_id: anchor.item_id,
            entry_index: entry.index,
            entry_item_id: entry.item_id,
            entry_flags: entry.flags,
            entry_slot: platform.entry_slot,
            entry_style: platform.entry_style,
            entry_text: platform.entry_text.clone(),
            apps: setup.apps.as_ref().map(|apps| AppsSpec {
                index: apps.index,
                item_id: apps.item_id,
                flags: apps.flags,
                slot: apps.slot,
                text: apps.text.clone(),
            }),
            page_address: setup.page_address,
            page_field_offset: profile
                .memory
                .address_to_offset(setup.page_address + PAGE_FIELD_OFFSET, PAGE_FIELD_SIZE)
                .map_err(|error| Error::Object(error.to_string()))?,
            prefill_call_site: platform.prefill_call_site,
            prefill_return: platform.prefill_return,
            own_page: match &profile.menu.page {
                Some(page) => {
                    let offset = |address: u64, length: u64| -> Result<u64, Error> {
                        profile
                            .memory
                            .address_to_offset(address, length)
                            .map_err(|error| Error::Object(error.to_string()))
                    };
                    let window = profile.menu.window_address(page.window_id).ok_or_else(|| {
                        Error::Object("page window id is out of the table".into())
                    })?;
                    let template_window = profile
                        .menu
                        .window_address(page.template_window)
                        .ok_or_else(|| {
                            Error::Object("template window id is out of the table".into())
                        })?;
                    // The template's handler block is page-specific code;
                    // only its footer handler is carried over.
                    let template_record = menu_bytes(
                        payload,
                        offset(template_window, WINDOW_SIZE)?,
                        WINDOW_SIZE as usize,
                    )?;
                    let handlers = u64::from_le_bytes(
                        template_record[WINDOW_CBTAB_OFFSET..WINDOW_CBTAB_OFFSET + 8]
                            .try_into()
                            .expect("8 bytes"),
                    );
                    let block = menu_bytes(
                        payload,
                        offset(handlers, HANDLER_BLOCK_SIZE as u64)?,
                        HANDLER_BLOCK_SIZE,
                    )?;
                    let footer_handler = u64::from_le_bytes(
                        block[FOOTER_SLOT * 8..FOOTER_SLOT * 8 + 8]
                            .try_into()
                            .expect("8 bytes"),
                    );
                    if footer_handler == 0 {
                        return Err(Error::Object(
                            "page template has no footer handler to reuse".into(),
                        ));
                    }
                    let required = |value: Option<u64>, field: &str| {
                        value.ok_or_else(|| Error::Object(format!("{field} is not declared")))
                    };
                    Some(OwnPageSpec {
                        footer_handler,
                        widget_find: required(profile.ui.widget_find, "ui.widget_find")?,
                        text_store: required(profile.ui.text_store, "ui.text_store")?,
                        text_bind: required(profile.ui.text_bind, "ui.text_bind")?,
                        widget_show: required(profile.ui.widget_show, "ui.widget_show")?,
                        title_slot: page.title_slot,
                        title_format: page.title_format,
                        container_offset: profile.ui.widget_container_offset.ok_or_else(|| {
                            Error::Object("ui.widget_container_offset is not declared".into())
                        })?,
                        title_slot_in_element: profile
                            .abi
                            .ui
                            .unwrap_or(nloader_profile::UiFamily::Z8MenuV1)
                            .title_slot_in_element(),
                        window_id: page.window_id,
                        window_record_offset: offset(window, WINDOW_SIZE)?,
                        page_record_address: page.page_record,
                        page_record_offset: offset(page.page_record, PAGE_SIZE)?,
                        template_window: page.template_window,
                        template_window_offset: offset(template_window, WINDOW_SIZE)?,
                        template_page_address: page.template_page,
                        template_page_offset: offset(page.template_page, PAGE_SIZE)?,
                        row_event_table: page.row_event_table,
                        row_template_event_table: page.row_template_event_table,
                        item_id: page.item_id,
                        item_flags: page.item_flags,
                        item_slot: page.item_slot,
                        item_style: page.item_style,
                        item_text: page.item_text.clone(),
                        row_slots: match (row_action, page.row_slots.is_empty()) {
                            (true, true) => return Err(Error::Object(
                                "menu.page.row_slots is not declared; the list needs its 64 rows"
                                    .into(),
                            )),
                            (true, false) => page.row_slots.clone(),
                            (false, _) => page.row_slots.first().copied().into_iter().collect(),
                        },
                        // Lower rungs keep one row and never hide any, so an
                        // undeclared function stays absent there; the list
                        // cannot work without it.
                        row_hide: match (row_action, page.row_hide) {
                            (_, Some(address)) => address,
                            (false, None) => 0,
                            (true, None) => return Err(Error::Object(
                                "menu.page.row_hide is not declared; the list hides unused rows"
                                    .into(),
                            )),
                        },
                        page_refresh: page.refresh.as_ref().map_or(0, |r| r.function),
                        selected_offset: page.selected_offset.ok_or_else(|| {
                            Error::Object("menu.page.selected_offset is not declared".into())
                        })?,
                        viewport_bottom: page.viewport_bottom,
                        row_action,
                        row_words: page.row_words.clone(),
                        style_page_offset: page
                            .style_page
                            .map(|address| offset(address, PAGE_SIZE))
                            .transpose()?,
                        dynamic_rows: page.dynamic_rows && row_action,
                        detail_window: match page.detail_window_id {
                            Some(id) if row_action => {
                                if id == page.window_id {
                                    return Err(Error::Object(
                                        "menu.page.detail_window_id is the page's own window"
                                            .into(),
                                    ));
                                }
                                let address = profile.menu.window_address(id).ok_or_else(|| {
                                    Error::Object("detail window id is out of the table".into())
                                })?;
                                Some((id, address, offset(address, WINDOW_SIZE)?))
                            }
                            _ => None,
                        },
                        rows: if page.dynamic_rows && row_action {
                            page.rows.clone()
                        } else {
                            None
                        },
                        keyboard: match &page.keyboard {
                            Some(keyboard) if page.dynamic_rows && row_action => {
                                if profile.menu.window_address(keyboard.window_id)
                                    != Some(page.page_record)
                                {
                                    return Err(Error::Object(
                                        "menu.page.keyboard.window_id is not the entry the \
                                         page record is built into"
                                            .into(),
                                    ));
                                }
                                let template = profile
                                    .keyboard_template(payload, keyboard)
                                    .ok_or_else(|| {
                                        Error::Object(
                                            "menu.page.keyboard.template_window is not a \
                                             keyboard the core can clone"
                                                .into(),
                                        )
                                    })?;
                                Some(KeyboardSpec {
                                    keyboard: keyboard.clone(),
                                    template,
                                    page_window: window,
                                })
                            }
                            _ => None,
                        },
                        rebuild: if page.dynamic_rows && row_action {
                            page.rebuild.clone()
                        } else {
                            None
                        },
                        caution: match (&page.caution, &page.keyboard) {
                            (Some(caution), Some(keyboard)) if page.dynamic_rows && row_action => {
                                let template = profile
                                    .caution_template(payload, caution, keyboard)
                                    .ok_or_else(|| {
                                        Error::Object(
                                            "menu.page.caution.template_window is not a popup \
                                             the core can clone"
                                                .into(),
                                        )
                                    })?;
                                Some((caution.clone(), template))
                            }
                            (Some(_), None) => {
                                return Err(Error::Object(
                                    "menu.page.caution needs menu.page.keyboard".into(),
                                ))
                            }
                            _ => None,
                        },
                    })
                }
                None => None,
            },
        })
    }
}

/// The generated menu content as raw bytes, independent of the C rendering.
#[derive(Clone, Debug)]
pub struct MenuData {
    /// `new_count` item records of `ITEM_SIZE` bytes each: the stock records
    /// with the NLoader row inserted at `entry_index`.
    pub items: Vec<u8>,
    /// `new_count` eight-byte pointers to each row's event table; the entry
    /// row's slot is a zero placeholder the build fills after linking.
    pub pointers: Vec<u8>,
    /// The entry row's event table records (the anchor's table minus the
    /// activation codes, terminator included).
    pub row_table: Vec<u8>,
    pub new_count: u32,
    pub entry_index: u32,
    pub entry_text: String,
    /// Where the NLoader row and the Apps row landed in the new arrays, and
    /// the Apps label; the Apps row's table is `row_table` again, its open
    /// records running the Apps open action.
    pub entry_position: u32,
    pub apps_position: Option<u32>,
    pub apps_text: Option<String>,
    /// NLoader page: its fixed item records and one event pointer per row
    /// array, empty when the profile declares no page. With the row action
    /// the pointer array is rendered to point at `page_row_table` instead
    /// and stays empty here.
    pub page_items: Vec<u8>,
    pub page_pointers: Vec<u8>,
    /// The row's own event table when OK runs the row action: the stock
    /// row table cloned with its open records re-entering the page, and the
    /// indices of the records whose action is NLoader's.
    pub page_row_table: Vec<u8>,
    pub page_row_actions: Vec<usize>,
    pub page_row_back_actions: Vec<usize>,
    /// Records of `row_table` (the Setup row's) whose action becomes the
    /// core's open action: the open records, when the page is sized by the
    /// core.
    pub entry_open_actions: Vec<usize>,
    pub exit_menu_release_code: Option<u32>,
    pub page_elements: Vec<u8>,
    pub page_text: String,
    /// The page entry's table and handler block, present with the page.
    pub page_table: Option<OwnPageTable>,
}

/// What the generated menu data hands the core's page entry: the ids of
/// the title and row widgets in the cloned page, their slots, the stock
/// text functions and the footer handler that fills the handler block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnPageTable {
    /// The details' window and the pop that leaves it, zero without one.
    pub detail_next: u32,
    pub back_next: u32,
    pub detail_record: u64,
    /// Address of the page record's item count when the core sizes the
    /// page, zero otherwise; `stay_next` is the stay navigation then.
    pub page_count: u64,
    pub stay_next: u32,
    /// Address of the page record's items pointer when the page draws row
    /// kinds, zero otherwise, and the profile's recipe for them.
    pub page_items: u64,
    pub rows: Option<nloader_profile::MenuRows>,
    /// The page record's address and the pop navigation when the page has
    /// the keyboard, zero otherwise, and the keyboard.
    pub page_record: u64,
    pub back_nav: u32,
    pub keyboard: Option<KeyboardSpec>,
    pub rebuild: Option<nloader_profile::MenuRebuild>,
    pub caution: Option<(
        nloader_profile::MenuCaution,
        nloader_profile::CautionTemplate,
    )>,
    pub page_refresh: u64,
    pub refresh_next: u32,
    pub reenter_next: u32,
    pub title_widget: u32,
    pub title_slot: u32,
    pub title_format: u32,
    pub row_widget: u32,
    pub row_slot: u32,
    pub row_style: u32,
    pub row_slots: Vec<u32>,
    pub row_hide: u64,
    pub selected_offset: u32,
    pub container_offset: u32,
    pub widget_find: u64,
    pub text_store: u64,
    pub text_bind: u64,
    pub widget_show: u64,
    pub footer_handler: u64,
}

fn menu_bytes(payload: &[u8], offset: u64, length: usize) -> Result<&[u8], Error> {
    let start =
        usize::try_from(offset).map_err(|_| Error::Object("menu offset overflow".into()))?;
    payload
        .get(start..start + length)
        .ok_or_else(|| Error::Object("menu read exceeds module".into()))
}

fn event_table_records(
    payload: &[u8],
    table_eg_off: u64,
    terminator_code: u32,
) -> Result<(Vec<u32>, Vec<[u8; 0x20]>), Error> {
    let mut codes = Vec::new();
    let mut raw = Vec::new();
    for index in 0..256u64 {
        let record = menu_bytes(payload, table_eg_off + index * EVENT_SIZE, 0x20)?;
        let code = u32::from_le_bytes(record[0..4].try_into().expect("4 bytes"));
        let terminator = code == terminator_code;
        codes.push(code);
        raw.push(record.try_into().expect("0x20 bytes"));
        if terminator {
            return Ok((codes, raw));
        }
    }
    Err(Error::Object(
        "menu event table does not terminate within the family limit".into(),
    ))
}

/// The NLoader entry row's event table.
///
/// With a page of our own, the table is the stock row table the profile
/// names, cloned byte for byte except that the four open records are
/// retargeted from the template window to ours: opening a page is a pure
/// data mechanism in this firmware, so the stock action stub stays.
/// Without a page the activation records are dropped instead and the codes
/// fall through to the terminator's no-op.
fn entry_event_table(spec: &MenuSpec, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if let Some(page) = &spec.own_page {
        return row_table_for_own_page(spec, page, payload);
    }
    anchor_event_table(spec, payload)
}

/// Clone the stock row table and point its open records at our window. The
/// template's open records must all name the template window, so a profile
/// that names the wrong table cannot silently produce a row that opens
/// someone else's page.
fn row_table_for_own_page(
    spec: &MenuSpec,
    page: &OwnPageSpec,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let table_eg_off = page
        .row_template_event_table
        .checked_sub(spec.xip_base)
        .ok_or_else(|| Error::Object("row event template is outside the XIP segment".into()))?;
    let (codes, raw) = event_table_records(payload, table_eg_off, spec.events.terminator)?;
    let mut table = Vec::with_capacity(raw.len() * EVENT_SIZE as usize);
    let mut retargeted = 0;
    for (record, code) in raw.iter().zip(&codes) {
        let mut record = *record;
        if spec.events.activation.contains(code) {
            let next = u32::from_le_bytes(
                record[EVENT_NEXT_OFFSET..EVENT_NEXT_OFFSET + 4]
                    .try_into()
                    .expect("4 bytes"),
            );
            let action = u64::from_le_bytes(
                record[EVENT_ACTION_OFFSET..EVENT_ACTION_OFFSET + 8]
                    .try_into()
                    .expect("8 bytes"),
            );
            if next != page.template_window || action == 0 {
                return Err(Error::Object(format!(
                    "row event template record {code:#x} opens {next:#x} through action {action:#x}, \
                     not the declared template window {:#x}",
                    page.template_window
                )));
            }
            record[EVENT_NEXT_OFFSET..EVENT_NEXT_OFFSET + 4]
                .copy_from_slice(&page.window_id.to_le_bytes());
            retargeted += 1;
        }
        table.extend_from_slice(&record);
    }
    if retargeted != spec.events.activation.len() {
        return Err(Error::Object(format!(
            "row event template carries {retargeted} of the {} open records",
            spec.events.activation.len()
        )));
    }
    Ok(table)
}

/// The no-page table: the Firmware version anchor's table minus the
/// activation records, terminator included.
fn anchor_event_table(spec: &MenuSpec, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let pointers_eg_off = spec
        .pointers_va
        .checked_sub(spec.xip_base)
        .ok_or_else(|| Error::Object("menu event pointers are outside the XIP segment".into()))?;
    let table_va = u64::from_le_bytes(
        menu_bytes(
            payload,
            pointers_eg_off + u64::from(spec.anchor_index) * 8,
            8,
        )?
        .try_into()
        .expect("8 bytes"),
    );
    let table_eg_off = table_va
        .checked_sub(spec.xip_base)
        .ok_or_else(|| Error::Object("menu event table is outside the XIP segment".into()))?;
    let (codes, raw) = event_table_records(payload, table_eg_off, spec.events.terminator)?;
    Ok(raw
        .iter()
        .zip(&codes)
        .filter(|(_, code)| !spec.events.activation.contains(code))
        .flat_map(|(record, _)| record.iter().copied())
        .collect())
}

/// The NLoader entry row's item record: the Firmware version anchor record
/// cloned with the label slot, the proven flags and the unique item id.
fn entry_item_record(spec: &MenuSpec, payload: &[u8]) -> Result<Vec<u8>, Error> {
    row_item_record(
        spec,
        payload,
        spec.entry_slot,
        spec.entry_flags,
        spec.entry_item_id,
    )
}

/// A row of ours: the anchor's record with our label slot, flags and id.
fn row_item_record(
    spec: &MenuSpec,
    payload: &[u8],
    slot: u32,
    flags: u32,
    item_id: u32,
) -> Result<Vec<u8>, Error> {
    let items_eg_off = spec
        .items_va
        .checked_sub(spec.xip_base)
        .ok_or_else(|| Error::Object("menu items address is outside the XIP segment".into()))?;
    let mut record = menu_bytes(
        payload,
        items_eg_off + u64::from(spec.anchor_index) * ITEM_SIZE,
        0x2C,
    )?
    .to_vec();
    let anchor_id = u32::from_le_bytes(record[0x18..0x1C].try_into().expect("4 bytes"));
    if anchor_id != spec.anchor_item_id {
        return Err(Error::Object(format!(
            "menu anchor record item id {anchor_id:#x} differs from the profile's {:#x}",
            spec.anchor_item_id
        )));
    }
    record[0..4].copy_from_slice(&slot.to_le_bytes());
    record[0x10..0x14].copy_from_slice(&flags.to_le_bytes());
    record[0x18..0x1C].copy_from_slice(&item_id.to_le_bytes());
    Ok(record)
}

/// Generate the menu content. The NLoader row -- and the Apps row, when
/// the profile has one -- is INSERTED: the record that occupied its index
/// keeps its place after the new row, and every row's event pointer moves
/// with its record. Skipping the displaced record would drop it from the
/// page and leave a zero-filled tail record whose null table pointer is
/// reachable. An index equal to the item count appends the row after every
/// stock row (hidden ones included: layout and cursor skip those).
pub fn build_menu_data(spec: &MenuSpec, payload: &[u8]) -> Result<MenuData, Error> {
    if spec.entry_index > spec.item_count {
        return Err(Error::Object(
            "menu entry index exceeds the item count".into(),
        ));
    }
    if spec
        .apps
        .as_ref()
        .is_some_and(|apps| apps.index > spec.item_count || apps.item_id == spec.entry_item_id)
    {
        return Err(Error::Object(
            "menu apps row needs an index within the page and an item id of its own".into(),
        ));
    }
    let items_eg_off = spec
        .items_va
        .checked_sub(spec.xip_base)
        .ok_or_else(|| Error::Object("menu items address is outside the XIP segment".into()))?;
    let pointers_eg_off = spec
        .pointers_va
        .checked_sub(spec.xip_base)
        .ok_or_else(|| Error::Object("menu event pointers are outside the XIP segment".into()))?;
    let new_item = entry_item_record(spec, payload)?;
    let apps_item = spec
        .apps
        .as_ref()
        .map(|apps| row_item_record(spec, payload, apps.slot, apps.flags, apps.item_id))
        .transpose()?;
    let row_table = entry_event_table(spec, payload)?;
    let new_count = spec.new_count();
    let entry_index = spec.entry_index as usize;

    let mut items = Vec::with_capacity(new_count as usize * ITEM_SIZE as usize);
    let mut pointers = Vec::with_capacity(new_count as usize * 8);
    for index in 0..=spec.item_count as usize {
        /* the new rows' table addresses are filled post-link from the
         * linked symbols; the placeholders keep the array length stable */
        if let (Some(apps), Some(record)) = (&spec.apps, &apps_item) {
            if index == apps.index as usize {
                items.extend_from_slice(record);
                pointers.extend_from_slice(&[0u8; 8]);
            }
        }
        if index == entry_index {
            items.extend_from_slice(&new_item);
            pointers.extend_from_slice(&[0u8; 8]);
        }
        if index == spec.item_count as usize {
            break;
        }
        let record = menu_bytes(payload, items_eg_off + index as u64 * ITEM_SIZE, 0x2C)?.to_vec();
        let table_va = u64::from_le_bytes(
            menu_bytes(payload, pointers_eg_off + index as u64 * 8, 8)?
                .try_into()
                .expect("8 bytes"),
        );
        items.extend_from_slice(&record);
        pointers.extend_from_slice(&table_va.to_le_bytes());
    }
    let (page_row_table, page_row_actions) = match &spec.own_page {
        Some(page) if page.row_action || !page.row_slots.is_empty() => {
            own_page_row_table(spec, page, payload)?
        }
        _ => (Vec::new(), Vec::new()),
    };
    let (page_items, page_pointers, page_elements, page_text, page_table) = match &spec.own_page {
        Some(page) => {
            let elements = own_page_elements(spec, page, payload)?;
            // The title is the one element the clone switched to runtime
            // text; its control id is how the page entry finds its widget.
            let title_widget = elements
                .chunks_exact(ELEMENT_SIZE)
                .find(|element| {
                    u32::from_le_bytes(
                        element[ELEMENT_TYPE_OFFSET..ELEMENT_TYPE_OFFSET + 4]
                            .try_into()
                            .expect("4 bytes"),
                    ) == nloader_profile::MENU_ELEMENT_SLOT_TEXT
                })
                .map(|element| {
                    u32::from_le_bytes(
                        element[ELEMENT_CONTROL_OFFSET..ELEMENT_CONTROL_OFFSET + 4]
                            .try_into()
                            .expect("4 bytes"),
                    )
                })
                .ok_or_else(|| Error::Object("page title element missing".into()))?;
            let table = OwnPageTable {
                detail_next: page.detail_window.map_or(0, |(id, _, _)| id),
                detail_record: page.detail_window.map_or(0, |(_, address, _)| address),
                back_next: if page.detail_window.is_some() {
                    spec.events.nav_back
                } else {
                    0
                },
                page_count: if page.dynamic_rows {
                    page.page_record_address + PAGE_COUNT_OFFSET as u64
                } else {
                    0
                },
                stay_next: if page.dynamic_rows {
                    spec.events.nav_first
                } else {
                    0
                },
                page_refresh: page.page_refresh,
                refresh_next: if page.page_refresh != 0 {
                    spec.events.nav_first
                } else {
                    0
                },
                page_items: if page.rows.is_some() {
                    page.page_record_address + PAGE_ITEMS_OFFSET as u64
                } else {
                    0
                },
                rows: page.rows.clone(),
                page_record: if page.keyboard.is_some() {
                    page.page_record_address
                } else {
                    0
                },
                back_nav: if page.keyboard.is_some() {
                    spec.events.nav_back
                } else {
                    0
                },
                keyboard: page.keyboard.clone(),
                rebuild: page.rebuild.clone(),
                caution: page.caution.clone(),
                reenter_next: spec.events.nav_reenter,
                title_widget,
                title_slot: page.title_slot,
                title_format: page.title_format,
                row_widget: page.item_id,
                row_slot: page.item_slot,
                row_style: page.item_style,
                row_slots: if page.row_slots.is_empty() {
                    vec![page.item_slot]
                } else {
                    page.row_slots.clone()
                },
                row_hide: page.row_hide,
                selected_offset: page.selected_offset,
                container_offset: page.container_offset,
                widget_find: page.widget_find,
                text_store: page.text_store,
                text_bind: page.text_bind,
                widget_show: page.widget_show,
                footer_handler: page.footer_handler,
            };
            (
                own_page_item(spec, page, payload)?,
                if page.row_action {
                    Vec::new()
                } else {
                    own_page_pointers(page)
                },
                elements,
                page.item_text.clone(),
                Some(table),
            )
        }
        None => (Vec::new(), Vec::new(), Vec::new(), String::new(), None),
    };
    let page_row_back_actions = if spec
        .own_page
        .as_ref()
        .is_some_and(|p| p.row_action && !p.row_slots.is_empty())
    {
        page_row_table
            .chunks_exact(EVENT_SIZE as usize)
            .enumerate()
            .filter_map(|(index, record)| {
                let code = u32::from_le_bytes(record[..4].try_into().expect("4 bytes"));
                spec.events.back.contains(&code).then_some(index)
            })
            .collect()
    } else {
        Vec::new()
    };
    let entry_open_actions = if spec.own_page.as_ref().is_some_and(|p| p.dynamic_rows) {
        row_table
            .chunks_exact(EVENT_SIZE as usize)
            .enumerate()
            .filter_map(|(index, record)| {
                let code = u32::from_le_bytes(record[..4].try_into().expect("4 bytes"));
                spec.events.activation.contains(&code).then_some(index)
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(MenuData {
        items,
        pointers,
        row_table,
        entry_open_actions,
        new_count,
        entry_index: spec.entry_index,
        entry_text: spec.entry_text.clone(),
        entry_position: spec.entry_position(),
        apps_position: spec.apps_position(),
        apps_text: spec.apps.as_ref().map(|apps| apps.text.clone()),
        page_items,
        page_pointers,
        page_row_table,
        page_row_actions,
        page_row_back_actions,
        exit_menu_release_code: spec
            .exit_menu_release_code
            .filter(|_| spec.own_page.as_ref().is_some_and(|page| page.row_action)),
        page_elements,
        page_text,
        page_table,
    })
}

/// Render the menu content as the C translation unit compiled into the blob.
/// Item records need 4-byte alignment; event tables and the pointer array
/// are read as 8-byte words and need 8-byte alignment — the linker honours
/// each section's declared alignment, and the build verifies the linked
/// placement again before patching.
pub fn render_menu_source(data: &MenuData) -> String {
    let new_count = data.new_count;
    let entry_index = data.entry_position;
    let mut source = String::new();
    source.push_str(&format!(
        "/* Generated menu data: the NLoader entry row inserted at index \
         {entry_index} (label from the runtime text slot), the stock records \
         shifted behind it, and the entry row's event table. With a page of \
         our own the open records point at it; without one they are omitted \
         and OK/touch fall through to the 0x3bb terminator no-op. */\n\n\
         #include \"nlr/menu.h\"\n#include \"nlr/graphics_runtime.h\"\n\n"
    ));

    source.push_str(&format!(
        "const unsigned char nlr_menu_items[{new_count} * 0x2c] \
         __attribute__((aligned(4))) = {{\n"
    ));
    for chunk in data.items.chunks(12) {
        source.push_str(&format!(
            "    {},\n",
            chunk
                .iter()
                .map(|byte| format!("{byte:#04x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    source.push_str("};\n\n");

    // The row table is emitted before the pointer array that references it.
    if data.entry_open_actions.is_empty() {
        source.push_str(&format!(
            "const unsigned char nlr_menu_row_table[{:#x}] \
             __attribute__((aligned(8))) = {{\n",
            data.row_table.len()
        ));
        for chunk in data.row_table.chunks(12) {
            source.push_str(&format!(
                "    {},\n",
                chunk
                    .iter()
                    .map(|byte| format!("{byte:#04x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        source.push_str("};\n\n");
    } else {
        // The open records run the core's open action, which sizes the page
        // before the dispatcher builds it; every other field is the stock
        // value.
        source.push_str(EVENT_RECORD_STRUCT);
        source.push_str(&format!(
            "const struct nlr_event_record nlr_menu_row_table[{}] \
             __attribute__((aligned(8))) = {{\n",
            data.row_table.len() / EVENT_SIZE as usize
        ));
        for (index, record) in data.row_table.chunks(EVENT_SIZE as usize).enumerate() {
            let word =
                |at: usize| u32::from_le_bytes(record[at..at + 4].try_into().expect("4 bytes"));
            let pointer =
                |at: usize| u64::from_le_bytes(record[at..at + 8].try_into().expect("8 bytes"));
            let action = if data.entry_open_actions.contains(&index) {
                "(const void *)nlr_page_open_action".to_string()
            } else {
                format!("(const void *){:#x}", pointer(EVENT_ACTION_OFFSET))
            };
            source.push_str(&format!(
                "    {{ {:#x}, {:#x}, {action}, (const void *){:#x}, {:#x}, {:#x} }},\n",
                word(0),
                word(4),
                pointer(EVENT_GUARD_OFFSET),
                word(EVENT_NEXT_OFFSET),
                word(0x1c),
            ));
        }
        source.push_str("};\n\n");
    }

    if data.apps_position.is_some() {
        source.push_str(&render_apps_row_table(data));
    }
    source.push_str(&format!(
        "const unsigned char nlr_menu_evptrs[{new_count} * 8] \
         __attribute__((aligned(8))) = {{\n"
    ));
    for chunk in data.pointers.chunks(12) {
        source.push_str(&format!(
            "    {},\n",
            chunk
                .iter()
                .map(|byte| format!("{byte:#04x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    source.push_str("};\n\n");
    source.push_str(&format!(
        "const char nlr_menu_entry_text[] = {:?};\n",
        data.entry_text
    ));
    if let Some(text) = &data.apps_text {
        source.push_str(&format!("const char nlr_menu_apps_text[] = {text:?};\n"));
    }
    if !data.page_items.is_empty() {
        source.push_str(&format!(
            "\n/* NLoader page: rows cloned from the stock list page, and \
             their event pointer array. */\nconst unsigned char nlr_page_items[{:#x}] \
             __attribute__((aligned(4))) = {{\n",
            data.page_items.len()
        ));
        for chunk in data.page_items.chunks(12) {
            source.push_str(&format!(
                "    {},\n",
                chunk
                    .iter()
                    .map(|byte| format!("{byte:#04x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        source.push_str("};\n\n");
        if data.page_row_table.is_empty() {
            source.push_str(&format!(
                "const unsigned char nlr_page_evptrs[{:#x}] \
                 __attribute__((aligned(8))) = {{\n",
                data.page_pointers.len()
            ));
            for chunk in data.page_pointers.chunks(12) {
                source.push_str(&format!(
                    "    {},\n",
                    chunk
                        .iter()
                        .map(|byte| format!("{byte:#04x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            source.push_str("};\n\n");
        } else {
            source.push_str(&render_row_table(data));
        }
        source.push_str(&format!(
            "/* NLoader page title bar: the template's elements, title read \
             from the entry row's text slot. */\nconst unsigned char \
             nlr_page_elements[{:#x}] __attribute__((aligned(4))) = {{\n",
            data.page_elements.len()
        ));
        for chunk in data.page_elements.chunks(12) {
            source.push_str(&format!(
                "    {},\n",
                chunk
                    .iter()
                    .map(|byte| format!("{byte:#04x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        source.push_str("};\n");
        source.push_str(&format!(
            "const char nlr_page_row_text[] = {:?};\n",
            data.page_text
        ));
    }
    if let Some(table) = &data.page_table {
        let keyboard = table.keyboard.as_ref();
        let caution = table.caution.as_ref();
        source.push_str(&format!(
            "const uint32_t nlr_page_row_slots[] = {{ {} }};\n",
            table
                .row_slots
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        // A two-call lookup resolves the widget id against the window and
        // then looks the index up in the container; the single-call form
        // takes the id straight. Only one of the two is ever set.
        source.push_str(&format!(
            "\n/* NLoader page handler block: the page entry in slot 0 and the \
             template's footer handler in slot 2; the other slots stay empty, \
             so no page-specific stock code runs on this page. */\n\
             void *const nlr_page_handlers[5] __attribute__((aligned(8))) = {{\n\
             \x20   (void *)nlr_page_enter,\n#if NLR_HAS_GRAPHICS\n    (void *)nlr_graphics_page_leave,\n#else\n    0,\n#endif\n    (void *){:#x}, 0,\n#if NLR_HAS_GRAPHICS\n    (void *)nlr_graphics_page_install,\n#else\n    0,\n#endif\n}};\n\n\
             const struct nlr_menu_page nlr_menu_page = {{\n\
             \x20   .title_widget = {:#x},\n\
             \x20   .title_slot = {},\n\
             \x20   .title_format = {:#x},\n\
             \x20   .row_widget = {:#x},\n\
             \x20   .row_slot = {},\n\
             \x20   .row_style = {},\n\
             \x20   .row_count = {row_count},\n\
             \x20   .row_slots = nlr_page_row_slots,\n\
             \x20   .selected_offset = {selected_offset},\n\
             \x20   .row_hide = (void (*)(void *, uint32_t, uint32_t)){row_hide:#x},\n\
             \x20   .reenter_next = {reenter_next:#x},\n\
             \x20   .page_refresh = (void (*)(void *)){page_refresh:#x},\n\
             \x20   .refresh_next = {refresh_next:#x},\n\
             \x20   .page_count = (uint16_t *){page_count:#x},\n\
             \x20   .page_items = (void **){page_items:#x},\n\
             \x20   .switch_flags = {switch_flags:#x},\n\
             \x20   .switch_on = {switch_on:#x},\n\
             \x20   .switch_off = {switch_off:#x},\n\
             \x20   .select_flags = {select_flags:#x},\n\
             \x20   .select_format = {select_format:#x},\n\
             \x20   .select_style = {select_style:#x},\n\
             \x20   .skip_flag = {skip_flag:#x},\n\
             \x20   .widget_table = {widget_table:#x},\n\
             \x20   .row_get = (void *(*)(void *, uint32_t, uint32_t)){row_get:#x},\n\
             \x20   .switch_set = (void (*)(void *, uint32_t)){switch_set:#x},\n\
             \x20   .widget_enable = (void (*)(void *, uint32_t)){widget_enable:#x},\n\
             \x20   .page_record = (uint8_t *){page_record:#x},\n\
             \x20   .page_window = (uint8_t *){page_window:#x},\n\
             \x20   .input_window = {input_window:#x},\n\
             \x20   .back_nav = {back_nav:#x},\n\
             \x20   .input_template = (const uint8_t *){input_template:#x},\n\
             \x20   .input_page = (const uint8_t *){input_page:#x},\n\
             \x20   .input_events = (const uint8_t *){input_events:#x},\n\
             \x20   .input_event_count = {input_event_count},\n\
             \x20   .input_save = {input_save:#x},\n\
             \x20   .input_menu = {input_menu:#x},\n\
             \x20   .input_back = {input_back:#x},\n\
             \x20   .input_help = {input_help:#x},\n\
             \x20   .input_handlers = (const uint64_t *){input_handlers:#x},\n\
             \x20   .input_open = (void (*)(const void *, void *)){input_open:#x},\n\
             \x20   .input_take = (uint32_t (*)(char *)){input_take:#x},\n\
             \x20   .input_shown = (void (*)(void *, uint32_t)){input_shown:#x},\n\
             \x20   .page_rebuild = (void (*)(uint32_t, uint32_t)){page_rebuild:#x},\n\
             \x20   .present = (void (*)(const void *, uint32_t, uint32_t)){present:#x},\n\
             \x20   .present_source = (const void *){present_source:#x},\n\
             \x20   .present_a = {present_a},\n\
             \x20   .present_b = {present_b},\n\
             \x20   .caution_template = (const uint8_t *){caution_template:#x},\n\
             \x20   .caution_page = (const uint8_t *){caution_page:#x},\n\
             \x20   .caution_items = (const uint8_t *){caution_items:#x},\n\
             \x20   .caution_tables = (const uint64_t *){caution_tables:#x},\n\
             \x20   .caution_count_yes = {caution_count_yes},\n\
             \x20   .caution_count_no = {caution_count_no},\n\
             \x20   .caution_handlers = (const uint64_t *){caution_handlers:#x},\n\
             \x20   .caution_yes = {caution_yes:#x},\n\
             \x20   .caution_no = {caution_no:#x},\n\
             \x20   .caution_panel = {caution_panel:#x},\n\
             \x20   .caution_slot = {caution_slot},\n\
             \x20   .caution_format = {caution_format:#x},\n\
             \x20   .caution_ok_label = {caution_ok_label:#x},\n\
             \x20   .caution_no_item = {caution_no_item:#x},\n\
             \x20   .panel_text = (void (*)(void *, uint32_t, uint32_t)){panel_text:#x},\n\
             \x20   .cursor_set = (void (*)(void *, uint32_t)){cursor_set:#x},\n\
             \x20   .widget_enable_inverted = {widget_enable_inverted},\n\
             \x20   .detail_next = {detail_next:#x},\n\
             \x20   .back_next = {back_next:#x},\n\
             \x20   .detail_record = (const void *){detail_record:#x},\n\
             \x20   .stay_next = {stay_next:#x},\n\
             \x20   .container_offset = {:#x},\n\
             \x20   .title_text = nlr_menu_entry_text,\n\
             \x20   .row_text = nlr_page_row_text,\n\
             \x20   .widget_find = (void *(*)(uint32_t, void *)){:#x},\n\
             \x20   .text_store = (void (*)(const char *, uint32_t, uint32_t)){:#x},\n\
             \x20   .text_bind = (void (*)(void *, uint32_t)){:#x},\n\
             \x20   .widget_show = (void (*)(void *, uint32_t)){:#x},\n}};\n",
            table.footer_handler,
            table.title_widget,
            table.title_slot,
            table.title_format,
            table.row_widget,
            table.row_slot,
            table.row_style,
            table.container_offset,
            table.widget_find,
            table.text_store,
            table.text_bind,
            table.widget_show,
            row_count = table.row_slots.len(),
            selected_offset = table.selected_offset,
            row_hide = table.row_hide,
            reenter_next = table.reenter_next,
            page_refresh = table.page_refresh,
            refresh_next = table.refresh_next,
            page_count = table.page_count,
            page_items = table.page_items,
            switch_flags = table.rows.as_ref().map_or(0, |r| r.switch_flags),
            switch_on = table.rows.as_ref().map_or(0, |r| r.switch_on),
            switch_off = table.rows.as_ref().map_or(0, |r| r.switch_off),
            select_flags = table.rows.as_ref().map_or(0, |r| r.select_flags),
            select_format = table.rows.as_ref().map_or(0, |r| r.select_format),
            select_style = table.rows.as_ref().map_or(0, |r| r.select_style),
            skip_flag = table.rows.as_ref().map_or(0, |r| r.skip_flag),
            widget_table = table.rows.as_ref().map_or(0, |r| r.widget_table),
            row_get = table.rows.as_ref().map_or(0, |r| r.row_get),
            switch_set = table.rows.as_ref().map_or(0, |r| r.switch_set),
            widget_enable = table.rows.as_ref().map_or(0, |r| r.widget_enable),
            page_record = table.page_record,
            page_window = keyboard.map_or(0, |k| k.page_window),
            back_nav = table.back_nav,
            input_window = keyboard.map_or(0, |k| k.keyboard.window_id),
            input_template = keyboard.map_or(0, |k| k.template.window),
            input_page = keyboard.map_or(0, |k| k.template.page),
            input_events = keyboard.map_or(0, |k| k.template.events),
            input_event_count = keyboard.map_or(0, |k| k.template.event_count),
            input_save = keyboard.map_or(0, |k| k.keyboard.save_event),
            input_menu = keyboard.map_or(0, |k| k.keyboard.menu_event),
            input_back = keyboard.map_or(0, |k| k.keyboard.back_event),
            input_help = keyboard.map_or(0, |k| k.keyboard.help_event),
            input_handlers = keyboard.map_or(0, |k| k.template.handlers),
            input_open = keyboard.map_or(0, |k| k.keyboard.open),
            input_take = keyboard.map_or(0, |k| k.keyboard.take),
            input_shown = keyboard.map_or(0, |k| k.keyboard.shown),
            page_rebuild = table.rebuild.as_ref().map_or(0, |r| r.rebuild),
            present = table.rebuild.as_ref().map_or(0, |r| r.present),
            present_source = table.rebuild.as_ref().map_or(0, |r| r.present_source),
            present_a = table.rebuild.as_ref().map_or(0, |r| r.present_args[0]),
            present_b = table.rebuild.as_ref().map_or(0, |r| r.present_args[1]),
            caution_template = caution.map_or(0, |(_, t)| t.window),
            caution_page = caution.map_or(0, |(_, t)| t.page),
            caution_items = caution.map_or(0, |(_, t)| t.items),
            caution_tables = caution.map_or(0, |(_, t)| t.tables),
            caution_count_yes = caution.map_or(0, |(_, t)| t.count_yes),
            caution_count_no = caution.map_or(0, |(_, t)| t.count_no),
            caution_handlers = caution.map_or(0, |(_, t)| t.handlers),
            caution_yes = caution.map_or(0, |(c, _)| c.yes_action),
            caution_no = caution.map_or(0, |(c, _)| c.no_action),
            caution_panel = caution.map_or(0, |(c, _)| c.panel),
            caution_slot = caution.map_or(0, |(c, _)| c.text_slot),
            caution_format = caution.map_or(0, |(c, _)| c.text_format),
            caution_ok_label = caution.map_or(0, |(c, _)| c.ok_label),
            caution_no_item = caution.map_or(0, |(_, t)| t.no_item),
            panel_text = caution.map_or(0, |(c, _)| c.panel_text),
            cursor_set = caution.map_or(0, |(c, _)| c.cursor_set),
            widget_enable_inverted = u32::from(table.rows.as_ref().is_some_and(|r| r.widget_enable_inverted)),
            detail_next = table.detail_next,
            back_next = table.back_next,
            detail_record = table.detail_record,
            stay_next = table.stay_next,
        ));
    }
    source
}

/// The Apps row's event table: the entry row's
/// records, whose open records run the Apps open action instead. Without a
/// page sized by the core, the bytes are the entry row's own.
fn render_apps_row_table(data: &MenuData) -> String {
    let mut source = String::new();
    if data.entry_open_actions.is_empty() {
        source.push_str(&format!(
            "const unsigned char nlr_menu_apps_row_table[{:#x}] \
             __attribute__((aligned(8))) = {{\n",
            data.row_table.len()
        ));
        for chunk in data.row_table.chunks(12) {
            source.push_str(&format!(
                "    {},\n",
                chunk
                    .iter()
                    .map(|byte| format!("{byte:#04x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        source.push_str("};\n\n");
        return source;
    }
    source.push_str(&format!(
        "const struct nlr_event_record nlr_menu_apps_row_table[{}] \
         __attribute__((aligned(8))) = {{\n",
        data.row_table.len() / EVENT_SIZE as usize
    ));
    for (index, record) in data.row_table.chunks(EVENT_SIZE as usize).enumerate() {
        let word = |at: usize| u32::from_le_bytes(record[at..at + 4].try_into().expect("4 bytes"));
        let pointer =
            |at: usize| u64::from_le_bytes(record[at..at + 8].try_into().expect("8 bytes"));
        let action = if data.entry_open_actions.contains(&index) {
            "(const void *)nlr_page_open_apps_action".to_string()
        } else {
            format!("(const void *){:#x}", pointer(EVENT_ACTION_OFFSET))
        };
        source.push_str(&format!(
            "    {{ {:#x}, {:#x}, {action}, (const void *){:#x}, {:#x}, {:#x} }},\n",
            word(0),
            word(4),
            pointer(EVENT_GUARD_OFFSET),
            word(EVENT_NEXT_OFFSET),
            word(0x1c),
        ));
    }
    source.push_str("};\n\n");
    source
}

/// The page record edit: 18 bytes at page+0x10 covering the items pointer,
/// the event-pointer array and the item count. The stock bytes are verified
/// semantically against the module arrays and count the profile declares —
/// a pure byte-comparison against self-declared values would accept an edit
/// at the wrong offset.
pub fn menu_page_patch(spec: &MenuSpec, payload: &[u8]) -> Result<(u64, Vec<u8>, u32), Error> {
    let new_count = spec
        .item_count
        .checked_add(1 + u32::from(spec.apps.is_some()))
        .ok_or_else(|| Error::Object("menu item count overflows".into()))?;
    u16::try_from(new_count)
        .map_err(|_| Error::Object("menu item count exceeds the page record field".into()))?;
    let field_offset = spec.page_field_offset;
    let stock = menu_bytes(payload, field_offset, PAGE_FIELD_SIZE as usize)?.to_vec();
    let stock_items = u64::from_le_bytes(stock[0..8].try_into().expect("8 bytes"));
    let stock_pointers = u64::from_le_bytes(stock[8..16].try_into().expect("8 bytes"));
    let stock_count = u16::from_le_bytes(stock[16..18].try_into().expect("2 bytes"));
    if stock_items != spec.items_va {
        return Err(Error::Object(format!(
            "page items pointer {stock_items:#x} does not reference the module items array {:#x}",
            spec.items_va
        )));
    }
    if stock_pointers != spec.pointers_va {
        return Err(Error::Object(format!(
            "page event-pointer reference {stock_pointers:#x} does not reference the module pointer array {:#x}",
            spec.pointers_va
        )));
    }
    if u32::from(stock_count) != spec.item_count {
        return Err(Error::Object(format!(
            "page item count {stock_count} differs from the module's {}",
            spec.item_count
        )));
    }
    Ok((field_offset, stock, new_count))
}

/// The init-tail branch patch site, its stock bytes, and the original callee
/// the trampoline must tail-branch back to. The stock word is verified to be
/// a bl to the declared return target.
pub fn menu_branch_patch(spec: &MenuSpec, payload: &[u8]) -> Result<(u64, Vec<u8>, u64), Error> {
    let site_eg_off = spec
        .prefill_call_site
        .checked_sub(spec.xip_base)
        .ok_or_else(|| Error::Object("prefill call site is outside the XIP segment".into()))?;
    let stock = menu_bytes(payload, site_eg_off, 4)?.to_vec();
    let word = u32::from_le_bytes(stock.as_slice().try_into().expect("4 bytes"));
    if word >> 26 != 0b100101 {
        return Err(Error::Object(
            "prefill call site does not hold a bl instruction".into(),
        ));
    }
    let imm = (word & 0x03ff_ffff) as i32;
    let delta = ((imm << 6) >> 6) as i64 * 4;
    let target = i64::try_from(spec.prefill_call_site)
        .map_err(|_| Error::Object("call site overflow".into()))?
        + delta;
    if target
        != i64::try_from(spec.prefill_return)
            .map_err(|_| Error::Object("prefill return overflow".into()))?
    {
        return Err(Error::Object(format!(
            "prefill call site targets {target:#x}, not the declared {:#x}",
            spec.prefill_return
        )));
    }
    Ok((site_eg_off, stock, spec.prefill_return))
}

/// The NLoader page's own row item: the template page's first row cloned,
/// with the label moved onto a runtime text slot and a fresh item id. The
/// clone keeps the template's row style, value icon and help fields.
pub fn own_page_item(
    spec: &MenuSpec,
    page: &OwnPageSpec,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let template = menu_bytes(payload, page.template_page_offset, PAGE_SIZE as usize)?;
    let items_va = u64::from_le_bytes(
        template[PAGE_ITEMS_OFFSET..PAGE_ITEMS_OFFSET + 8]
            .try_into()
            .expect("8 bytes"),
    );
    let count = u16::from_le_bytes(
        template[PAGE_COUNT_OFFSET..PAGE_COUNT_OFFSET + 2]
            .try_into()
            .expect("2 bytes"),
    );
    if count == 0 {
        return Err(Error::Object(
            "page template has no row to take the row style from".into(),
        ));
    }
    let items_eg_off = items_va
        .checked_sub(spec.xip_base)
        .ok_or_else(|| Error::Object("page template items are outside the XIP segment".into()))?;
    let mut record = menu_bytes(payload, items_eg_off, ITEM_SIZE as usize)?.to_vec();
    for [at, value] in &page.row_words {
        let at = *at as usize;
        if at % 4 != 0 || at + 4 > ITEM_SIZE as usize || [0, 0x10, 0x18].contains(&at) {
            return Err(Error::Object(format!(
                "row word at {at:#x} is not a free word of the item record"
            )));
        }
        record[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    record[0..4].copy_from_slice(&page.item_slot.to_le_bytes());
    record[0x10..0x14].copy_from_slice(&page.item_flags.to_le_bytes());
    record[0x18..0x1c].copy_from_slice(&page.item_id.to_le_bytes());
    if page.row_slots.is_empty() {
        return Ok(record);
    }
    let mut items = Vec::with_capacity(page.row_slots.len() * ITEM_SIZE as usize);
    for (index, slot) in page.row_slots.iter().enumerate() {
        record[0..4].copy_from_slice(&slot.to_le_bytes());
        record[0x18..0x1c].copy_from_slice(&(page.item_id + index as u32).to_le_bytes());
        items.extend_from_slice(&record);
    }
    Ok(items)
}

/// The page's title bar: the template's element list cloned through its
/// terminator, with the one string element (the title) switched to the
/// runtime-text element type reading the title's own slot. Both types read
/// the same geometry, alignment and colour fields, so the title sits where
/// the template's did; the page entry fills and shows it.
pub fn own_page_elements(
    spec: &MenuSpec,
    page: &OwnPageSpec,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let template = menu_bytes(payload, page.template_page_offset, PAGE_SIZE as usize)?;
    let elements_va = u64::from_le_bytes(
        template[PAGE_ELEMENT_OFFSET..PAGE_ELEMENT_OFFSET + 8]
            .try_into()
            .expect("8 bytes"),
    );
    let elements_eg_off = elements_va.checked_sub(spec.xip_base).ok_or_else(|| {
        Error::Object("page template elements are outside the XIP segment".into())
    })?;
    let mut list = Vec::new();
    let mut titles = 0;
    for index in 0..nloader_profile::MENU_ELEMENT_MAX {
        let mut element = menu_bytes(
            payload,
            elements_eg_off + index * ELEMENT_SIZE as u64,
            ELEMENT_SIZE,
        )?
        .to_vec();
        let kind = u32::from_le_bytes(
            element[ELEMENT_TYPE_OFFSET..ELEMENT_TYPE_OFFSET + 4]
                .try_into()
                .expect("4 bytes"),
        );
        if kind == nloader_profile::MENU_ELEMENT_STRING {
            titles += 1;
            // Native title constructor clamps labels to stock slots; bind the
            // private token only after the owned pool becomes ready.
            let constructor_slot = if !page.title_slot_in_element || page.title_slot >= 300 {
                0
            } else {
                page.title_slot
            };
            element[0..4].copy_from_slice(&constructor_slot.to_le_bytes());
            element[ELEMENT_TYPE_OFFSET..ELEMENT_TYPE_OFFSET + 4]
                .copy_from_slice(&nloader_profile::MENU_ELEMENT_SLOT_TEXT.to_le_bytes());
        }
        list.extend_from_slice(&element);
        if kind == 0 {
            return if titles == 1 {
                Ok(list)
            } else {
                Err(Error::Object(format!(
                    "page template carries {titles} title strings, not one"
                )))
            };
        }
    }
    Err(Error::Object(
        "page template element list does not terminate".into(),
    ))
}

/// The unmodified diagnostic page's event-pointer array. Multirow pages
/// use the generated table so activation cannot enter a stock page.
pub fn own_page_pointers(page: &OwnPageSpec) -> Vec<u8> {
    page.row_event_table
        .to_le_bytes()
        .repeat(page.row_slots.len().max(1))
}

/// The row's event table when OK runs NLoader's row action: the stock row
/// table cloned through its terminator, with every open record marked to
/// run the action and then enter the page again. A row whose text changes
/// while the page is shown is not redrawn, so the result reaches the screen
/// through the page entry, which draws the page anew. Everything else — the
/// other codes, the back records, the terminator — is the stock bytes. A
/// guard is preserved because the firmware uses it to distinguish input
/// sources. A table without OK is refused. List-page back records may be
/// intercepted only when the stock action is absent or a verified RET stub.
pub fn own_page_row_table(
    spec: &MenuSpec,
    page: &OwnPageSpec,
    payload: &[u8],
) -> Result<(Vec<u8>, Vec<usize>), Error> {
    let table_eg_off = page
        .row_event_table
        .checked_sub(spec.xip_base)
        .ok_or_else(|| Error::Object("page row event table is outside the XIP segment".into()))?;
    let (codes, raw) = event_table_records(payload, table_eg_off, spec.events.terminator)?;
    if codes.last() != Some(&spec.events.terminator) {
        return Err(Error::Object(
            "page row event table does not terminate".into(),
        ));
    }
    let mut table = Vec::with_capacity(raw.len() * EVENT_SIZE as usize);
    let mut actions = Vec::new();
    for (index, (record, code)) in raw.iter().zip(&codes).enumerate() {
        let mut record = *record;
        if !page.row_slots.is_empty() && spec.events.back.contains(code) {
            let action = u64::from_le_bytes(record[8..16].try_into().expect("8 bytes"));
            let next = u32::from_le_bytes(record[0x18..0x1c].try_into().expect("4 bytes"));
            if next != spec.events.nav_back
                || (action != 0
                    && spec
                        .memory
                        .address_to_offset(action, 4)
                        .ok()
                        .and_then(|off| menu_bytes(payload, off, 4).ok())
                        != Some(&[0xc0, 0x03, 0x5f, 0xd6]))
            {
                return Err(Error::Object(format!(
                    "back record {code:#x} must return one level with no action or a RET stub"
                )));
            }
        }
        if spec.events.activation.contains(code) {
            let next = if page.row_action {
                spec.events.nav_reenter
            } else {
                spec.events.nav_back
            };
            record[EVENT_NEXT_OFFSET..EVENT_NEXT_OFFSET + 4].copy_from_slice(&next.to_le_bytes());
            if page.row_action {
                actions.push(index);
            } else {
                record[EVENT_ACTION_OFFSET..EVENT_ACTION_OFFSET + 8].fill(0);
            }
        }
        table.extend_from_slice(&record);
    }
    if !codes.contains(&spec.events.ok) {
        return Err(Error::Object(
            "page row event table has no OK record for the row action".into(),
        ));
    }
    Ok((table, actions))
}

/// The row table as C records, so the action fields that run NLoader's row
/// action are relocated to the linked function; every other field is the
/// cloned stock value. The event-pointer array points at it.
const EVENT_RECORD_STRUCT: &str = "struct nlr_event_record {\n\
     \x20   uint32_t code;\n\
     \x20   uint32_t word1;\n\
     \x20   const void *action;\n\
     \x20   const void *guard;\n\
     \x20   uint32_t next;\n\
     \x20   uint32_t word7;\n\
     };\n\
     _Static_assert(sizeof(struct nlr_event_record) == 0x20, \"event record\");\n";

fn render_row_table(data: &MenuData) -> String {
    let mut source = String::from(
        "/* NLoader page row: the stock row table cloned, its open records \
         running nlr_page_row_action and then entering the page again. */\n",
    );
    if data.entry_open_actions.is_empty() {
        source.push_str(EVENT_RECORD_STRUCT);
    }
    let count = data.page_row_table.len() / EVENT_SIZE as usize;
    let array_count = if data.exit_menu_release_code.is_some() {
        String::new()
    } else {
        count.to_string()
    };
    source.push_str(&format!(
        "const struct nlr_event_record nlr_page_row_table[{array_count}] \
         __attribute__((aligned(8))) = {{\n"
    ));
    let word = |record: &[u8], at: usize| {
        u32::from_le_bytes(record[at..at + 4].try_into().expect("4 bytes"))
    };
    let pointer = |record: &[u8], at: usize| {
        u64::from_le_bytes(record[at..at + 8].try_into().expect("8 bytes"))
    };
    for (index, record) in data.page_row_table.chunks(EVENT_SIZE as usize).enumerate() {
        if index + 1 == count {
            if let Some(code) = data.exit_menu_release_code {
                let next = data
                    .page_table
                    .as_ref()
                    .expect("row action page table")
                    .reenter_next;
                source.push_str(&format!(
                    "#if defined(NLR_STAGE_EXEC)\n\
                     \x20   {{ {code:#x}, 0, (const void *)nlr_page_exit_action, \
                     (const void *)nlr_page_exit_guard, {next:#x}, 0 }},\n\
                     #endif\n",
                ));
            }
        }
        let action = if data.page_row_actions.contains(&index) {
            "(const void *)nlr_page_row_action".to_string()
        } else if data.page_row_back_actions.contains(&index) {
            "(const void *)nlr_page_back_action".to_string()
        } else {
            format!("(const void *){:#x}", pointer(record, EVENT_ACTION_OFFSET))
        };
        source.push_str(&format!(
            "    {{ {:#x}, {:#x}, {action}, (const void *){:#x}, {:#x}, {:#x} }},\n",
            word(record, 0),
            word(record, 4),
            pointer(record, EVENT_GUARD_OFFSET),
            word(record, EVENT_NEXT_OFFSET),
            word(record, 0x1c),
        ));
    }
    source.push_str("};\n\n");
    let rows = data.page_items.len() / ITEM_SIZE as usize;
    source.push_str(&format!(
        "const void *const nlr_page_evptrs[{rows}] __attribute__((aligned(8))) = {{\n"
    ));
    for _ in 0..rows {
        source.push_str("    nlr_page_row_table,\n");
    }
    source.push_str("};\n\n");
    source
}

/// The page's window record: the template window cloned (kind, parent and
/// the remaining fields), carrying our id, our page record and the generated
/// handler block. The template's own block is code written for that page,
/// so it is not used.
pub fn own_page_window_patch(
    page: &OwnPageSpec,
    payload: &[u8],
    handlers_va: u64,
) -> Result<(u64, Vec<u8>, Vec<u8>), Error> {
    own_window_patch(
        page,
        payload,
        handlers_va,
        page.window_id,
        page.window_record_offset,
    )
}

/// A window-table edit: the record's file offset, its stock and new bytes.
pub type WindowPatch = (u64, Vec<u8>, Vec<u8>);

/// The details' window: the same clone under its own id, in its own hole,
/// with the page record and handler block the list uses.
pub fn own_detail_window_patch(
    page: &OwnPageSpec,
    payload: &[u8],
    handlers_va: u64,
) -> Result<Option<WindowPatch>, Error> {
    page.detail_window
        .map(|(id, _, offset)| own_window_patch(page, payload, handlers_va, id, offset))
        .transpose()
}

fn own_window_patch(
    page: &OwnPageSpec,
    payload: &[u8],
    handlers_va: u64,
    window_id: u32,
    window_record_offset: u64,
) -> Result<(u64, Vec<u8>, Vec<u8>), Error> {
    let stock = menu_bytes(payload, window_record_offset, WINDOW_SIZE as usize)?.to_vec();
    if stock.iter().any(|byte| *byte != 0) {
        return Err(Error::Object(
            "the window table entry the page takes is not an all-zero hole".into(),
        ));
    }
    let template = menu_bytes(payload, page.template_window_offset, WINDOW_SIZE as usize)?;
    let template_id = u16::from_le_bytes(
        template[WINDOW_ID_OFFSET..WINDOW_ID_OFFSET + 2]
            .try_into()
            .expect("2 bytes"),
    );
    let template_page = u64::from_le_bytes(
        template[WINDOW_PAGE_OFFSET..WINDOW_PAGE_OFFSET + 8]
            .try_into()
            .expect("8 bytes"),
    );
    if u32::from(template_id) != page.template_window || template_page != page.template_page_address
    {
        return Err(Error::Object(format!(
            "window template {template_id} points at {template_page:#x}, not the declared page {:#x}",
            page.template_page_address
        )));
    }
    let window_id = u16::try_from(window_id)
        .map_err(|_| Error::Object("page window id exceeds the record field".into()))?;
    let mut new = template.to_vec();
    new[WINDOW_ID_OFFSET..WINDOW_ID_OFFSET + 2].copy_from_slice(&window_id.to_le_bytes());
    new[WINDOW_CBTAB_OFFSET..WINDOW_CBTAB_OFFSET + 8].copy_from_slice(&handlers_va.to_le_bytes());
    new[WINDOW_PAGE_OFFSET..WINDOW_PAGE_OFFSET + 8]
        .copy_from_slice(&page.page_record_address.to_le_bytes());
    Ok((window_record_offset, stock, new))
}

/// The page record: the template page cloned, with the element, item and
/// event-pointer arrays moved to the linked copies and the fixed row count. The flags,
/// rectangles, layout and rows-per-screen stay the template's, which is
/// what keeps the page laid out by the firmware's own code.
pub fn own_page_record_patch(
    page: &OwnPageSpec,
    payload: &[u8],
    elements_va: u64,
    items_va: u64,
    pointers_va: u64,
) -> Result<(u64, Vec<u8>, Vec<u8>), Error> {
    let stock = menu_bytes(payload, page.page_record_offset, PAGE_SIZE as usize)?.to_vec();
    if stock.iter().any(|byte| *byte != 0) {
        return Err(Error::Object(
            "the window table entry borrowed for the page record is not an all-zero hole".into(),
        ));
    }
    let template = menu_bytes(payload, page.template_page_offset, PAGE_SIZE as usize)?;
    let mut new = template.to_vec();
    if let Some(style) = page.style_page_offset {
        let style = menu_bytes(payload, style, PAGE_SIZE as usize)?;
        new[PAGE_FLAGS_OFFSET..PAGE_FLAGS_OFFSET + 4]
            .copy_from_slice(&style[PAGE_FLAGS_OFFSET..PAGE_FLAGS_OFFSET + 4]);
        new[PAGE_LAYOUT_OFFSET..PAGE_LAYOUT_OFFSET + 8]
            .copy_from_slice(&style[PAGE_LAYOUT_OFFSET..PAGE_LAYOUT_OFFSET + 8]);
    }
    new[PAGE_ELEMENT_OFFSET..PAGE_ELEMENT_OFFSET + 8].copy_from_slice(&elements_va.to_le_bytes());
    new[PAGE_ITEMS_OFFSET..PAGE_ITEMS_OFFSET + 8].copy_from_slice(&items_va.to_le_bytes());
    new[PAGE_POINTERS_OFFSET..PAGE_POINTERS_OFFSET + 8].copy_from_slice(&pointers_va.to_le_bytes());
    new[PAGE_COUNT_OFFSET..PAGE_COUNT_OFFSET + 2]
        .copy_from_slice(&(page.row_slots.len().max(1) as u16).to_le_bytes());
    if let Some(bottom) = page.viewport_bottom {
        if ![424, 480].contains(&bottom)
            || [0x28, 0x30].iter().any(|offset| {
                u16::from_le_bytes(template[*offset..*offset + 2].try_into().expect("2 bytes"))
                    != 424
            })
        {
            return Err(Error::Object(
                "viewport change requires the stock 424px bottom in both rectangles".into(),
            ));
        }
        for offset in [0x28, 0x30] {
            new[offset..offset + 2].copy_from_slice(&bottom.to_le_bytes());
        }
    }
    Ok((page.page_record_offset, stock, new))
}

/// Bind the deferred publisher to the profile's existing Setup window. Every
/// capacity and template word is derived from mapped stock records; the
/// patched Setup item/event arrays contain one additional NLoader entry.
pub fn render_resource_source(profile: &Profile, payload: &[u8]) -> Result<String, Error> {
    let setup = profile
        .menu
        .setup
        .as_ref()
        .ok_or_else(|| Error::Object("resource publisher lacks Setup page".into()))?;
    let anchor = setup
        .firmware_version
        .ok_or_else(|| Error::Object("resource publisher lacks stock item template".into()))?;
    let events = profile
        .menu
        .events
        .as_ref()
        .ok_or_else(|| Error::Object("resource publisher lacks event semantics".into()))?;
    let table = profile
        .menu
        .window_table
        .ok_or_else(|| Error::Object("resource publisher lacks window table".into()))?;
    let window_address = table
        .checked_add(u64::from(setup.window_id) * WINDOW_SIZE)
        .ok_or_else(|| Error::Object("resource window address overflows".into()))?;
    let mapped = |address: u64, length: usize| -> Result<&[u8], Error> {
        let offset = profile
            .memory
            .address_to_offset(address, length as u64)
            .map_err(|error| Error::Object(error.to_string()))?;
        menu_bytes(payload, offset, length)
    };
    let pointer = |bytes: &[u8], offset: usize| -> u64 {
        u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("native pointer"),
        )
    };
    let word = |bytes: &[u8], offset: usize| -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("native word"))
    };
    let half = |bytes: &[u8], offset: usize| -> u16 {
        u16::from_le_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .expect("native halfword"),
        )
    };
    let window = mapped(window_address, WINDOW_SIZE as usize)?;
    let page = mapped(setup.page_address, PAGE_SIZE as usize)?;
    let layout = mapped(setup.layout, 0x30)?;
    if half(window, 0) != 2
        || u32::from(half(window, 2)) != setup.window_id
        || pointer(window, WINDOW_PAGE_OFFSET) != setup.page_address
        || word(page, 0) & 0x8000_0000 == 0
        || pointer(page, 0x38) != 0
        || pointer(page, PAGE_ITEMS_OFFSET) != setup.items
        || pointer(page, PAGE_POINTERS_OFFSET) != setup.event_table
        || pointer(page, 0x40) != setup.layout
        || u32::from(half(page, PAGE_COUNT_OFFSET)) != setup.item_count
        || half(layout, 0) == 0
        || word(page, 0x48) != u32::from(half(layout, 0))
        || anchor.index >= setup.item_count
    {
        return Err(Error::Object(
            "resource publisher native page/layout mismatch".into(),
        ));
    }
    // The firmware indexes each rectangle list modulo rows. Verify every
    // retained rectangle range instead of treating nonzero pointers as proof.
    for offset in [8, 0x10, 0x18] {
        mapped(pointer(layout, offset), usize::from(half(layout, 0)) * 8)?;
    }
    if half(layout, 0x20) != 0 {
        mapped(pointer(layout, 0x28), usize::from(half(layout, 0x20)) * 8)?;
    }
    mapped(setup.items, setup.item_count as usize * ITEM_SIZE as usize)?;
    mapped(setup.event_table, setup.item_count as usize * 8)?;
    let template_address = setup
        .items
        .checked_add(u64::from(anchor.index) * ITEM_SIZE)
        .ok_or_else(|| Error::Object("resource template address overflows".into()))?;
    let template = mapped(template_address, ITEM_SIZE as usize)?;
    if word(template, 0x18) != anchor.item_id
        || word(template, 0x10) & ((1 << 4) | (1 << 9) | (1 << 13)) != 0
    {
        return Err(Error::Object(
            "resource template is not the stock static-label item".into(),
        ));
    }
    let event_pointer_address = setup
        .event_table
        .checked_add(u64::from(anchor.index) * 8)
        .ok_or_else(|| Error::Object("resource event pointer address overflows".into()))?;
    let event_template_address = pointer(mapped(event_pointer_address, 8)?, 0);
    if event_template_address & 7 != 0 {
        return Err(Error::Object(
            "resource event template is not aligned".into(),
        ));
    }
    let mut event_template_bytes = None;
    let mut opening_records = [0u32; 4];
    for index in 0..256u64 {
        let address = event_template_address
            .checked_add(index * EVENT_SIZE)
            .ok_or_else(|| Error::Object("resource event address overflows".into()))?;
        let record = mapped(address, EVENT_SIZE as usize)?;
        let code = word(record, 0);
        let action = pointer(record, EVENT_ACTION_OFFSET);
        let guard = pointer(record, EVENT_GUARD_OFFSET);
        let next = word(record, EVENT_NEXT_OFFSET);
        for function in [action, guard] {
            if function != 0 {
                if function & 3 != 0 {
                    return Err(Error::Object(
                        "resource native event function is unaligned".into(),
                    ));
                }
                mapped(function, 4)?;
            }
        }
        if next > events.nav_last {
            return Err(Error::Object(
                "resource event navigation value is out of bounds".into(),
            ));
        }
        if code == events.terminator {
            if action != 0 || guard != 0 || next != events.nav_first {
                return Err(Error::Object(
                    "resource event terminator is not inert".into(),
                ));
            }
            event_template_bytes = Some((index + 1) * EVENT_SIZE);
            break;
        }
        for (position, activation) in events.activation.iter().enumerate() {
            if code == *activation {
                if action == 0 || next >= events.nav_first {
                    return Err(Error::Object(
                        "resource opening event is not a native open record".into(),
                    ));
                }
                opening_records[position] += 1;
            }
        }
    }
    let event_template_bytes = event_template_bytes
        .ok_or_else(|| Error::Object("resource event template does not terminate".into()))?;
    if opening_records != [1; 4] {
        return Err(Error::Object(
            "resource event template must carry each declared open event once".into(),
        ));
    }
    let open_events = events
        .activation
        .iter()
        .map(|code| format!("{code:#x}u"))
        .collect::<Vec<_>>()
        .join(", ");
    // No string-bank capacity is declared by this profile. A proven existing
    // label establishes a conservative prefix bound, never an invented slot.
    let string_count = word(template, 0)
        .checked_add(1)
        .ok_or_else(|| Error::Object("resource string bound overflows".into()))?;
    let elements_address = pointer(page, PAGE_ELEMENT_OFFSET);
    let mut elements_bytes = None;
    for index in 0..nloader_profile::MENU_ELEMENT_MAX {
        let address = elements_address
            .checked_add(index * ELEMENT_SIZE as u64)
            .ok_or_else(|| Error::Object("resource elements address overflows".into()))?;
        let element = mapped(address, ELEMENT_SIZE)?;
        if word(element, ELEMENT_TYPE_OFFSET) == 0 {
            elements_bytes = Some((index + 1) * ELEMENT_SIZE as u64);
            break;
        }
    }
    let elements_bytes =
        elements_bytes.ok_or_else(|| Error::Object("resource elements do not terminate".into()))?;
    // The live Setup page the clone copies: the stock rows plus the NLoader
    // row and, when declared, the Apps row (MenuSpec::new_count). Counting
    // only one added row made core's check of the copied arrays refuse the
    // page (items_bytes below its item count), so the boot's pass never
    // opened on a build with the Apps row.
    let count = setup
        .item_count
        .checked_add(1 + u32::from(setup.apps.is_some()))
        .filter(|count| *count < u32::from(u16::MAX))
        .ok_or_else(|| Error::Object("resource page cannot append another item".into()))?;
    let words = template
        .chunks_exact(4)
        .map(|bytes| format!("{:#x}u", word(bytes, 0)))
        .collect::<Vec<_>>()
        .join(", ");
    let (ready_function, ready_binding) = if profile.services.native_card.is_some() {
        (
            r#"extern const struct nlr_native_card_services nlr_native_card_services;
static int32_t nlr_model_resource_can_publish(void *context)
{
    (void)context;
    struct nlr_runtime *runtime = nlr_runtime_find(&nlr_services, 0);
    if (!runtime) return NLR_NOT_READY;
    nlr_model_resource_initialize(runtime);
    return nlr_resource_clone_ready(&runtime->resource_clone,
                                    nlr_native_card_services.menu.target_context_offset);
}
"#,
            "    .can_publish = nlr_model_resource_can_publish,\n",
        )
    } else {
        ("", "")
    };
    Ok(format!(
        "#include \"nlr/resource.h\"\n#include \"nlr/runtime.h\"\n#include \"nlr/native_card.h\"\n\
         extern const struct nlr_services nlr_services;\n\
         static const uint32_t nlr_resource_open_events[4] = {{ {open_events} }};\n\
         /* Profile-mapped stock Setup target; clone storage lives only in RAM. */\n\
         static const struct nlr_resource_clone_config nlr_resource_config = {{\n\
         \x20   .allocator = &nlr_services,\n\
         \x20   .window = (struct nlr_resource_window *){window_address:#x}UL,\n\
         \x20   .original_page = (const struct nlr_resource_page *){page_address:#x}UL,\n\
         \x20   .item_template = {{ .words = {{ {words} }} }},\n\
         \x20   .event_template = (const struct nlr_resource_event *){event_template_address:#x}UL,\n\
         \x20   .event_template_bytes = {event_template_bytes},\n\
         \x20   .open_events = nlr_resource_open_events, .open_event_count = 4,\n\
         \x20   .window_bytes = 0x60, .page_bytes = 0x50,\n\
         \x20   .items_bytes = {items_bytes}, .event_pointers_bytes = {pointers_bytes},\n\
         \x20   .elements_bytes = {elements_bytes}, .layout_bytes = 0x30,\n\
         \x20   .string_count = {string_count},\n\
         \x20   .event_terminator = {terminator:#x}, .no_jump = {no_jump:#x},\n\
         }};\n\
         static void nlr_model_resource_initialize(struct nlr_runtime *runtime)\n\
         {{\n\
         \x20   if (!runtime->resource_clone.config.allocator) {{\n\
         \x20       uint8_t *out = (void *)&runtime->resource_clone.config;\n\
         \x20       const uint8_t *in = (const void *)&nlr_resource_config;\n\
         \x20       for (uint32_t i = 0; i < sizeof(nlr_resource_config); ++i) out[i] = in[i];\n\
         \x20   }}\n\
         }}\n\
         {ready_function}\n\
         static int32_t nlr_model_resource_publish(void *context,\n\
         \x20                                        const struct nlr_menu_test_item *item)\n\
         {{\n\
         \x20   (void)context;\n\
         \x20   struct nlr_runtime *runtime = nlr_runtime_find(&nlr_services, 0);\n\
         \x20   if (!runtime) return NLR_NOT_READY;\n\
         \x20   nlr_model_resource_initialize(runtime);\n\
         \x20   return nlr_resource_clone_publish(&runtime->resource_clone, item);\n\
         }}\n\
         const struct nlr_resource_services nlr_resource_services = {{\n\
         \x20   .publish = nlr_model_resource_publish, .context = 0,\n\
         {ready_binding}\
         }};\n",
        page_address = setup.page_address,
        items_bytes = u64::from(count) * ITEM_SIZE,
        pointers_bytes = u64::from(count) * 8,
        terminator = events.terminator,
        no_jump = events.nav_first,
    ))
}
