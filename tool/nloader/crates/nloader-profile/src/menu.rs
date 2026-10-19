//! Menu records needed by the fixed Setup entry and NLoader's own page.
//! Recording them does not insert a row or authorize a menu hook.
use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Menu {
    pub window_table: Option<u64>,
    pub events: Option<MenuEvents>,
    pub record_sizes: Option<MenuRecordSizes>,
    /// Target of the NLoader entry, inserted at the declared entry index.
    pub setup: Option<MenuPage>,
    /// Runtime text platform the entry row's label binds to.
    pub text_platform: Option<MenuTextPlatform>,
    /// Required for private positive tokens; legacy stock slots stay explicit.
    pub private_text: Option<PrivateText>,
    /// NLoader's own second-level page. It uses all-zero holes of the stock
    /// window table and clones a stock list page, so no stock page is
    /// modified.
    pub page: Option<MenuOwnPage>,
}

/// Firmware-assigned event and navigation values. Navigation evidence covers
/// the family dispatcher, including the instructions consuming these values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MenuEvents {
    pub activation: [u32; 4],
    pub back: [u32; 3],
    pub ok: u32,
    pub terminator: u32,
    pub nav_first: u32,
    pub nav_back: u32,
    pub nav_reenter: u32,
    pub nav_last: u32,
    pub navigation_address: u64,
    pub navigation_sha256: String,
    pub lookup_address: u64,
    pub lookup_sha256: String,
}

/// NLoader's own page. The window table is indexed by id with stride 0x60
/// and is otherwise full, so the window and its page record take two of the
/// table's all-zero holes: page records are written at runtime, and those
/// holes are the only writable bytes that can be shown to have no
/// references. The page is a stock list page cloned: its title bar, layout
/// and row style come from the template, and its title and row label read
/// runtime text slots. Its handler block is generated: the template's footer
/// handler plus NLoader's own page entry, which binds the title through the
/// stock text functions; the page rung adds a status line to the row, and
/// from load-only on the entry reads the card directory into it. No
/// page-specific stock code runs on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MenuOwnPage {
    #[serde(default)]
    pub refresh: Option<MenuPageRefresh>,
    /// Window id taken from an all-zero hole; must stay below the first
    /// navigation sentinel.
    pub window_id: u32,
    /// Second hole, borrowed for the page record.
    pub page_record: u64,
    /// Stock list page cloned for the window record, the page record, the
    /// title bar elements and the row item (its first row).
    pub template_window: u32,
    pub template_page: u64,
    /// Stock row event template. Directory lists clone it and replace only
    /// activation and back actions; movement and all guards are preserved.
    /// Legacy one-row diagnostics may reuse a table only when its open
    /// records already stay or return, never enter a stock page.
    pub row_event_table: u64,
    /// Stock Setup row event table cloned for the NLoader row. Its open
    /// records must point at `template_window`; generation retargets them to
    /// `window_id` and changes nothing else.
    pub row_template_event_table: u64,
    /// The page title: a text slot of its own and the format the stock title
    /// chain stores with (`ui.title_chain`). The text is the entry row's, so
    /// the page is named like the row that opens it.
    pub title_slot: u32,
    pub title_format: u32,
    /// The page row: label from a runtime text slot, flags on the type-3
    /// text path, item id unused elsewhere.
    pub item_id: u32,
    pub item_flags: u32,
    pub item_slot: u32,
    pub item_style: u32,
    pub item_text: String,
    /// One dedicated runtime slot per physical list row; empty keeps the
    /// one-row diagnostic page. The directory list requires exactly 64.
    #[serde(default)]
    pub row_slots: Vec<u32>,
    #[serde(default)]
    pub row_hide: Option<u64>,
    #[serde(default)]
    pub row_hide_stock: Vec<u8>,
    #[serde(default)]
    pub selected_offset: Option<u32>,
    #[serde(default)]
    pub viewport_bottom: Option<u16>,
    /// Item words every row record takes in place of the template's, as
    /// `[offset, value]` pairs on the 44-byte record: the row kind, icon and
    /// help ids of plain rows. Offsets are 4-aligned inside the record and
    /// never the label slot (0), flags (0x10) or item id (0x18) the clone
    /// owns.
    #[serde(default)]
    pub row_words: Vec<[u32; 2]>,
    /// A stock page record whose flags word and row layout the page takes in
    /// place of the template's, so its rows draw like that page's.
    #[serde(default)]
    pub style_page: Option<u64>,
    /// NLoader writes the page record's item count before every build (the
    /// Setup row's open records run its open action), so the firmware builds
    /// only the rows a view shows.
    #[serde(default)]
    pub dynamic_rows: bool,
    /// A second all-zero window-table hole for the details: the list opens
    /// it and back pops it, so the page is never entered again shorter (the
    /// firmware leaves a re-entered window's longer rows on screen). It
    /// shares the page record, rows and handlers.
    #[serde(default)]
    pub detail_window_id: Option<u32>,
    /// The camera's own row kinds a program page may use (ABI 6 ui_rows):
    /// the stock toggle switch, a text value at the right, text rows the
    /// cursor passes. Without this table a page of row kinds is refused.
    #[serde(default)]
    pub rows: Option<MenuRows>,
    /// The camera's keyboard a program may open (ABI 6 ui_input). Without
    /// this table ui_input answers that there is none.
    #[serde(default)]
    pub keyboard: Option<MenuKeyboard>,
    /// The stock in-place rebuild the page's actions use, so that a view
    /// with fewer rows leaves nothing of a longer one behind. Without it
    /// the page is refreshed and re-entered and never shrinks.
    #[serde(default)]
    pub rebuild: Option<MenuRebuild>,
    /// The camera's caution box a program may open (ABI 6 ui_caution), on
    /// the keyboard's window id. Without it ui_caution answers that there
    /// is none.
    #[serde(default)]
    pub caution: Option<MenuCaution>,
}

/// The camera's caution box (`menu.page.caution`): a clone of a stock
/// Yes / No popup, built by the core at run time beside the keyboard, whose
/// window id it shares. The template's Yes and No actions become the
/// core's in the copies of its two items' event tables (the keyboard's
/// MENU and back events give up here too); the core's entry stores the
/// text in `text_slot` and turns the message panel (widget `panel`) to
/// that slot with `panel_text`, and puts a question's cursor on No with
/// `cursor_set`. A message has one button, labelled `ok_label`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MenuCaution {
    pub template_window: u32,
    pub yes_action: u64,
    pub no_action: u64,
    pub panel: u32,
    pub text_slot: u32,
    pub text_format: u32,
    pub ok_label: u32,
    /// (panel, slot, mode): the panel's text source.
    pub panel_text: u64,
    pub panel_text_stock: Vec<u8>,
    /// (window, item id): the cursor.
    pub cursor_set: u64,
    pub cursor_set_stock: Vec<u8>,
}

impl MenuCaution {
    /// The two stock functions with their entry fingerprints.
    pub fn functions(&self) -> [(&'static str, u64, &Vec<u8>); 2] {
        [
            (
                "menu.page.caution.panel_text",
                self.panel_text,
                &self.panel_text_stock,
            ),
            (
                "menu.page.caution.cursor_set",
                self.cursor_set,
                &self.cursor_set_stock,
            ),
        ]
    }
}

/// The firmware's own way of drawing a list again after it changed
/// (`menu.page.rebuild`): `rebuild(type, id)` runs the window's leave,
/// tears it down and builds it again from its page record, clearing the
/// layer its rows draw on first (a re-entry does not); `present(source,
/// a, b)` shows the result. The stock callers pass the same source and
/// words every time, and their action then stays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MenuRebuild {
    pub rebuild: u64,
    pub rebuild_stock: Vec<u8>,
    pub present: u64,
    pub present_stock: Vec<u8>,
    pub present_source: u64,
    pub present_source_stock: Vec<u8>,
    pub present_args: [u32; 2],
}

impl MenuRebuild {
    /// The three stock functions with their entry fingerprints.
    pub fn functions(&self) -> [(&'static str, u64, &Vec<u8>); 3] {
        [
            (
                "menu.page.rebuild.rebuild",
                self.rebuild,
                &self.rebuild_stock,
            ),
            (
                "menu.page.rebuild.present",
                self.present,
                &self.present_stock,
            ),
            (
                "menu.page.rebuild.present_source",
                self.present_source,
                &self.present_source_stock,
            ),
        ]
    }
}

/// The camera's text-entry keyboard (`menu.page.keyboard`): a clone of a
/// stock keyboard window, built by the core at run time. A window record
/// must sit in the window table, and the only entry left is the one the
/// page record is built into: the core moves the page record into its own
/// memory before the keyboard's window takes the entry. The clone keeps
/// the template's engine, layout and other events; save hands the text to
/// the program, MENU and back give up, help does nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MenuKeyboard {
    /// The keyboard's window id: the entry `menu.page.page_record` is.
    pub window_id: u32,
    /// The stock keyboard window cloned (its page, events and handlers).
    pub template_window: u32,
    /// Its events: save and leave, MENU, back, and help (0: none).
    pub save_event: u32,
    pub menu_event: u32,
    pub back_event: u32,
    #[serde(default)]
    pub help_event: u32,
    /// (params, window): the engine takes the text and its limits.
    pub open: u64,
    pub open_stock: Vec<u8>,
    /// (text): the text entered, bit 0 when accepted.
    pub take: u64,
    pub take_stock: Vec<u8>,
    /// (window, 0): what every stock keyboard's enter ends with.
    pub shown: u64,
    pub shown_stock: Vec<u8>,
}

impl MenuKeyboard {
    /// The three engine entries with their stock fingerprints.
    pub fn functions(&self) -> [(&'static str, u64, &Vec<u8>); 3] {
        [
            ("menu.page.keyboard.open", self.open, &self.open_stock),
            ("menu.page.keyboard.take", self.take, &self.take_stock),
            ("menu.page.keyboard.shown", self.shown, &self.shown_stock),
        ]
    }
}

/// How rows of the camera's own kinds are built (`menu.page.rows`). The
/// firmware builds a row from its item record, so a kind is two words of
/// it -- the flags at +0x10 and the value at +0x14 -- which the core writes
/// into its own copy of the records before every build; three stock
/// functions finish what the records cannot say after the build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MenuRows {
    /// Flags a switch row adds (its > mark is cleared): the stock toggle.
    pub switch_flags: u32,
    /// The ON and OFF pictures the switch starts from (+0x14).
    pub switch_on: u32,
    pub switch_off: u32,
    /// Flags a row with a text value adds; +0x14 is then a text slot.
    pub select_flags: u32,
    /// The text format the value is stored with.
    pub select_format: u32,
    /// Item styles (+0x1c, one u16 per direction) a row with a value
    /// takes, for a wider value column; 0 keeps the row's own.
    #[serde(default)]
    pub select_style: u32,
    /// Page flag that makes the cursor pass disabled rows.
    pub skip_flag: u32,
    /// Window offset of the built rows' widget table.
    pub widget_table: u32,
    /// (table, row, 0) -> a built row's widget, and its stock entry bytes.
    pub row_get: u64,
    pub row_get_stock: Vec<u8>,
    /// (row widget, on): the toggle switch's state.
    pub switch_set: u64,
    pub switch_set_stock: Vec<u8>,
    /// (widget, enabled): greyed, and passed by the cursor under skip_flag.
    pub widget_enable: u64,
    pub widget_enable_stock: Vec<u8>,
    /// The declared function's second argument means "disabled" rather
    /// than "enabled" (the Z 8's only stock primitive, whose callers invert
    /// their enable flag before the call). The core then passes 1 to grey a
    /// row. False keeps the (widget, enabled) reading.
    #[serde(default)]
    pub widget_enable_inverted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MenuPageRefreshFamily {
    #[serde(rename = "z8_list_page_refresh_v1")]
    Z8ListPageRefreshV1,
}

/// Original in-place page refresh. Its scratch return register is ignored;
/// only the window pointer is passed by the core adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MenuPageRefresh {
    pub family: MenuPageRefreshFamily,
    pub function: u64,
    pub body: ExecutionBody,
    pub entry_dispatch: u64,
    pub layout_changed: u64,
    pub display_refresh: u64,
}
/// Runtime text platform (page-independent): descriptor table, buffers, font
/// cache and the static font records, plus the slot the NLoader entry label
/// binds to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MenuTextPlatform {
    pub descriptor_base: u64,
    pub slot_stride: u32,
    pub buffer_base: u64,
    pub buffer_stride: u32,
    pub font_cache_base: u64,
    pub font_record_base: u64,
    pub entry_slot: u32,
    pub entry_style: u32,
    pub entry_text: String,
    /// The init-tail call the prefill trampoline retargets, and the original
    /// callee it tail-branches back to (both model addresses).
    pub prefill_call_site: u64,
    pub prefill_return: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MenuRecordSizes {
    pub window: u32,
    pub page: u32,
    pub item: u32,
    pub event: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MenuPage {
    pub window_id: u32,
    pub page_address: u64,
    pub items: u64,
    pub item_count: u32,
    /// Address of the per-item array of event-table pointers.
    pub event_table: u64,
    pub layout: u64,
    /// Setup only: the stock row that anchors the NLoader entry position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<MenuItemRef>,
    /// Setup only: the NLoader entry row. It takes `index` -- the anchor
    /// row's place, shifting the anchor and everything after it down one
    /// row, or `item_count`, after every stock row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<MenuEntrySpec>,
    /// Setup only: the Apps row, opening the loader's
    /// page on its list of applications. Same record as the entry row, its
    /// own label slot and item id; with it the page gains two rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apps: Option<MenuAppsSpec>,
    /// Setup only: the stock code that saves and restores the Setup cursor
    /// as a raw row number (crate::setup_cursor). With it the build stores
    /// stock row numbers there, so the two added rows never leave a row a
    /// stock page lacks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<crate::MenuSetupCursor>,
}
/// The Apps row: where it goes (a stock index it is inserted before, 0 for
/// the first row), its item id (unique in the page), the label flags (the
/// entry row's runtime-text combination) and the runtime text slot its
/// label is prefilled into at menu init, with that label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MenuAppsSpec {
    pub index: u32,
    pub item_id: u32,
    pub flags: u32,
    pub slot: u32,
    pub text: String,
}
/// The NLoader entry row: label comes from the runtime text platform slot,
/// flags are the on-device-proven text-slot combo, item id must be unique
/// within the page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MenuEntrySpec {
    pub index: u32,
    pub item_id: u32,
    pub flags: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MenuItemRef {
    pub index: u32,
    pub item_id: u32,
}
// Field offsets below describe this recovered record layout. Other layouts
// must get an explicit decoder rather than being interpreted at guessed offsets.
const SUPPORTED_SIZES: MenuRecordSizes = MenuRecordSizes {
    window: 96,
    page: 80,
    item: 44,
    event: 32,
};
const LAYOUT_SIZE: u64 = 48;
/// Longest row event table accepted while scanning for the terminator.
const MENU_TABLE_MAX: u64 = 256;
/// Event records the core's copy of a keyboard's table holds, the
/// terminator included (core/include/nlr/menu.h NLR_INPUT_EVENTS_MAX).
pub const KEYBOARD_EVENTS_MAX: u64 = 24;

/// A stock Yes / No popup as the core clones it (`caution_template`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CautionTemplate {
    pub window: u64,
    pub handlers: u64,
    pub page: u64,
    pub items: u64,
    pub tables: u64,
    pub count_yes: u32,
    pub count_no: u32,
    pub no_item: u32,
}

/// A stock keyboard window as the core clones it (`keyboard_template`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardTemplate {
    pub window: u64,
    pub handlers: u64,
    pub page: u64,
    pub events: u64,
    pub event_count: u32,
}
/// Audited navigation dispatcher layout of this menu service family.
const MENU_NAVIGATION_BYTES: u64 = 0x154;
/// Element records: 0x44 bytes, type at +0x04, a zero type ends the list.
pub const MENU_ELEMENT_SIZE: u64 = 0x44;
/// Longest element list accepted while scanning for its terminator.
pub const MENU_ELEMENT_MAX: u64 = 16;
/// Element type that draws a string resource; the page title is the one
/// such element of a stock list page.
pub const MENU_ELEMENT_STRING: u32 = 1;
/// Element type that draws a runtime text slot (single-byte text).
pub const MENU_ELEMENT_SLOT_TEXT: u32 = 2;
/// Handler block: five pointers, each called through a null-checking
/// trampoline. Slot 2 is the footer handler shared by the list pages.
pub const MENU_HANDLER_SLOTS: usize = 5;
pub const MENU_HANDLER_FOOTER_SLOT: usize = 2;
/// Page flag of the list pages whose rows the generic builder lays out.
const MENU_PAGE_LIST_FLAG: u32 = 0x8000_0000;

impl Menu {
    pub(crate) fn is_empty(&self) -> bool {
        self.events.is_none()
            && self.window_table.is_none()
            && self.record_sizes.is_none()
            && self.setup.is_none()
            && self.text_platform.is_none()
            && self.private_text.is_none()
            && self.page.is_none()
    }
    fn pages(&self) -> impl Iterator<Item = (&'static str, &MenuPage)> {
        self.setup
            .as_ref()
            .map(|page| ("menu.setup", page))
            .into_iter()
    }
    /// The window record follows from the table base, ID, and stride; it is
    /// not stored separately so the two cannot disagree.
    pub fn window_address(&self, id: u32) -> Option<u64> {
        if id > u32::from(u16::MAX) {
            return None;
        }
        self.window_table?
            .checked_add(u64::from(id).checked_mul(u64::from(self.record_sizes?.window))?)
    }
}
impl Profile {
    fn check_menu_range(
        &self,
        field: &str,
        address: u64,
        length: u64,
        kind: MemorySegmentKind,
        alignment: u64,
        report: &mut ValidationReport,
    ) {
        if address % alignment != 0
            || !self
                .memory
                .segment_for_address(address, length)
                .is_ok_and(|segment| segment.kind == kind)
        {
            report.add(
                field,
                IssueKind::OutOfBounds,
                "menu record has invalid alignment, address space, or mapped extent",
            );
        }
        if self.memory.slack.as_ref().is_some_and(|slack| {
            address.checked_add(length).is_some_and(|end| {
                slack.range().overlaps(&AddressRange {
                    start: address,
                    end,
                })
            })
        }) {
            report.add(
                field,
                IssueKind::Conflict,
                "menu record overlaps reserved loader space",
            );
        }
    }
    pub(crate) fn validate_menu(&self, report: &mut ValidationReport) {
        if self.menu.is_empty() {
            return;
        }
        if self.menu.page.is_some()
            || self
                .menu
                .setup
                .as_ref()
                .is_some_and(|page| page.entry.is_some())
        {
            report.require("menu.events", self.menu.events.as_ref());
        }
        if let Some(events) = &self.menu.events {
            let unique: std::collections::BTreeSet<_> = events
                .activation
                .iter()
                .chain(&events.back)
                .chain(std::iter::once(&events.terminator))
                .collect();
            if unique.len() != 8
                || !events.activation.contains(&events.ok)
                || events.nav_first == 0
                || events.nav_first.checked_add(1) != Some(events.nav_back)
                || events.nav_back.checked_add(9) != Some(events.nav_reenter)
                || events.nav_reenter.checked_add(1) != Some(events.nav_last)
                || events.nav_last > 4095
            {
                report.add("menu.events", IssueKind::Invalid,
                    "events must be distinct and navigation values must match the family history layout");
            }
            self.check_menu_range(
                "menu.events.navigation_address",
                events.navigation_address,
                MENU_NAVIGATION_BYTES,
                MemorySegmentKind::Xip,
                4,
                report,
            );
            self.check_menu_range(
                "menu.events.lookup_address",
                events.lookup_address,
                self.abi
                    .ui
                    .unwrap_or(crate::UiFamily::Z8MenuV1)
                    .lookup_shape()
                    .0,
                MemorySegmentKind::Xip,
                4,
                report,
            );
            for (field, hash) in [
                ("menu.events.navigation_sha256", &events.navigation_sha256),
                ("menu.events.lookup_sha256", &events.lookup_sha256),
            ] {
                if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    report.add(
                        field,
                        IssueKind::Invalid,
                        "menu function requires a SHA-256 fingerprint",
                    );
                }
            }
        }
        let table = report.require("menu.window_table", self.menu.window_table);
        let sizes = report.require("menu.record_sizes", self.menu.record_sizes);
        let Some(sizes) = sizes else {
            return;
        };
        if sizes != SUPPORTED_SIZES {
            report.add(
                "menu.record_sizes",
                IssueKind::Unsupported,
                "menu record layout does not have an implemented decoder",
            );
            return;
        }
        if let Some(table) = table {
            self.check_menu_range(
                "menu.window_table",
                table,
                u64::from(sizes.window),
                MemorySegmentKind::Ram,
                8,
                report,
            );
        }
        if let Some(page) = &self.menu.setup {
            if page
                .firmware_version
                .is_some_and(|anchor| anchor.index >= page.item_count)
            {
                report.add(
                    "menu.setup.firmware_version",
                    IssueKind::OutOfBounds,
                    "Firmware version row index exceeds the setup item count",
                );
            }
            if let Some(entry) = &page.entry {
                let field = "menu.setup.entry";
                if entry.index > page.item_count {
                    report.add(
                        field,
                        IssueKind::OutOfBounds,
                        "entry index exceeds the setup item count",
                    );
                }
                // Either the anchor's place (the row before Firmware
                // version) or after every stock row: the two positions the
                // firmware was seen to build and navigate (hidden rows at
                // the end are skipped by layout and cursor alike).
                if page.firmware_version.is_some_and(|anchor| {
                    anchor.index != entry.index && entry.index != page.item_count
                }) {
                    report.add(
                        field,
                        IssueKind::Conflict,
                        "the entry must take the Firmware version anchor's index or follow every row",
                    );
                }
                // The label path: bit9 (widget text type 3, runtime slot)
                // set; the image (bit4) and UTF-16 (bit13) paths clear.
                if entry.flags & 0x200 == 0 || entry.flags & 0x10 != 0 || entry.flags & 0x2000 != 0
                {
                    report.add(
                        field,
                        IssueKind::Invalid,
                        "entry flags must select the type-3 runtime text slot path",
                    );
                }
                match &self.menu.text_platform {
                    Some(platform) => {
                        report.require("ui.text_store", self.ui.text_store);
                        if platform.entry_slot >= 300
                            && !self
                                .menu
                                .private_text
                                .as_ref()
                                .is_some_and(|p| p.contains(platform.entry_slot))
                        {
                            report.add(
                                "menu.text_platform.entry_slot",
                                IssueKind::OutOfBounds,
                                "slot must be < 300 (the builder clamps higher slots to 0)",
                            );
                        }
                        let text = platform.entry_text.as_bytes();
                        if text.is_empty() || text.len() > 50 {
                            report.add(
                                "menu.text_platform.entry_text",
                                IssueKind::Invalid,
                                "entry text must fit the ASCII writer (1..=50 bytes)",
                            );
                        }
                    }
                    None => report.add(
                        "menu.text_platform",
                        IssueKind::Missing,
                        "the entry row label binds to a runtime text slot",
                    ),
                }
                if let Some(apps) = &page.apps {
                    let field = "menu.setup.apps";
                    if apps.index > page.item_count {
                        report.add(
                            field,
                            IssueKind::OutOfBounds,
                            "apps index exceeds the setup item count",
                        );
                    }
                    if apps.item_id == entry.item_id || apps.item_id > 0xffff {
                        report.add(
                            field,
                            IssueKind::Conflict,
                            "the apps row needs an item id of its own",
                        );
                    }
                    if apps.flags & 0x200 == 0 || apps.flags & 0x10 != 0 || apps.flags & 0x2000 != 0
                    {
                        report.add(
                            field,
                            IssueKind::Invalid,
                            "apps flags must select the type-3 runtime text slot path",
                        );
                    }
                    let taken = self.menu.text_platform.as_ref().map(|p| p.entry_slot)
                        == Some(apps.slot)
                        || self.menu.page.as_ref().is_some_and(|own| {
                            own.title_slot == apps.slot
                                || own.item_slot == apps.slot
                                || own.row_slots.contains(&apps.slot)
                                || own
                                    .caution
                                    .as_ref()
                                    .is_some_and(|c| c.text_slot == apps.slot)
                        });
                    // With private text the label is the family's exact
                    // Apps token (checked with the namespace); otherwise a
                    // stock slot below 300, which the builder keeps.
                    let private_apps = self
                        .menu
                        .private_text
                        .as_ref()
                        .map(|p| p.token_base.saturating_add(p.apps_index));
                    let slot_ok = match private_apps {
                        Some(token) => apps.slot == token,
                        None => apps.slot < 300,
                    };
                    if !slot_ok || taken {
                        report.add(
                            field,
                            IssueKind::Conflict,
                            "the apps label needs its own runtime text slot: below 300, or the exact private Apps token",
                        );
                    }
                    if apps.text.is_empty()
                        || apps.text.len() > 50
                        || !apps.text.bytes().all(|b| (0x20..0x7f).contains(&b))
                    {
                        report.add(
                            field,
                            IssueKind::Invalid,
                            "apps text must fit the ASCII writer (1..=50 printable bytes)",
                        );
                    }
                }
            }
        }
        if let Some(page) = &self.menu.page {
            let field = "menu.page";
            if page.window_id == 0
                || self
                    .menu
                    .events
                    .as_ref()
                    .is_none_or(|events| page.window_id >= events.nav_first)
            {
                report.add(
                    "menu.page.window_id",
                    IssueKind::OutOfBounds,
                    "window id must be a table index below the navigation sentinels",
                );
            }
            if [
                self.menu.setup.as_ref().map(|p| p.window_id),
                Some(page.template_window),
            ]
            .into_iter()
            .flatten()
            .any(|id| id == page.window_id)
            {
                report.add(
                    "menu.page.window_id",
                    IssueKind::Conflict,
                    "the NLoader page must not take a window the firmware uses",
                );
            }
            for (address, length, kind, alignment) in [
                (
                    page.page_record,
                    u64::from(sizes.page),
                    MemorySegmentKind::Ram,
                    8,
                ),
                (
                    page.template_page,
                    u64::from(sizes.page),
                    MemorySegmentKind::Ram,
                    8,
                ),
                (
                    page.row_event_table,
                    u64::from(sizes.event),
                    MemorySegmentKind::Xip,
                    8,
                ),
                (
                    page.row_template_event_table,
                    u64::from(sizes.event),
                    MemorySegmentKind::Xip,
                    8,
                ),
            ] {
                self.check_menu_range(field, address, length, kind, alignment, report);
            }
            if let Some(window) = self.menu.window_address(page.window_id) {
                self.check_menu_range(
                    "menu.page.window_id",
                    window,
                    u64::from(sizes.window),
                    MemorySegmentKind::Ram,
                    8,
                    report,
                );
            }
            // The page entry titles the page and writes the row through the
            // stock text functions, in the widget container the stock pages
            // use, following the stock title chain.
            report.require("ui.widget_find", self.ui.widget_find);
            report.require("ui.text_bind", self.ui.text_bind);
            report.require("ui.text_store", self.ui.text_store);
            report.require("ui.widget_show", self.ui.widget_show);
            report.require("ui.title_chain", self.ui.title_chain.as_ref());
            if let Some(offset) = report.require("menu.page.selected_offset", page.selected_offset)
            {
                if offset != 0x32 {
                    report.add(
                        "menu.page.selected_offset",
                        IssueKind::Unsupported,
                        "the supported v2 window layout stores the selected row at 0x32",
                    );
                }
            }
            if page
                .viewport_bottom
                .is_some_and(|bottom| ![424, 480].contains(&bottom))
            {
                report.add(
                    "menu.page.viewport_bottom",
                    IssueKind::Invalid,
                    "supported list viewport bottoms are 424 and 480",
                );
            }
            if !page.row_slots.is_empty() {
                if page.row_slots.len() != 64
                    || page.row_slots.first() != Some(&page.item_slot)
                    || page.item_flags & (1 << 20) == 0
                    || page.item_id <= 0x4dd3
                    || page.item_id.checked_add(63).is_none_or(|end| end >= 0xfffe)
                    || self
                        .menu
                        .setup
                        .as_ref()
                        .and_then(|p| p.entry.as_ref())
                        .is_some_and(|entry| {
                            (page.item_id..page.item_id.saturating_add(64)).contains(&entry.item_id)
                        })
                {
                    report.add("menu.page.row_slots", IssueKind::Invalid,
                        "list requires 64 slots, matching first slot, selected offset 0x32 and an unused ID range");
                }
                let mut used = std::collections::BTreeSet::new();
                for slot in &page.row_slots {
                    if *slot == 0
                        || (*slot >= 300
                            && !self
                                .menu
                                .private_text
                                .as_ref()
                                .is_some_and(|p| p.contains(*slot)))
                        || !used.insert(*slot)
                        || *slot == page.title_slot
                        || self
                            .menu
                            .text_platform
                            .as_ref()
                            .is_some_and(|p| p.entry_slot == *slot)
                    {
                        report.add("menu.page.row_slots", IssueKind::Conflict,
                            "list slots must be unique, nonzero, below 300 and distinct from title and entry");
                    }
                }
                if let Some(address) = report.require("menu.page.row_hide", page.row_hide) {
                    self.check_menu_range(
                        "menu.page.row_hide",
                        address,
                        page.row_hide_stock.len() as u64,
                        MemorySegmentKind::Xip,
                        4,
                        report,
                    );
                }
                if page.row_hide_stock.len() < 16 || page.row_hide_stock.len() % 4 != 0 {
                    report.add(
                        "menu.page.row_hide_stock",
                        IssueKind::Invalid,
                        "row hiding needs at least 16 bytes of aligned stock entry fingerprint",
                    );
                }
            }
            if page.title_slot >= 300
                && !self
                    .menu
                    .private_text
                    .as_ref()
                    .is_some_and(|p| p.contains(page.title_slot))
            {
                report.add(
                    "menu.page.title_slot",
                    IssueKind::OutOfBounds,
                    "slot must be < 300 (the builder clamps higher slots to 0)",
                );
            }
            if page.title_slot == page.item_slot
                || self
                    .menu
                    .text_platform
                    .as_ref()
                    .is_some_and(|platform| platform.entry_slot == page.title_slot)
            {
                report.add(
                    "menu.page.title_slot",
                    IssueKind::Conflict,
                    "the title is stored with its own format and needs a slot of its own",
                );
            }
            if page.title_format == 0 || page.title_format > 0xffff {
                report.add(
                    "menu.page.title_format",
                    IssueKind::Invalid,
                    "title format must be the 16-bit value the stock title chain passes",
                );
            }
            if let Some(offset) = report.require(
                "ui.widget_container_offset",
                self.ui.widget_container_offset,
            ) {
                if offset % 8 != 0 {
                    report.add(
                        "ui.widget_container_offset",
                        IssueKind::Invalid,
                        "container offset must be 8-byte aligned inside the window",
                    );
                }
            }
            if let Some(caution) = &page.caution {
                // On the keyboard's window, with a text slot of the
                // loader's own that no row or title uses, and a label.
                let slot_taken = page.row_slots.contains(&caution.text_slot)
                    || caution.text_slot == page.title_slot
                    || caution.text_slot == page.item_slot
                    || self
                        .menu
                        .text_platform
                        .as_ref()
                        .is_some_and(|t| t.entry_slot == caution.text_slot);
                // With private text the box's text is the family's status
                // token, which nothing else binds since the status rows were
                // retired; otherwise a stock slot below 300.
                let private_caution = self
                    .menu
                    .private_text
                    .as_ref()
                    .map(|p| p.token_base.saturating_add(p.status_index));
                let slot_ok = match private_caution {
                    Some(token) => caution.text_slot == token,
                    None => caution.text_slot != 0 && caution.text_slot < 300,
                };
                if page.keyboard.is_none()
                    || !slot_ok
                    || slot_taken
                    || caution.panel == 0
                    || caution.ok_label == 0
                    || caution.ok_label >= 0xffff
                    || caution.yes_action == 0
                    || caution.no_action == 0
                    || caution.yes_action == caution.no_action
                {
                    report.add(
                        "menu.page.caution",
                        IssueKind::Invalid,
                        "the caution box needs the keyboard, a text slot (the private \
                         family's status token, or a stock slot below 300) that no row, \
                         title or entry uses, a panel, a label and two distinct actions",
                    );
                }
                for (name, address, stock) in caution.functions() {
                    self.check_menu_range(
                        name,
                        address,
                        stock.len() as u64,
                        MemorySegmentKind::Xip,
                        4,
                        report,
                    );
                    if stock.len() < 16 || stock.len() % 4 != 0 {
                        report.add(
                            name,
                            IssueKind::Invalid,
                            "needs at least 16 bytes of aligned stock entry fingerprint",
                        );
                    }
                }
            }
            if let Some(rebuild) = &page.rebuild {
                // The action stays after the rebuild: only a dynamic page
                // has the stay navigation.
                if !page.dynamic_rows {
                    report.add(
                        "menu.page.rebuild",
                        IssueKind::Invalid,
                        "the in-place rebuild needs a dynamic page",
                    );
                }
                for (name, address, stock) in rebuild.functions() {
                    self.check_menu_range(
                        name,
                        address,
                        stock.len() as u64,
                        MemorySegmentKind::Xip,
                        4,
                        report,
                    );
                    if stock.len() < 16 || stock.len() % 4 != 0 {
                        report.add(
                            name,
                            IssueKind::Invalid,
                            "needs at least 16 bytes of aligned stock entry fingerprint",
                        );
                    }
                }
            }
            if let Some(keyboard) = &page.keyboard {
                // Its window takes the page record's entry, which no other
                // window of the page is; three distinct events; a dynamic
                // page (the core opens it from the page's own actions).
                let takes_record =
                    self.menu.window_address(keyboard.window_id) == Some(page.page_record);
                let ids = [keyboard.window_id, page.window_id, keyboard.template_window];
                let codes = [
                    keyboard.save_event,
                    keyboard.menu_event,
                    keyboard.back_event,
                ];
                if !page.dynamic_rows
                    || !takes_record
                    || ids.iter().enumerate().any(|(n, id)| ids[..n].contains(id))
                    || page.detail_window_id.is_some_and(|id| ids.contains(&id))
                    || codes.contains(&0)
                    || codes
                        .iter()
                        .enumerate()
                        .any(|(n, c)| codes[..n].contains(c))
                    || (keyboard.help_event != 0 && codes.contains(&keyboard.help_event))
                {
                    report.add(
                        "menu.page.keyboard",
                        IssueKind::Invalid,
                        "the keyboard needs a dynamic page, the entry the page record is \
                         built into as its window, a template of its own and three \
                         distinct events",
                    );
                }
                for (name, address, stock) in keyboard.functions() {
                    self.check_menu_range(
                        name,
                        address,
                        stock.len() as u64,
                        MemorySegmentKind::Xip,
                        4,
                        report,
                    );
                    if stock.len() < 16 || stock.len() % 4 != 0 {
                        report.add(
                            name,
                            IssueKind::Invalid,
                            "needs at least 16 bytes of aligned stock entry fingerprint",
                        );
                    }
                }
            }
            if let Some(rows) = &page.rows {
                // Every part present; the switch and value flags must not
                // be bits the row already uses (the > mark aside, which a
                // switch drops); one page flag bit; two distinct pictures;
                // a dynamic page, whose builds the core prepares, with a
                // label and a value slot for each of the 32 rows.
                let bit = |v: u32| v != 0 && v.is_power_of_two();
                if !page.dynamic_rows
                    || page.row_slots.len() < 64
                    || rows.switch_flags == 0
                    || rows.switch_flags & page.item_flags & !0x40 != 0
                    || rows.select_flags == 0
                    || rows.select_flags & page.item_flags != 0
                    || !bit(rows.skip_flag)
                    || rows.switch_on == rows.switch_off
                    || [rows.switch_on, rows.switch_off]
                        .iter()
                        .any(|id| *id == 0 || *id >= 0xffff)
                    || rows.widget_table == 0
                    || rows.widget_table % 8 != 0
                    || rows.widget_table >= 0x60
                {
                    report.add(
                        "menu.page.rows",
                        IssueKind::Invalid,
                        "row kinds need a dynamic 64-slot page, flags the row does not \
                         already use, one page flag bit, two distinct pictures and a \
                         window widget-table offset",
                    );
                }
                for (name, address, stock) in [
                    ("menu.page.rows.row_get", rows.row_get, &rows.row_get_stock),
                    (
                        "menu.page.rows.switch_set",
                        rows.switch_set,
                        &rows.switch_set_stock,
                    ),
                    (
                        "menu.page.rows.widget_enable",
                        rows.widget_enable,
                        &rows.widget_enable_stock,
                    ),
                ] {
                    self.check_menu_range(
                        name,
                        address,
                        stock.len() as u64,
                        MemorySegmentKind::Xip,
                        4,
                        report,
                    );
                    if stock.len() < 16 || stock.len() % 4 != 0 {
                        report.add(
                            name,
                            IssueKind::Invalid,
                            "needs at least 16 bytes of aligned stock entry fingerprint",
                        );
                    }
                }
            }
            // The row label takes the same type-3 runtime text path as the
            // Setup entry row, in a slot of its own.
            if page.item_flags & 0x200 == 0
                || page.item_flags & 0x10 != 0
                || page.item_flags & 0x2000 != 0
            {
                report.add(
                    "menu.page.item_flags",
                    IssueKind::Invalid,
                    "page row flags must select the type-3 runtime text slot path",
                );
            }
            if page.item_slot >= 300
                && !self
                    .menu
                    .private_text
                    .as_ref()
                    .is_some_and(|p| p.contains(page.item_slot))
            {
                report.add(
                    "menu.page.item_slot",
                    IssueKind::OutOfBounds,
                    "slot must be < 300 (the builder clamps higher slots to 0)",
                );
            }
            if self
                .menu
                .text_platform
                .as_ref()
                .is_some_and(|platform| platform.entry_slot == page.item_slot)
            {
                report.add(
                    "menu.page.item_slot",
                    IssueKind::Conflict,
                    "the page row needs a slot of its own, not the entry row's",
                );
            }
            let text = page.item_text.as_bytes();
            if text.is_empty() || text.len() > 50 {
                report.add(
                    "menu.page.item_text",
                    IssueKind::Invalid,
                    "page row text must fit the ASCII writer (1..=50 bytes)",
                );
            }
            if self
                .menu
                .setup
                .as_ref()
                .and_then(|p| p.entry.as_ref())
                .is_none()
            {
                report.add(
                    "menu.page",
                    IssueKind::Missing,
                    "the page is opened from the Setup entry row, which is not declared",
                );
            }
        }
        for (field, page) in self.menu.pages() {
            let Some(window) = self.menu.window_address(page.window_id) else {
                report.add(
                    format!("{field}.window_id"),
                    IssueKind::OutOfBounds,
                    "window ID cannot be represented in the window table",
                );
                continue;
            };
            if page.item_count == 0 || page.item_count > u32::from(u16::MAX) {
                report.add(
                    format!("{field}.item_count"),
                    IssueKind::Invalid,
                    "menu item count must fit a nonempty u16 range",
                );
            }
            for (address, length, kind, alignment) in [
                (window, u64::from(sizes.window), MemorySegmentKind::Ram, 8),
                (
                    page.page_address,
                    u64::from(sizes.page),
                    MemorySegmentKind::Ram,
                    8,
                ),
                (
                    page.items,
                    u64::from(page.item_count) * u64::from(sizes.item),
                    MemorySegmentKind::Xip,
                    4,
                ),
                (
                    page.event_table,
                    u64::from(page.item_count) * 8,
                    MemorySegmentKind::Xip,
                    8,
                ),
                (page.layout, LAYOUT_SIZE, MemorySegmentKind::Xip, 8),
            ] {
                self.check_menu_range(field, address, length, kind, alignment, report);
            }
        }
    }
    fn in_segment(&self, address: u64, kind: MemorySegmentKind) -> bool {
        self.memory
            .segment_for_address(address, 1)
            .is_ok_and(|segment| segment.kind == kind)
    }
    fn menu_bytes<'a>(&self, bytes: &'a [u8], address: u64, length: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(self.memory.address_to_offset(address, length).ok()?).ok()?;
        let length = usize::try_from(length).ok()?;
        bytes.get(start..start.checked_add(length)?)
    }
    /// Compare each declared page with the stock window, page, and layout
    /// records, and the Firmware version anchor with its stock item ID.
    pub(crate) fn validate_menu_bytes(&self, bytes: &[u8], report: &mut ValidationReport) {
        if self.menu.is_empty() || self.menu.record_sizes != Some(SUPPORTED_SIZES) {
            return;
        }
        for (field, page) in self.menu.pages() {
            let matched = (|| -> Option<bool> {
                let window = self.menu.window_address(page.window_id)?;
                let record = self.menu_bytes(bytes, window, 96)?;
                let stock = self.menu_bytes(bytes, page.page_address, 80)?;
                let layout = self.menu_bytes(bytes, page.layout, LAYOUT_SIZE)?;
                Some(
                    u32::from(u16_at(record, 2)?) == page.window_id
                        && u64_at(record, 0x50)? == page.page_address
                        && u32::from(u16_at(stock, 0x20)?) == page.item_count
                        && u64_at(stock, 0x10)? == page.items
                        && u64_at(stock, 0x18)? == page.event_table
                        && u64_at(stock, 0x40)? == page.layout
                        && u32_at(stock, 0x48)? == u32::from(u16_at(layout, 0)?),
                )
            })();
            if matched != Some(true) {
                report.add(
                    field,
                    IssueKind::Conflict,
                    "menu page fields differ from their mapped firmware bytes or layout",
                );
            }
            if let Some(anchor) = page.firmware_version {
                let matched = (|| -> Option<bool> {
                    let item = page
                        .items
                        .checked_add(u64::from(anchor.index).checked_mul(44)?)?;
                    Some(u32_at(self.menu_bytes(bytes, item, 44)?, 0x18)? == anchor.item_id)
                })();
                if anchor.index >= page.item_count || matched != Some(true) {
                    report.add(
                        format!("{field}.firmware_version"),
                        IssueKind::Conflict,
                        "Firmware version item ID differs from the stock row at that index",
                    );
                }
            }
        }
        self.validate_menu_event_bytes(bytes, report);
        self.validate_own_page_bytes(bytes, report);
    }

    fn validate_menu_event_bytes(&self, bytes: &[u8], report: &mut ValidationReport) {
        let Some(events) = &self.menu.events else {
            return;
        };
        let matched = self
            .menu_bytes(bytes, events.navigation_address, MENU_NAVIGATION_BYTES)
            .is_some_and(|body| {
                sha256(body).eq_ignore_ascii_case(&events.navigation_sha256)
                    && [
                        (0x34, 0x52800008 | (events.nav_first << 5)),
                        (0x50, 0x51000288 | (events.nav_back << 10)),
                        (0xbc, 0x7100029f | (events.nav_reenter << 10)),
                        (0xc4, 0x7100029f | (events.nav_last << 10)),
                    ]
                    .into_iter()
                    .all(|(offset, instruction)| u32_at(body, offset) == Some(instruction))
            });
        // Both families compare the terminator in the same registers; the
        // Z 6III build materialises its jump-table base with more
        // instructions, so the last two compares sit further in and its
        // lookup is four bytes longer.
        let (lookup_bytes, compares) = self
            .abi
            .ui
            .unwrap_or(crate::UiFamily::Z8MenuV1)
            .lookup_shape();
        let registers = [0x7100013f_u32, 0x7100017f, 0x7100013f, 0x7100013f];
        let lookup_matches = self
            .menu_bytes(bytes, events.lookup_address, lookup_bytes)
            .is_some_and(|body| {
                sha256(body).eq_ignore_ascii_case(&events.lookup_sha256)
                    && events.terminator <= 4095
                    && compares
                        .into_iter()
                        .zip(registers)
                        .all(|(offset, instruction)| {
                            u32_at(body, offset) == Some(instruction | (events.terminator << 10))
                        })
            });
        if !matched || !lookup_matches {
            report.add("menu.events", IssueKind::Conflict,
                "menu function fingerprints or decoded event/navigation values differ from firmware");
        }
    }

    /// The NLoader page's own byte checks: the two window-table holes it
    /// takes must still be all zero in the stock image, and every record it
    /// clones or points at must be the stock record the profile names — a
    /// list page with a footer handler to reuse, a terminating row table,
    /// and a Setup row table whose open records point at the
    /// template page.
    fn validate_own_page_bytes(&self, bytes: &[u8], report: &mut ValidationReport) {
        let Some(page) = &self.menu.page else {
            return;
        };
        let Some(events) = &self.menu.events else {
            return;
        };
        let zero = |address: u64, length: u64| -> bool {
            self.menu_bytes(bytes, address, length)
                .is_some_and(|slice| slice.iter().all(|byte| *byte == 0))
        };
        // Both holes are checked over the full window stride, not just the
        // bytes written, so a neighbour's record can never be clipped.
        let window = self.menu.window_address(page.window_id);
        if !window.is_some_and(|window| zero(window, 96)) {
            report.add(
                "menu.page.window_id",
                IssueKind::Conflict,
                "the window table entry is not an all-zero hole in the stock image",
            );
        }
        if !zero(page.page_record, 96) {
            report.add(
                "menu.page.page_record",
                IssueKind::Conflict,
                "the borrowed page record is not an all-zero hole in the stock image",
            );
        }
        // The template must be the stock list page the profile names: a menu
        // window pointing at that page, a page whose rows the generic builder
        // lays out, at least one row to take the style from, and an element
        // list that ends within bounds and carries exactly one title string.
        let template = (|| -> Option<(bool, u64)> {
            let record =
                self.menu_bytes(bytes, self.menu.window_address(page.template_window)?, 96)?;
            let stock = self.menu_bytes(bytes, page.template_page, 80)?;
            let elements = u64_at(stock, 0x08)?;
            let mut titles = 0;
            let mut terminated = false;
            for index in 0..MENU_ELEMENT_MAX {
                let element = self.menu_bytes(
                    bytes,
                    elements.checked_add(index * MENU_ELEMENT_SIZE)?,
                    MENU_ELEMENT_SIZE,
                )?;
                match u32_at(element, 4)? {
                    0 => {
                        terminated = true;
                        break;
                    }
                    MENU_ELEMENT_STRING => titles += 1,
                    _ => {}
                }
            }
            Some((
                u16_at(record, 0)? == 2
                    && u32::from(u16_at(record, 2)?) == page.template_window
                    && u64_at(record, 0x50)? == page.template_page
                    && u32_at(stock, 0)? & MENU_PAGE_LIST_FLAG != 0
                    && u16_at(stock, 0x20)? >= 1
                    && (page.viewport_bottom.is_none()
                        || (u16_at(stock, 0x28)? == 424 && u16_at(stock, 0x30)? == 424))
                    && self.in_segment(elements, MemorySegmentKind::Xip)
                    && terminated
                    && titles == 1,
                u64_at(record, 0x28)?,
            ))
        })();
        let template_handlers = match template {
            Some((true, handlers)) => Some(handlers),
            _ => {
                report.add(
                    "menu.page.template_page",
                    IssueKind::Conflict,
                    "the template is not the stock list page the profile names",
                );
                None
            }
        };
        // The generated handler block takes the template's footer handler;
        // the template must have one, and nothing else of its block is used.
        let footer = (|| -> Option<u64> {
            let block = self.menu_bytes(
                bytes,
                template_handlers.filter(|address| *address != 0)?,
                (MENU_HANDLER_SLOTS * 8) as u64,
            )?;
            u64_at(block, MENU_HANDLER_FOOTER_SLOT * 8)
        })();
        if !footer.is_some_and(|handler| self.memory.is_xip_range(handler, 4)) {
            report.add(
                "menu.page.template_window",
                IssueKind::Conflict,
                "the template's handler block has no footer handler in XIP to reuse",
            );
        }
        if !page.row_slots.is_empty() {
            let matches = page
                .row_hide
                .and_then(|address| {
                    self.menu_bytes(bytes, address, page.row_hide_stock.len() as u64)
                })
                .is_some_and(|stock| stock == page.row_hide_stock);
            if !matches {
                report.add(
                    "menu.page.row_hide_stock",
                    IssueKind::Conflict,
                    "row hiding function does not match its stock entry fingerprint",
                );
            }
        }
        if let Some(rows) = &page.rows {
            for (name, address, stock) in [
                ("menu.page.rows.row_get", rows.row_get, &rows.row_get_stock),
                (
                    "menu.page.rows.switch_set",
                    rows.switch_set,
                    &rows.switch_set_stock,
                ),
                (
                    "menu.page.rows.widget_enable",
                    rows.widget_enable,
                    &rows.widget_enable_stock,
                ),
            ] {
                let matches = self
                    .menu_bytes(bytes, address, stock.len() as u64)
                    .is_some_and(|found| found == stock.as_slice());
                if !matches {
                    report.add(
                        name,
                        IssueKind::Conflict,
                        "function does not match its stock entry fingerprint",
                    );
                }
            }
        }
        if let Some(caution) = &page.caution {
            for (name, address, stock) in caution.functions() {
                let matches = self
                    .menu_bytes(bytes, address, stock.len() as u64)
                    .is_some_and(|found| found == stock.as_slice());
                if !matches {
                    report.add(
                        name,
                        IssueKind::Conflict,
                        "function does not match its stock entry fingerprint",
                    );
                }
            }
            let template = page
                .keyboard
                .as_ref()
                .and_then(|keyboard| self.caution_template(bytes, caution, keyboard));
            if template.is_none() {
                report.add(
                    "menu.page.caution.template_window",
                    IssueKind::Conflict,
                    "the template is not a two-item popup with nothing but type, id, \
                     parent, handlers and page in its record, whose items' event tables \
                     terminate within 24 records, carry the Yes and No actions and the \
                     keyboard's MENU and back events once each",
                );
            }
        }
        if let Some(rebuild) = &page.rebuild {
            for (name, address, stock) in rebuild.functions() {
                let matches = self
                    .menu_bytes(bytes, address, stock.len() as u64)
                    .is_some_and(|found| found == stock.as_slice());
                if !matches {
                    report.add(
                        name,
                        IssueKind::Conflict,
                        "function does not match its stock entry fingerprint",
                    );
                }
            }
        }
        if let Some(keyboard) = &page.keyboard {
            for (name, address, stock) in keyboard.functions() {
                let matches = self
                    .menu_bytes(bytes, address, stock.len() as u64)
                    .is_some_and(|found| found == stock.as_slice());
                if !matches {
                    report.add(
                        name,
                        IssueKind::Conflict,
                        "function does not match its stock entry fingerprint",
                    );
                }
            }
            if self.keyboard_template(bytes, keyboard).is_none() {
                report.add(
                    "menu.page.keyboard.template_window",
                    IssueKind::Conflict,
                    "the template is not a one-item keyboard window with a full handler \
                     block, nothing but type, id, parent, handlers and page in its record, \
                     and an event table that terminates within 24 records and carries \
                     each declared event once",
                );
            }
        }
        // The page row's event table must be a real table that ends in the
        // terminator, and its open records may only stay or return: a row
        // on NLoader's page must never lead into a stock page.
        let row_table = (|| -> Option<bool> {
            let length = self.event_table_length(bytes, page.row_event_table)?;
            let table = self.menu_bytes(bytes, page.row_event_table, length * 32)?;
            if !page.row_slots.is_empty()
                && !events.back.iter().all(|code| {
                    table
                        .chunks_exact(32)
                        .filter(|record| {
                            u32_at(record, 0) == Some(*code)
                                && u32_at(record, 0x18) == Some(events.nav_back)
                        })
                        .count()
                        == 1
                })
            {
                return Some(false);
            }
            for record in table.chunks_exact(32) {
                if events.activation.contains(&u32_at(record, 0)?)
                    && page.row_slots.is_empty()
                    && !(events.nav_first..=events.nav_last).contains(&u32_at(record, 0x18)?)
                {
                    return Some(false);
                }
            }
            Some(true)
        })();
        if row_table != Some(true) {
            report.add(
                "menu.page.row_event_table",
                IssueKind::Conflict,
                "the reused row event table must terminate and only stay or return on open",
            );
        }
        // The Setup row table is cloned with only the open records
        // retargeted, so the stock table must carry all four of them and
        // they must open the template window.
        let row = (|| -> Option<bool> {
            let length = self.event_table_length(bytes, page.row_template_event_table)?;
            let table = self.menu_bytes(bytes, page.row_template_event_table, length * 32)?;
            let mut found = std::collections::BTreeSet::new();
            for record in table.chunks_exact(32) {
                if !events.activation.contains(&u32_at(record, 0)?) {
                    continue;
                }
                // next (+0x18) names the window the row opens; the action
                // (+0x08) is the stock stub that leaves it to the dispatcher.
                if u32_at(record, 0x18)? != page.template_window || u64_at(record, 8)? == 0 {
                    return Some(false);
                }
                if !found.insert(u32_at(record, 0)?) {
                    return Some(false);
                }
            }
            Some(found.len() == events.activation.len())
        })();
        if row != Some(true) {
            report.add(
                "menu.page.row_template_event_table",
                IssueKind::Conflict,
                "the Setup row template does not open the template window through all four open codes",
            );
        }
    }

    /// The stock keyboard window the profile names, as the core clones it:
    /// the addresses of its handler block, page and event table, and the
    /// table's record count with the terminator. The window record holds
    /// nothing the clone drops (type, id, parent, handlers and page only),
    /// the page has one item, every handler slot is code, and each event
    /// the clone changes occurs exactly once.
    pub fn keyboard_template(
        &self,
        bytes: &[u8],
        keyboard: &MenuKeyboard,
    ) -> Option<KeyboardTemplate> {
        let window = self.menu.window_address(keyboard.template_window)?;
        let record = self.menu_bytes(bytes, window, 96)?;
        let handlers = u64_at(record, 0x28)?;
        let page = u64_at(record, 0x50)?;
        let kept = [0..4usize, 8..16, 0x28..0x30, 0x50..0x58];
        if u16::from_le_bytes([record[0], record[1]]) == 0
            || u32::from(u16::from_le_bytes([record[2], record[3]])) != keyboard.template_window
            || u64_at(record, 8)? == 0
            || (0..96).any(|n| record[n] != 0 && !kept.iter().any(|range| range.contains(&n)))
        {
            return None;
        }
        let block = self.menu_bytes(bytes, handlers, 40)?;
        for slot in 0..5 {
            if !self.in_segment(u64_at(block, slot * 8)?, MemorySegmentKind::Xip) {
                return None;
            }
        }
        let page_record = self.menu_bytes(bytes, page, 80)?;
        if u16::from_le_bytes([page_record[0x20], page_record[0x21]]) != 1 {
            return None;
        }
        let pointers = u64_at(page_record, 0x18)?;
        let events = u64_at(self.menu_bytes(bytes, pointers, 8)?, 0)?;
        let count = self.event_table_length(bytes, events)?;
        let table = self.menu_bytes(bytes, events, count * 32)?;
        let once = |code: u32| {
            table
                .chunks_exact(32)
                .filter(|record| u32_at(record, 0) == Some(code))
                .count()
                == 1
        };
        let mut codes = vec![
            keyboard.save_event,
            keyboard.menu_event,
            keyboard.back_event,
        ];
        if keyboard.help_event != 0 {
            codes.push(keyboard.help_event);
        }
        if count > KEYBOARD_EVENTS_MAX || !codes.into_iter().all(once) {
            return None;
        }
        Some(KeyboardTemplate {
            window,
            handlers,
            page,
            events,
            event_count: count as u32,
        })
    }

    /// The stock Yes / No popup the profile names, as the core clones it:
    /// a popup page (flag 0x100) of two items, a window record holding
    /// nothing the clone drops, code in the handler block's first three
    /// slots, and two event tables that terminate within 24 records --
    /// the first with the Yes action, the second with the No action, both
    /// with the keyboard's MENU and back events once each.
    pub fn caution_template(
        &self,
        bytes: &[u8],
        caution: &MenuCaution,
        keyboard: &MenuKeyboard,
    ) -> Option<CautionTemplate> {
        let window = self.menu.window_address(caution.template_window)?;
        let record = self.menu_bytes(bytes, window, 96)?;
        let handlers = u64_at(record, 0x28)?;
        let page = u64_at(record, 0x50)?;
        let kept = [0..4usize, 8..16, 0x28..0x30, 0x50..0x58];
        if u16::from_le_bytes([record[0], record[1]]) == 0
            || u32::from(u16::from_le_bytes([record[2], record[3]])) != caution.template_window
            || u64_at(record, 8)? == 0
            || (0..96).any(|n| record[n] != 0 && !kept.iter().any(|range| range.contains(&n)))
        {
            return None;
        }
        let block = self.menu_bytes(bytes, handlers, 40)?;
        for slot in 0..5 {
            let code = u64_at(block, slot * 8)?;
            if (slot < 3 || code != 0) && !self.in_segment(code, MemorySegmentKind::Xip) {
                return None;
            }
        }
        let page_record = self.menu_bytes(bytes, page, 80)?;
        if u32_at(page_record, 0)? & 0x100 == 0
            || u16::from_le_bytes([page_record[0x20], page_record[0x21]]) != 2
        {
            return None;
        }
        let items = u64_at(page_record, 0x10)?;
        let item_records = self.menu_bytes(bytes, items, 88)?;
        let pointers = u64_at(page_record, 0x18)?;
        let tables = self.menu_bytes(bytes, pointers, 16)?;
        let mut counts = [0u32; 2];
        for (k, action) in [caution.yes_action, caution.no_action]
            .into_iter()
            .enumerate()
        {
            let events = u64_at(tables, k * 8)?;
            let count = self.event_table_length(bytes, events)?;
            let table = self.menu_bytes(bytes, events, count * 32)?;
            let codes = |code: u32| {
                table
                    .chunks_exact(32)
                    .filter(|record| u32_at(record, 0) == Some(code))
                    .count()
            };
            if count > KEYBOARD_EVENTS_MAX
                || !table
                    .chunks_exact(32)
                    .any(|record| u64_at(record, 8) == Some(action))
                || codes(keyboard.menu_event) != 1
                || codes(keyboard.back_event) != 1
            {
                return None;
            }
            counts[k] = count as u32;
        }
        Some(CautionTemplate {
            window,
            handlers,
            page,
            items,
            tables: pointers,
            count_yes: counts[0],
            count_no: counts[1],
            no_item: u32_at(item_records, 44 + 0x18)?,
        })
    }

    /// Record count of an event table, or None when it does not terminate
    /// within the accepted bound.
    fn event_table_length(&self, bytes: &[u8], address: u64) -> Option<u64> {
        for index in 0..MENU_TABLE_MAX {
            let record = self.menu_bytes(bytes, address.checked_add(index * 32)?, 32)?;
            if u32_at(record, 0)? == self.menu.events.as_ref()?.terminator {
                return Some(index + 1);
            }
        }
        None
    }
}
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}
