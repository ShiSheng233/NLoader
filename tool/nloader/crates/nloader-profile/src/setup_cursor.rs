//! The Setup cursor the firmware saves as a raw row number
//! (`[menu.setup.cursor]`).
//!
//! When the menu closes, the stock code stores the Setup window's cursor
//! (its cursor half-word plus its scroll half-word) in one setting; when the
//! menu opens on Setup again it writes that setting back as the cursor. A
//! second stock writer looks a row up by item id in the page's items and
//! stores its index there. Nothing checks the range. With the Apps row first
//! and NLoader last the page has two rows the stock page has not, so the
//! build sends the three stock calls through core: the two writers store a
//! stock row number (Apps as the stock first row, NLoader as Firmware
//! version, every other row as the stock row it shows), and the reader maps
//! it back. A camera flashed back to stock firmware then always restores a
//! row of its own page.
//!
//! Each site is declared with the stock instructions around it, and the
//! declaration is accepted only if those instructions are the exact
//! sequence the fields describe: the setting id loaded into w0, the cursor
//! and scroll half-words of the window, and a BL to the declared setter or
//! getter at the call. The bytes are then compared with the official module.
use crate::{IssueKind, Profile, ValidationReport};
use serde::{Deserialize, Serialize};

/// The three stock sites and the stock accessors they call.
///
/// * `save_site`: five instructions, `ldrh w8,[x0,#scroll]`,
///   `ldrh w9,[x0,#cursor]`, `movz w0,#setting`, `add w1,w9,w8`,
///   `bl setter` (the menu-close save of the Setup window).
/// * `lookup_site`: four instructions, `tbnz w8,#31,..`, `movz w0,#setting`,
///   `mov w1,w8`, `bl setter` (the writer that stores an index it looked up
///   by item id).
/// * `restore_site`: ten instructions starting at the Setup branch of the
///   restore, `movz w0,#setting`, `b call`, three other windows' branches,
///   `bl getter` (the call), `ldrh w8,[x19,#2]`, `mov w20,w0`,
///   `strh wzr,[x19,#scroll]`, `strh w20,[x19,#cursor]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MenuSetupCursor {
    /// The setting the stock code keeps the Setup cursor in.
    pub setting: u32,
    /// The stock setting setter `(id, value)` and getter `(id) -> value`.
    pub setter: u64,
    pub getter: u64,
    /// The window record's cursor and scroll half-words.
    pub cursor_offset: u32,
    pub scroll_offset: u32,
    pub save_site: u64,
    pub save_stock: Vec<u8>,
    pub lookup_site: u64,
    pub lookup_stock: Vec<u8>,
    pub restore_site: u64,
    pub restore_stock: Vec<u8>,
}

/// One redirected stock call: where the BL is, what it calls in the
/// official module and which core entry the build points it at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupCursorCall {
    pub site: u64,
    pub callee: u64,
    pub entry: &'static str,
}

/// Core's entries (core/menu_page.c).
pub const SETUP_CURSOR_SAVE_ENTRY: &str = "nlr_setup_cursor_save";
pub const SETUP_CURSOR_RESTORE_ENTRY: &str = "nlr_setup_cursor_restore";

const SAVE_WORDS: usize = 5;
const LOOKUP_WORDS: usize = 4;
const RESTORE_WORDS: usize = 10;

fn words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes(w.try_into().expect("four bytes")))
        .collect()
}

/// `bl target` / `b target` placed at `at`, if the distance fits.
fn branch(opcode: u32, at: u64, target: u64) -> Option<u32> {
    let delta = i64::try_from(target).ok()? - i64::try_from(at).ok()?;
    if delta % 4 != 0 || !(-(1 << 27)..(1 << 27)).contains(&delta) {
        return None;
    }
    Some(opcode | ((delta / 4) as u32 & 0x03ff_ffff))
}

fn movz_w(rd: u32, imm: u32) -> u32 {
    0x5280_0000 | ((imm & 0xffff) << 5) | rd
}
/// `ldrh wt,[xn,#offset]` / `strh wt,[xn,#offset]` (even offset < 8192).
fn ldrh(rt: u32, rn: u32, offset: u32) -> u32 {
    0x7940_0000 | ((offset / 2) << 10) | (rn << 5) | rt
}
fn strh(rt: u32, rn: u32, offset: u32) -> u32 {
    0x7900_0000 | ((offset / 2) << 10) | (rn << 5) | rt
}

impl MenuSetupCursor {
    /// The three calls the build redirects, in a fixed order.
    pub fn calls(&self) -> [SetupCursorCall; 3] {
        [
            SetupCursorCall {
                site: self.save_site + 4 * (SAVE_WORDS as u64 - 1),
                callee: self.setter,
                entry: SETUP_CURSOR_SAVE_ENTRY,
            },
            SetupCursorCall {
                site: self.lookup_site + 4 * (LOOKUP_WORDS as u64 - 1),
                callee: self.setter,
                entry: SETUP_CURSOR_SAVE_ENTRY,
            },
            SetupCursorCall {
                site: self.restore_site + 0x14,
                callee: self.getter,
                entry: SETUP_CURSOR_RESTORE_ENTRY,
            },
        ]
    }

    /// The declared stock instructions are the exact sequences the fields
    /// describe. Returns the first mismatch, if any.
    pub fn shape_error(&self) -> Option<&'static str> {
        if self.setting == 0 || self.setting > 0xffff {
            return Some("setting must be a non-zero 16-bit id (loaded by one movz)");
        }
        for offset in [self.cursor_offset, self.scroll_offset] {
            if offset % 2 != 0 || offset >= 0x60 {
                return Some("cursor and scroll offsets must be half-words of the window record");
            }
        }
        if self.cursor_offset == self.scroll_offset {
            return Some("cursor and scroll are two different half-words");
        }
        let id = movz_w(0, self.setting);
        let save = words(&self.save_stock);
        let call = self.save_site + 16;
        if self.save_stock.len() != SAVE_WORDS * 4
            || save[..4]
                != [
                    ldrh(8, 0, self.scroll_offset),
                    ldrh(9, 0, self.cursor_offset),
                    id,
                    0x0b08_0121,
                ]
            || Some(save[4]) != branch(0x9400_0000, call, self.setter)
        {
            return Some(
                "save_stock is not ldrh w8,[x0,#scroll]; ldrh w9,[x0,#cursor]; movz w0,#setting; add w1,w9,w8; bl setter",
            );
        }
        let lookup = words(&self.lookup_stock);
        let call = self.lookup_site + 12;
        // tbnz w8,#31: b5=0, op=1, b40=31, rt=8; the target is not used.
        if self.lookup_stock.len() != LOOKUP_WORDS * 4
            || lookup[0] & 0xfff8_001f != 0x37f8_0008
            || lookup[1..3] != [id, 0x2a08_03e1]
            || Some(lookup[3]) != branch(0x9400_0000, call, self.setter)
        {
            return Some("lookup_stock is not tbnz w8,#31; movz w0,#setting; mov w1,w8; bl setter");
        }
        let restore = words(&self.restore_stock);
        let call = self.restore_site + 0x14;
        if self.restore_stock.len() != RESTORE_WORDS * 4
            || restore[0] != id
            || Some(restore[1]) != branch(0x1400_0000, self.restore_site + 4, call)
            || Some(restore[5]) != branch(0x9400_0000, call, self.getter)
            || restore[6] != ldrh(8, 19, 2)
            || restore[7] != 0x2a00_03f4
            || restore[8] != strh(31, 19, self.scroll_offset)
            || restore[9] != strh(20, 19, self.cursor_offset)
        {
            return Some(
                "restore_stock is not movz w0,#setting; b call; ..; bl getter; ldrh w8,[x19,#2]; mov w20,w0; strh wzr,[x19,#scroll]; strh w20,[x19,#cursor]",
            );
        }
        // Between the Setup branch and the call, the next window's branch
        // loads its own id into w0 and jumps to the call, and the default
        // id falls through into it: the call is the one read every window's
        // restore shares, so core passes other ids through unchanged.
        let loads_w0 = |w: u32| w & 0xffe0_001f == 0x5280_0000;
        if !loads_w0(restore[2])
            || Some(restore[3]) != branch(0x1400_0000, self.restore_site + 12, call)
            || !loads_w0(restore[4])
        {
            return Some(
                "restore_stock: the windows before the call do not load an id into w0 and reach it",
            );
        }
        None
    }
}

impl Profile {
    pub(crate) fn validate_setup_cursor(&self, report: &mut ValidationReport) {
        let Some(setup) = &self.menu.setup else {
            return;
        };
        let Some(cursor) = &setup.cursor else {
            return;
        };
        let field = "menu.setup.cursor";
        // The mapping is the Apps-first, NLoader-row layout's: it needs the
        // entry row, the Apps row as the first row and the Firmware version
        // row NLoader is saved as.
        if setup.entry.is_none()
            || setup.apps.as_ref().is_none_or(|apps| apps.index != 0)
            || setup.firmware_version.is_none()
        {
            report.add(
                field,
                IssueKind::Conflict,
                "the cursor mapping needs the entry row, the Apps row first and the Firmware version row",
            );
        }
        for (name, address) in [
            ("setter", cursor.setter),
            ("getter", cursor.getter),
            ("save_site", cursor.save_site),
            ("lookup_site", cursor.lookup_site),
            ("restore_site", cursor.restore_site),
        ] {
            if address % 4 != 0 || !self.memory.is_xip_range(address, 4) {
                report.add(
                    format!("{field}.{name}"),
                    IssueKind::OutOfBounds,
                    "must be an instruction in firmware text",
                );
            }
        }
        if let Some(message) = cursor.shape_error() {
            report.add(field, IssueKind::Invalid, message);
        }
    }

    pub(crate) fn validate_setup_cursor_bytes(&self, bytes: &[u8], report: &mut ValidationReport) {
        let Some(cursor) = self.menu.setup.as_ref().and_then(|s| s.cursor.as_ref()) else {
            return;
        };
        for (name, address, stock) in [
            ("save_stock", cursor.save_site, &cursor.save_stock),
            ("lookup_stock", cursor.lookup_site, &cursor.lookup_stock),
            ("restore_stock", cursor.restore_site, &cursor.restore_stock),
        ] {
            let found = self
                .memory
                .address_to_offset(address, stock.len() as u64)
                .ok()
                .and_then(|o| usize::try_from(o).ok())
                .and_then(|o| bytes.get(o..o.checked_add(stock.len())?));
            if found != Some(stock.as_slice()) {
                report.add(
                    format!("menu.setup.cursor.{name}"),
                    IssueKind::Conflict,
                    "differs from the official module at the declared site",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
    /// The three stock shapes at synthetic addresses.
    fn good() -> MenuSetupCursor {
        let (setter, getter) = (0x2000u64, 0x2004u64);
        let (save, lookup, restore) = (0x1000u64, 0x1100u64, 0x1200u64);
        MenuSetupCursor {
            setting: 0x4904,
            setter,
            getter,
            cursor_offset: 0x32,
            scroll_offset: 0x58,
            save_site: save,
            save_stock: le(&[
                0x7940_b008,
                0x7940_6409,
                0x5289_2080,
                0x0b08_0121,
                branch(0x9400_0000, save + 16, setter).unwrap(),
            ]),
            lookup_site: lookup,
            lookup_stock: le(&[
                0x37f8_0088,
                0x5289_2080,
                0x2a08_03e1,
                branch(0x9400_0000, lookup + 12, setter).unwrap(),
            ]),
            restore_site: restore,
            restore_stock: le(&[
                0x5289_2080,
                branch(0x1400_0000, restore + 4, restore + 0x14).unwrap(),
                0x5289_20c0,
                branch(0x1400_0000, restore + 12, restore + 0x14).unwrap(),
                0x5289_2020,
                branch(0x9400_0000, restore + 0x14, getter).unwrap(),
                0x7940_0668,
                0x2a00_03f4,
                0x7900_b27f,
                0x7900_6674,
            ]),
        }
    }

    #[test]
    fn accepts_the_stock_shapes_and_names_three_calls() {
        let c = good();
        assert_eq!(c.shape_error(), None);
        assert_eq!(
            c.calls().map(|x| (x.site, x.callee, x.entry)),
            [
                (0x1010, 0x2000, SETUP_CURSOR_SAVE_ENTRY),
                (0x110c, 0x2000, SETUP_CURSOR_SAVE_ENTRY),
                (0x1214, 0x2004, SETUP_CURSOR_RESTORE_ENTRY),
            ]
        );
    }

    type Mutation = (&'static str, fn(&mut MenuSetupCursor));

    #[test]
    fn refuses_fields_the_instructions_do_not_show() {
        let mutations: [Mutation; 21] = [
            ("other setting", |c| c.setting = 0x4903),
            ("zero setting", |c| c.setting = 0),
            ("wide setting", |c| c.setting = 0x1_4904),
            ("cursor offset", |c| c.cursor_offset = 0x34),
            ("scroll offset", |c| c.scroll_offset = 0x5a),
            ("same half-word", |c| c.scroll_offset = 0x32),
            ("odd offset", |c| c.cursor_offset = 0x33),
            ("other setter", |c| c.setter = 0x2008),
            ("other getter", |c| c.getter = 0x2008),
            ("save site moved", |c| c.save_site += 4),
            ("lookup site moved", |c| c.lookup_site += 4),
            ("restore site moved", |c| c.restore_site += 4),
            ("short save", |c| c.save_stock.truncate(16)),
            ("save add", |c| c.save_stock[12] ^= 1),
            ("lookup guard", |c| c.lookup_stock[3] = 0),
            ("lookup mov", |c| c.lookup_stock[8] ^= 1),
            ("restore branch", |c| c.restore_stock[4] ^= 1),
            ("restore other window", |c| c.restore_stock[12] ^= 1),
            ("restore default id", |c| c.restore_stock[19] = 0),
            ("restore cursor store", |c| c.restore_stock[36] ^= 1),
            ("restore scroll store", |c| c.restore_stock[32] ^= 1),
        ];
        for (label, mutate) in mutations {
            let mut c = good();
            mutate(&mut c);
            assert!(c.shape_error().is_some(), "{label} accepted");
        }
    }
}
