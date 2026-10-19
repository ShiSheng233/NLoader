//! ABI 7 platform services (`[services.platform]`, core/include/nlr/platform.h):
//! every control of the body, its dials and the settings store's tables.
//!
//! Each part is optional. A part left out keeps its calls at -ENOSYS on the
//! camera; nothing is guessed in its place.
use crate::{IssueKind, Profile, ValidationReport};
use serde::{Deserialize, Serialize};

/// The logical controls, as `enum nlr_ctl` numbers them. A profile names
/// them in lower case without the prefix.
pub const CONTROLS: &[(&str, u8)] = &[
    ("up", 0),
    ("down", 1),
    ("left", 2),
    ("right", 3),
    ("ok", 4),
    ("menu", 5),
    ("play", 6),
    ("delete", 7),
    ("info", 8),
    ("disp", 9),
    ("zoom_in", 10),
    ("zoom_out", 11),
    ("af_on", 12),
    ("half", 13),
    ("full", 14),
    ("sub_up", 15),
    ("sub_down", 16),
    ("sub_left", 17),
    ("sub_right", 18),
    ("sub_press", 19),
    ("fn1", 20),
    ("fn2", 21),
    ("fn_v", 22),
    ("movie", 23),
    ("iso", 24),
    ("exp_comp", 25),
    ("release_mode", 26),
    ("illuminate", 27),
    ("af_on_v", 28),
    ("remote_fn", 29),
    // The battery grip's and the remote's own contacts for the same
    // logical controls: the program sees one control either way.
    ("half_v", 13),
    ("full_v", 14),
    ("sub_v_up", 15),
    ("sub_v_down", 16),
    ("sub_v_left", 17),
    ("sub_v_right", 18),
    ("sub_v_press", 19),
    ("remote_half", 13),
    ("remote_full", 14),
];

/// Core's bound on the control table (NLR_PLATFORM_CONTROLS_MAX).
pub const CONTROLS_MAX: usize = 40;

/// The control's `enum nlr_ctl` number.
pub fn control_number(name: &str) -> Option<u8> {
    CONTROLS.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformServices {
    /// `[name, bank, mask]` per control, in the scan object
    /// `services.program` describes. A control may own several bits of one
    /// bank; two controls never share a bit.
    pub controls: Vec<(String, u32, u32)>,
    /// The scan object's geometry when its carrier is not the program input
    /// slot (the Z 8: the exit callback). Absent: the program input slot's
    /// fields describe it.
    pub scan: Option<PlatformScan>,
    /// The s32 dial words at `services.program.dial_offset`: for the main
    /// dial, the sub dial and the lens ring, 1 + the word's index (0: the
    /// body has none), and -1 where the word counts clockwise as negative.
    pub dial_words: [u8; 3],
    pub dial_signs: [i8; 3],
    /// A second word for the same dial (the battery grip's), same encoding.
    pub dial_alt_words: [u8; 3],
    /// The touch driver's report slot (run-time RAM), its stock occupant
    /// (fingerprinted as `platform.touch_original`) and the record size.
    pub touch_slot: Option<u64>,
    pub touch_original: Option<u64>,
    pub touch_record_bytes: u32,
    /// The eye sensor's last state, a u32 in run-time RAM.
    pub eye_state: Option<u64>,
    pub props: Option<PlatformProps>,
    /// A stock function of no arguments the GUI task calls as it leaves a
    /// hold after a program gave the screen back: it makes the GUI draw its
    /// whole screen again. Fingerprinted as `platform.gui_redraw`.
    pub gui_redraw: Option<u64>,
    pub card: Option<PlatformCard>,
    /// Where the release bundle goes: a span of the
    /// module that is all zero in the stock firmware and is copied to DRAM
    /// with the code at boot, so the loader reads the bundle where the
    /// camera already has it. `nloader build --bundle` fills it.
    pub bundle: Option<PlatformBundle>,
    /// ABI 8 names.
    pub points: Vec<PlatformPoint>,
    pub tables: Vec<PlatformTable>,
    pub functions: Vec<PlatformFunction>,
    pub devices: Vec<PlatformDevice>,
    /// The I2C service the devices use (see PlatformI2c).
    pub i2c: Option<PlatformI2c>,
    /// The stock GUI's turns, for a body whose GUI is several services each
    /// taking its turn on its own task (the Z 8): the call each service's
    /// loop makes once a turn before it waits for work. The build points
    /// each at a generated entry that runs core's GUI turn (the boot hold's
    /// two halves) around the stock call.
    pub gui_turns: Vec<PlatformGuiTurn>,
    /// When and how long the stock GUI is held for a shell (core's GUI
    /// hold): required wherever a hold point exists (GUI turns or the boot
    /// checkpoint), never defaulted.
    pub hold: Option<PlatformHold>,
    /// The stock GUI's commit calls, each pointed at core's commit observer
    /// (nlr_platform_gui_commit): the settle signal of a "settle" hold and
    /// the frame count of the loader's own canvas (services.graphics).
    pub commit: Option<PlatformCommit>,
}

/// Core's bound on the GUI turns (the generated entries it may be given).
pub const GUI_TURNS_MAX: usize = 8;

/// When a shell opened from a menu is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HoldWhen {
    /// At the next hold point.
    Immediate,
    /// Only once the stock GUI has committed a frame after a hold point
    /// ran (told by `services.platform.commit`).
    Settle,
}

impl HoldWhen {
    /// core's NLR_HOLD_* value.
    pub fn core_value(self) -> u32 {
        match self {
            HoldWhen::Immediate => 1,
            HoldWhen::Settle => 2,
        }
    }
}

/// The GUI hold (core/include/nlr/platform.h `hold_when`, `hold_wait_ms`,
/// `scanout_stable_ms`). Every field is required; the bounds are
/// HOLD_WAIT_MS and SCANOUT_STABLE_MS, in steps of 10 ms (core's poll).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformHold {
    pub when: HoldWhen,
    /// The longest screen_claim waits for the stock GUI to reach a hold
    /// point before it refuses (-EBUSY) and lets the GUI go on.
    pub wait_ms: u32,
    /// How long the shown buffers must stay the same after the hold is
    /// taken before screen_claim hands them out; 0: no such wait. Never
    /// more than core's 2000 ms ceiling.
    pub scanout_stable_ms: u32,
}

/// Bounds of `services.platform.hold`.
pub const HOLD_WAIT_MS: std::ops::RangeInclusive<u32> = 500..=10_000;
pub const SCANOUT_STABLE_MS: std::ops::RangeInclusive<u32> = 0..=1_000;
/// core's bound on the commit calls.
pub const COMMIT_SITES_MAX: usize = 4;

/// The commit observer: BLs in firmware text (`sites`), all calling the
/// stock commit `callee` (`int32_t (uint32_t mask, void *request)`, bit 0
/// of the result set when the commit was taken), with each BL's 4 stock
/// bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformCommit {
    pub callee: u64,
    pub sites: Vec<u64>,
    pub stock: Vec<Vec<u8>>,
}

impl PlatformCommit {
    /// Where the declared stock word at `n` branches when it is a BL.
    pub fn stock_target(&self, n: usize) -> Option<u64> {
        bl_target(*self.sites.get(n)?, self.stock.get(n)?)
    }
}

/// The target of the 4-byte little-endian BL `stock` at `site`.
fn bl_target(site: u64, stock: &[u8]) -> Option<u64> {
    let word = u32::from_le_bytes(stock.try_into().ok()?);
    if word & 0xfc00_0000 != 0x9400_0000 {
        return None;
    }
    let delta = (((word & 0x03ff_ffff) as i32) << 6 >> 6) as i64 * 4;
    site.checked_add_signed(delta)
}

/// One GUI turn: a BL in firmware text (`site`), the function it calls
/// (`callee`, no arguments, its result returned as is) and the 4 bytes of
/// that BL in the stock module.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformGuiTurn {
    pub name: String,
    pub site: u64,
    pub callee: u64,
    pub stock: Vec<u8>,
}

impl PlatformGuiTurn {
    /// Where the declared stock word branches when it is a BL.
    pub fn stock_target(&self) -> Option<u64> {
        bl_target(self.site, &self.stock)
    }
}

/// The scan object's geometry for a body whose input hook is not the
/// program input slot: where the bank records (u32[5] current, previous,
/// changed, pressed, released) and the s32 dial words live, which bits the
/// camera always sees, and the activity entry. The exit callback (the Z 8)
/// fills these; a body that declares the program input slot leaves the
/// whole table out and keeps the geometry there.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformScan {
    pub bank_base: u32,
    pub bank_stride: u32,
    pub banks: u32,
    pub keep_bank: u32,
    pub keep_mask: u32,
    pub dial_offset: u32,
    pub dial_bytes: u32,
    /// The stock no-argument activity signal (fingerprinted as
    /// `platform.activity`); absent leaves standby semantics unproven.
    pub activity: Option<u64>,
    /// The scan object itself, for the boot escape's held-buttons read.
    pub object: Option<u64>,
}

/// A hook point: a firmware function's entry, the four instruction words
/// it holds (the detour overwrites them; the build generates the
/// continuation that runs them from the loader) and how many register
/// arguments it takes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformPoint {
    pub name: String,
    pub target: u64,
    pub expect: [u32; 4],
    pub args: u32,
    /// Which task runs it; documentation only.
    pub task: Option<String>,
}

/// A data table: where its bytes are, how many, how the loader may change
/// them (`ram`, `text`, `pointer`, `repack`) and the CRC-32 of the stock
/// bytes. A pointer table is an 8-byte RAM slot holding `stock_pointer`,
/// the address of `size` bytes of read-only data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformTable {
    pub name: String,
    pub address: u64,
    pub size: u32,
    pub class: String,
    pub crc: u32,
    pub stock_pointer: Option<u64>,
}

/// A firmware function by name, with the 16 bytes its entry holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformFunction {
    pub name: String,
    pub address: u64,
    pub stock: Vec<u8>,
}

/// A device on a bus: its bank, address and the client the loader
/// attaches as (never one of the camera's own).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformDevice {
    pub name: String,
    pub bank: u32,
    pub address: u32,
    pub client: u32,
}

/// The firmware's I2C service as the devices use it: attach(client),
/// xfer(client, message) with the message {u32 1, u16 address, tx*, rx*,
/// u32 txlen, u32 rxlen} under the bank's mutex, detach(client), the client
/// handle being bank << 16 | 1 << index. Names of functions in `functions`
/// (fingerprinted there).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformI2c {
    pub attach: String,
    pub xfer: String,
    pub detach: String,
}

/// A table class as core numbers it (NLR_TABLE_*).
pub fn table_class(class: &str) -> Option<u32> {
    match class {
        "ram" => Some(0),
        "text" => Some(1),
        "repack" => Some(2),
        "pointer" => Some(3),
        _ => None,
    }
}

/// A position-independent instruction: one a continuation may run from
/// another address (no branch, ADR/ADRP or literal load).
pub fn position_independent(word: u32) -> bool {
    let branch = (word & 0x7c00_0000) == 0x1400_0000      // B, BL
        || (word & 0xfe00_0000) == 0x5400_0000          // B.cond
        || (word & 0x7e00_0000) == 0x3400_0000          // CBZ, CBNZ
        || (word & 0x7e00_0000) == 0x3600_0000          // TBZ, TBNZ
        || (word & 0xfe00_0000) == 0xd600_0000; // BR, BLR, RET...
    let adr = (word & 0x1f00_0000) == 0x1000_0000; // ADR, ADRP
    let literal = (word & 0x3b00_0000) == 0x1800_0000; // LDR (literal)
    !(branch || adr || literal)
}

/// The release bundle's span: start (64-byte aligned) and most bytes, and
/// the stock boot copy that brings the span into DRAM.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformBundle {
    pub address: u64,
    pub size: u32,
    /// The stock boot copy of the code-window block that holds the span.
    /// The loader reads the bundle at its run address, and while the
    /// window is mapped to DRAM that address shows the DRAM copy, so the
    /// copy must reach the span's end. Required with a bundle.
    pub copy: Option<BundleCopy>,
}

impl PlatformBundle {
    /// One past the span's last byte: where the extended copy ends.
    pub fn end(&self) -> u64 {
        self.address + self.size as u64
    }
}

/// A stock copy routine's end constant, built by a MOVZ (bits 0..16) and a
/// MOVK (bits 16..32) into one register; the routine copies
/// `end - source` bytes from `source` to `destination` and maps
/// `block_bytes` of the window from `source` onto `destination`. The build
/// rewrites the two immediates so the copy ends at the bundle span's end.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BundleCopy {
    /// The block's first window address (the copy's source).
    pub source: u64,
    /// The block the routine maps; the copy never runs past it.
    pub block_bytes: u32,
    /// Where `source` lands in DRAM.
    pub destination: u64,
    /// The stock end constant (`source` + the stock copy length).
    pub stock_end: u64,
    /// The MOVZ and the MOVK (LSL 16) that build the end.
    pub low_site: u64,
    pub high_site: u64,
    /// The X register both write.
    pub register: u8,
    /// The stock words: the MOVZ's four bytes, then the MOVK's.
    pub stock: Vec<u8>,
}

/// A 64-bit MOVZ/MOVK's (opcode bits, hw, imm16, Rd), or `None`.
fn wide_move(word: u32) -> Option<(u32, u32, u32, u8)> {
    let opcode = word & 0xff80_0000;
    if opcode != 0xd280_0000 && opcode != 0xf280_0000 {
        return None;
    }
    Some((
        opcode,
        (word >> 21) & 3,
        (word >> 5) & 0xffff,
        (word & 31) as u8,
    ))
}

impl BundleCopy {
    fn stock_words(&self) -> Option<(u32, u32)> {
        if self.stock.len() != 8 {
            return None;
        }
        let low = u32::from_le_bytes(self.stock[..4].try_into().ok()?);
        let high = u32::from_le_bytes(self.stock[4..].try_into().ok()?);
        Some((low, high))
    }

    /// The value the stock pair builds, when the words are the declared
    /// register's MOVZ #imm and MOVK #imm, LSL #16.
    pub fn stock_value(&self) -> Option<u64> {
        let (low, high) = self.stock_words()?;
        let (lo_op, lo_hw, lo, lo_rd) = wide_move(low)?;
        let (hi_op, hi_hw, hi, hi_rd) = wide_move(high)?;
        (lo_op == 0xd280_0000
            && lo_hw == 0
            && hi_op == 0xf280_0000
            && hi_hw == 1
            && lo_rd == self.register
            && hi_rd == self.register)
            .then_some(u64::from(lo) | u64::from(hi) << 16)
    }

    /// The two words with their immediates set to build `end` (below
    /// 2^32); every other bit stays as in the stock words.
    pub fn patched_words(&self, end: u64) -> Option<[u32; 2]> {
        self.stock_value()?;
        if end >> 32 != 0 {
            return None;
        }
        let (low, high) = self.stock_words()?;
        let field = 0xffffu32 << 5;
        Some([
            (low & !field) | ((end as u32 & 0xffff) << 5),
            (high & !field) | (((end >> 16) as u32 & 0xffff) << 5),
        ])
    }
}

/// The card slots, as the filesystem's volume table shows them: a volume
/// record per mounted volume, "X:" at +0, a state byte that is `mounted`
/// while it serves files. Slot n is the volume named `letters[n]` + ':'.
/// The table is in run-time RAM the module does not load.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformCard {
    pub volumes: u64,
    pub volume_count: u32,
    pub volume_bytes: u32,
    pub volume_state: u16,
    pub mounted: u8,
    pub letters: String,
}

/// The settings and status store: item id 0xGGII is group GG's item II.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformProps {
    pub groups: u64,
    pub group_count: u32,
    pub group_bytes: u32,
    pub group_live_at: u16,
    pub group_first_at: u16,
    pub group_items_at: u16,
    pub items: u64,
    pub item_count: u32,
    pub item_bytes: u32,
    pub item_size_at: u16,
    pub item_ram_at: u16,
    /// Where every value lives: an item record pointing anywhere else is
    /// never followed.
    pub ram_lo: u64,
    pub ram_hi: u64,
    /// The settings service the menus call, for one item by its tagged id,
    /// and for a blob item. Fingerprinted as `platform.prop_set` and
    /// `platform.prop_set_blob`.
    pub setter: Option<u64>,
    pub setter_blob: Option<u64>,
}

pub const GUI_REDRAW_FINGERPRINT: &str = "platform.gui_redraw";
pub const PROP_SET_FINGERPRINT: &str = "platform.prop_set";
pub const TOUCH_FINGERPRINT: &str = "platform.touch_original";
pub const PROP_SET_BLOB_FINGERPRINT: &str = "platform.prop_set_blob";
pub const ACTIVITY_FINGERPRINT: &str = "platform.activity";

/// Calls `each` with the dotted path and value of every non-negative
/// integer in a serialized profile.
fn profile_integers(value: &toml::Value, path: String, each: &mut dyn FnMut(&str, u64)) {
    match value {
        toml::Value::Integer(v) if *v >= 0 => each(&path, *v as u64),
        toml::Value::Table(table) => {
            for (key, v) in table {
                let next = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                profile_integers(v, next, each);
            }
        }
        toml::Value::Array(items) => {
            for (n, v) in items.iter().enumerate() {
                profile_integers(v, format!("{path}[{n}]"), each);
            }
        }
        _ => {}
    }
}

fn le(bytes: &[u8], at: usize, n: usize) -> Option<u64> {
    let b = bytes.get(at..at + n)?;
    Some(b.iter().rev().fold(0u64, |v, &x| v << 8 | x as u64))
}

/// CRC-32 (IEEE, reflected), as core's nlr_platform_crc32 computes it.
pub fn table_crc32(bytes: &[u8]) -> u32 {
    let mut c = u32::MAX;
    for &b in bytes {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = (c >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(c & 1));
        }
    }
    !c
}

impl Profile {
    pub(crate) fn validate_platform(&self, report: &mut ValidationReport) {
        let Some(platform) = &self.services.platform else {
            return;
        };
        let program = self.services.program.as_ref();
        let exit = self.services.exit.as_ref();
        /* The scan object's geometry and the hook that reads it: the
         * program input slot and its fields, or -- for the exit callback --
         * the platform scan's own. */
        let program_carrier = program.and_then(|p| p.input_slot.map(|_| p));
        let exit_carrier = exit.is_some();
        let carrier = program_carrier.is_some() || exit_carrier;
        let geometry = match platform.scan.as_ref() {
            Some(scan) if scan.bank_stride != 0 && scan.banks != 0 => {
                Some((scan.banks, scan.keep_bank, scan.keep_mask))
            }
            _ => program_carrier.map(|p| (p.banks, p.keep_bank, p.keep_mask)),
        };
        if !platform.controls.is_empty() {
            match geometry {
                Some((banks, keep_bank, keep_mask)) if carrier => {
                    let mut seen: Vec<&str> = Vec::new();
                    let mut bits = [0u32; 4];
                    for (name, bank, mask) in &platform.controls {
                        let field = format!("services.platform.controls.{name}");
                        if control_number(name).is_none() {
                            report.add(field, IssueKind::Invalid, "not a known control name");
                            continue;
                        }
                        if seen.contains(&name.as_str()) {
                            report.add(field, IssueKind::Conflict, "a control is declared once");
                            continue;
                        }
                        seen.push(name.as_str());
                        /* The bank is checked against core's four as well as
                         * the declared count: an over-wide count is its own
                         * reported issue and must not widen this index. */
                        let slot = bits.get_mut(*bank as usize).filter(|_| {
                            *mask != 0
                                && *bank < banks
                                && !(*bank == keep_bank && mask & keep_mask != 0)
                        });
                        let Some(slot) = slot else {
                            report.add(
                                field,
                                IssueKind::Conflict,
                                "a control names a declared bank and never the retained power bit",
                            );
                            continue;
                        };
                        if *slot & mask != 0 {
                            report.add(field, IssueKind::Conflict, "two controls share a bit");
                        }
                        *slot |= mask;
                    }
                    if platform.controls.len() > CONTROLS_MAX {
                        report.add(
                            "services.platform.controls",
                            IssueKind::Invalid,
                            "at most 40 controls",
                        );
                    }
                }
                Some(_) => report.add(
                    "services.platform.controls",
                    IssueKind::Missing,
                    "controls need the scan hook of services.program or services.exit",
                ),
                None => report.add(
                    "services.platform.controls",
                    IssueKind::Missing,
                    "controls need a declared scan (services.platform.scan or the \
                     program input slot)",
                ),
            }
        }
        if let Some(scan) = platform.scan.as_ref() {
            let field = "services.platform.scan";
            if scan.bank_stride == 0
                || scan.banks == 0
                || scan.banks > 4
                || scan.keep_bank >= scan.banks
                || scan.bank_base % 4 != 0
                || scan.bank_stride < 20
                || scan.dial_offset % 4 != 0
                || scan.dial_bytes % 4 != 0
                || scan.dial_bytes > 32
            {
                report.add(
                    field,
                    IssueKind::Invalid,
                    "the scan's banks, offsets and dial words must be bounded",
                );
            }
            /* Core hides every scan bit but the kept ones while a program
             * holds the controls (core/platform.c nlr_platform_input_pass),
             * on whichever carrier runs the scan. With no kept bit the
             * camera would lose its main switch too -- the shutter-release
             * black screen -- so a declared scan names at least one, as the
             * program input slot's keep_mask must. */
            if scan.keep_mask == 0 {
                report.add(
                    "services.platform.scan.keep_mask",
                    IssueKind::Invalid,
                    "a declared scan keeps at least one bit visible to the camera",
                );
            }
            if !carrier {
                report.add(
                    field,
                    IssueKind::Missing,
                    "the scan's carrier hook (services.program input slot or \
                     services.exit) is not declared",
                );
            }
            if exit_carrier && scan.banks > 3 {
                report.add(
                    field,
                    IssueKind::Conflict,
                    "the exit callback forwards three banks; a scan over more is \
                     never restored to the stock occupant",
                );
            }
            if let Some(object) = scan.object {
                if object % 8 != 0 || self.memory.segment_for_address(object, 4).is_ok() {
                    report.add(
                        "services.platform.scan.object",
                        IssueKind::Invalid,
                        "the scan object is aligned run-time RAM, outside the module",
                    );
                }
            }
            if let Some(address) = scan.activity {
                if address % 4 != 0 || !self.memory.is_xip_range(address, 4) {
                    report.add(
                        "services.platform.scan.activity",
                        IssueKind::OutOfBounds,
                        "the activity entry is an instruction in firmware text",
                    );
                }
                if !self.service_fingerprints.contains_key(ACTIVITY_FINGERPRINT) {
                    report.add(
                        "services.platform.scan.activity",
                        IssueKind::Missing,
                        "the activity entry needs its fingerprint",
                    );
                }
            }
        }
        let words = match platform.scan.as_ref() {
            Some(scan) => scan.dial_bytes / 4,
            None => program.map_or(0, |p| p.dial_bytes / 4),
        };
        for (n, ((&word, &sign), &alt)) in platform
            .dial_words
            .iter()
            .zip(platform.dial_signs.iter())
            .zip(platform.dial_alt_words.iter())
            .enumerate()
        {
            if word as u32 > words
                || alt as u32 > words
                || ((word != 0 || alt != 0) && sign != 1 && sign != -1)
            {
                report.add(
                    format!("services.platform.dial_words[{n}]"),
                    IssueKind::OutOfBounds,
                    "a dial is one of the declared dial words, counted +1 or -1",
                );
            }
        }
        if let Some(props) = &platform.props {
            let field = "services.platform.props";
            let groups = props.group_count as u64 * props.group_bytes as u64;
            let items = props.item_count as u64 * props.item_bytes as u64;
            if props.group_count == 0
                || props.group_count > 0x100
                || props.item_count == 0
                || props.group_bytes < 4
                || props.item_bytes < 8
                || props.group_live_at as u32 + 4 > props.group_bytes
                || props.group_first_at as u32 + 2 > props.group_bytes
                || props.group_items_at as u32 + 2 > props.group_bytes
                || props.item_size_at as u32 + 4 > props.item_bytes
                || props.item_ram_at as u32 + 8 > props.item_bytes
                || props.ram_lo >= props.ram_hi
            {
                report.add(
                    field,
                    IssueKind::Invalid,
                    "store records and offsets must be bounded",
                );
            } else if !self.memory.is_xip_range(props.groups, groups)
                || !self.memory.is_xip_range(props.items, items)
            {
                report.add(
                    field,
                    IssueKind::OutOfBounds,
                    "the store's group and item tables are read from the module",
                );
            }
        }
        if let Some(props) = &platform.props {
            for (field, address, key) in [
                (
                    "services.platform.props.setter",
                    props.setter,
                    PROP_SET_FINGERPRINT,
                ),
                (
                    "services.platform.props.setter_blob",
                    props.setter_blob,
                    PROP_SET_BLOB_FINGERPRINT,
                ),
            ] {
                let Some(address) = address else { continue };
                if address % 4 != 0 || !self.memory.is_xip_range(address, 4) {
                    report.add(
                        field,
                        IssueKind::OutOfBounds,
                        "the settings service is an instruction in firmware text",
                    );
                }
                if !self.service_fingerprints.contains_key(key) {
                    report.add(
                        field,
                        IssueKind::Missing,
                        "the settings service needs its fingerprint",
                    );
                }
            }
        }
        if platform.touch_slot.is_some() != platform.touch_original.is_some()
            || platform.touch_slot.is_some_and(|slot| {
                slot % 8 != 0 || self.memory.segment_for_address(slot, 8).is_ok()
            })
            || (platform.touch_slot.is_some() && !(14..=64).contains(&platform.touch_record_bytes))
        {
            report.add(
                "services.platform.touch_slot",
                IssueKind::Invalid,
                "the touch slot is aligned run-time RAM, declared with its occupant and a record of 14..=64 bytes",
            );
        }
        if let Some(address) = platform.touch_original {
            if !self.memory.is_xip_range(address, 4)
                || !self.service_fingerprints.contains_key(TOUCH_FINGERPRINT)
            {
                report.add(
                    "services.platform.touch_original",
                    IssueKind::Missing,
                    "the touch occupant is fingerprinted firmware text",
                );
            }
        }
        if platform
            .eye_state
            .is_some_and(|a| a % 4 != 0 || self.memory.is_xip_range(a, 4))
        {
            report.add(
                "services.platform.eye_state",
                IssueKind::Invalid,
                "the eye state is an aligned word of RAM, never firmware text",
            );
        }
        let mut names: Vec<String> = Vec::new();
        let mut unique = |name: &str, report: &mut ValidationReport, field: &str| {
            if name.is_empty()
                || name.len() > 63
                || name.contains(['"', '\\'])
                || names.iter().any(|n| n == name)
            {
                report.add(
                    field,
                    IssueKind::Invalid,
                    "a name is 1..=63 bytes and used once",
                );
            }
            names.push(name.to_string());
        };
        let text_lo = self
            .services
            .code
            .as_ref()
            .and_then(|c| c.text_lo)
            .unwrap_or(0);
        let text_hi = self
            .services
            .code
            .as_ref()
            .and_then(|c| c.text_hi)
            .unwrap_or(0);
        for point in &platform.points {
            let field = format!("services.platform.points.{}", point.name);
            unique(&point.name, report, &field);
            if point.target % 4 != 0
                || point.target % 64 > 48
                || point.target < text_lo
                || point.target + 16 > text_hi
                || point.args > 8
                || !point.expect.iter().all(|w| position_independent(*w))
            {
                report.add(
                    field,
                    IssueKind::Invalid,
                    "a hook point is a function entry in the code window whose first 16 bytes \
                     share one cache line, at most 8 register arguments, and whose first four \
                     instructions are position independent",
                );
            }
        }
        for table in &platform.tables {
            let field = format!("services.platform.tables.{}", table.name);
            unique(&table.name, report, &field);
            let class = table_class(&table.class);
            let bad = match class {
                None => true,
                Some(3) => {
                    table.stock_pointer.is_none()
                        || table.address % 8 != 0
                        || self.memory.is_xip_range(table.address, 8)
                }
                Some(1) => table.address < text_lo || table.address + table.size as u64 > text_hi,
                Some(2) => !self.memory.is_xip_range(table.address, table.size as u64),
                Some(_) => self.memory.is_xip_range(table.address, table.size as u64),
            };
            if bad || table.size == 0 || table.size > 0x40000 {
                report.add(
                    field,
                    IssueKind::Invalid,
                    "a table's class fits where it lives, and it has 1..=262144 bytes",
                );
            }
        }
        for function in &platform.functions {
            let field = format!("services.platform.functions.{}", function.name);
            unique(&function.name, report, &field);
            if function.address % 4 != 0
                || !self.memory.is_xip_range(function.address, 16)
                || function.stock.len() != 16
            {
                report.add(
                    field,
                    IssueKind::Invalid,
                    "a function is an entry in firmware text with its 16 stock bytes",
                );
            }
        }
        for device in &platform.devices {
            let field = format!("services.platform.devices.{}", device.name);
            unique(&device.name, report, &field);
            if device.address > 0x7f || device.client == 0 {
                report.add(
                    field,
                    IssueKind::Invalid,
                    "a 7-bit address and a client of its own",
                );
            }
        }
        if let Some(i2c) = &platform.i2c {
            for name in [&i2c.attach, &i2c.xfer, &i2c.detach] {
                if !platform.functions.iter().any(|f| &f.name == name) {
                    report.add(
                        "services.platform.i2c",
                        IssueKind::Missing,
                        format!("the I2C service names function {name}, which is not declared"),
                    );
                }
            }
        }
        if let Some(bundle) = &platform.bundle {
            if bundle.address % 64 != 0
                || bundle.size < 0x40
                || !self.memory.is_xip_range(bundle.address, bundle.size as u64)
                || bundle.address < text_lo
                || bundle.address + bundle.size as u64 > text_hi
            {
                report.add(
                    "services.platform.bundle",
                    IssueKind::Invalid,
                    "the bundle span is 64-byte aligned module text inside the code window",
                );
            }
            match &bundle.copy {
                None => report.add(
                    "services.platform.bundle.copy",
                    IssueKind::Missing,
                    "a bundle names the stock boot copy that brings its span into DRAM",
                ),
                Some(copy) => self.validate_bundle_copy(bundle, copy, text_lo, text_hi, report),
            }
        }
        if let Some(card) = &platform.card {
            let letters = card.letters.as_bytes();
            if card.volumes == 0
                || card.volume_count == 0
                || card.volume_count > 8
                || card.volume_bytes < 3
                || card.volume_state as u32 >= card.volume_bytes
                || letters.is_empty()
                || letters.len() > 4
                || !letters.iter().all(|b| b.is_ascii_uppercase())
                || self
                    .memory
                    .segment_for_address(
                        card.volumes,
                        card.volume_count as u64 * card.volume_bytes as u64,
                    )
                    .is_ok()
            {
                report.add(
                    "services.platform.card",
                    IssueKind::Invalid,
                    "the volume table is bounded run-time RAM outside the module, \
                     and each slot a drive letter",
                );
            }
        }
        self.validate_gui_turns(platform, text_lo, text_hi, report);
        self.validate_hold(platform, text_lo, text_hi, report);
        if let Some(address) = platform.gui_redraw {
            if address % 4 != 0 || !self.memory.is_xip_range(address, 4) {
                report.add(
                    "services.platform.gui_redraw",
                    IssueKind::OutOfBounds,
                    "the redraw entry is an instruction in firmware text",
                );
            }
            if !self
                .service_fingerprints
                .contains_key(GUI_REDRAW_FINGERPRINT)
            {
                report.add(
                    "services.platform.gui_redraw",
                    IssueKind::Missing,
                    "the redraw entry needs its fingerprint",
                );
            }
        }
    }

    /// The GUI hold and its commit observer. A hold point (GUI turns or
    /// the boot checkpoint) needs `hold`, and `hold` needs a hold point;
    /// the waits stay in bounds; "settle" needs the commit observer, and
    /// the observer needs a reader ("settle" or the loader's canvas). Each
    /// commit call is a BL in firmware text to the one declared callee,
    /// distinct from every GUI turn and the native card's checkpoint.
    fn validate_hold(
        &self,
        platform: &PlatformServices,
        text_lo: u64,
        text_hi: u64,
        report: &mut ValidationReport,
    ) {
        let hold_point = !platform.gui_turns.is_empty() || self.boot_hooks.autoload.is_some();
        match (&platform.hold, hold_point) {
            (None, true) => report.add(
                "services.platform.hold",
                IssueKind::Missing,
                "a hold point (GUI turns or the boot checkpoint) needs the declared hold: \
                 when (\"immediate\" or \"settle\"), wait_ms and scanout_stable_ms",
            ),
            (Some(_), false) => report.add(
                "services.platform.hold",
                IssueKind::Conflict,
                "a hold is declared but no hold point (GUI turns or the boot checkpoint) takes it",
            ),
            _ => {}
        }
        if let Some(hold) = &platform.hold {
            if !HOLD_WAIT_MS.contains(&hold.wait_ms) || hold.wait_ms % 10 != 0 {
                report.add(
                    "services.platform.hold.wait_ms",
                    IssueKind::OutOfBounds,
                    "the hold wait is 500..=10000 ms in steps of 10 ms",
                );
            }
            if !SCANOUT_STABLE_MS.contains(&hold.scanout_stable_ms)
                || hold.scanout_stable_ms % 10 != 0
            {
                report.add(
                    "services.platform.hold.scanout_stable_ms",
                    IssueKind::OutOfBounds,
                    "the scanout settle is 0..=1000 ms in steps of 10 ms, inside core's \
                     2000 ms ceiling",
                );
            }
            if hold.when == HoldWhen::Settle && platform.commit.is_none() {
                report.add(
                    "services.platform.commit",
                    IssueKind::Missing,
                    "a \"settle\" hold waits for the stock GUI's commit: it needs the declared \
                     commit observer",
                );
            }
        }
        let Some(commit) = &platform.commit else {
            return;
        };
        let settle = platform
            .hold
            .as_ref()
            .is_some_and(|h| h.when == HoldWhen::Settle);
        if !settle && self.services.graphics.is_none() {
            report.add(
                "services.platform.commit",
                IssueKind::Conflict,
                "the commit observer has no reader: neither a \"settle\" hold nor the \
                 loader's canvas (services.graphics)",
            );
        }
        if commit.callee % 4 != 0 || !self.memory.is_xip_range(commit.callee, 4) {
            report.add(
                "services.platform.commit.callee",
                IssueKind::OutOfBounds,
                "the commit callee is an instruction in firmware text",
            );
        }
        if commit.sites.is_empty()
            || commit.sites.len() > COMMIT_SITES_MAX
            || commit.stock.len() != commit.sites.len()
        {
            report.add(
                "services.platform.commit.sites",
                IssueKind::Invalid,
                "1..=4 commit calls, each with its 4 stock bytes",
            );
        }
        let windowed = text_lo != 0 || text_hi != 0;
        let menu_site = self
            .services
            .native_card
            .as_ref()
            .map(|card| card.menu.call_site);
        for (n, site) in commit.sites.iter().enumerate() {
            let field = format!("services.platform.commit.sites[{n}]");
            if site % 4 != 0
                || !self.memory.is_xip_range(*site, 4)
                || (windowed && (*site < text_lo || site + 4 > text_hi))
            {
                report.add(
                    field.clone(),
                    IssueKind::OutOfBounds,
                    "a commit call is an aligned instruction in firmware text, inside the \
                     code window",
                );
            }
            if commit.stock.get(n).is_none_or(|w| w.len() != 4)
                || commit.stock_target(n) != Some(commit.callee)
            {
                report.add(
                    field.clone(),
                    IssueKind::Invalid,
                    "a commit call's stock word is a BL to the declared callee",
                );
            }
            if commit.sites[..n].contains(site)
                || platform.gui_turns.iter().any(|t| t.site == *site)
                || menu_site == Some(*site)
            {
                report.add(
                    field,
                    IssueKind::Conflict,
                    "a commit call is its own site: not repeated, not a GUI turn, not the \
                     native card's checkpoint",
                );
            }
        }
    }

    /// GUI turns: each a BL in firmware text (inside the code window when
    /// one is declared) whose declared stock word calls the declared
    /// callee; sites distinct and never the native card's menu checkpoint,
    /// which has its own entry; at most GUI_TURNS_MAX.
    fn validate_gui_turns(
        &self,
        platform: &PlatformServices,
        text_lo: u64,
        text_hi: u64,
        report: &mut ValidationReport,
    ) {
        if platform.gui_turns.len() > GUI_TURNS_MAX {
            report.add(
                "services.platform.gui_turns",
                IssueKind::Invalid,
                "at most 8 GUI turns",
            );
        }
        let menu_site = self
            .services
            .native_card
            .as_ref()
            .map(|card| card.menu.call_site);
        let windowed = text_lo != 0 || text_hi != 0;
        let mut names: Vec<&str> = Vec::new();
        let mut sites: Vec<u64> = Vec::new();
        for turn in &platform.gui_turns {
            let field = format!("services.platform.gui_turns.{}", turn.name);
            if turn.name.is_empty()
                || turn.name.len() > 63
                || turn.name.contains(['"', '\\'])
                || names.contains(&turn.name.as_str())
            {
                report.add(
                    field.clone(),
                    IssueKind::Invalid,
                    "a GUI turn's name is 1..=63 bytes and used once",
                );
            }
            names.push(turn.name.as_str());
            if turn.site % 4 != 0
                || !self.memory.is_xip_range(turn.site, 4)
                || (windowed && (turn.site < text_lo || turn.site + 4 > text_hi))
            {
                report.add(
                    field.clone(),
                    IssueKind::OutOfBounds,
                    "a GUI turn's site is an aligned instruction in firmware text, \
                     inside the code window",
                );
            }
            if turn.callee % 4 != 0 || !self.memory.is_xip_range(turn.callee, 4) {
                report.add(
                    field.clone(),
                    IssueKind::OutOfBounds,
                    "a GUI turn's callee is an instruction in firmware text",
                );
            }
            if turn.stock.len() != 4 || turn.stock_target() != Some(turn.callee) {
                report.add(
                    field.clone(),
                    IssueKind::Invalid,
                    "a GUI turn's stock word is a BL to its declared callee",
                );
            }
            if sites.contains(&turn.site) {
                report.add(
                    field.clone(),
                    IssueKind::Conflict,
                    "two GUI turns share a site",
                );
            }
            if menu_site == Some(turn.site) {
                report.add(
                    field,
                    IssueKind::Conflict,
                    "the native card's menu checkpoint is not a GUI turn",
                );
            }
            sites.push(turn.site);
        }
    }

    /// The stock boot copy that must bring the bundle span into DRAM: a
    /// MOVZ/MOVK pair building the declared stock end, a block inside the
    /// code window whose mapped length the extended copy stays within (so
    /// it never writes the next block's DRAM copy), and a DRAM destination
    /// that is the window's own alias of the copied bytes and that nothing
    /// else the profile names lies in.
    fn validate_bundle_copy(
        &self,
        bundle: &PlatformBundle,
        copy: &BundleCopy,
        text_lo: u64,
        text_hi: u64,
        report: &mut ValidationReport,
    ) {
        const FIELD: &str = "services.platform.bundle.copy";
        let end = bundle.end();
        if copy.register > 30 || copy.stock_value() != Some(copy.stock_end) {
            report.add(
                FIELD,
                IssueKind::Invalid,
                "the stock words are the register's MOVZ #lo and MOVK #hi, LSL #16 \
                 building the stock end",
            );
        }
        let span = crate::AddressRange {
            start: bundle.address,
            end,
        };
        for site in [copy.low_site, copy.high_site] {
            if site % 4 != 0
                || !self.memory.is_xip_range(site, 4)
                || span.overlaps(&crate::AddressRange {
                    start: site,
                    end: site + 4,
                })
            {
                report.add(
                    FIELD,
                    IssueKind::OutOfBounds,
                    "the end's instructions are aligned firmware text outside the span",
                );
            }
        }
        if copy.low_site == copy.high_site {
            report.add(
                FIELD,
                IssueKind::Conflict,
                "the MOVZ and the MOVK are two sites",
            );
        }
        let block_end = copy.source.checked_add(copy.block_bytes as u64);
        if copy.block_bytes == 0
            || copy.source < text_lo
            || block_end.is_none_or(|block_end| block_end > text_hi)
        {
            report.add(
                FIELD,
                IssueKind::OutOfBounds,
                "the copied block lies inside the code window",
            );
            return;
        }
        let block_end = block_end.unwrap_or(0);
        if copy.stock_end <= copy.source || copy.stock_end > bundle.address {
            report.add(
                FIELD,
                IssueKind::Invalid,
                "the stock copy starts the block and stops at or before the span",
            );
        }
        if bundle.address < copy.source || end > block_end {
            report.add(
                FIELD,
                IssueKind::Conflict,
                "the span lies inside the block, so the extended copy ends within the \
                 block the routine maps and never writes the next block's DRAM copy",
            );
        }
        if copy.patched_words(end).is_none() {
            report.add(
                FIELD,
                IssueKind::Invalid,
                "the extended end must fit the MOVZ/MOVK pair (below 2^32)",
            );
        }
        let destination = crate::AddressRange {
            start: copy.destination,
            end: copy
                .destination
                .saturating_add(end.saturating_sub(copy.source)),
        };
        if let Some(code) = &self.services.code {
            if let (Some(lo), Some(alias_lo), Some(alias_hi)) =
                (code.text_lo, code.alias_lo, code.alias_hi)
            {
                if copy.destination.wrapping_sub(copy.source) != alias_lo.wrapping_sub(lo)
                    || destination.start < alias_lo
                    || destination.end > alias_hi
                {
                    report.add(
                        FIELD,
                        IssueKind::Conflict,
                        "the copy lands on the code window's own DRAM alias of the copied \
                         bytes, inside the alias band",
                    );
                }
            }
        }
        if self.memory.segments.iter().any(|segment| {
            segment
                .runtime_range()
                .is_some_and(|range| range.overlaps(&destination))
        }) {
            report.add(
                FIELD,
                IssueKind::Conflict,
                "the copy's DRAM destination overlaps the module's mapped image",
            );
        }
        // Every other address the profile names: none may fall where the
        // copy writes. The code window and the bundle itself describe this
        // band, so their own fields are left out.
        match toml::Value::try_from(self) {
            Ok(value) => {
                let mut users = Vec::new();
                profile_integers(&value, String::new(), &mut |path, v| {
                    if path.starts_with("services.code.")
                        || path.starts_with("services.platform.bundle.")
                    {
                        return;
                    }
                    if v >= destination.start && v < destination.end {
                        users.push(path.to_string());
                    }
                });
                for user in users {
                    report.add(
                        FIELD,
                        IssueKind::Conflict,
                        format!(
                            "the copy's DRAM destination holds {user}, which the profile names"
                        ),
                    );
                }
            }
            Err(_) => report.add(
                FIELD,
                IssueKind::Unconfirmed,
                "the profile's other addresses could not be listed against the copy",
            ),
        }
    }

    /// The store's tables as the module holds them: every group in use must
    /// name items inside the item table. Hook points and functions must
    /// hold the bytes the profile says.
    pub(crate) fn validate_platform_bytes(&self, module: &[u8], report: &mut ValidationReport) {
        let Some(platform) = self.services.platform.as_ref() else {
            return;
        };
        let bytes_at = |address: u64, n: u64| -> Option<&[u8]> {
            let offset = usize::try_from(self.memory.address_to_offset(address, n).ok()?).ok()?;
            module.get(offset..offset + n as usize)
        };
        for point in &platform.points {
            let want: Vec<u8> = point.expect.iter().flat_map(|w| w.to_le_bytes()).collect();
            if bytes_at(point.target, 16) != Some(want.as_slice()) {
                report.add(
                    format!("services.platform.points.{}", point.name),
                    IssueKind::FingerprintMismatch,
                    "the module does not hold the declared instructions there",
                );
            }
        }
        for function in &platform.functions {
            if bytes_at(function.address, 16) != Some(function.stock.as_slice()) {
                report.add(
                    format!("services.platform.functions.{}", function.name),
                    IssueKind::FingerprintMismatch,
                    "the module does not hold the declared bytes at the function's entry",
                );
            }
        }
        // A table's stock bytes are the module's: the CRC is computed here
        // from them, never taken on trust. A pointer table's data is the
        // read-only data its slot starts out pointing at; a slot the module
        // loads (initialized RAM) must start out null or at that data. A
        // RAM table outside the module's loaded segments has no stock bytes
        // in the image and is checked by core at run time only.
        for table in &platform.tables {
            let field = format!("services.platform.tables.{}", table.name);
            let (data, slot) = match (table_class(&table.class), table.stock_pointer) {
                (Some(3), Some(pointer)) => (Some(pointer), Some(table.address)),
                (Some(3), None) | (None, _) => continue, // reported by validate_platform
                (Some(0), _) => (
                    bytes_at(table.address, table.size as u64).map(|_| table.address),
                    None,
                ),
                _ => (Some(table.address), None),
            };
            if let Some(address) = data {
                match bytes_at(address, table.size as u64) {
                    Some(bytes) if table_crc32(bytes) == table.crc => {}
                    Some(_) => report.add(
                        field.clone(),
                        IssueKind::FingerprintMismatch,
                        "the declared CRC is not the CRC-32 of the table's stock bytes in the module",
                    ),
                    None => report.add(
                        field.clone(),
                        IssueKind::OutOfBounds,
                        "the table's stock bytes are not in the module",
                    ),
                }
            }
            if let (Some(slot), Some(pointer)) = (slot, table.stock_pointer) {
                if let Some(start) = bytes_at(slot, 8) {
                    let value = le(start, 0, 8);
                    if value != Some(0) && value != Some(pointer) {
                        report.add(
                            field,
                            IssueKind::Conflict,
                            "the module loads the pointer slot with neither null nor the stock data",
                        );
                    }
                }
            }
        }
        if let Some(commit) = &platform.commit {
            for (n, (site, stock)) in commit.sites.iter().zip(&commit.stock).enumerate() {
                if bytes_at(*site, 4) != Some(stock.as_slice()) {
                    report.add(
                        format!("services.platform.commit.sites[{n}]"),
                        IssueKind::FingerprintMismatch,
                        "the module does not hold the declared stock call at the commit site",
                    );
                }
            }
        }
        for turn in &platform.gui_turns {
            if bytes_at(turn.site, 4) != Some(turn.stock.as_slice()) {
                report.add(
                    format!("services.platform.gui_turns.{}", turn.name),
                    IssueKind::FingerprintMismatch,
                    "the module does not hold the declared stock call at the GUI turn's site",
                );
            }
        }
        if let Some(bundle) = &platform.bundle {
            if bytes_at(bundle.address, bundle.size as u64)
                .is_none_or(|span| span.iter().any(|b| *b != 0))
            {
                report.add(
                    "services.platform.bundle",
                    IssueKind::Conflict,
                    "the bundle span is not all zero in the stock module",
                );
            }
            if let Some(copy) = &bundle.copy {
                let declared = copy.stock.get(..4).zip(copy.stock.get(4..));
                if declared.is_none_or(|(low, high)| {
                    bytes_at(copy.low_site, 4) != Some(low)
                        || bytes_at(copy.high_site, 4) != Some(high)
                }) {
                    report.add(
                        "services.platform.bundle.copy",
                        IssueKind::FingerprintMismatch,
                        "the module does not hold the declared stock end instructions",
                    );
                }
            }
        }
        let Some(props) = platform.props.as_ref() else {
            return;
        };
        let bytes = props.group_count as u64 * props.group_bytes as u64;
        let Some(start) = self
            .memory
            .address_to_offset(props.groups, bytes)
            .ok()
            .and_then(|o| usize::try_from(o).ok())
        else {
            return;
        };
        for group in 0..props.group_count as usize {
            let record = start + group * props.group_bytes as usize;
            let live = le(module, record + props.group_live_at as usize, 4);
            let first = le(module, record + props.group_first_at as usize, 2);
            let count = le(module, record + props.group_items_at as usize, 2);
            match (live, first, count) {
                (Some(0), _, _) => {}
                (Some(_), Some(first), Some(count)) if first + count <= props.item_count as u64 => {
                }
                _ => {
                    report.add(
                        format!("services.platform.props.groups[{group:#x}]"),
                        IssueKind::OutOfBounds,
                        "a group in use names items past the item table",
                    );
                    return;
                }
            }
        }
    }
}
