//! Complete stock evidence for the Z8 native FILESRV transaction family.
use crate::validation::{hash_matches, valid_hash};
use crate::{
    sha256, BuildMode, FsFamily, IssueKind, NativeCardServices, Profile, ValidationReport,
};
use std::collections::BTreeSet;

const EXIT_BODIES: &[(&str, u32)] = &[
    ("menu_exit_dispatch", 536),
    ("menu_exit_window", 44),
    ("menu_exit_window_helper", 44),
    ("menu_exit_state_handler", 32),
    ("menu_exit_state1", 2112),
];
const BODIES: &[(&str, u32)] = &[
    ("claim", 48),
    ("submit_frame", 276),
    ("submit_wrapper", 132),
    ("dispatcher", 2968),
    ("lock", 60),
    ("unlock", 84),
    ("open", 668),
    ("read", 668),
    ("write", 2104),
    ("seek", 52),
    ("close", 428),
    ("stat", 356),
    ("lookup", 1908),
    ("volume_sync", 1840),
    ("volume_index", 124),
    ("volume_ready", 96),
    // The stock per-slot flush and what binds it: the slot table (two
    // copied slot descriptors, each with its volume name), its install, the
    // registration of the per-slot flush as the filesystem service's
    // after-write hook, and the dispatcher's call of that hook.
    ("slot_flush", 48),
    ("slot_table_init", 140),
    ("slot_table_set", 24),
    ("slot_install", 156),
    ("flush_hook_register", 24),
    ("open_middleware", 96),
    ("media_lookup", 116),
    ("mount", 96),
    ("unmount", 72),
    ("menu_getter", 20),
    ("menu_loop", 748),
    ("generic_worker", 148),
    ("menu_init", 112),
    ("menu_prepare", 292),
    ("fcb_get", 124),
    ("file_set_decode", 1916),
    ("file_set_lookup", 2516),
    ("open_lookup", 1032),
    ("stat_lookup", 488),
    ("chain_end", 348),
    ("clean_source", 28),
    ("clean_helper", 100),
    ("volume_lock", 36),
    ("volume_unlock", 36),
    ("low_unmount", 212),
    ("low_unmount_format", 128),
    ("low_unmount_rebuild", 2700),
    ("low_unmount_repair", 1720),
    ("low_unmount_format_core", 864),
    ("reply_wait", 48),
    ("reply_kernel_wait", 676),
    ("reply_kernel_match", 104),
];

fn word(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn words(bytes: &[u8], offset: usize, expected: &[u32]) -> bool {
    expected
        .iter()
        .enumerate()
        .all(|(n, value)| word(bytes, offset + n * 4) == Some(*value))
}
fn address(bytes: &[u8], offsets: [usize; 4], reg: u32, value: u64) -> bool {
    offsets.into_iter().enumerate().all(|(half, offset)| {
        let opcode = if half == 0 { 0xd2800000 } else { 0xf2800000 };
        word(bytes, offset)
            == Some(
                opcode
                    | ((half as u32) << 21)
                    | (((value >> (half * 16)) as u32 & 0xffff) << 5)
                    | reg,
            )
    })
}
fn bl_target(site: u64, instruction: u32) -> Option<u64> {
    if instruction & 0xfc000000 != 0x94000000 {
        return None;
    }
    let displacement = ((instruction & 0x03ffffff) as i32) << 6 >> 6;
    site.checked_add_signed(i64::from(displacement) * 4)
}
fn b_target(site: u64, instruction: u32) -> Option<u64> {
    bl_target(site, instruction | 0x80000000).filter(|_| instruction & 0xfc000000 == 0x14000000)
}
/// The 64-bit constant a MOVZ (bits 0-15) and three MOVKs (16-31, 32-47,
/// 48-63) build in `reg`, read from the four given instruction offsets.
fn constant(bytes: &[u8], offsets: [usize; 4], reg: u32) -> Option<u64> {
    let mut value = 0u64;
    for (half, offset) in offsets.into_iter().enumerate() {
        let w = word(bytes, offset)?;
        let opcode = if half == 0 { 0xd2800000 } else { 0xf2800000 };
        if w & 0xffe0001f != opcode | ((half as u32) << 21) | reg {
            return None;
        }
        value |= u64::from((w >> 5) & 0xffff) << (half * 16);
    }
    Some(value)
}
/// `cmp w<reg>, #imm` (SUBS WZR, Wn, #imm12).
fn cmp_immediate(reg: u32, imm: u32) -> u32 {
    0x7100001f | (imm << 10) | (reg << 5)
}

impl NativeCardServices {
    pub fn entry(&self, name: &str) -> Option<u64> {
        Some(match name {
            "claim" => self.claim,
            "submit_frame" => self.submit_frame,
            "submit_wrapper" => self.submit_wrapper,
            "dispatcher" => self.dispatcher,
            "lock" => self.lock,
            "unlock" => self.unlock,
            "open" => self.open,
            "read" => self.read,
            "write" => self.write,
            "seek" => self.seek,
            "close" => self.close,
            "stat" => self.stat,
            "fcb_get" => self.fcb_get,
            "volume_sync" => self.volume_sync,
            "volume_index" => self.volume_index,
            "volume_ready" => self.volume_ready,
            "slot_flush" => self.slot_flush,
            "clean_source" => self.clean_source,
            "low_unmount" => self.low_unmount,
            "volume_lock" => self.volume_lock,
            "volume_unlock" => self.volume_unlock,
            "reply_wait" => self.rpc.wait_callee,
            "mount" => self.mount.callee,
            "unmount" => self.unmount.callee,
            "menu_getter" => self.menu.callee,
            "menu_exit_dispatch" => self.menu.exit_menu.as_ref()?.dispatch,
            "menu_exit_window" => self.menu.exit_menu.as_ref()?.current_window,
            auxiliary => {
                self.bodies
                    .iter()
                    .chain(self.menu.exit_menu.iter().flat_map(|e| &e.bodies))
                    .find(|b| b.name == auxiliary)?
                    .address
            }
        })
    }
}

impl Profile {
    pub(crate) fn validate_native_card(&self, mode: BuildMode, report: &mut ValidationReport) {
        let Some(card) = &self.services.native_card else {
            return;
        };
        let field = "services.native_card";
        // The Exec build sends a program's open and write through the card
        // owner's transaction to the low-level open, not through the
        // FILESRV wrapper whose flags the stock callers pass. A program's
        // write modes must then be exactly the two the audited state file
        // uses there, with that file's mode word.
        let ops = &self.services.file_ops;
        if self.services.fs_write.is_some()
            && (ops.open_read_write != Some(card.write_flags)
                || ops
                    .open_write_create
                    .is_some_and(|f| f != card.create_flags)
                || ops.create_attributes.is_some_and(|a| a != card.file_mode))
        {
            report.add(
                "services.file_ops.open_write_create",
                IssueKind::Conflict,
                "a native-card model writes through the low-level open: the program's write \
                 modes must be the state file's write_flags/create_flags and its file_mode",
            );
        }
        // One identity and one durability rule for both slots (decision 15):
        // the root may be on either stock volume, A: or B:. Which slot the
        // letter names is checked against the stock slot table's own volume
        // names in validate_native_card_bytes.
        if mode != BuildMode::Exec
            || self.identity.model != "Z8"
            || self.identity.firmware != "3.11"
            || self.abi.fs != Some(FsFamily::Z8FileV1)
            || !self
                .storage
                .root
                .as_deref()
                .is_some_and(|root| root.starts_with("A:\\") || root.starts_with("B:\\"))
        {
            report.add(field,IssueKind::Unsupported,"native card RPC is only audited for Z8 C3.11 Exec with an explicit A: or B: exFAT root");
        }
        if (card.callback_slot, card.request_bytes, card.operation) != (0, 0x118, 31)
            || (
                card.request_volume_offset,
                card.request_user_offset,
                card.request_callback_offset,
            ) != (8, 0x100, 0x108)
            || (
                card.request_operation_offset,
                card.request_result_offset,
                card.request_priority_offset,
            ) != (0x10c, 0x110, 0xf0)
        {
            report.add(field,IssueKind::Conflict,"native owned-frame RPC requires slot0, operation31 and its complete 0x118-byte layout");
        }
        if card.stat_bytes != 0x220
            || card.not_found != 0x80000010
            || card.write_flags != 1
            || card.file_mode != 0
            || card.create_flags != 0x301
            || card.journal_read_flags != 2
        {
            report.add(field,IssueKind::Conflict,"raw stat size/reason or journal existing-file open semantics differ from the audited family");
        }
        if card.menu.wake_mask != 8
            || card.menu.target_context_offset != 0x48
            || !valid_hash(&card.menu.worker_record_sha256)
            || self
                .memory
                .address_to_offset(card.menu.worker_record, 0x100)
                .is_err()
        {
            report.add("services.native_card.menu", IssueKind::Conflict,
                "GuiMe checkpoint requires its accepted undispatched wake bit, context field and mapped complete worker record");
        }
        let expected_low_sites = [
            ("low_unmount_format", 0x34),
            ("low_unmount_rebuild", 0x34),
            ("low_unmount_repair", 0x28),
            ("low_unmount_format_core", 0xb4),
        ]
        .map(|(name, at)| card.entry(name).and_then(|entry| entry.checked_add(at)));
        if card.low_unmount_call_sites.len() != 4
            || card
                .low_unmount_call_sites
                .iter()
                .copied()
                .map(Some)
                .collect::<Vec<_>>()
                != expected_low_sites
            || card.rpc.wait_call_site != card.submit_frame.saturating_add(0xec)
        {
            report.add(
                "services.native_card.rpc",
                IssueKind::Conflict,
                "all four original low-unmount edges and the actual submit wait must be observed",
            );
        }
        if let Some(exit) = &card.menu.exit_menu {
            if exit.menu_press_code != 0x27e
                || exit.gui_state != card.menu.worker_record.saturating_add(0xd0)
                || self
                    .menu
                    .page
                    .as_ref()
                    .and_then(|page| self.menu.window_address(page.window_id))
                    .is_none()
            {
                report.add("services.native_card.menu.exit_menu",IssueKind::Conflict,"original MENU dispatch requires the own window and original 32-bit GUI-state field");
            }
            let names: BTreeSet<_> = exit.bodies.iter().map(|e| e.name.as_str()).collect();
            for (name, size) in EXIT_BODIES {
                let e = exit.bodies.iter().find(|e| e.name == *name);
                if e.is_none_or(|e| {
                    e.length != *size
                        || !valid_hash(&e.sha256)
                        || card.entry(name) != Some(e.address)
                        || !self.memory.is_xip_range(e.address, u64::from(e.length))
                }) || !self
                    .service_fingerprints
                    .contains_key(&format!("native_card.{name}"))
                {
                    report.add(format!("services.native_card.menu.exit_menu.bodies.{name}"),IssueKind::Missing,"optional native MENU restoration requires every complete original body and fingerprint");
                }
            }
            if names.len() != EXIT_BODIES.len() || exit.bodies.len() != EXIT_BODIES.len() {
                report.add(
                    "services.native_card.menu.exit_menu.bodies",
                    IssueKind::Invalid,
                    "unknown or duplicate MENU restoration body",
                );
            }
        }
        let l = &card.layout;
        if (l.stat_size_offset, l.stat_attributes_offset) != (0x218, 0x20e) {
            report.add(
                "services.native_card.layout.stat",
                IssueKind::Conflict,
                "stat layout only attests native valid-data length and the attribute byte",
            );
        }
        if (
            l.volume_count,
            l.volume_stride,
            l.volume_device_offset,
            l.volume_name_offset,
            l.volume_state_offset,
            l.volume_type_offset,
            l.exfat_type,
        ) != (2, 0xc0, 0, 0x10, 0x50, 0x52, 4)
            || (
                l.media_count,
                l.media_stride,
                l.media_slot_offset,
                l.slot_count,
            ) != (3, 0x28, 0, 2)
        {
            report.add(
                "services.native_card.layout",
                IssueKind::Conflict,
                "native volume/media/slot layout differs from the audited family",
            );
        }
        if (
            l.fcb_volume_count,
            l.fcb_slot_count,
            l.fcb_volume_stride,
            l.fcb_slot_stride,
            l.fcb_flags_offset,
            l.fcb_ready_mask,
            l.fcb_reject_mask,
            l.fcb_valid_size_offset,
            l.fcb_data_size_offset,
            l.fcb_first_cluster_offset,
            l.fcb_last_cluster_offset,
            l.fcb_no_fat_chain_offset,
        ) != (
            2, 30, 0x3f570, 0x21c8, 0, 1, 0x40, 0x48, 0x20b8, 0x60, 0x68, 0x20c4,
        ) {
            report.add("services.native_card.layout.fcb", IssueKind::Conflict,
                "native handle validity and decoded exFAT stream fields differ from the audited family");
        }
        if (
            l.volume_sector_bytes_offset,
            l.volume_cluster_sectors_offset,
            l.volume_sector_shift_offset,
            l.volume_cluster_shift_offset,
            l.volume_cluster_heap_offset,
        ) != (0x54, 0x60, 0x3c, 0x3e, 0x80)
        {
            report.add(
                "services.native_card.layout.geometry",
                IssueKind::Conflict,
                "exFAT native contiguous-range geometry differs from original consumers",
            );
        }
        let ram = l.runtime_ram;
        if ram.start == 0 || ram.end <= ram.start || ram.start % 4096 != 0 || ram.end % 4096 != 0 {
            report.add(
                "services.native_card.layout.runtime_ram",
                IssueKind::Invalid,
                "native pointer observations require an explicit aligned runtime RAM range",
            );
        }
        for (name, base, size) in [
            ("callback_table", card.callback_table, 16),
            ("mutex", card.mutex, 16),
            ("rpc.reply_flag", card.rpc.reply_flag, 0x20),
            (
                "rpc.shared_frame",
                card.rpc.shared_frame,
                u64::from(card.request_bytes),
            ),
            (
                "fcb_table",
                l.fcb_table,
                u64::from(l.fcb_volume_count) * u64::from(l.fcb_volume_stride),
            ),
            (
                "volume_table",
                l.volume_table,
                u64::from(l.volume_count) * u64::from(l.volume_stride),
            ),
            (
                "media_table",
                l.media_table,
                u64::from(l.media_count) * u64::from(l.media_stride),
            ),
        ] {
            if base % 8 != 0 || !ram.contains(base, size) {
                report.add(
                    format!("services.native_card.{name}"),
                    IssueKind::OutOfBounds,
                    "native object range must be aligned and contained in the declared runtime RAM",
                );
            }
        }
        let mut seen = BTreeSet::new();
        for body in &card.bodies {
            let body_field = format!("services.native_card.bodies.{}", body.name);
            let required = BODIES.iter().find(|(name, _)| *name == body.name);
            if required.is_none() || !seen.insert(body.name.as_str()) {
                report.add(
                    &body_field,
                    IssueKind::Invalid,
                    "unknown or duplicate native card body",
                );
            }
            if required.is_some_and(|(_, length)| body.length != *length)
                || !valid_hash(&body.sha256)
                || body.address % 4 != 0
                || !self
                    .memory
                    .is_xip_range(body.address, u64::from(body.length))
            {
                report.add(&body_field,IssueKind::Invalid,"complete native function span/hash/XIP mapping differs from the audited family");
            }
            if card.entry(&body.name) != Some(body.address) {
                report.add(
                    &body_field,
                    IssueKind::Conflict,
                    "declared native service differs from its complete function evidence",
                );
            }
            if self.memory.slack.as_ref().is_some_and(|s| {
                s.range().overlaps(&crate::AddressRange {
                    start: body.address,
                    end: body.address.saturating_add(u64::from(body.length)),
                })
            }) {
                report.add(
                    &body_field,
                    IssueKind::Conflict,
                    "stock native evidence cannot be inside loader slack",
                );
            }
        }
        for (name, _) in BODIES {
            if !seen.contains(name) {
                report.add(
                    format!("services.native_card.bodies.{name}"),
                    IssueKind::Missing,
                    "native card family requires this complete stock body",
                );
            }
            if !self
                .service_fingerprints
                .contains_key(&format!("native_card.{name}"))
            {
                report.add(
                    format!("service_fingerprints.native_card.{name}"),
                    IssueKind::Missing,
                    "native primitive requires an entry fingerprint",
                );
            }
        }
        for (name, site, _callee) in [
            ("mount", card.mount.call_site, card.mount.callee),
            ("unmount", card.unmount.call_site, card.unmount.callee),
            ("menu", card.menu.call_site, card.menu.callee),
        ] {
            if !self.memory.is_xip_range(site, 4) || site % 4 != 0 {
                report.add(
                    format!("services.native_card.{name}.call_site"),
                    IssueKind::OutOfBounds,
                    "lifecycle hook requires an aligned stock XIP call site",
                );
            }
        }
    }

    pub(crate) fn validate_native_card_bytes(&self, module: &[u8], report: &mut ValidationReport) {
        let Some(card) = &self.services.native_card else {
            return;
        };
        let slice = |address: u64, length: u64| {
            self.memory
                .address_to_offset(address, length)
                .ok()
                .and_then(|at| usize::try_from(at).ok())
                .and_then(|at| module.get(at..at.checked_add(length as usize)?))
        };
        let body = |name: &str| {
            card.bodies
                .iter()
                .chain(card.menu.exit_menu.iter().flat_map(|e| &e.bodies))
                .find(|b| b.name == name)
                .and_then(|b| slice(b.address, u64::from(b.length)))
        };
        for evidence in card
            .bodies
            .iter()
            .chain(card.menu.exit_menu.iter().flat_map(|e| &e.bodies))
        {
            if !slice(evidence.address, u64::from(evidence.length))
                .is_some_and(|bytes| hash_matches(&sha256(bytes), &evidence.sha256))
            {
                report.add(
                    format!("services.native_card.bodies.{}", evidence.name),
                    IssueKind::FingerprintMismatch,
                    "complete native primitive differs from the official image",
                );
            }
        }
        let check = |ok: bool, name: &str, report: &mut ValidationReport| {
            if !ok {
                report.add(
                    format!("services.native_card.{name}"),
                    IssueKind::Conflict,
                    "native instruction semantics do not bind the declared contract",
                );
            }
        };
        check(
            body("claim").is_some_and(|b| {
                address(b, [0, 4, 8, 12], 9, card.callback_table)
                    && words(
                        b,
                        0x10,
                        &[
                            0xaa0003e8, 0xf940012a, 0xb400006a, 0x12800000, 0xd65f03c0, 0x2a1f03e0,
                            0xf9000128, 0xd65f03c0,
                        ],
                    )
            }),
            "claim",
            report,
        );
        check(
            body("submit_wrapper").is_some_and(|b| {
                address(b, [0x2c, 0x30, 0x34, 0x38], 8, card.callback_table)
                    && word(b, 0x1c) == Some(0x52802302)
                    && words(
                        b,
                        0x44,
                        &[
                            0x320003e8, 0xf9000bf5, 0x320013e9, 0xf90087f4, 0x910023e0, 0xb90113f3,
                            0xb9000be8, 0xb90117e9,
                        ],
                    )
                    && word(b, 0x64).and_then(|w| bl_target(card.submit_wrapper + 0x64, w))
                        == Some(card.submit_frame)
            }),
            "submit_wrapper",
            report,
        );
        check(
            body("dispatcher").is_some_and(|b| {
                address(b, [0x34, 0x38, 0x3c, 0x40], 9, card.dispatch_table)
                    && address(b, [0x818, 0x820, 0x824, 0x828], 8, card.callback_table)
                    && words(b, 0x82c, &[0xf8697908, 0xb4000ca8, 0xf9408260, 0xd63f0100])
            }),
            "dispatcher",
            report,
        );
        let dispatch_matches = slice(card.dispatch_table + 31 * 8, 8)
            .is_some_and(|b| u64::from_le_bytes(b.try_into().unwrap()) == card.dispatcher + 0x814);
        check(dispatch_matches, "dispatch_table", report);
        check(
            body("open_middleware").is_some_and(|b| {
                address(b, [0xc, 0x10, 0x14, 0x18], 22, card.mutex)
                    && word(b, 0x2c).and_then(|w| {
                        bl_target(card.entry("open_middleware").unwrap_or(0) + 0x2c, w)
                    }) == Some(card.lock)
                    && word(b, 0x3c).and_then(|w| {
                        bl_target(card.entry("open_middleware").unwrap_or(0) + 0x3c, w)
                    }) == Some(card.open)
                    && word(b, 0x48).and_then(|w| {
                        bl_target(card.entry("open_middleware").unwrap_or(0) + 0x48, w)
                    }) == Some(card.unlock)
            }),
            "mutex",
            report,
        );
        check(
            body("open").is_some_and(|b| {
                // Flags 2 sets read/write permission and follows the real open
                // lookup. Creation/truncation/append depend on other bits.
                words(b, 0xf0, &[0x720006bf, 0x540002c0, 0x320007e8, 0x39000a68])
                    && word(b, 0x100) == Some(0x360002b5)
                    && words(b, 0x154, &[0x52804109, 0x6a0902b9])
                    && word(b, 0x1b0).and_then(|w| bl_target(card.open + 0x1b0, w))
                        == card.entry("open_lookup")
            }) && body("read").is_some_and(|b| words(b, 0x48, &[0x39400a88, 0x360005c8])),
            "journal_read_flags",
            report,
        );
        check(
            body("stat").is_some_and(|b| word(b, 0x14c) == Some(0x2a1503e0))
                && body("lookup")
                    .is_some_and(|b| words(b, 0x178, &[0x52800208, 0x72b00008, 0x6b0802bf])),
            "not_found",
            report,
        );
        check(
            body("volume_index").is_some_and(|b| {
                address(b, [0xc, 0x10, 0x14, 0x28], 23, card.layout.volume_table)
                    && words(b, 0x24, &[0x321a07f6])
            }) && body("volume_ready").is_some_and(|b| {
                address(b, [0x20, 0x24, 0x2c, 0x30], 9, card.layout.volume_table)
                    && word(b, 0x38) == Some(0x39414129)
            }),
            "layout.volume_table",
            report,
        );
        check(
            body("media_lookup")
                .is_some_and(|b| address(b, [0x14, 0x1c, 0x24, 0x30], 9, card.layout.media_table)),
            "layout.media_table",
            report,
        );
        // The volume type byte and the exFAT value, as the volume sync reads
        // them: add x8, x8, #type_offset ... ldrb w8, [x8]; cmp w8, #exfat.
        check(
            body("volume_sync").is_some_and(|b| {
                word(b, 0x44) == Some(0x91000108 | (card.layout.volume_type_offset << 10))
                    && word(b, 0xbc) == Some(0x39400108)
                    && word(b, 0xc0) == Some(cmp_immediate(8, card.layout.exfat_type))
            }),
            "layout.exfat_type",
            report,
        );
        self.check_slot_flush(card, &slice, &body, report);
        check(
            body("fcb_get").is_some_and(|b| {
                address(b, [0x20, 0x24, 0x2c, 0x34], 9, card.layout.fcb_table)
                    && words(b, 0x10, &[0x7100051f, 0x540002c8, 0x7100743f])
                    && word(b, 0x28) == Some(0x529eae0a)
                    && word(b, 0x30) == Some(0x72a0006a)
                    && word(b, 0x3c) == Some(0x5284390a)
                    && words(b, 0x44, &[0x79400149, 0xf900004a, 0x36000149, 0x37300129])
            }),
            "fcb_get",
            report,
        );
        check(
            body("file_set_decode").is_some_and(|b| {
                words(b, 0x504, &[0xf9002668, 0x39406348])
                    && word(b, 0x544) == Some(0xf9105e68)
                    && word(b, 0x548) == Some(0x39405348)
                    && word(b, 0x568) == Some(0xf9003268)
            }),
            "layout.fcb",
            report,
        );
        check(
            body("clean_source").is_some_and(|b| {
                word(b, 12).and_then(|w| bl_target(card.clean_source + 12, w))
                    == card.entry("clean_helper")
            }) && body("clean_helper").is_some_and(|b| {
                word(b, 0x40) == Some(0xd50b7a28) && word(b, 0x50) == Some(0xd5033f9f)
            }),
            "clean_source",
            report,
        );
        check(
            slice(card.rpc.wait_call_site, 4)
                .and_then(|v| word(v, 0))
                .and_then(|w| bl_target(card.rpc.wait_call_site, w))
                == Some(card.rpc.wait_callee)
                && body("submit_frame").is_some_and(|b| {
                    address(b, [0x48, 0x50, 0x58, 0x60], 9, card.rpc.reply_flag)
                        && address(b, [0x68, 0x7c, 0x90, 0xa0], 12, card.rpc.shared_frame)
                        && word(b, 0x28) == Some(0xb9000fff)
                })
                && body("reply_wait").is_some_and(|b| {
                    word(b, 0x18) == Some(0x320003e2)
                        && word(b, 0x1c).and_then(|w| bl_target(card.rpc.wait_callee + 0x1c, w))
                            == card.entry("reply_kernel_wait")
                }),
            "rpc",
            report,
        );
        for &site in &card.low_unmount_call_sites {
            check(
                slice(site, 4)
                    .and_then(|v| word(v, 0))
                    .and_then(|w| bl_target(site, w))
                    == Some(card.low_unmount),
                "low_unmount_call_sites",
                report,
            );
        }
        if let Some(exit) = &card.menu.exit_menu {
            check(
                body("menu_exit_state_handler").is_some_and(|b| {
                    word(b, 0) == Some(0xb940d008) && word(b, 8) == Some(0xf9406d03)
                }) && slice(card.menu.worker_record + 0xe0, 8).is_some_and(|b| {
                    Some(u64::from_le_bytes(b.try_into().unwrap()))
                        == card.entry("menu_exit_state1")
                }),
                "menu.exit_menu.gui_state",
                report,
            );
            check(
                body("menu_exit_window").is_some_and(|b| {
                    word(b, 0x18).and_then(|w| bl_target(exit.current_window + 0x18, w))
                        == card.entry("menu_exit_window_helper")
                }),
                "menu.exit_menu.current_window",
                report,
            );
            check(
                body("menu_exit_state1").is_some_and(|b| {
                    word(b, 0x600).and_then(|w| {
                        bl_target(card.entry("menu_exit_state1").unwrap_or(0) + 0x600, w)
                    }) == Some(exit.dispatch)
                }),
                "menu.exit_menu.dispatch",
                report,
            );
        }
        check(
            body("volume_lock").is_some_and(|b| {
                word(b, 0x18) == Some(0x2a1f03e0) && word(b, 0x20) == Some(0xd65f03c0)
            }) && body("volume_unlock").is_some_and(|b| {
                word(b, 0x18) == Some(0x2a1f03e0) && word(b, 0x20) == Some(0xd65f03c0)
            }),
            "volume_lock",
            report,
        );
        let m = &card.menu;
        check(
            body("menu_getter").is_some_and(|b| word(b, 16) == Some(0xd65f03c0))
                && body("menu_loop").is_some_and(|b| {
                    address(b, [0x1c, 0x20, 0x24, 0x2c], 20, m.worker_record)
                        && word(b, 0x28) == Some(0x12a00893)
                        && !b.chunks_exact(4).any(|v| {
                            let w = u32::from_le_bytes(v.try_into().unwrap());
                            w & 0x7e00001f == 0x36000017 && ((w >> 19) & 0x1f) == 3
                        })
                }),
            "menu",
            report,
        );
        check(
            slice(m.worker_record, 0x100).is_some_and(|b| {
                hash_matches(&sha256(b), &m.worker_record_sha256)
                    && [
                        (0x58, "menu_init"),
                        (0x60, "menu_prepare"),
                        (0x68, "menu_loop"),
                    ]
                    .iter()
                    .all(|(at, name)| {
                        b.get(*at..*at + 8).is_some_and(|v| {
                            u64::from_le_bytes(v.try_into().unwrap())
                                == card.entry(name).unwrap_or(0)
                        })
                    })
            }),
            "menu.worker_record",
            report,
        );
        for (name, site, callee) in [
            ("mount", card.mount.call_site, card.mount.callee),
            ("unmount", card.unmount.call_site, card.unmount.callee),
            ("menu", card.menu.call_site, card.menu.callee),
        ] {
            check(
                slice(site, 4)
                    .and_then(|b| word(b, 0))
                    .and_then(|w| bl_target(site, w))
                    == Some(callee),
                name,
                report,
            );
        }
    }

    /// The stock per-slot flush, bound instruction by instruction:
    /// - slot_install builds the slot table (slot_table_init, then
    ///   slot_table_set stores its base), walks `slot_count` slots, and
    ///   registers a thunk that branches to slot_flush with
    ///   flush_hook_register;
    /// - flush_hook_register stores it in the hook the dispatcher loads and
    ///   calls after its write operations;
    /// - slot_flush loads that same table base and tail-calls the flush entry
    ///   (+0x80) of slot descriptor `slot` (0x88 bytes each, after an 8-byte
    ///   head), returning 0 where a slot has none;
    /// - slot_table_init copies exactly two 0x88-byte descriptors and gives
    ///   them their volume names; the root's drive must be one of them.
    fn check_slot_flush<'a>(
        &self,
        card: &NativeCardServices,
        slice: &impl Fn(u64, u64) -> Option<&'a [u8]>,
        body: &impl Fn(&str) -> Option<&'a [u8]>,
        report: &mut ValidationReport,
    ) {
        let check = |ok: bool, name: &str, report: &mut ValidationReport| {
            if !ok {
                report.add(
                    format!("services.native_card.{name}"),
                    IssueKind::Conflict,
                    "native instruction semantics do not bind the declared contract",
                );
            }
        };
        let entry = |name: &str| card.entry(name).unwrap_or(0);
        let table_base = body("slot_table_set").and_then(|b| {
            (word(b, 16) == Some(0xf9000100) && word(b, 20) == Some(0xd65f03c0))
                .then(|| constant(b, [0, 4, 8, 12], 8))
                .flatten()
        });
        check(
            table_base.is_some()
                && body("slot_flush").is_some_and(|b| {
                    constant(b, [0, 4, 8, 12], 8) == table_base
                        && words(
                            b,
                            0x10,
                            &[
                                0x52801109, 0xf9400108, 0x9ba92008, 0xf9404501, 0xb4000041,
                                0xd61f0020, 0x2a1f03e0, 0xd65f03c0,
                            ],
                        )
                }),
            "slot_flush",
            report,
        );
        let hook = body("flush_hook_register").and_then(|b| {
            (word(b, 16) == Some(0xf9000100) && word(b, 20) == Some(0xd65f03c0))
                .then(|| constant(b, [0, 4, 8, 12], 8))
                .flatten()
        });
        let install = entry("slot_install");
        let thunk = body("slot_install").and_then(|b| constant(b, [0x84, 0x88, 0x8c, 0x90], 0));
        check(
            body("slot_install").is_some_and(|b| {
                word(b, 4).and_then(|w| bl_target(install + 4, w)) == card.entry("slot_table_init")
                    && word(b, 8).and_then(|w| bl_target(install + 8, w))
                        == card.entry("slot_table_set")
                    && word(b, 0x1c) == Some(cmp_immediate(19, card.layout.slot_count))
                    && word(b, 0x98).and_then(|w| b_target(install + 0x98, w))
                        == card.entry("flush_hook_register")
            }) && thunk.is_some_and(|t| {
                slice(t, 4)
                    .and_then(|v| word(v, 0))
                    .and_then(|w| b_target(t, w))
                    == Some(card.slot_flush)
            }) && hook.is_some_and(|h| {
                body("dispatcher").is_some_and(|b| {
                    address(b, [0x5d0, 0x5dc, 0x5e4, 0x5f0], 8, h)
                        && word(b, 0x5f8) == Some(0xf9400114)
                        && word(b, 0x604) == Some(0xd63f0280)
                })
            }),
            "slot_flush_hook",
            report,
        );
        let init = entry("slot_table_init");
        let names = body("slot_table_init").and_then(|b| {
            let copies = word(b, 0x24) == Some(0x52801114)
                && word(b, 0x2c) == Some(0x91002260)
                && word(b, 0x44) == Some(0x91024260)
                && word(b, 0x30) == Some(0xaa1403e2)
                && word(b, 0x4c) == Some(0xaa1403e2)
                && word(b, 0x78) == Some(0xf9004a68)
                && word(b, 0x34)
                    .and_then(|w| bl_target(init + 0x34, w))
                    .is_some()
                && word(b, 0x34).and_then(|w| bl_target(init + 0x34, w))
                    == word(b, 0x50).and_then(|w| bl_target(init + 0x50, w));
            if !copies || card.layout.slot_count != 2 {
                return None;
            }
            let first = constant(b, [0x0c, 0x14, 0x1c, 0x28], 1)?;
            let first_name = u64::from_le_bytes(slice(first, 8)?.try_into().ok()?);
            let second_name = constant(b, [0x54, 0x5c, 0x64, 0x6c], 8)?;
            Some([slice(first_name, 3)?, slice(second_name, 3)?])
        });
        check(names.is_some(), "layout.slot_count", report);
        let root = self.storage.root.as_deref().unwrap_or("");
        if !names.is_some_and(|names| {
            names
                .iter()
                .any(|n| n[2] == 0 && n[1] == b':' && root.as_bytes().first() == Some(&n[0]))
        }) {
            report.add(
                "storage.root",
                IssueKind::Conflict,
                "the root's drive is not one of the stock slot table's volume names",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AddressRange, ExecutionBody, Memory, MemorySegment, MemorySegmentKind, NativeCardFamily,
        NativeCardLayout, NativeCardLifecycle, NativeCardMenu, NativeCardRpc, ServiceFingerprint,
    };

    fn fixture() -> Profile {
        let mut profile = Profile::draft("Z8", "3.11");
        profile.abi.fs = Some(FsFamily::Z8FileV1);
        profile.storage.root = Some("A:\\NLOADER\\".into());
        profile.memory = Memory {
            xip_base: Some(0x1000),
            module_size: Some(0x40000),
            segments: vec![MemorySegment {
                file_offset: 0,
                runtime_start: 0x1000,
                size: 0x40000,
                kind: MemorySegmentKind::Xip,
            }],
            ..Memory::default()
        };
        let bodies: Vec<_> = BODIES
            .iter()
            .enumerate()
            .map(|(n, (name, length))| ExecutionBody {
                name: (*name).into(),
                address: 0x1000 + n as u64 * 0x1000,
                length: *length,
                sha256: "00".repeat(32),
            })
            .collect();
        let entry = |name: &str| bodies.iter().find(|b| b.name == name).unwrap().address;
        let card = NativeCardServices {
            family: NativeCardFamily::Z8LowfilRpcV1,
            claim: entry("claim"),
            submit_frame: entry("submit_frame"),
            submit_wrapper: entry("submit_wrapper"),
            dispatcher: entry("dispatcher"),
            dispatch_table: 0x29000,
            callback_table: 0xb00001000,
            callback_slot: 0,
            request_bytes: 0x118,
            request_volume_offset: 8,
            request_user_offset: 0x100,
            request_callback_offset: 0x108,
            request_operation_offset: 0x10c,
            request_result_offset: 0x110,
            request_priority_offset: 0xf0,
            operation: 31,
            mutex: 0xb00002000,
            lock: entry("lock"),
            unlock: entry("unlock"),
            open: entry("open"),
            read: entry("read"),
            write: entry("write"),
            seek: entry("seek"),
            close: entry("close"),
            stat: entry("stat"),
            fcb_get: entry("fcb_get"),
            stat_bytes: 0x220,
            not_found: 0x80000010,
            write_flags: 1,
            file_mode: 0,
            create_flags: 0x301,
            journal_read_flags: 2,
            volume_sync: entry("volume_sync"),
            volume_index: entry("volume_index"),
            volume_ready: entry("volume_ready"),
            slot_flush: entry("slot_flush"),
            clean_source: entry("clean_source"),
            low_unmount: entry("low_unmount"),
            volume_lock: entry("volume_lock"),
            volume_unlock: entry("volume_unlock"),
            low_unmount_call_sites: [
                ("low_unmount_format", 0x34),
                ("low_unmount_rebuild", 0x34),
                ("low_unmount_repair", 0x28),
                ("low_unmount_format_core", 0xb4),
            ]
            .map(|(name, at)| entry(name) + at)
            .to_vec(),
            rpc: NativeCardRpc {
                wait_call_site: entry("submit_frame") + 0xec,
                wait_callee: entry("reply_wait"),
                reply_flag: 0xb00006000,
                shared_frame: 0xb00007000,
            },
            layout: NativeCardLayout {
                fcb_table: 0xb00100000,
                fcb_volume_count: 0x2,
                fcb_slot_count: 0x1e,
                fcb_volume_stride: 0x3f570,
                fcb_slot_stride: 0x21c8,
                fcb_flags_offset: 0x0,
                fcb_ready_mask: 0x1,
                fcb_reject_mask: 0x40,
                fcb_valid_size_offset: 0x48,
                fcb_data_size_offset: 0x20b8,
                fcb_first_cluster_offset: 0x60,
                fcb_last_cluster_offset: 0x68,
                fcb_no_fat_chain_offset: 0x20c4,
                stat_size_offset: 0x218,
                stat_attributes_offset: 0x20e,
                runtime_ram: AddressRange {
                    start: 0xb00000000,
                    end: 0xb40000000,
                },
                volume_table: 0xb00003000,
                volume_sector_bytes_offset: 0x54,
                volume_cluster_sectors_offset: 0x60,
                volume_sector_shift_offset: 0x3c,
                volume_cluster_shift_offset: 0x3e,
                volume_cluster_heap_offset: 0x80,

                volume_count: 2,
                volume_stride: 0xc0,
                volume_device_offset: 0,
                volume_name_offset: 0x10,
                volume_state_offset: 0x50,
                volume_type_offset: 0x52,
                exfat_type: 4,
                media_table: 0xb00004000,
                media_count: 3,
                media_stride: 0x28,
                media_slot_offset: 0,
                slot_count: 2,
            },
            mount: NativeCardLifecycle {
                call_site: 0x2a000,
                callee: entry("mount"),
            },
            unmount: NativeCardLifecycle {
                call_site: 0x2a004,
                callee: entry("unmount"),
            },
            menu: NativeCardMenu {
                call_site: 0x2a008,
                callee: entry("menu_getter"),
                wake_mask: 8,
                target_context_offset: 0x48,
                worker_record: 0x2b000,
                worker_record_sha256: "00".repeat(32),
                exit_menu: None,
            },
            bodies,
        };
        for body in &card.bodies {
            profile.service_fingerprints.insert(
                format!("native_card.{}", body.name),
                ServiceFingerprint {
                    eg_off: body.address - 0x1000,
                    stock: vec![0; 16],
                },
            );
        }
        profile.services.native_card = Some(card);
        profile
    }

    fn report(profile: &Profile) -> ValidationReport {
        let mut report = ValidationReport::default();
        profile.validate_native_card(BuildMode::Exec, &mut report);
        report
    }

    #[test]
    fn a_gui_turn_is_never_the_menu_checkpoint() {
        let mut profile = fixture();
        let site = profile
            .services
            .native_card
            .as_ref()
            .unwrap()
            .menu
            .call_site;
        let callee = profile.services.native_card.as_ref().unwrap().menu.callee;
        let turn = |site: u64| crate::PlatformGuiTurn {
            name: "menu".into(),
            site,
            callee,
            stock: (0x9400_0000u32 | (((callee as i64 - site as i64) / 4) as u32 & 0x03ff_ffff))
                .to_le_bytes()
                .to_vec(),
        };
        profile.services.platform = Some(crate::PlatformServices {
            gui_turns: vec![turn(site)],
            ..Default::default()
        });
        let conflict = |profile: &Profile| {
            let mut report = ValidationReport::default();
            profile.validate_platform(&mut report);
            report.issues.iter().any(|i| {
                i.kind == IssueKind::Conflict && i.field == "services.platform.gui_turns.menu"
            })
        };
        assert!(conflict(&profile));
        profile.services.platform.as_mut().unwrap().gui_turns = vec![turn(site + 4)];
        assert!(!conflict(&profile));
    }

    #[test]
    fn explicit_complete_contract_is_valid_and_absent_contract_stays_disabled() {
        assert!(report(&fixture()).is_valid());
        let mut absent = fixture();
        absent.services.native_card = None;
        assert!(report(&absent).is_valid());
    }

    /// Dev firmware runs its boot pass on the file store: a profile with a
    /// native card store is refused for it, with the field named, while the
    /// same profile without that store (and with the boot checkpoint) is
    /// accepted.
    #[test]
    fn dev_core_with_a_native_card_store_is_refused() {
        let mut profile = fixture();
        profile.boot_hooks.autoload = Some(crate::BootCall {
            call_site: 0x2000,
            callee: 0x3000,
        });
        let refused = profile.validate_dev_core();
        assert!(!refused.is_valid());
        assert!(refused.issues.iter().any(|issue| {
            issue.kind == IssueKind::Unsupported && issue.field == "services.native_card"
        }));
        profile.services.native_card = None;
        assert!(profile.validate_dev_core().is_valid());
        profile.boot_hooks.autoload = None;
        assert!(profile
            .validate_dev_core()
            .issues
            .iter()
            .any(|issue| issue.kind == IssueKind::Missing && issue.field == "boot_hooks.autoload"));
    }

    #[test]
    fn program_write_modes_are_the_state_files_own() {
        let mut p = fixture();
        p.services.fs_write = Some(0x1000);
        p.services.file_ops.open_read_write = Some(1);
        p.services.file_ops.open_write_create = Some(0x301);
        p.services.file_ops.create_attributes = Some(0);
        assert!(report(&p).is_valid());
        // The FILESRV wrapper's own create attributes do not reach the
        // low-level open, nor do flags the state file never uses.
        for edit in [
            |p: &mut Profile| p.services.file_ops.create_attributes = Some(0x20),
            |p: &mut Profile| p.services.file_ops.open_read_write = Some(0x101),
            |p: &mut Profile| p.services.file_ops.open_read_write = None,
            |p: &mut Profile| p.services.file_ops.open_write_create = Some(0x302),
        ] {
            let mut wrong = p.clone();
            edit(&mut wrong);
            assert!(report(&wrong)
                .issues
                .iter()
                .any(|issue| issue.field == "services.file_ops.open_write_create"));
        }
        // Without a write wrapper nothing is written and nothing is asked.
        let mut p = fixture();
        p.services.file_ops.open_read_write = Some(0x101);
        assert!(report(&p).is_valid());
    }

    #[test]
    fn refuses_wrong_platform_root_or_rung() {
        // Either stock volume carries the same rule (decision 15).
        let mut p = fixture();
        p.storage.root = Some("B:\\NLOADER\\".into());
        assert!(report(&p).is_valid());
        for root in ["C:\\NLOADER\\", "NLOADER\\", "a:\\NLOADER\\"] {
            let mut p = fixture();
            p.storage.root = Some(root.into());
            assert!(!report(&p).is_valid(), "{root}");
        }
        let mut p = fixture();
        p.identity.firmware = "3.10".into();
        assert!(!report(&p).is_valid());
        let mut report = ValidationReport::default();
        fixture().validate_native_card(BuildMode::LoadOnly, &mut report);
        assert!(!report.is_valid());
    }

    #[test]
    fn refuses_unsafe_rpc_and_io_contracts() {
        let edits: [fn(&mut NativeCardServices); 16] = [
            |c| c.callback_slot = 1,
            |c| c.request_bytes = 0x110,
            |c| c.request_user_offset = 0xf8,
            |c| c.request_priority_offset = 0,
            |c| c.operation = 32,
            |c| c.not_found = u32::MAX,
            |c| c.write_flags = 0x301,
            |c| c.stat_bytes = 32,
            |c| c.layout.slot_count = 3,
            |c| c.menu.wake_mask = 4,
            |c| c.layout.fcb_valid_size_offset = 0x20b8,
            |c| c.create_flags = 0,
            |c| c.journal_read_flags = 0,
            |c| c.journal_read_flags = 1,
            |c| c.journal_read_flags = 0x301,
            |c| c.layout.volume_cluster_sectors_offset = 0x54,
        ];
        for edit in edits {
            let mut p = fixture();
            edit(p.services.native_card.as_mut().unwrap());
            assert!(!report(&p).is_valid());
        }
    }

    #[test]
    fn refuses_missing_divergent_or_short_stock_evidence() {
        let mut p = fixture();
        p.services.native_card.as_mut().unwrap().bodies.pop();
        assert!(!report(&p).is_valid());
        let mut p = fixture();
        p.services.native_card.as_mut().unwrap().claim += 4;
        assert!(!report(&p).is_valid());
        let mut p = fixture();
        p.services.native_card.as_mut().unwrap().bodies[0].length = 16;
        assert!(!report(&p).is_valid());
        let mut p = fixture();
        p.service_fingerprints.remove("native_card.write");
        assert!(!report(&p).is_valid());
    }

    #[test]
    fn zero_synthetic_bytes_cannot_attest_instruction_semantics() {
        let p = fixture();
        let mut report = ValidationReport::default();
        p.validate_native_card_bytes(&vec![0; 0x40000], &mut report);
        assert!(report
            .issues
            .iter()
            .any(|i| i.field == "services.native_card.claim"));
        assert!(report
            .issues
            .iter()
            .any(|i| i.field == "services.native_card.not_found"));
        assert!(report
            .issues
            .iter()
            .any(|i| i.field == "services.native_card.mount"));
        for field in [
            "services.native_card.slot_flush",
            "services.native_card.slot_flush_hook",
            "services.native_card.layout.slot_count",
            "services.native_card.layout.exfat_type",
            "storage.root",
        ] {
            assert!(report.issues.iter().any(|i| i.field == field), "{field}");
        }
    }

    /// A synthetic module carrying exactly the stock instruction shapes of
    /// the per-slot flush chain and the volume type check (the words read
    /// from the Z 8 C3.11 module, build/z8-c-20261017/sd-full/RESEARCH.md),
    /// with the fixture's own addresses.
    fn slot_chain_module(p: &Profile) -> Vec<u8> {
        let card = p.services.native_card.as_ref().unwrap();
        let entry = |name: &str| card.entry(name).unwrap();
        let mut module = vec![0u8; 0x40000];
        let mut put = |address: u64, value: u32| {
            let at = (address - 0x1000) as usize;
            module[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        let load = |put: &mut dyn FnMut(u64, u32), at: [u64; 4], reg: u32, value: u64| {
            for (half, address) in at.into_iter().enumerate() {
                let opcode = if half == 0 { 0xd2800000 } else { 0xf2800000 };
                put(
                    address,
                    opcode
                        | ((half as u32) << 21)
                        | (((value >> (half * 16)) as u32 & 0xffff) << 5)
                        | reg,
                );
            }
        };
        let branch = |from: u64, to: u64, link: bool| {
            (if link { 0x94000000u32 } else { 0x14000000 })
                | ((to.wrapping_sub(from) >> 2) as u32 & 0x03ff_ffff)
        };
        let (table, hook) = (0xb00009000u64, 0xb0000a000u64);
        let set = entry("slot_table_set");
        load(&mut put, [set, set + 4, set + 8, set + 12], 8, table);
        put(set + 16, 0xf9000100);
        put(set + 20, 0xd65f03c0);
        let flush = entry("slot_flush");
        load(
            &mut put,
            [flush, flush + 4, flush + 8, flush + 12],
            8,
            table,
        );
        for (n, w) in [
            0x52801109u32,
            0xf9400108,
            0x9ba92008,
            0xf9404501,
            0xb4000041,
            0xd61f0020,
            0x2a1f03e0,
            0xd65f03c0,
        ]
        .into_iter()
        .enumerate()
        {
            put(flush + 0x10 + 4 * n as u64, w);
        }
        let register = entry("flush_hook_register");
        load(
            &mut put,
            [register, register + 4, register + 8, register + 12],
            8,
            hook,
        );
        put(register + 16, 0xf9000100);
        put(register + 20, 0xd65f03c0);
        let install = entry("slot_install");
        let init = entry("slot_table_init");
        let thunk = install + 0x200;
        put(install + 4, branch(install + 4, init, true));
        put(install + 8, branch(install + 8, set, true));
        put(install + 0x1c, cmp_immediate(19, 2));
        load(
            &mut put,
            [0x84, 0x88, 0x8c, 0x90].map(|o| install + o),
            0,
            thunk,
        );
        put(install + 0x98, branch(install + 0x98, register, false));
        put(thunk, branch(thunk, flush, false));
        let dispatcher = entry("dispatcher");
        load(
            &mut put,
            [0x5d0, 0x5dc, 0x5e4, 0x5f0].map(|o| dispatcher + o),
            8,
            hook,
        );
        put(dispatcher + 0x5f8, 0xf9400114);
        put(dispatcher + 0x604, 0xd63f0280);
        let (template, name_a, name_b) = (init + 0x900, init + 0xa00, init + 0xa10);
        for (o, w) in [
            (0x24, 0x52801114u32),
            (0x2c, 0x91002260),
            (0x44, 0x91024260),
            (0x30, 0xaa1403e2),
            (0x4c, 0xaa1403e2),
            (0x78, 0xf9004a68),
        ] {
            put(init + o, w);
        }
        put(init + 0x34, branch(init + 0x34, init + 0x800, true));
        put(init + 0x50, branch(init + 0x50, init + 0x800, true));
        load(
            &mut put,
            [0x0c, 0x14, 0x1c, 0x28].map(|o| init + o),
            1,
            template,
        );
        load(
            &mut put,
            [0x54, 0x5c, 0x64, 0x6c].map(|o| init + o),
            8,
            name_b,
        );
        put(template, name_a as u32);
        put(template + 4, (name_a >> 32) as u32);
        put(name_a, u32::from_le_bytes(*b"A:\0\0"));
        put(name_b, u32::from_le_bytes(*b"B:\0\0"));
        let sync = entry("volume_sync");
        put(sync + 0x44, 0x91000108 | (0x52 << 10));
        put(sync + 0xbc, 0x39400108);
        put(sync + 0xc0, cmp_immediate(8, 4));
        module
    }

    fn slot_issues(p: &Profile, module: &[u8]) -> Vec<String> {
        let mut report = ValidationReport::default();
        p.validate_native_card_bytes(module, &mut report);
        report
            .issues
            .into_iter()
            .map(|i| i.field)
            .filter(|f| {
                f.starts_with("services.native_card.slot_flush")
                    || f == "services.native_card.layout.slot_count"
                    || f == "services.native_card.layout.exfat_type"
                    || f == "storage.root"
            })
            .collect()
    }

    /// One durability rule on both slots: the per-slot flush bound through
    /// its install, hook and dispatcher call; the slot table's own names
    /// admit A: and B: and nothing else. Each broken link is refused.
    #[test]
    fn the_per_slot_flush_and_the_roots_drive_are_bound_to_stock_bytes() {
        let mut p = fixture();
        let module = slot_chain_module(&p);
        assert_eq!(slot_issues(&p, &module), Vec::<String>::new());
        p.storage.root = Some("B:\\NLOADER\\".into());
        assert_eq!(slot_issues(&p, &module), Vec::<String>::new());
        p.storage.root = Some("C:\\NLOADER\\".into());
        assert_eq!(slot_issues(&p, &module), ["storage.root"]);
        let card = |p: &Profile| p.services.native_card.clone().unwrap();
        let at = |p: &Profile, name: &str| (card(p).entry(name).unwrap() - 0x1000) as usize;
        let p = fixture();
        // a flush that is not what the hook's thunk branches to
        let mut q = p.clone();
        q.services.native_card.as_mut().unwrap().slot_flush += 4;
        assert!(slot_issues(&q, &module)
            .iter()
            .any(|f| f == "services.native_card.slot_flush_hook"));
        for (name, offset, field) in [
            ("slot_flush", 0x1c, "services.native_card.slot_flush"),
            ("slot_table_set", 0, "services.native_card.slot_flush"),
            ("slot_install", 0x1c, "services.native_card.slot_flush_hook"),
            ("slot_install", 0x98, "services.native_card.slot_flush_hook"),
            ("dispatcher", 0x604, "services.native_card.slot_flush_hook"),
            (
                "flush_hook_register",
                0,
                "services.native_card.slot_flush_hook",
            ),
            (
                "slot_table_init",
                0x44,
                "services.native_card.layout.slot_count",
            ),
            (
                "volume_sync",
                0xc0,
                "services.native_card.layout.exfat_type",
            ),
        ] {
            let mut broken = module.clone();
            broken[at(&p, name) + offset] ^= 0x20;
            assert!(
                slot_issues(&p, &broken).iter().any(|f| f == field),
                "{name}+{offset:#x}"
            );
        }
        let mut q = p.clone();
        q.services.native_card.as_mut().unwrap().layout.exfat_type = 3;
        assert!(slot_issues(&q, &module)
            .iter()
            .any(|f| f == "services.native_card.layout.exfat_type"));
    }
}
