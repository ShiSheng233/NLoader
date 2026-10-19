//! Complete original drawing and GUI ownership evidence for one audited family.
use crate::validation::{hash_matches, valid_hash};
use crate::{sha256, AddressRange, BuildMode, IssueKind, Profile, ValidationReport};
use std::collections::BTreeSet;
const BODIES: &[(&str, u32)] = &[
    ("blit", 492),
    ("current_index", 88),
    ("current_surface", 256),
    ("caller", 320),
    ("current_window", 44),
    ("window_helper", 44),
    ("current_task", 144),
    ("clean_source", 28),
    ("clean_helper", 100),
    ("menu_constructor", 88),
    ("worker_constructor", 64),
    ("task_constructor", 276),
    ("app_config_getter", 36),
    ("app_config_setter", 24),
    ("app_config_base", 20),
    ("config_install", 568),
];
fn word(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn target(site: u64, w: u32) -> Option<u64> {
    if w & 0xfc000000 != 0x94000000 {
        return None;
    }
    site.checked_add_signed(i64::from(((w & 0x03ffffff) as i32) << 6 >> 6) * 4)
}
fn materializes(b: &[u8], at: [usize; 4], reg: u32, value: u64) -> bool {
    at.into_iter().enumerate().all(|(n, at)| {
        word(b, at)
            == Some(
                (if n == 0 { 0xd2800000 } else { 0xf2800000 })
                    | ((n as u32) << 21)
                    | (((value >> (16 * n)) as u32 & 0xffff) << 5)
                    | reg,
            )
    })
}
impl Profile {
    pub(crate) fn validate_bitmap(&self, mode: BuildMode, report: &mut ValidationReport) {
        let Some(b) = &self.services.bitmap else {
            return;
        };
        if mode != BuildMode::Exec
            || self.identity.model != "Z8"
            || self.identity.firmware != "3.11"
            || self.menu.page.is_none()
        {
            report.add(
                "services.bitmap",
                IssueKind::Unsupported,
                "native bitmap diagnostics require Z8 C3.11 Exec and the declared NLoader page",
            );
        }
        if b.blit != b.original_callee
            || b.gui_task_name != "APPMENU"
            || self
                .memory
                .address_to_offset(b.gui_task_config, 28)
                .is_err()
        {
            report.add("services.bitmap.owner",IssueKind::Conflict,"original drawing identity and the complete APPMENU task configuration are required");
        }
        if self.services.dcache_inv_post != Some(b.clean_source)
            || self.services.registry_lookup.is_none()
        {
            report.add(
                "services.bitmap.clean_source",
                IssueKind::Conflict,
                "bitmap sources require the audited native clean and task registry interfaces",
            );
        }
        let t = &b.surface_case_table;
        if t.name != "surface_cases"
            || t.element_bytes != 8
            || t.address % 8 != 0
            || t.values != [0x80, 0x9c, 0xac, 0xc8, 0xdc].map(|offset| b.current_surface + offset)
        {
            report.add("services.bitmap.surface_case_table",IssueKind::Conflict,"all five original surface-selector cases must bind the getter's complete dispatcher");
        }
        let mut seen = BTreeSet::new();
        for e in &b.bodies {
            let expected = BODIES.iter().find(|(name, _)| *name == e.name);
            if !seen.insert(e.name.as_str())
                || expected.is_none_or(|(_, n)| *n != e.length)
                || !valid_hash(&e.sha256)
                || e.address % 4 != 0
                || !self.memory.is_xip_range(e.address, u64::from(e.length))
                || b.entry(&e.name) != Some(e.address)
            {
                report.add(
                    format!("services.bitmap.bodies.{}", e.name),
                    IssueKind::Invalid,
                    "unknown, duplicate, incomplete or conflicting original bitmap body",
                );
            }
            if self.memory.slack.as_ref().is_some_and(|s| {
                s.range().overlaps(&AddressRange {
                    start: e.address,
                    end: e.address.saturating_add(u64::from(e.length)),
                })
            }) {
                report.add(
                    format!("services.bitmap.bodies.{}", e.name),
                    IssueKind::Conflict,
                    "original drawing evidence overlaps loader reservation",
                );
            }
        }
        for (name, _) in BODIES {
            if !seen.contains(name)
                || !self
                    .service_fingerprints
                    .contains_key(&format!("bitmap.{name}"))
            {
                report.add(format!("services.bitmap.bodies.{name}"),IssueKind::Missing,"bitmap diagnostics require the complete original body and its entry fingerprint");
            }
        }
        if !self.memory.is_xip_range(b.call_site, 4) || b.call_site % 4 != 0 {
            report.add(
                "services.bitmap.call_site",
                IssueKind::OutOfBounds,
                "bitmap observation requires an aligned original GUI call site",
            );
        }
    }
    pub(crate) fn validate_bitmap_bytes(&self, module: &[u8], report: &mut ValidationReport) {
        let Some(b) = &self.services.bitmap else {
            return;
        };
        let slice = |a, n| {
            self.memory
                .address_to_offset(a, n)
                .ok()
                .and_then(|at| usize::try_from(at).ok())
                .and_then(|at| module.get(at..at.checked_add(n as usize)?))
        };
        let body = |name: &str| {
            b.bodies
                .iter()
                .find(|e| e.name == name)
                .and_then(|e| slice(e.address, u64::from(e.length)))
        };
        for e in &b.bodies {
            if !slice(e.address, u64::from(e.length))
                .is_some_and(|v| hash_matches(&sha256(v), &e.sha256))
            {
                report.add(
                    format!("services.bitmap.bodies.{}", e.name),
                    IssueKind::FingerprintMismatch,
                    "complete original bitmap body differs from the official image",
                );
            }
        }
        let mut check = |ok: bool, name: &str| {
            if !ok {
                report.add(
                    format!("services.bitmap.{name}"),
                    IssueKind::Conflict,
                    "original bitmap instructions do not establish the declared contract",
                )
            }
        };
        check(
            slice(b.call_site, 4)
                .and_then(|v| word(v, 0))
                .and_then(|w| target(b.call_site, w))
                == Some(b.original_callee)
                && b.entry("caller").is_some_and(|a| b.call_site == a + 0x124),
            "call_site",
        );
        check(
            body("blit").is_some_and(|v| {
                word(v, 0x1e0) == Some(0x2a1f03e0) && word(v, 0x1e8) == Some(0xd65f03c0)
            }),
            "blit",
        );
        check(
            slice(b.surface_case_table.address, 40).is_some_and(|v| {
                v.chunks_exact(8)
                    .zip(&b.surface_case_table.values)
                    .all(|(v, expected)| u64::from_le_bytes(v.try_into().unwrap()) == *expected)
            }) && body("current_surface").is_some_and(|v| {
                materializes(
                    v,
                    [0x64, 0x68, 0x6c, 0x74],
                    12,
                    b.surface_case_table.address,
                ) && word(v, 0xf4) == Some(0x2a1f03e0)
                    && word(v, 0xfc) == Some(0xd65f03c0)
            }),
            "surface_case_table",
        );
        check(
            body("current_window").is_some_and(|v| {
                word(v, 0x18).and_then(|w| target(b.current_window + 0x18, w))
                    == b.entry("window_helper")
            }),
            "current_window",
        );
        check(
            body("clean_source").is_some_and(|v| {
                word(v, 12).and_then(|w| target(b.clean_source + 12, w)) == b.entry("clean_helper")
            }) && body("clean_helper").is_some_and(|v| {
                word(v, 0x40) == Some(0xd50b7a28) && word(v, 0x50) == Some(0xd5033f9f)
            }),
            "clean_source",
        );
        let cfg_base = b.gui_task_config.checked_sub(7 * 28);
        check(
            slice(b.gui_task_config, 28).is_some_and(|v| &v[13..21] == b"APPMENU\0")
                && body("app_config_base").is_some_and(|v| {
                    cfg_base.is_some_and(|a| materializes(v, [0, 4, 8, 12], 0, a))
                })
                && body("config_install").is_some_and(|v| {
                    word(v, 0x70)
                        .and_then(|w| target(b.entry("config_install").unwrap_or(0) + 0x70, w))
                        == b.entry("app_config_base")
                        && word(v, 0x74)
                            .and_then(|w| target(b.entry("config_install").unwrap_or(0) + 0x74, w))
                            == b.entry("app_config_setter")
                })
                && body("menu_constructor").is_some_and(|v| {
                    word(v, 0x14)
                        .and_then(|w| target(b.entry("menu_constructor").unwrap_or(0) + 0x14, w))
                        == b.entry("app_config_getter")
                        && word(v, 8) == Some(0x528000f3)
                        && word(v, 12) == Some(0x72a00033)
                }),
            "gui_task_name",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BitmapFamily, BitmapMode, BitmapServices, ExecutionBody, ExecutionTable, Memory,
        MemorySegment, MemorySegmentKind, MenuOwnPage, ServiceFingerprint,
    };
    fn fixture() -> Profile {
        let mut p = Profile::draft("Z8", "3.11");
        p.memory = Memory {
            xip_base: Some(0x1000),
            module_size: Some(0x21000),
            segments: vec![
                MemorySegment {
                    file_offset: 0,
                    runtime_start: 0x1000,
                    size: 0x20000,
                    kind: MemorySegmentKind::Xip,
                },
                MemorySegment {
                    file_offset: 0x20000,
                    runtime_start: 0xb00000000,
                    size: 0x1000,
                    kind: MemorySegmentKind::Ram,
                },
            ],
            ..Memory::default()
        };
        p.menu.page = Some(MenuOwnPage {
            refresh: None,
            window_id: 1,
            page_record: 0xb00000100,
            template_window: 2,
            template_page: 0xb00000200,
            row_event_table: 0x1500,
            row_template_event_table: 0x1600,
            title_slot: 1,
            title_format: 1,
            item_id: 1,
            item_flags: 0,
            item_slot: 1,
            item_style: 1,
            item_text: "test".into(),
            row_slots: vec![],
            row_hide: None,
            row_hide_stock: vec![],
            selected_offset: None,
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
        let bodies: Vec<_> = BODIES
            .iter()
            .enumerate()
            .map(|(n, (name, size))| ExecutionBody {
                name: (*name).into(),
                address: 0x1000 + n as u64 * 0x1000,
                length: *size,
                sha256: "00".repeat(32),
            })
            .collect();
        let entry = |name: &str| bodies.iter().find(|b| b.name == name).unwrap().address;
        p.services.dcache_inv_post = Some(entry("clean_source"));
        p.services.registry_lookup = Some(0x18000);
        let b = BitmapServices {
            family: BitmapFamily::Z8BitmapProbeV1,
            mode: BitmapMode::Trace,
            blit: entry("blit"),
            current_index: entry("current_index"),
            current_surface: entry("current_surface"),
            current_window: entry("current_window"),
            current_task: entry("current_task"),
            clean_source: entry("clean_source"),
            call_site: entry("caller") + 0x124,
            original_callee: entry("blit"),
            gui_task_name: "APPMENU".into(),
            gui_task_config: 0xb00000000,
            surface_case_table: ExecutionTable {
                name: "surface_cases".into(),
                address: 0x19000,
                element_bytes: 8,
                values: [0x80, 0x9c, 0xac, 0xc8, 0xdc]
                    .map(|n| entry("current_surface") + n)
                    .to_vec(),
            },
            bodies,
        };
        for e in &b.bodies {
            p.service_fingerprints.insert(
                format!("bitmap.{}", e.name),
                ServiceFingerprint {
                    eg_off: e.address - 0x1000,
                    stock: vec![0; 16],
                },
            );
        }
        p.services.bitmap = Some(b);
        p
    }
    fn report(p: &Profile) -> ValidationReport {
        let mut r = ValidationReport::default();
        p.validate_bitmap(BuildMode::Exec, &mut r);
        r
    }
    #[test]
    fn trace_is_explicit_optional_and_complete() {
        let mut p = fixture();
        assert!(report(&p).is_valid());
        p.services.bitmap = None;
        assert!(report(&p).is_valid());
        assert_eq!(BitmapMode::Trace.pattern(), 0);
        assert_eq!(BitmapMode::Checker.pattern(), 1);
        assert_eq!(BitmapMode::Rgb.pattern(), 2);
    }
    #[test]
    fn incomplete_or_wrong_owner_cannot_enable_drawing() {
        let changes: [fn(&mut BitmapServices); 4] = [
            |b| b.gui_task_name = "GuiMe".into(),
            |b| b.original_callee += 4,
            |b| b.bodies[0].length = 16,
            |b| b.surface_case_table.values[0] += 4,
        ];
        for change in changes {
            let mut p = fixture();
            change(p.services.bitmap.as_mut().unwrap());
            assert!(!report(&p).is_valid());
        }
        let mut p = fixture();
        p.service_fingerprints.remove("bitmap.current_task");
        assert!(!report(&p).is_valid());
        let mut r = ValidationReport::default();
        fixture().validate_bitmap(BuildMode::LoadOnly, &mut r);
        assert!(!r.is_valid());
    }
    #[test]
    fn synthetic_zeroes_cannot_attest_gui_or_cleaning() {
        let mut r = ValidationReport::default();
        fixture().validate_bitmap_bytes(&vec![0; 0x21000], &mut r);
        for name in ["call_site", "gui_task_name", "clean_source"] {
            assert!(r
                .issues
                .iter()
                .any(|i| i.field == format!("services.bitmap.{name}")));
        }
    }
}
