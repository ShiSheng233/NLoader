//! Complete original drawing and GUI ownership evidence for one audited family.
use crate::validation::{hash_matches, valid_hash};
use crate::{sha256, AddressRange, BuildMode, IssueKind, Profile, ValidationReport};
use std::collections::BTreeSet;
const BODIES: &[(&str, u32)] = &[
    ("blit", 492),
    ("current_index", 88),
    ("current_surface", 256),
    ("caller", 1372),
    ("text_draw", 6244),
    ("widget_root", 32),
    ("surface_record", 348),
    ("surface_record_consumer", 224),
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
fn expected_bodies(family: crate::PaintFamily) -> Vec<(&'static str, u32)> {
    let mut bodies = BODIES.to_vec();
    if family == crate::PaintFamily::Z8TextNativeBitmapProbeV1 {
        bodies[0] = ("blit", 296);
        bodies.extend([
            ("bitmap_translate", 200),
            ("bitmap_draw", 620),
            ("bitmap_target_setup", 116),
            ("bitmap_target_restore", 28),
        ]);
    }
    bodies
}
pub(super) fn word(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
pub(super) fn target(site: u64, w: u32) -> Option<u64> {
    if w & 0xfc000000 != 0x94000000 {
        return None;
    }
    site.checked_add_signed(i64::from(((w & 0x03ffffff) as i32) << 6 >> 6) * 4)
}
pub(super) fn materializes(b: &[u8], at: [usize; 4], reg: u32, value: u64) -> bool {
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
    pub(crate) fn validate_paint(&self, mode: BuildMode, report: &mut ValidationReport) {
        let Some(b) = &self.services.paint else {
            return;
        };
        if mode != BuildMode::Exec
            || self.identity.model != "Z8"
            || self.identity.firmware != "3.11"
            || self.menu.page.is_none()
        {
            report.add(
                "services.paint",
                IssueKind::Unsupported,
                "native paint diagnostics require Z8 C3.11 Exec and the declared NLoader page",
            );
        }
        if b.text_draw != b.original_callee
            || b.gui_task_name != "APPMENU"
            || self
                .memory
                .address_to_offset(b.gui_task_config, 28)
                .is_err()
        {
            report.add("services.paint.owner",IssueKind::Conflict,"original drawing identity and the complete APPMENU task configuration are required");
        }
        if b.surface_group > 1
            || (b.mode != crate::BitmapMode::Trace && b.surface_group != 1)
            || (b.surface_group == 1 && b.surface_mapping.is_none())
        {
            report.add("services.paint.surface_group",IssueKind::Unsupported,"drawing requires the independently checked group1 mapping; trace may retain unknown group0");
        }
        if b.full_screen && b.family != crate::PaintFamily::Z8TextNativeBitmapProbeV1 {
            report.add(
                "services.paint.full_screen",
                IssueKind::Unsupported,
                "full-screen diagnostics require the audited alternate native bitmap family",
            );
        }
        if let Some(m) = &b.surface_mapping {
            if m.group_map.name != "surface_groups"
                || m.group_map.element_bytes != 1
                || m.group_map.values != [0, 0]
                || !self.memory.is_xip_range(m.group_map.address, 2)
                || m.type_cases.name != "record_types"
                || m.type_cases.element_bytes != 8
                || m.type_cases.address % 8 != 0
                || m.type_cases.values
                    != [0x40, 0x78, 0xb4, 0xf0, 0x124].map(|n| b.surface_record + n)
                || m.record_base == 0
                || m.record_base % 8 != 0
                || (m.group_stride, m.index_stride, m.index_offset) != (0x1938, 0x208, 0xb0)
            {
                report.add("services.paint.surface_mapping",IssueKind::Conflict,"native group1 and all five record type cases must bind the original bounded lookup");
            }
        }
        if self.services.dcache_inv_post != Some(b.clean_source)
            || self.services.registry_lookup.is_none()
        {
            report.add(
                "services.paint.clean_source",
                IssueKind::Conflict,
                "paint sources require the audited native clean and task registry interfaces",
            );
        }
        let t = &b.surface_case_table;
        if t.name != "surface_cases"
            || t.element_bytes != 8
            || t.address % 8 != 0
            || t.values != [0x80, 0x9c, 0xac, 0xc8, 0xdc].map(|offset| b.current_surface + offset)
        {
            report.add("services.paint.surface_case_table",IssueKind::Conflict,"all five original surface-selector cases must bind the getter's complete dispatcher");
        }
        crate::paint_native_validation::validate_declaration(self, b, report);
        let expected_bodies = expected_bodies(b.family);
        let mut seen = BTreeSet::new();
        for e in &b.bodies {
            let expected = expected_bodies.iter().find(|(name, _)| *name == e.name);
            if !seen.insert(e.name.as_str())
                || expected.is_none_or(|(_, n)| *n != e.length)
                || !valid_hash(&e.sha256)
                || e.address % 4 != 0
                || !self.memory.is_xip_range(e.address, u64::from(e.length))
                || b.entry(&e.name) != Some(e.address)
            {
                report.add(
                    format!("services.paint.bodies.{}", e.name),
                    IssueKind::Invalid,
                    "unknown, duplicate, incomplete or conflicting original paint body",
                );
            }
            if self.memory.slack.as_ref().is_some_and(|s| {
                s.range().overlaps(&AddressRange {
                    start: e.address,
                    end: e.address.saturating_add(u64::from(e.length)),
                })
            }) {
                report.add(
                    format!("services.paint.bodies.{}", e.name),
                    IssueKind::Conflict,
                    "original drawing evidence overlaps loader reservation",
                );
            }
        }
        for (name, _) in &expected_bodies {
            if *name == "surface_record_consumer" && b.surface_mapping.is_none() {
                continue;
            }
            if !seen.contains(name)
                || !self
                    .service_fingerprints
                    .contains_key(&format!("paint.{name}"))
            {
                report.add(format!("services.paint.bodies.{name}"),IssueKind::Missing,"paint diagnostics require the complete original body and its entry fingerprint");
            }
        }
        if !self.memory.is_xip_range(b.call_site, 4) || b.call_site % 4 != 0 {
            report.add(
                "services.paint.call_site",
                IssueKind::OutOfBounds,
                "paint observation requires an aligned original GUI call site",
            );
        }
    }
    pub(crate) fn validate_paint_bytes(&self, module: &[u8], report: &mut ValidationReport) {
        let Some(b) = &self.services.paint else {
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
                    format!("services.paint.bodies.{}", e.name),
                    IssueKind::FingerprintMismatch,
                    "complete original paint body differs from the official image",
                );
            }
        }
        let mut check = |ok: bool, name: &str| {
            if !ok {
                report.add(
                    format!("services.paint.{name}"),
                    IssueKind::Conflict,
                    "original paint instructions do not establish the declared contract",
                )
            }
        };
        check(
            slice(b.call_site, 4)
                .and_then(|v| word(v, 0))
                .and_then(|w| target(b.call_site, w))
                == Some(b.original_callee)
                && b.entry("caller").is_some_and(|a| b.call_site == a + 0x4c4),
            "call_site",
        );
        check(
            body("text_draw").is_some_and(|v| {
                word(v, 0x20) == Some(0x2a0303f3)
                    && word(v, 0x24) == Some(0x2a0203f4)
                    && word(v, 0x28) == Some(0xaa0103f5)
                    && word(v, 0x2c) == Some(0xaa0003f8)
                    && word(v, 0xa2c) == Some(0x2a1603e0)
                    && word(v, 0xa50) == Some(0xd65f03c0)
            }) && slice(b.call_site.saturating_sub(4), 4).and_then(|v| word(v, 0))
                == Some(0x790033e9),
            "text_draw",
        );
        check(
            body("widget_root").is_some_and(|v| {
                word(v, 8) == Some(0xf9402100)
                    && word(v, 0x18) == Some(0xaa0803e0)
                    && word(v, 0x1c) == Some(0xd65f03c0)
            }) && body("surface_record").is_some_and(|v| {
                word(v, 0) == Some(0x7100105f)
                    && word(v, 0x10) == Some(0x7100111f)
                    && word(v, 0x18) == Some(0x34000a01)
                    && word(v, 0x158) == Some(0xd65f03c0)
            }),
            "root_surface",
        );
        if let Some(m) = &b.surface_mapping {
            check(
                slice(m.group_map.address, 2) == Some(&[0, 0])
                    && slice(m.type_cases.address, 40).is_some_and(|v| {
                        v.chunks_exact(8)
                            .zip(&m.type_cases.values)
                            .all(|(v, expected)| {
                                u64::from_le_bytes(v.try_into().unwrap()) == *expected
                            })
                    })
                    && body("surface_record").is_some_and(|v| {
                        materializes(v, [0x24, 0x28, 0x2c, 0x34], 10, m.type_cases.address)
                            && materializes(v, [0x78, 0x7c, 0x80, 0x84], 8, m.group_map.address)
                            && materializes(v, [0x88, 0x8c, 0x98, 0x9c], 11, m.record_base)
                            && word(v, 0x90) == Some(0x38614908)
                            && word(v, 0x94) == Some(0x5280000a | (m.group_stride << 5))
                            && word(v, 0xa4) == Some(0x5280000a | (m.index_stride << 5))
                            && word(v, 0xa8) == Some(0x9baa2128)
                            && word(v, 0xac) == Some(0x91000100 | (m.index_offset << 10))
                    })
                    && body("surface_record_consumer").is_some_and(|v| {
                        word(v, 0x34).and_then(|w| {
                            target(b.entry("surface_record_consumer").unwrap_or(0) + 0x34, w)
                        }) == Some(b.surface_record)
                            && word(v, 0x40) == Some(0xf9401417)
                            && word(v, 0x74) == Some(0xaa1703e1)
                    }),
                "surface_mapping",
            );
        }
        if b.family == crate::PaintFamily::Z8TextPaintProbeV1 {
            check(
                body("blit").is_some_and(|v| {
                    word(v, 0x1e0) == Some(0x2a1f03e0) && word(v, 0x1e8) == Some(0xd65f03c0)
                }),
                "blit",
            );
        }
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
        if b.family == crate::PaintFamily::Z8TextNativeBitmapProbeV1 {
            crate::paint_native_validation::validate_bytes(self, b, module, report);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BitmapMode, ExecutionBody, ExecutionTable, Memory, MemorySegment, MemorySegmentKind,
        MenuOwnPage, PaintFamily, PaintServices, ServiceFingerprint,
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
        let b = PaintServices {
            family: PaintFamily::Z8TextPaintProbeV1,
            text_draw: entry("text_draw"),
            widget_root: entry("widget_root"),
            surface_record: entry("surface_record"),
            surface_group: 0,
            surface_mapping: None,
            native_bitmap: None,
            mode: BitmapMode::Trace,
            full_screen: false,
            blit: entry("blit"),
            current_index: entry("current_index"),
            current_surface: entry("current_surface"),
            current_window: entry("current_window"),
            current_task: entry("current_task"),
            clean_source: entry("clean_source"),
            call_site: entry("caller") + 0x4c4,
            original_callee: entry("text_draw"),
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
                format!("paint.{}", e.name),
                ServiceFingerprint {
                    eg_off: e.address - 0x1000,
                    stock: vec![0; 16],
                },
            );
        }
        p.services.paint = Some(b);
        p
    }
    fn report(p: &Profile) -> ValidationReport {
        let mut r = ValidationReport::default();
        p.validate_paint(BuildMode::Exec, &mut r);
        r
    }
    #[test]
    fn trace_is_explicit_optional_and_complete() {
        let mut p = fixture();
        assert!(report(&p).is_valid());
        p.services.paint = None;
        assert!(report(&p).is_valid());
        assert_eq!(BitmapMode::Trace.pattern(), 0);
        assert_eq!(BitmapMode::Checker.pattern(), 1);
        assert_eq!(BitmapMode::Rgb.pattern(), 2);
        let text = toml::to_string(fixture().services.paint.as_ref().unwrap()).unwrap();
        let parsed: PaintServices =
            toml::from_str(&text.replace("full_screen = false\n", "")).unwrap();
        assert!(!parsed.full_screen);
        let mut original = fixture();
        original.services.paint.as_mut().unwrap().full_screen = true;
        assert!(!report(&original).is_valid());
    }
    #[test]
    fn incomplete_or_wrong_owner_cannot_enable_drawing() {
        let changes: [fn(&mut PaintServices); 6] = [
            |b| b.gui_task_name = "GuiMe".into(),
            |b| b.original_callee += 4,
            |b| b.bodies[0].length = 16,
            |b| b.surface_case_table.values[0] += 4,
            |b| b.mode = BitmapMode::Checker,
            |b| b.surface_group = 2,
        ];
        for change in changes {
            let mut p = fixture();
            change(p.services.paint.as_mut().unwrap());
            assert!(!report(&p).is_valid());
        }
        let mut p = fixture();
        p.service_fingerprints.remove("paint.current_task");
        assert!(!report(&p).is_valid());
        let mut r = ValidationReport::default();
        fixture().validate_paint(BuildMode::LoadOnly, &mut r);
        assert!(!r.is_valid());
    }
    #[test]
    fn checked_group_one_enables_patterns_and_refuses_mapping_drift() {
        let mut p = fixture();
        let b = p.services.paint.as_mut().unwrap();
        b.surface_group = 1;
        b.surface_mapping = Some(crate::PaintSurfaceMapping {
            group_map: ExecutionTable {
                name: "surface_groups".into(),
                address: 0x18000,
                element_bytes: 1,
                values: vec![0, 0],
            },
            type_cases: ExecutionTable {
                name: "record_types".into(),
                address: 0x18100,
                element_bytes: 8,
                values: [0x40, 0x78, 0xb4, 0xf0, 0x124]
                    .map(|n| b.surface_record + n)
                    .to_vec(),
            },
            record_base: 0xb00000400,
            group_stride: 0x1938,
            index_stride: 0x208,
            index_offset: 0xb0,
        });
        for mode in [BitmapMode::Trace, BitmapMode::Checker, BitmapMode::Rgb] {
            p.services.paint.as_mut().unwrap().mode = mode;
            assert!(report(&p).is_valid());
        }
        p.services
            .paint
            .as_mut()
            .unwrap()
            .surface_mapping
            .as_mut()
            .unwrap()
            .index_stride += 8;
        assert!(!report(&p).is_valid());
    }
    #[test]
    fn synthetic_zeroes_cannot_attest_gui_or_cleaning() {
        let mut r = ValidationReport::default();
        fixture().validate_paint_bytes(&vec![0; 0x21000], &mut r);
        for name in ["call_site", "gui_task_name", "clean_source"] {
            assert!(r
                .issues
                .iter()
                .any(|i| i.field == format!("services.paint.{name}")));
        }
    }
    #[test]
    fn alternate_family_requires_its_own_chain_and_exact_request_tables() {
        let mut p = fixture();
        let b = p.services.paint.as_mut().unwrap();
        b.family = PaintFamily::Z8TextNativeBitmapProbeV1;
        assert!(!report(&p).is_valid());
        let b = p.services.paint.as_mut().unwrap();
        b.bodies[0].length = 296;
        let table = |name: &str, address, values: Vec<u64>| ExecutionTable {
            name: name.into(),
            address,
            element_bytes: 4,
            values,
        };
        b.native_bitmap = Some(crate::NativeBitmapMapping {
            translate: 0x15000,
            draw: 0x16000,
            target_setup: 0x17000,
            target_restore: 0x18000,
            source_translate: table("bitmap_source_translate", 0x1a000, vec![0, 6, 5]),
            source_formats: table(
                "bitmap_source_formats",
                0x1b000,
                vec![1, 11, 12, 1, 1, 7, 5, 13],
            ),
            target_formats: table("bitmap_target_formats", 0x1c000, vec![0, 3, 2, 5, 4, 0, 1]),
            blend_modes: table("bitmap_blend_modes", 0x1d000, vec![0, 1, 2, 3, 4]),
        });
        for (name, size) in [
            ("bitmap_translate", 200),
            ("bitmap_draw", 620),
            ("bitmap_target_setup", 116),
            ("bitmap_target_restore", 28),
        ] {
            let address = b.entry(name).unwrap();
            b.bodies.push(ExecutionBody {
                name: name.into(),
                address,
                length: size,
                sha256: "00".repeat(32),
            });
            p.service_fingerprints.insert(
                format!("paint.{name}"),
                ServiceFingerprint {
                    eg_off: address - 0x1000,
                    stock: vec![0; 16],
                },
            );
        }
        assert!(report(&p).is_valid());
        p.services.paint.as_mut().unwrap().full_screen = true;
        assert!(report(&p).is_valid());
        let mut wrong = p.clone();
        wrong.services.paint.as_mut().unwrap().family = PaintFamily::Z8TextPaintProbeV1;
        assert!(!report(&wrong).is_valid());
        let mut wrong = p.clone();
        wrong
            .services
            .paint
            .as_mut()
            .unwrap()
            .native_bitmap
            .as_mut()
            .unwrap()
            .target_formats
            .values[0] = 1;
        assert!(!report(&wrong).is_valid());
        let mut wrong = p.clone();
        wrong.services.paint.as_mut().unwrap().bodies[0].length = 492;
        assert!(!report(&wrong).is_valid());
        let mut bytes_report = ValidationReport::default();
        p.validate_paint_bytes(&vec![0; 0x21000], &mut bytes_report);
        for name in [
            "entry_return",
            "source_translation_and_zero_target",
            "request_tables_setup_and_restore",
        ] {
            assert!(bytes_report
                .issues
                .iter()
                .any(|i| i.field == format!("services.paint.native_bitmap.{name}")));
        }
    }
}
