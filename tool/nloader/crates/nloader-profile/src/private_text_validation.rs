use crate::paint_validation::{materializes, target, word};
use crate::validation::{hash_matches, valid_hash};
use crate::{sha256, BuildMode, IssueKind, Profile, UiFamily, ValidationReport};
use std::collections::BTreeSet;

pub(crate) const BODIES: &[(&str, u64)] = &[
    ("ascii_writer", 212),
    ("runtime_getter", 88),
    ("low_level_set", 176),
    ("low_level_get", 20),
    ("high_level_bind", 72),
    ("high_level_type_slot_set", 20),
    ("item_builder", 520),
    ("utf16_writer", 244),
    ("conversion_writer", 208),
    ("font_getter", 36),
    ("font_adjustment", 100),
    ("utf_conversion_helper", 600),
    ("wrapper_ascii", 88),
    ("wrapper_conversion", 84),
    ("wrapper_utf16", 84),
    ("current_task", 144),
    ("menu_constructor", 88),
    ("worker_constructor", 64),
    ("task_constructor", 276),
    ("app_config_getter", 36),
    ("app_config_setter", 24),
    ("app_config_base", 20),
    ("config_install", 568),
    ("registry_lookup", 296),
    ("worker_starter", 60),
];
/// Original words from 0x40 before the value clamp to 0x20 after it
/// (Z8 C3.11 row value builder, the window the profile's value_clamp names).
pub(crate) const VALUE_CLAMP_WINDOW: [u32; 24] = [
    0xb94012a8, 0x528974e9, 0x321e03ea, 0x320003eb, 0xb9000289, 0x79000a8a, 0xb9000e8b, 0x371800c8,
    0x36f80188, 0xb94002a9, 0x320007ea, 0x321e03eb, 0x14000004, 0xb94002a9, 0x321f03ea, 0x320007eb,
    0x7104ad3f, 0x79000a8a, 0xb9000e8b, 0x54000068, 0xb94016a9, 0x14000002, 0x2a1f03e9, 0xb9000a89,
];
impl Profile {
    pub(crate) fn validate_private_text(&self, mode: BuildMode, r: &mut ValidationReport) {
        let Some(p) = &self.menu.private_text else {
            return;
        };
        let issue =
            |r: &mut ValidationReport, msg| r.add("menu.private_text", IssueKind::Conflict, msg);
        if self.identity.model != "Z8"
            || self.identity.firmware != "3.11"
            || self.abi.ui != Some(UiFamily::Z8MenuV1)
        {
            r.add(
                "menu.private_text",
                IssueKind::Unsupported,
                "private text routing is audited only for Z8 C3.11",
            );
        }
        if p.token_base != u32::from_be_bytes(*b"NL\0\0")
            // 68 tokens: rows 0..63, title 64, status 65, entry 66, Apps 67.
            // One geometry for every private profile (decided 2026-10-17),
            // with or without a Setup Apps row.
            || p.token_count != 68
            || (p.title_index, p.status_index, p.entry_index, p.apps_index) != (64, 65, 66, 67)
            || p.row_first_item != 0x7f80
            || p.entry_item_id != 0x7ffe
            || p.apps_item_id != 0x7ffd
            || p.ascii_flags != 0x200
            || p.styles != [3, 4]
        {
            issue(r,"namespace, exact item mapping, ASCII selector and font styles differ from the audited family");
        }
        if p.fallback_text.is_empty()
            || p.fallback_text.len() > 50
            || !p.fallback_text.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            issue(
                r,
                "ROM failure text must be printable ASCII fitting the native 50-byte limit",
            );
        }
        if p.gui_task_name != "APPMENU"
            || self
                .memory
                .address_to_offset(p.gui_task_config, 28)
                .is_err()
        {
            issue(
                r,
                "private writes require the audited native APPMENU task configuration",
            );
        }
        r.require("abi.task", self.abi.task);
        r.require("services.registry_lookup", self.services.registry_lookup);
        if self.services.registry_lookup != p.body("registry_lookup").map(|b| b.address) {
            issue(r,"private GUI lookup must bind the same original registry service used by the runtime");
        }
        let table = &p.registry_cases;
        if table.name != "registry_cases"
            || table.element_bytes != 8
            || table.values.len() != 8
            || !self.memory.is_xip_range(table.address, 64)
            || table.address % 8 != 0
            || p.body("registry_lookup").is_none_or(|body| {
                table.values.first() != Some(&(body.address + 0x40))
                    || table
                        .values
                        .iter()
                        .any(|v| *v < body.address || *v >= body.address + u64::from(body.length))
            })
        {
            issue(r,"registry dispatch requires the complete original eight-case table and exact type-zero case");
        }
        let names: BTreeSet<_> = p.bodies.iter().map(|b| b.name.as_str()).collect();
        if p.bodies.len() != BODIES.len() || names != BODIES.iter().map(|(n, _)| *n).collect() {
            issue(r,"all text primitives, truncating wrappers and GUI identity functions require unique complete bodies");
        }
        for &(name, length) in BODIES {
            if p.body(name).is_none_or(|b| {
                u64::from(b.length) != length
                    || b.address % 4 != 0
                    || !self.memory.is_xip_range(b.address, length)
                    || !valid_hash(&b.sha256)
            }) {
                r.add(
                    format!("menu.private_text.bodies.{name}"),
                    IssueKind::Invalid,
                    "complete aligned original body and SHA-256 are required",
                );
            }
            if !self
                .service_fingerprints
                .contains_key(&format!("private_text.{name}"))
            {
                r.add(format!("service_fingerprints.private_text.{name}"),IssueKind::Missing,"private text primitive and GUI identity require an explicit original entry fingerprint");
            }
        }
        if self
            .menu
            .page
            .as_ref()
            .is_some_and(|page| page.rows.is_some())
            != p.value_clamp.is_some()
        {
            issue(
                r,
                "the value clamp route is declared exactly when the page has row kinds",
            );
        }
        for address in [p.strlen, p.memcpy, p.item_clamp]
            .into_iter()
            .chain(p.value_clamp)
            .chain(p.getter_call_sites.iter().copied())
        {
            if address % 4 != 0 || !self.memory.is_xip_range(address, 4) {
                issue(
                    r,
                    "all native call and patch sites must lie in mapped original XIP",
                );
            }
        }
        if p.getter_call_sites.len() != 3
            || p.getter_call_sites
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != 3
        {
            issue(
                r,
                "exactly three distinct original getter BL sites are required",
            );
        }
        if let Some(platform) = &self.menu.text_platform {
            if !platform
                .entry_text
                .bytes()
                .all(|b| (0x20..=0x7e).contains(&b))
            {
                issue(
                    r,
                    "private ROM entry labels must use printable native ASCII",
                );
            }
            if platform.entry_slot != p.token_base.saturating_add(p.entry_index)
                || !p.styles.contains(&platform.entry_style)
                || self.ui.text_store != p.body("ascii_writer").map(|b| b.address)
            {
                issue(r,"entry token/style/native writer must agree with the explicit private namespace");
            }
        } else {
            issue(r,"private routing requires the existing audited text platform and its initialization hook");
        }
        if self
            .menu
            .setup
            .as_ref()
            .and_then(|s| s.entry.as_ref())
            .is_none_or(|e| e.item_id != p.entry_item_id || e.flags & 0x2210 != p.ascii_flags)
        {
            issue(
                r,
                "Setup item must use its exact private-token item ID and ASCII path",
            );
        }
        // The Apps row, when declared, takes exactly the family's Apps token
        // and item ID on the same ASCII path; the clamp keeps nothing else.
        if let Some(apps) = self.menu.setup.as_ref().and_then(|s| s.apps.as_ref()) {
            if apps.slot != p.token_base.saturating_add(p.apps_index)
                || apps.item_id != p.apps_item_id
                || apps.flags & 0x2210 != p.ascii_flags
                || !apps.text.bytes().all(|b| (0x20..=0x7e).contains(&b))
            {
                issue(
                    r,
                    "Setup Apps row must use the exact private Apps token, item ID and ASCII path",
                );
            }
        }
        if let Some(page) = &self.menu.page {
            if !page.item_text.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                issue(r, "private ROM page labels must use printable native ASCII");
            }
            if page.item_id != p.row_first_item
                || page.item_slot != p.token_base
                || page.title_slot != p.token_base.saturating_add(p.title_index)
                || page.item_flags & 0x2210 != p.ascii_flags
                || !p.styles.contains(&page.item_style)
                || !p.styles.contains(&page.title_format)
                || (!page.row_slots.is_empty()
                    && page.row_slots != (0..64).map(|i| p.token_base + i).collect::<Vec<_>>())
            {
                issue(r,"private row/title tokens must use the exact generated item-to-local-index mapping");
            }
            // The caution box owns the status token (nothing else binds it)
            // and draws in one of the family's styles.
            if let Some(caution) = &page.caution {
                if caution.text_slot != p.token_base.saturating_add(p.status_index)
                    || !p.styles.contains(&caution.text_format)
                {
                    issue(
                        r,
                        "private caution text must use the exact status token and a family style",
                    );
                }
            }
        }
        // Page allocates the same registered runtime but never invokes file services.
        if mode == BuildMode::Page {
            r.require("abi.task", self.abi.task);
            for (name, value) in [
                ("mem_alloc", self.services.mem_alloc),
                ("mem_free", self.services.mem_free),
                ("worker_init", self.services.worker_init),
                ("worker_start", self.services.worker_start),
                ("flag_set", self.services.flag_set),
                ("registry_lookup", self.services.registry_lookup),
            ] {
                r.require(&format!("services.{name}"), value);
                if !self.service_fingerprints.contains_key(name) {
                    r.add(format!("service_fingerprints.{name}"),IssueKind::Missing,"private Page owns a full registered runtime; its native services require fingerprints");
                }
            }
        }
    }
    pub(crate) fn validate_private_text_bytes(&self, module: &[u8], r: &mut ValidationReport) {
        let Some(p) = &self.menu.private_text else {
            return;
        };
        let bytes = |name: &str| {
            let b = p.body(name)?;
            let o = usize::try_from(
                self.memory
                    .address_to_offset(b.address, u64::from(b.length))
                    .ok()?,
            )
            .ok()?;
            module.get(o..o.checked_add(b.length as usize)?)
        };
        for b in &p.bodies {
            let actual = self
                .memory
                .address_to_offset(b.address, u64::from(b.length))
                .ok()
                .and_then(|o| usize::try_from(o).ok())
                .and_then(|o| module.get(o..o.checked_add(b.length as usize)?));
            if actual.is_none_or(|x| !hash_matches(&sha256(x), &b.sha256)) {
                r.add(
                    format!("menu.private_text.bodies.{}", b.name),
                    IssueKind::FingerprintMismatch,
                    "complete original text primitive differs from firmware",
                );
            }
        }
        let eq = |name: &str, off: usize, w: u32| bytes(name).and_then(|b| word(b, off)) == Some(w);
        let call = |name: &str, off: usize, to: u64| {
            p.body(name)
                .zip(bytes(name))
                .and_then(|(b, x)| word(x, off).and_then(|w| target(b.address + off as u64, w)))
                == Some(to)
        };
        let address = |name: &str| p.body(name).map(|b| b.address).unwrap_or(0);
        let mapped = |address: u64, length: u64| {
            self.memory
                .address_to_offset(address, length)
                .ok()
                .and_then(|o| usize::try_from(o).ok())
                .and_then(|o| module.get(o..o.checked_add(length as usize)?))
        };
        let tail = |name: &str, offset: usize, to: u64| {
            bytes(name).and_then(|b| word(b, offset)).is_some_and(|w| {
                w & 0xfc000000 == 0x14000000
                    && (address(name) as i64
                        + offset as i64
                        + i64::from(((w & 0x03ffffff) as i32) << 6 >> 6) * 4)
                        as u64
                        == to
            })
        };
        let gui_ok = bytes("current_task").is_some_and(|v| {
            word(v, 0x10) == Some(0xd538d089)
                && word(v, 0x14) == Some(0xb9405129)
                && word(v, 0x70) == Some(0xb9000009)
                && word(v, 0x74) == Some(0x2a1f03e0)
                && word(v, 0x88) == Some(0x321b77e0)
        }) && mapped(p.gui_task_config, 28)
            .is_some_and(|v| &v[13..21] == b"APPMENU\0")
            && bytes("app_config_base").is_some_and(|v| {
                p.gui_task_config
                    .checked_sub(7 * 28)
                    .is_some_and(|base| materializes(v, [0, 4, 8, 12], 0, base))
            })
            && call("config_install", 0x70, address("app_config_base"))
            && call("config_install", 0x74, address("app_config_setter"))
            && eq("menu_constructor", 8, 0x528000f3)
            && eq("menu_constructor", 12, 0x72a00033)
            && call("menu_constructor", 0x14, address("app_config_getter"))
            && call("menu_constructor", 0x40, address("worker_constructor"))
            && tail("worker_constructor", 0x3c, address("task_constructor"))
            && eq("task_constructor", 0x98, 0xb9000276)
            && eq("task_constructor", 0x9c, 0x91007660)
            && eq("task_constructor", 0xa4, 0x91003681)
            && eq("worker_starter", 0x14, 0xf9001661)
            && eq("registry_lookup", 0x14, 0x710bfd1f)
            && eq("registry_lookup", 0x50, 0x8b21d108)
            && eq("registry_lookup", 0x54, 0xf9400508)
            && eq("registry_lookup", 0x120, 0xf9000048)
            && bytes("registry_lookup").is_some_and(|v| {
                materializes(v, [0x24, 0x28, 0x2c, 0x34], 9, p.registry_cases.address)
            })
            && mapped(p.registry_cases.address, 64).is_some_and(|v| {
                v.chunks_exact(8)
                    .zip(&p.registry_cases.values)
                    .all(|(x, value)| u64::from_le_bytes(x.try_into().unwrap()) == *value)
            });
        if !gui_ok {
            r.add("menu.private_text.gui_identity",IssueKind::Conflict,"GetTid success/error, native task ID/name/self registration and APPMENU configuration source differ from the audited family");
        }
        let writer_ok = eq("ascii_writer", 0, 0xf81d0ff6)
            && eq("ascii_writer", 0x14, 0xaa0003f5)
            && call("ascii_writer", 0x18, p.strlen)
            && call("ascii_writer", 0x54, p.memcpy)
            && call("ascii_writer", 0x64, address("font_getter"))
            && call("ascii_writer", 0x78, address("font_adjustment"))
            && eq("ascii_writer", 0x24, 0x12003e88)
            && eq("ascii_writer", 0x2c, 0x321d07ea)
            && eq("ascii_writer", 0x34, 0x9baa2516)
            && eq("ascii_writer", 0x60, 0x3834691f)
            && eq("ascii_writer", 0x6c, 0xb90002d4)
            && eq("ascii_writer", 0x74, 0xb90012d3)
            && eq("ascii_writer", 208, 0xd65f03c0);
        let getter_ok = eq("runtime_getter",0x14,0x32003fea) && eq("runtime_getter",0x18,0x6b0a013f)
            && eq("runtime_getter",0x20,0x5400006b) // signed B.LT, never an unsigned stock rewrite
            && eq("runtime_getter",0x28,0xb900001f) && eq("runtime_getter",0x34,0xb940012b)
            && eq("runtime_getter",0x4c,0xf9000029) && eq("runtime_getter",0x50,0xb9000068);
        let clamp_ok = p
            .body("item_builder")
            .is_some_and(|b| p.item_clamp == b.address + 0xbc)
            && eq("item_builder", 0x60, 0xb9400288)
            && eq("item_builder", 0x6c, 0xb900026a)
            && eq("item_builder", 0x70, 0xb9000a68)
            && eq("item_builder", 0xbc, 0x7104b11f)
            && eq("item_builder", 0xc0, 0x54000043)
            && eq("item_builder", 0xc4, 0xb9000a7f);
        // The value builder around the value clamp, word for word: the label
        // id in w9, the item in x21, the value widget in x20, the text-slot
        // mode in w11 (3 on the item-flag bit 3 path), keep at +0x10, clear
        // at +0x18, store at +0x1c.
        let value_ok = p.value_clamp.is_none_or(|site| {
            site.checked_sub(0x40)
                .and_then(|at| mapped(at, 0x60))
                .is_some_and(|v| {
                    VALUE_CLAMP_WINDOW
                        .iter()
                        .enumerate()
                        .all(|(n, w)| word(v, n * 4) == Some(*w))
                })
        });
        if !value_ok {
            r.add(
                "menu.private_text.value_clamp",
                IssueKind::FingerprintMismatch,
                "value builder clamp differs from the audited family",
            );
        }
        let low_ok = eq("low_level_set", 0x48, 0x97ffe082)
            && eq("low_level_set", 0x7c, 0x6b15011f)
            && eq("low_level_set", 0x8c, 0xb9000a75)
            && eq("low_level_set", 0xa0, 0xb9000e74)
            && eq("low_level_get", 4, 0xb9000028)
            && eq("low_level_get", 12, 0xb9000048);
        let wrappers_ok = [
            ("wrapper_ascii", 0x20, "utf16_writer", 0x38, 0x12003e81),
            (
                "wrapper_conversion",
                0x20,
                "conversion_writer",
                0x38,
                0x12003e82,
            ),
            ("wrapper_utf16", 0x20, "utf16_writer", 0x38, 0x12003e82),
        ]
        .into_iter()
        .all(|(n, utf_off, utf, ascii_off, andword)| {
            eq(n, 0, 0xf81e0ff4)
                && eq(n, 12, 0x2a0203f4)
                && call(n, utf_off, address(utf))
                && call(n, ascii_off, address("ascii_writer"))
                && eq(n, if n == "wrapper_ascii" { 0x4c } else { 0x48 }, andword)
        });
        let sites_ok = p.getter_call_sites.iter().all(|site| {
            self.memory
                .address_to_offset(*site, 4)
                .ok()
                .and_then(|o| module.get(o as usize..o as usize + 4))
                .and_then(|x| word(x, 0))
                .and_then(|w| target(*site, w))
                == Some(address("runtime_getter"))
        });
        let mut actual_getter_calls = BTreeSet::new();
        for segment in self
            .memory
            .segments
            .iter()
            .filter(|s| s.kind == crate::MemorySegmentKind::Xip)
        {
            let Some(data) = usize::try_from(segment.file_offset)
                .ok()
                .and_then(|o| module.get(o..o.checked_add(segment.size as usize)?))
            else {
                continue;
            };
            for (index, bytes) in data.chunks_exact(4).enumerate() {
                let site = segment.runtime_start + index as u64 * 4;
                if word(bytes, 0).and_then(|w| target(site, w)) == Some(address("runtime_getter")) {
                    actual_getter_calls.insert(site);
                }
            }
        }
        if actual_getter_calls != p.getter_call_sites.iter().copied().collect() {
            r.add("menu.private_text.getter_call_sites", IssueKind::Conflict,
                  "declared getter BL sites do not cover the full mapped original XIP scan; indirect calls remain outside this direct-call evidence");
        }
        if !(writer_ok && getter_ok && clamp_ok && low_ok && wrappers_ok && sites_ok) {
            r.add("menu.private_text.semantics",IssueKind::Conflict,"native writer/getter/clamp/full-token binding and wrapper UTF/low16 boundaries do not match the audited family");
        }
        // Resolve both writable stock bases from the real writer, never reinterpret ROM as writable.
        if let (Some(b), Some(t)) = (bytes("ascii_writer"), &self.menu.text_platform) {
            for (offsets, reg, expected) in [
                ([0x1c, 0x20, 0x28, 0x30], 9, t.descriptor_base),
                ([0x7c, 0x84, 0x8c, 0x90], 8, t.font_cache_base),
            ] {
                let matched = offsets.into_iter().enumerate().all(|(i, o)| {
                    let half = ((expected >> (i * 16)) & 0xffff) as u32;
                    eq(
                        "ascii_writer",
                        o,
                        (if i == 0 { 0xd2800000 } else { 0xf2800000 })
                            | ((i as u32) << 21)
                            | (half << 5)
                            | reg,
                    )
                });
                if !matched || b.len() != 212 {
                    r.add("menu.private_text.stock_bases",IssueKind::Conflict,"original writer descriptor and style-cache bases differ from the audited text platform");
                }
            }
        }
    }
}
