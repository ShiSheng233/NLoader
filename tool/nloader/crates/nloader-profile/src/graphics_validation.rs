//! Original-byte and semantic qualification of the synchronous canvas path.
use crate::paint_validation::{materializes, target, word};
use crate::validation::{hash_matches, valid_hash};
use crate::{
    sha256, BitmapMode, BuildMode, GraphicsServices, IssueKind, PaintFamily, Profile,
    ValidationReport,
};
use std::collections::BTreeSet;

pub const GRAPHICS_BODIES: &[(&str, u32)] = &[
    ("widget_find", 56),
    ("get_draw", 4),
    ("get_draw_body", 8),
    ("set_draw", 4),
    ("set_draw_body", 8),
    ("set_dirty", 8),
    ("set_dirty_body", 20),
    ("get_visible", 4),
    ("get_visible_body", 8),
    ("set_visible", 8),
    ("set_visible_body", 44),
    ("row_hide", 468),
    ("row_dirty", 8),
    ("row_dirty_body", 128),
    ("window_render", 100),
    ("window_visit", 108),
    ("locked_render", 100),
    ("draw_dispatch", 120),
    ("context_dispatch", 24),
    ("context_setter", 24),
    ("context_installer", 108),
    ("context_from_root", 176),
    ("display_refresh", 1384),
    ("display_abort", 44),
    ("submit", 428),
    ("submit_body", 2860),
    ("queue_task", 24),
    ("fence", 136),
    ("fence_callback", 24),
    ("fence_wait", 48),
    ("slot4_caller", 488),
    ("slot4_thunk", 28),
    ("element_interpreter", 2276),
    ("element_generic", 212),
    ("widget_constructor", 4),
    ("widget_constructor_body", 172),
];

fn branch(site: u64, instruction: u32) -> Option<u64> {
    match instruction & 0xfc00_0000 {
        0x9400_0000 | 0x1400_0000 => {
            site.checked_add_signed(i64::from(((instruction & 0x03ff_ffff) as i32) << 6 >> 6) * 4)
        }
        _ => None,
    }
}

fn bitmap_evidence(p: &Profile, g: &GraphicsServices) -> Profile {
    let mut evidence = p.clone();
    evidence.services.paint = Some(g.bitmap.clone());
    for (name, fingerprint) in &p.service_fingerprints {
        if let Some(suffix) = name.strip_prefix("graphics.bitmap.") {
            evidence
                .service_fingerprints
                .insert(format!("paint.{suffix}"), fingerprint.clone());
        }
    }
    evidence
}

pub fn validate_graphics(
    p: &Profile,
    g: &GraphicsServices,
    mode: BuildMode,
    r: &mut ValidationReport,
) {
    if p.services.time.is_none() {
        r.add(
            "services.graphics.time",
            IssueKind::Missing,
            "synchronous frame handoff needs the qualified original clock and worker delay",
        );
    } else {
        p.validate_time(r);
    }
    if mode != BuildMode::Exec || p.identity.model != "Z8" || p.identity.firmware != "3.11" {
        r.add(
            "services.graphics",
            IssueKind::Unsupported,
            "self canvas requires the qualified Z8 C3.11 execution profile",
        );
    }
    if p.services.paint.is_some() || p.services.bitmap.is_some() {
        r.add(
            "services.graphics",
            IssueKind::Conflict,
            "the application canvas and immutable paint diagnostics are separate builds",
        );
    }
    if g.bitmap.family != PaintFamily::Z8TextNativeBitmapProbeV1
        || g.bitmap.mode != BitmapMode::Trace
        || g.bitmap.full_screen
        || g.bitmap.surface_group != 1
        || g.bitmap.surface_mapping.is_none()
    {
        r.add("services.graphics.bitmap", IssueKind::Conflict, "reuse native bitmap evidence without enabling a diagnostic pattern or full-screen claim");
    }
    let evidence = bitmap_evidence(p, g);
    evidence.validate_paint(mode, r);
    let Some(page) = &p.menu.page else {
        r.add(
            "services.graphics.canvas",
            IssueKind::Missing,
            "self canvas needs the declared own NLoader page",
        );
        return;
    };
    let count = page.row_slots.len().max(1) as u32;
    if page.row_hide.is_none() {
        r.add(
            "services.graphics.row_hide",
            IssueKind::Missing,
            "the canvas needs the original complete-row visibility operation",
        );
    }
    if g.entry("row_hide") != page.row_hide {
        r.add(
            "services.graphics.row_hide",
            IssueKind::Conflict,
            "complete-row evidence must refer to the existing original page operation",
        );
    }
    if count > 64
        || g.canvas_id == 0
        || g.canvas_id == 0x8e
        || g.canvas_id > u16::MAX as u32
        || (g.canvas_id >= page.item_id && g.canvas_id < page.item_id.saturating_add(count))
    {
        r.add(
            "services.graphics.canvas_id",
            IssueKind::Conflict,
            "canvas must have a distinct own ID outside its rows and the native special-help path",
        );
    }
    let [x, y, w, h] = g.destination;
    if g.surface_index != 2 || g.surface_size != [640, 422] {
        r.add(
            "services.graphics.surface",
            IssueKind::Unsupported,
            "the qualified content root selects surface 1/1/2 with a 640x422 backing",
        );
    }
    if x >= 632 || y >= 422 || w == 0 || h == 0 || w > 632 - x || h > 422 - y {
        r.add(
            "services.graphics.destination",
            IssueKind::OutOfBounds,
            "canvas stays inside the 632x422 content viewport in local coordinates",
        );
    }
    if p.ui.widget_find != Some(g.widget_find)
        || p.ui.widget_show != Some(g.set_visible)
        || p.services
            .native_card
            .as_ref()
            .and_then(|c| c.menu.exit_menu.as_ref())
            .is_none_or(|e| e.gui_state != g.gui_state)
    {
        r.add(
            "services.graphics.owner",
            IssueKind::Conflict,
            "canvas must use existing original menu lookup, visibility and native GUI state",
        );
    }
    // The canvas counts its frames through the platform's commit observer,
    // which owns the commit call sites: it must observe both original
    // display-composition calls of `submit` and no other site.
    let commit = p
        .services
        .platform
        .as_ref()
        .and_then(|pl| pl.commit.as_ref());
    match commit {
        None => r.add(
            "services.platform.commit",
            IssueKind::Missing,
            "the canvas counts its frames through the declared commit observer",
        ),
        Some(c)
            if c.callee != g.submit
                || c.sites
                    != [
                        g.display_refresh.saturating_add(0x344),
                        g.display_refresh.saturating_add(0x4b8),
                    ] =>
        {
            r.add(
                "services.platform.commit",
                IssueKind::Conflict,
                "observe both original display-composition calls of the graphics submit \
                 and no other sites",
            )
        }
        Some(_) => {}
    }
    let mut seen = BTreeSet::new();
    for body in &g.bodies {
        if !seen.insert(body.name.as_str())
            || GRAPHICS_BODIES
                .iter()
                .find(|(n, _)| *n == body.name)
                .is_none_or(|(_, size)| *size != body.length)
            || g.entry(&body.name) != Some(body.address)
            || !valid_hash(&body.sha256)
            || body.address % 4 != 0
            || !p.memory.is_xip_range(body.address, u64::from(body.length))
        {
            r.add(
                format!("services.graphics.bodies.{}", body.name),
                IssueKind::Invalid,
                "complete unique aligned original function evidence is required",
            );
        }
    }
    for (name, _) in GRAPHICS_BODIES {
        if !seen.contains(name) {
            r.add(
                format!("services.graphics.bodies.{name}"),
                IssueKind::Missing,
                "required canvas function is missing",
            );
        }
    }
    if g.canvas_element.name != "canvas_element"
        || g.canvas_element.length != 68
        || !valid_hash(&g.canvas_element.sha256)
        || !p.memory.is_xip_range(g.canvas_element.address, 68)
    {
        r.add(
            "services.graphics.canvas_element",
            IssueKind::Invalid,
            "complete original element template is required",
        );
    }
    if g.element_cases.name != "element_cases"
        || g.element_cases.element_bytes != 8
        || g.element_cases.values.len() != 29
        || !p.memory.is_xip_range(g.element_cases.address, 232)
    {
        r.add(
            "services.graphics.element_cases",
            IssueKind::Invalid,
            "complete original element type dispatch table is required",
        );
    }
}

pub fn validate_graphics_bytes(
    p: &Profile,
    g: &GraphicsServices,
    module: &[u8],
    r: &mut ValidationReport,
) {
    p.validate_time_bytes(module, r);
    let evidence = bitmap_evidence(p, g);
    evidence.validate_paint_bytes(module, r);
    let slice = |address, length| {
        p.memory
            .address_to_offset(address, length)
            .ok()
            .and_then(|o| usize::try_from(o).ok())
            .and_then(|o| module.get(o..o.checked_add(length as usize)?))
    };
    let body = |name: &str| {
        g.bodies
            .iter()
            .find(|b| b.name == name)
            .and_then(|b| slice(b.address, u64::from(b.length)))
    };
    for b in g.bodies.iter().chain([&g.canvas_element]) {
        if !slice(b.address, u64::from(b.length))
            .is_some_and(|v| hash_matches(&sha256(v), &b.sha256))
        {
            r.add(
                format!("services.graphics.bodies.{}", b.name),
                IssueKind::FingerprintMismatch,
                "complete original canvas bytes differ",
            );
        }
    }
    let mut check = |ok: bool, name: &str| {
        if !ok {
            r.add(
                format!("services.graphics.{name}"),
                IssueKind::Conflict,
                "original instructions do not establish the declared canvas contract",
            );
        }
    };
    let link = |name: &str, at, other: &str| {
        let Some(callee) = g.entry(other) else {
            return false;
        };
        body(name)
            .and_then(|v| word(v, at))
            .and_then(|w| branch(g.entry(name)?.checked_add(at as u64)?, w))
            == Some(callee)
    };
    for (name, at, other) in [
        ("get_draw", 0, "get_draw_body"),
        ("set_draw", 0, "set_draw_body"),
        ("set_dirty", 4, "set_dirty_body"),
        ("get_visible", 0, "get_visible_body"),
        ("set_visible", 4, "set_visible_body"),
        ("row_hide", 0x1c0, "row_dirty"),
        ("row_dirty", 4, "row_dirty_body"),
        ("window_render", 0x4c, "window_visit"),
        ("window_visit", 0x20, "locked_render"),
        ("window_visit", 0x5c, "locked_render"),
        ("locked_render", 0x40, "draw_dispatch"),
        ("draw_dispatch", 0x20, "context_dispatch"),
        ("context_installer", 0x28, "context_setter"),
        ("slot4_caller", 0xf0, "slot4_thunk"),
        ("element_generic", 0xa4, "widget_constructor"),
        ("widget_constructor", 0, "widget_constructor_body"),
        ("display_refresh", 0x344, "submit"),
        ("display_refresh", 0x4b8, "submit"),
        ("fence", 0x6c, "fence_wait"),
        ("fence", 0xc, "queue_task"),
        ("submit", 0xd4, "submit_body"),
        ("submit", 0x130, "submit_body"),
        ("submit", 0x194, "submit_body"),
        ("submit_body", 0xaf8, "fence_wait"),
    ] {
        check(link(name, at, other), name);
    }
    for (name, at, expected) in [
        ("get_draw_body", 0, 0xf9405800),
        ("set_draw_body", 0, 0xf9005801),
        ("set_dirty_body", 12, 0x3900f109),
        ("get_visible_body", 0, 0x3940a000),
        ("set_visible_body", 24, 0x3900a008),
        ("row_hide", 0x19c, 0x12000113),
        ("row_dirty", 0, 0x12000021),
        ("row_dirty_body", 0x14, 0x9104a013),
        ("row_dirty_body", 0x18, 0x3900f014),
        ("row_dirty_body", 0x58, 0x3900f014),
        ("row_dirty_body", 0x7c, 0xd65f03c0),
        ("element_interpreter", 0x68, 0x9100227c),
        ("element_interpreter", 0x1a0, 0x29402138),
        ("element_interpreter", 0x1ac, 0x720c011f),
        ("element_interpreter", 0x1b0, 0x9a9c0268),
        ("element_interpreter", 0x1b4, 0xf940011c),
        ("slot4_thunk", 12, 0xf9401101),
        ("display_refresh", 0x40, 0xd63f0000),
        ("display_refresh", 0x564, 0xd65f03c0),
        ("submit", 0x1a8, 0xd65f03c0),
        ("submit", 0x1a0, 0x12000000),
        ("submit", 0xd0, 0x2a1f03e4),
        ("submit", 0xc4, 0x320003e2),
        ("submit", 0xcc, 0xaa1f03e3),
        ("submit", 0x12c, 0x2a1f03e4),
        ("submit", 0x120, 0x320003e2),
        ("submit", 0x128, 0xaa1f03e3),
        ("submit", 0x18c, 0x2a1f03e4),
        ("submit", 0x184, 0x320003e2),
        ("submit", 0x188, 0xaa1f03e3),
        ("submit_body", 0x340, 0x2a1f03f8),
        ("submit_body", 0xb08, 0x12000300),
        ("submit_body", 0xb28, 0xd65f03c0),
        ("queue_task", 0x10, 0x79c00100),
        ("queue_task", 0x14, 0xd65f03c0),
        ("display_abort", 8, 0x52800233),
        ("display_abort", 12, 0x72a01013),
        ("display_abort", 28, 0x6a13001f),
        ("fence_wait", 0x18, 0x321f03e2),
    ] {
        check(body(name).and_then(|v| word(v, at)) == Some(expected), name);
    }
    check(
        body("context_installer").is_some_and(|v| {
            materializes(
                v,
                [0x18, 0x1c, 0x20, 0x24],
                0,
                g.entry("context_from_root").unwrap_or(0),
            )
        }),
        "context_installer",
    );
    check(
        body("context_from_root").is_some_and(|v| {
            word(v, 8).and_then(|w| target(g.entry("context_from_root").unwrap_or(0) + 8, w))
                == Some(g.bitmap.widget_root)
                && word(v, 0x78)
                    .and_then(|w| target(g.entry("context_from_root").unwrap_or(0) + 0x78, w))
                    == g.bitmap.entry("surface_record_consumer").map(|a| a + 12)
        }),
        "context_from_root",
    );
    check(
        body("widget_constructor_body").is_some_and(|v| {
            materializes(
                v,
                [0x14, 0x1c, 0x24, 0x34],
                8,
                g.bitmap.entry("caller").unwrap_or(0),
            )
        }),
        "original_canvas_callback",
    );
    check(
        body("fence").is_some_and(|v| {
            materializes(
                v,
                [0x14, 0x1c, 0x24, 0x2c],
                9,
                g.entry("fence_callback").unwrap_or(0),
            ) && word(v, 0x20) == Some(0x52800228)
                && word(v, 0x28) == Some(0x72a84028)
                && body("fence_callback").is_some_and(|callback| {
                    [0x3c, 0x40, 0x44, 0x48]
                        .into_iter()
                        .enumerate()
                        .all(|(n, at)| {
                            word(v, at)
                                .zip(word(callback, n * 4))
                                .is_some_and(|(a, b)| a & !31 == b & !31)
                        })
                })
        }),
        "fence_identity",
    );
    check(
        slice(g.element_cases.address, 232).is_some_and(|v| {
            v.chunks_exact(8)
                .zip(&g.element_cases.values)
                .all(|(b, w)| u64::from_le_bytes(b.try_into().unwrap()) == *w)
        }) && g.element_cases.values.get(3).copied()
            == g.entry("element_interpreter").map(|a| a + 0x190)
            && link("element_interpreter", 0x604, "element_generic"),
        "element_cases",
    );
    check(
        slice(g.canvas_element.address, 68).is_some_and(|v| word(v, 4) == Some(4)),
        "canvas_element",
    );
    if let Some(page) = &p.menu.page {
        let template = slice(page.template_page, 80);
        let elements = template
            .and_then(|v| v.get(8..16))
            .map(|v| u64::from_le_bytes(v.try_into().unwrap()));
        let mut found = false;
        if let Some(base) = elements {
            for n in 0..crate::MENU_ELEMENT_MAX {
                let Some(address) = base.checked_add(n * 68) else {
                    break;
                };
                let Some(v) = slice(address, 68) else { break };
                if word(v, 4) == Some(0) {
                    break;
                }
                if address == g.canvas_element.address {
                    found = true;
                }
                if word(v, 0x38) == Some(g.canvas_id) {
                    found = false;
                    break;
                }
            }
        }
        check(found, "canvas_template_membership");
    }
}
