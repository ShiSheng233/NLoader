//! The alternate bitmap chain has its own immutable enum tables and return path.
use crate::paint_validation::{materializes, target, word};
use crate::{IssueKind, PaintFamily, PaintServices, Profile, ValidationReport};

pub(super) fn validate_declaration(p: &Profile, b: &PaintServices, r: &mut ValidationReport) {
    if b.family == PaintFamily::Z8TextPaintProbeV1 {
        if b.native_bitmap.is_some() {
            r.add(
                "services.paint.native_bitmap",
                IssueKind::Conflict,
                "the original paint family cannot declare the alternate bitmap chain",
            );
        }
        return;
    }
    let Some(n) = &b.native_bitmap else {
        r.add(
            "services.paint.native_bitmap",
            IssueKind::Missing,
            "the alternate native bitmap family requires its complete translation chain",
        );
        return;
    };
    for (table, name, values) in [
        (
            &n.source_translate,
            "bitmap_source_translate",
            &[0, 6, 5][..],
        ),
        (
            &n.source_formats,
            "bitmap_source_formats",
            &[1, 11, 12, 1, 1, 7, 5, 13][..],
        ),
        (
            &n.target_formats,
            "bitmap_target_formats",
            &[0, 3, 2, 5, 4, 0, 1][..],
        ),
        (&n.blend_modes, "bitmap_blend_modes", &[0, 1, 2, 3, 4][..]),
    ] {
        if table.name != name
            || table.element_bytes != 4
            || table.address % 4 != 0
            || table.values != values
            || !p
                .memory
                .is_xip_range(table.address, values.len() as u64 * 4)
        {
            r.add(
                format!("services.paint.native_bitmap.{name}"),
                IssueKind::Conflict,
                "complete original u32 request-enum table is required",
            );
        }
    }
}

pub(super) fn validate_bytes(
    p: &Profile,
    b: &PaintServices,
    module: &[u8],
    r: &mut ValidationReport,
) {
    let Some(n) = &b.native_bitmap else {
        return;
    };
    let slice = |a, size| {
        p.memory
            .address_to_offset(a, size)
            .ok()
            .and_then(|o| usize::try_from(o).ok())
            .and_then(|o| module.get(o..o.checked_add(size as usize)?))
    };
    let body = |name: &str| {
        b.bodies
            .iter()
            .find(|e| e.name == name)
            .and_then(|e| slice(e.address, u64::from(e.length)))
    };
    let mut check = |ok: bool, name: &str| {
        if !ok {
            r.add(
                format!("services.paint.native_bitmap.{name}"),
                IssueKind::Conflict,
                "original native bitmap instructions do not establish the declared chain",
            );
        }
    };
    for table in [
        &n.source_translate,
        &n.source_formats,
        &n.target_formats,
        &n.blend_modes,
    ] {
        check(
            slice(table.address, table.values.len() as u64 * 4).is_some_and(|v| {
                v.chunks_exact(4)
                    .zip(&table.values)
                    .all(|(v, w)| u64::from(u32::from_le_bytes(v.try_into().unwrap())) == *w)
            }),
            &table.name,
        );
    }
    check(
        body("blit").is_some_and(|v| {
            word(v, 0x90) == Some(0xb900527f)
                && word(v, 0x94).and_then(|w| target(b.blit + 0x94, w)) == Some(n.translate)
                && word(v, 0xe4).and_then(|w| target(b.blit + 0xe4, w)) == Some(n.translate)
                && word(v, 0xa4) == Some(0x2a1f03e0)
                && word(v, 0xac) == Some(0xd65f03c0)
                && word(v, 0x124) == Some(0x17ffffdc)
        }),
        "entry_return",
    );
    check(
        body("bitmap_translate").is_some_and(|v| {
            word(v, 0xc) == Some(0x52800b02)
                && word(v, 0x18) == Some(0x943d77d7)
                && word(v, 0x20) == Some(0x51000508)
                && word(v, 0x24) == Some(0x7100091f)
                && materializes(v, [0x2c, 0x30, 0x34, 0x38], 9, n.source_translate.address)
                && word(v, 0x3c) == Some(0xb868d928)
                && word(v, 0x48) == Some(0x29057fe8)
                && word(v, 0xb8).and_then(|w| target(n.translate + 0xb8, w)) == Some(n.draw)
                && word(v, 0xc4) == Some(0xd65f03c0)
        }),
        "source_translation_and_zero_target",
    );
    check(
        body("bitmap_draw").is_some_and(|v| {
            materializes(v, [0x34, 0x38, 0x40, 0x48], 29, n.blend_modes.address)
                && word(v, 0x70) == Some(0xb8757bb4)
                && word(v, 0xf0) == Some(0xb8757bbd)
                && materializes(v, [0x134, 0x138, 0x13c, 0x140], 8, n.source_formats.address)
                && word(v, 0x148) == Some(0xb8777908)
                && word(v, 0x118) == Some(0x71001eff)
                && word(v, 0x128) == Some(0x52801ce9)
                && word(v, 0x144) == Some(0x71001b7f)
                && word(v, 0x158) == Some(0x52800be9)
                && materializes(v, [0x168, 0x16c, 0x170, 0x174], 8, n.target_formats.address)
                && word(v, 0x184) == Some(0xb87b7901)
                && word(v, 0x194).and_then(|w| target(n.draw + 0x194, w)) == Some(n.target_setup)
                && word(v, 0x23c) == Some(0x97ff331c)
                && word(v, 0x240) == Some(0x97ff28c7)
                && word(v, 0x248).and_then(|w| target(n.draw + 0x248, w)) == Some(n.target_restore)
                && word(v, 0x268) == Some(0xd65f03c0)
        }),
        "request_tables_setup_and_restore",
    );
    check(
        body("bitmap_target_setup").is_some_and(|v| {
            word(v, 0x28) == Some(0x7100191f)
                && word(v, 0x2c) == Some(0x1a9f32d6)
                && word(v, 0x3c) == Some(0x321f03e1)
                && word(v, 0x40) == Some(0xaa1403e0)
                && word(v, 0x48) == Some(0x2a1603e3)
                && word(v, 0x70) == Some(0xd65f03c0)
        }) && body("bitmap_target_restore").is_some_and(|v| word(v, 0x18) == Some(0x17ff24da)),
        "complete_target_helpers",
    );
}
