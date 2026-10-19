//! Original self-canvas services and owned element generation.
use crate::{Error, Result};
use nloader_profile::{GraphicsServices, Profile};
use std::fmt::Write;

pub(crate) fn generate(profile: &Profile, g: &GraphicsServices) -> Result<String> {
    let page = profile
        .menu
        .page
        .as_ref()
        .ok_or_else(|| Error::Object("graphics needs the own page".into()))?;
    let window = profile
        .menu
        .window_address(page.window_id)
        .ok_or_else(|| Error::Object("graphics window is outside the declared table".into()))?;
    let registry = profile
        .services
        .registry_lookup
        .ok_or_else(|| Error::Object("graphics lacks original task lookup".into()))?;
    let row_hide = page
        .row_hide
        .ok_or_else(|| Error::Object("graphics lacks original complete-row visibility".into()))?;
    let mapping = g
        .bitmap
        .surface_mapping
        .as_ref()
        .ok_or_else(|| Error::Object("graphics lacks original surface mapping".into()))?;
    let record = mapping
        .index_stride
        .checked_mul(g.surface_index)
        .and_then(|offset| mapping.record_base.checked_add(u64::from(offset)))
        .and_then(|a| a.checked_add(u64::from(mapping.index_offset)))
        .ok_or_else(|| Error::Object("graphics surface record overflows".into()))?;
    let original = g
        .bitmap
        .entry("caller")
        .ok_or_else(|| Error::Object("graphics lacks original canvas callback".into()))?;
    let mut out=String::from("\n#if defined(NLR_STAGE_EXEC)\nstatic const char nlr_graphics_gui_name[8] = \"APPMENU\";\nconst struct nlr_native_graphics_services nlr_native_graphics_services = {\n");
    for (name, address) in [
        ("current_task", g.bitmap.current_task),
        ("registry_lookup", registry),
        ("current_window", g.bitmap.current_window),
        ("widget_find", g.widget_find),
        ("widget_root", g.bitmap.widget_root),
        ("get_draw", g.get_draw),
        ("set_draw", g.set_draw),
        ("set_dirty", g.set_dirty),
        ("get_visible", g.get_visible),
        ("set_visible", g.set_visible),
        ("window_render", g.window_render),
        ("display_refresh", g.display_refresh),
        (
            "render_widget",
            g.entry("locked_render")
                .ok_or_else(|| Error::Object("graphics lacks original locked rendering".into()))?,
        ),
        ("display_abort", g.display_abort),
        ("submit", g.submit),
        (
            "queue_task",
            g.entry("queue_task")
                .ok_or_else(|| Error::Object("graphics lacks original queue task getter".into()))?,
        ),
        ("fence", g.fence),
        ("blit", g.bitmap.blit),
        ("current_index", g.bitmap.current_index),
        ("current_surface", g.bitmap.current_surface),
        ("surface_record", g.bitmap.surface_record),
        ("row_hide", row_hide),
        (
            "row_dirty",
            g.entry("row_dirty").ok_or_else(|| {
                Error::Object("graphics lacks original complete-row redraw".into())
            })?,
        ),
    ] {
        writeln!(out, "    .{name} = (void *)0x{address:x}UL,").unwrap();
    }
    let [x, y, w, h] = g.destination;
    let index = g.surface_index;
    let [surface_width, surface_height] = g.surface_size;
    writeln!(out,"    .window = (const void *)0x{window:x}UL,\n    .window_id = {}U,\n    .canvas_id = {}U,\n    .row_first = {}U,\n    .row_count = {}U,\n    .destination_x = {x}U, .destination_y = {y}U,\n    .destination_width = {w}U, .destination_height = {h}U,\n    .surface_type = 1U, .surface_group = 1U, .surface_index = {index}U,\n    .surface_record_address = (const void *)0x{record:x}UL,\n    .surface_width = {surface_width}U, .surface_height = {surface_height}U,\n    .gui_task_name = nlr_graphics_gui_name,\n    .gui_state = (const volatile uint32_t *)0x{:x}UL,\n    .original_draw = (nlr_native_canvas_draw)0x{original:x}UL,\n}};\n#else\nconst struct nlr_native_graphics_services nlr_native_graphics_services = {{0}};\n#endif\n",page.window_id,g.canvas_id,page.item_id,page.row_slots.len().max(1),g.gui_state).unwrap();
    Ok(out)
}

/// Append before the original terminator, preserving all pre-existing
/// element bytes and requiring a distinct control ID in the final own page.
pub(crate) fn append_canvas(
    elements: &mut Vec<u8>,
    profile: &Profile,
    g: &GraphicsServices,
    module: &[u8],
) -> Result<()> {
    const SIZE: usize = 68;
    if elements.len() < SIZE
        || elements.len() % SIZE != 0
        || elements[elements.len() - SIZE + 4..elements.len() - SIZE + 8] != [0, 0, 0, 0]
    {
        return Err(Error::Object(
            "graphics needs the final original element terminator".into(),
        ));
    }
    if elements
        .chunks_exact(SIZE)
        .any(|e| u32::from_le_bytes(e[0x38..0x3c].try_into().unwrap()) == g.canvas_id)
    {
        return Err(Error::Object(
            "graphics canvas ID conflicts with the own page".into(),
        ));
    }
    let offset = profile
        .memory
        .address_to_offset(g.canvas_element.address, SIZE as u64)
        .map_err(|e| Error::Object(e.to_string()))?;
    let offset = usize::try_from(offset)
        .map_err(|_| Error::Object("canvas offset exceeds host range".into()))?;
    let end = offset
        .checked_add(SIZE)
        .ok_or_else(|| Error::Object("canvas offset overflow".into()))?;
    let template = module
        .get(offset..end)
        .ok_or_else(|| Error::Object("canvas template is outside the official module".into()))?;
    if nloader_profile::sha256(template) != g.canvas_element.sha256
        || u32::from_le_bytes(template[4..8].try_into().unwrap()) != 4
    {
        return Err(Error::Object(
            "canvas requires the independently checked original image element".into(),
        ));
    }
    let mut canvas = template.to_vec();
    canvas[0x38..0x3c].copy_from_slice(&g.canvas_id.to_le_bytes());
    // The audited type-4 parser selects window+0x20 with bit20. All other
    // stock grouping/anchoring flags must stay clear for this own canvas.
    canvas[0x3c..0x44].fill(0);
    canvas[0x3c..0x40].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    let [x, y, w, h] = g.destination;
    let rectangle = [
        x,
        y,
        x.checked_add(w)
            .ok_or_else(|| Error::Object("canvas width overflow".into()))?,
        y.checked_add(h)
            .ok_or_else(|| Error::Object("canvas height overflow".into()))?,
    ];
    for start in [0x18, 0x20] {
        for (n, value) in rectangle.iter().enumerate() {
            let value = u16::try_from(*value)
                .map_err(|_| Error::Object("canvas rectangle exceeds native fields".into()))?;
            canvas[start + n * 2..start + n * 2 + 2].copy_from_slice(&value.to_le_bytes());
        }
    }
    let at = elements.len() - SIZE;
    elements.splice(at..at, canvas);
    Ok(())
}
