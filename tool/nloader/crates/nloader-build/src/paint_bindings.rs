//! Preserve the text renderer ABI; painting has an independent diagnostic table.
use nloader_profile::Profile;
use std::fmt::Write;

pub(crate) fn generate(profile: &Profile) -> String {
    let Some(p) = &profile.services.paint else {
        return String::new();
    };
    let page = profile.menu.page.as_ref().expect("validated page");
    let window = profile
        .menu
        .window_address(page.window_id)
        .expect("validated window");
    let mut out = String::from("\n#if defined(NLR_STAGE_EXEC)\nstatic const char nlr_paint_task_name[8] = \"APPMENU\";\nconst struct nlr_paint_services nlr_paint_services = {\n");
    for (name, value) in [
        ("text_draw", p.text_draw),
        ("blit", p.blit),
        ("current_index", p.current_index),
        ("current_surface", p.current_surface),
        ("current_window", p.current_window),
        ("current_task", p.current_task),
        ("clean_source", p.clean_source),
        ("widget_root", p.widget_root),
        ("surface_record", p.surface_record),
    ] {
        writeln!(out, "    .{name} = (void *)0x{value:x}UL,").unwrap();
    }
    writeln!(out,"    .window = (const void *)0x{window:x}UL,\n    .task_name = nlr_paint_task_name,\n    .window_id = {}U,\n    .pattern = {}U,\n    .surface_group = {}U,\n    .full_screen = {}U,\n}};\n#endif",page.window_id,p.mode.pattern(),p.surface_group,u32::from(p.full_screen)).unwrap();
    out
}
