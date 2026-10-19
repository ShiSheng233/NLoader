//! Optional GUI diagnostics use only original profile-owned native services.
use nloader_profile::Profile;
use std::fmt::Write;
pub(crate) fn generate(profile: &Profile) -> String {
    let Some(b) = &profile.services.bitmap else {
        return String::new();
    };
    let window = profile
        .menu
        .window_address(
            profile
                .menu
                .page
                .as_ref()
                .expect("validated page")
                .window_id,
        )
        .expect("validated window");
    let mut out=String::from("\n#if defined(NLR_STAGE_EXEC)\nstatic const char nlr_bitmap_gui_task_name[8] = \"APPMENU\";\nconst struct nlr_bitmap_services nlr_bitmap_services = {\n");
    for (name, value) in [
        ("blit", b.blit),
        ("current_index", b.current_index),
        ("current_surface", b.current_surface),
        ("current_window", b.current_window),
        ("current_task", b.current_task),
        ("clean_source", b.clean_source),
    ] {
        writeln!(out, "    .{name} = (void *)0x{value:x}UL,").unwrap();
    }
    writeln!(out,"    .window = (const void *)0x{window:x}UL,\n    .window_id = {}U,\n    .gui_task_name = nlr_bitmap_gui_task_name,\n    .pattern = {}U,\n}};\n#endif",profile.menu.page.as_ref().unwrap().window_id,b.mode.pattern()).unwrap();
    out
}
