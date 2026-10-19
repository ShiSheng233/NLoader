//! Profile-owned native primitive table. Core supplies RPC and recovery policy.
use nloader_profile::Profile;
use std::fmt::Write;

pub(crate) fn generate(profile: &Profile) -> String {
    let Some(card) = &profile.services.native_card else {
        return "\nconst struct nlr_native_card_services nlr_native_card_services = { 0 };\n"
            .into();
    };
    let mut out = String::from("\n#if defined(NLR_STAGE_EXEC)\nconst struct nlr_native_card_services nlr_native_card_services = {\n");
    for (name, value) in [
        ("claim", card.claim),
        ("submit_frame", card.submit_frame),
        ("callback_table", card.callback_table),
        ("lock", card.lock),
        ("unlock", card.unlock),
        ("open", card.open),
        ("read", card.read),
        ("write", card.write),
        ("seek", card.seek),
        ("close", card.close),
        ("stat", card.stat),
        ("fcb_get", card.fcb_get),
        ("volume_sync", card.volume_sync),
        ("volume_index", card.volume_index),
        ("volume_ready", card.volume_ready),
        ("slot_flush", card.slot_flush),
        ("clean_source", card.clean_source),
        ("low_unmount", card.low_unmount),
        ("volume_lock", card.volume_lock),
        ("volume_unlock", card.volume_unlock),
    ] {
        writeln!(out, "    .{name} = (void *)0x{value:x}UL,").unwrap();
    }
    for (name, value) in [
        ("submit_wrapper", card.submit_wrapper),
        ("dispatcher", card.dispatcher),
    ] {
        writeln!(out, "    .{name} = 0x{value:x}UL,").unwrap();
    }
    writeln!(
        out,
        "    .dispatch_table = (const void *)0x{:x}UL,\n    .mutex = (void *)0x{:x}UL,",
        card.dispatch_table, card.mutex
    )
    .unwrap();
    for (name, value) in [
        ("callback_slot", card.callback_slot),
        ("request_bytes", card.request_bytes),
        ("request_volume_offset", card.request_volume_offset),
        ("request_user_offset", card.request_user_offset),
        ("request_callback_offset", card.request_callback_offset),
        ("request_operation_offset", card.request_operation_offset),
        ("request_result_offset", card.request_result_offset),
        ("request_priority_offset", card.request_priority_offset),
        ("operation", card.operation),
        ("stat_bytes", card.stat_bytes),
        ("not_found", card.not_found),
        ("write_flags", card.write_flags),
        ("file_mode", card.file_mode),
        ("create_flags", card.create_flags),
        ("journal_read_flags", card.journal_read_flags),
    ] {
        writeln!(out, "    .{name} = 0x{value:x}U,").unwrap();
    }
    writeln!(out,"    .rpc = {{ .wait_call_site = 0x{:x}UL, .wait_callee = (void *)0x{:x}UL, .reply_flag = (const void *)0x{:x}UL, .shared_frame = (const void *)0x{:x}UL }},",card.rpc.wait_call_site,card.rpc.wait_callee,card.rpc.reply_flag,card.rpc.shared_frame).unwrap();
    let l = &card.layout;
    out.push_str("    .layout = {\n");
    for (name, value) in [
        ("runtime_ram_start", l.runtime_ram.start),
        ("runtime_ram_end", l.runtime_ram.end),
    ] {
        writeln!(out, "        .{name} = 0x{value:x}UL,").unwrap();
    }
    for (name, value) in [
        ("volume_table", l.volume_table),
        ("media_table", l.media_table),
        ("fcb_table", l.fcb_table),
    ] {
        writeln!(out, "        .{name} = (const void *)0x{value:x}UL,").unwrap();
    }
    for (name, value) in [
        ("fcb_volume_count", l.fcb_volume_count),
        ("fcb_slot_count", l.fcb_slot_count),
        ("fcb_volume_stride", l.fcb_volume_stride),
        ("fcb_slot_stride", l.fcb_slot_stride),
        ("fcb_flags_offset", l.fcb_flags_offset),
        ("fcb_ready_mask", l.fcb_ready_mask),
        ("fcb_reject_mask", l.fcb_reject_mask),
        ("fcb_valid_size_offset", l.fcb_valid_size_offset),
        ("fcb_data_size_offset", l.fcb_data_size_offset),
        ("fcb_first_cluster_offset", l.fcb_first_cluster_offset),
        ("fcb_last_cluster_offset", l.fcb_last_cluster_offset),
        ("fcb_no_fat_chain_offset", l.fcb_no_fat_chain_offset),
        ("stat_size_offset", l.stat_size_offset),
        ("stat_attributes_offset", l.stat_attributes_offset),
        ("volume_sector_bytes_offset", l.volume_sector_bytes_offset),
        (
            "volume_cluster_sectors_offset",
            l.volume_cluster_sectors_offset,
        ),
        ("volume_sector_shift_offset", l.volume_sector_shift_offset),
        ("volume_cluster_shift_offset", l.volume_cluster_shift_offset),
        ("volume_cluster_heap_offset", l.volume_cluster_heap_offset),
        ("volume_count", l.volume_count),
        ("volume_stride", l.volume_stride),
        ("volume_device_offset", l.volume_device_offset),
        ("volume_name_offset", l.volume_name_offset),
        ("volume_state_offset", l.volume_state_offset),
        ("volume_type_offset", l.volume_type_offset),
        ("exfat_type", l.exfat_type),
        ("media_count", l.media_count),
        ("media_stride", l.media_stride),
        ("media_slot_offset", l.media_slot_offset),
        ("slot_count", l.slot_count),
    ] {
        writeln!(out, "        .{name} = 0x{value:x}U,").unwrap();
    }
    let exit_fields = if let Some(e) = &card.menu.exit_menu {
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
        format!(" .dispatch = (void *)0x{:x}UL, .current_window = (void *)0x{:x}UL, .loader_window = (const void *)0x{window:x}UL, .gui_state = (const volatile uint32_t *)0x{:x}UL, .menu_press_code = 0x{:x}U,",e.dispatch,e.current_window,e.gui_state,e.menu_press_code)
    } else {
        String::new()
    };
    writeln!(out,"    }},\n    .mount = {{ .call_site = 0x{:x}UL, .callee = (void *)0x{:x}UL }},\n    .unmount = {{ .call_site = 0x{:x}UL, .callee = (void *)0x{:x}UL }},\n    .menu = {{ .call_site = 0x{:x}UL, .callee = (void *)0x{:x}UL, .wake_mask = 0x{:x}U, .target_context_offset = 0x{:x}U, {exit_fields} }},\n}};\n#else\nconst struct nlr_native_card_services nlr_native_card_services = {{ 0 }};\n#endif",card.mount.call_site,card.mount.callee,card.unmount.call_site,card.unmount.callee,card.menu.call_site,card.menu.callee,card.menu.wake_mask,card.menu.target_context_offset).unwrap();
    out
}
