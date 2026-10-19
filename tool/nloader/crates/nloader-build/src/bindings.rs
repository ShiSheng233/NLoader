//! Per-model C bindings generation. The generated translation unit contains
//! the model's raw service addresses as constants, adapter wrappers where the
//! firmware ABI differs from the normalized `nlr_services` contract, and the
//! service table the core consumes. Addresses come only from the validated
//! profile; nothing here guesses.

use nloader_profile::Profile;

/// Neutral table for compiler/toolchain checks: no model addresses, no
/// adapters, never dereferenced.
pub(crate) const NEUTRAL: &str = r#"#include "nlr/services.h"
#include "nlr/manifest.h"
#include "nlr/native_card.h"
const struct nlr_native_card_services nlr_native_card_services = { 0 };
/* Neutral bindings for toolchain checks only; every member stays null. */
const struct nlr_services nlr_services = {
    .abi = 1,
    .alloc = 0,
    .release = 0,
    .worker_init = 0,
    .worker_start = 0,
    .flag_set = 0,
    .file_open = 0,
    .file_read = 0,
    .file_seek = 0,
    .file_close = 0,
    .cache_before_read = 0,
    .cache_after_read = 0,
    .registry_lookup = 0,
    .exit = 0,
};
/* No camera identity in a neutral build; the gate then reports that a
 * program's declaration cannot be confirmed. */
const struct nlr_identity nlr_identity = { 0, 0 };
"#;

/// (profile field, emitted define name, service table member).
const MAPPINGS: &[(&str, &str, &str)] = &[
    ("worker_init", "NLR_MODEL_WORKER_INIT", "worker_init"),
    ("worker_start", "NLR_MODEL_WORKER_START", "worker_start"),
    ("flag_set", "NLR_MODEL_FLAG_SET", "flag_set"),
    ("fs_open", "NLR_MODEL_FILE_OPEN", "file_open"),
    ("fs_read", "NLR_MODEL_FILE_READ", "file_read"),
    ("fs_seek", "NLR_MODEL_FILE_SEEK", "file_seek"),
    ("fs_close", "NLR_MODEL_FILE_CLOSE", "file_close"),
    ("fs_write", "NLR_MODEL_FILE_WRITE", "file_write"),
    (
        "dcache_inv_pre",
        "NLR_MODEL_DCACHE_PRE",
        "cache_before_read",
    ),
    (
        "dcache_inv_post",
        "NLR_MODEL_DCACHE_POST",
        "cache_after_read",
    ),
    ("dcache_clean", "NLR_MODEL_DCACHE_CLEAN", "cache_clean"),
    (
        "registry_lookup",
        "NLR_MODEL_REGISTRY_LOOKUP",
        "registry_lookup",
    ),
    ("mem_alloc", "NLR_MODEL_MEM_ALLOC", "alloc"),
    ("mem_free", "NLR_MODEL_MEM_FREE", "release"),
];

/// Table members whose firmware ABI matches the contract and are wired
/// directly; the rest go through generated adapters below.
const DIRECT: &[&str] = &[
    "worker_init",
    "worker_start",
    "file_open",
    "file_read",
    "file_close",
    "file_write",
    "cache_before_read",
    "cache_after_read",
    "cache_clean",
    "registry_lookup",
];

fn define_of(field: &str) -> &'static str {
    MAPPINGS
        .iter()
        .find(|(f, _, _)| *f == field)
        .map(|(_, d, _)| *d)
        .expect("known field")
}

fn member_of(field: &str) -> &'static str {
    MAPPINGS
        .iter()
        .find(|(f, _, _)| *f == field)
        .map(|(_, _, m)| *m)
        .expect("known field")
}

/// C string literal body for profile text. Quotes and backslashes are
/// escaped; anything outside printable ASCII becomes a fixed-width octal
/// escape so the emitted bytes are exactly the profile's bytes.
fn escape(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(byte));
            }
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\{byte:03o}")),
        }
    }
    out
}

/// The generated entry for GUI turn `n` (services.platform.gui_turns).
pub(crate) fn gui_turn_symbol(n: usize) -> String {
    format!("nlr_model_gui_turn_{n}")
}

/// The ABI 7 platform table (core/include/nlr/platform.h) for an execution
/// build: the control table, the dial words, the settings store and the
/// GUI redraw entry. Absent parts stay zero; core reports -ENOSYS for them.
fn platform_services(p: &nloader_profile::PlatformServices) -> String {
    let mut out = String::from("\n#if defined(NLR_STAGE_EXEC)\n#include \"nlr/platform.h\"\n");
    let mut controls = String::new();
    for (name, bank, mask) in &p.controls {
        // Validation refused unknown names before any binding is made.
        let number = nloader_profile::control_number(name).unwrap_or(u8::MAX);
        controls.push_str(&format!(
            "    {{ {number}, {bank}, 0, 0x{mask:x}U }}, /* {name} */\n"
        ));
    }
    if !p.controls.is_empty() {
        out.push_str(&format!(
            "static const struct nlr_platform_control nlr_model_platform_controls[] = {{\n{controls}}};\n"
        ));
    }
    let props = match &p.props {
        Some(s) => format!(
            "    .prop_groups = (const volatile uint8_t *)0x{:x}UL,\n\
             \x20   .prop_group_count = {}U,\n\
             \x20   .prop_group_bytes = {}U,\n\
             \x20   .group_live_at = {},\n\
             \x20   .group_first_at = {},\n\
             \x20   .group_items_at = {},\n\
             \x20   .item_size_at = {},\n\
             \x20   .prop_items = (const volatile uint8_t *)0x{:x}UL,\n\
             \x20   .prop_item_count = {}U,\n\
             \x20   .prop_item_bytes = {}U,\n\
             \x20   .item_ram_at = {},\n\
             \x20   .prop_ram_lo = 0x{:x}UL,\n\
             \x20   .prop_ram_hi = 0x{:x}UL,\n\
             \x20   .prop_set = {},\n\
             \x20   .prop_set_blob = {},\n",
            s.groups,
            s.group_count,
            s.group_bytes,
            s.group_live_at,
            s.group_first_at,
            s.group_items_at,
            s.item_size_at,
            s.items,
            s.item_count,
            s.item_bytes,
            s.item_ram_at,
            s.ram_lo,
            s.ram_hi,
            s.setter.map_or("0".to_string(), |a| format!(
                "(uint64_t (*)(uint32_t, uint32_t))0x{a:x}UL"
            )),
            s.setter_blob.map_or("0".to_string(), |a| format!(
                "(uint64_t (*)(uint32_t, const void *, uint32_t))0x{a:x}UL"
            ))
        ),
        None => String::new(),
    };
    // ABI 8: the profile's names. A point's continuation runs the four
    // words its detour overwrites, then branches to target + 16; it lives in
    // the loader's own image, so a program gets it without an address.
    for (n, point) in p.points.iter().enumerate() {
        out.push_str(&format!(
            "__attribute__((naked, noinline, used)) static void nlr_model_point_{n}(void)\n\
             {{\n\
             \x20   __asm__ volatile(\".inst 0x{:08x}\\n.inst 0x{:08x}\\n.inst 0x{:08x}\\n\
             .inst 0x{:08x}\\nldr x16, 1f\\nbr x16\\n.balign 8\\n1: .quad 0x{:x}\");\n\
             }}\n",
            point.expect[0],
            point.expect[1],
            point.expect[2],
            point.expect[3],
            point.target + 16
        ));
    }
    let names = |list: &mut String, entries: Vec<String>| {
        for e in entries {
            list.push_str(&e);
        }
    };
    let mut points = String::new();
    names(
        &mut points,
        p.points
            .iter()
            .enumerate()
            .map(|(n, pt)| {
                format!(
                    "    {{ \"{}\", 0x{:x}UL, {{ 0x{:08x}U, 0x{:08x}U, 0x{:08x}U, 0x{:08x}U }}, \
                     nlr_model_point_{n}, {}U }},\n",
                    pt.name,
                    pt.target,
                    pt.expect[0],
                    pt.expect[1],
                    pt.expect[2],
                    pt.expect[3],
                    pt.args
                )
            })
            .collect(),
    );
    let mut tables = String::new();
    names(
        &mut tables,
        p.tables
            .iter()
            .map(|t| {
                format!(
                    "    {{ \"{}\", 0x{:x}UL, {}U, {}U, 0x{:08x}U, 0, 0x{:x}UL }},\n",
                    t.name,
                    t.address,
                    t.size,
                    nloader_profile::table_class(&t.class).unwrap_or(2),
                    t.crc,
                    t.stock_pointer.unwrap_or(0)
                )
            })
            .collect(),
    );
    let mut functions = String::new();
    names(
        &mut functions,
        p.functions
            .iter()
            .map(|f| format!("    {{ \"{}\", (void *)0x{:x}UL }},\n", f.name, f.address))
            .collect(),
    );
    let mut devices = String::new();
    names(
        &mut devices,
        p.devices
            .iter()
            .map(|d| {
                format!(
                    "    {{ \"{}\", {}U, 0x{:x}U, 0x{:x}U, 0 }},\n",
                    d.name, d.bank, d.address, d.client
                )
            })
            .collect(),
    );
    for (kind, body) in [
        ("point", &points),
        ("table", &tables),
        ("function", &functions),
        ("device", &devices),
    ] {
        if !body.is_empty() {
            out.push_str(&format!(
                "static const struct nlr_platform_{kind} nlr_model_platform_{kind}s[] = {{\n{body}}};\n"
            ));
        }
    }
    let address_of = |name: &str| {
        p.functions
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.address)
            .unwrap_or(0)
    };
    let i2c = match &p.i2c {
        Some(i) => {
            out.push_str(&format!(
                "/* The firmware's I2C service (services.platform.i2c): attach the\n\
                 \x20* device's client handle (bank << 16 | 1 << index, a bit of the\n\
                 \x20* loader's own), one message under the bank's mutex, detach. */\n\
                 static int32_t nlr_model_i2c(uint32_t bank, uint32_t client, uint32_t address,\n\
                 \x20                            const void *tx, uint32_t txlen, void *rx,\n\
                 \x20                            uint32_t rxlen)\n\
                 {{\n\
                 \x20   int32_t (*attach)(uint32_t) = (void *)0x{:x}UL;\n\
                 \x20   int32_t (*xfer)(uint32_t, void *) = (void *)0x{:x}UL;\n\
                 \x20   int32_t (*detach)(uint32_t) = (void *)0x{:x}UL;\n\
                 \x20   struct {{ uint32_t nea; uint16_t slave; uint16_t pad; const void *tx;\n\
                 \x20            void *rx; uint32_t txlen; uint32_t rxlen; }} m = {{\n\
                 \x20       1u, (uint16_t)address, 0, tx, rx, txlen, rxlen }};\n\
                 \x20   (void)bank;\n\
                 \x20   if (attach(client))\n\
                 \x20       return -1;\n\
                 \x20   int32_t result = xfer(client, &m);\n\
                 \x20   detach(client);\n\
                 \x20   return result;\n\
                 }}\n",
                address_of(&i.attach),
                address_of(&i.xfer),
                address_of(&i.detach)
            ));
            "nlr_model_i2c"
        }
        None => "0",
    };
    // The GUI turns: one entry per declared site, the build's BL patch
    // points the stock call there; core makes the stock call itself.
    let gui_turns = if p.gui_turns.is_empty() {
        "    .gui_turn_count = 0U,\n    .gui_turns = 0,\n".to_string()
    } else {
        let mut rows = String::new();
        for (n, turn) in p.gui_turns.iter().enumerate() {
            out.push_str(&format!(
                "/* GUI turn {name} (services.platform.gui_turns): the stock call at \
                 0x{site:x}. */\n\
                 void *{symbol}(void);\n\
                 __attribute__((noinline, used)) void *{symbol}(void)\n\
                 {{\n\
                 \x20   return nlr_platform_gui_turn({n}U);\n\
                 }}\n",
                name = turn.name,
                site = turn.site,
                symbol = gui_turn_symbol(n),
            ));
            rows.push_str(&format!(
                "    {{ (void *(*)(void))0x{:x}UL }}, /* {} */\n",
                turn.callee, turn.name
            ));
        }
        out.push_str(&format!(
            "static const struct nlr_platform_gui_turn nlr_model_platform_gui_turns[] = {{\n{rows}}};\n"
        ));
        format!(
            "    .gui_turn_count = {}U,\n    .gui_turns = nlr_model_platform_gui_turns,\n",
            p.gui_turns.len()
        )
    };
    let list = |kind: &str, n: usize| {
        if n == 0 {
            "0".to_string()
        } else {
            format!("nlr_model_platform_{kind}s")
        }
    };
    let names_fields = format!(
        "    .points = {},\n    .point_count = {}U,\n    .tables = {},\n    .table_count = {}U,\n\
         \x20   .functions = {},\n    .function_count = {}U,\n    .devices = {},\n\
         \x20   .device_count = {}U,\n    .i2c_transfer = {i2c},\n",
        list("point", p.points.len()),
        p.points.len(),
        list("table", p.tables.len()),
        p.tables.len(),
        list("function", p.functions.len()),
        p.functions.len(),
        list("device", p.devices.len()),
        p.devices.len()
    );
    /* The scan object's geometry, when the body's input hook is not the
     * program input slot (the Z 8's exit callback). */
    let scan = match &p.scan {
        Some(s) => {
            let activity = match s.activity {
                Some(a) => format!("(void (*)(void))0x{a:x}UL"),
                None => "0".to_string(),
            };
            let object = match s.object {
                Some(o) => format!("(void *)0x{o:x}UL"),
                None => "0".to_string(),
            };
            out.push_str(&format!(
                "static const struct nlr_platform_scan nlr_model_platform_scan = {{\n\
                 \x20   .bank_base = {},\n\
                 \x20   .bank_stride = {},\n\
                 \x20   .banks = {},\n\
                 \x20   .keep_bank = {},\n\
                 \x20   .keep_mask = 0x{:x}U,\n\
                 \x20   .dial_offset = {},\n\
                 \x20   .dial_bytes = {},\n\
                 \x20   .activity = {activity},\n\
                 \x20   .object = {object},\n\
                 }};\n",
                s.bank_base,
                s.bank_stride,
                s.banks,
                s.keep_bank,
                s.keep_mask,
                s.dial_offset,
                s.dial_bytes
            ));
            "&nlr_model_platform_scan"
        }
        None => "0",
    };
    out.push_str(&format!(
        "static const struct nlr_platform_services nlr_model_platform_services = {{\n\
         \x20   .controls = {controls},\n\
         \x20   .control_count = {count}U,\n\
         \x20   .scan = {scan},\n\
         \x20   .dial_word = {{ {w0}, {w1}, {w2} }},\n\
         \x20   .dial_sign = {{ {s0}, {s1}, {s2} }},\n\
         \x20   .dial_alt = {{ {a0}, {a1}, {a2} }},\n\
         {touch}\
         {props}\
         \x20   .gui_redraw = {redraw},\n\
         {card}\
         {bundle}\
         {names_fields}\
         {gui_turns}\
         {hold}\
         }};\n#endif\n",
        controls = if p.controls.is_empty() {
            "0"
        } else {
            "nlr_model_platform_controls"
        },
        count = p.controls.len(),
        scan = scan,
        w0 = p.dial_words[0],
        w1 = p.dial_words[1],
        w2 = p.dial_words[2],
        s0 = if p.dial_signs[0] < 0 { -1 } else { 1 },
        s1 = if p.dial_signs[1] < 0 { -1 } else { 1 },
        s2 = if p.dial_signs[2] < 0 { -1 } else { 1 },
        a0 = p.dial_alt_words[0],
        a1 = p.dial_alt_words[1],
        a2 = p.dial_alt_words[2],
        touch = {
            let mut t = String::new();
            if let (Some(slot), Some(original)) = (p.touch_slot, p.touch_original) {
                t.push_str(&format!(
                    "    .touch_slot = (void (**)(uint32_t, void *))0x{slot:x}UL,\n\
                     \x20   .touch_original = (void (*)(uint32_t, void *))0x{original:x}UL,\n\
                     \x20   .touch_record_bytes = {}U,\n",
                    p.touch_record_bytes
                ));
            }
            if let Some(eye) = p.eye_state {
                t.push_str(&format!(
                    "    .eye_state = (const volatile uint32_t *)0x{eye:x}UL,\n"
                ));
            }
            t
        },
        // The GUI hold and the commit observer's stock callee
        // (services.platform.hold / .commit); undeclared stays zero.
        hold = {
            let mut h = String::new();
            if let Some(hold) = &p.hold {
                h.push_str(&format!(
                    "    .hold_when = {}U,\n    .hold_wait_ms = {}U,\n    .scanout_stable_ms = {}U,\n",
                    hold.when.core_value(),
                    hold.wait_ms,
                    hold.scanout_stable_ms
                ));
            }
            if let Some(commit) = &p.commit {
                h.push_str(&format!(
                    "    .commit = (int32_t (*)(uint32_t, void *))0x{:x}UL,\n",
                    commit.callee
                ));
            }
            h
        },
        bundle = match &p.bundle {
            Some(b) => format!(
                "    .bundle = (const uint8_t *)0x{:x}UL,\n    .bundle_bytes = 0x{:x}U,\n",
                b.address, b.size
            ),
            None => String::new(),
        },
        card = match &p.card {
            Some(c) => {
                let letters: Vec<String> = c
                    .letters
                    .bytes()
                    .map(|b| format!("'{}'", b as char))
                    .collect();
                format!(
                    "    .volumes = (const volatile uint8_t *)0x{:x}UL,\n\
                     \x20   .volume_count = {}U,\n\
                     \x20   .volume_bytes = {}U,\n\
                     \x20   .volume_state = 0x{:x},\n\
                     \x20   .mounted = {},\n\
                     \x20   .card_slots = {},\n\
                     \x20   .card_letters = {{ {} }},\n",
                    c.volumes,
                    c.volume_count,
                    c.volume_bytes,
                    c.volume_state,
                    c.mounted,
                    c.letters.len(),
                    letters.join(", ")
                )
            }
            None => String::new(),
        },
        redraw = match p.gui_redraw {
            Some(a) => format!("(void (*)(void))0x{a:x}UL"),
            None => "0".to_string(),
        },
    ));
    out
}

/// The ABI 4 program services table and native-menu delay adapter for an
/// execution build. Absent parts stay null; core reports -ENOSYS for them.
fn program_services(p: &nloader_profile::ProgramServices) -> String {
    let mut out = String::from("\n#if defined(NLR_STAGE_EXEC)\n");
    if let Some(delay) = p.task_delay {
        out.push_str(&format!(
            "static void nlr_model_sleep_ms(uint32_t ms)\n\
             {{\n\
                 int32_t (*raw)(int32_t) = (void *)0x{delay:x}UL;\n\
                 raw((int32_t)ms);\n\
             }}\n"
        ));
    }
    let code = |v: Option<u64>| match v {
        Some(a) => format!("(void *)0x{a:x}UL"),
        None => "0".to_string(),
    };
    let mut keys = String::new();
    for (i, [bank, mask]) in p.keys.iter().enumerate() {
        keys.push_str(&format!("        [{i}] = {{ {bank}, 0x{mask:x}U }},\n"));
    }
    out.push_str(&format!(
        "static const struct nlr_program_services nlr_model_program_services = {{\n\
             .fs_enum = {fs_enum},\n\
             .enum_done = 0x{enum_done:x}U,\n\
             .mask_directories = 0x{mask_dirs:x}U,\n\
             .mask_files = 0x{mask_files:x}U,\n\
             .attr_directory = 0x{attr_dir:x}U,\n\
             .info_short = 0x{info_short:x},\n\
             .info_long = 0x{info_long:x},\n\
             .info_attr = 0x{info_attr:x},\n\
             .info_size = 0x{info_size:x},\n\
             .info_long_unit = {info_long_unit},\n\
             .input_slot = (void (**)(void *)){slot},\n\
             .input_original = {original},\n\
             .input_object = (void *){object},\n\
             .bank_base = 0x{bank_base:x}U,\n\
             .bank_stride = 0x{bank_stride:x}U,\n\
             .banks = {banks}U,\n\
             .keep_bank = {keep_bank}U,\n\
             .keep_mask = 0x{keep_mask:x}U,\n\
             .dial_offset = 0x{dial_offset:x}U,\n\
             .dial_bytes = {dial_bytes}U,\n\
             .keys = {{\n{keys}    }},\n\
             .scanout_colour = (const volatile uint32_t *){scanout_colour},\n\
             .scanout_alpha = (const volatile uint32_t *){scanout_alpha},\n\
             .scanout_high_mask = 0x{high_mask:x}U,\n\
             .bus_offset = 0x{bus_offset:x}UL,\n\
             .plane_lo = 0x{plane_lo:x}UL,\n\
             .plane_hi = 0x{plane_hi:x}UL,\n\
             .width = {width}U,\n\
             .height = {height}U,\n\
             .stride = {stride}U,\n\
             .alpha_stride = {alpha_stride}U,\n\
             .activity = {activity},\n\
         }};\n#endif\n",
        fs_enum = code(p.fs_enum),
        enum_done = p.enum_done,
        mask_dirs = p.mask_directories,
        mask_files = p.mask_files,
        attr_dir = p.attr_directory,
        info_short = p.info_short,
        info_long = p.info_long,
        info_attr = p.info_attr,
        info_size = p.info_size,
        info_long_unit = p.info_long_unit,
        slot = match p.input_slot {
            Some(a) => format!("0x{a:x}UL"),
            None => "0".to_string(),
        },
        original = code(p.input_original),
        object = code(p.input_object),
        bank_base = p.bank_base,
        bank_stride = p.bank_stride,
        banks = p.banks,
        keep_bank = p.keep_bank,
        keep_mask = p.keep_mask,
        dial_offset = p.dial_offset,
        dial_bytes = p.dial_bytes,
        keys = keys,
        scanout_colour = match p.scanout_colour {
            Some(a) => format!("0x{a:x}UL"),
            None => "0".to_string(),
        },
        scanout_alpha = match p.scanout_alpha {
            Some(a) => format!("0x{a:x}UL"),
            None => "0".to_string(),
        },
        high_mask = p.scanout_high_mask,
        bus_offset = p.bus_offset,
        plane_lo = p.plane_lo,
        plane_hi = p.plane_hi,
        width = p.width,
        height = p.height,
        stride = p.stride,
        alpha_stride = p.alpha_stride,
        activity = code(p.activity),
    ));
    out
}

/// The ABI 5 firmware-code channel for an execution build: the two windows
/// from `services.code` and the execution family's own mapping and cache
/// services, which core drives but never addresses itself. An incomplete
/// declaration emits nothing, and core then reports -ENOSYS.
fn code_services(profile: &Profile) -> String {
    let Some(code) = &profile.services.code else {
        return String::new();
    };
    let exec = &profile.services.exec;
    let (Some(text_lo), Some(text_hi), Some(alias_lo), Some(alias_hi)) =
        (code.text_lo, code.text_hi, code.alias_lo, code.alias_hi)
    else {
        return String::new();
    };
    let (Some(manager), Some(translate), Some(query), Some(cacheable), Some(invalidate)) = (
        exec.manager,
        exec.mmu_translate,
        exec.page_query,
        exec.cacheable,
        exec.icache_inval,
    ) else {
        return String::new();
    };
    let Some(clean) = profile.services.dcache_clean else {
        return String::new();
    };
    let writable = exec.flag_writable.unwrap_or(0);
    let executable = exec.flag_executable.unwrap_or(0);
    let unaligned = u32::from(code.unaligned_literals.unwrap_or(false));
    format!(
        "\n#if defined(NLR_STAGE_EXEC)\n\
         /* The code window and the DRAM alias band its pages translate into;\n\
          * the mapping manager, the virtual-to-physical and permission\n\
          * services, the cacheable predicate, the D-cache clean to the point\n\
          * of coherency and the broadcast I-cache invalidation. */\n\
         static const struct nlr_code_services nlr_model_code_services = {{\n\
         \x20   .text_lo = 0x{text_lo:x}UL,\n\
         \x20   .text_hi = 0x{text_hi:x}UL,\n\
         \x20   .alias_lo = 0x{alias_lo:x}UL,\n\
         \x20   .alias_hi = 0x{alias_hi:x}UL,\n\
         \x20   .manager = (const volatile void *)0x{manager:x}UL,\n\
         \x20   .translate = (int32_t (*)(const volatile void *, uintptr_t,\n\
         \x20                             uint64_t *))0x{translate:x}UL,\n\
         \x20   .query = (int32_t (*)(void *, uint32_t *))0x{query:x}UL,\n\
         \x20   .cacheable = (uint32_t (*)(void *))0x{cacheable:x}UL,\n\
         \x20   .clean = (void (*)(void *, uint32_t))0x{clean:x}UL,\n\
         \x20   .invalidate = (void (*)(void *, uint64_t))0x{invalidate:x}UL,\n\
         \x20   .flag_writable = 0x{writable:x}U,\n\
         \x20   .flag_executable = 0x{executable:x}U,\n\
         \x20   .unaligned_literals = {unaligned}U,\n\
         }};\n#endif\n"
    )
}

/// Emit the bindings translation unit for a profile.
pub(crate) fn generate(profile: &Profile, menu_enabled: bool) -> String {
    let value = |field: &str| -> Option<u64> {
        let s = &profile.services;
        match field {
            "worker_init" => s.worker_init,
            "worker_start" => s.worker_start,
            "flag_set" => s.flag_set,
            "fs_open" => s.fs_open,
            "fs_read" => s.fs_read,
            "fs_seek" => s.fs_seek,
            "fs_close" => s.fs_close,
            "fs_write" => s.fs_write,
            "dcache_inv_pre" => s.dcache_inv_pre,
            "dcache_inv_post" => s.dcache_inv_post,
            "dcache_clean" => s.dcache_clean,
            "registry_lookup" => s.registry_lookup,
            "mem_alloc" => s.mem_alloc,
            "mem_free" => s.mem_free,
            _ => None,
        }
    };

    let mut emitted = false;
    let mut out = String::new();
    out.push_str(
        "#include \"nlr/services.h\"\n#include \"nlr/menu.h\"\n#include \"nlr/manifest.h\"\n#include \"nlr/native_card.h\"\n\n",
    );
    out.push_str("/* Generated per-model bindings. Raw addresses come from the validated\n");
    out.push_str(" * profile; adapters normalize firmware ABI differences onto the\n");
    out.push_str(" * nlr_services contract. Missing profile fields stay null and are\n");
    out.push_str(" * never dereferenced by builds that do not select them. */\n\n");
    for (field, define, _) in MAPPINGS {
        match value(field) {
            Some(v) => out.push_str(&format!("#define {define} 0x{v:x}UL\n")),
            None => out.push_str(&format!(
                "#define {define} 0UL /* not established for this model yet */\n"
            )),
        }
    }

    if profile.services.fs_seek.is_some() {
        if profile.services.native_card.is_some() {
            out.push_str("#if !defined(NLR_STAGE_EXEC)\n");
        }
        out.push_str(
            r#"
/* The file family takes (fd, offset, whence, out), while the core contract
 * takes (fd, whence, offset, out). Raw success is nonzero (cset ne); the
 * normalized service returns 0. */
static int32_t nlr_model_file_seek(int32_t fd, int32_t whence, uint32_t offset,
                                   uint32_t *out_position)
{
    int32_t (*raw)(int32_t, uint32_t, int32_t, uint32_t *) =
        (void *)NLR_MODEL_FILE_SEEK;
    return raw(fd, offset, whence, out_position) ? 0 : -1;
}
"#,
        );
        if profile.services.native_card.is_some() {
            out.push_str("#endif\n");
        }
    }
    if profile.services.flag_set.is_some() {
        out.push_str(
            if profile
                .abi
                .task
                .is_some_and(nloader_profile::TaskFamily::flag_slot_is_id)
            {
                r#"
/* This body's set entry is the kernel's own set_flg(ID, pattern): it bounds
 * the id against the flag count and indexes the flag table, so the slot at
 * worker+0x38 holds the id worker_init created, not the object. Passing the
 * slot's address instead is refused as a bad id and wakes nothing, with no
 * fault to show for it, so the id is loaded here and the status kept. */
static int32_t nlr_model_flag_set(void *flag, uint32_t mask)
{
    int32_t (*raw)(int32_t, uint32_t) = (void *)NLR_MODEL_FLAG_SET;
    return raw(*(const int32_t *)flag, mask) ? -1 : 0;
}
"#
            } else {
                r#"
/* The stock set entry's return convention is not established on this build
 * and its callers ignore it; the flag object is created in place by
 * worker_init, so a failed set is not a reportable condition here. */
static int32_t nlr_model_flag_set(void *flag, uint32_t mask)
{
    int32_t (*raw)(void *, uint32_t) = (void *)NLR_MODEL_FLAG_SET;
    raw(flag, mask);
    return 0;
}
"#
            },
        );
    }
    if profile.services.mem_alloc.is_some() {
        out.push_str(
            if profile
                .abi
                .mem
                .is_some_and(nloader_profile::MemFamily::allocates_through_out)
            {
                r#"
/* This body's allocator takes the destination and returns a status, and
 * refuses a null destination, so the payload can only come back through the
 * argument. The heap is fixed inside the stock entry. */
static int32_t nlr_model_alloc(uint32_t bytes, void **out)
{
    int32_t (*raw)(uint32_t, void **) = (void *)NLR_MODEL_MEM_ALLOC;
    void *p = 0;
    int32_t status = raw(bytes, &p);
    if (status || !p) {
        *out = 0;
        return -1;
    }
    *out = p;
    return 0;
}
"#
            } else {
                r#"
/* The model allocator returns a payload pointer or 0 and selects a heap by
 * index; the contract wants 0/-1 with an out pointer. Heap 0 is the General
 * heap shared with the GUI under the allocator lock. */
static int32_t nlr_model_alloc(uint32_t bytes, void **out)
{
    void *(*raw)(uint32_t, uint32_t) = (void *)NLR_MODEL_MEM_ALLOC;
    void *p = raw(bytes, 0);
    *out = p;
    return p ? 0 : -1;
}
"#
            },
        );
    }
    if profile.services.mem_free.is_some() {
        out.push_str(
            if profile
                .abi
                .mem
                .is_some_and(nloader_profile::MemFamily::allocates_through_out)
            {
                r#"
/* The matching release returns a status rather than nothing. */
static int32_t nlr_model_release(void *ptr)
{
    int32_t (*raw)(void *) = (void *)NLR_MODEL_MEM_FREE;
    return raw(ptr) ? -1 : 0;
}
"#
            } else {
                r#"
static int32_t nlr_model_release(void *ptr)
{
    void (*raw)(void *) = (void *)NLR_MODEL_MEM_FREE;
    raw(ptr);
    return 0;
}
"#
            },
        );
    }

    // Optional physical exit support is only published on the executable
    // rung. Native task APIs take the kernel id stored at worker+0; they
    // return E_OK=0, unlike middleware's nonzero-success wrappers. In
    // particular ter_tsk's same-PCB refusal must never become success.
    if let Some(exit) = &profile.services.exit {
        out.push_str("\n#if defined(NLR_STAGE_EXEC)\n");
        for (name, address) in [
            ("suspend", exit.suspend),
            ("resume", exit.resume),
            ("terminate", exit.terminate),
            ("restart", exit.restart),
        ] {
            out.push_str(&format!(
                "static int32_t nlr_model_task_{name}(void *worker)\n\
                 {{\n\
                     int32_t (*raw)(int32_t) = (void *)0x{address:x}UL;\n\
                     int32_t id = *(const int32_t *)worker;\n\
                     return raw(id) == 0 ? 0 : -1;\n\
                 }}\n",
            ));
        }
        out.push_str(&format!(
            "static const struct nlr_exit_services nlr_model_exit_services = {{\n\
                 .input_callback = (void (**)(void *))0x{:x}UL,\n\
                 .bank = {},\n\
                 .mask = 0x{:x}U,\n\
                 .suspend = nlr_model_task_suspend,\n\
                 .resume = nlr_model_task_resume,\n\
                 .terminate = nlr_model_task_terminate,\n\
                 .restart = nlr_model_task_restart,\n\
                 .release_mask = 0x{:x}U,\n\
                 .menu_release_code = 0x{:x}U,\n\
             }};\n#endif\n",
            exit.input_callback, exit.bank, exit.mask, exit.release_mask, exit.menu_release_code,
        ));
    }

    if menu_enabled {
        out.push_str(
            "\n#if defined(NLR_STAGE_EXEC)\n\
             extern const struct nlr_resource_services nlr_resource_services;\n\
             #endif\n",
        );
    }
    if let Some(program) = &profile.services.program {
        out.push_str(&program_services(program));
    }
    if let Some(platform) = &profile.services.platform {
        out.push_str(&platform_services(platform));
    }
    out.push_str(&crate::native_card_bindings::generate(profile));
    if let Some(call) = &profile.boot_hooks.autoload {
        out.push_str(&format!(
            "\n#if defined(NLR_STAGE_EXEC)\n\
             /* The boot checkpoint's stock call (core/boot_autoload.c). */\n\
             const struct nlr_boot_autoload nlr_boot_autoload = {{\n\
             \x20   .call_site = {:#x},\n\
             \x20   .callee = (void *(*)(void)){:#x},\n\
             }};\n\
             #endif\n",
            call.call_site, call.callee
        ));
    }
    out.push_str("\n#include \"nlr/bitmap.h\"\n");
    out.push_str(&crate::bitmap_bindings::generate(profile));
    out.push_str("\n#include \"nlr/paint.h\"\n");
    out.push_str(&crate::paint_bindings::generate(profile));
    out.push_str(&crate::time_bindings::generate(profile));
    out.push_str(&crate::input_bindings::generate(profile));
    out.push_str(&code_services(profile));
    out.push_str("\nconst struct nlr_services nlr_services = {\n    .abi = 1,\n");
    for (field, _, member) in MAPPINGS {
        let expr = match value(field) {
            Some(_) if DIRECT.contains(member) => format!("(void *){}", define_of(field)),
            Some(_) => format!("nlr_model_{}", member_of(field)), // adapter function
            None => "0".to_string(),
        };
        // With the native card RPC the Exec build reaches the card only
        // through the card owner's own transaction, so a program's writes
        // go the same way as its reads: a descriptor from the native open
        // is never handed to the plain FILESRV wrapper. A profile without
        // the write wrapper keeps the write member null.
        let native_member = ["file_open", "file_read", "file_seek", "file_close"].contains(member)
            || (*member == "file_write" && value(field).is_some());
        if profile.services.native_card.is_some() && native_member {
            out.push_str(&format!(
                "#if defined(NLR_STAGE_EXEC)\n    .{member} = nlr_native_card_{member},\n#else\n    .{member} = {expr},\n#endif\n"
            ));
        } else {
            out.push_str(&format!("    .{member} = {expr},\n"));
        }
    }
    if let Some(flags) = profile.services.file_ops.open_read_write {
        out.push_str(&format!("    .file_open_rw = {flags:#x}U,\n"));
    }
    if let Some(flags) = profile.services.file_ops.open_write_create {
        out.push_str(&format!("    .file_open_write = {flags:#x}U,\n"));
        let attributes = profile.services.file_ops.create_attributes.unwrap_or(0);
        out.push_str(&format!(
            "    .file_create_attributes = {attributes:#x}U,\n"
        ));
    }
    if menu_enabled {
        out.push_str(
            "#if defined(NLR_STAGE_EXEC)\n    .resources = &nlr_resource_services,\n#endif\n",
        );
    }
    if profile.services.exit.is_some() {
        out.push_str(
            "#if defined(NLR_STAGE_EXEC)\n    .exit = &nlr_model_exit_services,\n#else\n    .exit = 0,\n#endif\n",
        );
    } else {
        out.push_str("    .exit = 0,\n");
    }
    if profile.services.native_card.is_some() {
        out.push_str(
            "#if defined(NLR_STAGE_EXEC)\n    .native_card = &nlr_native_card_services,\n#endif\n",
        );
    }
    if profile.services.bitmap.is_some() {
        out.push_str("#if defined(NLR_STAGE_EXEC)\n    .bitmap = &nlr_bitmap_services,\n#endif\n");
    }
    if let Some(program) = &profile.services.program {
        if program.task_delay.is_some() {
            out.push_str(
                "#if defined(NLR_STAGE_EXEC)\n    .sleep_ms = nlr_model_sleep_ms,\n#endif\n",
            );
        }
        out.push_str(
            "#if defined(NLR_STAGE_EXEC)\n    .program = &nlr_model_program_services,\n#endif\n",
        );
    }
    if profile.services.time.is_some() {
        out.push_str(
            "#if defined(NLR_STAGE_EXEC)\n    .time = &nlr_model_time_services,\n#endif\n",
        );
    }
    if profile.services.code.is_some() {
        out.push_str(
            "#if defined(NLR_STAGE_EXEC)\n    .code = &nlr_model_code_services,\n#endif\n",
        );
    }
    if profile.services.input.is_some() {
        out.push_str(
            "#if defined(NLR_STAGE_EXEC)\n    .input = &nlr_model_input_services,\n#endif\n",
        );
    }
    if profile.services.platform.is_some() {
        out.push_str(
            "#if defined(NLR_STAGE_EXEC)\n    .platform = &nlr_model_platform_services,\n#endif\n",
        );
    }
    // The loader's own log (core/journal.c) needs a file it can append to.
    if profile.services.file_ops.open_write_create.is_some()
        && profile.services.file_ops.open_read_write.is_some()
    {
        out.push_str(
            "#if defined(NLR_STAGE_EXEC)\n    .journal_path = NLR_CARD_ROOT \"LOADER.LOG\",\n#endif\n",
        );
    }
    out.push_str("};\n");

    // Menu text platform + entry prefill: ALWAYS emitted so the trampoline's
    // symbol reference resolves in every build. Without the menu feature the
    // members are null/zero and nothing reaches this table (the branch patch
    // that calls the trampoline is only installed with the menu feature).
    if menu_enabled {
        if let Some(platform) = &profile.menu.text_platform {
            out.push_str("\nextern const char nlr_menu_entry_text[];\n");
            if profile.menu.page.is_some() {
                out.push_str("extern const char nlr_page_row_text[];\n");
            }
            let apps = profile.menu.setup.as_ref().and_then(|s| s.apps.as_ref());
            if apps.is_some() {
                out.push_str("extern const char nlr_menu_apps_text[];\n");
            }
            out.push_str("const struct nlr_menu_prefill nlr_menu_prefill = {\n");
            out.push_str(&format!(
                "    .descriptor_base = {:#x},\n    .slot_stride = {:#x},\n",
                platform.descriptor_base, platform.slot_stride
            ));
            out.push_str(&format!(
                "    .buffer_base = {:#x},\n    .buffer_stride = {:#x},\n",
                platform.buffer_base, platform.buffer_stride
            ));
            out.push_str(&format!(
                "    .font_cache_base = {:#x},\n    .font_record_base = {:#x},\n",
                platform.font_cache_base, platform.font_record_base
            ));
            out.push_str(&format!(
                "    .entry_slot = {},\n    .entry_style = {},\n",
                platform.entry_slot, platform.entry_style
            ));
            out.push_str("    .text = nlr_menu_entry_text,\n");
            out.push_str(&format!(
                "    .prefill_call_site = {:#x},\n    .return_target = {:#x},\n",
                platform.prefill_call_site, platform.prefill_return
            ));
            out.push_str(&format!(
                "    .text_store = (void (*)(const char *, uint32_t, uint32_t)){:#x},\n",
                profile.ui.text_store.expect("menu writer validated")
            ));
            if let Some(page) = &profile.menu.page {
                out.push_str(&format!(
                    "    .page_slot = {},\n    .page_style = {},\n",
                    page.item_slot, page.item_style
                ));
                out.push_str("    .page_text = nlr_page_row_text,\n");
            }
            if let Some(apps) = apps {
                out.push_str(&format!(
                    "    .apps_slot = {},\n    .apps_style = {},\n    .apps_text = nlr_menu_apps_text,\n",
                    apps.slot, platform.entry_style
                ));
            }
            out.push_str("};\n");
            emitted = true;
        }
    }
    if !emitted {
        out.push_str("\nconst struct nlr_menu_prefill nlr_menu_prefill = { 0 };\n");
    }
    // NLoader's page table travels with the generated menu data, which knows
    // the cloned page's ids. Without the page the table is empty and the page
    // entry does nothing; it is never reached then, since no window points
    // at its handler block.
    if !(emitted && profile.menu.page.is_some()) {
        out.push_str("const struct nlr_menu_page nlr_menu_page = { 0 };\n");
    }
    // The Setup page as the loader's own pages see it: where its record keeps the items, event pointers and count, so
    // the Apps row -- when it is the first row -- can be left out at a boot
    // whose NLoader switch is off; and what About says about this build.
    let setup = profile.menu.setup.as_ref();
    let apps_first = menu_enabled
        && setup
            .is_some_and(|s| s.entry.is_some() && s.apps.as_ref().is_some_and(|a| a.index == 0));
    // The pages need the page of row kinds the profile declares
    // (menu.page.rows) and the Apps row that opens one of them.
    let pages = menu_enabled
        && setup.is_some_and(|s| s.entry.is_some() && s.apps.is_some())
        && profile
            .menu
            .page
            .as_ref()
            .is_some_and(|p| p.dynamic_rows && p.rows.is_some());
    let fields = if apps_first {
        setup.map_or(0, |s| s.page_address + 0x10)
    } else {
        0
    };
    // The Setup window record, whose built-rows table tells core whether the
    // page is up when the arrays would move.
    let window = if apps_first {
        setup
            .and_then(|s| profile.menu.window_address(s.window_id))
            .unwrap_or(0)
    } else {
        0
    };
    let module = profile
        .checks
        .module_sha256
        .as_deref()
        .map_or(String::new(), |sha| sha.chars().take(8).collect());
    if apps_first {
        out.push_str("extern const unsigned char nlr_menu_items[];\n");
    }
    // The Setup cursor (menu.setup.cursor): only with the Apps-first layout
    // its mapping is written for; otherwise zero, and no call reaches core.
    let cursor = setup
        .filter(|_| apps_first)
        .and_then(|s| Some((s, s.cursor.as_ref()?)));
    let cursor_fields = match cursor {
        Some((s, c)) => format!(
            "\x20   .cursor_setting = {:#x},\n\
             \x20   .stock_rows = {},\n\
             \x20   .entry_index = {},\n\
             \x20   .version_row = {},\n\
             \x20   .cursor_offset = {:#x},\n\
             \x20   .scroll_offset = {:#x},\n\
             \x20   .cursor_get = (uint32_t (*)(uint32_t)){:#x}UL,\n\
             \x20   .cursor_set = (uint32_t (*)(uint32_t, uint32_t)){:#x}UL,\n",
            c.setting,
            s.item_count,
            s.entry.as_ref().map_or(0, |e| e.index),
            s.firmware_version.map_or(0, |f| f.index),
            c.cursor_offset,
            c.scroll_offset,
            c.getter,
            c.setter,
        ),
        None => String::new(),
    };
    out.push_str(&format!(
        "const struct nlr_menu_setup nlr_menu_setup = {{\n\
         \x20   .pages = {pages},\n\
         \x20   .fields = (uint8_t *){fields:#x}UL,\n\
         \x20   .items = {items},\n\
         \x20   .apps_first = {},\n\
         \x20   .version = \"{}\",\n\
         \x20   .module = \"{}\",\n\
         \x20   .window = (const uint8_t *){window:#x}UL,\n\
         {cursor_fields}\
         }};\n",
        u32::from(apps_first),
        escape(env!("CARGO_PKG_VERSION")),
        escape(&module),
        items = if apps_first { "nlr_menu_items" } else { "0" },
        pages = u32::from(pages),
    ));

    // Camera identity for the directory gate. The strings are the profile's
    // own model and firmware; a program's declaration is matched against
    // them and nothing is assumed when they are absent.
    out.push_str("\n/* Camera identity from the profile, used by the directory gate. */\n");
    out.push_str(&format!(
        "static const char nlr_identity_model[] = \"{}\";\n",
        escape(&profile.identity.model)
    ));
    out.push_str(&format!(
        "static const char nlr_identity_firmware[] = \"{}\";\n",
        escape(&profile.identity.firmware)
    ));
    out.push_str("const struct nlr_identity nlr_identity = {\n");
    out.push_str("    .model = nlr_identity_model,\n");
    out.push_str("    .firmware = nlr_identity_firmware,\n};\n");

    // Task configuration from the profile: the single source for the worker
    // task parameters (AUDIT C4). Missing fields emit zeros, which the core
    // rejects at init.
    let task = &profile.task;
    out.push_str("\n/* Worker task parameters from the profile. */\n");
    out.push_str("const struct nlr_task_config nlr_task_config = {\n");
    out.push_str(&format!(
        "    .core = {},\n    .priority = {},\n    .stack_bytes = {},\n",
        task.core.unwrap_or(0),
        task.priority.unwrap_or(0),
        task.stack.unwrap_or(0),
    ));
    let mut name = [0u8; 8];
    if let Some(n) = &task.name {
        for (index, byte) in n.as_bytes().iter().enumerate().take(8) {
            name[index] = *byte;
        }
    }
    out.push_str(&format!(
        "    .name = {{ {} }},\n",
        name.iter()
            .map(|b| format!("{b}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str("};\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use nloader_profile::{ExitServices, FsFamily};
    use std::{path::Path, process::Command};

    #[test]
    #[ignore = "requires clang"]
    fn file_seek_adapter_preserves_native_argument_order_and_positions() {
        let mut profile = Profile::default();
        profile.abi.fs = Some(FsFamily::Z8FileV1);
        profile.services.fs_seek = Some(0x10000);
        let generated = generate(&profile, false);
        let address_define = "#define NLR_MODEL_FILE_SEEK 0x10000UL";
        assert_eq!(generated.matches(address_define).count(), 1);
        // Replace only the synthetic service address. The adapter body and
        // published service table remain the real generator's output.
        let generated = generated.replacen(
            address_define,
            "#define NLR_MODEL_FILE_SEEK ((uintptr_t)native_seek)",
            1,
        );
        let native_service = r#"
#include <assert.h>
#include <stdint.h>
static int32_t seen_fd, seen_whence;
static uint32_t seen_offset, calls;
static uint32_t *seen_position;
static int fail_seek;
static int32_t native_seek(int32_t fd, uint32_t offset, int32_t whence,
                           uint32_t *position)
{
    seen_fd = fd;
    seen_offset = offset;
    seen_whence = whence;
    seen_position = position;
    calls++;
    if (fail_seek)
        return 0;
    if (whence == 0)
        *position = offset;
    else if (whence == 2)
        *position = 941 + offset;
    else
        return 0;
    return 1;
}
"#;
        let harness = r#"
int main(void)
{
    uint32_t position = 0;
    assert(nlr_services.file_seek(7, 2, 0, &position) == 0);
    assert(seen_fd == 7 && seen_offset == 0 && seen_whence == 2);
    assert(seen_position == &position && position == 941 && calls == 1);
    assert(nlr_services.file_seek(7, 0, 0, &position) == 0);
    assert(seen_offset == 0 && seen_whence == 0 && position == 0);
    assert(nlr_services.file_seek(7, 0, 13, &position) == 0);
    assert(seen_offset == 13 && seen_whence == 0 && position == 13);
    assert(nlr_services.file_seek(7, 2, 13, &position) == 0);
    assert(seen_offset == 13 && seen_whence == 2 && position == 954);
    fail_seek = 1;
    position = 123;
    assert(nlr_services.file_seek(7, 2, 0, &position) == -1);
    assert(seen_offset == 0 && seen_whence == 2 && position == 123);
    assert(calls == 5);
    return 0;
}
"#;
        let directory = tempfile::tempdir().unwrap();
        let generated_include = directory.path().join("include/nlr");
        std::fs::create_dir_all(&generated_include).unwrap();
        std::fs::write(
            generated_include.join("card_config.h"),
            "#define NLR_CARD_ROOT \"A:\\\\NLOADER\\\\\"\n",
        )
        .unwrap();
        let source = directory.path().join("seek_adapter.c");
        std::fs::write(&source, format!("{native_service}\n{generated}\n{harness}")).unwrap();
        let core_include = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core/include");
        for optimization in ["-O0", "-Os"] {
            let binary = directory.path().join("seek_adapter");
            let compilation = Command::new("clang")
                .args(["-Wall", "-Wextra", "-Werror", optimization])
                .arg("-I")
                .arg(&core_include)
                .arg("-I")
                .arg(directory.path().join("include"))
                .arg(&source)
                .arg("-o")
                .arg(&binary)
                .output()
                .expect("clang should be available");
            assert!(
                compilation.status.success(),
                "seek adapter compilation failed ({optimization}):\n{}",
                String::from_utf8_lossy(&compilation.stderr)
            );
            let run = Command::new(&binary).output().unwrap();
            assert!(
                run.status.success(),
                "seek adapter behavior failed ({optimization}):\n{}",
                String::from_utf8_lossy(&run.stderr)
            );
        }
    }

    #[test]
    fn gui_turns_get_one_entry_each_and_the_stock_callees() {
        let mut profile = Profile::default();
        profile.services.platform = Some(nloader_profile::PlatformServices {
            gui_turns: vec![
                nloader_profile::PlatformGuiTurn {
                    name: "idle".into(),
                    site: 0x1100,
                    callee: 0x1800,
                    stock: vec![0xc0, 0x01, 0x00, 0x94],
                },
                nloader_profile::PlatformGuiTurn {
                    name: "lv".into(),
                    site: 0x1200,
                    callee: 0x1800,
                    stock: vec![0x80, 0x01, 0x00, 0x94],
                },
            ],
            ..Default::default()
        });
        let generated = generate(&profile, true);
        for n in 0..2 {
            assert!(generated.contains(&format!(
                "void *nlr_model_gui_turn_{n}(void)\n{{\n    return nlr_platform_gui_turn({n}U);\n}}"
            )));
        }
        assert!(generated.contains("{ (void *(*)(void))0x1800UL }, /* lv */"));
        assert!(generated
            .contains("    .gui_turn_count = 2U,\n    .gui_turns = nlr_model_platform_gui_turns,"));
        profile.services.platform = Some(Default::default());
        let generated = generate(&profile, true);
        assert!(generated.contains("    .gui_turn_count = 0U,\n    .gui_turns = 0,"));
        assert!(!generated.contains("nlr_model_gui_turn_"));
    }

    /// The hold's declaration reaches core as declared, in both modes, and
    /// the commit observer's stock callee with it; undeclared stays zero.
    #[test]
    fn hold_and_commit_observer_are_bound_as_declared() {
        let mut profile = Profile::default();
        for (when, value, wait, stable) in [
            (nloader_profile::HoldWhen::Immediate, 1, 5000, 300),
            (nloader_profile::HoldWhen::Settle, 2, 2000, 0),
        ] {
            profile.services.platform = Some(nloader_profile::PlatformServices {
                hold: Some(nloader_profile::PlatformHold {
                    when,
                    wait_ms: wait,
                    scanout_stable_ms: stable,
                }),
                commit: Some(nloader_profile::PlatformCommit {
                    callee: 0x1900,
                    sites: vec![0x1300],
                    stock: vec![vec![0x80, 0x01, 0x00, 0x94]],
                }),
                ..Default::default()
            });
            let generated = generate(&profile, true);
            assert!(generated.contains(&format!(
                "    .hold_when = {value}U,\n    .hold_wait_ms = {wait}U,\n    \
                 .scanout_stable_ms = {stable}U,\n    \
                 .commit = (int32_t (*)(uint32_t, void *))0x1900UL,\n"
            )));
        }
        profile.services.platform = Some(Default::default());
        let generated = generate(&profile, true);
        assert!(!generated.contains(".hold_when") && !generated.contains(".commit ="));
    }

    #[test]
    fn absent_exit_stays_null_without_task_adapters() {
        let generated = generate(&Profile::default(), true);
        assert!(generated.contains("    .exit = 0,\n"));
        assert!(!generated.contains("nlr_model_task_"));
        assert!(!generated.contains("nlr_model_exit_services"));
        assert!(NEUTRAL.contains("    .exit = 0,\n"));
    }

    #[test]
    fn optional_exit_uses_profile_slot_and_kernel_task_id() {
        let mut profile = Profile::default();
        profile.services.exit = Some(ExitServices {
            input_callback: 0x70008,
            bank: 1,
            mask: 0xc000,
            release_mask: 0x8000,
            menu_release_code: 0x279,
            menu_release_mapping: nloader_profile::ExecutionTable {
                name: "menu_release".into(),
                address: 0x20000,
                element_bytes: 4,
                values: vec![0, 0x279],
            },
            suspend: 0x21000,
            resume: 0x22000,
            terminate: 0x23000,
            restart: 0x24000,
            bodies: Vec::new(),
        });
        let generated = generate(&profile, true);
        assert!(generated.contains(".input_callback = (void (**)(void *))0x70008UL"));
        assert!(generated.contains(".bank = 1,"));
        assert!(generated.contains(".mask = 0xc000U,"));
        assert!(generated.contains(".release_mask = 0x8000U,"));
        for address in ["21000", "22000", "23000", "24000"] {
            assert!(generated.contains(&format!("(void *)0x{address}UL;")));
        }
        assert_eq!(
            generated
                .matches("int32_t id = *(const int32_t *)worker;")
                .count(),
            4
        );
        assert_eq!(
            generated.matches("return raw(id) == 0 ? 0 : -1;").count(),
            4
        );
        assert!(generated.contains(
            "#if defined(NLR_STAGE_EXEC)\n    .exit = &nlr_model_exit_services,\n#else\n    .exit = 0,\n#endif"
        ));
        assert!(!generated.contains("raw(worker)"));
    }

    /// The Setup cursor fields come from [menu.setup.cursor] only with the
    /// Apps-first layout the core mapping is written for.
    #[test]
    fn setup_cursor_fields_follow_the_apps_first_layout() {
        use nloader_profile::{
            MenuAppsSpec, MenuEntrySpec, MenuItemRef, MenuPage, MenuSetupCursor,
        };
        let cursor = MenuSetupCursor {
            setting: 0x4904,
            setter: 0x2000,
            getter: 0x2004,
            cursor_offset: 0x32,
            scroll_offset: 0x58,
            save_site: 0x1000,
            save_stock: vec![],
            lookup_site: 0x1100,
            lookup_stock: vec![],
            restore_site: 0x1200,
            restore_stock: vec![],
        };
        let setup = |apps_index: u32| MenuPage {
            window_id: 7,
            page_address: 0x3000,
            items: 0x4000,
            item_count: 44,
            event_table: 0x5000,
            layout: 0x6000,
            firmware_version: Some(MenuItemRef {
                index: 42,
                item_id: 0x100,
            }),
            entry: Some(MenuEntrySpec {
                index: 44,
                item_id: 0x7ffe,
                flags: 0x101240,
            }),
            apps: Some(MenuAppsSpec {
                index: apps_index,
                item_id: 0x7ffd,
                flags: 0x101240,
                slot: 1,
                text: "Apps".into(),
            }),
            cursor: Some(cursor.clone()),
        };
        let mut profile = Profile::default();
        profile.menu.setup = Some(setup(0));
        let generated = generate(&profile, true);
        for field in [
            ".cursor_setting = 0x4904,",
            ".stock_rows = 44,",
            ".entry_index = 44,",
            ".version_row = 42,",
            ".cursor_offset = 0x32,",
            ".scroll_offset = 0x58,",
            ".cursor_get = (uint32_t (*)(uint32_t))0x2004UL,",
            ".cursor_set = (uint32_t (*)(uint32_t, uint32_t))0x2000UL,",
        ] {
            assert_eq!(generated.matches(field).count(), 1, "{field}");
        }
        profile.menu.setup = Some(setup(1));
        assert!(!generate(&profile, true).contains(".cursor_setting"));
        profile.menu.setup = Some(setup(0));
        assert!(!generate(&profile, false).contains(".cursor_setting"));
    }
}
