//! Native text copies and precise entry guards, generated only from audited bytes.
use crate::{Error, Patch, Result};
use nloader_profile::{PrivateText, Profile};
use std::collections::BTreeMap;
use std::fmt::Write;

fn body<'a>(p: &Profile, input: &'a [u8], name: &str) -> Result<&'a [u8]> {
    let b = p
        .menu
        .private_text
        .as_ref()
        .and_then(|x| x.body(name))
        .ok_or_else(|| Error::Object(format!("missing private text body {name}")))?;
    let offset = p
        .memory
        .address_to_offset(b.address, u64::from(b.length))
        .map_err(|e| Error::Object(e.to_string()))? as usize;
    input
        .get(offset..offset + b.length as usize)
        .ok_or_else(|| Error::Object("private text body exceeds firmware".into()))
}
fn word(x: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(x[offset..offset + 4].try_into().expect("validated word"))
}
fn addr(t: &PrivateText, name: &str) -> u64 {
    t.body(name).expect("validated body").address
}
fn begin(s: &mut String, name: &str) {
    writeln!(s,".section .text.{name},\"ax\",%progbits\n.p2align 2\n.global {name}\n.type {name},%function\n{name}:").unwrap();
}
fn finish(s: &mut String, name: &str) {
    writeln!(s, ".size {name}, .-{name}").unwrap();
}
fn save(s: &mut String) {
    s.push_str("    sub sp,sp,#0x300\n");
    for n in (0..30).step_by(2) {
        writeln!(s, "    stp x{n},x{},[sp,#{}]", n + 1, n * 8).unwrap();
    }
    s.push_str("    str x30,[sp,#0xf0]\n    mrs x16,nzcv\n    str x16,[sp,#0xf8]\n");
    for n in (0..32).step_by(2) {
        writeln!(s, "    stp q{n},q{},[sp,#{}]", n + 1, 0x100 + n * 16).unwrap();
    }
}
fn restore(s: &mut String) {
    for n in (0..32).step_by(2) {
        writeln!(s, "    ldp q{n},q{},[sp,#{}]", n + 1, 0x100 + n * 16).unwrap();
    }
    s.push_str("    ldr x16,[sp,#0xf8]\n    msr nzcv,x16\n");
    for n in (0..30).step_by(2) {
        writeln!(s, "    ldp x{n},x{},[sp,#{}]", n + 1, n * 8).unwrap();
    }
    s.push_str("    ldr x30,[sp,#0xf0]\n    add sp,sp,#0x300\n");
}

pub(crate) fn assembly(p: &Profile, input: &[u8]) -> Result<String> {
    let t = p
        .menu
        .private_text
        .as_ref()
        .ok_or_else(|| Error::Object("private text not enabled".into()))?;
    let raw = body(p, input, "ascii_writer")?;
    let mut s=String::from("/* Profile-verified native instructions. All private guards preserve GPR/SIMD/NZCV/SP. */\n");
    begin(&mut s, "nlr_private_text_ascii_copy");
    let calls = [
        (0x18, t.strlen),
        (0x54, t.memcpy),
        (0x64, addr(t, "font_getter")),
        (0x78, addr(t, "font_adjustment")),
    ];
    for offset in (0..212).step_by(4) {
        if offset == 0x18 {
            s.push_str("    mov x22,x3\n");
        }
        if let Some((_, callee)) = calls.iter().find(|(off, _)| *off == offset) {
            let _ = callee;
            s.push_str("    .inst 0x94000000\n");
        } else {
            let w = match offset {
                0x1c => 0xaa1603e9,
                0x20 | 0x28 | 0x30 => 0xd503201f,
                _ => word(raw, offset),
            };
            writeln!(s, "    .inst {w:#x}").unwrap();
        }
    }
    finish(&mut s, "nlr_private_text_ascii_copy");
    // Direct native fallback bypasses the guard once, then executes the untouched remaining prologue.
    begin(&mut s, "nlr_private_text_native_ascii");
    writeln!(s, "    .inst {:#x}\n    .inst 0x14000000", word(raw, 0)).unwrap();
    finish(&mut s, "nlr_private_text_native_ascii");
    begin(&mut s, "nlr_private_text_getter_route");
    writeln!(s,"    stp x16,x17,[sp,#-0x20]!\n    mrs x16,nzcv\n    str x16,[sp,#0x10]\n    cbz x0,.Lgetter_stock\n    ldr w17,[x0]\n    movz w16,#{}\n    movk w16,#{},lsl #16\n    sub w17,w17,w16\n    cmp w17,#{}\n    b.hs .Lgetter_stock\n    ldr x16,[sp,#0x10]\n    msr nzcv,x16\n    ldp x16,x17,[sp],#0x20",t.token_base&0xffff,t.token_base>>16,t.token_count).unwrap();
    save(&mut s);
    s.push_str("    bl nlr_private_text_getter\n");
    restore(&mut s);
    s.push_str("    ret\n.Lgetter_stock:\n    ldr x16,[sp,#0x10]\n    msr nzcv,x16\n    ldp x16,x17,[sp],#0x20\n");
    writeln!(
        s,
        "    .inst {:#x}\n    .inst 0x14000000",
        word(body(p, input, "runtime_getter")?, 0)
    )
    .unwrap();
    finish(&mut s, "nlr_private_text_getter_route");
    for (name, source, token_reg, kind) in [
        ("ascii_guard", "ascii_writer", 1, 0),
        ("utf16_guard", "utf16_writer", 1, 1),
        ("conversion_guard", "conversion_writer", 1, 2),
        ("wrapper_ascii_guard", "wrapper_ascii", 2, 3),
        ("wrapper_conversion_guard", "wrapper_conversion", 2, 4),
        ("wrapper_utf16_guard", "wrapper_utf16", 2, 5),
    ] {
        let symbol = format!("nlr_private_text_{name}");
        begin(&mut s, &symbol);
        writeln!(s,"    stp x16,x17,[sp,#-0x20]!\n    mrs x16,nzcv\n    str x16,[sp,#0x10]\n    movz w16,#{}\n    movk w16,#{},lsl #16\n    sub w17,w{token_reg},w16\n    cmp w17,#{}\n    b.hs .Lstock_{name}\n    ldr x16,[sp,#0x10]\n    msr nzcv,x16\n    ldp x16,x17,[sp],#0x20",t.token_base&0xffff,t.token_base>>16,t.token_count).unwrap();
        save(&mut s);
        if kind == 0 {
            s.push_str("    bl nlr_private_text_writer\n");
        } else {
            writeln!(
                s,
                "    mov w0,w{token_reg}\n    mov w1,#{kind}\n    bl nlr_private_text_reject"
            )
            .unwrap();
        }
        restore(&mut s);
        s.push_str("    ret\n");
        writeln!(s,".Lstock_{name}:\n    ldr x16,[sp,#0x10]\n    msr nzcv,x16\n    ldp x16,x17,[sp],#0x20\n    .inst {:#x}\n    .inst 0x14000000",word(body(p,input,source)?,0)).unwrap();
        finish(&mut s, &symbol);
    }
    begin(&mut s, "nlr_private_text_item_clamp");
    // Original W8 label, X19 widget, X20 item remain live at this mid-body site.
    // A private label survives only on its own item: rows by local index,
    // the entry and the Apps row by their exact item IDs.
    writeln!(s,"    stp x16,x17,[sp,#-0x20]!\n    movz w16,#{}\n    movk w16,#{},lsl #16\n    sub w17,w8,w16\n    cmp w17,#{}\n    b.hs .Lclamp_stock\n    ldr w16,[x19,#0xc]\n    cmp w16,#3\n    b.ne .Lclamp_stock\n    ldr w16,[x20,#0x10]\n    tbz w16,#9,.Lclamp_stock\n    tbnz w16,#4,.Lclamp_stock\n    tbnz w16,#13,.Lclamp_stock\n    cmp w17,#64\n    b.lo .Lclamp_row\n    cmp w17,#{}\n    b.ne .Lclamp_apps\n    ldr w16,[x20,#0x18]\n    mov w17,#{}\n    cmp w16,w17\n    b.eq .Lclamp_keep\n    b .Lclamp_stock\n.Lclamp_apps:\n    cmp w17,#{}\n    b.ne .Lclamp_stock\n    ldr w16,[x20,#0x18]\n    mov w17,#{}\n    cmp w16,w17\n    b.eq .Lclamp_keep\n    b .Lclamp_stock\n.Lclamp_row:\n    mov w16,#{}\n    add w17,w17,w16\n    ldr w16,[x20,#0x18]\n    cmp w16,w17\n    b.ne .Lclamp_stock\n.Lclamp_keep:\n    ldp x16,x17,[sp],#0x20\n    cmp w8,#300\n    b .Lclamp_resume\n.Lclamp_stock:\n    ldp x16,x17,[sp],#0x20\n    cmp w8,#300\n    b.lo .Lclamp_resume\n    str wzr,[x19,#8]\n.Lclamp_resume:\n    .inst 0x14000000",t.token_base&0xffff,t.token_base>>16,t.token_count,t.entry_index,t.entry_item_id,t.apps_index,t.apps_item_id,t.row_first_item).unwrap();
    finish(&mut s, "nlr_private_text_item_clamp");
    if let Some(site) = t.value_clamp {
        // Entered by a B at the clamp (`cmp w9,#0x12b`), with the two stores
        // it skips done first. The row's value slot is kept past the stock
        // pool only for an exact private row label k < 32 on item
        // row_first_item + k, in the text-slot mode (w11 == 3), whose flags
        // carry the ASCII and text-value bits and whose value is its own
        // value token (label + 32). Everything else takes the stock
        // decision. NZCV leaves as the stock compare set it.
        let w = |off: u64| -> Result<u32> {
            let at = p
                .memory
                .address_to_offset(site + off, 4)
                .map_err(|e| Error::Object(e.to_string()))? as usize;
            input
                .get(at..at + 4)
                .map(|x| word(x, 0))
                .ok_or_else(|| Error::Object("value clamp exceeds firmware".into()))
        };
        let (store_mode, store_kind, keep, clear) = (w(4)?, w(8)?, w(0x10)?, w(0x18)?);
        begin(&mut s, "nlr_private_text_value_clamp");
        writeln!(
            s,
            r#"    .inst {store_mode:#x}
    .inst {store_kind:#x}
    cmp w9,#0x12b
    sub sp,sp,#0x30
    stp x14,x15,[sp]
    stp x16,x17,[sp,#0x10]
    mrs x16,nzcv
    str x16,[sp,#0x20]
    b.ls .Lvalue_keep
    movz w16,#{}
    movk w16,#{},lsl #16
    sub w17,w9,w16
    cmp w17,#32
    b.hs .Lvalue_clear
    cmp w11,#3
    b.ne .Lvalue_clear
    ldr w14,[x21,#0x10]
    tbz w14,#9,.Lvalue_clear
    tbz w14,#3,.Lvalue_clear
    add w15,w9,#32
    ldr w14,[x21,#0x14]
    cmp w14,w15
    b.ne .Lvalue_clear
    mov w15,#{}
    add w15,w15,w17
    ldr w14,[x21,#0x18]
    cmp w14,w15
    b.ne .Lvalue_clear
.Lvalue_keep:
    ldr x16,[sp,#0x20]
    msr nzcv,x16
    ldp x16,x17,[sp,#0x10]
    ldp x14,x15,[sp]
    add sp,sp,#0x30
    .inst {keep:#x}
    b .Lvalue_store
.Lvalue_clear:
    ldr x16,[sp,#0x20]
    msr nzcv,x16
    ldp x16,x17,[sp,#0x10]
    ldp x14,x15,[sp]
    add sp,sp,#0x30
    .inst {clear:#x}
.Lvalue_store:
    .inst 0x14000000"#,
            t.token_base & 0xffff,
            t.token_base >> 16,
            t.row_first_item
        )
        .unwrap();
        finish(&mut s, "nlr_private_text_value_clamp");
    }
    Ok(s)
}

pub(crate) fn bindings(p: &Profile) -> String {
    let Some(t) = &p.menu.private_text else {
        return "#include \"nlr/text.h\"\nconst struct nlr_private_text_services nlr_private_text_services={0};\n".into();
    };
    let platform = p.menu.text_platform.as_ref().expect("validated platform");
    let page = p.menu.page.as_ref().expect("validated page");
    let escape = |x: &str| x.replace('\\', "\\\\").replace('"', "\\\"");
    // The Apps descriptor's ROM label: the Setup Apps row's own text, or the
    // failure text when the profile declares no such row (index 67 is then
    // never bound by any item).
    let (apps_extern, rom_apps) = match p.menu.setup.as_ref().and_then(|s| s.apps.as_ref()) {
        Some(_) => (",nlr_menu_apps_text[]", "nlr_menu_apps_text".to_string()),
        None => ("", format!("\"{}\"", escape(&t.fallback_text))),
    };
    format!("#include \"nlr/text.h\"\nextern const char nlr_menu_entry_text[],nlr_page_row_text[]{};\nextern void nlr_private_text_ascii_copy(const char*,uint32_t,uint32_t,struct nlr_private_text_descriptor*);\nextern void nlr_private_text_native_ascii(const char*,uint32_t,uint32_t);\nconst struct nlr_private_text_services nlr_private_text_services={{\n .token_base={:#x},.count={},.row_first_item={},.entry_item_id={},\n .title_index={},.status_index={},.entry_index={},.row_style={},.title_style={},.entry_style={},\n .native_getter=(void(*)(uint32_t*,char**,uint32_t*,uint32_t*)){:#x},\n .native_ascii=nlr_private_text_native_ascii,.ascii_copy=nlr_private_text_ascii_copy,\n .low_get=(void(*)(const void*,uint32_t*,uint32_t*)){:#x},.low_set=(int32_t(*)(void*,uint32_t,uint32_t)){:#x},\n .rom_entry=nlr_menu_entry_text,.rom_title=nlr_menu_entry_text,.rom_status=nlr_page_row_text,.rom_failure=\"{}\",\n .current_task=(int32_t(*)(uint32_t*)){:#x},.task_name=\"{}\",\n .apps_index={},.apps_item_id={},.rom_apps={},\n}};\n",apps_extern,t.token_base,t.token_count,t.row_first_item,t.entry_item_id,t.title_index,t.status_index,t.entry_index,page.item_style,page.title_format,platform.entry_style,addr(t,"runtime_getter"),addr(t,"low_level_get"),addr(t,"low_level_set"),escape(&t.fallback_text),addr(t,"current_task"),escape(&t.gui_task_name),t.apps_index,t.apps_item_id,rom_apps)
}

pub(crate) fn patches(
    p: &Profile,
    input: &[u8],
    symbols: &BTreeMap<String, u64>,
) -> Result<Vec<Patch>> {
    let Some(t) = &p.menu.private_text else {
        return Ok(Vec::new());
    };
    let symbol = |name: &str| {
        symbols
            .get(name)
            .copied()
            .ok_or_else(|| Error::Object(format!("private text missing linked symbol {name}")))
    };
    let mut edits = Vec::new();
    for site in &t.getter_call_sites {
        edits.push(crate::native_card_patches::branch_patch(
            p,
            input,
            "private_text_getter",
            *site,
            addr(t, "runtime_getter"),
            symbol("nlr_private_text_getter_route")?,
        )?);
    }
    for (name, kind) in [
        ("ascii_writer", "ascii_guard"),
        ("utf16_writer", "utf16_guard"),
        ("conversion_writer", "conversion_guard"),
        ("wrapper_ascii", "wrapper_ascii_guard"),
        ("wrapper_conversion", "wrapper_conversion_guard"),
        ("wrapper_utf16", "wrapper_utf16_guard"),
    ] {
        edits.push(entry_patch(
            p,
            input,
            name,
            addr(t, name),
            symbol(&format!("nlr_private_text_{kind}"))?,
        )?);
    }
    edits.push(entry_patch(
        p,
        input,
        "item_clamp",
        t.item_clamp,
        symbol("nlr_private_text_item_clamp")?,
    )?);
    if let Some(site) = t.value_clamp {
        edits.push(entry_patch(
            p,
            input,
            "value_clamp",
            site,
            symbol("nlr_private_text_value_clamp")?,
        )?);
    }
    Ok(edits)
}
fn entry_patch(
    p: &Profile,
    input: &[u8],
    _name: &str,
    site: u64,
    destination: u64,
) -> Result<Patch> {
    let offset = p
        .memory
        .address_to_offset(site, 4)
        .map_err(|e| Error::Object(e.to_string()))? as usize;
    let old = input[offset..offset + 4].to_vec();
    let delta = i128::from(destination) - i128::from(site);
    if delta % 4 != 0 || !(-(1 << 27)..(1 << 27)).contains(&delta) {
        return Err(Error::Object(
            "private entry branch exceeds signed imm26".into(),
        ));
    }
    Ok(Patch {
        site: Some(site),
        file_offset: offset as u64,
        kind: "private_text",
        stock: old,
        new: (0x14000000 | ((delta / 4) as u32 & 0x03ffffff))
            .to_le_bytes()
            .to_vec(),
    })
}

pub(crate) fn verify_copy(
    p: &Profile,
    input: &[u8],
    linked: &crate::linker::LinkedImage,
) -> Result<()> {
    let t = p
        .menu
        .private_text
        .as_ref()
        .ok_or_else(|| Error::Object("private text not declared".into()))?;
    let at = *linked
        .symbols
        .get("nlr_private_text_ascii_copy")
        .ok_or_else(|| Error::Object("native ASCII copy not linked".into()))?;
    let section = linked
        .sections
        .iter()
        .find(|s| s.address == at && s.executable && s.size == 216)
        .ok_or_else(|| {
            Error::Object("native ASCII copy is not exactly 216 executable bytes".into())
        })?;
    let base = linked
        .sections
        .iter()
        .map(|s| s.address)
        .min()
        .expect("linked section");
    let raw = body(p, input, "ascii_writer")?;
    let final_bytes = linked
        .bytes
        .get((at - base) as usize..(at - base + section.size) as usize)
        .ok_or_else(|| Error::Object("native ASCII copy exceeds linked area".into()))?;
    let mut expected = Vec::new();
    for offset in (0..212).step_by(4) {
        if offset == 0x18 {
            expected.extend_from_slice(&0xaa0303f6u32.to_le_bytes());
        }
        let mut w = word(raw, offset);
        if [0x1c, 0x20, 0x28, 0x30].contains(&offset) {
            w = if offset == 0x1c {
                0xaa1603e9
            } else {
                0xd503201f
            };
        }
        if w & 0xfc000000 == 0x94000000 {
            if ![0x18, 0x54, 0x64, 0x78].contains(&offset) {
                return Err(Error::Object(
                    "unattested additional native ASCII call".into(),
                ));
            }
            let original = addr(t, "ascii_writer") + offset as u64;
            let imm = (i64::from(((w & 0x03ffffff) as i32) << 6 >> 6)) * 4;
            let destination = (original as i64 + imm) as u64;
            let current = at + expected.len() as u64;
            let delta = i128::from(destination) - i128::from(current);
            if delta % 4 != 0 || !(-(1 << 27)..(1 << 27)).contains(&delta) {
                return Err(Error::Object(
                    "native ASCII relocation exceeds BL range".into(),
                ));
            }
            w = 0x94000000 | ((delta / 4) as u32 & 0x03ffffff);
        }
        expected.extend_from_slice(&w.to_le_bytes());
    }
    if final_bytes != expected {
        return Err(Error::Object(
            "linked native writer differs from independently relocated original instructions"
                .into(),
        ));
    }
    Ok(())
}

/// Native destination branches are resolved after placement; the strict
/// generic linker remains unaware of firmware addresses or null-symbol ELF
/// relocations. Every reserved instruction must still be its exact opcode.
pub(crate) fn relocate(
    p: &Profile,
    input: &[u8],
    linked: &mut crate::linker::LinkedImage,
) -> Result<()> {
    let t = p
        .menu
        .private_text
        .as_ref()
        .ok_or_else(|| Error::Object("private text not declared".into()))?;
    let base = linked
        .sections
        .iter()
        .map(|s| s.address)
        .min()
        .ok_or_else(|| Error::Object("empty linked image".into()))?;
    let copy = linked.symbols["nlr_private_text_ascii_copy"];
    let raw = body(p, input, "ascii_writer")?;
    let mut sites = Vec::new();
    for offset in [0x18, 0x54, 0x64, 0x78] {
        let w = word(raw, offset);
        if w & 0xfc000000 != 0x94000000 {
            return Err(Error::Object("native writer source call is not BL".into()));
        }
        let delta = i64::from(((w & 0x03ffffff) as i32) << 6 >> 6) * 4;
        let destination = (addr(t, "ascii_writer") as i64 + offset as i64 + delta) as u64;
        sites.push((copy + offset as u64 + 4, destination, 0x94000000u32));
    }
    let value_route = t
        .value_clamp
        .map(|site| ("nlr_private_text_value_clamp", site + 0x1c));
    for (symbol, destination) in [
        ("nlr_private_text_native_ascii", addr(t, "ascii_writer") + 4),
        (
            "nlr_private_text_getter_route",
            addr(t, "runtime_getter") + 4,
        ),
        ("nlr_private_text_ascii_guard", addr(t, "ascii_writer") + 4),
        ("nlr_private_text_utf16_guard", addr(t, "utf16_writer") + 4),
        (
            "nlr_private_text_conversion_guard",
            addr(t, "conversion_writer") + 4,
        ),
        (
            "nlr_private_text_wrapper_ascii_guard",
            addr(t, "wrapper_ascii") + 4,
        ),
        (
            "nlr_private_text_wrapper_conversion_guard",
            addr(t, "wrapper_conversion") + 4,
        ),
        (
            "nlr_private_text_wrapper_utf16_guard",
            addr(t, "wrapper_utf16") + 4,
        ),
        ("nlr_private_text_item_clamp", t.item_clamp + 12),
    ]
    .into_iter()
    .chain(value_route)
    {
        let address = linked
            .symbols
            .get(symbol)
            .copied()
            .ok_or_else(|| Error::Object(format!("missing {symbol}")))?;
        let section = linked
            .sections
            .iter()
            .find(|s| s.address == address && s.executable && s.size >= 8)
            .ok_or_else(|| Error::Object(format!("missing executable section for {symbol}")))?;
        sites.push((address + section.size - 4, destination, 0x14000000));
    }
    for (site, destination, opcode) in sites {
        let offset = usize::try_from(site - base)
            .map_err(|_| Error::Object("native relocation outside linked image".into()))?;
        if word(&linked.bytes, offset) != opcode {
            return Err(Error::Object(
                "native relocation reservation differs from its exact branch opcode".into(),
            ));
        }
        let delta = i128::from(destination) - i128::from(site);
        if delta % 4 != 0 || !(-(1 << 27)..(1 << 27)).contains(&delta) {
            return Err(Error::Object(
                "native branch destination exceeds signed imm26".into(),
            ));
        }
        let instruction = opcode | ((delta / 4) as u32 & 0x03ffffff);
        linked.bytes[offset..offset + 4].copy_from_slice(&instruction.to_le_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nloader_profile::{
        ExecutionBody, Memory, MemorySegment, MemorySegmentKind, PrivateTextFamily,
    };
    fn fixture() -> (Profile, Vec<u8>) {
        let mut p = Profile {
            memory: Memory {
                xip_base: Some(0x100000),
                module_size: Some(8192),
                segments: vec![MemorySegment {
                    file_offset: 0,
                    runtime_start: 0x100000,
                    size: 8192,
                    kind: MemorySegmentKind::Xip,
                }],
                ..Memory::default()
            },
            ..Profile::default()
        };
        let names = [
            ("ascii_writer", 212),
            ("utf16_writer", 244),
            ("conversion_writer", 208),
            ("wrapper_ascii", 88),
            ("wrapper_conversion", 84),
            ("wrapper_utf16", 84),
            ("runtime_getter", 88),
            ("font_getter", 36),
            ("font_adjustment", 100),
        ];
        let bodies = names
            .into_iter()
            .enumerate()
            .map(|(i, (name, length))| ExecutionBody {
                name: name.into(),
                address: 0x100000 + i as u64 * 512,
                length,
                sha256: "0".repeat(64),
            })
            .collect();
        p.menu.private_text = Some(PrivateText {
            family: PrivateTextFamily::Z8PrivateAsciiNamespaceV1,
            token_base: u32::from_be_bytes(*b"NL\0\0"),
            token_count: 68,
            title_index: 64,
            status_index: 65,
            entry_index: 66,
            apps_index: 67,
            row_first_item: 0x7f80,
            entry_item_id: 0x7ffe,
            apps_item_id: 0x7ffd,
            ascii_flags: 0x200,
            styles: vec![3, 4],
            getter_call_sites: vec![],
            item_clamp: 0x100f00,
            value_clamp: None,
            strlen: 0x101800,
            memcpy: 0x101900,
            fallback_text: "unavailable".into(),
            gui_task_name: "APPMENU".into(),
            gui_task_config: 0,
            registry_cases: nloader_profile::ExecutionTable {
                name: "registry_cases".into(),
                address: 0,
                element_bytes: 8,
                values: vec![],
            },
            bodies,
        });
        let mut raw = vec![0; 8192];
        for chunk in raw.chunks_exact_mut(4) {
            chunk.copy_from_slice(&0xd503201fu32.to_le_bytes());
        }
        raw[..4].copy_from_slice(&0xf81d0ff6u32.to_le_bytes());
        for index in 1..6 {
            let instruction = if index < 3 {
                0xf81d0ff6u32
            } else {
                0xf81e0ff4u32
            };
            raw[index * 512..index * 512 + 4].copy_from_slice(&instruction.to_le_bytes());
        }
        raw[208..212].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
        let t = p.menu.private_text.as_ref().unwrap();
        for (o, target) in [
            (0x18, t.strlen),
            (0x54, t.memcpy),
            (0x64, addr(t, "font_getter")),
            (0x78, addr(t, "font_adjustment")),
        ] {
            let delta = target as i64 - (0x100000 + o) as i64;
            raw[o..o + 4]
                .copy_from_slice(&(0x94000000 | ((delta / 4) as u32 & 0x03ffffff)).to_le_bytes());
        }
        (p, raw)
    }
    #[test]
    fn guards_keep_exact_full_tokens_and_the_original_mid_body_clamp() {
        let (p, input) = fixture();
        let a = assembly(&p, &input).unwrap();
        assert_eq!(a.matches("cmp w17,#68").count(), 8);
        // The clamp keeps the entry and the Apps token only on their own items.
        assert!(a.contains(
            "cmp w17,#66\n    b.ne .Lclamp_apps\n    ldr w16,[x20,#0x18]\n    mov w17,#32766\n"
        ));
        assert!(a.contains(".Lclamp_apps:\n    cmp w17,#67\n    b.ne .Lclamp_stock\n    ldr w16,[x20,#0x18]\n    mov w17,#32765\n    cmp w16,w17\n    b.eq .Lclamp_keep\n"));
        assert_eq!(a.matches("mrs x16,nzcv").count(), 14);
        assert_eq!(a.matches("stp q30,q31").count(), 7);
        assert_eq!(a.matches("ldp q30,q31").count(), 7);
        assert!(a.contains("tbz w16,#9,.Lclamp_stock"));
        assert!(a.contains("tbnz w16,#4,.Lclamp_stock"));
        assert!(a.contains("tbnz w16,#13,.Lclamp_stock"));
        assert!(a.contains("str wzr,[x19,#8]"));
        assert!(a.contains("cmp w8,#300\n    b.lo .Lclamp_resume"));
    }
    #[test]
    fn value_clamp_keeps_only_the_exact_private_row_value() {
        let (mut p, mut input) = fixture();
        let without = assembly(&p, &input).unwrap();
        assert!(!without.contains("nlr_private_text_value_clamp"));
        let site = 0x101a00u64;
        p.menu.private_text.as_mut().unwrap().value_clamp = Some(site);
        let at = (site - 0x100000) as usize;
        for (n, w) in [
            0x7104ad3fu32,
            0x79000a8a,
            0xb9000e8b,
            0x54000068,
            0xb94016a9,
            0x14000002,
            0x2a1f03e9,
            0xb9000a89,
        ]
        .into_iter()
        .enumerate()
        {
            input[at + n * 4..at + n * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let a = assembly(&p, &input).unwrap();
        // The two stores the B skips, from the module, then the stock test.
        assert!(a.contains(
            "nlr_private_text_value_clamp:\n    .inst 0x79000a8a\n    .inst 0xb9000e8b\n    cmp w9,#0x12b\n"
        ));
        // Row labels 0..31 only, text-slot mode, ASCII and value flags, the
        // row's own value token and its own item id.
        assert!(a.contains("cmp w17,#32\n    b.hs .Lvalue_clear\n    cmp w11,#3\n"));
        assert!(a.contains(
            "tbz w14,#9,.Lvalue_clear\n    tbz w14,#3,.Lvalue_clear\n    add w15,w9,#32\n"
        ));
        assert!(a.contains("mov w15,#32640\n    add w15,w15,w17\n    ldr w14,[x21,#0x18]\n"));
        // Keep and clear are the module's own instructions; NZCV restored.
        assert!(a.contains("    .inst 0xb94016a9\n    b .Lvalue_store\n"));
        assert!(a.contains("    .inst 0x2a1f03e9\n.Lvalue_store:\n    .inst 0x14000000"));
        assert_eq!(
            a.matches("msr nzcv,x16").count(),
            without.matches("msr nzcv,x16").count() + 2
        );
        let edits = patches(
            &p,
            &input,
            &[
                "nlr_private_text_getter_route",
                "nlr_private_text_ascii_guard",
                "nlr_private_text_utf16_guard",
                "nlr_private_text_conversion_guard",
                "nlr_private_text_wrapper_ascii_guard",
                "nlr_private_text_wrapper_conversion_guard",
                "nlr_private_text_wrapper_utf16_guard",
                "nlr_private_text_item_clamp",
                "nlr_private_text_value_clamp",
            ]
            .into_iter()
            .enumerate()
            .map(|(n, name)| (name.to_string(), 0x103000 + n as u64 * 0x100))
            .collect(),
        )
        .unwrap();
        let value = edits.iter().find(|e| e.site == Some(site)).unwrap();
        assert_eq!(value.stock, 0x7104ad3fu32.to_le_bytes());
        let delta = (0x103800i64 - site as i64) / 4;
        assert_eq!(
            value.new,
            (0x14000000 | (delta as u32 & 0x03ffffff)).to_le_bytes()
        );
    }
    #[test]
    #[ignore = "requires AArch64 clang"]
    fn native_copy_and_protected_entry_guards_link_and_reject_tampering() {
        let (p, input) = fixture();
        let a = assembly(&p, &input).unwrap();
        let directory = tempfile::tempdir().unwrap();
        if let Some(path) = std::env::var_os("NLOADER_TEST_PRIVATE_TEXT_ASSEMBLY") {
            std::fs::write(path, &a).unwrap();
        }
        std::fs::write(directory.path().join("private.S"), a).unwrap();
        let stubs=".text\n.p2align 2\n.global entry,nlr_private_text_getter,nlr_private_text_writer,nlr_private_text_reject\n.type entry,%function\nentry: ret\nnlr_private_text_getter: ret\nnlr_private_text_writer: ret\nnlr_private_text_reject: ret\n";
        std::fs::write(directory.path().join("stubs.S"), stubs).unwrap();
        let mut objects = vec![];
        for name in ["private", "stubs"] {
            crate::compile(
                std::ffi::OsStr::new("clang"),
                directory.path(),
                &format!("{name}.S"),
                &format!("{name}.o"),
                &[],
            )
            .unwrap();
            objects.push(crate::linker::ObjectInput {
                name: format!("{name}.o"),
                bytes: std::fs::read(directory.path().join(format!("{name}.o"))).unwrap(),
            });
        }
        let mut linked = crate::linker::link(&objects, 0x200000, 65536, "entry").unwrap();
        relocate(&p, &input, &mut linked).unwrap();
        verify_copy(&p, &input, &linked).unwrap();
        let copy = linked.symbols["nlr_private_text_ascii_copy"];
        let base = linked.sections.iter().map(|s| s.address).min().unwrap();
        let offset = (copy - base) as usize + 0x18;
        linked.bytes[offset] ^= 1;
        assert!(verify_copy(&p, &input, &linked).is_err());
    }
}
