//! Native-provider contracts plus explicit local original-byte qualification.
use nloader_build::{Error, Result};
use std::{fs, path::Path, process::Command};
#[path = "../src/graphics_bindings.rs"]
mod graphics_bindings;

#[test]
#[ignore = "requires clang, linker section removal and its sanitizer runtime"]
fn runtime_row_count_tracks_constructed_rows_and_rejects_invalid_declarations() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let directory = tempfile::tempdir().unwrap();
    let include = directory.path().join("include/nlr");
    fs::create_dir_all(&include).unwrap();
    fs::write(
        include.join("card_config.h"),
        "#define NLR_CARD_ROOT \"?:\\\\NLOADER\\\\\"\n#define NLR_HAS_NATIVE_CARD 0\n#define NLR_HAS_BITMAP 0\n#define NLR_HAS_PAINT 0\n#define NLR_HAS_PRIVATE_TEXT 0\n",
    )
    .unwrap();
    let cases: [(&str, &[&str]); 6] = [
        ("fixed", &["-DNLR_TEST_STAY_NEXT=0"]),
        ("dynamic", &["-DNLR_TEST_DYNAMIC_ROWS=1"]),
        (
            "missing-stay",
            &["-DNLR_TEST_DYNAMIC_ROWS=1", "-DNLR_TEST_STAY_NEXT=0"],
        ),
        (
            "capacity-mismatch",
            &["-DNLR_TEST_DYNAMIC_ROWS=1", "-DNLR_TEST_PAGE_ROWS=3"],
        ),
        (
            "unaligned-count",
            &["-DNLR_TEST_DYNAMIC_ROWS=1", "-DNLR_TEST_UNALIGNED_ROWS=1"],
        ),
        (
            "zero-capacity",
            &["-DNLR_TEST_DYNAMIC_ROWS=1", "-DNLR_TEST_PAGE_ROWS=0"],
        ),
    ];
    for (name, defines) in cases {
        for (optimization, sanitizer) in [("-O0", false), ("-O1", true), ("-Os", false)] {
            let binary = directory
                .path()
                .join(format!("graphics-rows-{name}-{optimization}"));
            let mut compiler = Command::new("clang");
            compiler
                .args([
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-DNLR_HAS_GRAPHICS=1",
                    "-ffunction-sections",
                    "-fdata-sections",
                    optimization,
                ])
                .args(defines)
                .arg(if cfg!(target_os = "macos") {
                    "-Wl,-dead_strip"
                } else {
                    "-Wl,--gc-sections"
                })
                .arg("-I")
                .arg(directory.path().join("include"))
                .arg("-I")
                .arg(core.join("include"));
            if sanitizer {
                compiler.arg("-fsanitize=address,undefined");
            }
            let compiled = compiler
                .arg(core.join("graphics_runtime.c"))
                .arg(core.join("test_graphics_rows.c"))
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                compiled.status.success(),
                "{name}/{optimization}: {}",
                String::from_utf8_lossy(&compiled.stderr)
            );
            let ran = Command::new(binary).output().unwrap();
            assert!(
                ran.status.success(),
                "{name}/{optimization}: {}\n{}",
                String::from_utf8_lossy(&ran.stdout),
                String::from_utf8_lossy(&ran.stderr)
            );
            assert!(String::from_utf8_lossy(&ran.stdout)
                .contains("native graphics actual row count checks passed"));
        }
    }
}

#[test]
#[ignore = "requires clang and sanitizer support"]
fn provider_requires_real_self_callback_and_display_submit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let temp = tempfile::tempdir().unwrap();
    for (opt, sanitize) in [("-O0", false), ("-O1", true), ("-Os", false)] {
        let bin = temp.path().join(format!("provider-{opt}"));
        let mut command = Command::new("clang");
        command
            .args(["-Wall", "-Wextra", "-Werror", opt])
            .arg("-I")
            .arg(root.join("core/include"));
        if sanitize {
            command.arg("-fsanitize=address,undefined");
        }
        let built = command
            .arg(root.join("core/graphics.c"))
            .arg(root.join("core/native_graphics.c"))
            .arg(root.join("core/test_native_graphics.c"))
            .arg("-o")
            .arg(&bin)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let ran = Command::new(bin).output().unwrap();
        assert!(
            ran.status.success(),
            "{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        assert!(String::from_utf8_lossy(&ran.stdout)
            .contains("native graphics callback and submit checks passed"));
    }
}

#[test]
#[ignore = "requires local Z8 C3.11 official module and isolated graphics profile"]
fn official_graphics_profile_and_generated_bindings_are_independently_checked() {
    use nloader_profile::{
        validate_graphics, validate_graphics_bytes, BuildMode, Profile, ValidationReport,
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let text =
        fs::read_to_string(root.join("build/m3-graphics-research-20261013/z8-qemu-graphics.toml"))
            .unwrap();
    let module =
        fs::read(root.join("firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi")).unwrap();
    let text = with_commit_observer(&with_slot_rule(&text), &module);
    let p: Profile = toml_profile(&text);
    let g = p.services.graphics.as_ref().unwrap();
    let mut report = ValidationReport::default();
    validate_graphics(&p, g, BuildMode::Exec, &mut report);
    validate_graphics_bytes(&p, g, &module, &mut report);
    assert!(report.issues.is_empty(), "{report:#?}");
    let mut bad = g.clone();
    bad.bodies[0].length -= 4;
    let mut report = ValidationReport::default();
    validate_graphics(&p, &bad, BuildMode::Exec, &mut report);
    assert!(!report.issues.is_empty());
    let mut altered = module.clone();
    let mut bad = g.clone();
    let b = bad
        .bodies
        .iter_mut()
        .find(|b| b.name == "set_draw_body")
        .unwrap();
    let offset = p
        .memory
        .address_to_offset(b.address, u64::from(b.length))
        .unwrap() as usize;
    altered[offset..offset + 4].copy_from_slice(&0xf9005401u32.to_le_bytes());
    b.sha256 = nloader_profile::sha256(&altered[offset..offset + b.length as usize]);
    let mut report = ValidationReport::default();
    validate_graphics_bytes(&p, &bad, &altered, &mut report);
    assert!(
        !report.issues.is_empty(),
        "rehashing a setter for the wrong field must not qualify it"
    );
    let mut elements = vec![0u8; 68];
    graphics_bindings::append_canvas(&mut elements, &p, g, &module).unwrap();
    assert_eq!(elements.len(), 136);
    assert_eq!(&elements[68..], &[0; 68]);
    assert_eq!(
        u32::from_le_bytes(elements[0x38..0x3c].try_into().unwrap()),
        g.canvas_id
    );
    assert_eq!(u32::from_le_bytes(elements[4..8].try_into().unwrap()), 4);
    assert_eq!(
        u32::from_le_bytes(elements[0x3c..0x40].try_into().unwrap()),
        0x0010_0000
    );
    assert_eq!(&elements[0x40..0x44], &[0; 4]);
    assert_eq!(g.surface_index, 2);
    assert_eq!(g.surface_size, [640, 422]);
    assert_eq!(g.destination, [0, 0, 632, 395]);
    assert!(graphics_bindings::append_canvas(&mut elements, &p, g, &module).is_err());
    let generated = graphics_bindings::generate(&p, g).unwrap();
    assert!(generated.contains("nlr_native_graphics_services"));
    assert!(generated.contains(&format!(
        ".row_hide = (void *)0x{:x}UL,",
        p.menu.page.as_ref().unwrap().row_hide.unwrap()
    )));
    let mut missing = p.clone();
    missing.menu.page.as_mut().unwrap().row_hide = None;
    let mut report = ValidationReport::default();
    validate_graphics(&missing, g, BuildMode::Exec, &mut report);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.field == "services.graphics.row_hide"));
    assert!(graphics_bindings::generate(&missing, g).is_err());
    // The canvas counts frames through the platform's commit observer: a
    // commit call that is not one of the two composition calls, or a callee
    // that is not the graphics submit, is refused.
    let commit = p
        .services
        .platform
        .as_ref()
        .and_then(|pl| pl.commit.clone())
        .unwrap();
    assert_eq!(
        commit.sites,
        [g.display_refresh + 0x344, g.display_refresh + 0x4b8]
    );
    for change in [0usize, 1, 2] {
        let mut wrong = p.clone();
        let c = wrong
            .services
            .platform
            .as_mut()
            .unwrap()
            .commit
            .as_mut()
            .unwrap();
        match change {
            0 => c.sites[1] += 4,
            1 => c.callee += 4,
            _ => wrong.services.platform.as_mut().unwrap().commit = None,
        }
        let mut report = ValidationReport::default();
        validate_graphics(&wrong, g, BuildMode::Exec, &mut report);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.field == "services.platform.commit"),
            "{change}: {report:#?}"
        );
    }
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("bindings.c");
    fs::write(
        &source,
        format!("#include \"nlr/native_graphics.h\"\n{generated}"),
    )
    .unwrap();
    for (name, input) in [
        ("native_graphics", root.join("core/native_graphics.c")),
        ("bindings", source),
    ] {
        let output = temp.path().join(format!("{name}.o"));
        let result = Command::new("clang")
            .args([
                "--target=aarch64-none-elf",
                "-march=armv8-a",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-common",
                "-fno-stack-protector",
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-ffunction-sections",
                "-fdata-sections",
                "-Os",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-DNLR_STAGE_EXEC",
                "-c",
            ])
            .arg("-I")
            .arg(root.join("core/include"))
            .arg(input)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let bytes = fs::read(output).unwrap();
        nloader_build::inspect_object(name, &bytes).unwrap();
        use object::{Object, ObjectSymbol};
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let allowed = [
            "nlr_graphics_snapshot",
            "nlr_native_graphics_context",
            "nlr_native_graphics_gui_committed",
            "nlr_native_graphics_row_count",
            "nlr_native_graphics_services",
        ];
        for symbol in object.symbols().filter(|s| s.is_undefined()) {
            let name = symbol.name().unwrap();
            assert!(
                name.is_empty() || allowed.contains(&name),
                "unexpected camera import: {name}"
            );
        }
    }
}

fn toml_profile(text: &str) -> nloader_profile::Profile {
    nloader_profile::Profile::from_toml(text).unwrap()
}

/// The local graphics fixture predates the per-slot durability rule: its native-card section still names the NVMe flush and the NVMe
/// layout. This test reads only that section's GUI-state field, so the old
/// keys are dropped in memory and the per-slot flush is declared as 0, an
/// address nothing here calls or checks. A fixture already in the new form
/// is used as it is.
fn with_slot_rule(text: &str) -> String {
    if !text.lines().any(|l| l.starts_with("\"flush\" = ")) {
        return text.to_string();
    }
    let gone = [
        "media_controller_offset",
        "cfe_",
        "block_io_",
        "namespace_",
        "controller_",
        "identify_",
    ];
    text.lines()
        .filter(|l| !gone.iter().any(|k| l.starts_with(&format!("\"{k}"))))
        .map(|l| {
            if l.starts_with("\"flush\" = ") {
                "\"slot_flush\" = 0\n".to_string()
            } else if l.starts_with("\"media_slot_offset\" = ") {
                format!("{l}\n\"slot_count\" = 2\n")
            } else {
                format!("{l}\n")
            }
        })
        .collect()
}

/// The local graphics fixture predates the commit observer: its graphics
/// table named the two display-composition calls itself
/// (`"submit_sites" = [..]`). They now belong to `services.platform.commit`,
/// which owns those sites for every reader; the fixture is moved over in
/// memory, with each call's stock word read from the official module. A
/// fixture that already declares the observer is used as it is.
fn with_commit_observer(text: &str, module: &[u8]) -> String {
    let Some(line) = text
        .lines()
        .find(|l| l.trim_start().starts_with("\"submit_sites\""))
    else {
        return text.to_string();
    };
    let number = |s: &str| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap();
    let sites: Vec<u64> = line
        .split_once('[')
        .unwrap()
        .1
        .trim_end_matches(']')
        .split(',')
        .map(number)
        .collect();
    let submit = text
        .lines()
        .find(|l| l.trim_start().starts_with("\"submit\" ="))
        .map(|l| number(l.split_once('=').unwrap().1))
        .unwrap();
    let without: String = text
        .lines()
        .filter(|l| *l != line)
        .map(|l| format!("{l}\n"))
        .collect();
    let p = toml_profile(&without);
    let stock: Vec<String> = sites
        .iter()
        .map(|site| {
            let at = p.memory.address_to_offset(*site, 4).unwrap() as usize;
            format!("{:?}", &module[at..at + 4])
        })
        .collect();
    format!(
        "{without}\n[services.platform.commit]\ncallee = 0x{submit:x}\nsites = [{}]\nstock = [{}]\n",
        sites
            .iter()
            .map(|s| format!("0x{s:x}"))
            .collect::<Vec<_>>()
            .join(", "),
        stock.join(", ")
    )
}
