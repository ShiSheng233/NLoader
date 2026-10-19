//! Real input interception and GUI dispatch, without storage or entry mocks.
use std::{fs, path::Path, process::Command};

#[test]
#[ignore = "requires clang, linker section removal and its sanitizer runtime"]
fn retained_menu_edges_do_not_replay_other_inputs_or_obsolete_navigation() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let directory = tempfile::tempdir().unwrap();
    let include = directory.path().join("include/nlr");
    fs::create_dir_all(&include).unwrap();
    fs::write(include.join("card_config.h"),
        "#define NLR_CARD_ROOT \"?:\\\\NLOADER\\\\\"\n#define NLR_HAS_BITMAP 0\n#define NLR_HAS_NATIVE_CARD 1\n").unwrap();
    for (optimization, sanitizer) in [("-O0", false), ("-O1", true), ("-Os", false)] {
        let binary = directory.path().join(format!("exit-menu-{optimization}"));
        let mut compiler = Command::new("clang");
        compiler
            .args([
                "-Wall",
                "-Wextra",
                "-Werror",
                "-DNLR_STAGE_EXEC",
                "-ffunction-sections",
                "-fdata-sections",
                optimization,
            ])
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
        let output = compiler
            .arg(core.join("runtime.c"))
            .arg(core.join("platform.c"))
            .arg(core.join("time.c"))
            .arg(core.join("input.c"))
            .arg(core.join("native_card.c"))
            .arg(core.join("test_exit_menu.c"))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result = Command::new(binary).output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout)
            .contains("retained MENU and actual-release GUI checks passed"));
    }
}
