//! Checks that the diagnostic never draws from a changed or unknown owner.
use std::{fs, path::Path, process::Command};

#[test]
#[ignore = "requires clang and its sanitizer runtime"]
fn bitmap_preserves_native_call_and_requires_stable_gui_owner() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let directory = tempfile::tempdir().unwrap();
    let include = directory.path().join("include/nlr");
    fs::create_dir_all(&include).unwrap();
    fs::write(include.join("card_config.h"),
        "#define NLR_CARD_ROOT \"?:\\\\NLOADER\\\\\"\n#define NLR_HAS_BITMAP 1\n#define NLR_HAS_NATIVE_CARD 0\n").unwrap();
    for (optimization, sanitizer) in [("-O0", false), ("-O1", true), ("-Os", false)] {
        let binary = directory.path().join(format!("bitmap-{optimization}"));
        let mut compiler = Command::new("clang");
        compiler
            .args(["-Wall", "-Wextra", "-Werror", optimization])
            .arg("-I")
            .arg(directory.path().join("include"))
            .arg("-I")
            .arg(core.join("include"));
        if sanitizer {
            compiler.arg("-fsanitize=address,undefined");
        }
        let output = compiler
            .arg(core.join("bitmap.c"))
            .arg(core.join("test_bitmap.c"))
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
            .contains("bitmap owner and immutable DMA source checks passed"));
    }
}
