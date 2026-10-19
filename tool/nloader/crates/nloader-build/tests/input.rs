use std::{path::Path, process::Command};

#[test]
#[ignore = "requires Clang with an AArch64 backend"]
fn integrated_input_compiles_with_and_without_graphics() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let temporary = tempfile::tempdir().unwrap();
    let include = temporary.path().join("include/nlr");
    std::fs::create_dir_all(&include).unwrap();
    for graphics in [0, 1] {
        std::fs::write(include.join("card_config.h"), format!(
            "#define NLR_CARD_ROOT \"A:\\\\NLOADER\\\\\"\n#define NLR_HAS_NATIVE_CARD 1\n#define NLR_HAS_BITMAP 0\n#define NLR_HAS_PAINT 0\n#define NLR_HAS_PRIVATE_TEXT 1\n#define NLR_HAS_GRAPHICS {graphics}\n"
        )).unwrap();
        for name in ["input.c", "api.c", "runtime.c", "load.c"] {
            let output = Command::new("clang")
                .args([
                    "--target=aarch64-none-elf",
                    "-march=armv8-a",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-fno-stack-protector",
                    "-fno-unwind-tables",
                    "-fno-asynchronous-unwind-tables",
                    "-fno-pic",
                    "-Os",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-DNLR_STAGE_EXEC",
                ])
                .arg("-I")
                .arg(temporary.path().join("include"))
                .arg("-I")
                .arg(core.join("include"))
                .arg("-c")
                .arg(core.join(name))
                .arg("-o")
                .arg(temporary.path().join(format!("{graphics}-{name}.o")))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{name}, graphics={graphics}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn input_queue_preserves_owner_and_reports_overflow() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let temporary = tempfile::tempdir().unwrap();
    for (optimization, sanitizer) in [("-O0", false), ("-O1", true), ("-Os", false)] {
        let binary = temporary.path().join(format!("input-{optimization}"));
        let mut command = Command::new("clang");
        command.args(["-Wall", "-Wextra", "-Werror", "-pthread", optimization]);
        if sanitizer {
            command.arg("-fsanitize=address,undefined");
        }
        let compiled = command
            .arg("-I")
            .arg(core.join("include"))
            .arg(core.join("input.c"))
            .arg(core.join("test_input.c"))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let ran = Command::new(binary).output().unwrap();
        assert!(
            ran.status.success(),
            "{}{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
    }
}
