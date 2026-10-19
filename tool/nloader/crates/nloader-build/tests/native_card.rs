//! Core-owned RPC/journal failure tests. No QEMU, camera or disk image is used.
use std::{fs, path::Path, process::Command};

/// The same core and the same tests for either slot's root: one identity
/// and one durability rule.
const ROOTS: [(&str, &str, &str); 2] = [("A", "A:", "B:"), ("B", "B:", "A:")];

#[test]
#[ignore = "requires clang and an AArch64 backend"]
fn native_card_keeps_owned_requests_and_stops_uncertain_commits() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let sources = [
        "native_card.c",
        "native_card_state.c",
        "card_state.c",
        "manifest.c",
        "test_native_card.c",
    ];
    for (letter, drive, other) in ROOTS {
        let temporary = tempfile::tempdir().unwrap();
        let include = temporary.path().join("include/nlr");
        fs::create_dir_all(&include).unwrap();
        fs::write(
            include.join("card_config.h"),
            format!(
                "#define NLR_CARD_ROOT \"{letter}:\\\\NLOADER\\\\\"\n#define NLR_HAS_NATIVE_CARD 1\n#define NLR_HAS_BITMAP 0\n#define NLR_TEST_DRIVE \"{drive}\"\n#define NLR_TEST_OTHER \"{other}\"\n"
            ),
        )
        .unwrap();
        for (optimization, sanitizer) in [("-O0", false), ("-O1", true), ("-Os", false)] {
            let executable = temporary.path().join(format!("native-card{optimization}"));
            let mut compiler = Command::new("clang");
            compiler
                .args(["-Wall", "-Wextra", "-Werror", optimization])
                .arg("-I")
                .arg(temporary.path().join("include"))
                .arg("-I")
                .arg(core.join("include"));
            if sanitizer {
                compiler.arg("-fsanitize=address,undefined");
            }
            for source in sources {
                compiler.arg(core.join(source));
            }
            let result = compiler.arg("-o").arg(&executable).output().unwrap();
            assert!(
                result.status.success(),
                "{letter}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let result = Command::new(executable).output().unwrap();
            assert!(
                result.status.success(),
                "{letter}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(String::from_utf8_lossy(&result.stdout)
                .contains("native card ownership and failure tests passed"));
        }
        for source in &sources[..4] {
            let object = temporary.path().join(format!("{source}.o"));
            let result = Command::new("clang")
                .args([
                    "--target=aarch64-none-elf",
                    "-march=armv8-a",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-fno-stack-protector",
                    "-fno-unwind-tables",
                    "-fno-asynchronous-unwind-tables",
                    "-fno-pic",
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
                .arg(temporary.path().join("include"))
                .arg("-I")
                .arg(core.join("include"))
                .arg(core.join(source))
                .arg("-o")
                .arg(&object)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{letter}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            nloader_build::inspect_object(source, &fs::read(object).unwrap()).unwrap();
        }
    }
}
