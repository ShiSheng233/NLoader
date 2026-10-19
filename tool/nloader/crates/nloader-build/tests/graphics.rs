//! Isolated frame handoff checks; synthetic services, no GUI or camera access.
use std::{fs, path::Path, process::Command};

#[test]
#[ignore = "requires clang and its sanitizer runtime"]
fn public_api4_preserves_frame_ownership_and_confines_directory_access() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let directory = tempfile::tempdir().unwrap();
    let include = directory.path().join("include/nlr");
    fs::create_dir_all(&include).unwrap();
    fs::write(include.join("card_config.h"),
        "#define NLR_CARD_ROOT \"B:\\\\NLOADER\\\\\"\n#define NLR_HAS_NATIVE_CARD 0\n#define NLR_HAS_BITMAP 0\n#define NLR_HAS_PAINT 0\n#define NLR_HAS_PRIVATE_TEXT 0\n#define NLR_HAS_GRAPHICS 1\n#define NLR_PROGRAM_ARENA_BYTES 65536u\n").unwrap();
    for (optimization, sanitizer) in [("-O0", false), ("-O1", true), ("-Os", false)] {
        let binary = directory.path().join(format!("api4-{optimization}"));
        let mut command = Command::new("clang");
        command
            .args([
                "-Wall",
                "-Wextra",
                "-Werror",
                optimization,
                "-DNLR_STAGE_EXEC",
                "-DNLR_HAS_GRAPHICS=1",
            ])
            .arg("-I")
            .arg(directory.path().join("include"))
            .arg("-I")
            .arg(core.join("include"));
        if sanitizer {
            command.arg("-fsanitize=address,undefined");
        }
        for source in [
            "api.c",
            "platform.c",
            "journal.c",
            "graphics.c",
            "time.c",
            "input.c",
            "hook.c",
            "test_api4.c",
        ] {
            command.arg(core.join(source));
        }
        let compiled = command.arg("-o").arg(&binary).output().unwrap();
        assert!(
            compiled.status.success(),
            "{optimization}: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let ran = Command::new(binary).output().unwrap();
        assert!(
            ran.status.success(),
            "{optimization}: {}\n{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
    }
}

#[test]
#[ignore = "requires clang, AArch64 support and its sanitizer runtime"]
fn graphics_ownership_and_uncertain_completion_keep_sources_alive() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let directory = tempfile::tempdir().unwrap();
    for (optimization, sanitizer) in [("-O0", false), ("-O1", true), ("-Os", false)] {
        let binary = directory.path().join(format!("graphics-{optimization}"));
        let mut command = Command::new("clang");
        command
            .args(["-Wall", "-Wextra", "-Werror", "-pthread", optimization])
            .arg("-I")
            .arg(core.join("include"));
        if sanitizer {
            command.arg("-fsanitize=address,undefined");
        }
        let compiled = command
            .arg(core.join("graphics.c"))
            .arg(core.join("test_graphics.c"))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{optimization}: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let ran = Command::new(binary).output().unwrap();
        assert!(
            ran.status.success(),
            "{optimization}: {}\n{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
        assert!(String::from_utf8_lossy(&ran.stdout)
            .contains("graphics frame ownership and completion checks passed"));
    }
    let object = directory.path().join("graphics.o");
    let compiled = Command::new("clang")
        .args([
            "--target=aarch64-none-elf",
            "-march=armv8-a",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-common",
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
            "-c",
        ])
        .arg("-I")
        .arg(core.join("include"))
        .arg(core.join("graphics.c"))
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "AArch64: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let bytes = fs::read(object).unwrap();
    nloader_build::inspect_object("graphics.c", &bytes).unwrap();
    use object::{Object, ObjectSymbol};
    let file = object::File::parse(bytes.as_slice()).unwrap();
    assert!(
        !file
            .symbols()
            .any(|symbol| symbol.is_undefined() && symbol.name().is_ok_and(|name| !name.is_empty())),
        "frame handoff must not import libc or hardwired firmware symbols"
    );
}
