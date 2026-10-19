//! Pure state codec checks; no production storage, QEMU or camera access.
use std::{fs, path::Path, process::Command};

#[test]
#[ignore = "requires clang and an AArch64 backend"]
fn card_state_recovers_complete_records_and_refuses_uncertain_commits() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let directory = tempfile::tempdir().unwrap();
    let include = directory.path().join("include/nlr");
    fs::create_dir_all(&include).unwrap();
    fs::write(
        include.join("card_config.h"),
        "#define NLR_CARD_ROOT \"?:\\\\NLOADER\\\\\"\n",
    )
    .unwrap();
    for (optimization, sanitizer) in [("-O0", false), ("-O1", true), ("-Os", false)] {
        let binary = directory.path().join(format!("card-state-{optimization}"));
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
        let compiled = compiler
            .arg(core.join("card_state.c"))
            .arg(core.join("test_card_state.c"))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{optimization}: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let run = Command::new(&binary).output().unwrap();
        assert!(
            run.status.success(),
            "{optimization}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(String::from_utf8_lossy(&run.stdout).contains("card state codec tests passed"));
    }
    let object = directory.path().join("card-state.o");
    let compiled = Command::new("clang")
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
            "-c",
        ])
        .arg("-I")
        .arg(directory.path().join("include"))
        .arg("-I")
        .arg(core.join("include"))
        .arg(core.join("card_state.c"))
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let bytes = fs::read(object).unwrap();
    nloader_build::inspect_object("card_state.c", &bytes).unwrap();
    use object::{Object, ObjectSymbol};
    let file = object::File::parse(bytes.as_slice()).unwrap();
    assert!(
        !file
            .symbols()
            .any(|symbol| symbol.is_undefined() && symbol.name().is_ok_and(|name| !name.is_empty())),
        "the standalone codec must not require a libc or native storage function"
    );
}
