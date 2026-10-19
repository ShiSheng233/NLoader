use std::{path::Path, process::Command};

#[test]
fn time_services_measure_waits_and_refuse_stalled_providers() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let temporary = tempfile::tempdir().unwrap();
    for (optimization, sanitizer) in [("-O0", false), ("-O1", true), ("-Os", false)] {
        let binary = temporary.path().join(format!("time-{optimization}"));
        let mut command = Command::new("clang");
        command.args(["-Wall", "-Wextra", "-Werror", optimization]);
        if sanitizer {
            command.arg("-fsanitize=address,undefined");
        }
        let output = command
            .arg("-I")
            .arg(core.join("include"))
            .arg(core.join("time.c"))
            .arg(core.join("test_time.c"))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(binary).output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
