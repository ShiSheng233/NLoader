//! Standalone SDK WAD reader checks; no firmware, game data or camera input.

use nloader_build::program::{build::build, ProgramBuildRequest, ProgramMeta};
use std::{fs, path::Path, process::Command};

#[test]
#[ignore = "requires clang"]
fn wad_reader_validates_formats_and_closes_failures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let output = tempfile::tempdir().unwrap();
    for (name, flags) in [
        ("debug", vec!["-O0"]),
        ("sanitized", vec!["-O1", "-fsanitize=address,undefined"]),
        ("optimized", vec!["-Os"]),
    ] {
        let binary = output.path().join(name);
        let compiled = Command::new("clang")
            .args(["-Wall", "-Wextra", "-Werror"])
            .args(flags)
            .arg("-I")
            .arg(root.join("sdk"))
            .arg("-I")
            .arg(root.join("sdk/examples/doom"))
            .arg(root.join("sdk/examples/doom/wad.c"))
            .arg(root.join("sdk/examples/doom/wad_check.c"))
            .arg(root.join("tests/test_wad.c"))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{name} compile: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let ran = Command::new(binary).output().unwrap();
        assert!(
            ran.status.success(),
            "{name} run: {}\n{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
        assert!(String::from_utf8_lossy(&ran.stdout).contains("WAD tests passed"));
    }
}

#[test]
#[ignore = "requires AArch64 clang"]
fn wad_check_build_is_reproducible_and_declares_foreground() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let output = tempfile::tempdir().unwrap();
    let declaration_bytes = fs::read(root.join("sdk/examples/doom/wad_check.json")).unwrap();
    let mut packages = Vec::new();
    let mut manifests = Vec::new();
    for run in 0..2 {
        let declaration: ProgramMeta = serde_json::from_slice(&declaration_bytes).unwrap();
        let path = output.path().join(format!("WADCHECK{run}.NLB"));
        let manifest = output.path().join(format!("MANIFEST{run}.TXT"));
        let report = build(&ProgramBuildRequest {
            compiler: "clang".into(),
            declaration,
            sources: [
                "sdk/crt0.s",
                "sdk/examples/doom/wad.c",
                "sdk/examples/doom/wad_check.c",
            ]
            .into_iter()
            .map(|name| root.join(name))
            .collect(),
            objects: vec![],
            include_dirs: vec![root.join("sdk")],
            output: path.clone(),
            manifest_output: Some(manifest.clone()),
        })
        .unwrap();
        assert_eq!(report.data_bytes, 0);
        assert_eq!(report.bss_size, 0);
        packages.push(fs::read(path).unwrap());
        manifests.push(fs::read_to_string(manifest).unwrap());
    }
    assert_eq!(packages[0], packages[1]);
    assert_eq!(manifests[0], manifests[1]);
    let package = &packages[0];
    assert_eq!(&package[..4], b"NPLD");
    assert_eq!(u16::from_le_bytes(package[4..6].try_into().unwrap()), 2);
    assert_eq!(
        u32::from_le_bytes(package[0x20..0x24].try_into().unwrap()),
        2
    );
    assert_eq!(
        u32::from_le_bytes(package[0x18..0x1c].try_into().unwrap()),
        2
    );
    assert!(manifests[0]
        .contains("wad_check | foreground | WAD check | APPS/WADCHECK.NLB | 2 | z8/3.11"));
}
