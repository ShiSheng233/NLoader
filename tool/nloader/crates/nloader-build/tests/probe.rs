use nloader_build::probe::{self, ProbeBuildRequest};
use std::{fs, path::Path};

#[test]
fn exact_envelope_and_response_vectors() {
    let bytes = probe::package_bytes();
    let expected_header = [
        0x4e, 0x50, 0x4c, 0x44, 2, 0, 48, 0, 1, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        0, 0, 0x87, 0xea, 0x73, 0x7f, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(bytes[..48], expected_header);
    assert_eq!(
        bytes[48..],
        [
            0x00, 0x44, 0xc0, 0x93, 0x00, 0x34, 0x00, 0xca, 0x00, 0x44, 0x0c, 0x91, 0xc0, 0x03,
            0x5f, 0xd6,
        ]
    );
    for (challenge, response) in [
        (0, 0x311),
        (1, 0x1000_8000_0000_0311),
        (u64::MAX, 0x2310),
        (0x0123_4567_89ab_cdef, 0x16e5_b4c7_da29_67e6),
    ] {
        assert_eq!(probe::expected_response(challenge), response);
    }
}

#[test]
fn rejects_v1_other_types_bad_fields_corruption_and_wrong_length() {
    let bytes = probe::package_bytes();
    probe::validate(&bytes, 2).unwrap();
    for kind in [0, 1, 3, u32::MAX] {
        assert!(probe::validate(&bytes, kind).is_err());
    }
    for offset in 0..bytes.len() {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(probe::validate(&changed, 2).is_err(), "offset {offset}");
    }
    let mut v1 = bytes;
    v1[4] = 1;
    assert!(probe::validate(&v1, 2).is_err());
    for length in 0..bytes.len() {
        assert!(probe::validate(&bytes[..length], 2).is_err());
    }
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert!(probe::validate(&extended, 2).is_err());
}

fn build_at(path: &Path, compiler: &str) -> nloader_build::Result<probe::ProbeBuildReport> {
    probe::build(&ProbeBuildRequest {
        compiler: compiler.into(),
        output: path.into(),
    })
}

#[test]
fn refuses_existing_output_before_invoking_compiler() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("PROBE.NLB");
    fs::write(&output, b"keep").unwrap();
    assert!(matches!(
        build_at(&output, "missing-compiler"),
        Err(nloader_build::Error::OutputExists(_))
    ));
    assert_eq!(fs::read(output).unwrap(), b"keep");
}

#[test]
fn compiler_failure_leaves_no_formal_output() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("PROBE.NLB");
    assert!(build_at(&output, "missing-compiler").is_err());
    assert!(!output.exists());
}

#[cfg(unix)]
#[test]
fn refuses_dangling_symlink_without_following_it() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("PROBE.NLB");
    let target = directory.path().join("not-created");
    std::os::unix::fs::symlink(&target, &output).unwrap();
    assert!(matches!(
        build_at(&output, "missing-compiler"),
        Err(nloader_build::Error::OutputExists(_))
    ));
    assert!(!target.exists());
}

#[test]
#[ignore = "requires AArch64 clang"]
fn compiled_probe_is_deterministic_and_matches_independent_instructions() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.NLB");
    let second = directory.path().join("second.NLB");
    let first_report = build_at(&first, "clang").unwrap();
    let second_report = build_at(&second, "clang").unwrap();
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    assert_eq!(first_report.sha256, second_report.sha256);
    assert_eq!(fs::read(&first).unwrap(), probe::package_bytes());
    assert!(first_report.diagnostic_only);
}

#[test]
#[ignore = "requires clang"]
fn execution_services_fail_closed_and_preserve_unsafe_allocations() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("test-exec");
    let compilation = std::process::Command::new("clang")
        .args(["-Wall", "-Wextra", "-Werror", "-Os", "-I"])
        .arg(core.join("include"))
        .arg(core.join("exec.c"))
        .arg(core.join("test_exec.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compilation.status.success(),
        "{}",
        String::from_utf8_lossy(&compilation.stderr)
    );
    let run = std::process::Command::new(binary).output().unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(String::from_utf8_lossy(&run.stdout).contains("probe execution tests passed"));
}
