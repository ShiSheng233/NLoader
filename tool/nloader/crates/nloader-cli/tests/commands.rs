use std::{fs, process::Command};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nloader"))
}

#[test]
fn memory_capture_requires_image_inputs_before_any_camera_access() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("profile.toml");
    let result = command()
        .args([
            "profile",
            "discover",
            "--camera",
            "not-a-device",
            "--memory",
            "--out",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(!output.exists());
}

#[test]
fn menu_auto_capture_is_not_offered() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("profile.toml");
    let result = command()
        .args([
            "profile",
            "discover",
            "--camera",
            "not-a-device",
            "--menu",
            "--firmware",
            "missing-firmware.bin",
            "--key-file",
            "missing-keys.json",
            "--out",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(!output.exists());
}

#[test]
fn firmware_validation_requires_a_key_file_and_fails_on_missing_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile.toml");
    fs::write(
        &profile,
        "schema = 1\n[identity]\nmodel = \"Z8\"\nfirmware = \"3.11\"\neg_module = \"eg.bi\"\n",
    )
    .unwrap();
    let result = command()
        .args([
            "profile",
            "validate",
            "--mode",
            "marker",
            "--firmware",
            "missing.bin",
            "--profile",
        ])
        .arg(&profile)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    let result = command()
        .args([
            "profile",
            "validate",
            "--mode",
            "marker",
            "--firmware",
            "missing.bin",
            "--key-file",
            "missing-keys.json",
            "--profile",
        ])
        .arg(&profile)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("error:"));
}

#[test]
fn marker_build_rejects_draft_without_publishing_output() {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile.toml");
    fs::write(
        &profile,
        "schema = 1\n[identity]\nmodel = 'Z8'\nfirmware = '3.11'\n",
    )
    .unwrap();
    let output = directory.path().join("result.bin");
    let result = command()
        .args(["build", "--profile"])
        .arg(&profile)
        .arg("--firmware")
        .arg(directory.path().join("missing.bin"))
        .arg("--key-file")
        .arg(directory.path().join("missing.json"))
        .args(["--mode", "marker", "--out"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("profile validation failed"));
    assert!(!output.exists());
    assert!(!output.with_extension("patch.json").exists());
}

#[test]
fn key_recovery_refuses_existing_output_before_reading_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("local.json");
    fs::write(&output, b"preserve existing material").unwrap();
    let result = command()
        .args(["keys", "recover", "--firmware"])
        .arg(directory.path().join("missing.bin"))
        .args(["--model", "Z8", "--firmware-version", "3.11", "--out"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("output already exists"));
    assert_eq!(fs::read(&output).unwrap(), b"preserve existing material");
}

#[test]
fn incomplete_profile_reports_missing_fields_and_fails() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("draft.toml");
    fs::write(
        &path,
        "schema = 1\n[identity]\nmodel = 'Z8'\nfirmware = '3.11'\n",
    )
    .unwrap();
    let result = command()
        .args(["profile", "validate", "--profile"])
        .arg(path)
        .args(["--mode", "marker"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| { issue["field"] == "checks.package_sha256" && issue["kind"] == "missing" }));
}

#[test]
fn malformed_profile_and_unknown_mode_fail() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invalid.toml");
    fs::write(&path, "[invalid").unwrap();
    for mode in ["marker", "guess"] {
        let result = command()
            .args(["profile", "validate", "--profile"])
            .arg(&path)
            .args(["--mode", mode])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!result.stderr.is_empty());
    }
}

#[test]
fn unpack_without_keys_leaves_no_output() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("out");
    let result = command()
        .args(["unpack", "--firmware"])
        .arg(directory.path().join("missing.bin"))
        .arg("--key-file")
        .arg(directory.path().join("missing.json"))
        .args(["--model", "Z8", "--firmware-version", "3.11", "--out"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
}

#[test]
fn program_without_inputs_fails_and_leaves_no_output() {
    let directory = tempfile::tempdir().unwrap();
    let declaration = directory.path().join("hello.json");
    fs::write(
        &declaration,
        r#"{"id":"hello","kind":"foreground","display_name":"Hello","file":"APPS/HELLO.NLB","min_abi":2}"#,
    )
    .unwrap();
    let output = directory.path().join("HELLO.NLB");
    let result = command()
        .args(["program", "--decl"])
        .arg(&declaration)
        .arg("--out")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("source or object"));
    assert!(!output.exists());
}

#[test]
fn program_rejects_malformed_and_unknown_kind_declarations() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("HELLO.NLB");
    for content in [
        "{not json",
        r#"{"id":"hello","kind":"diagnostic","display_name":"Hello","file":"APPS/HELLO.NLB","min_abi":2}"#,
    ] {
        let declaration = directory.path().join("hello.json");
        fs::write(&declaration, content).unwrap();
        let result = command()
            .args(["program", "--decl"])
            .arg(&declaration)
            .arg("--out")
            .arg(&output)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!output.exists());
    }
}

use nloader_sdk as sdk;
#[path = "../../nloader-sdk/src/readback_fixture.rs"]
mod readback_fixture;

fn readback_command(directory: &std::path::Path, phase: &str, out: &std::path::Path) -> Command {
    let mut command = command();
    command
        .args(["flash-check", "--phase", phase, "--profile"])
        .arg(directory.join("profile.toml"))
        .arg("--firmware")
        .arg(directory.join("stock.bin"))
        .arg("--key-file")
        .arg(directory.join("key.json"))
        .arg("--snapshot")
        .arg(directory.join("capture.json"))
        .arg("--out")
        .arg(out);
    command
}

#[test]
fn flash_check_requires_post_pins_and_exactly_one_read_source() {
    for source in [
        vec![],
        vec!["--camera", "not-a-device", "--snapshot", "missing.json"],
        vec!["--snapshot", "missing.json"],
    ] {
        let directory = tempfile::tempdir().unwrap();
        let out = directory.path().join("check.json");
        let result = command()
            .args([
                "flash-check",
                "--phase",
                "post",
                "--profile",
                "missing.toml",
                "--firmware",
                "missing.bin",
                "--key-file",
                "missing.key",
                "--out",
            ])
            .arg(&out)
            .args(source)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(!out.exists());
        assert!(!out.with_extension("snapshot.json").exists());
    }
}

#[test]
fn flash_check_output_preflight_preserves_existing_without_input_or_device_access() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("check.json");
    fs::write(&out, b"keep report").unwrap();
    let result = command()
        .args([
            "flash-check",
            "--phase",
            "pre",
            "--profile",
            "missing.toml",
            "--firmware",
            "missing.bin",
            "--key-file",
            "missing.key",
            "--camera",
            "not-a-device",
            "--out",
        ])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("output already exists"));
    assert_eq!(fs::read(out).unwrap(), b"keep report");
}

#[test]
fn flash_check_offline_pre_post_and_failed_capture_have_distinct_outputs() {
    let directory = tempfile::tempdir().unwrap();
    let (profile, eg) = readback_fixture::files(directory.path());
    let mut changed = eg.clone();
    let offset = profile
        .memory
        .address_to_offset(readback_fixture::REQUESTS[0].0 + 16, 1)
        .unwrap() as usize;
    changed[offset] ^= 1;
    let package = readback_fixture::package(&changed, 1);
    fs::write(directory.path().join("candidate.bin"), &package).unwrap();
    for (name, phase, observed, unstable, expected_status, code) in [
        ("pre", "pre", &eg, false, "matched", 0),
        ("diff", "pre", &changed, false, "bytes_mismatch", 1),
        ("post", "post", &changed, false, "matched", 0),
        ("failed", "pre", &eg, true, "capture_failed", 1),
    ] {
        let capture = readback_fixture::capture(&profile, observed, unstable, false);
        fs::write(
            directory.path().join("capture.json"),
            serde_json::to_vec(&capture).unwrap(),
        )
        .unwrap();
        let out = directory.path().join(format!("{name}.json"));
        let mut command = readback_command(directory.path(), phase, &out);
        if phase == "post" {
            command
                .arg("--candidate")
                .arg(directory.path().join("candidate.bin"))
                .arg("--candidate-sha256")
                .arg(sdk::profile::sha256(&package))
                .arg("--candidate-eg-sha256")
                .arg(sdk::profile::sha256(&changed));
        }
        let result = command.output().unwrap();
        assert_eq!(
            result.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        assert_eq!(report["status"], expected_status);
        assert_eq!(report["replayed"], true);
        let raw: sdk::camera::MemoryCapture =
            serde_json::from_slice(&fs::read(out.with_extension("snapshot.json")).unwrap())
                .unwrap();
        assert_eq!(raw, capture);
    }
    let out = directory.path().join("bad-pins.json");
    let result = readback_command(directory.path(), "post", &out)
        .arg("--candidate")
        .arg(directory.path().join("candidate.bin"))
        .arg("--candidate-sha256")
        .arg("00".repeat(32))
        .arg("--candidate-eg-sha256")
        .arg(sdk::profile::sha256(&changed))
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(!out.exists());
    assert!(!out.with_extension("snapshot.json").exists());
}

#[test]
fn successful_identity_replay_never_publishes_a_toml_profile() {
    let d = tempfile::tempdir().unwrap();
    let (profile, eg) = readback_fixture::files(d.path());
    let capture = readback_fixture::capture(&profile, &eg, false, false);
    let snapshot = sdk::camera::CameraSnapshot::from_raw(
        capture.device,
        capture.raw_device_info,
        sdk::camera::CaptureOrigin::SyntheticFixture,
        sdk::camera::CleanupReport {
            interface_released: true,
            maintenance_mode_entered: false,
            session_opened: false,
        },
    )
    .unwrap();
    let source = d.path().join("identity.json");
    fs::write(&source, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let out = d.path().join("discovery.toml");
    let result = command()
        .args(["profile", "replay", "--snapshot"])
        .arg(source)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!out.exists());
    assert!(out.with_extension("report.json").exists());
    assert!(out.with_extension("snapshot.json").exists());
    let paths: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(paths["profile"].is_null());
}

#[test]
fn discovery_and_replay_refuse_each_output_collision_before_reading_inputs() {
    for mode in ["discover", "replay"] {
        for sidecar in [None, Some("report.json"), Some("snapshot.json")] {
            let d = tempfile::tempdir().unwrap();
            let out = d.path().join("evidence.capture");
            let occupied =
                sidecar.map_or_else(|| out.clone(), |extension| out.with_extension(extension));
            fs::write(&occupied, b"keep existing").unwrap();
            let mut cmd = command();
            cmd.args(["profile", mode, "--out"]).arg(&out);
            if mode == "discover" {
                cmd.args(["--camera", "not-a-device"]);
            } else {
                cmd.args(["--snapshot", "missing.json"]);
            }
            let result = cmd.output().unwrap();
            assert_eq!(result.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&result.stderr).contains("existing discovery output"));
            assert_eq!(fs::read(&occupied).unwrap(), b"keep existing");
        }
    }
    #[cfg(unix)]
    {
        let d = tempfile::tempdir().unwrap();
        let out = d.path().join("evidence.capture");
        std::os::unix::fs::symlink(d.path().join("missing"), &out).unwrap();
        let result = command()
            .args(["profile", "discover", "--camera", "not-a-device", "--out"])
            .arg(&out)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&result.stderr).contains("existing discovery output"));
        assert!(fs::symlink_metadata(&out).is_ok());
    }
}

#[test]
fn runtime_trace_offers_no_live_camera_option_and_preflights_existing_output() {
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("trace");
    fs::write(&out, b"keep").unwrap();
    let result = command()
        .args([
            "runtime-trace",
            "--layout-object",
            "missing.o",
            "--layout-sha256",
            "bad",
            "--expectations",
            "missing.json",
            "--snapshot",
            "missing-snapshot.json",
            "--out",
        ])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("output already exists"));
    assert_eq!(fs::read(&out).unwrap(), b"keep");
    let result = command()
        .args(["runtime-trace", "--camera", "not-a-device"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
}

#[test]
fn runtime_trace_invalid_inputs_keep_refusal_and_provided_raw_bytes() {
    let d = tempfile::tempdir().unwrap();
    let object = d.path().join("bad.o");
    fs::write(&object, b"bad ELF").unwrap();
    let oracle = d.path().join("oracle.json");
    fs::write(&oracle, b"{}").unwrap();
    let qemu = d.path().join("qemu.json");
    fs::write(&qemu, b"{}").unwrap();
    let raw = d.path().join("runtime.bin");
    fs::write(&raw, b"provided bytes").unwrap();
    let out = d.path().join("refused");
    let result = command()
        .arg("runtime-trace")
        .arg("--layout-object")
        .arg(&object)
        .arg("--layout-sha256")
        .arg(sdk::profile::sha256(b"bad ELF"))
        .arg("--expectations")
        .arg(oracle)
        .arg("--qemu-result")
        .arg(qemu)
        .arg("--runtime")
        .arg(raw)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "refused");
    assert_eq!(report["physical_fresh"], false);
    assert_eq!(
        fs::read(out.join("provided-raw-0.bin")).unwrap(),
        b"provided bytes"
    );
}

#[test]
#[ignore = "requires Clang AArch64 for independent geometry; uses only supplied synthetic files"]
fn runtime_trace_qemu_adapter_refusals_retain_result_runtime_and_pool() {
    let d = tempfile::tempdir().unwrap();
    let profile = d.path().join("profile.toml");
    fs::write(
        &profile,
        "schema=2\n[identity]\nmodel='Z8'\nfirmware='3.11'\n[storage]\nroot='B:\\NLOADER\\'\n",
    )
    .unwrap();
    let layout_dir = d.path().join("layout");
    let built = command()
        .args(["runtime-layout", "--mode", "load-only", "--profile"])
        .arg(&profile)
        .arg("--out")
        .arg(&layout_dir)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let object = layout_dir.join("runtime-layout.o");
    let object_bytes = fs::read(&object).unwrap();
    let object_sha = sdk::profile::sha256(&object_bytes);
    let layout = sdk::build::layout::inspect(&object_bytes).unwrap();
    let oracle = d.path().join("oracle.json");
    fs::write(&oracle,serde_json::to_vec(&serde_json::json!({"schema":1,"candidate_eg_sha256":"12".repeat(32),"proof_reference":"synthetic test expectations","worker_name":"NLOADER","callback":4096,"services":8192,"private_services":null})).unwrap()).unwrap();
    let raw = vec![7u8; layout.runtime_bytes];
    let pool = vec![9u8; 32];
    let raw_path = d.path().join("runtime.bin");
    let pool_path = d.path().join("pool.bin");
    fs::write(&raw_path, &raw).unwrap();
    fs::write(&pool_path, &pool).unwrap();
    for (label, names) in [
        (
            "multiple",
            vec![serde_json::json!({"registry_id":27,"address":"0x3000"}); 2],
        ),
        (
            "nonmatch",
            vec![serde_json::json!({"registry_id":28,"address":"0x3008"})],
        ),
        (
            "maximum",
            vec![serde_json::json!({"registry_id":27,"address":"0x3000"}); 768],
        ),
    ] {
        let result = serde_json::json!({"runtime_snapshot":{"found":true,"registry_id":27,"address":"0x3000","bytes":raw.len(),"snapshot_sha256":sdk::profile::sha256(&raw),"named_candidates":names},"followed_snapshot":{"bytes":pool.len(),"snapshot_sha256":sdk::profile::sha256(&pool),"address":"0x8000"}});
        let input = serde_json::to_vec(&result).unwrap();
        let input_path = d.path().join(format!("{label}.json"));
        fs::write(&input_path, &input).unwrap();
        let out = d.path().join(label);
        let result = command()
            .arg("runtime-trace")
            .arg("--layout-object")
            .arg(&object)
            .arg("--layout-sha256")
            .arg(&object_sha)
            .arg("--expectations")
            .arg(&oracle)
            .arg("--qemu-result")
            .arg(&input_path)
            .arg("--runtime")
            .arg(&raw_path)
            .arg("--pool")
            .arg(&pool_path)
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(out.join("report.json")).unwrap()).unwrap();
        assert_eq!(report["status"], "refused");
        assert_eq!(report["physical_fresh"], false);
        assert!(report["reason"]
            .as_str()
            .unwrap()
            .contains(if label == "nonmatch" {
                "does not match"
            } else {
                "ambiguous"
            }));
        let refs: serde_json::Value =
            serde_json::from_slice(&fs::read(out.join("provided-sources.json")).unwrap()).unwrap();
        for (role, expected) in [("qemu_result", &input), ("runtime", &raw), ("pool", &pool)] {
            let reference = refs
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["role"] == role)
                .unwrap();
            let filename = reference["retained"].as_str().unwrap();
            assert_eq!(fs::read(out.join(filename)).unwrap(), *expected);
            assert_eq!(reference["sha256"], sdk::profile::sha256(expected));
        }
    }
}
