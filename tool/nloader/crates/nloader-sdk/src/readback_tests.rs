use super::*;
use crate as sdk;
use fixture::REQUESTS;
#[path = "readback_fixture.rs"]
mod fixture;

#[test]
fn pre_and_post_use_validated_packages_and_preserve_differences() {
    let d = tempfile::tempdir().unwrap();
    let (profile, eg) = fixture::files(d.path());
    let pre = ReadbackPlan::prepare(
        &profile,
        &d.path().join("stock.bin"),
        &d.path().join("key.json"),
        None,
    )
    .unwrap();
    let check = pre.replay(fixture::capture(&profile, &eg, false, false));
    assert!(check.matched());
    assert!(check.report.replayed);
    assert_eq!(check.report.origin, camera::CaptureOrigin::SyntheticFixture);
    let mut changed = eg.clone();
    let offset = profile
        .memory
        .address_to_offset(REQUESTS[0].0 + 16, 1)
        .unwrap() as usize;
    changed[offset] ^= 1;
    let raw = fixture::package(&changed, 1);
    let path = d.path().join("candidate.bin");
    fs::write(&path, &raw).unwrap();
    let post = ReadbackPlan::prepare(
        &profile,
        &d.path().join("stock.bin"),
        &d.path().join("key.json"),
        Some(Candidate {
            package: &path,
            package_sha256: &profile::sha256(&raw),
            eg_sha256: &profile::sha256(&changed),
        }),
    )
    .unwrap();
    let capture = fixture::capture(&profile, &changed, false, false);
    let check = pre.replay(capture.clone());
    assert_eq!(check.report.status, Status::BytesMismatch);
    assert!(check.report.reason.is_none());
    assert_eq!(check.report.comparisons[0].differences[0].offset, 16);
    assert!(post.replay(capture).matched());
    assert_eq!(
        post.replay(fixture::capture(&profile, &eg, false, false))
            .report
            .status,
        Status::BytesMismatch
    );
    // A legitimate runtime change in an adjacent byte remains an exact failure.
    changed[offset - 1] ^= 1;
    let check = post.replay(fixture::capture(&profile, &changed, false, false));
    assert_eq!(check.report.status, Status::BytesMismatch);
    assert_eq!(check.report.comparisons[0].differences[0].offset, 15);
    assert_eq!(check.report.comparisons[0].site_matched, Some(true));
    assert!(!check.report.comparisons[0].neighbors_matched);
    assert_eq!(
        check.report.comparisons[0].differences[0].domain,
        Domain::ProtectedNeighbor
    );
}

#[test]
fn invalid_capture_or_cleanup_never_becomes_a_byte_mismatch_or_success() {
    let d = tempfile::tempdir().unwrap();
    let (profile, eg) = fixture::files(d.path());
    let plan = ReadbackPlan::prepare(
        &profile,
        &d.path().join("stock.bin"),
        &d.path().join("key.json"),
        None,
    )
    .unwrap();
    for capture in [
        fixture::capture(&profile, &eg, true, false),
        fixture::capture(&profile, &eg, false, true),
    ] {
        let check = plan.replay(capture);
        assert_eq!(check.report.status, Status::CaptureFailed);
        assert!(!check.matched());
        assert!(check.report.comparisons.is_empty());
        let out = d
            .path()
            .join(format!("failed{}.json", check.capture.segments.len()));
        let paths = check.write_outputs(&out).unwrap();
        let raw: camera::MemoryCapture =
            serde_json::from_slice(&fs::read(paths.snapshot).unwrap()).unwrap();
        assert_eq!(raw, check.capture);
    }
    let capture = fixture::capture(&profile, &eg, false, false);
    for case in 0..7 {
        let mut bad = capture.clone();
        match case {
            0 => bad.segments[0].repeat_sha256 = "bad".into(),
            1 => bad.identity.as_mut().unwrap().device_version = "V3.12".into(),
            2 => bad.requests[0].address += 1,
            3 => bad.cleanup.interface_released = false,
            4 => bad.transactions[0].reply.as_mut().unwrap().response_code = 0x2002,
            5 => bad.transactions[0].reply.as_mut().unwrap().parameters = vec![0x2001],
            _ => bad.transactions[0].reply.as_mut().unwrap().data[0] ^= 1,
        };
        assert_eq!(plan.replay(bad).report.status, Status::CaptureFailed);
    }
}

#[test]
fn unaccepted_inputs_and_protected_candidate_changes_are_refused() {
    let d = tempfile::tempdir().unwrap();
    let (profile, eg) = fixture::files(d.path());
    let path = d.path().join("candidate.bin");
    let stock = d.path().join("stock.bin");
    let key = d.path().join("key.json");
    for case in 0..4 {
        let mut eg = eg.clone();
        let offset = profile
            .memory
            .address_to_offset(REQUESTS[2].0 + 80, 1)
            .unwrap() as usize;
        if case == 0 {
            eg[offset] = 1;
        }
        let raw = fixture::package(&eg, if case == 1 { 2 } else { 1 });
        fs::write(&path, &raw).unwrap();
        let package_sha = if case == 2 {
            "00".repeat(32)
        } else {
            profile::sha256(&raw)
        };
        let eg_sha = if case == 3 {
            "00".repeat(32)
        } else {
            profile::sha256(&eg)
        };
        assert!(ReadbackPlan::prepare(
            &profile,
            &stock,
            &key,
            Some(Candidate {
                package: &path,
                package_sha256: &package_sha,
                eg_sha256: &eg_sha
            })
        )
        .is_err());
    }
    for case in 0..4 {
        let mut bad = profile.clone();
        match case {
            0 => bad.capture.as_mut().unwrap().requests[0].address = 0x30000000,
            1 => bad.capture.as_mut().unwrap().requests[0].length += 1,
            2 => bad.menu.page.as_mut().unwrap().window_id = 1492,
            _ => bad.capture.as_mut().unwrap().requests.reverse(),
        };
        assert!(ReadbackPlan::prepare(&bad, &stock, &key, None).is_err());
    }
}

#[test]
fn output_collision_and_dangling_symlink_preserve_original_data() {
    let d = tempfile::tempdir().unwrap();
    let (profile, eg) = fixture::files(d.path());
    let plan = ReadbackPlan::prepare(
        &profile,
        &d.path().join("stock.bin"),
        &d.path().join("key.json"),
        None,
    )
    .unwrap();
    let check = plan.replay(fixture::capture(&profile, &eg, false, false));
    let out = d.path().join("check.json");
    fs::write(out.with_extension("snapshot.json"), b"keep snapshot").unwrap();
    assert!(check.write_outputs(&out).is_err());
    assert!(!out.exists());
    assert_eq!(
        fs::read(out.with_extension("snapshot.json")).unwrap(),
        b"keep snapshot"
    );
    fs::remove_file(out.with_extension("snapshot.json")).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(d.path().join("missing"), &out).unwrap();
        assert!(check.write_outputs(&out).is_err());
        assert!(fs::symlink_metadata(&out).is_ok());
        assert!(!out.with_extension("snapshot.json").exists());
    }
}

#[test]
#[ignore = "requires local official stock package, key and manually maintained profile; never accesses a device"]
fn local_stock_readback_plan_without_device() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let mut profile = crate::read_profile(&root.join("profiles/z8/v3_11.toml")).unwrap();
    let window = profile.menu.window_address(1493).unwrap();
    let native =
        fs::read(root.join("firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi")).unwrap();
    let battery = profile.menu.window_address(729).unwrap();
    let offset = profile.memory.address_to_offset(battery + 40, 8).unwrap() as usize;
    let handlers = u64::from_le_bytes(native[offset..offset + 8].try_into().unwrap());
    let requests = [
        (profile.menu.setup.as_ref().unwrap().page_address, 80),
        (window - 96, 192),
        (profile.menu.page.as_ref().unwrap().page_record, 192),
        (handlers, 40),
    ];
    profile.capture.as_mut().unwrap().requests = requests
        .iter()
        .enumerate()
        .map(|(index, (address, length))| profile::CaptureRequest {
            label: format!("reviewed{index}"),
            address: *address,
            length: *length,
        })
        .collect();
    let plan = ReadbackPlan::prepare(
        &profile,
        &root.join("firmware/stock/Z_8_0311.bin"),
        &root.join("tool/nloader/keys/local.json"),
        None,
    )
    .unwrap();
    assert_eq!(plan.expected.iter().map(Vec::len).sum::<usize>(), 504);
    assert_eq!(plan.phase, Phase::Pre);
    assert!(plan.candidate_sha256.is_none());
}
