use nloader_build::{build, BuildRequest, BuildSource, Error};
use nloader_firmware::{crc16, FirmwareIdentity, KeyFile, ModuleEdit};
use nloader_profile::{
    sha256, BuildMode, ContainerKind, Memory, MemorySegment, MemorySegmentKind, Profile,
    ServiceFingerprint, Slack, VersionLiteral,
};
use sha1::{Digest, Sha1};
use std::{fs, path::Path};

const XIP_BASE: u64 = 0x1000;
const LINK_OFFSET: u64 = 0x200;
const LINK_BASE: u64 = XIP_BASE + LINK_OFFSET;
/// Room for the whole loader with slack to spare: the synthetic package is
/// here to exercise the build, not to bound core's size, and a window that
/// a new core source outgrows fails as a capacity error far from its cause.
const LINK_BYTES: u64 = 0x20000;
const MODULE_BYTES: u64 = LINK_OFFSET + LINK_BYTES + 0x1000;
const SLACK_END: u64 = XIP_BASE + MODULE_BYTES;

/// A menu-less synthetic package: enough for the marker build and for the
/// refusals that must happen before compilation. The flashable rungs are
/// covered end to end by the menu package test.
fn fixture(directory: &Path) -> (BuildRequest, Vec<u8>) {
    let payload = vec![0; usize::try_from(MODULE_BYTES).unwrap()];
    let mut body = vec![0; 80];
    body[..32].fill(b' ');
    body[32..36].copy_from_slice(&1_u32.to_be_bytes());
    body[36..40].copy_from_slice(&80_u32.to_be_bytes());
    let name = "eg2070_test.bi";
    body[48..48 + name.len()].copy_from_slice(name.as_bytes());
    body[64..68].copy_from_slice(&80_u32.to_be_bytes());
    let module_with_crc = u32::try_from(MODULE_BYTES + 2).unwrap();
    body[68..72].copy_from_slice(&module_with_crc.to_be_bytes());
    body.extend(&payload);
    body.extend(crc16(&payload).to_be_bytes());
    body.extend(crc16(&body).to_be_bytes());
    body.extend([0; 14]);
    let mut digest = Sha1::new_with_prefix(&body);
    digest.update([0; 8]);
    let mut stock = digest.finalize().to_vec();
    stock.extend([0; 12]);
    stock.extend(body);
    // The test's XOR tables are all zero, so the fixture needs no transform.
    let keys = serde_json::json!({"schema":1,"materials":{"legacy-xor":{
        "t1":"00".repeat(256),"t2":"00".repeat(256),"t3":"00".repeat(256),
        "self_check":{"t1":sha256(&[0;256]),"t2":sha256(&[0;256]),"t3":sha256(&[0;256])}
    }},"keys":[{"scheme":"legacy-xor","model":"Z8","firmware":["3.11"],
        "firmware_sha256":{"3.11":sha256(&stock)},"k8":"00".repeat(8),
        "self_check":{"k8":sha256(&[0;8])}}]});
    let mut profile = Profile::draft("Z8", "3.11");
    profile.identity.container = Some(ContainerKind::LegacyXor);
    profile.identity.stock_pkg = Some("synthetic.bin".into());
    profile.identity.eg_module = Some(name.into());
    profile.checks.package_sha256 = Some(sha256(&stock));
    profile.checks.module_sha256 = Some(sha256(&payload));
    profile.memory = Memory {
        xip_base: Some(XIP_BASE),
        module_size: Some(MODULE_BYTES),
        segments: vec![MemorySegment {
            file_offset: 0,
            runtime_start: XIP_BASE,
            size: MODULE_BYTES,
            kind: MemorySegmentKind::Xip,
        }],
        slack: Some(Slack {
            start: LINK_BASE,
            end: SLACK_END,
            require_zero: true,
        }),
        link_base: Some(LINK_BASE),
        link_size: Some(LINK_BYTES),
        ram_pool: None,
        program_budget_blocks: None,
        program_max_resident: None,
        program_arena_bytes: None,
    };
    let firmware = directory.join("synthetic.bin");
    let key_file = directory.join("keys.json");
    let request = BuildRequest {
        profile: directory.join("profile.toml"),
        source: BuildSource::Package {
            firmware: firmware.clone(),
            key_file: key_file.clone(),
        },
        compiler: "clang".into(),
        mode: BuildMode::Marker,
        output: directory.join("result.bin"),
        bundle: None,
    };
    fs::write(&firmware, &stock).unwrap();
    fs::write(&key_file, serde_json::to_vec(&keys).unwrap()).unwrap();
    let text = profile.to_toml().unwrap();
    assert!(!text.contains("evidence"));
    assert!(!text.contains("conflicts"));
    assert_eq!(Profile::from_toml(&text).unwrap(), profile);
    fs::write(&request.profile, text).unwrap();
    (request, stock)
}

#[test]
fn rejects_missing_profile_fields_and_unsupported_modes_before_compilation() {
    let directory = tempfile::tempdir().unwrap();
    let (mut request, _) = fixture(directory.path());
    request.mode = BuildMode::Page;
    assert!(matches!(build(&request), Err(Error::Validation(_))));
    request.mode = BuildMode::Marker;
    fs::write(
        &request.profile,
        Profile::draft("Z8", "3.11").to_toml().unwrap(),
    )
    .unwrap();
    assert!(matches!(build(&request), Err(Error::Validation(_))));
    assert!(!request.output.exists());
}

#[test]
fn flashable_rungs_require_the_menu_page() {
    let directory = tempfile::tempdir().unwrap();
    let (mut request, _) = fixture(directory.path());
    request.compiler = "nloader-no-such-compiler".into();
    // The flashable rungs consist of the Setup entry row and NLoader's page;
    // without them in the profile each is refused before compilation.
    for mode in [BuildMode::HookOnly, BuildMode::Page, BuildMode::LoadOnly] {
        request.mode = mode;
        match build(&request) {
            Err(Error::Validation(report)) => assert!(
                report.issues.iter().any(|issue| issue.field == "menu.page"),
                "{mode}: {report:?}"
            ),
            other => panic!("{mode}: expected a validation failure, got {other:?}"),
        }
        assert_no_outputs(&request);
    }
}

#[test]
fn wrong_stock_or_dirty_slack_never_publishes_outputs() {
    let directory = tempfile::tempdir().unwrap();
    let (request, mut stock) = fixture(directory.path());
    stock[100] ^= 1;
    fs::write(request.source.firmware().unwrap(), &stock).unwrap();
    assert!(matches!(build(&request), Err(Error::Firmware(_))));
    assert!(!request.output.exists());
    assert!(!request.output.with_extension("patch.json").exists());

    let (request, stock) = fixture(directory.path());
    let key = KeyFile::load(request.source.key_file().unwrap())
        .unwrap()
        .for_identity(&FirmwareIdentity {
            model: "Z8".into(),
            firmware: "3.11".into(),
        })
        .unwrap();
    let modified = key
        .pack(
            &stock,
            &[ModuleEdit::Patch {
                module: "eg2070_test.bi".into(),
                offset: usize::try_from(LINK_OFFSET).unwrap(),
                bytes: vec![1],
            }],
        )
        .unwrap();
    let image = key.unpack(&modified).unwrap();
    let module_hash = sha256(image.payload("eg2070_test.bi").unwrap());
    let mut profile = Profile::from_toml(&fs::read_to_string(&request.profile).unwrap()).unwrap();
    profile.checks.package_sha256 = Some(sha256(&modified));
    profile.checks.module_sha256 = Some(module_hash);
    let mut keys: serde_json::Value =
        serde_json::from_slice(&fs::read(request.source.key_file().unwrap()).unwrap()).unwrap();
    keys["keys"][0]["firmware_sha256"]["3.11"] = sha256(&modified).into();
    fs::write(request.source.firmware().unwrap(), modified).unwrap();
    fs::write(
        request.source.key_file().unwrap(),
        serde_json::to_vec(&keys).unwrap(),
    )
    .unwrap();
    fs::write(&request.profile, profile.to_toml().unwrap()).unwrap();
    match build(&request) {
        Err(Error::Validation(report)) => assert!(report
            .issues
            .iter()
            .any(|issue| issue.field == "memory.slack")),
        _ => panic!("dirty declared slack must be rejected"),
    }
    assert!(!request.output.exists());
}

#[test]
#[ignore = "requires clang with AArch64 code generation"]
fn compiles_links_and_verifies_the_complete_marker_package() {
    let directory = tempfile::tempdir().unwrap();
    let (request, stock) = fixture(directory.path());
    assert!(!request.profile.with_extension("report.json").exists());
    let report = build(&request).unwrap();
    assert!(!report.installable);
    let patches: serde_json::Value =
        serde_json::from_slice(&fs::read(&report.manifest).unwrap()).unwrap();
    assert_eq!(patches[0]["site"], LINK_BASE);
    assert_eq!(patches[0]["file_offset"], LINK_OFFSET);
    let key = KeyFile::load(request.source.key_file().unwrap())
        .unwrap()
        .for_identity(&FirmwareIdentity {
            model: "Z8".into(),
            firmware: "3.11".into(),
        })
        .unwrap();
    let output = fs::read(&request.output).unwrap();
    let image = key.unpack(&output).unwrap();
    let module = image.payload("eg2070_test.bi").unwrap();
    let bytes: Vec<u8> = serde_json::from_value(patches[0]["new"].clone()).unwrap();
    let offset = usize::try_from(LINK_OFFSET).unwrap();
    assert_eq!(module.len(), usize::try_from(MODULE_BYTES).unwrap());
    assert_eq!(&module[offset..offset + bytes.len()], bytes.as_slice());
    // The reported entry (NLoader's page entry) is code inside the blob.
    assert!(report.entry >= LINK_BASE && report.entry < LINK_BASE + bytes.len() as u64);
    assert_eq!(report.entry % 4, 0);
    assert!(module[..offset].iter().all(|byte| *byte == 0));
    assert!(module[offset + bytes.len()..].iter().all(|byte| *byte == 0));
    assert!(fs::read(request.source.firmware().unwrap()).unwrap() == stock);
    assert!(matches!(build(&request), Err(Error::OutputExists(_))));
    assert!(fs::read(&request.output).unwrap() == output);
}

#[test]
fn clean_profile_reaches_compilation_without_an_extraction_report() {
    let directory = tempfile::tempdir().unwrap();
    let (mut request, _) = fixture(directory.path());
    request.compiler = "nloader-no-such-compiler".into();
    assert!(!request.profile.with_extension("report.json").exists());
    assert!(matches!(build(&request), Err(Error::Io(_))));
    assert_no_outputs(&request);
}

fn assert_no_outputs(request: &BuildRequest) {
    assert!(!request.output.exists());
    assert!(!request.output.with_extension("patch.json").exists());
    assert!(!request.output.with_extension("build.json").exists());
}

#[test]
fn actual_identity_original_bytes_and_ranges_remain_required() {
    for case in 0..8 {
        let directory = tempfile::tempdir().unwrap();
        let (mut request, _) = fixture(directory.path());
        // A missing compiler makes it observable that rejection happens during
        // input validation, before compilation or output publication.
        request.compiler = "nloader-no-such-compiler".into();
        let mut profile =
            Profile::from_toml(&fs::read_to_string(&request.profile).unwrap()).unwrap();
        let field = match case {
            0 => {
                profile.identity.firmware = "3.10".into();
                "identity"
            }
            1 => {
                profile.checks.package_sha256 = Some("ff".repeat(32));
                "checks.package_sha256"
            }
            2 => {
                profile.checks.module_sha256 = Some("ff".repeat(32));
                "checks.module_sha256"
            }
            3 => {
                profile.services.fs_open = Some(4096);
                profile.service_fingerprints.insert(
                    "fs_open".into(),
                    ServiceFingerprint {
                        eg_off: 0,
                        stock: vec![1, 0, 0, 0],
                    },
                );
                "service_fingerprints.fs_open"
            }
            4 => {
                profile.updater.version_literals.push(VersionLiteral {
                    eg_off: 0,
                    stock: "A".into(),
                    patched: "B".into(),
                });
                "updater.version_literals[0]"
            }
            5 => {
                profile.memory.link_base = Some(SLACK_END);
                "memory.link_base"
            }
            6 => {
                profile.memory.slack.as_mut().unwrap().end = SLACK_END + 1;
                "memory.slack"
            }
            _ => {
                profile.memory.module_size = Some(MODULE_BYTES + 0x1000);
                "memory.module_size"
            }
        };
        fs::write(&request.profile, profile.to_toml().unwrap()).unwrap();
        match build(&request) {
            Err(Error::Firmware(nloader_firmware::Error::KeyIdentity)) if case == 0 => {}
            Err(Error::Validation(report)) => assert!(
                report.issues.iter().any(|issue| issue.field == field),
                "case {case}: {report:?}"
            ),
            other => panic!("case {case}: expected actual-input validation failure, got {other:?}"),
        }
        assert_no_outputs(&request);
    }
}

#[test]
#[ignore = "requires clang with AArch64 code generation"]
fn insufficient_capacity_and_failed_compiler_leave_no_package() {
    let directory = tempfile::tempdir().unwrap();
    let (mut request, _) = fixture(directory.path());
    request.compiler = "nloader-no-such-compiler".into();
    assert!(matches!(build(&request), Err(Error::Io(_))));
    assert!(!request.output.exists());
    request.compiler = "clang".into();
    let mut profile = Profile::from_toml(&fs::read_to_string(&request.profile).unwrap()).unwrap();
    profile.memory.link_size = Some(4);
    fs::write(&request.profile, profile.to_toml().unwrap()).unwrap();
    assert!(matches!(build(&request), Err(Error::Object(_))));
    assert!(!request.output.exists());
    assert!(!request.output.with_extension("build.json").exists());
}
