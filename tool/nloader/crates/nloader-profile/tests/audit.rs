mod common;
use nloader_profile::*;
use std::collections::BTreeMap;

fn fixture() -> Profile {
    let mut profile = Profile::draft("Z8", "3.11");
    profile.identity.container = Some(ContainerKind::LegacyXor);
    profile.identity.stock_pkg = Some("synthetic.bin".into());
    profile.identity.eg_module = Some("synthetic.bi".into());
    profile.checks = Checks {
        package_sha256: Some(sha256(b"synthetic package")),
        module_sha256: Some(sha256(&[0; 512])),
    };
    profile.memory = Memory {
        xip_base: Some(4096),
        module_size: Some(512),
        segments: vec![MemorySegment {
            file_offset: 0,
            runtime_start: 4096,
            size: 512,
            kind: MemorySegmentKind::Xip,
        }],
        slack: Some(Slack {
            start: 4352,
            end: 4608,
            require_zero: true,
        }),
        link_base: Some(4352),
        link_size: Some(256),
        ram_pool: None,
        program_budget_blocks: None,
        program_max_resident: None,
        program_arena_bytes: None,
    };
    profile
}
fn issue(report: &ValidationReport, field: &str, kind: IssueKind) -> bool {
    report
        .issues
        .iter()
        .any(|issue| issue.field == field && issue.kind == kind)
}
#[test]
fn pure_configuration_has_no_audit_fields_and_rejects_old_embedded_records() {
    let profile = fixture();
    assert!(profile.validate(BuildMode::Marker).is_valid());
    let encoded = profile.to_toml().unwrap();
    assert!(!encoded.contains("evidence"));
    assert!(!encoded.contains("conflicts"));
    assert_eq!(Profile::from_toml(&encoded).unwrap(), profile);
    for embedded in ["schema = 1\n[evidence]", "schema = 1\nconflicts = []"] {
        assert!(Profile::from_toml(embedded).is_err());
    }
}
#[test]
fn extraction_requires_provenance_even_when_configuration_is_valid() {
    let profile = fixture();
    let evidence = common::evidence_for(&profile);
    assert!(profile
        .validate_extraction(BuildMode::Marker, &evidence, &[])
        .is_valid());
    let report = profile.validate_extraction(BuildMode::Marker, &BTreeMap::new(), &[]);
    for field in [
        "identity.model",
        "identity.firmware",
        "memory.segments",
        "memory.slack",
        "memory.link_base",
        "memory.link_size",
    ] {
        assert!(issue(
            &report,
            &format!("evidence.{field}"),
            IssueKind::Missing
        ));
    }
    assert!(profile.validate(BuildMode::Marker).is_valid());
}
#[test]
fn extraction_checks_identity_hash_confirmation_and_module_binding() {
    let profile = fixture();
    let evidence = common::evidence_for(&profile);
    for (variant, kind) in [
        (0, IssueKind::IdentityMismatch),
        (1, IssueKind::FingerprintMismatch),
        (2, IssueKind::Unconfirmed),
        (3, IssueKind::Missing),
    ] {
        let mut changed = evidence.clone();
        let record = changed.get_mut("memory.slack").unwrap();
        match variant {
            0 => record.firmware = "3.01".into(),
            1 => record.module_sha256 = Some("0".repeat(64)),
            2 => record.status = EvidenceStatus::Unconfirmed,
            _ => record.module_sha256 = None,
        }
        assert!(issue(
            &profile.validate_extraction(BuildMode::Marker, &changed, &[]),
            "evidence.memory.slack",
            kind
        ));
    }
}
#[test]
fn extraction_rejects_false_device_claims_and_malformed_source_records() {
    let profile = fixture();
    let evidence = common::evidence_for(&profile);
    for (variant, kind) in [
        (0, IssueKind::Invalid),
        (1, IssueKind::Missing),
        (2, IssueKind::Invalid),
        (3, IssueKind::Missing),
    ] {
        let mut changed = evidence.clone();
        let record = changed.get_mut("identity.model").unwrap();
        match variant {
            0 => record.status = EvidenceStatus::DeviceVerified,
            1 => record.fragment_sha256 = None,
            2 => record.fragment_sha256 = Some("not-a-hash".into()),
            _ => record.rule.clear(),
        }
        assert!(issue(
            &profile.validate_extraction(BuildMode::Marker, &changed, &[]),
            "evidence.identity.model",
            kind
        ));
    }
}
#[test]
fn unresolved_external_candidates_block_extraction_without_mutating_configuration() {
    let profile = fixture();
    let evidence = common::evidence_for(&profile);
    let conflicts = [Conflict {
        field: "memory.xip_base".into(),
        candidates: vec!["1".into(), "2".into()],
        reason: "not unique".into(),
    }];
    let original = profile.to_toml().unwrap();
    assert!(issue(
        &profile.validate_extraction(BuildMode::Marker, &evidence, &conflicts),
        "memory.xip_base",
        IssueKind::Conflict
    ));
    assert!(profile.validate(BuildMode::Marker).is_valid());
    assert_eq!(profile.to_toml().unwrap(), original);
}
#[test]
fn optional_addresses_require_their_evidence_only_during_extraction() {
    let mut profile = fixture();
    let evidence = common::evidence_for(&profile);
    profile.services.fs_open = Some(4100);
    profile.memory.ram_pool = Some(AddressRange {
        start: 65536,
        end: 66048,
    });
    profile.updater.version_literals.push(VersionLiteral {
        eg_off: 8,
        stock: "ABCD".into(),
        patched: "WXYZ".into(),
    });
    assert!(profile.validate(BuildMode::Marker).is_valid());
    let report = profile.validate_extraction(BuildMode::Marker, &evidence, &[]);
    for field in [
        "services.fs_open",
        "memory.ram_pool",
        "updater.version_literals[0]",
    ] {
        assert!(issue(
            &report,
            &format!("evidence.{field}"),
            IssueKind::Missing
        ));
    }
}
#[test]
fn valid_evidence_does_not_override_configuration_bounds() {
    let mut profile = fixture();
    let evidence = common::evidence_for(&profile);
    profile.memory.link_size = Some(257);
    assert!(issue(
        &profile.validate_extraction(BuildMode::Marker, &evidence, &[]),
        "memory.link_base",
        IssueKind::OutOfBounds
    ));
}
