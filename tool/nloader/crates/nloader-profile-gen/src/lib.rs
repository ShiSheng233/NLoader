//! Deterministic, evidence-bound discovery. Research records are development
//! references, never runtime inputs. Missing capabilities remain unavailable.
mod capture;
mod image;
mod slot;
pub use capture::{
    discover_memory_with_firmware, from_memory_capture_with_firmware, memory_requests,
    MemoryComparison, MemoryCrossCheck,
};
pub use image::{
    discover_with_firmware, from_snapshot_with_firmware, FirmwareModuleReport,
    FirmwareSupplementReport,
};
use nloader_camera::{CameraSnapshot, CaptureOrigin};
use nloader_profile::{BuildMode, Conflict, Evidence, EvidenceSource, EvidenceStatus, Profile};
use serde::{Deserialize, Serialize};
pub use slot::{MarkerSlot, SlotEvidenceFragment};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub const RULE_VERSION: &str = "identity-only-v1";
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Camera(#[from] nloader_camera::Error),
    #[error(transparent)]
    Firmware(#[from] nloader_firmware::Error),
    #[error("firmware supplement rejected: {0}")]
    FirmwareMismatch(String),
    #[error(transparent)]
    Profile(#[from] nloader_profile::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("refusing to replace existing discovery output: {0}")]
    Exists(PathBuf),
}

#[derive(Debug, Clone, Serialize)]
pub struct MissingField {
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryReport {
    pub schema: u32,
    pub rule_version: String,
    pub replayed_snapshot: bool,
    pub origin: CaptureOrigin,
    pub device_id: String,
    pub raw_device_info_sha256: String,
    pub raw_device_info_length: usize,
    pub build_ready: bool,
    pub evidence: BTreeMap<String, Evidence>,
    pub conflicts: Vec<Conflict>,
    pub validation_mode: BuildMode,
    pub missing: Vec<MissingField>,
    pub validation: serde_json::Value,
    pub notes: Vec<String>,
    pub firmware: Option<FirmwareSupplementReport>,
    pub memory: Option<MemoryCrossCheck>,
}

impl DiscoveryReport {
    /// Indicates successful acquisition and the requested image comparison,
    /// not completeness of a configuration or proof of camera behavior.
    pub fn collection_succeeded(&self) -> bool {
        self.conflicts.is_empty()
            && self.memory.as_ref().is_none_or(|memory| {
                memory.evidence_valid
                    && memory.capture_complete
                    && memory.matches_image == Some(true)
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DiscoverySnapshot {
    Identity(CameraSnapshot),
    Memory(nloader_camera::MemoryCapture),
}

#[derive(Debug)]
pub struct Discovery {
    pub profile: Profile,
    pub report: DiscoveryReport,
    pub snapshot: DiscoverySnapshot,
}

/// Reads only the selected device's identity. Unsupported memory collection is
/// reported explicitly, including for the first target Z8 C3.11.
pub fn discover(selector: &str) -> Result<Discovery> {
    generate(nloader_camera::capture_identity(selector)?, false)
}

/// Replays the exact bytes in a previously recorded or synthetic snapshot;
/// replay is labelled separately from a new physical device capture.
pub fn from_snapshot(snapshot: CameraSnapshot) -> Result<Discovery> {
    generate(snapshot, true)
}

fn generate(snapshot: CameraSnapshot, replay: bool) -> Result<Discovery> {
    snapshot.validate()?;
    let (profile, report) = generate_parts(
        Some(&snapshot.device_info),
        &snapshot.device.id,
        snapshot.origin,
        &snapshot.raw_device_info,
        replay,
    )?;
    Ok(Discovery {
        profile,
        report,
        snapshot: DiscoverySnapshot::Identity(snapshot),
    })
}

fn generate_parts(
    info: Option<&nloader_camera::DeviceInfo>,
    device_id: &str,
    origin: CaptureOrigin,
    raw: &[u8],
    replay: bool,
) -> Result<(Profile, DiscoveryReport)> {
    let raw_model = info.map_or("", |info| info.model.as_str());
    let raw_firmware = info.map_or("", |info| info.device_version.as_str());
    let model = match raw_model {
        "Z 8" => "Z8",
        other => other,
    };
    // The reference transport reports e.g. V3.11. Retain the complete original
    // string in DeviceInfo; only the profile identity removes this prefix.
    let firmware = raw_firmware.strip_prefix('V').unwrap_or(raw_firmware);
    let profile = Profile::draft(model, firmware);
    let mut evidence = Evidence::device_read(
        model,
        firmware,
        RULE_VERSION,
        nloader_camera::fingerprint(raw),
    );
    evidence.note = "GetDeviceInfo identity only; does not verify module identity, memory layout, or firmware behavior".into();
    if origin == CaptureOrigin::SyntheticFixture {
        evidence.source = EvidenceSource::Snapshot;
    }
    if origin == CaptureOrigin::SyntheticFixture || info.is_none() {
        evidence.status = EvidenceStatus::Unconfirmed;
    }
    let evidence = BTreeMap::from([
        ("identity.model".into(), evidence.clone()),
        ("identity.firmware".into(), evidence),
    ]);
    let conflicts = Vec::new();
    let validation = profile.validate_extraction(BuildMode::Marker, &evidence, &conflicts);
    let target = model == "Z8" && firmware == "3.11";
    let rule_reason = if target {
        "Z8 C3.11 memory collection and structure-identification rules are not implemented or verified; C3.01 and other models are not substitutes"
    } else {
        "no memory collection or structure-identification rule is implemented for this model and firmware"
    };
    let missing = [
        ("collection.memory", rule_reason),
        (
            "collection.restricted_firmware",
            "no verified restricted-region read path or matching image cross-check is implemented",
        ),
        (
            "checks.package_sha256",
            "GetDeviceInfo cannot establish official firmware package identity",
        ),
        (
            "checks.module_sha256",
            "no firmware module bytes have been collected",
        ),
        (
            "memory",
            "XIP, free firmware space, link address and RAM ownership are unknown",
        ),
        (
            "services",
            "no supported service-identification rule has run",
        ),
        (
            "menu",
            "menu records are written manually from reviewed analysis; the generator does not collect them",
        ),
        ("abi", "calling conventions require separate evidence"),
        (
            "updater",
            "update behavior and version fields have not been verified",
        ),
    ]
    .into_iter()
    .map(|(field, reason)| MissingField {
        field: field.into(),
        reason: reason.into(),
    })
    .collect();
    let report = DiscoveryReport {
        schema: 1, rule_version: RULE_VERSION.into(), replayed_snapshot: replay,
        origin, device_id: device_id.into(),
        raw_device_info_sha256: nloader_camera::fingerprint(raw), raw_device_info_length: raw.len(),
        build_ready: false, validation_mode: BuildMode::Marker, missing, firmware: None, memory: None,
        validation: serde_json::to_value(validation)?, evidence, conflicts,
        notes: vec![
            "identity-only capture does not open a PTP session or change camera maintenance mode".into(),
            "optional menu, graphics, input, configuration and boot capabilities remain unsupported".into(),
            "raw DeviceInfo, supported operation codes and USB cleanup results are retained in the snapshot".into(),
            "replay preserves the recorded evidence origin and is not a new device validation".into(),
        ],
    };
    Ok((profile, report))
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputPaths {
    /// Retained for callers that inspect earlier output sets. Discovery never
    /// publishes a profile, so this is always `None` for newly written outputs.
    pub profile: Option<PathBuf>,
    pub report: PathBuf,
    pub snapshot: PathBuf,
}

/// Reject name collisions before opening a device or reading inputs. The
/// requested base name remains reserved even though no TOML is written.
pub fn output_paths(out: &Path) -> Result<OutputPaths> {
    let paths = OutputPaths {
        profile: None,
        report: out.with_extension("report.json"),
        snapshot: out.with_extension("snapshot.json"),
    };
    // Check the requested name as well as both sidecars, so an existing
    // profile cannot appear to belong to newly written audit files.
    for path in [out, &paths.report, &paths.snapshot] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(Error::Exists(path.to_path_buf())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if out == paths.report || out == paths.snapshot || paths.report == paths.snapshot {
        return Err(Error::Exists(out.to_path_buf()));
    }
    Ok(paths)
}

impl Discovery {
    pub(crate) fn refresh_validation(&mut self) -> Result<()> {
        let validation = self.profile.validate_extraction(
            self.report.validation_mode,
            &self.report.evidence,
            &self.report.conflicts,
        );
        self.report.build_ready = validation.is_valid() && self.report.collection_succeeded();
        self.report.validation = serde_json::to_value(validation)?;
        Ok(())
    }
    /// Writes only a report and the recorded snapshot, including on failed
    /// acquisition. Profiles remain manually maintained; the internal typed
    /// profile is used only to check the collected evidence.
    pub fn write_outputs(&self, out: &Path) -> Result<OutputPaths> {
        let validation = self.profile.validate_extraction(
            self.report.validation_mode,
            &self.report.evidence,
            &self.report.conflicts,
        );
        let mut report = self.report.clone();
        report.build_ready = report.collection_succeeded() && validation.is_valid();
        report.validation = serde_json::to_value(validation)?;
        let paths = output_paths(out)?;
        let entries = [
            (&paths.report, serde_json::to_vec_pretty(&report)?),
            (&paths.snapshot, serde_json::to_vec_pretty(&self.snapshot)?),
        ];
        if let Some(parent) = out.parent().filter(|path| !path.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let mut created = Vec::new();
        let result = (|| -> std::io::Result<()> {
            for (path, bytes) in &entries {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?;
                created.push((*path).clone());
                file.write_all(bytes)?;
                file.sync_all()?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            for path in created {
                let _ = fs::remove_file(path);
            }
            return Err(Error::Io(error));
        }
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nloader_camera::{CameraDevice, CleanupReport};

    pub(crate) fn fixture() -> CameraSnapshot {
        let mut bytes = Vec::new();
        bytes.extend(100u16.to_le_bytes());
        bytes.extend(10u32.to_le_bytes());
        bytes.extend(100u16.to_le_bytes());
        bytes.push(0);
        bytes.extend(0u16.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(0x1001u16.to_le_bytes());
        for _ in 0..4 {
            bytes.extend(0u32.to_le_bytes());
        }
        for string in ["NIKON", "Z 8", "V3.11", "SYNTHETIC-ONLY"] {
            bytes.push((string.encode_utf16().count() + 1) as u8);
            for unit in string.encode_utf16().chain([0]) {
                bytes.extend(unit.to_le_bytes());
            }
        }
        CameraSnapshot::from_raw(
            CameraDevice {
                id: "fixture:z8".into(),
                bus: 0,
                address: 0,
                vendor_id: 0x04b0,
                product_id: 0,
            },
            bytes,
            CaptureOrigin::SyntheticFixture,
            CleanupReport {
                interface_released: true,
                maintenance_mode_entered: false,
                session_opened: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn deterministic_draft_preserves_identity_and_missing_rules() {
        let first = from_snapshot(fixture()).unwrap();
        let second = from_snapshot(fixture()).unwrap();
        assert_eq!(
            first.profile.to_toml().unwrap(),
            second.profile.to_toml().unwrap()
        );
        assert_eq!(first.profile.identity.model, "Z8");
        assert_eq!(first.profile.identity.firmware, "3.11");
        assert!(!first.report.build_ready);
        assert!(first
            .report
            .missing
            .iter()
            .any(|entry| entry.reason.contains("C3.11")));
        assert_eq!(
            first.report.evidence["identity.model"].status,
            EvidenceStatus::Unconfirmed
        );
        assert!(first.profile.memory.xip_base.is_none());
    }

    #[test]
    fn replay_preserves_the_profile_for_the_same_recorded_capture() {
        let mut snapshot = fixture();
        snapshot.origin = CaptureOrigin::UsbDevice;
        let original = generate(snapshot.clone(), false).unwrap();
        let replay = from_snapshot(snapshot).unwrap();
        assert_eq!(
            original.profile.to_toml().unwrap(),
            replay.profile.to_toml().unwrap()
        );
        assert!(!original.report.replayed_snapshot);
        assert!(replay.report.replayed_snapshot);
    }

    #[test]
    fn tampered_or_unclean_snapshot_is_rejected() {
        let mut snapshot = fixture();
        snapshot.device_info.model = "Z9".into();
        assert!(from_snapshot(snapshot).is_err());
        let mut snapshot = fixture();
        snapshot.raw_device_info[0] ^= 1;
        assert!(from_snapshot(snapshot).is_err());
        let mut snapshot = fixture();
        snapshot.cleanup.interface_released = false;
        assert!(from_snapshot(snapshot).is_err());
    }

    #[test]
    fn every_truncated_dataset_is_rejected() {
        let snapshot = fixture();
        for length in 0..snapshot.raw_device_info.len() {
            assert!(
                nloader_camera::parse_device_info(&snapshot.raw_device_info[..length]).is_err(),
                "accepted prefix length {length}"
            );
        }
    }

    #[test]
    fn unknown_version_never_borrows_target_rules() {
        let mut snapshot = fixture();
        let position = snapshot
            .raw_device_info
            .windows(10)
            .position(|bytes| bytes == [b'V', 0, b'3', 0, b'.', 0, b'1', 0, b'1', 0])
            .unwrap();
        snapshot.raw_device_info[position + 8] = b'0';
        snapshot.device_info =
            nloader_camera::parse_device_info(&snapshot.raw_device_info).unwrap();
        snapshot.sha256 = nloader_camera::fingerprint(&snapshot.raw_device_info);
        let discovery = from_snapshot(snapshot).unwrap();
        assert_eq!(discovery.profile.identity.firmware, "3.10");
        assert!(discovery.report.missing[0]
            .reason
            .contains("no memory collection"));
        assert!(!discovery.report.build_ready);
    }

    #[test]
    fn successful_identity_collection_only_writes_report_and_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let discovery = from_snapshot(fixture()).unwrap();
        assert!(discovery.report.collection_succeeded());
        let requested = directory.path().join("profile.toml");
        let paths = discovery.write_outputs(&requested).unwrap();
        assert!(paths.profile.is_none());
        assert!(!requested.exists());
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(&paths.report).unwrap()).unwrap();
        assert_eq!(report["evidence"]["identity.model"]["source"], "snapshot");
        assert_eq!(report["conflicts"], serde_json::json!([]));
        let snapshot: CameraSnapshot =
            serde_json::from_slice(&fs::read(&paths.snapshot).unwrap()).unwrap();
        snapshot.validate().unwrap();
        assert_eq!(snapshot, fixture());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
        assert!(matches!(
            discovery.write_outputs(&requested),
            Err(Error::Exists(_))
        ));
    }

    #[test]
    fn invalid_metadata_and_conflicts_only_publish_audit_files() {
        for failure in ["identity", "hash", "conflict"] {
            let mut discovery = from_snapshot(fixture()).unwrap();
            match failure {
                "identity" => {
                    discovery
                        .report
                        .evidence
                        .get_mut("identity.model")
                        .unwrap()
                        .model = "Z6III".into()
                }
                "hash" => {
                    discovery
                        .report
                        .evidence
                        .get_mut("identity.model")
                        .unwrap()
                        .fragment_sha256 = Some("invalid".into())
                }
                _ => discovery.report.conflicts.push(Conflict {
                    field: "collection.window_records".into(),
                    candidates: vec![],
                    reason: "inconsistent record".into(),
                }),
            }
            let directory = tempfile::tempdir().unwrap();
            let out = directory.path().join("profile.toml");
            let paths = discovery.write_outputs(&out).unwrap();
            assert!(paths.profile.is_none());
            assert!(!out.exists());
            assert!(paths.report.exists());
            assert!(paths.snapshot.exists());
            let report: serde_json::Value =
                serde_json::from_slice(&fs::read(paths.report).unwrap()).unwrap();
            assert_eq!(report["build_ready"], false);
            assert!(!report["validation"]["issues"]
                .as_array()
                .unwrap()
                .is_empty());
            assert!(report["evidence"].get("identity.model").is_some());
        }
    }
    #[test]
    fn complete_configuration_still_requires_extraction_validation() {
        use nloader_profile::{ContainerKind, Memory, MemorySegment, MemorySegmentKind, Slack};
        let mut discovery = from_snapshot(fixture()).unwrap();
        let profile = &mut discovery.profile;
        profile.identity.container = Some(ContainerKind::LegacyXor);
        profile.identity.stock_pkg = Some("synthetic.bin".into());
        profile.identity.eg_module = Some("synthetic.bi".into());
        profile.checks.package_sha256 = Some(nloader_profile::sha256(b"synthetic package"));
        profile.checks.module_sha256 = Some(nloader_profile::sha256(&[0; 512]));
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
        assert!(profile.validate(BuildMode::Marker).is_valid());
        assert!(!profile
            .validate_extraction(
                BuildMode::Marker,
                &discovery.report.evidence,
                &discovery.report.conflicts
            )
            .is_valid());
        discovery.report.build_ready = true;
        let directory = tempfile::tempdir().unwrap();
        let out = directory.path().join("profile.toml");
        let paths = discovery.write_outputs(&out).unwrap();
        assert!(paths.profile.is_none());
        assert!(!out.exists());
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(paths.report).unwrap()).unwrap();
        assert_eq!(report["build_ready"], false);
    }
    #[test]
    fn existing_requested_name_or_either_sidecar_rejects_the_entire_output_set() {
        for failed in [false, true] {
            for extension in ["toml", "report.json", "snapshot.json"] {
                let mut discovery = from_snapshot(fixture()).unwrap();
                if failed {
                    discovery.report.conflicts.push(Conflict {
                        field: "collection.memory".into(),
                        candidates: vec![],
                        reason: "read failed".into(),
                    });
                }
                let directory = tempfile::tempdir().unwrap();
                let out = directory.path().join("profile.toml");
                let occupied = out.with_extension(extension);
                fs::write(&occupied, "prior evidence").unwrap();
                assert!(matches!(
                    discovery.write_outputs(&out),
                    Err(Error::Exists(path)) if path == occupied
                ));
                assert_eq!(fs::read_to_string(occupied).unwrap(), "prior evidence");
                assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
            }
        }
    }
    #[test]
    fn failed_collection_never_reuses_an_existing_profile_name() {
        let mut discovery = from_snapshot(fixture()).unwrap();
        discovery.report.conflicts.push(Conflict {
            field: "collection.memory".into(),
            candidates: vec![],
            reason: "read failed".into(),
        });
        let directory = tempfile::tempdir().unwrap();
        let out = directory.path().join("profile.toml");
        fs::write(&out, "prior profile").unwrap();
        assert!(matches!(
            discovery.write_outputs(&out),
            Err(Error::Exists(_))
        ));
        assert_eq!(fs::read_to_string(&out).unwrap(), "prior profile");
        assert!(!out.with_extension("report.json").exists());
    }
    #[cfg(unix)]
    #[test]
    fn dangling_requested_name_or_sidecar_symlink_is_not_replaced() {
        for extension in ["toml", "report.json", "snapshot.json"] {
            let discovery = from_snapshot(fixture()).unwrap();
            let directory = tempfile::tempdir().unwrap();
            let out = directory.path().join("profile.toml");
            let occupied = out.with_extension(extension);
            let target = directory.path().join("missing");
            std::os::unix::fs::symlink(&target, &occupied).unwrap();
            assert!(matches!(
                discovery.write_outputs(&out),
                Err(Error::Exists(path)) if path == occupied
            ));
            assert!(fs::symlink_metadata(&occupied)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(fs::read_link(occupied).unwrap(), target);
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        }
    }
    #[test]
    fn simulated_transport_records_raw_identity_and_releases_once() {
        struct Transport {
            raw: Vec<u8>,
            reads: usize,
            releases: usize,
        }
        impl nloader_camera::IdentityTransport for Transport {
            fn read_device_info(&mut self) -> nloader_camera::Result<Vec<u8>> {
                self.reads += 1;
                Ok(self.raw.clone())
            }
            fn release(&mut self) -> nloader_camera::Result<()> {
                self.releases += 1;
                Ok(())
            }
        }
        let expected = fixture();
        let mut transport = Transport {
            raw: expected.raw_device_info.clone(),
            reads: 0,
            releases: 0,
        };
        let snapshot = nloader_camera::capture_with_transport(
            expected.device.clone(),
            &mut transport,
            CaptureOrigin::SyntheticFixture,
        )
        .unwrap();
        assert_eq!(snapshot, expected);
        assert_eq!((transport.reads, transport.releases), (1, 1));
    }
}
