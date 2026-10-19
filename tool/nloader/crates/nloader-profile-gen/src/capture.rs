use crate::{generate_parts, image, Discovery, DiscoverySnapshot, Result};
use nloader_camera::{CaptureOrigin, MemoryCapture, MemoryReadRequest, MemoryReadWindow};
use nloader_profile::{sha256, Conflict, Evidence, EvidenceSource, EvidenceStatus, Profile};
#[cfg(test)]
use nloader_profile::{BuildMode, MemorySegmentKind};
use serde::Serialize;
use std::path::Path;

/// Requests are explicit profile inputs; no model-specific address fallback.
pub fn memory_requests(profile: &Profile) -> Result<Vec<MemoryReadRequest>> {
    let config = profile
        .capture
        .as_ref()
        .ok_or_else(|| crate::Error::FirmwareMismatch("missing capture configuration".into()))?;
    Ok(config
        .requests
        .iter()
        .map(|request| MemoryReadRequest {
            label: request.label.clone(),
            address: request.address,
            length: request.length,
        })
        .collect())
}

pub(crate) fn verified_windows(
    profile: &Profile,
    payload: &[u8],
) -> Result<nloader_profile::VerifiedReadWindows> {
    profile
        .verify_read_windows(payload)
        .map_err(crate::Error::FirmwareMismatch)
}
#[derive(Debug, Clone, Serialize)]
pub struct MemoryComparison {
    pub label: String,
    pub address: u64,
    pub length: u32,
    pub image_fragment_sha256: String,
    pub collected_fragment_sha256: String,
    pub matched: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct MemoryCrossCheck {
    pub capture: MemoryCapture,
    pub evidence_valid: bool,
    pub capture_complete: bool,
    pub matches_image: Option<bool>,
    pub image_fragment_sha256: Option<String>,
    pub collected_fragment_sha256: Option<String>,
    pub reason: String,
    pub comparisons: Vec<MemoryComparison>,
}
/// Validates local firmware before entering camera maintenance mode. Partial
/// captures remain reports and snapshots; errors never become empty memory bytes.
pub fn discover_memory_with_firmware(
    selector: &str,
    firmware: &Path,
    key_file: &Path,
    profile: &Profile,
) -> Result<Discovery> {
    let image = image::load(firmware, key_file, profile)?;
    let windows = verified_windows(profile, &image.payload)?;
    let capture = nloader_camera::capture_memory(selector, &memory_requests(profile)?, &windows)?;
    generate_memory(capture, &image, false)
}
pub fn from_memory_capture_with_firmware(
    capture: MemoryCapture,
    firmware: &Path,
    key_file: &Path,
    profile: &Profile,
) -> Result<Discovery> {
    generate_memory(capture, &image::load(firmware, key_file, profile)?, true)
}
fn generate_memory(
    capture: MemoryCapture,
    image: &image::MatchedFirmware,
    replay: bool,
) -> Result<Discovery> {
    let validation = capture.validate();
    let info = if validation.is_ok() {
        capture.identity.as_ref()
    } else {
        None
    };
    let (profile, mut report) = generate_parts(
        info,
        &capture.device.id,
        capture.origin,
        &capture.raw_device_info,
        replay,
    )?;
    report.notes.retain(|note| {
        !note.contains("identity-only capture does not open")
            && !note.contains("USB cleanup results are retained")
    });
    report.notes.push("F001 can change camera mode and reload configuration. Session close acknowledgements and USB release do not prove the prior UI state has been restored; see the complete memory capture.".into());
    let mut discovery = Discovery {
        profile,
        report,
        snapshot: DiscoverySnapshot::Memory(capture.clone()),
    };
    let target_matches = image::ensure_target(&discovery).is_ok();
    if target_matches && validation.is_ok() {
        image::apply(&mut discovery, image)?;
    }
    let evidence_valid = validation.is_ok();
    let capture_complete = capture.is_complete();
    let mut check = MemoryCrossCheck {
        capture: capture.clone(),
        evidence_valid,
        capture_complete,
        matches_image: None,
        image_fragment_sha256: None,
        collected_fragment_sha256: None,
        reason: String::new(),
        comparisons: Vec::new(),
    };
    if let Err(error) = validation {
        check.reason = format!("capture evidence is invalid: {error}");
    } else if !target_matches {
        check.reason =
            "capture has no matching Z8 C3.11 identity; image mappings were not applied".into();
    } else if !capture_complete {
        check.reason = capture
            .failure
            .clone()
            .unwrap_or_else(|| "memory capture or cleanup is incomplete".into());
    } else if capture.requests != memory_requests(&image.source_profile)?
        || capture.windows
            != image
                .source_profile
                .capture
                .as_ref()
                .ok_or_else(|| {
                    crate::Error::FirmwareMismatch("missing capture configuration".into())
                })?
                .windows
                .iter()
                .map(|window| MemoryReadWindow {
                    start: window.start,
                    end: window.end,
                })
                .collect::<Vec<_>>()
    {
        // Only the window-record plan has a reviewed image comparison; other
        // read plans are reported, never replayed as profile evidence.
        check.reason = "capture does not match the supported read plan".into();
    } else {
        compare_requests(&mut discovery, &capture, image, &mut check)?;
    }
    if let Some(missing) = discovery
        .report
        .missing
        .iter_mut()
        .find(|entry| entry.field == "collection.memory")
    {
        missing.reason = if check.matches_image == Some(true) {
            "only the selected read-plan records were cross-checked; menu behavior, service discovery, other memory structures and ownership remain incomplete".into()
        } else {
            check.reason.clone()
        };
    }
    discovery.report.rule_version = format!("{}+{}", discovery.report.rule_version, capture.rule);
    if check.matches_image != Some(true) {
        discovery.report.conflicts.push(Conflict {
            field: "collection.memory".into(),
            candidates: Vec::new(),
            reason: check.reason.clone(),
        });
    }
    discovery.report.memory = Some(check);
    discovery.refresh_validation()?;
    Ok(discovery)
}

fn compare_requests(
    discovery: &mut Discovery,
    capture: &MemoryCapture,
    image: &image::MatchedFirmware,
    check: &mut MemoryCrossCheck,
) -> Result<()> {
    for (index, request) in capture.requests.iter().enumerate() {
        let offset = discovery
            .profile
            .memory
            .address_to_offset(request.address, u64::from(request.length))
            .map_err(|error| crate::Error::FirmwareMismatch(error.to_string()))?;
        let start = usize::try_from(offset).map_err(|_| {
            crate::Error::FirmwareMismatch("image offset does not fit host size".into())
        })?;
        let end = start
            .checked_add(request.length as usize)
            .ok_or_else(|| crate::Error::FirmwareMismatch("image range overflow".into()))?;
        let expected = image.payload.get(start..end).ok_or_else(|| {
            crate::Error::FirmwareMismatch("requested records exceed image payload".into())
        })?;
        let observed: Vec<_> = capture
            .segments
            .iter()
            .filter(|segment| segment.request_index == index)
            .flat_map(|segment| segment.bytes.iter().copied())
            .collect();
        let matched = expected == observed;
        let expected_hash = sha256(expected);
        let observed_hash = sha256(&observed);
        let field = "collection.window_records".to_owned();
        let note = if matched {
            "Repeated reads match this initialized image record; menu behavior and runtime ownership remain unverified."
        } else {
            "Repeated reads were consistent but differ from the initialized image record; runtime changes or a mapping mismatch remain unresolved."
        };
        if matched {
            let synthetic = capture.origin == CaptureOrigin::SyntheticFixture;
            discovery.report.evidence.insert(
                field,
                Evidence {
                    source: if synthetic {
                        EvidenceSource::Snapshot
                    } else {
                        EvidenceSource::Device
                    },
                    status: if synthetic {
                        EvidenceStatus::Unconfirmed
                    } else {
                        EvidenceStatus::Observed
                    },
                    model: "Z8".into(),
                    firmware: "3.11".into(),
                    rule: format!("{}+per-request-image-cross-check-v1", capture.rule),
                    fragment_sha256: Some(observed_hash.clone()),
                    module_sha256: Some(image.report.eg_payload_sha256.clone()),
                    note: note.into(),
                },
            );
        } else {
            discovery.report.conflicts.push(Conflict {
                field,
                candidates: vec![expected_hash.clone(), observed_hash.clone()],
                reason: note.into(),
            });
        }
        check.image_fragment_sha256 = Some(expected_hash.clone());
        check.collected_fragment_sha256 = Some(observed_hash.clone());
        check.comparisons.push(MemoryComparison {
            label: request.label.clone(),
            address: request.address,
            length: request.length,
            image_fragment_sha256: expected_hash,
            collected_fragment_sha256: observed_hash,
            matched,
        });
    }
    let all_match = check
        .comparisons
        .iter()
        .all(|comparison| comparison.matched);
    check.matches_image = Some(all_match);
    check.reason = if all_match {
        "All selected records match their initialized image bytes; this does not validate menu execution or free-space ownership.".into()
    } else {
        "Some records differ from their initialized image bytes; each difference is retained separately and no menu capability is granted.".into()
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nloader_camera::{MemoryReply, MemoryTransport};
    use std::sync::OnceLock;

    fn synthetic_config() -> nloader_profile::CaptureConfig {
        nloader_profile::CaptureConfig {
            family: "z8_readonly_v1".into(),
            windows: vec![nloader_profile::AddressRange {
                start: 0x1000,
                end: 0x1800,
            }],
            requests: vec![nloader_profile::CaptureRequest {
                label: "window_records_0_1".into(),
                address: 0x1000,
                length: 192,
            }],
            range_check: nloader_profile::CaptureFragment {
                name: "fixture".into(),
                file_offset: 0,
                length: 0,
                sha256: sha256(&[]),
            },
            slot: nloader_profile::CaptureSlot {
                descriptor_offset: 0,
                region_getter_offset: 0,
                overlay_getter_offset: 0,
                flash_table_offset: 0,
                flash_record_count: 0,
                region_count: 0,
                overlay_count: 0,
                instruction_windows: Vec::new(),
            },
        }
    }
    fn synthetic_image() -> &'static image::MatchedFirmware {
        static IMAGE: OnceLock<image::MatchedFirmware> = OnceLock::new();
        IMAGE.get_or_init(|| {
            let payload = vec![0; 0x1000];
            let mut source_profile = Profile::draft("Z8", "3.11");
            source_profile.memory = nloader_profile::Memory {
                module_size: Some(0x1000),
                xip_base: Some(0x8000),
                segments: vec![
                    nloader_profile::MemorySegment {
                        file_offset: 0,
                        runtime_start: 0x8000,
                        size: 0x800,
                        kind: MemorySegmentKind::Xip,
                    },
                    nloader_profile::MemorySegment {
                        file_offset: 0x800,
                        runtime_start: 0x1000,
                        size: 0x800,
                        kind: MemorySegmentKind::Ram,
                    },
                ],
                ..Default::default()
            };
            source_profile.capture = Some(synthetic_config());
            let hash = sha256(&payload);
            image::MatchedFirmware {
                payload,
                source_profile,
                report: image::FirmwareSupplementReport {
                    source: "synthetic-only.bin".into(),
                    rule: "synthetic-test-only".into(),
                    package_sha256: sha256(b"synthetic package"),
                    eg_module: "fixture.bi".into(),
                    eg_payload_sha256: hash,
                    header_digest_verified: true,
                    modules: Vec::new(),
                    segments: Vec::new(),
                    marker_slot: None,
                },
            }
        })
    }
    fn memory_capture(byte: u8, unstable: bool, cleanup_error: bool) -> MemoryCapture {
        struct Transport {
            byte: u8,
            reads: usize,
            unstable: bool,
            cleanup_error: bool,
        }
        impl MemoryTransport for Transport {
            fn transact(
                &mut self,
                transaction_id: u32,
                operation: u16,
                parameters: &[u32],
            ) -> nloader_camera::Result<MemoryReply> {
                let mut reply = MemoryReply {
                    transaction_id,
                    response_code: 0x2001,
                    parameters: Vec::new(),
                    data: Vec::new(),
                };
                match operation {
                    0x1001 => reply.data = crate::tests::fixture().raw_device_info,
                    0x94fd => {
                        reply.parameters = vec![
                            if parameters[0] == 0xf002 && self.cleanup_error {
                                0xa001
                            } else {
                                0x2001
                            },
                            0,
                            0,
                            0,
                            0,
                        ];
                    }
                    0x94ff => {
                        self.reads += 1;
                        reply.parameters = vec![0x2001, 0, 0, 0, 0];
                        let value = if self.unstable && self.reads == 2 {
                            self.byte.wrapping_add(1)
                        } else {
                            self.byte
                        };
                        reply.data = vec![value; parameters[3] as usize];
                    }
                    _ => {}
                }
                Ok(reply)
            }
            fn release(&mut self) -> nloader_camera::Result<()> {
                Ok(())
            }
        }
        let mut transport = Transport {
            byte,
            reads: 0,
            unstable,
            cleanup_error,
        };
        nloader_camera::capture_memory_with_transport(
            crate::tests::fixture().device,
            &mut transport,
            &memory_requests(&synthetic_image().source_profile).unwrap(),
            &[MemoryReadWindow {
                start: 0x1000,
                end: 0x1800,
            }],
            CaptureOrigin::SyntheticFixture,
        )
        .unwrap()
    }
    #[test]
    fn replay_requires_explicit_current_windows_and_rejects_changed_plan() {
        let capture = memory_capture(0, false, false);
        let mut value = serde_json::to_value(&capture).unwrap();
        value.as_object_mut().unwrap().remove("windows");
        assert!(serde_json::from_value::<MemoryCapture>(value).is_err());
        let mut old = capture.clone();
        old.schema = 1;
        assert!(old.validate().is_err());
        let mut changed = capture;
        changed.windows[0].end += 1;
        let discovery = generate_memory(changed, synthetic_image(), true).unwrap();
        assert!(!discovery.report.collection_succeeded());
        assert!(discovery
            .report
            .memory
            .as_ref()
            .unwrap()
            .matches_image
            .is_none());
        assert!(!discovery
            .report
            .evidence
            .contains_key("collection.window_records"));
    }
    #[test]
    fn consistent_image_match_remains_an_incomplete_unconfirmed_draft() {
        let discovery =
            generate_memory(memory_capture(0, false, false), synthetic_image(), true).unwrap();
        let check = discovery.report.memory.as_ref().unwrap();
        assert!(check.capture_complete, "{:?}", check);
        assert_eq!(check.matches_image, Some(true));
        assert_eq!(
            discovery.report.evidence["collection.window_records"].status,
            EvidenceStatus::Unconfirmed
        );
        assert_eq!(
            discovery.report.evidence["memory.segments"].source,
            EvidenceSource::FirmwareImage
        );
        assert!(discovery.profile.memory.slack.is_none());
        assert!(discovery.profile.memory.link_base.is_none());
        assert!(discovery.profile.services.fs_open.is_none());
        assert!(!discovery.report.build_ready);
        assert!(discovery.report.collection_succeeded());
        assert!(!discovery.profile.validate(BuildMode::Marker).is_valid());
        assert!(discovery.report.replayed_snapshot);
        let second =
            generate_memory(memory_capture(0, false, false), synthetic_image(), true).unwrap();
        assert_eq!(
            discovery.profile.to_toml().unwrap(),
            second.profile.to_toml().unwrap()
        );
        let directory = tempfile::tempdir().unwrap();
        let requested = directory.path().join("matched.toml");
        let output = discovery.write_outputs(&requested).unwrap();
        assert!(output.profile.is_none());
        assert!(!requested.exists());
        let saved: MemoryCapture =
            serde_json::from_slice(&std::fs::read(output.snapshot).unwrap()).unwrap();
        assert_eq!(saved, check.capture);
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.report).unwrap()).unwrap();
        assert_eq!(report["memory"]["capture_complete"], true);
        assert_eq!(report["memory"]["matches_image"], true);
    }
    #[test]
    fn consistent_but_different_bytes_record_a_conflict() {
        let discovery =
            generate_memory(memory_capture(7, false, false), synthetic_image(), true).unwrap();
        assert!(!discovery.report.collection_succeeded());
        let check = discovery.report.memory.as_ref().unwrap();
        assert!(check.evidence_valid);
        assert!(check.capture_complete);
        assert_eq!(
            discovery.report.memory.as_ref().unwrap().matches_image,
            Some(false)
        );
        assert!(discovery
            .report
            .conflicts
            .iter()
            .any(|entry| entry.field == "collection.window_records"));
        assert!(!discovery
            .report
            .evidence
            .contains_key("collection.window_records"));
        let directory = tempfile::tempdir().unwrap();
        let requested = directory.path().join("different.toml");
        let output = discovery.write_outputs(&requested).unwrap();
        assert!(output.profile.is_none());
        assert!(!requested.exists());
        let saved: MemoryCapture =
            serde_json::from_slice(&std::fs::read(output.snapshot).unwrap()).unwrap();
        assert_eq!(saved, check.capture);
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.report).unwrap()).unwrap();
        assert_eq!(report["memory"]["evidence_valid"], true);
        assert_eq!(report["memory"]["capture_complete"], true);
        assert_eq!(report["memory"]["matches_image"], false);
        assert_eq!(report["build_ready"], false);
    }
    #[test]
    fn unstable_and_unclean_captures_are_retained_without_cross_check_success() {
        for (unstable, cleanup_error) in [(true, false), (false, true)] {
            let capture = memory_capture(0, unstable, cleanup_error);
            let discovery = generate_memory(capture.clone(), synthetic_image(), false).unwrap();
            assert!(!discovery.report.collection_succeeded());
            let check = discovery.report.memory.as_ref().unwrap();
            assert!(!check.capture_complete);
            assert_eq!(check.matches_image, None);
            assert_eq!(check.capture, capture);
            assert!(!discovery.report.build_ready);
            let directory = tempfile::tempdir().unwrap();
            let output = discovery
                .write_outputs(&directory.path().join("draft.toml"))
                .unwrap();
            assert!(output.profile.is_none());
            assert!(!directory.path().join("draft.toml").exists());
            assert!(output.report.exists());
            let report: serde_json::Value =
                serde_json::from_slice(&std::fs::read(output.report).unwrap()).unwrap();
            assert_eq!(report["memory"]["capture_complete"], false);
            assert_eq!(report["memory"]["matches_image"], serde_json::Value::Null);
            let saved: MemoryCapture =
                serde_json::from_slice(&std::fs::read(output.snapshot).unwrap()).unwrap();
            assert_eq!(saved, capture);
        }
    }
    #[test]
    fn invalid_capture_does_not_borrow_image_identity_or_mappings() {
        let mut capture = memory_capture(0, false, false);
        capture.identity = None;
        let discovery = generate_memory(capture, synthetic_image(), true).unwrap();
        assert!(!discovery.report.collection_succeeded());
        assert!(!discovery.report.memory.as_ref().unwrap().evidence_valid);
        assert!(discovery.profile.identity.model.is_empty());
        assert!(discovery.profile.memory.segments.is_empty());
        assert!(discovery.report.firmware.is_none());
    }
}
