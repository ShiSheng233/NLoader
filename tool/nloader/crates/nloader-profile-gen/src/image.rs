use crate::{generate, Discovery, Error, Result};
use nloader_camera::CameraSnapshot;
use nloader_firmware::{FirmwareIdentity, KeyFile};
#[cfg(test)]
use nloader_profile::BuildMode;
use nloader_profile::{
    sha256, ContainerKind, Evidence, EvidenceSource, EvidenceStatus, Memory, MemorySegment, Profile,
};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

const RULE: &str = "z8-c3.11-official-image-mapping-v1";

#[derive(Debug, Clone, Serialize)]
pub struct FirmwareModuleReport {
    pub name: String,
    pub payload_length: usize,
    pub payload_sha256: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct FirmwareSupplementReport {
    pub source: PathBuf,
    pub rule: String,
    pub package_sha256: String,
    pub eg_module: String,
    pub eg_payload_sha256: String,
    pub header_digest_verified: bool,
    pub modules: Vec<FirmwareModuleReport>,
    pub segments: Vec<MemorySegment>,
    pub marker_slot: Option<crate::MarkerSlot>,
}
pub(crate) struct MatchedFirmware {
    pub report: FirmwareSupplementReport,
    pub payload: Vec<u8>,
    pub source_profile: Profile,
}

/// Supplements actual identity with independently verified image bytes; never
/// labels the image's static mappings as on-device observations.
pub fn discover_with_firmware(
    selector: &str,
    firmware: &Path,
    key_file: &Path,
    profile: &Profile,
) -> Result<Discovery> {
    let mut discovery = generate(nloader_camera::capture_identity(selector)?, false)?;
    ensure_target(&discovery)?;
    apply(&mut discovery, &load(firmware, key_file, profile)?)?;
    Ok(discovery)
}
pub fn from_snapshot_with_firmware(
    snapshot: CameraSnapshot,
    firmware: &Path,
    key_file: &Path,
    profile: &Profile,
) -> Result<Discovery> {
    let mut discovery = generate(snapshot, true)?;
    ensure_target(&discovery)?;
    apply(&mut discovery, &load(firmware, key_file, profile)?)?;
    Ok(discovery)
}
pub(crate) fn ensure_target(discovery: &Discovery) -> Result<()> {
    if discovery.profile.identity.model != "Z8" || discovery.profile.identity.firmware != "3.11" {
        return Err(Error::FirmwareMismatch(
            "image mapping requires exactly Z8 firmware 3.11".into(),
        ));
    }
    Ok(())
}
fn require_hash(actual: &str, expected: &str, what: &str) -> Result<()> {
    if actual != expected {
        return Err(Error::FirmwareMismatch(format!(
            "{what} does not match the reviewed Z8 C3.11 input"
        )));
    }
    Ok(())
}
pub(crate) fn load(path: &Path, key_file: &Path, profile: &Profile) -> Result<MatchedFirmware> {
    if profile.identity.model != "Z8" || profile.identity.firmware != "3.11" {
        return Err(Error::FirmwareMismatch(
            "collection supports only Z8 C3.11".into(),
        ));
    }
    let capture = profile
        .capture
        .as_ref()
        .ok_or_else(|| Error::FirmwareMismatch("missing capture configuration".into()))?;
    if capture.family != "z8_readonly_v1" {
        return Err(Error::FirmwareMismatch("unsupported capture family".into()));
    }
    let package_sha256 = profile
        .checks
        .package_sha256
        .as_deref()
        .ok_or_else(|| Error::FirmwareMismatch("missing package fingerprint".into()))?;
    let module_sha256 = profile
        .checks
        .module_sha256
        .as_deref()
        .ok_or_else(|| Error::FirmwareMismatch("missing module fingerprint".into()))?;
    let module_name = profile
        .identity
        .eg_module
        .as_deref()
        .ok_or_else(|| Error::FirmwareMismatch("missing module name".into()))?;
    let raw = fs::read(path)?;
    let package_hash = sha256(&raw);
    require_hash(&package_hash, package_sha256, "official package SHA-256")?;
    let key = KeyFile::load(key_file)?.for_identity(&FirmwareIdentity {
        model: "Z8".into(),
        firmware: "3.11".into(),
    })?;
    key.verify_stock_identity(&raw)?;
    if key.scheme() != "legacy-xor" {
        return Err(Error::FirmwareMismatch("wrong container for target".into()));
    }
    let image = key.unpack(&raw)?;
    if !image.header_digest_verified() {
        return Err(Error::FirmwareMismatch(
            "header digest has not been verified".into(),
        ));
    }
    let payload = image.payload(module_name)?;
    let eg_hash = sha256(payload);
    require_hash(&eg_hash, module_sha256, "EG payload SHA-256")?;
    let memory = &profile.memory;
    if memory.module_size != Some(payload.len() as u64) {
        return Err(Error::FirmwareMismatch(
            "module length differs from profile".into(),
        ));
    }
    memory
        .validated_segments()
        .map_err(|error| Error::FirmwareMismatch(error.to_string()))?;
    let marker_slot = crate::slot::inspect(payload, memory, &capture.slot)?;
    crate::capture::verified_windows(profile, payload)?;
    let modules = image
        .modules()
        .iter()
        .map(|module| {
            let bytes = image.payload(&module.name)?;
            Ok(FirmwareModuleReport {
                name: module.name.clone(),
                payload_length: bytes.len(),
                payload_sha256: sha256(bytes),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(MatchedFirmware {
        payload: payload.to_vec(),
        source_profile: profile.clone(),
        report: FirmwareSupplementReport {
            source: path.to_path_buf(),
            rule: RULE.into(),
            package_sha256: package_hash,
            eg_module: module_name.into(),
            eg_payload_sha256: eg_hash,
            header_digest_verified: true,
            modules,
            segments: memory.segments.clone(),
            marker_slot: Some(marker_slot),
        },
    })
}
pub(crate) fn apply(discovery: &mut Discovery, image: &MatchedFirmware) -> Result<()> {
    ensure_target(discovery)?;
    let profile = &mut discovery.profile;
    profile.identity.container = Some(ContainerKind::LegacyXor);
    profile.identity.stock_pkg = image.source_profile.identity.stock_pkg.clone();
    profile.identity.eg_module = Some(image.report.eg_module.clone());
    profile.checks.package_sha256 = Some(image.report.package_sha256.clone());
    profile.checks.module_sha256 = Some(image.report.eg_payload_sha256.clone());
    profile.memory = Memory {
        xip_base: image.source_profile.memory.xip_base,
        module_size: image.source_profile.memory.module_size,
        segments: image.source_profile.memory.segments.clone(),
        ..Memory::default()
    };
    if let Some(slot) = &image.report.marker_slot {
        profile.memory.slack = Some(slot.slack.clone());
        profile.memory.link_base = Some(slot.link_base);
        profile.memory.link_size = Some(slot.link_size);
    }
    let evidence = Evidence { source: EvidenceSource::FirmwareImage, status: EvidenceStatus::Static,
        model: "Z8".into(), firmware: "3.11".into(), rule: RULE.into(),
        fragment_sha256: Some(image.report.eg_payload_sha256.clone()), module_sha256: Some(image.report.eg_payload_sha256.clone()),
        note: "Exact official package and EG payload match the reviewed C3.11 inputs. Image bytes only, not device verification or proof of free space.".into() };
    for field in [
        "identity.container",
        "identity.stock_pkg",
        "identity.eg_module",
        "checks.module_sha256",
        "memory.xip_base",
        "memory.module_size",
        "memory.segments",
    ] {
        discovery
            .report
            .evidence
            .insert(field.into(), evidence.clone());
    }
    let mut package_evidence = evidence;
    package_evidence.fragment_sha256 = Some(image.report.package_sha256.clone());
    discovery
        .report
        .evidence
        .insert("checks.package_sha256".into(), package_evidence);
    if let Some(slot) = &image.report.marker_slot {
        for field in ["memory.slack", "memory.link_base", "memory.link_size"] {
            discovery.report.evidence.insert(
                field.into(),
                Evidence {
                    source: EvidenceSource::StaticAnalysis,
                    status: EvidenceStatus::Static,
                    model: "Z8".into(),
                    firmware: "3.11".into(),
                    rule: "z8-c3.11-reviewed-marker-slot-v1".into(),
                    fragment_sha256: Some(image.report.eg_payload_sha256.clone()),
                    module_sha256: Some(image.report.eg_payload_sha256.clone()),
                    note: slot.note.clone(),
                },
            );
        }
    }
    discovery.report.firmware = Some(image.report.clone());
    discovery.report.rule_version = format!("{}+{RULE}", discovery.report.rule_version);
    discovery.report.missing.retain(|entry| {
        !matches!(
            entry.field.as_str(),
            "collection.restricted_firmware" | "checks.package_sha256" | "checks.module_sha256"
        )
    });
    if let Some(entry) = discovery
        .report
        .missing
        .iter_mut()
        .find(|entry| entry.field == "memory")
    {
        entry.reason = if image.report.marker_slot.is_some() {
            "a static marker slot and limited link allocation are identified; long-term RAM ownership and device execution remain unverified".into()
        } else {
            "image mappings are known; free firmware space, link allocation and long-term RAM ownership remain unverified".into()
        };
    }
    discovery.report.notes.push("Official-image mappings and the marker slot are static evidence. Passing marker profile checks does not verify any service, menu hook, update acceptance or camera execution.".into());
    discovery.refresh_validation()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_incomplete_profile_before_io() {
        assert!(load(
            Path::new("missing"),
            Path::new("missing"),
            &Profile::draft("Z8", "3.11")
        )
        .is_err());
        assert!(load(
            Path::new("missing"),
            Path::new("missing"),
            &Profile::draft("other", "3.11")
        )
        .is_err());
    }

    #[test]
    #[ignore = "requires explicit local official package, key file and profile; no camera access"]
    fn verifies_local_image_without_promoting_synthetic_identity() {
        let firmware =
            std::env::var_os("NLOADER_TEST_FIRMWARE").expect("set NLOADER_TEST_FIRMWARE");
        let keys = std::env::var_os("NLOADER_TEST_KEY_FILE").expect("set NLOADER_TEST_KEY_FILE");
        let path = std::env::var_os("NLOADER_TEST_PROFILE").expect("set NLOADER_TEST_PROFILE");
        let profile = Profile::from_toml(&fs::read_to_string(path).unwrap()).unwrap();
        let image = load(Path::new(&firmware), Path::new(&keys), &profile).unwrap();
        let mut discovery = generate(crate::tests::fixture(), true).unwrap();
        apply(&mut discovery, &image).unwrap();
        assert!(image.report.header_digest_verified);
        assert!(image.report.marker_slot.is_some());
        assert_eq!(
            discovery.report.evidence["identity.model"].status,
            EvidenceStatus::Unconfirmed
        );
        assert!(!discovery
            .profile
            .validate_extraction(
                BuildMode::Marker,
                &discovery.report.evidence,
                &discovery.report.conflicts
            )
            .is_valid());
    }
}
