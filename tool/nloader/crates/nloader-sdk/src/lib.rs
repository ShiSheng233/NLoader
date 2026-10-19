//! Public host SDK. Frontends share these libraries and never own format rules.
pub mod readback;
pub mod runtime_trace;
pub use nloader_build as build;
pub use nloader_camera as camera;
pub use nloader_firmware as firmware;
pub use nloader_profile as profile;
pub use nloader_profile_gen as discovery;

use std::{fs, path::Path};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Profile(#[from] profile::Error),
    #[error(transparent)]
    Discovery(#[from] discovery::Error),
    #[error(transparent)]
    Firmware(#[from] firmware::Error),
    #[error("profile does not name its firmware module")]
    MissingModule,
    #[error("invalid snapshot JSON: {0}")]
    Snapshot(#[from] serde_json::Error),
    #[error("memory snapshot replay requires matching firmware and a key file")]
    MissingFirmwareForMemoryCapture,
}

pub fn read_profile(path: &Path) -> Result<profile::Profile, Error> {
    Ok(profile::Profile::from_toml(&fs::read_to_string(path)?)?)
}

/// Check a profile, including a hand-written one, against the official package
/// it names: package and module fingerprints, mappings, menu records, and
/// stock bytes. The package identity comes from the local key record, not
/// from the profile. Nothing is built, patched, or sent to a camera.
pub fn validate_profile_with_firmware(
    path: &Path,
    mode: profile::BuildMode,
    package: &Path,
    key_file: &Path,
) -> Result<profile::ValidationReport, Error> {
    let profile = read_profile(path)?;
    let identity = firmware::FirmwareIdentity {
        model: profile.identity.model.clone(),
        firmware: profile.identity.firmware.clone(),
    };
    let raw = fs::read(package)?;
    let key = firmware::KeyFile::load(key_file)?.for_identity(&identity)?;
    key.verify_stock_identity(&raw)?;
    let image = key.unpack(&raw)?;
    let module_name = profile
        .identity
        .eg_module
        .as_deref()
        .ok_or(Error::MissingModule)?;
    let mut report = profile.validate_package_output();
    report.issues.extend(
        profile
            .validate_for(
                mode,
                &profile::ValidationContext {
                    model: &identity.model,
                    firmware: &identity.firmware,
                    package: Some(&raw),
                    module_name,
                    module: image.payload(module_name)?,
                },
            )
            .issues,
    );
    Ok(report)
}

pub fn replay_profile(path: &Path) -> Result<discovery::Discovery, Error> {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    if value.get("requests").is_some() {
        return Err(Error::MissingFirmwareForMemoryCapture);
    }
    let snapshot = serde_json::from_value(value)?;
    Ok(discovery::from_snapshot(snapshot)?)
}

pub fn replay_profile_with_firmware(
    path: &Path,
    firmware: &Path,
    key_file: &Path,
    profile: &profile::Profile,
) -> Result<discovery::Discovery, Error> {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    if value.get("requests").is_some() {
        let snapshot = serde_json::from_value(value)?;
        Ok(discovery::from_memory_capture_with_firmware(
            snapshot, firmware, key_file, profile,
        )?)
    } else {
        let snapshot = serde_json::from_value(value)?;
        Ok(discovery::from_snapshot_with_firmware(
            snapshot, firmware, key_file, profile,
        )?)
    }
}
