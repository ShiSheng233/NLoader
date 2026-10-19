//! Recovery orchestration. Algorithm candidates remain in memory until every
//! input passes its applicable checks and the target digest has been reproduced.

use crate::{
    keys, recovery_signature, recovery_xor, signature, validate_body, Error, FirmwareIdentity,
    KeyFile, Result, HEADER,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize)]
pub struct RecoverySource {
    pub sha256: String,
    pub bytes: usize,
    pub module_count: usize,
    /// False for other models, whose signatures are outside this target's scope.
    pub target_signature_verified: bool,
}

/// Contains verification metadata only; never key bytes or seed candidates.
#[derive(Debug, Serialize)]
pub struct RecoveryReport {
    pub identity: FirmwareIdentity,
    pub key_file: PathBuf,
    pub sources: Vec<RecoverySource>,
    pub table_blocks: usize,
    pub table_source: &'static str,
    pub target_model_packages_verified: usize,
}

/// Recover a target model's key using additional packages for shared table
/// coverage. Extra packages may be other Legacy XOR models; only Z8/Z9 target
/// signatures are supported. Repeated files cannot add votes or coverage.
pub fn recover_key_file(
    firmware_path: &Path,
    identity: &FirmwareIdentity,
    additional_sources: &[PathBuf],
    output: &Path,
) -> Result<RecoveryReport> {
    recover(firmware_path, identity, additional_sources, None, output)
}

/// Use explicit, externally supplied tables instead of inferring them from
/// padding. All package checks and signature recovery are still mandatory.
pub fn recover_key_file_with_tables(
    firmware_path: &Path,
    identity: &FirmwareIdentity,
    additional_sources: &[PathBuf],
    table_file: &Path,
    output: &Path,
) -> Result<RecoveryReport> {
    recover(
        firmware_path,
        identity,
        additional_sources,
        Some(table_file),
        output,
    )
}

fn recover(
    firmware_path: &Path,
    identity: &FirmwareIdentity,
    additional_sources: &[PathBuf],
    table_file: Option<&Path>,
    output: &Path,
) -> Result<RecoveryReport> {
    if output.symlink_metadata().is_ok() {
        return Err(Error::OutputExists);
    }
    let model_id = match identity.model.as_str() {
        "Z8" => "2070",
        "Z9" => "1990",
        _ => return Err(Error::KeyIdentity),
    };
    if identity.firmware.trim().is_empty() {
        return Err(Error::KeyIdentity);
    }
    let mut images = Vec::new();
    let mut fingerprints = BTreeSet::new();
    for path in
        std::iter::once(firmware_path).chain(additional_sources.iter().map(PathBuf::as_path))
    {
        let raw = fs::read(path)?;
        crate::check_scheme(&raw)?;
        let hash = hex::encode(Sha256::digest(&raw));
        if fingerprints.insert(hash) {
            images.push(raw);
        }
    }
    let slices: Vec<_> = images.iter().map(Vec::as_slice).collect();
    let tables = match table_file {
        Some(path) => {
            let bytes = fs::read(path)?;
            match recovery_xor::from_json(&bytes) {
                Ok(tables) => tables,
                Err(_) => KeyFile::from_json(&bytes)?.xor_tables()?,
            }
        }
        None => recovery_xor::recover(&slices)?,
    };
    let target = tables.decrypt(&images[0]);
    let k8 = recovery_signature::recover(&target, &identity.model)?;
    let mut sources = Vec::new();
    for raw in &images {
        let plain = tables.decrypt(raw);
        let modules = validate_body(&plain[HEADER..])?;
        let same_model = modules.first().and_then(|module| module.name.get(2..6)) == Some(model_id);
        if same_model && signature(&plain[HEADER..], &k8).as_slice() != &plain[..20] {
            return Err(Error::Recovery(
                "same-model packages disagree on the signature key",
            ));
        }
        sources.push(RecoverySource {
            sha256: hex::encode(Sha256::digest(raw)),
            bytes: raw.len(),
            module_count: modules.len(),
            target_signature_verified: same_model,
        });
    }
    let encoded = keys::encode_recovered(
        identity, &images[0], &tables.t1, &tables.t2, &tables.t3, &k8,
    )?;
    // Exercise the same public key reader and full target verification used by
    // unpack/pack before any secret material is published.
    let key = KeyFile::from_json(&encoded)?.legacy_xor(identity)?;
    key.verify_stock_identity(&images[0])?;
    crate::unpack(&images[0], &key)?;
    keys::write_new_key_file(output, &encoded)?;
    Ok(RecoveryReport {
        identity: identity.clone(),
        key_file: output.to_owned(),
        target_model_packages_verified: sources
            .iter()
            .filter(|source| source.target_signature_verified)
            .count(),
        sources,
        table_blocks: 256,
        table_source: if table_file.is_some() {
            "provided"
        } else {
            "recovered"
        },
    })
}
