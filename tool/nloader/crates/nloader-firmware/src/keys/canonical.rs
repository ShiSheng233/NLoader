use super::{AesRecord, KeyFile, KeyRecord, LegacyRecord};
use crate::{Error, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    schema: u32,
    materials: Materials,
    keys: Vec<Record>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Materials {
    #[serde(default, rename = "legacy-xor")]
    legacy: Option<LegacyMaterial>,
    #[serde(default, rename = "aes-ctr")]
    aes: Option<AesMaterial>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyMaterial {
    t1: String,
    t2: String,
    t3: String,
    self_check: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AesMaterial {
    key: String,
    iv: String,
    self_check: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    scheme: String,
    model: String,
    firmware: Vec<String>,
    firmware_sha256: BTreeMap<String, String>,
    #[serde(default)]
    k8: Option<String>,
    self_check: BTreeMap<String, String>,
}

pub(super) fn decode(value: Value) -> Result<KeyFile> {
    let file: File = serde_json::from_value(value).map_err(|_| Error::KeyFile)?;
    if file.schema != 1 {
        return Err(Error::KeyFile);
    }
    if let Some(material) = &file.materials.legacy {
        if material.self_check.len() != 3 {
            return Err(Error::KeyFile);
        }
        super::field::<256>(&material.t1, material.self_check.get("t1"))?;
        super::field::<256>(&material.t2, material.self_check.get("t2"))?;
        super::field::<256>(&material.t3, material.self_check.get("t3"))?;
    }
    if let Some(material) = &file.materials.aes {
        if material.self_check.len() != 2 {
            return Err(Error::KeyFile);
        }
        super::field::<32>(&material.key, material.self_check.get("key"))?;
        super::field::<16>(&material.iv, material.self_check.get("iv"))?;
    }
    let mut keys = Vec::new();
    let mut used_legacy = false;
    let mut used_aes = false;
    for record in file.keys {
        if record.self_check.len() != usize::from(record.k8.is_some()) {
            return Err(Error::KeyFile);
        }
        let mut checks = record.self_check;
        match record.scheme.as_str() {
            "legacy-xor" => {
                used_legacy = true;
                let material = file.materials.legacy.as_ref().ok_or(Error::KeyFile)?;
                checks.extend(material.self_check.clone());
                keys.push(KeyRecord::LegacyXor(LegacyRecord {
                    model: record.model,
                    firmware: record.firmware,
                    firmware_sha256: record.firmware_sha256,
                    t1: material.t1.clone(),
                    t2: material.t2.clone(),
                    t3: material.t3.clone(),
                    k8: record.k8.ok_or(Error::KeyFile)?,
                    self_check: checks,
                }));
            }
            "aes-ctr" => {
                used_aes = true;
                let material = file.materials.aes.as_ref().ok_or(Error::KeyFile)?;
                checks.extend(material.self_check.clone());
                keys.push(KeyRecord::AesCtr(AesRecord {
                    model: record.model,
                    firmware: record.firmware,
                    firmware_sha256: record.firmware_sha256,
                    key: material.key.clone(),
                    iv: material.iv.clone(),
                    k8: record.k8,
                    self_check: checks,
                }));
            }
            _ => return Err(Error::KeyFile),
        }
    }
    // Refuse orphan material rather than silently dropping it when saving.
    if file.materials.legacy.is_some() != used_legacy || file.materials.aes.is_some() != used_aes {
        return Err(Error::KeyFile);
    }
    Ok(KeyFile { keys })
}

pub(super) fn encode(file: &KeyFile) -> Result<Vec<u8>> {
    let mut materials = serde_json::Map::new();
    let mut records = Vec::new();
    for record in &file.keys {
        let (scheme, material, model, firmware, hashes, k8, k8_check) = match record {
            KeyRecord::LegacyXor(record) => (
                "legacy-xor",
                json!({
                    "t1": record.t1, "t2": record.t2, "t3": record.t3,
                    "self_check": {"t1": record.self_check.get("t1"), "t2": record.self_check.get("t2"), "t3": record.self_check.get("t3")},
                }),
                &record.model,
                &record.firmware,
                &record.firmware_sha256,
                Some(&record.k8),
                record.self_check.get("k8"),
            ),
            KeyRecord::AesCtr(record) => (
                "aes-ctr",
                json!({
                    "key": record.key, "iv": record.iv,
                    "self_check": {"key": record.self_check.get("key"), "iv": record.self_check.get("iv")},
                }),
                &record.model,
                &record.firmware,
                &record.firmware_sha256,
                record.k8.as_ref(),
                record.self_check.get("k8"),
            ),
        };
        if materials
            .get(scheme)
            .is_some_and(|previous| *previous != material)
        {
            return Err(Error::KeyFile);
        }
        materials.insert(scheme.into(), material);
        let mut record = json!({"scheme": scheme, "model": model, "firmware": firmware,
            "firmware_sha256": hashes, "self_check": {}});
        if let Some(k8) = k8 {
            record["k8"] = k8.clone().into();
            record["self_check"]["k8"] = k8_check.ok_or(Error::KeyFile)?.clone().into();
        }
        records.push(record);
    }
    serde_json::to_vec_pretty(&json!({"schema": 1, "materials": materials, "keys": records}))
        .map_err(|_| Error::KeyFile)
}
