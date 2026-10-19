use crate::{Error, FirmwareImage, ModuleEdit, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, path::Path};
mod canonical;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirmwareIdentity {
    pub model: String,
    pub firmware: String,
}

pub struct KeyFile {
    keys: Vec<KeyRecord>,
}

#[derive(Deserialize)]
#[serde(tag = "scheme")]
enum KeyRecord {
    #[serde(rename = "legacy-xor")]
    LegacyXor(LegacyRecord),
    #[serde(rename = "aes-ctr")]
    AesCtr(AesRecord),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRecord {
    model: String,
    firmware: Vec<String>,
    firmware_sha256: BTreeMap<String, String>,
    t1: String,
    t2: String,
    t3: String,
    k8: String,
    self_check: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AesRecord {
    model: String,
    firmware: Vec<String>,
    firmware_sha256: BTreeMap<String, String>,
    key: String,
    iv: String,
    #[serde(default)]
    k8: Option<String>,
    self_check: BTreeMap<String, String>,
}

pub struct LegacyXorKey {
    pub(crate) model: String,
    stock_sha256: [u8; 32],
    pub(crate) t1: [u8; 256],
    pub(crate) t2: [u8; 256],
    pub(crate) t3: [u8; 256],
    pub(crate) k8: [u8; 8],
}

pub struct AesCtrKey {
    pub(crate) model: String,
    stock_sha256: [u8; 32],
    pub(crate) key: [u8; 32],
    pub(crate) iv: [u8; 16],
    pub(crate) k8: Option<[u8; 8]>,
}

impl fmt::Debug for LegacyXorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyXorKey([redacted])")
    }
}
impl fmt::Debug for AesCtrKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AesCtrKey([redacted])")
    }
}

#[derive(Debug)]
pub enum FirmwareKey {
    LegacyXor(Box<LegacyXorKey>),
    AesCtr(AesCtrKey),
}

impl FirmwareKey {
    pub fn scheme(&self) -> &'static str {
        match self {
            Self::LegacyXor(_) => "legacy-xor",
            Self::AesCtr(_) => "aes-ctr",
        }
    }
    pub fn unpack(&self, raw: &[u8]) -> Result<FirmwareImage> {
        match self {
            Self::LegacyXor(key) => crate::unpack(raw, key),
            Self::AesCtr(key) => crate::unpack_aes_ctr(raw, key),
        }
    }
    pub fn pack(&self, raw: &[u8], edits: &[ModuleEdit]) -> Result<Vec<u8>> {
        match self {
            Self::LegacyXor(key) => crate::pack(raw, key, edits),
            Self::AesCtr(key) => crate::pack_aes_ctr(raw, key, edits),
        }
    }
    pub fn verify_stock_identity(&self, bytes: &[u8]) -> Result<()> {
        let expected = match self {
            Self::LegacyXor(key) => &key.stock_sha256,
            Self::AesCtr(key) => &key.stock_sha256,
        };
        verify_stock(bytes, expected)
    }
}

impl KeyFile {
    pub fn load(path: &Path) -> Result<Self> {
        Self::from_json(&std::fs::read(path)?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        // Parser diagnostics can contain input values; never expose them.
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Error::KeyFile)?;
        let file = canonical::decode(value)?;
        if file.keys.is_empty() {
            return Err(Error::KeyFile);
        }
        for record in &file.keys {
            let (model, firmware, hashes) = record.identity_fields();
            let supported = match record {
                KeyRecord::LegacyXor(_) => matches!(model, "Z8" | "Z9"),
                KeyRecord::AesCtr(_) => matches!(model, "Z6III" | "ZR"),
            };
            if !supported
                || firmware.is_empty()
                || firmware.iter().any(|version| version.trim().is_empty())
                || firmware.len() != hashes.len()
            {
                return Err(Error::KeyFile);
            }
            for version in firmware {
                record.decode(version)?;
            }
        }
        Ok(file)
    }

    pub fn for_identity(&self, identity: &FirmwareIdentity) -> Result<FirmwareKey> {
        let mut matches = self.keys.iter().filter(|record| {
            let (model, versions, _) = record.identity_fields();
            model == identity.model && versions.contains(&identity.firmware)
        });
        let record = matches.next().ok_or(Error::KeyIdentity)?;
        if matches.next().is_some() {
            return Err(Error::KeyIdentity);
        }
        record.decode(&identity.firmware)
    }

    pub fn legacy_xor(&self, identity: &FirmwareIdentity) -> Result<LegacyXorKey> {
        match self.for_identity(identity)? {
            FirmwareKey::LegacyXor(key) => Ok(*key),
            FirmwareKey::AesCtr(_) => Err(Error::KeyIdentity),
        }
    }

    pub fn aes_ctr(&self, identity: &FirmwareIdentity) -> Result<AesCtrKey> {
        match self.for_identity(identity)? {
            FirmwareKey::AesCtr(key) => Ok(key),
            FirmwareKey::LegacyXor(_) => Err(Error::KeyIdentity),
        }
    }

    /// Store one shared material set per container, with per-model signature
    /// records, using the single supported schema.
    pub fn write_canonical(&self, path: &Path) -> Result<()> {
        write_new_key_file(path, &canonical::encode(self)?)
    }

    pub(super) fn xor_tables(&self) -> Result<crate::recovery_xor::XorTables> {
        let mut result: Option<crate::recovery_xor::XorTables> = None;
        for record in &self.keys {
            if let KeyRecord::LegacyXor(record) = record {
                let tables = crate::recovery_xor::XorTables {
                    t1: field(&record.t1, record.self_check.get("t1"))?,
                    t2: field(&record.t2, record.self_check.get("t2"))?,
                    t3: field(&record.t3, record.self_check.get("t3"))?,
                };
                if result.as_ref().is_some_and(|previous| {
                    previous.t1 != tables.t1 || previous.t2 != tables.t2 || previous.t3 != tables.t3
                }) {
                    return Err(Error::KeyFile);
                }
                result = Some(tables);
            }
        }
        result.ok_or(Error::KeyFile)
    }
}

impl KeyRecord {
    fn identity_fields(&self) -> (&str, &[String], &BTreeMap<String, String>) {
        match self {
            Self::LegacyXor(record) => (&record.model, &record.firmware, &record.firmware_sha256),
            Self::AesCtr(record) => (&record.model, &record.firmware, &record.firmware_sha256),
        }
    }

    fn decode(&self, firmware: &str) -> Result<FirmwareKey> {
        let (_, _, hashes) = self.identity_fields();
        let stock_sha256 = hex::decode(hashes.get(firmware).ok_or(Error::KeyFile)?)
            .map_err(|_| Error::KeyFile)?
            .try_into()
            .map_err(|_| Error::KeyFile)?;
        match self {
            Self::LegacyXor(record) => {
                if record.self_check.len() != 4 {
                    return Err(Error::KeyFile);
                }
                Ok(FirmwareKey::LegacyXor(Box::new(LegacyXorKey {
                    model: record.model.clone(),
                    stock_sha256,
                    t1: field(&record.t1, record.self_check.get("t1"))?,
                    t2: field(&record.t2, record.self_check.get("t2"))?,
                    t3: field(&record.t3, record.self_check.get("t3"))?,
                    k8: field(&record.k8, record.self_check.get("k8"))?,
                })))
            }
            Self::AesCtr(record) => {
                if record.self_check.len() != 2 + usize::from(record.k8.is_some()) {
                    return Err(Error::KeyFile);
                }
                Ok(FirmwareKey::AesCtr(AesCtrKey {
                    model: record.model.clone(),
                    stock_sha256,
                    key: field(&record.key, record.self_check.get("key"))?,
                    iv: field(&record.iv, record.self_check.get("iv"))?,
                    k8: record
                        .k8
                        .as_ref()
                        .map(|value| field(value, record.self_check.get("k8")))
                        .transpose()?,
                }))
            }
        }
    }
}

fn field<const N: usize>(value: &str, checksum: Option<&String>) -> Result<[u8; N]> {
    let bytes = hex::decode(value).map_err(|_| Error::KeyFile)?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if checksum != Some(&actual) {
        return Err(Error::KeyFile);
    }
    bytes.try_into().map_err(|_| Error::KeyFile)
}

fn verify_stock(bytes: &[u8], expected: &[u8; 32]) -> Result<()> {
    if Sha256::digest(bytes).as_slice() != expected {
        return Err(Error::KeyIdentity);
    }
    Ok(())
}

impl LegacyXorKey {
    pub(crate) fn verify_stock_identity(&self, bytes: &[u8]) -> Result<()> {
        verify_stock(bytes, &self.stock_sha256)
    }
}

pub(super) fn encode_recovered(
    identity: &FirmwareIdentity,
    stock: &[u8],
    t1: &[u8; 256],
    t2: &[u8; 256],
    t3: &[u8; 256],
    k8: &[u8; 8],
) -> Result<Vec<u8>> {
    let mut fields = serde_json::json!({
        "scheme": "legacy-xor",
        "model": identity.model,
        "firmware": [&identity.firmware],
        "firmware_sha256": { &identity.firmware: hex::encode(Sha256::digest(stock)) },
        "self_check": {},
    });
    for (name, bytes) in [
        ("t1", t1.as_slice()),
        ("t2", t2.as_slice()),
        ("t3", t3.as_slice()),
        ("k8", k8.as_slice()),
    ] {
        fields[name] = hex::encode(bytes).into();
        fields["self_check"][name] = hex::encode(Sha256::digest(bytes)).into();
    }
    let record: KeyRecord = serde_json::from_value(fields).map_err(|_| Error::KeyFile)?;
    canonical::encode(&KeyFile { keys: vec![record] })
}

pub(super) fn write_new_key_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    // Validate again at the write boundary, avoiding partially usable key files.
    KeyFile::from_json(bytes)?;
    if path.symlink_metadata().is_ok() {
        return Err(Error::OutputExists);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    // NamedTempFile creates a mode-0600 file on Unix; persist keeps that mode.
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| Error::Io(error.error))?;
    Ok(())
}
