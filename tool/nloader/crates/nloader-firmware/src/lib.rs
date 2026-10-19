//! Validated Legacy XOR containers. No firmware or key material is embedded.
mod aes_container;
mod directory;
mod keys;
mod recovery;
mod recovery_signature;
mod recovery_xor;
pub use aes_container::{pack as pack_aes_ctr, unpack as unpack_aes_ctr};
pub use directory::{pack_directory, unpack_directory, PackageManifest};
pub use keys::{AesCtrKey, FirmwareIdentity, FirmwareKey, KeyFile, LegacyXorKey};
pub use recovery::{
    recover_key_file, recover_key_file_with_tables, RecoveryReport, RecoverySource,
};

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashSet;

const HEADER: usize = 32;
const TRAILER: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read or write firmware material: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid local key file")]
    KeyFile,
    #[error("no unique key matches the requested model and firmware")]
    KeyIdentity,
    #[error("unsupported or unrecognized firmware container")]
    UnsupportedContainer,
    #[error("invalid firmware directory: {0}")]
    Directory(&'static str),
    #[error("firmware checksum or key verification failed: {0}")]
    Integrity(&'static str),
    #[error("module name does not identify exactly one module")]
    Module,
    #[error("edit must be nonempty and remain inside the module payload")]
    EditRange,
    #[error("replacement length must equal the module payload length")]
    ReplacementLength,
    #[error("repacked firmware failed its output checks")]
    OutputVerification,
    #[error("output already exists")]
    OutputExists,
    #[error("invalid package manifest or preserved stock image")]
    Manifest,
    #[error("key recovery failed: {0}")]
    Recovery(&'static str),
    #[error("key recovery requires all 256 table blocks; covered {covered}, missing indices: {missing:?}; add more distinct legacy firmware packages")]
    RecoveryCoverage { covered: usize, missing: Vec<u8> },
    #[error("packing requires a verified signature key for this model")]
    MissingSignatureKey,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Module {
    pub name: String,
    /// Relative to the decrypted body, which starts at file offset 32.
    pub body_offset: usize,
    /// Includes the final two checksum bytes.
    pub length: usize,
}

impl Module {
    pub fn payload_length(&self) -> usize {
        self.length - 2
    }
}

pub struct FirmwareImage {
    plain: Vec<u8>,
    modules: Vec<Module>,
    body_offset: usize,
    header_digest_verified: bool,
}

impl FirmwareImage {
    pub fn header_digest_verified(&self) -> bool {
        self.header_digest_verified
    }
    pub fn modules(&self) -> &[Module] {
        &self.modules
    }
    pub fn plaintext(&self) -> &[u8] {
        &self.plain
    }
    pub fn payload(&self, name: &str) -> Result<&[u8]> {
        let module = find_module(&self.modules, name)?;
        let start = self.body_offset + module.body_offset;
        Ok(&self.plain[start..start + module.payload_length()])
    }
}

#[derive(Clone)]
pub enum ModuleEdit {
    Patch {
        module: String,
        offset: usize,
        bytes: Vec<u8>,
    },
    Replace {
        module: String,
        bytes: Vec<u8>,
    },
}

pub fn unpack(raw: &[u8], key: &LegacyXorKey) -> Result<FirmwareImage> {
    check_scheme(raw)?;
    let plain = xor(raw, key);
    let modules = validate_body(&plain[HEADER..])?;
    let expected_model = match key.model.as_str() {
        "Z8" => "2070",
        "Z9" => "1990",
        _ => return Err(Error::KeyIdentity),
    };
    if modules.first().and_then(|module| module.name.get(2..6)) != Some(expected_model) {
        return Err(Error::KeyIdentity);
    }
    if signature(&plain[HEADER..], &key.k8).as_slice() != &plain[..20] {
        return Err(Error::Integrity("header digest"));
    }
    Ok(FirmwareImage {
        plain,
        modules,
        body_offset: HEADER,
        header_digest_verified: true,
    })
}

/// Validates the stock image, applies payload edits, and validates the encrypted
/// result before returning it. Callers must not overwrite the original file.
pub fn pack(raw: &[u8], key: &LegacyXorKey, edits: &[ModuleEdit]) -> Result<Vec<u8>> {
    let mut image = unpack(raw, key)?;
    let body = &mut image.plain[HEADER..];
    apply_edits(body, &image.modules, edits)?;
    reseal(body, &image.modules);
    let digest = signature(body, &key.k8);
    image.plain[..20].copy_from_slice(&digest);
    let output = xor(&image.plain, key);
    let checked = unpack(&output, key)?;
    if checked.plain != image.plain || (edits.is_empty() && output != raw) {
        return Err(Error::OutputVerification);
    }
    Ok(output)
}

fn apply_edits(body: &mut [u8], modules: &[Module], edits: &[ModuleEdit]) -> Result<()> {
    for edit in edits {
        let (name, offset, bytes, replace) = match edit {
            ModuleEdit::Patch {
                module,
                offset,
                bytes,
            } => (module, *offset, bytes, false),
            ModuleEdit::Replace { module, bytes } => (module, 0, bytes, true),
        };
        let module = find_module(modules, name)?;
        if replace && bytes.len() != module.payload_length() {
            return Err(Error::ReplacementLength);
        }
        if bytes.is_empty()
            || offset
                .checked_add(bytes.len())
                .is_none_or(|end| end > module.payload_length())
        {
            return Err(Error::EditRange);
        }
        let start = module.body_offset + offset;
        body[start..start + bytes.len()].copy_from_slice(bytes);
    }
    Ok(())
}

fn find_module<'a>(modules: &'a [Module], name: &str) -> Result<&'a Module> {
    // Exact names only: a shortened historical selector must never pick another extent.
    let mut matches = modules.iter().filter(|module| module.name == name);
    let result = matches.next().ok_or(Error::Module)?;
    if matches.next().is_some() {
        return Err(Error::Module);
    }
    Ok(result)
}

fn check_scheme(raw: &[u8]) -> Result<()> {
    if raw.get(HEADER..HEADER + 32) != Some(&[b' '; 32]) {
        return Err(Error::UnsupportedContainer);
    }
    Ok(())
}

fn xor(raw: &[u8], key: &LegacyXorKey) -> Vec<u8> {
    let mut result = raw.to_vec();
    for (i, byte) in result[HEADER..].iter_mut().enumerate().skip(32) {
        *byte ^= key.t1[i & 255] ^ key.t2[(i >> 8) & 255] ^ key.t3[(i >> 16) & 255];
    }
    result
}

fn u32_at(bytes: &[u8], offset: usize) -> usize {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}

fn parse_directory(body: &[u8]) -> Result<Vec<Module>> {
    parse_directory_layout(body, false)
}

fn parse_directory_layout(body: &[u8], aligned: bool) -> Result<Vec<Module>> {
    if body.len() < 96 {
        return Err(Error::Directory("truncated body"));
    }
    let count = u32_at(body, 32);
    let directory_size = u32_at(body, 36);
    if !(1..=64).contains(&count) || directory_size != 48 + 32 * count {
        return Err(Error::Directory("invalid count or directory size"));
    }
    let end = body.len() - TRAILER;
    if directory_size + 2 * count > end || body[40..48] != [0; 8] {
        return Err(Error::Directory(
            "invalid directory bounds or reserved bytes",
        ));
    }
    let mut expected = directory_size;
    let mut names = HashSet::new();
    let mut modules = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 48 + 32 * index;
        let name_bytes = &body[offset..offset + 16];
        let name_end = name_bytes
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |i| i + 1);
        let name_bytes = &name_bytes[..name_end];
        if name_bytes.len() < 3
            || !name_bytes[0].is_ascii_alphanumeric() && name_bytes[0] != b'_'
            || !name_bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'.')
        {
            return Err(Error::Directory("invalid module name"));
        }
        let name =
            String::from_utf8(name_bytes.to_vec()).map_err(|_| Error::Directory("invalid name"))?;
        if !names.insert(name.clone()) {
            return Err(Error::Directory("duplicate module names"));
        }
        let start = u32_at(body, offset + 16);
        let length = u32_at(body, offset + 20);
        if body[offset + 24..offset + 32] != [0; 8]
            || length < 2
            || !valid_gap(body, expected, start, aligned)
            || start.checked_add(length).is_none_or(|value| value > end)
        {
            return Err(Error::Directory("invalid module extent or reserved bytes"));
        }
        expected = start + length;
        modules.push(Module {
            name,
            body_offset: start,
            length,
        });
    }
    if !valid_gap(body, expected, end, aligned) {
        return Err(Error::Directory("module extents do not cover body"));
    }
    Ok(modules)
}

fn validate_body(body: &[u8]) -> Result<Vec<Module>> {
    let modules = parse_directory(body)?;
    validate_checksums(body, modules)
}

fn validate_body_aligned(body: &[u8]) -> Result<Vec<Module>> {
    let modules = parse_directory_layout(body, true)?;
    validate_checksums(body, modules)
}

fn valid_gap(body: &[u8], expected: usize, next: usize, aligned: bool) -> bool {
    if expected == next {
        return true;
    }
    aligned
        && next % 16 == 0
        && next.checked_sub(expected).is_some_and(|gap| gap < 16)
        && body
            .get(expected..next)
            .is_some_and(|gap| gap.iter().all(|byte| *byte == 0))
}

fn validate_checksums(body: &[u8], modules: Vec<Module>) -> Result<Vec<Module>> {
    if body[..32] != [b' '; 32] || body[body.len() - 14..] != [0; 14] {
        return Err(Error::Integrity("space label or trailer padding"));
    }
    for module in &modules {
        let crc_offset = module.body_offset + module.payload_length();
        let expected = crc16(&body[module.body_offset..crc_offset]).to_be_bytes();
        if body[crc_offset..crc_offset + 2] != expected {
            return Err(Error::Integrity("module CRC"));
        }
    }
    let crc_offset = body.len() - TRAILER;
    if body[crc_offset..crc_offset + 2] != crc16(&body[..crc_offset]).to_be_bytes() {
        return Err(Error::Integrity("package CRC"));
    }
    Ok(modules)
}

/// CRC-16/CCITT polynomial 0x1021, initial value zero, no final XOR.
pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for byte in bytes {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            crc = (crc << 1) ^ if crc & 0x8000 != 0 { 0x1021 } else { 0 };
        }
    }
    crc
}

fn reseal(body: &mut [u8], modules: &[Module]) {
    for module in modules {
        let offset = module.body_offset + module.payload_length();
        let crc = crc16(&body[module.body_offset..offset]);
        body[offset..offset + 2].copy_from_slice(&crc.to_be_bytes());
    }
    let offset = body.len() - TRAILER;
    let crc = crc16(&body[..offset]);
    body[offset..offset + 2].copy_from_slice(&crc.to_be_bytes());
}

fn signature(body: &[u8], key: &[u8; 8]) -> [u8; 20] {
    let mut digest = Sha1::new();
    digest.update(body);
    digest.update(key);
    digest.finalize().into()
}
