use crate::{Error, FirmwareIdentity, KeyFile, Module, ModuleEdit, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    pub schema: u32,
    pub container: String,
    pub identity: FirmwareIdentity,
    pub stock_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<PathBuf>,
    /// Reports the unpack result; packing always verifies the source again.
    #[serde(default)]
    pub header_digest_verified: Option<bool>,
    pub modules: Vec<Module>,
}

pub fn unpack_directory(
    firmware_path: &Path,
    key_file: &Path,
    identity: &FirmwareIdentity,
    output_dir: &Path,
) -> Result<PackageManifest> {
    if output_dir.exists() {
        return Err(Error::OutputExists);
    }
    let key = KeyFile::load(key_file)?.for_identity(identity)?;
    let stock = fs::read(firmware_path)?;
    key.verify_stock_identity(&stock)?;
    let image = key.unpack(&stock)?;
    let manifest = PackageManifest {
        schema: 1,
        container: key.scheme().into(),
        identity: identity.clone(),
        stock_sha256: hex::encode(Sha256::digest(&stock)),
        source_file: Some(source_file_reference(firmware_path, output_dir)?),
        header_digest_verified: Some(image.header_digest_verified()),
        modules: image.modules().to_vec(),
    };
    let encoded = toml::to_string_pretty(&manifest).map_err(|_| Error::Manifest)?;
    let parent = output_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staged = tempfile::tempdir_in(parent)?;
    fs::write(staged.path().join("package.toml"), encoded)?;
    fs::create_dir(staged.path().join("modules"))?;
    for module in image.modules() {
        // Names have passed directory validation. Exclusive creation also rejects
        // collisions on filesystems that treat letter case as equivalent.
        let mut payload = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(staged.path().join("modules").join(&module.name))?;
        payload.write_all(image.payload(&module.name)?)?;
    }
    // Reserve destination without replacing an existing directory or symlink.
    fs::create_dir(output_dir)?;
    if let Err(error) = fs::rename(staged.path(), output_dir) {
        let _ = fs::remove_dir(output_dir);
        return Err(error.into());
    }
    Ok(manifest)
}

pub fn pack_directory(
    input_dir: &Path,
    key_file: &Path,
    output_file: &Path,
) -> Result<PackageManifest> {
    if output_file.exists() {
        return Err(Error::OutputExists);
    }
    let mut manifest: PackageManifest =
        toml::from_str(&fs::read_to_string(input_dir.join("package.toml"))?)
            .map_err(|_| Error::Manifest)?;
    if manifest.schema != 1 {
        return Err(Error::Manifest);
    }
    let key = KeyFile::load(key_file)?.for_identity(&manifest.identity)?;
    if manifest.container != key.scheme() {
        return Err(Error::Manifest);
    }
    let source = input_dir.join(
        manifest
            .source_file
            .as_deref()
            .unwrap_or(Path::new("stock.bin")),
    );
    let raw = fs::read(source)?;
    key.verify_stock_identity(&raw)?;
    if manifest.stock_sha256 != hex::encode(Sha256::digest(&raw)) {
        return Err(Error::Manifest);
    }
    let image = key.unpack(&raw)?;
    manifest.header_digest_verified = Some(image.header_digest_verified());
    if image.modules() != manifest.modules {
        return Err(Error::Manifest);
    }
    let mut edits = Vec::new();
    for (index, module) in image.modules().iter().enumerate() {
        let payload_path = module_payload_path(&input_dir.join("modules"), index, module)?;
        let bytes = fs::read(payload_path)?;
        if bytes != image.payload(&module.name)? {
            edits.push(ModuleEdit::Replace {
                module: module.name.clone(),
                bytes,
            });
        }
    }
    let output = key.pack(&raw, &edits)?;
    let parent = output_file
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&output)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(output_file)
        .map_err(|error| Error::Io(error.error))?;
    Ok(manifest)
}

fn source_file_reference(source_file: &Path, output_dir: &Path) -> Result<PathBuf> {
    let source = source_file.canonicalize()?;
    let parent = output_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    let destination = parent.join(output_dir.file_name().ok_or(Error::Manifest)?);
    let source_parts: Vec<_> = source.components().collect();
    let destination_parts: Vec<_> = destination.components().collect();
    // Different drive prefixes cannot be represented by a relative reference.
    if source_parts.first() != destination_parts.first() {
        return Ok(source);
    }
    let common = source_parts
        .iter()
        .zip(&destination_parts)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in &destination_parts[common..] {
        relative.push("..");
    }
    for component in &source_parts[common..] {
        relative.push(component.as_os_str());
    }
    Ok(relative)
}

fn module_payload_path(directory: &Path, index: usize, module: &Module) -> Result<PathBuf> {
    let named = directory.join(&module.name);
    let numbered = directory.join(format!("{index:02}.bin"));
    if named == numbered {
        return Ok(named);
    }
    let named_exists = path_is_present(&named)?;
    let numbered_exists = path_is_present(&numbered)?;
    if named_exists && numbered_exists {
        return Err(Error::Directory(
            "both named and numbered module payload files exist",
        ));
    }
    Ok(if numbered_exists { numbered } else { named })
}

fn path_is_present(path: &Path) -> Result<bool> {
    // Dangling symlinks also occupy a name and must not mask an ambiguous input.
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
