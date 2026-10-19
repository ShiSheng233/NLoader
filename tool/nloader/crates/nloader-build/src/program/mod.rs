//! General NPLD v2 program packaging (PLAN 6.3 M2-T4): the two-segment PIC
//! program linker, the 64-byte execution header packager, MANIFEST line
//! generation, and the camera-program build flow.
//!
//! General program layout:
//! header → relocation table → image → data, `kind` 1 = resource_extension
//! and 2 = foreground, `flags` 0 for general programs, and a 12-byte
//! relocation table for code-to-data ADRP and absolute code/data pointers.
//! The diagnostic probe subset
//! (48-byte header, `flags` 1) stays in [`crate::probe`].

pub mod build;
pub mod link;
pub mod manifest;
pub mod package;

pub use build::{ProgramBuildReport, ProgramBuildRequest, ProgramMeta};
pub use link::ProgramLink;
pub use manifest::ManifestEntry;
pub use package::{
    ProgramDeclaration, Relocation, BLOCK_CAPACITY, HEADER_SIZE, KIND_FOREGROUND,
    KIND_RESOURCE_EXTENSION, MAX_ABI_VERSION, RELOCATION_ENTRY_BYTES, RELOCATION_KIND_ABS64,
    RELOCATION_KIND_ABS64_DATA, RELOCATION_KIND_ADRP,
};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};
use std::io::Write;

/// The two program kinds of PLAN 5.1/6.2. The numeric coding is fixed by the
/// M2-T4 header table; the MANIFEST kind string and the file header's numeric
/// `kind` are derived from the same value, so the two declarations cannot
/// disagree (PLAN 6.2: type mismatch is refused at load).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramKind {
    ResourceExtension,
    Foreground,
}

impl ProgramKind {
    /// The header's numeric `kind` (M2-T4 table).
    pub fn code(self) -> u32 {
        match self {
            ProgramKind::ResourceExtension => KIND_RESOURCE_EXTENSION,
            ProgramKind::Foreground => KIND_FOREGROUND,
        }
    }

    /// The MANIFEST kind string (PLAN 6.2).
    pub fn label(self) -> &'static str {
        match self {
            ProgramKind::ResourceExtension => "resource_extension",
            ProgramKind::Foreground => "foreground",
        }
    }

    /// The one API-table entry this kind may be executed through (PLAN 6.3:
    /// `entry_offset` points at the entry matching `kind`).
    pub fn entry_symbol(self) -> &'static str {
        match self {
            ProgramKind::ResourceExtension => "nlr_extension_init",
            ProgramKind::Foreground => "nlr_app_main",
        }
    }
}

/// Refuse a previously existing destination: formal outputs are never
/// replaced (AGENTS.md: an existing target must be rejected).
pub(crate) fn reject_existing(path: &std::path::Path) -> Result<()> {
    if path.symlink_metadata().is_ok() {
        return Err(Error::OutputExists(path.to_path_buf()));
    }
    if path.file_name().is_none() {
        return Err(Error::InvalidOutput(path.to_path_buf()));
    }
    Ok(())
}

/// Stage every requested file before publishing any of them. Each rename
/// refuses replacement; publication failures remove only files this call
/// created. This is not an atomic multi-file transaction across power loss.
pub(crate) fn publish_outputs(outputs: &[(&std::path::Path, &[u8])]) -> Result<()> {
    let mut destinations = std::collections::BTreeSet::new();
    let mut staged = Vec::new();
    for (path, bytes) in outputs {
        reject_existing(path)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent)?;
        let resolved = parent.canonicalize()?.join(
            path.file_name()
                .ok_or_else(|| Error::InvalidOutput(path.to_path_buf()))?,
        );
        if !destinations.insert(resolved.clone()) {
            return Err(Error::InvalidOutput(path.to_path_buf()));
        }
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(bytes)?;
        temporary.as_file().sync_all()?;
        staged.push((resolved, temporary));
    }
    publish_staged(staged)
}

fn publish_staged(staged: Vec<(std::path::PathBuf, tempfile::NamedTempFile)>) -> Result<()> {
    let mut created: Vec<std::path::PathBuf> = Vec::new();
    for (path, temporary) in staged {
        if let Err(error) = temporary.persist_noclobber(&path) {
            let failure = if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::OutputExists(path)
            } else {
                Error::Io(error.error)
            };
            for owned in created.iter().rev() {
                if let Err(cleanup) = std::fs::remove_file(owned) {
                    return Err(Error::Object(format!(
                        "{failure}; failed to remove this build's partial output {}: {cleanup}",
                        owned.display()
                    )));
                }
            }
            return Err(failure);
        }
        created.push(path);
    }
    Ok(())
}

#[cfg(test)]
mod publication_tests {
    use super::*;

    #[test]
    fn preparation_failure_and_aliases_publish_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("APP.NLB");
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"keep").unwrap();
        let manifest = blocker.join("MANIFEST");
        assert!(publish_outputs(&[(&output, b"program"), (&manifest, b"manifest")]).is_err());
        assert!(!output.exists());
        assert_eq!(std::fs::read(&blocker).unwrap(), b"keep");
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        let alias = dir.path().join("nested/../APP.NLB");
        assert!(publish_outputs(&[(&output, b"program"), (&alias, b"manifest")]).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn late_collision_preserves_existing_file_and_removes_only_own_output() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("MANIFEST");
        let second = dir.path().join("APP.NLB");
        let mut staged = Vec::new();
        for path in [&first, &second] {
            let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
            file.write_all(b"new").unwrap();
            staged.push((path.clone(), file));
        }
        // Another writer wins the final destination after preflight.
        std::fs::write(&second, b"other writer").unwrap();
        assert!(matches!(
            publish_staged(staged),
            Err(Error::OutputExists(_))
        ));
        assert!(!first.exists());
        assert_eq!(std::fs::read(second).unwrap(), b"other writer");
    }
}
