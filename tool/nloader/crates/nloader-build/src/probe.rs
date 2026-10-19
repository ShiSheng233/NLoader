//! The return probe's deliberately closed diagnostic subset of NPLD v2.
//! This does not package arbitrary applications or implement the general SDK.

use crate::{inspect_object, Error, Result};
use object::{Object, ObjectSection, ObjectSymbol};
use serde::Serialize;
use std::{ffi::OsString, fs, io::Write, path::PathBuf, process::Command};

pub const HEADER_SIZE: usize = 48;
pub const IMAGE_SIZE: usize = 16;
pub const FOREGROUND_KIND: u32 = 2;
pub const PROBE_FLAG: u32 = 1;
pub const PROBE_ABI_VERSION: u32 = 1;
const SOURCE: &str = include_str!("../../../../../core/probe.S");
const INSTRUCTIONS: [u32; 4] = [0x93c0_4400, 0xca00_3400, 0x910c_4400, 0xd65f_03c0];

pub struct ProbeBuildRequest {
    pub compiler: OsString,
    pub output: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct ProbeBuildReport {
    pub output: PathBuf,
    pub header_version: u16,
    pub image_bytes: usize,
    pub sha256: String,
    pub kind: &'static str,
    pub diagnostic_only: bool,
}

pub fn expected_response(challenge: u64) -> u64 {
    let rotated = challenge.rotate_right(17);
    (rotated ^ (rotated << 13)).wrapping_add(0x311)
}

pub fn image_bytes() -> [u8; IMAGE_SIZE] {
    let mut image = [0; IMAGE_SIZE];
    for (bytes, instruction) in image.chunks_exact_mut(4).zip(INSTRUCTIONS) {
        bytes.copy_from_slice(&instruction.to_le_bytes());
    }
    image
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// This exact envelope is intentionally narrower than the future v2 format:
/// neither data, BSS, relocations, alternative code nor an API-table entry is
/// accepted by the diagnostic execution path.
pub fn package_bytes() -> [u8; HEADER_SIZE + IMAGE_SIZE] {
    let mut bytes = [0; HEADER_SIZE + IMAGE_SIZE];
    bytes[..4].copy_from_slice(b"NPLD");
    bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    for (offset, value) in [
        (8, PROBE_FLAG),
        (12, IMAGE_SIZE as u32),
        (24, PROBE_ABI_VERSION),
        (28, crc32(&image_bytes())),
        (32, FOREGROUND_KIND),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[HEADER_SIZE..].copy_from_slice(&image_bytes());
    bytes
}

/// Require both the current file and the freshly read manifest declaration.
/// Rejecting every differing byte prevents a v1 load check or an arbitrary
/// v2 application from obtaining the probe's execution permission.
pub fn validate(bytes: &[u8], manifest_kind: u32) -> Result<()> {
    if manifest_kind != FOREGROUND_KIND {
        return Err(Error::Object(
            "return probe requires foreground manifest kind".into(),
        ));
    }
    if bytes != package_bytes() {
        return Err(Error::Object(
            "not the supported return-probe diagnostic".into(),
        ));
    }
    Ok(())
}

/// Compile the assembly, independently verify the resulting instructions,
/// and publish one deterministic file without replacing any existing path.
pub fn build(request: &ProbeBuildRequest) -> Result<ProbeBuildReport> {
    if request.output.symlink_metadata().is_ok() {
        return Err(Error::OutputExists(request.output.clone()));
    }
    if request.output.file_name().is_none() {
        return Err(Error::InvalidOutput(request.output.clone()));
    }
    let stage = tempfile::tempdir()?;
    fs::write(stage.path().join("probe.S"), SOURCE)?;
    let output = Command::new(&request.compiler)
        .current_dir(stage.path())
        .args([
            "--target=aarch64-none-elf",
            "-march=armv8-a",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-c",
            "probe.S",
            "-o",
            "probe.o",
        ])
        .output()?;
    if !output.status.success() {
        return Err(Error::Compiler {
            source_file: "probe.S".into(),
            diagnostic: String::from_utf8_lossy(&output.stderr).trim().into(),
        });
    }
    let object_bytes = fs::read(stage.path().join("probe.o"))?;
    let report = inspect_object("probe.o", &object_bytes)?;
    let object = object::File::parse(object_bytes.as_slice())
        .map_err(|error| Error::Object(error.to_string()))?;
    let text = object
        .section_by_name(".text")
        .ok_or_else(|| Error::Object("return probe lacks .text".into()))?;
    let image = text
        .data()
        .map_err(|error| Error::Object(error.to_string()))?;
    let entry_valid = object.symbols().any(|symbol| {
        symbol.name() == Ok("nlr_return_probe")
            && symbol.address() == 0
            && symbol.size() == IMAGE_SIZE as u64
            && symbol.section_index() == Some(text.index())
    });
    if report.code_bytes != IMAGE_SIZE as u64
        || report.readonly_bytes != 0
        || report.relocations != 0
        || image != image_bytes()
        || !entry_valid
    {
        return Err(Error::Object(
            "return probe must contain exactly the audited 16-byte entry".into(),
        ));
    }
    let bytes = package_bytes();
    validate(&bytes, FOREGROUND_KIND)?;
    let parent = request
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(&request.output)
        .map_err(|error| {
            if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::OutputExists(request.output.clone())
            } else {
                Error::Io(error.error)
            }
        })?;
    Ok(ProbeBuildReport {
        output: request.output.clone(),
        header_version: 2,
        image_bytes: IMAGE_SIZE,
        sha256: nloader_profile::sha256(&bytes),
        kind: "foreground",
        diagnostic_only: true,
    })
}
