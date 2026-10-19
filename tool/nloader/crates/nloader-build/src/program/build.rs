//! End-to-end general program build: compile C/assembly sources with the
//! host's AArch64 clang, link the objects into the two-segment PIC program,
//! package the v2 file, and optionally publish its MANIFEST entry. Outputs
//! are never replaced.

use serde::{Deserialize, Serialize};
use std::{ffi::OsString, fs, path::PathBuf, process::Command};

use crate::linker::ObjectInput;
use crate::program::link;
use crate::program::manifest::{manifest_file, ManifestEntry};
use crate::program::package::{self, ProgramDeclaration, MAX_ABI_VERSION};
use crate::program::{publish_outputs, reject_existing, ProgramKind};
use crate::{Error, Result};

/// The fixed file entry: `crt0.s` receives the API pointer in x0 and
/// tail-branches to the kind's API entry, so the file entry is the stub.
pub const DEFAULT_ENTRY_SYMBOL: &str = "_start";

/// The declaration part of a program build, read from a JSON file by the
/// CLI. `kind` decides the header's numeric kind, the MANIFEST kind string,
/// and which API entry must exist; `abi_version` defaults to the newest
/// table this SDK knows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramMeta {
    pub id: String,
    pub kind: ProgramKind,
    pub display_name: String,
    pub file: String,
    pub min_abi: u32,
    pub abi_version: Option<u32>,
    pub entry_symbol: Option<String>,
    pub models: Option<String>,
    /// Settings the NLoader page offers for the program; they go to a
    /// `.SET` file beside the program (same name), which the page rewrites
    /// in place and the program reads through the API.
    #[serde(default)]
    pub settings: Vec<ProgramSetting>,
    /// Write the program's own description into the file (NPLD header
    /// version 3), so a card needs no MANIFEST line for
    /// it. Needs a loader with ABI 7; older loaders refuse version 3, so it
    /// is asked for, not the default.
    #[serde(default)]
    pub describe: bool,
    #[serde(default)]
    pub description: ProgramDescription,
}

/// What a program says about itself beyond its MANIFEST fields (§8): the
/// role it plays, its names and descriptions per language, who made it,
/// the memory it wants reserved and the resources it uses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProgramDescription {
    /// `app` or `shell` for a foreground program, `extension` or `service`
    /// for a resident one; defaults to app / extension by kind.
    pub role: Option<String>,
    /// Names by language code ("zh": "新界面"); `display_name` is the
    /// default and the one MANIFEST-era loaders show.
    pub names: std::collections::BTreeMap<String, String>,
    pub summary: Option<String>,
    pub summaries: std::collections::BTreeMap<String, String>,
    pub version: Option<String>,
    pub author: Option<String>,
    pub licence: Option<String>,
    /// Bytes, or with a K or M suffix: taken for the program before it runs
    /// (ABI 7 mem_reserved).
    pub memory: Option<String>,
    /// Resources it claims, as "screen:rear", "input:all", "prop:psm.*".
    pub uses: Vec<String>,
    pub icon: Option<String>,
}

/// The metadata block of a version 3 header: "key=value" lines, LF,
/// NUL-padded to a multiple of 8. Values are one line each; the block is at
/// most 4096 bytes (core/include/nlr/load.h NLR_META_MAX).
pub fn metadata_block(meta: &ProgramMeta) -> Result<Vec<u8>> {
    let d = &meta.description;
    let role = match (d.role.as_deref(), meta.kind) {
        (None, ProgramKind::Foreground) => "app",
        (None, ProgramKind::ResourceExtension) => "extension",
        (Some(r @ ("app" | "shell")), ProgramKind::Foreground) => r,
        (Some(r @ ("extension" | "service")), ProgramKind::ResourceExtension) => r,
        (Some(other), _) => {
            return Err(Error::Object(format!(
                "role {other:?} does not fit the program's kind"
            )))
        }
    };
    let mut lines: Vec<(String, String)> = vec![
        ("id".into(), meta.id.clone()),
        ("kind".into(), role.into()),
        ("name".into(), meta.display_name.clone()),
    ];
    for (lang, name) in &d.names {
        lines.push((format!("name.{lang}"), name.clone()));
    }
    if let Some(v) = &d.summary {
        lines.push(("description".into(), v.clone()));
    }
    for (lang, v) in &d.summaries {
        lines.push((format!("description.{lang}"), v.clone()));
    }
    for (key, value) in [
        ("version", &d.version),
        ("author", &d.author),
        ("licence", &d.licence),
    ] {
        if let Some(v) = value {
            lines.push((key.into(), v.clone()));
        }
    }
    lines.push(("min_abi".into(), meta.min_abi.to_string()));
    if let Some(models) = &meta.models {
        lines.push(("targets".into(), models.clone()));
    }
    if let Some(memory) = &d.memory {
        let digits = memory.trim_end_matches(['K', 'k', 'M', 'm']);
        if digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || memory.len() > digits.len() + 1
        {
            return Err(Error::Object(format!(
                "memory {memory:?}: bytes, or a number with K or M"
            )));
        }
        lines.push(("memory".into(), memory.clone()));
    }
    if !d.uses.is_empty() {
        lines.push(("uses".into(), d.uses.join(",")));
    }
    for setting in &meta.settings {
        lines.push((
            "setting".into(),
            format!(
                "{}|{}|{}|{}",
                setting.key,
                setting.label,
                setting.choices.join(","),
                setting.default
            ),
        ));
    }
    if let Some(icon) = &d.icon {
        lines.push(("icon".into(), icon.clone()));
    }
    let mut block = Vec::new();
    for (key, value) in lines {
        if value.is_empty() || value.contains(['\n', '\r', '\0']) || value.len() > 256 {
            return Err(Error::Object(format!(
                "description field {key}: one line of 1..=256 bytes"
            )));
        }
        block.extend_from_slice(key.as_bytes());
        block.push(b'=');
        block.extend_from_slice(value.as_bytes());
        block.push(b'\n');
    }
    while block.len() % 8 != 0 {
        block.push(0);
    }
    if block.len() > package::META_MAX {
        return Err(Error::Object(format!(
            "the description is {} bytes; at most {}",
            block.len(),
            package::META_MAX
        )));
    }
    Ok(block)
}

/// One setting: the key the program asks for, the label the page shows,
/// the choices and the one it starts on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramSetting {
    pub key: String,
    pub label: String,
    pub choices: Vec<String>,
    #[serde(default)]
    pub default: u32,
}

/// Settings a program may declare, choices a setting may have, and the
/// row text the page has for "label: choice".
const SETTINGS_MAX: usize = 8;
const CHOICES_MAX: usize = 10;
const ROW_TEXT_MAX: usize = 50;

/// The `.SET` file: one `key|label|choice,choice|D` line per setting, D the
/// current choice as one digit just before the line end, so the page
/// changes a setting by overwriting that byte. None without settings.
pub fn settings_file(settings: &[ProgramSetting]) -> Result<Option<String>> {
    if settings.is_empty() {
        return Ok(None);
    }
    if settings.len() > SETTINGS_MAX {
        return Err(Error::Object(format!("at most {SETTINGS_MAX} settings")));
    }
    let text = |s: &str, max: usize, separators: &str| {
        !s.is_empty()
            && s.len() <= max
            && s.bytes()
                .all(|b| (0x20..0x7f).contains(&b) && !separators.contains(b as char))
    };
    let mut out = String::new();
    for (index, setting) in settings.iter().enumerate() {
        if !setting
            .key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || setting.key.is_empty()
            || setting.key.len() > 16
            || settings[..index].iter().any(|s| s.key == setting.key)
        {
            return Err(Error::Object(format!(
                "setting key {:?} must be 1..=16 of a-z 0-9 _, and unique",
                setting.key
            )));
        }
        if !text(&setting.label, 24, "|") {
            return Err(Error::Object(format!(
                "setting {:?}: the label must be 1..=24 printable ASCII without |",
                setting.key
            )));
        }
        if !(2..=CHOICES_MAX).contains(&setting.choices.len())
            || setting
                .choices
                .iter()
                .any(|c| !text(c, 16, "|,") || setting.label.len() + 2 + c.len() > ROW_TEXT_MAX)
            || setting.default as usize >= setting.choices.len()
        {
            return Err(Error::Object(format!(
                "setting {:?}: 2..={CHOICES_MAX} choices of 1..=16 printable ASCII without | or ,, \
                 and a default among them",
                setting.key
            )));
        }
        out.push_str(&format!(
            "{}|{}|{}|{}\n",
            setting.key,
            setting.label,
            setting.choices.join(","),
            setting.default
        ));
    }
    Ok(Some(out))
}

pub struct ProgramBuildRequest {
    pub compiler: OsString,
    pub declaration: ProgramMeta,
    /// C or assembly sources, compiled with the flags below.
    pub sources: Vec<PathBuf>,
    /// Prebuilt little-endian AArch64 ELF64 relocatable objects.
    pub objects: Vec<PathBuf>,
    /// Header search directories passed to --source compilations.
    pub include_dirs: Vec<PathBuf>,
    /// New .nlb destination; an existing path is refused.
    pub output: PathBuf,
    /// New MANIFEST destination holding this program's entry line.
    pub manifest_output: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct ProgramBuildReport {
    pub output: PathBuf,
    pub manifest: Option<PathBuf>,
    /// The settings file beside the program, when it declares settings.
    pub settings: Option<PathBuf>,
    pub id: String,
    pub kind: ProgramKind,
    pub image_bytes: usize,
    pub data_bytes: usize,
    pub bss_size: u32,
    pub entry_offset: u32,
    pub relocations: usize,
    pub sha256: String,
}

fn source_flags(kind: ProgramKind, extension: &str) -> Vec<&'static str> {
    let define = match kind {
        ProgramKind::Foreground => "-DNLR_PROGRAM_FOREGROUND",
        ProgramKind::ResourceExtension => "-DNLR_PROGRAM_EXTENSION",
    };
    // -fPIC makes code→data references ADRP-based and initialized pointers
    // ABS64; the loader selects the code or data base for each pointer.
    // hidden visibility keeps same-program data access direct instead of
    // going through a GOT the table cannot represent.
    if extension == "c" {
        return vec![
            "--target=aarch64-none-elf",
            "-march=armv8-a",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-common",
            "-fno-stack-protector",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fPIC",
            "-fvisibility=hidden",
            "-Os",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-c",
            define,
        ];
    }
    // Assembly goes through the preprocessor, so crt0.s can select the
    // program type with #ifdef.
    vec![
        "--target=aarch64-none-elf",
        "-march=armv8-a",
        "-x",
        "assembler-with-cpp",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-c",
        define,
    ]
}

/// Compile one source, verify it is a relocatable AArch64 object, and return
/// its bytes under a unique basename.
fn compile_source(
    compiler: &OsString,
    directory: &std::path::Path,
    source: &std::path::Path,
    include_dirs: &[std::path::PathBuf],
    kind: ProgramKind,
) -> Result<ObjectInput> {
    // The compiler runs inside the staging directory, so a caller-supplied
    // relative path must be resolved against the caller's directory first.
    let source = &source.canonicalize()?;
    let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Object(format!("unusable source path {}", source.display())))?;
    let extension = source
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase());
    let extension = extension.as_deref().unwrap_or_default();
    if !matches!(extension, "c" | "s") {
        return Err(Error::Object(format!(
            "unsupported source {}: expected .c, .s or .S",
            source.display()
        )));
    }
    let output = format!("{}.o", name);
    let mut include_flags = Vec::new();
    for include_dir in include_dirs {
        include_flags.push("-I".into());
        // The compiler runs in the staging directory; keep include paths
        // absolute for the same reason as the source path.
        include_flags.push(include_dir.canonicalize()?);
    }
    let result = Command::new(compiler)
        .current_dir(directory)
        .args(source_flags(kind, extension))
        .args(include_flags)
        .arg(source)
        .arg("-o")
        .arg(&output)
        .output()?;
    if !result.status.success() {
        return Err(Error::Compiler {
            source_file: name.to_owned(),
            diagnostic: String::from_utf8_lossy(&result.stderr).trim().into(),
        });
    }
    load_object(&output, &fs::read(directory.join(&output))?)
}

fn load_object(name: &str, bytes: &[u8]) -> Result<ObjectInput> {
    // The linker re-parses the object, so here it is only checked enough to
    // name failures before staging.
    object::File::parse(bytes)
        .map_err(|error| Error::Object(format!("invalid object {name}: {error}")))?;
    Ok(ObjectInput {
        name: name.to_owned(),
        bytes: bytes.to_vec(),
    })
}

/// Compile, link, package, and publish one program. Nothing is published
/// unless every stage passed, and no existing destination is replaced.
pub fn build(request: &ProgramBuildRequest) -> Result<ProgramBuildReport> {
    reject_existing(&request.output)?;
    if let Some(manifest) = &request.manifest_output {
        reject_existing(manifest)?;
    }
    let settings_content = settings_file(&request.declaration.settings)?;
    let settings_output = settings_content
        .as_ref()
        .map(|_| request.output.with_extension("SET"));
    if let Some(path) = &settings_output {
        reject_existing(path)?;
    }
    // A declaration must be usable on the camera even when the caller only
    // requests the NLB. Validate it before compilation or output creation.
    let manifest_content = manifest_file(&ManifestEntry {
        id: request.declaration.id.clone(),
        kind: request.declaration.kind,
        display_name: request.declaration.display_name.clone(),
        file: request.declaration.file.clone(),
        min_abi: request.declaration.min_abi,
        models: request.declaration.models.clone(),
        shell: request.declaration.description.role.as_deref() == Some("shell"),
    })?;
    if request.sources.is_empty() && request.objects.is_empty() {
        return Err(Error::Object(
            "a program build needs at least one source or object".into(),
        ));
    }
    let stage = tempfile::tempdir()?;
    let mut inputs = Vec::new();
    for source in &request.sources {
        inputs.push(compile_source(
            &request.compiler,
            stage.path(),
            source,
            &request.include_dirs,
            request.declaration.kind,
        )?);
    }
    for object_path in &request.objects {
        let name = object_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                Error::Object(format!("unusable object path {}", object_path.display()))
            })?;
        inputs.push(load_object(name, &fs::read(object_path)?)?);
    }
    let entry_symbol = request
        .declaration
        .entry_symbol
        .as_deref()
        .unwrap_or(DEFAULT_ENTRY_SYMBOL);
    let linked = link::link(&inputs, entry_symbol)?;
    check_entry_consistency(&linked, request.declaration.kind)?;
    let declaration = ProgramDeclaration {
        image: linked.image,
        data: linked.data,
        bss_size: u32::try_from(linked.bss_size)
            .map_err(|_| Error::Object("BSS exceeds the 32-bit header field".into()))?,
        entry_offset: u32::try_from(linked.entry)
            .map_err(|_| Error::Object("entry exceeds the 32-bit header field".into()))?,
        relocations: linked.relocations,
        abi_version: request.declaration.abi_version.unwrap_or(MAX_ABI_VERSION),
        metadata: if request.declaration.describe {
            Some(metadata_block(&request.declaration)?)
        } else {
            None
        },
    };
    let bytes = package::package(request.declaration.kind, &declaration)?;
    let mut outputs = Vec::new();
    if let Some(manifest) = &request.manifest_output {
        outputs.push((manifest.as_path(), manifest_content.as_bytes()));
    }
    outputs.push((request.output.as_path(), bytes.as_slice()));
    if let (Some(path), Some(content)) = (&settings_output, &settings_content) {
        outputs.push((path.as_path(), content.as_bytes()));
    }
    publish_outputs(&outputs)?;
    Ok(ProgramBuildReport {
        output: request.output.clone(),
        manifest: request.manifest_output.clone(),
        settings: settings_output.clone(),
        id: request.declaration.id.clone(),
        kind: request.declaration.kind,
        image_bytes: declaration.image.len(),
        data_bytes: declaration.data.len(),
        bss_size: declaration.bss_size,
        entry_offset: declaration.entry_offset,
        relocations: declaration.relocations.len(),
        sha256: nloader_profile::sha256(&bytes),
    })
}

/// PLAN 6.3: `entry_offset` points at the entry matching `kind`. With the
/// crt0 stub the file entry is `_start`, and the consistency check is that
/// exactly the kind's API entry exists in the program.
fn check_entry_consistency(linked: &link::ProgramLink, kind: ProgramKind) -> Result<()> {
    let required = kind.entry_symbol();
    let other = match kind {
        ProgramKind::Foreground => ProgramKind::ResourceExtension.entry_symbol(),
        ProgramKind::ResourceExtension => ProgramKind::Foreground.entry_symbol(),
    };
    if !linked.symbols.contains_key(required) {
        return Err(Error::Object(format!(
            "a {kind:?} program must define {required}"
        )));
    }
    if linked.symbols.contains_key(other) {
        return Err(Error::Object(format!(
            "both {required} and {other} are defined; the program type is ambiguous"
        )));
    }
    Ok(())
}
