//! Host-side compiler checks. No camera access and no implicit firmware writes.
pub mod bindings;
mod bitmap_bindings;
mod bitmap_patches;
pub mod bundle;
mod exec_bindings;
mod graphics_bindings;
mod input_bindings;
pub mod layout;
pub mod linker;
mod marker;
pub mod menubuild;
mod native_card_bindings;
mod native_card_patches;
mod paint_bindings;
mod paint_patches;
mod private_text;
pub mod probe;
pub mod program;
mod time_bindings;
pub use marker::{build, build_dev, BuildReport, BuildRequest, BuildSource, DevCoreReport, Patch};

use nloader_profile::BuildMode;
use object::{Object, ObjectSection, ObjectSymbol};
use serde::Serialize;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CORE_HEADER: &str = include_str!("../../../../../core/include/nlr/services.h");
const CORE_LOAD_HEADER: &str = include_str!("../../../../../core/include/nlr/load.h");
const CORE_RUNTIME_HEADER: &str = include_str!("../../../../../core/include/nlr/runtime.h");
const CORE_MENU_HEADER: &str = include_str!("../../../../../core/include/nlr/menu.h");
const CORE_MENU_PAGE: &str = include_str!("../../../../../core/menu_page.c");
const CORE_MANIFEST_HEADER: &str = include_str!("../../../../../core/include/nlr/manifest.h");
const CORE_MANIFEST: &str = include_str!("../../../../../core/manifest.c");
const CORE_LOAD: &str = include_str!("../../../../../core/load.c");
const CORE_RUNTIME: &str = include_str!("../../../../../core/runtime.c");
const CORE_MENU_PREFILL: &str = include_str!("../../../../../core/menu_prefill.c");
const CORE_MENU_TRAMPOLINE: &str = include_str!("../../../../../core/menu_prefill_trampoline.S");

/// The blob's entry symbol: NLoader's page entry, where the code a user
/// reaches from the menu starts. Nothing jumps to the blob entry itself; the
/// firmware reaches the blob only through the generated menu records and
/// the prefill branch.
pub(crate) const BLOB_ENTRY: &str = "nlr_page_enter";

/// Core C and assembly sources compiled for every camera package, in link
/// order. Bindings are appended by the caller because they are mode-specific.
pub(crate) const CORE_SOURCES: &[(&str, &str)] = &[
    ("exec.c", include_str!("../../../../../core/exec.c")),
    ("api.c", include_str!("../../../../../core/api.c")),
    ("platform.c", include_str!("../../../../../core/platform.c")),
    ("journal.c", include_str!("../../../../../core/journal.c")),
    ("time.c", include_str!("../../../../../core/time.c")),
    ("input.c", include_str!("../../../../../core/input.c")),
    ("hook.c", include_str!("../../../../../core/hook.c")),
    (
        "file_store.c",
        include_str!("../../../../../core/file_store.c"),
    ),
    (
        "program_context.S",
        include_str!("../../../../../core/program_context.S"),
    ),
    ("load.c", CORE_LOAD),
    ("manifest.c", CORE_MANIFEST),
    ("runtime.c", CORE_RUNTIME),
    ("resource.c", include_str!("../../../../../core/resource.c")),
    ("menu_prefill.c", CORE_MENU_PREFILL),
    ("menu_prefill_trampoline.S", CORE_MENU_TRAMPOLINE),
    ("menu_page.c", CORE_MENU_PAGE),
];

/// Native transactions and state recovery are linked only when the audited
/// Exec profile declares them. Smaller stages retain their existing code.
pub(crate) const CORE_NATIVE_CARD_SOURCES: &[(&str, &str)] = &[
    (
        "card_state.c",
        include_str!("../../../../../core/card_state.c"),
    ),
    (
        "native_card.c",
        include_str!("../../../../../core/native_card.c"),
    ),
    (
        "native_card_state.c",
        include_str!("../../../../../core/native_card_state.c"),
    ),
];

/// Core headers staged into the compile include directory.
pub(crate) const CORE_HEADERS: &[(&str, &str)] = &[
    (
        "graphics.h",
        include_str!("../../../../../core/include/nlr/graphics.h"),
    ),
    (
        "native_graphics.h",
        include_str!("../../../../../core/include/nlr/native_graphics.h"),
    ),
    (
        "graphics_runtime.h",
        include_str!("../../../../../core/include/nlr/graphics_runtime.h"),
    ),
    (
        "text.h",
        include_str!("../../../../../core/include/nlr/text.h"),
    ),
    ("services.h", CORE_HEADER),
    (
        "card.h",
        include_str!("../../../../../core/include/nlr/card.h"),
    ),
    (
        "exec.h",
        include_str!("../../../../../core/include/nlr/exec.h"),
    ),
    (
        "api.h",
        include_str!("../../../../../core/include/nlr/api.h"),
    ),
    (
        "platform.h",
        include_str!("../../../../../core/include/nlr/platform.h"),
    ),
    (
        "journal.h",
        include_str!("../../../../../core/include/nlr/journal.h"),
    ),
    (
        "time.h",
        include_str!("../../../../../core/include/nlr/time.h"),
    ),
    (
        "input.h",
        include_str!("../../../../../core/include/nlr/input.h"),
    ),
    ("load.h", CORE_LOAD_HEADER),
    (
        "stage0.h",
        include_str!("../../../../../core/include/nlr/stage0.h"),
    ),
    ("manifest.h", CORE_MANIFEST_HEADER),
    (
        "card_state.h",
        include_str!("../../../../../core/include/nlr/card_state.h"),
    ),
    (
        "native_card.h",
        include_str!("../../../../../core/include/nlr/native_card.h"),
    ),
    (
        "native_card_internal.h",
        include_str!("../../../../../core/include/nlr/native_card_internal.h"),
    ),
    ("runtime.h", CORE_RUNTIME_HEADER),
    (
        "paint.h",
        include_str!("../../../../../core/include/nlr/paint.h"),
    ),
    (
        "bitmap.h",
        include_str!("../../../../../core/include/nlr/bitmap.h"),
    ),
    ("menu.h", CORE_MENU_HEADER),
    (
        "resource.h",
        include_str!("../../../../../core/include/nlr/resource.h"),
    ),
];

/// This drive cannot be addressed by card services. Only neutral compiler
/// checks and modes that compile card access out may use this placeholder.
pub(crate) const UNCONFIGURED_CARD_ROOT: &str = "?:\\NLOADER\\";

pub(crate) struct CoreHeaderConfig {
    native_card: bool,
    bitmap: bool,
    paint: bool,
    private_text: bool,
    graphics: bool,
    arena_bytes: u32,
}

impl CoreHeaderConfig {
    pub(crate) fn from_profile(
        profile: &nloader_profile::Profile,
        mode: BuildMode,
    ) -> Result<Self> {
        Ok(Self {
            native_card: mode == BuildMode::Exec && profile.services.native_card.is_some(),
            bitmap: mode == BuildMode::Exec && profile.services.bitmap.is_some(),
            paint: mode == BuildMode::Exec && profile.services.paint.is_some(),
            private_text: mode != BuildMode::Marker && profile.menu.private_text.is_some(),
            graphics: mode == BuildMode::Exec && profile.services.graphics.is_some(),
            arena_bytes: nloader_profile::resolve_program_arena_bytes(
                profile.memory.program_arena_bytes,
            )
            .map_err(|e| Error::Object(e.to_string()))?,
        })
    }
}

impl Default for CoreHeaderConfig {
    fn default() -> Self {
        Self {
            native_card: false,
            bitmap: false,
            paint: false,
            private_text: false,
            graphics: false,
            arena_bytes: nloader_profile::DEFAULT_PROGRAM_ARENA_BYTES,
        }
    }
}

pub(crate) fn stage_core_headers(
    directory: &Path,
    card_root: &str,
    config: &CoreHeaderConfig,
) -> Result<()> {
    let include = directory.join("include/nlr");
    fs::create_dir_all(&include)?;
    for (name, text) in CORE_HEADERS {
        fs::write(include.join(name), text)?;
    }
    // Only the position-independent dev core includes it (compile_pic).
    fs::write(
        include.join("pic_hidden.h"),
        "#pragma GCC visibility push(hidden)\n",
    )?;
    // Profile validation only permits simple ASCII directory components;
    // backslashes are the only bytes requiring C-string escaping.
    let literal = card_root.replace('\\', "\\\\");
    fs::write(
        include.join("card_config.h"),
        format!(
            "/* Generated card root; ?: is inaccessible and only used without card access. */\n#ifndef NLR_CARD_CONFIG_H\n#define NLR_CARD_CONFIG_H\n#define NLR_CARD_ROOT \"{literal}\"\n#define NLR_HAS_NATIVE_CARD {}\n#define NLR_HAS_BITMAP {}\n#define NLR_HAS_PAINT {}\n#define NLR_HAS_PRIVATE_TEXT {}\n#define NLR_HAS_GRAPHICS {}\n#define NLR_PROGRAM_ARENA_BYTES {}u\n#endif\n",u8::from(config.native_card),u8::from(config.bitmap),u8::from(config.paint),u8::from(config.private_text),u8::from(config.graphics),config.arena_bytes
        ),
    )?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("compiler failed for {source_file}: {diagnostic}")]
    Compiler {
        source_file: String,
        diagnostic: String,
    },
    #[error("invalid camera object: {0}")]
    Object(String),
    #[error("output already exists: {0}")]
    OutputExists(PathBuf),
    #[error("invalid output directory: {0}")]
    InvalidOutput(PathBuf),
    #[error("report serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Profile(#[from] nloader_profile::Error),
    #[error(transparent)]
    Validation(#[from] nloader_profile::ValidationReport),
    #[error(transparent)]
    Firmware(#[from] nloader_firmware::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Serialize)]
pub struct ObjectReport {
    pub name: String,
    pub code_bytes: u64,
    pub readonly_bytes: u64,
    pub relocations: usize,
}

#[derive(Debug, Serialize)]
pub struct ToolchainReport {
    pub target: String,
    pub objects: Vec<ObjectReport>,
    /// Neutral checks do not select a card; they compile with the inaccessible
    /// placeholder and cannot establish storage behavior.
    pub storage_root: Option<String>,
    pub firmware_ready: bool,
}

/// Check the boundary required by the XIP loader before any linking occurs.
/// Relocations are reported, not applied; this is not a linker.
pub fn inspect_object(name: &str, bytes: &[u8]) -> Result<ObjectReport> {
    let file = object::File::parse(bytes).map_err(|e| Error::Object(e.to_string()))?;
    if file.format() != object::BinaryFormat::Elf
        || file.architecture() != object::Architecture::Aarch64
        || file.kind() != object::ObjectKind::Relocatable
        || !file.is_little_endian()
        || !file.is_64()
    {
        return Err(Error::Object(
            "expected a little-endian AArch64 ELF64 relocatable object".into(),
        ));
    }
    // COMMON symbols allocate writable storage only when linked, so inspecting
    // sections alone cannot establish the XIP restriction.
    if file.symbols().any(|symbol| symbol.is_common()) {
        return Err(Error::Object("XIP forbids COMMON storage".into()));
    }
    let mut report = ObjectReport {
        name: name.to_owned(),
        code_bytes: 0,
        readonly_bytes: 0,
        relocations: 0,
    };
    for section in file.sections() {
        let section_name = section.name().map_err(|e| Error::Object(e.to_string()))?;
        if let object::SectionFlags::Elf { sh_flags } = section.flags() {
            let allocated = sh_flags & u64::from(object::elf::SHF_ALLOC) != 0;
            let writable = sh_flags & u64::from(object::elf::SHF_WRITE) != 0;
            let executable = sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0;
            if section.size() > 0 && allocated {
                if writable || section.kind() == object::SectionKind::UninitializedData {
                    return Err(Error::Object(format!(
                        "XIP forbids writable storage: {section_name}"
                    )));
                }
                if executable {
                    report.code_bytes += section.size();
                } else {
                    report.readonly_bytes += section.size();
                }
            }
        }
        report.relocations += section.relocations().count();
    }
    Ok(report)
}

/// Object file name for a staged source: "load.c" and "entry.S" both map to
/// the same basename with an "o" extension.
fn object_name(source: &str) -> String {
    let mut name = source.to_owned();
    let dot = name.rfind('.').unwrap_or(name.len());
    name.truncate(dot);
    name.push_str(".o");
    name
}

/// The stage macro passed to the C sources for a build mode (AUDIT B2): the
/// page behavior is stage-selected at compile time, so a missing define would
/// silently compile the loading path away. The blob hash difference between
/// stages is the machine-checkable discriminator.
pub fn stage_defines(mode: BuildMode) -> &'static [&'static str] {
    match mode {
        BuildMode::Marker => &["-DNLR_STAGE_MARKER"],
        BuildMode::HookOnly => &["-DNLR_STAGE_HOOK_ONLY"],
        BuildMode::Page => &["-DNLR_STAGE_PAGE"],
        BuildMode::LoadOnly => &["-DNLR_STAGE_LOAD_ONLY"],
        BuildMode::PrepareOnly => &["-DNLR_STAGE_PREPARE_ONLY"],
        BuildMode::Exec => &["-DNLR_STAGE_EXEC"],
    }
}

fn compile(
    compiler: &OsStr,
    directory: &Path,
    source: &str,
    output: &str,
    defines: &[&str],
) -> Result<()> {
    let result = Command::new(compiler)
        .current_dir(directory)
        .args([
            "--target=aarch64-none-elf",
            "-march=armv8-a",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-pic",
            "-ffunction-sections",
            "-fdata-sections",
            "-Os",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Iinclude",
            "-c",
        ])
        .args(defines)
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()?;
    if !result.status.success() {
        return Err(Error::Compiler {
            source_file: source.to_owned(),
            diagnostic: String::from_utf8_lossy(&result.stderr).trim().to_owned(),
        });
    }
    Ok(())
}

/// The same compilation for a loader that runs from memory it is loaded
/// into (dev firmware's CORE.NLC): position independent with hidden
/// symbols, as the program builder compiles, so code-to-data references are
/// ADRP-based and initialized pointers are ABS64 the loader can relocate.
pub(crate) fn compile_pic(
    compiler: &OsStr,
    directory: &Path,
    source: &str,
    output: &str,
    defines: &[&str],
) -> Result<()> {
    let result = Command::new(compiler)
        .current_dir(directory)
        .args([
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
            // A jump table's entries are offsets between sections, which
            // the program format has no relocation for.
            "-fno-jump-tables",
            "-ffunction-sections",
            "-fdata-sections",
            "-Os",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Iinclude",
            "-DNLR_DEV_CORE",
            // Declarations of other units' symbols are hidden too: without
            // it a position-independent build reaches them through a GOT
            // the relocation table cannot represent.
            "-include",
            "nlr/pic_hidden.h",
            "-c",
        ])
        .args(defines)
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()?;
    if !result.status.success() {
        return Err(Error::Compiler {
            source_file: source.to_owned(),
            diagnostic: String::from_utf8_lossy(&result.stderr).trim().to_owned(),
        });
    }
    Ok(())
}

/// Compile the actual diagnostic C and assembly sources and retain ELF objects.
/// The destination must not exist. No output is published if compilation fails.
pub fn check_toolchain(compiler: &OsStr, output: &Path) -> Result<ToolchainReport> {
    if output.symlink_metadata().is_ok() {
        return Err(Error::OutputExists(output.to_owned()));
    }
    if output.file_name().is_none() {
        return Err(Error::InvalidOutput(output.to_owned()));
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let stage = tempfile::Builder::new()
        .prefix(".nloader-compile-")
        .tempdir_in(parent)?;
    stage_core_headers(
        stage.path(),
        UNCONFIGURED_CARD_ROOT,
        &CoreHeaderConfig::default(),
    )?;
    for (name, text) in CORE_SOURCES {
        fs::write(stage.path().join(name), text)?;
    }
    fs::write(stage.path().join("bindings.c"), bindings::NEUTRAL)?;
    let mut objects = Vec::new();
    let mut sources: Vec<&str> = CORE_SOURCES.iter().map(|(name, _)| *name).collect();
    sources.push("bindings.c");
    for source in &sources {
        let object = object_name(source);
        // Neutral toolchain check: no stage define, hook-only semantics.
        compile(compiler, stage.path(), source, &object, &[])?;
        objects.push(inspect_object(
            source,
            &fs::read(stage.path().join(&object))?,
        )?);
    }
    let report = ToolchainReport {
        target: "aarch64-none-elf".into(),
        objects,
        storage_root: None,
        firmware_ready: false,
    };
    fs::write(
        stage.path().join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    // Reserve a new directory; create_dir never follows/overwrites an existing
    // path. Publish individual files only after both compilations pass.
    fs::create_dir(output)?;
    let publish = (|| -> std::io::Result<()> {
        let mut filenames: Vec<String> = sources.iter().map(|s| object_name(s)).collect();
        filenames.push("report.json".to_owned());
        for filename in &filenames {
            fs::rename(stage.path().join(filename), output.join(filename))?;
        }
        Ok(())
    })();
    if let Err(error) = publish {
        // This directory was created by this call and contains only our output.
        let _ = fs::remove_dir_all(output);
        return Err(error.into());
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_object_input() {
        assert!(inspect_object("bad", b"not an ELF").is_err());
    }

    #[test]
    fn refuses_existing_output_without_running_compiler() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            check_toolchain(OsStr::new("nonexistent-compiler"), directory.path()),
            Err(Error::OutputExists(_))
        ));
    }

    #[test]
    fn missing_compiler_leaves_no_output() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("result");
        assert!(check_toolchain(OsStr::new("nloader-no-such-compiler"), &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    #[ignore = "requires clang with an AArch64 backend"]
    fn compiles_c_and_assembly_and_rejects_writable_storage() {
        let directory = tempfile::tempdir().unwrap();
        let report = check_toolchain(OsStr::new("clang"), &directory.path().join("out")).unwrap();
        assert_eq!(report.objects.len(), CORE_SOURCES.len() + 1);
        // Core sources carry code; bindings only carry read-only neutral tables.
        for object in &report.objects[..CORE_SOURCES.len()] {
            assert!(object.code_bytes > 0, "{}", object.name);
        }
        assert_eq!(report.objects[CORE_SOURCES.len()].relocations, 0);
        assert!(report.objects[CORE_SOURCES.len()].readonly_bytes > 0);
        for (source, text) in [
            ("bss.c", "int state; int value(void) { return state; }"),
            ("data.c", "int state = 1; int value(void) { return state; }"),
            ("common.S", ".comm state,4,4"),
        ] {
            fs::write(directory.path().join(source), text).unwrap();
            compile(OsStr::new("clang"), directory.path(), source, "bad.o", &[]).unwrap();
            let bytes = fs::read(directory.path().join("bad.o")).unwrap();
            assert!(matches!(
                inspect_object(source, &bytes),
                Err(Error::Object(_))
            ));
        }
    }
}
