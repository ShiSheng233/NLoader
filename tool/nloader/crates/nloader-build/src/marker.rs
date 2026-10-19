use crate::{linker, Error, Result, CORE_SOURCES};
use nloader_firmware::{FirmwareIdentity, KeyFile, ModuleEdit};
use nloader_profile::{sha256, BuildMode, Profile, ValidationContext};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use crate::bindings;

/// What the build reads and what it therefore produces. A package input is
/// resealed into a package; a bare module input stays a module, which an
/// emulator can boot but nothing can flash.
pub enum BuildSource {
    /// The official package and the local key record that opens it.
    Package {
        firmware: PathBuf,
        key_file: PathBuf,
    },
    /// Only the decrypted target module, named as the profile names it. No
    /// container is opened, so the recorded package fingerprint is not
    /// checked and no installable output exists.
    Module { path: PathBuf },
}

/// The input once it has been read: a package that was opened with its key,
/// or a module on its own.
enum BuildInput {
    Package {
        raw: Vec<u8>,
        key: Box<nloader_firmware::FirmwareKey>,
        image: nloader_firmware::FirmwareImage,
    },
    Module {
        bytes: Vec<u8>,
    },
}

impl BuildInput {
    fn payload(&self, module_name: &str) -> Result<&[u8]> {
        match self {
            Self::Package { image, .. } => Ok(image.payload(module_name)?),
            Self::Module { bytes } => Ok(bytes),
        }
    }
    /// The package bytes, or `None` when only a module was supplied: the
    /// recorded package fingerprint then has nothing to be compared with.
    fn package(&self) -> Option<&[u8]> {
        match self {
            Self::Package { raw, .. } => Some(raw),
            Self::Module { .. } => None,
        }
    }
    fn input_bytes(&self) -> &[u8] {
        match self {
            Self::Package { raw, .. } => raw,
            Self::Module { bytes } => bytes,
        }
    }
}

impl BuildSource {
    /// The package this source reads, or `None` for a module-only source.
    pub fn firmware(&self) -> Option<&Path> {
        match self {
            Self::Package { firmware, .. } => Some(firmware),
            Self::Module { .. } => None,
        }
    }
    /// The key record that opens the package, or `None` without one.
    pub fn key_file(&self) -> Option<&Path> {
        match self {
            Self::Package { key_file, .. } => Some(key_file),
            Self::Module { .. } => None,
        }
    }
}

pub struct BuildRequest {
    pub profile: PathBuf,
    pub source: BuildSource,
    pub compiler: OsString,
    pub mode: BuildMode,
    pub output: PathBuf,
    /// A release bundle directory, placed into the
    /// profile's `services.platform.bundle` span. Execution builds only.
    pub bundle: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct Patch {
    /// Runtime address of the edit, or null for file-only edits that are
    /// never loaded to memory (the eg trailer version literal).
    pub site: Option<u64>,
    pub file_offset: u64,
    pub kind: &'static str,
    pub stock: Vec<u8>,
    pub new: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct BuildReport {
    pub model: String,
    pub firmware: String,
    pub mode: BuildMode,
    /// The explicit profile root, or None for a non-card stage compiled with
    /// the inaccessible placeholder. Card-reading stages always have a root.
    pub storage_root: Option<String>,
    pub input_sha256: String,
    pub output_sha256: String,
    pub blob_sha256: String,
    pub entry: u64,
    pub sections: Vec<linker::LinkedSection>,
    pub output: PathBuf,
    pub manifest: PathBuf,
    pub report: PathBuf,
    /// Counts derived from the actual patch list, not from hand-written
    /// strings: the report cannot drift from what was really changed.
    pub patch_counts: BTreeMap<&'static str, usize>,
    /// True when at least one version literal was applied.
    pub version_bumped: bool,
    /// True when the package is the intended flash artifact for its mode
    /// (hook-only and later rungs); marker packages are inert by design.
    pub installable: bool,
    pub notes: Vec<&'static str>,
    /// The release bundle the build placed, when it was given one.
    pub bundle: Option<crate::bundle::BundleReport>,
    /// Dev firmware only: the core written beside the module.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_core: Option<DevCoreReport>,
}

/// The dev firmware's core: CORE.NLC.
#[derive(Debug, Clone, Serialize)]
pub struct DevCoreReport {
    pub output: PathBuf,
    pub sha256: String,
    pub image_bytes: usize,
    pub data_bytes: usize,
    pub bss_bytes: u64,
    pub relocations: usize,
    pub entry_offset: u64,
}

/// The core's data must be read-only once relocated: stage 0 loads it into
/// one region that ends up executable and read-only (exec.c, the flat
/// layout). The loader's sources hold no writable statics -- the module
/// build refuses them -- so a position-independent build may only add
/// relocated constant tables (.data.rel.ro); anything else writable, BSS
/// included, is refused here, and the description says data=readonly.
fn readonly_after_relocation(source: &str, bytes: &[u8]) -> Result<()> {
    use object::{Object, ObjectSection};
    let file = object::File::parse(bytes).map_err(|e| Error::Object(e.to_string()))?;
    for section in file.sections() {
        let name = section.name().map_err(|e| Error::Object(e.to_string()))?;
        if let object::SectionFlags::Elf { sh_flags } = section.flags() {
            let allocated = sh_flags & u64::from(object::elf::SHF_ALLOC) != 0;
            let writable = sh_flags & u64::from(object::elf::SHF_WRITE) != 0;
            if section.size() > 0
                && allocated
                && (section.kind() == object::SectionKind::UninitializedData
                    || (writable && !name.starts_with(".data.rel.ro")))
            {
                return Err(Error::Object(format!(
                    "the dev core forbids writable data: {name} in {source}"
                )));
            }
        }
    }
    Ok(())
}

/// The loader as CORE.NLC: the staged sources compiled position independent,
/// linked as a two-segment program whose entry is nlr_core_entry, packaged
/// as an NPLD v3 resident extension whose description names it the core for
/// stage 0 version 1 (core/include/nlr/stage0.h).
fn build_dev_core(
    compiler: &OsString,
    directory: &Path,
    sources: &[(String, String)],
    defines: &[&str],
    identity: &FirmwareIdentity,
    output: &Path,
) -> Result<(Vec<u8>, DevCoreReport)> {
    let mut objects = Vec::new();
    for (source, text) in sources {
        fs::write(directory.join(source), text)?;
        let object = format!("core-{}", crate::object_name(source));
        crate::compile_pic(compiler, directory, source, &object, defines)?;
        let bytes = fs::read(directory.join(&object))?;
        readonly_after_relocation(source, &bytes)?;
        objects.push(linker::ObjectInput {
            name: object.clone(),
            bytes,
        });
    }
    let linked = crate::program::link::link(&objects, "nlr_core_entry")?;
    let mut meta = format!(
        "id=core\nkind=extension\nname=NLoader core\nmin_abi=1\nstage0=1\ndata=readonly\ncore_abi={}\ntargets={}/{}\n",
        crate::program::MAX_ABI_VERSION,
        identity.model.to_ascii_lowercase(),
        identity.firmware
    )
    .into_bytes();
    while meta.len() % 8 != 0 {
        meta.push(0);
    }
    let declaration = crate::program::ProgramDeclaration {
        image: linked.image,
        data: linked.data,
        bss_size: u32::try_from(linked.bss_size)
            .map_err(|_| Error::Object("core BSS exceeds the header field".into()))?,
        entry_offset: u32::try_from(linked.entry)
            .map_err(|_| Error::Object("core entry exceeds the header field".into()))?,
        relocations: linked.relocations,
        abi_version: crate::program::MAX_ABI_VERSION,
        metadata: Some(meta),
    };
    let bytes = crate::program::package::package(
        crate::program::ProgramKind::ResourceExtension,
        &declaration,
    )?;
    let report = DevCoreReport {
        output: output.to_owned(),
        sha256: sha256(&bytes),
        image_bytes: declaration.image.len(),
        data_bytes: declaration.data.len(),
        bss_bytes: linked.bss_size,
        relocations: declaration.relocations.len(),
        entry_offset: linked.entry,
    };
    Ok((bytes, report))
}

/// Produce a camera package for the supported diagnostic modes. Marker keeps
/// the upper-layer core unreachable; the flashable rungs install the Setup
/// entry row and NLoader's own page, and no stock page is changed. Version
/// literals are applied whenever the profile declares them and `[updater]
/// bump_version` is true. Camera acceptance and execution are never claimed
/// by the build; they are on-body verification results.
pub fn build(request: &BuildRequest) -> Result<BuildReport> {
    build_inner(request, None)
}

/// Dev firmware: the module gets stage 0 only
/// (core/stage0.c) -- the boot checkpoint, DISP at power-on, the card's
/// answer, the start mark, the checks and the execution blocks -- and the
/// loader itself is written to `core_output` as CORE.NLC, an NPLD v3
/// resident extension built position independent, which stage 0 loads from
/// the card at every boot. The core has no menu integration: nothing in the
/// module points at it, so the Setup menu has no NLoader row on dev
/// firmware. Exec mode only.
pub fn build_dev(request: &BuildRequest, core_output: &Path) -> Result<BuildReport> {
    build_inner(request, Some(core_output))
}

/// Sources stage 0 is made of: its own file, the executor and what the
/// executor needs, the card reader and the card store, the generated
/// bindings. Everything else is the core's.
const STAGE0_SOURCES: &[&str] = &[
    "stage0.c",
    "exec.c",
    "program_context.S",
    "manifest.c",
    "file_store.c",
    "bindings.c",
    "exec_bindings.c",
];

fn build_inner(request: &BuildRequest, dev_core: Option<&Path>) -> Result<BuildReport> {
    if let Some(core) = dev_core {
        if request.mode != BuildMode::Exec {
            return Err(Error::Object("dev firmware is an Exec build".into()));
        }
        if core.symlink_metadata().is_ok() {
            return Err(Error::OutputExists(core.to_owned()));
        }
    }
    let manifest_path = request.output.with_extension("patch.json");
    let report_path = request.output.with_extension("build.json");
    if request.output == manifest_path || request.output == report_path {
        return Err(Error::InvalidOutput(request.output.clone()));
    }
    for path in [&request.output, &manifest_path, &report_path] {
        if path.symlink_metadata().is_ok() {
            return Err(Error::OutputExists(path.clone()));
        }
    }
    let profile = Profile::from_toml(&fs::read_to_string(&request.profile)?)?;
    profile.validate(request.mode).into_result()?;
    if dev_core.is_some() {
        profile.validate_dev_core().into_result()?;
    }
    if matches!(request.source, BuildSource::Package { .. }) {
        profile.validate_package_output().into_result()?;
    }
    let identity = FirmwareIdentity {
        model: profile.identity.model.clone(),
        firmware: profile.identity.firmware.clone(),
    };
    let module_name = profile
        .identity
        .eg_module
        .as_deref()
        .ok_or_else(|| Error::Object("profile lacks the target module".into()))?;
    let input = match &request.source {
        BuildSource::Package { firmware, key_file } => {
            let raw = fs::read(firmware)?;
            let key = KeyFile::load(key_file)?.for_identity(&identity)?;
            key.verify_stock_identity(&raw)?;
            let image = key.unpack(&raw)?;
            BuildInput::Package {
                raw,
                key: Box::new(key),
                image,
            }
        }
        // The only identity a bare module carries is its name: require it,
        // so the profile is still matched against something observed rather
        // than against itself.
        BuildSource::Module { path } => {
            if path.file_name().and_then(|name| name.to_str()) != Some(module_name) {
                return Err(Error::Object(format!(
                    "module file is not named {module_name}"
                )));
            }
            BuildInput::Module {
                bytes: fs::read(path)?,
            }
        }
    };
    let payload = input.payload(module_name)?;
    profile
        .validate_for(
            request.mode,
            &ValidationContext {
                model: &identity.model,
                firmware: &identity.firmware,
                package: input.package(),
                module_name,
                module: payload,
            },
        )
        .into_result()?;

    let base = profile
        .memory
        .link_base
        .ok_or_else(|| Error::Object("profile lacks link base".into()))?;
    let capacity = profile
        .memory
        .link_size
        .ok_or_else(|| Error::Object("profile lacks link capacity".into()))?;
    let stage = tempfile::tempdir()?;
    crate::stage_core_headers(
        stage.path(),
        profile
            .storage
            .root
            .as_deref()
            .unwrap_or(crate::UNCONFIGURED_CARD_ROOT),
        &crate::CoreHeaderConfig::from_profile(&profile, request.mode)?,
    )?;
    // The menu feature is what the flashable rungs consist of: the NLoader
    // entry row, its page and the text-slot prefill trampoline. Validation
    // has required all three for these modes. Marker stays inert.
    // Dev firmware has no menu integration: its patches would point the
    // module at the core, which is not there until a card provides it.
    let menu_enabled = dev_core.is_none()
        && matches!(
            request.mode,
            BuildMode::HookOnly
                | BuildMode::Page
                | BuildMode::LoadOnly
                | BuildMode::PrepareOnly
                | BuildMode::Exec
        )
        && profile
            .menu
            .setup
            .as_ref()
            .and_then(|setup| setup.entry.as_ref())
            .is_some()
        && profile.menu.text_platform.is_some();
    // From load-only on, OK on the page row runs the row action that checks
    // a program; below that the row keeps the stock table.
    let row_action = matches!(
        request.mode,
        BuildMode::LoadOnly | BuildMode::PrepareOnly | BuildMode::Exec
    );
    let menu_spec = if menu_enabled {
        Some(crate::menubuild::MenuSpec::from_profile(
            &profile, payload, row_action,
        )?)
    } else {
        None
    };
    let mut objects = Vec::new();
    let mut sources: Vec<(String, String)> = CORE_SOURCES
        .iter()
        .map(|(name, text)| (name.to_string(), (*text).to_string()))
        .collect();
    if request.mode == BuildMode::Exec && profile.services.native_card.is_some() {
        sources.extend(
            crate::CORE_NATIVE_CARD_SOURCES
                .iter()
                .map(|(name, text)| (name.to_string(), (*text).to_string())),
        );
    }
    if request.mode == BuildMode::Exec && profile.boot_hooks.autoload.is_some() {
        sources.push((
            "boot_autoload.c".into(),
            include_str!("../../../../../core/boot_autoload.c").into(),
        ));
    }
    if request.mode == BuildMode::Exec && profile.services.paint.is_some() {
        sources.push((
            "paint.c".into(),
            include_str!("../../../../../core/paint.c").into(),
        ));
    }
    if request.mode == BuildMode::Exec && profile.services.bitmap.is_some() {
        sources.push((
            "bitmap.c".into(),
            include_str!("../../../../../core/bitmap.c").into(),
        ));
    }
    if menu_enabled && profile.menu.private_text.is_some() {
        sources.push((
            "text.c".into(),
            include_str!("../../../../../core/text.c").into(),
        ));
        sources.push((
            "private_text_native.S".into(),
            crate::private_text::assembly(&profile, payload)?,
        ));
        sources.push((
            "private_text_bindings.c".into(),
            crate::private_text::bindings(&profile),
        ));
    }
    if let Some(spec) = &menu_spec {
        let mut data = crate::menubuild::build_menu_data(spec, payload)?;
        if let Some(g) = &profile.services.graphics {
            crate::graphics_bindings::append_canvas(&mut data.page_elements, &profile, g, payload)?;
        }
        sources.push((
            "menu_data.c".into(),
            format!(
                "#include \"nlr/card_config.h\"\n{}",
                crate::menubuild::render_menu_source(&data)
            ),
        ));
    }
    if request.mode == BuildMode::Exec {
        if let Some(g) = &profile.services.graphics {
            for (name, source) in [
                ("graphics.c", include_str!("../../../../../core/graphics.c")),
                (
                    "native_graphics.c",
                    include_str!("../../../../../core/native_graphics.c"),
                ),
                (
                    "graphics_runtime.c",
                    include_str!("../../../../../core/graphics_runtime.c"),
                ),
            ] {
                sources.push((name.into(), source.into()));
            }
            sources.push((
                "graphics_bindings.c".into(),
                format!(
                    "#include \"nlr/native_graphics.h\"\n{}",
                    crate::graphics_bindings::generate(&profile, g)?
                ),
            ));
        }
    }
    if menu_enabled && request.mode == BuildMode::Exec {
        sources.push((
            "resource_bindings.c".into(),
            crate::menubuild::render_resource_source(&profile, payload)?,
        ));
    }
    sources.push((
        "bindings.c".into(),
        bindings::generate(&profile, menu_enabled),
    ));
    sources.push((
        "exec_bindings.c".into(),
        if matches!(request.mode, BuildMode::PrepareOnly | BuildMode::Exec) {
            crate::exec_bindings::generate(&profile)?
        } else {
            crate::exec_bindings::NEUTRAL.into()
        },
    ));
    // Dev firmware: the core is every source of the loader build but the
    // checkpoint entry (stage 0 makes the stock call and owns the entry),
    // with its own entry instead; the module gets stage 0's few.
    let core_sources: Vec<(String, String)> = if dev_core.is_some() {
        let mut core: Vec<(String, String)> = sources
            .iter()
            .filter(|(name, _)| name != "boot_autoload.c")
            .cloned()
            .collect();
        core.push((
            "core_entry.c".into(),
            include_str!("../../../../../core/core_entry.c").into(),
        ));
        let mut stage0: Vec<(String, String)> = vec![(
            "stage0.c".into(),
            include_str!("../../../../../core/stage0.c").into(),
        )];
        stage0.extend(
            sources
                .iter()
                .filter(|(name, _)| STAGE0_SOURCES.contains(&name.as_str()) && name != "stage0.c")
                .cloned(),
        );
        sources = stage0;
        core
    } else {
        Vec::new()
    };
    for (source, text) in &sources {
        let object = crate::object_name(source);
        fs::write(stage.path().join(source), text)?;
        crate::compile(
            &request.compiler,
            stage.path(),
            source,
            &object,
            crate::stage_defines(request.mode),
        )?;
        objects.push(linker::ObjectInput {
            name: object.clone(),
            bytes: fs::read(stage.path().join(&object))?,
        });
    }
    let entry_symbol = if dev_core.is_some() {
        "nlr_boot_autoload_checkpoint"
    } else {
        crate::BLOB_ENTRY
    };
    let mut linked = linker::link(&objects, base, capacity, entry_symbol)?;
    if menu_enabled && profile.menu.private_text.is_some() {
        crate::private_text::relocate(&profile, payload, &mut linked)?;
        crate::private_text::verify_copy(&profile, payload, &linked)?;
    }
    // Fill the new row's event-pointer slot with the linked row-table
    // address: the generated array carries a zero placeholder at
    // entry_index * 8 (menu data is linked, then filled, then hashed).
    if let Some(spec) = &menu_spec {
        let evptrs_va = *linked
            .symbols
            .get("nlr_menu_evptrs")
            .ok_or_else(|| Error::Object("linked image lacks nlr_menu_evptrs".into()))?;
        let row_table_va = *linked
            .symbols
            .get("nlr_menu_row_table")
            .ok_or_else(|| Error::Object("linked image lacks nlr_menu_row_table".into()))?;
        let slot = evptrs_va - base + u64::from(spec.entry_position()) * 8;
        let slot = usize::try_from(slot)
            .map_err(|_| Error::Object("event pointer slot exceeds host size".into()))?;
        linked.bytes[slot..slot + 8].copy_from_slice(&row_table_va.to_le_bytes());
        // The Apps row's slot takes its own table.
        if let Some(position) = spec.apps_position() {
            let apps_va = *linked
                .symbols
                .get("nlr_menu_apps_row_table")
                .ok_or_else(|| {
                    Error::Object("linked image lacks nlr_menu_apps_row_table".into())
                })?;
            let slot = usize::try_from(evptrs_va - base + u64::from(position) * 8)
                .map_err(|_| Error::Object("event pointer slot exceeds host size".into()))?;
            linked.bytes[slot..slot + 8].copy_from_slice(&apps_va.to_le_bytes());
        }
        // The generated declarations request storage alignment; verify the
        // linked placement honours it before any patch references the
        // addresses (the firmware reads the pointer array as 8-byte words).
        let mut aligned: Vec<(&str, u64)> = vec![
            ("nlr_menu_items", 4u64),
            ("nlr_menu_row_table", 8),
            ("nlr_menu_evptrs", 8),
        ];
        if spec.apps.is_some() {
            aligned.push(("nlr_menu_apps_row_table", 8));
        }
        if spec.own_page.is_some() {
            aligned.push(("nlr_page_items", 4));
            aligned.push(("nlr_page_evptrs", 8));
            aligned.push(("nlr_page_elements", 4));
            aligned.push(("nlr_page_handlers", 8));
            // The row table is generated whenever the page declares its
            // rows, lower rungs included; the event-pointer array reads it
            // as 8-byte words wherever it exists.
            if linked.symbols.contains_key("nlr_page_row_table") {
                aligned.push(("nlr_page_row_table", 8));
            }
        }
        for (symbol, alignment) in aligned {
            let va = *linked
                .symbols
                .get(symbol)
                .ok_or_else(|| Error::Object(format!("linked image lacks {symbol}")))?;
            if (va - base) % alignment != 0 {
                return Err(Error::Object(format!(
                    "linked {symbol} at {va:#x} misses its {alignment}-byte alignment"
                )));
            }
        }
    }
    let file_offset = profile
        .memory
        .address_to_offset(base, linked.bytes.len() as u64)
        .map_err(|error| Error::Object(error.to_string()))?;
    let offset = usize::try_from(file_offset)
        .map_err(|_| Error::Object("module offset exceeds host size".into()))?;
    let end = offset
        .checked_add(linked.bytes.len())
        .ok_or_else(|| Error::Object("blob end overflows".into()))?;
    let stock = payload
        .get(offset..end)
        .ok_or_else(|| Error::Object("blob exceeds module".into()))?;
    if stock.iter().any(|byte| *byte != 0) {
        return Err(Error::Object("blob destination is not zero-filled".into()));
    }
    let patch = Patch {
        site: Some(base),
        file_offset,
        kind: "blob",
        stock: stock.to_vec(),
        new: linked.bytes.clone(),
    };
    let mut patches = vec![patch];
    // The release bundle: a same-length edit of a span the stock module
    // keeps all zero (validated with the profile), inside the code the
    // camera copies to DRAM at boot.
    let mut bundle_report = None;
    if let Some(dir) = &request.bundle {
        if request.mode != BuildMode::Exec {
            return Err(Error::Object(
                "a release bundle needs the execution build".into(),
            ));
        }
        let span = profile
            .services
            .platform
            .as_ref()
            .and_then(|p| p.bundle.as_ref())
            .ok_or_else(|| Error::Object("the profile names no bundle span".into()))?;
        let (bytes, entries) = crate::bundle::build_bundle(dir)?;
        if bytes.len() > span.size as usize {
            return Err(Error::Object(format!(
                "the bundle is {} bytes; its span holds {}",
                bytes.len(),
                span.size
            )));
        }
        let file_offset = profile
            .memory
            .address_to_offset(span.address, bytes.len() as u64)
            .map_err(|error| Error::Object(error.to_string()))?;
        let start = usize::try_from(file_offset)
            .map_err(|_| Error::Object("bundle offset exceeds host size".into()))?;
        let stock = payload
            .get(start..start + bytes.len())
            .ok_or_else(|| Error::Object("bundle exceeds module".into()))?;
        if stock.iter().any(|byte| *byte != 0) {
            return Err(Error::Object(
                "bundle destination is not zero-filled".into(),
            ));
        }
        bundle_report = Some(crate::bundle::BundleReport {
            address: span.address,
            span: span.size,
            bytes: bytes.len() as u32,
            entries,
            copy_end: span.end(),
        });
        patches.push(Patch {
            site: Some(span.address),
            file_offset,
            kind: "bundle",
            stock: stock.to_vec(),
            new: bytes,
        });
        // The stock boot copy of the span's block stops before the span;
        // its end constant is rewritten to the span's end so the DRAM copy
        // the window maps holds the bundle too (validated with the profile:
        // inside the block, on the window's own alias, nothing else there).
        patches.extend(bundle_copy_patches(&profile, payload, span)?);
    }
    // The Setup cursor (menu.setup.cursor): the two stock writers' and the
    // restore's calls go to core, which stores stock row numbers. Only with
    // the Apps-first layout the mapping is written for (the bindings name
    // the same condition).
    if let Some(cursor) = profile.menu.setup.as_ref().and_then(|s| {
        s.cursor
            .as_ref()
            .filter(|_| menu_enabled && s.entry.is_some())
            .filter(|_| s.apps.as_ref().is_some_and(|a| a.index == 0))
    }) {
        for call in cursor.calls() {
            let target = *linked.symbols.get(call.entry).ok_or_else(|| {
                Error::Object(format!("Setup cursor entry {} is missing", call.entry))
            })?;
            patches.push(crate::native_card_patches::branch_patch(
                &profile,
                payload,
                "setup cursor",
                call.site,
                call.callee,
                target,
            )?);
        }
    }
    if menu_enabled && profile.menu.private_text.is_some() {
        patches.extend(crate::private_text::patches(
            &profile,
            payload,
            &linked.symbols,
        )?);
    }
    // Version literals apply in every mode once the profile declares them and
    // [updater] bump_version is true: without the bump the updater refuses a
    // same-version package, and the Firmware version screen is the visible
    // "flashed" proof. The profile owns the decision; the CLI carries no
    // override.
    let literals: &[nloader_profile::VersionLiteral] = if profile.updater.bump_version {
        &profile.updater.version_literals
    } else {
        &[]
    };
    for (index, version) in literals.iter().enumerate() {
        let length = version.stock.len();
        let site_offset = usize::try_from(version.eg_off)
            .map_err(|_| Error::Object("version offset exceeds host size".into()))?;
        let stock = payload
            .get(site_offset..site_offset + length)
            .ok_or_else(|| Error::Object("version literal exceeds module".into()))?;
        if stock != version.stock.as_bytes() {
            return Err(Error::Object(format!(
                "version literal [{index}] stock bytes differ from the module"
            )));
        }
        patches.push(Patch {
            site: profile
                .memory
                .offset_to_address(version.eg_off, length as u64)
                .ok(),
            file_offset: version.eg_off,
            kind: "literal",
            stock: stock.to_vec(),
            new: version.patched.as_bytes().to_vec(),
        });
    }
    // The menu entry row's page edit and the init-tail branch retarget: the
    // new bytes reference the linked menu symbols (AUDIT B2's stage define
    // makes the blob differ from the hook-only build).
    if let Some(spec) = &menu_spec {
        let (page_offset, page_stock, new_count) =
            crate::menubuild::menu_page_patch(spec, payload)?;
        let items_va = *linked
            .symbols
            .get("nlr_menu_items")
            .ok_or_else(|| Error::Object("linked image lacks nlr_menu_items".into()))?;
        let evptrs_va = *linked
            .symbols
            .get("nlr_menu_evptrs")
            .ok_or_else(|| Error::Object("linked image lacks nlr_menu_evptrs".into()))?;
        let mut new_page = items_va.to_le_bytes().to_vec();
        new_page.extend_from_slice(&evptrs_va.to_le_bytes());
        new_page.extend_from_slice(&(new_count as u16).to_le_bytes());
        patches.push(Patch {
            site: profile
                .memory
                .offset_to_address(page_offset, page_stock.len() as u64)
                .ok(),
            file_offset: page_offset,
            kind: "data",
            stock: page_stock,
            new: new_page,
        });

        // NLoader's own page: a window record and a page record written
        // into two all-zero holes of the stock window table. Nothing the
        // firmware uses is touched; the row above now opens this window
        // instead of doing nothing.
        if let Some(page) = &spec.own_page {
            let page_items_va = *linked
                .symbols
                .get("nlr_page_items")
                .ok_or_else(|| Error::Object("linked image lacks nlr_page_items".into()))?;
            let page_evptrs_va = *linked
                .symbols
                .get("nlr_page_evptrs")
                .ok_or_else(|| Error::Object("linked image lacks nlr_page_evptrs".into()))?;
            let page_elements_va = *linked
                .symbols
                .get("nlr_page_elements")
                .ok_or_else(|| Error::Object("linked image lacks nlr_page_elements".into()))?;
            let page_handlers_va = *linked
                .symbols
                .get("nlr_page_handlers")
                .ok_or_else(|| Error::Object("linked image lacks nlr_page_handlers".into()))?;
            let (window_offset, window_stock, window_new) =
                crate::menubuild::own_page_window_patch(page, payload, page_handlers_va)?;
            patches.push(Patch {
                site: profile
                    .memory
                    .offset_to_address(window_offset, window_stock.len() as u64)
                    .ok(),
                file_offset: window_offset,
                kind: "data",
                stock: window_stock,
                new: window_new,
            });
            if let Some((detail_offset, detail_stock, detail_new)) =
                crate::menubuild::own_detail_window_patch(page, payload, page_handlers_va)?
            {
                patches.push(Patch {
                    site: profile
                        .memory
                        .offset_to_address(detail_offset, detail_stock.len() as u64)
                        .ok(),
                    file_offset: detail_offset,
                    kind: "data",
                    stock: detail_stock,
                    new: detail_new,
                });
            }
            let (record_offset, record_stock, record_new) =
                crate::menubuild::own_page_record_patch(
                    page,
                    payload,
                    page_elements_va,
                    page_items_va,
                    page_evptrs_va,
                )?;
            patches.push(Patch {
                site: profile
                    .memory
                    .offset_to_address(record_offset, record_stock.len() as u64)
                    .ok(),
                file_offset: record_offset,
                kind: "data",
                stock: record_stock,
                new: record_new,
            });
        }

        let (branch_offset, branch_stock, _return_target) =
            crate::menubuild::menu_branch_patch(spec, payload)?;
        let call_site_va = spec.prefill_call_site;
        let trampoline_va = *linked
            .symbols
            .get("nlr_menu_prefill_trampoline")
            .ok_or_else(|| Error::Object("linked image lacks the prefill trampoline".into()))?;
        let delta = i64::try_from(trampoline_va)
            .map_err(|_| Error::Object("trampoline overflow".into()))?
            - i64::try_from(call_site_va)
                .map_err(|_| Error::Object("call site overflow".into()))?;
        if !(-(1 << 25)..(1 << 25)).contains(&(delta / 4)) {
            return Err(Error::Object("prefill branch out of range".into()));
        }
        let word = 0x9400_0000u32 | (((delta / 4) as u32) & 0x03ff_ffff);
        patches.push(Patch {
            site: Some(call_site_va),
            file_offset: branch_offset,
            kind: "branch",
            stock: branch_stock,
            new: word.to_le_bytes().to_vec(),
        });
    }

    if request.mode == BuildMode::Exec && dev_core.is_some() {
        // Stage 0 takes the boot checkpoint and nothing else.
        if let Some(call) = &profile.boot_hooks.autoload {
            let target = *linked
                .symbols
                .get("nlr_boot_autoload_checkpoint")
                .ok_or_else(|| Error::Object("stage 0 checkpoint is missing".into()))?;
            patches.push(crate::native_card_patches::branch_patch(
                &profile,
                payload,
                "boot autoload",
                call.call_site,
                call.callee,
                target,
            )?);
        }
    } else if request.mode == BuildMode::Exec {
        // The commit observer (services.platform.commit): each declared
        // stock commit call goes to core, which makes the same call.
        if let Some(commit) = profile
            .services
            .platform
            .as_ref()
            .and_then(|p| p.commit.as_ref())
        {
            let target = *linked
                .symbols
                .get("nlr_platform_gui_commit")
                .ok_or_else(|| Error::Object("commit observer is missing".into()))?;
            for site in &commit.sites {
                patches.push(crate::native_card_patches::branch_patch(
                    &profile,
                    payload,
                    "gui commit",
                    *site,
                    commit.callee,
                    target,
                )?);
            }
        }
        patches.extend(crate::native_card_patches::generate(
            &profile,
            payload,
            &linked.symbols,
        )?);
        // Each GUI turn's stock call goes to its generated entry, which
        // makes the same call from core (nlr_platform_gui_turn).
        if let Some(platform) = &profile.services.platform {
            for (n, turn) in platform.gui_turns.iter().enumerate() {
                let symbol = bindings::gui_turn_symbol(n);
                let target = *linked
                    .symbols
                    .get(&symbol)
                    .ok_or_else(|| Error::Object(format!("GUI turn entry {symbol} is missing")))?;
                patches.push(crate::native_card_patches::branch_patch(
                    &profile,
                    payload,
                    "gui turn",
                    turn.site,
                    turn.callee,
                    target,
                )?);
            }
        }
        if let Some(call) = &profile.boot_hooks.autoload {
            let target = *linked
                .symbols
                .get("nlr_boot_autoload_checkpoint")
                .ok_or_else(|| Error::Object("boot autoload checkpoint is missing".into()))?;
            patches.push(crate::native_card_patches::branch_patch(
                &profile,
                payload,
                "boot autoload",
                call.call_site,
                call.callee,
                target,
            )?);
        }
        patches.extend(crate::paint_patches::generate(
            &profile,
            payload,
            &linked.symbols,
        )?);
        patches.extend(crate::bitmap_patches::generate(
            &profile,
            payload,
            &linked.symbols,
        )?);
    }
    // No two edits may touch the same byte: each one was checked against
    // the stock bytes on its own, and an overlap would let one undo the
    // other unnoticed.
    let mut spans: Vec<(u64, u64, &str)> = patches
        .iter()
        .map(|p| (p.file_offset, p.file_offset + p.new.len() as u64, p.kind))
        .collect();
    spans.sort();
    if let Some(pair) = spans.windows(2).find(|pair| pair[1].0 < pair[0].1) {
        return Err(Error::Object(format!(
            "the {} edit overlaps the {} edit",
            pair[1].2, pair[0].2
        )));
    }
    let mut expected = payload.to_vec();
    expected[offset..end].copy_from_slice(&patches[0].new);
    for edit in &patches[1..] {
        let site = usize::try_from(edit.file_offset)
            .map_err(|_| Error::Object("edit offset exceeds host size".into()))?;
        expected[site..site + edit.new.len()].copy_from_slice(&edit.new);
    }
    let mut edits: Vec<ModuleEdit> = Vec::with_capacity(patches.len());
    for p in &patches {
        let offset = usize::try_from(p.file_offset)
            .map_err(|_| Error::Object("edit offset exceeds host size".into()))?;
        edits.push(ModuleEdit::Patch {
            module: module_name.into(),
            offset,
            bytes: p.new.clone(),
        });
    }
    let output = match &input {
        BuildInput::Package { raw, key, image } => {
            let output = key.pack(raw, &edits)?;
            let checked = key.unpack(&output)?;
            for module in image.modules() {
                let expected_payload = if module.name == module_name {
                    expected.as_slice()
                } else {
                    image.payload(&module.name)?
                };
                if checked.payload(&module.name)? != expected_payload {
                    return Err(Error::Object(
                        "output payload differs from the patch manifest".into(),
                    ));
                }
            }
            output
        }
        // The module is the output, so the independent step is reading the
        // file back after it is published (below) rather than reopening a
        // container.
        BuildInput::Module { .. } => expected.clone(),
    };
    // The explicit edit list above is the complete payload change set. The
    // container writer owns only CRC and digest updates outside those slices.
    // Notes are derived from the actual patch set (AUDIT B1): the counts and
    // the version line come from `patches`, never from the mode alone.
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for patch in &patches {
        *counts.entry(patch.kind).or_default() += 1;
    }
    let version_bumped = counts.contains_key("literal");
    let mut notes: Vec<&'static str> = Vec::new();
    if profile.storage.root.is_none() {
        notes.push("No storage root configured: this non-card stage uses an inaccessible ?: drive placeholder, with card access compiled out.");
    }
    if matches!(input, BuildInput::Module { .. }) {
        notes.push(
            "Module-only build: no container was opened, so the recorded package fingerprint was not checked and no flashable package exists. The output is the patched module for an emulator.",
        );
    }
    match request.mode {
        BuildMode::Marker => notes.push(
            "Inert build: the upper-layer core is packaged unreachable, so nothing of ours runs on the body.",
        ),
        BuildMode::HookOnly => notes.push(
            "Menu diagnostic build: Setup gains the NLoader row before Firmware version and OK opens NLoader's own page, titled from the row; its row keeps the prefilled label (stage HOOK_ONLY). No stock page is changed.",
        ),
        BuildMode::Page => notes.push(
            "Page diagnostic build: as hook-only, and entering NLoader's page rewrites its row with the label plus 'W' (row widget found and re-bound) or 'X' (stage PAGE). No card access and no worker.",
        ),
        BuildMode::LoadOnly => notes.push(
            "Load-only diagnostic build: entering NLoader's page reads SAFE_MODE, MANIFEST and the gate from the card and the page lists up to 64 programs or why there are none; OK on a row checks that program's file (header, bounds, size, CRC) and opens its details and result. Nothing is executed. Every step is also recorded in the RAM trace ring (read over PTP) (stage LOAD_ONLY).",
        ),
        BuildMode::PrepareOnly => notes.push(
            "Preparation build: the foreground detail action queues a pinned worker and rechecks MANIFEST, SAFE_MODE and the selected file. Generic v2 foreground programs prepare their owned code/data blocks, BSS, relocations, permissions and cache; the fixed return probe prepares its owned page. Neither entry is called; successful cleanup restores permissions and releases the allocations, while cleanup failures retain them. V1 files cannot be prepared for execution. Resource details remain check-only; this build does not bind card_store or mount ownership and does not establish resource autoload or persistent settings. Not camera acceptance.",
        ),
        BuildMode::Exec if profile.services.native_card.is_some() => notes.push(
            "Execution build with the audited native FILESRV transaction backend, genuine reply observations, filesystem and volume locks, two-slot state recovery, and natural GUI checkpoints. Mount/owner changes and unconfirmed commits stop further loading or writes. Compilation and package checks do not establish native execution, power-loss behavior or physical-camera acceptance.",
        ),
        BuildMode::Exec => notes.push(
            "Execution build: the foreground detail action queues a pinned worker and rechecks MANIFEST, SAFE_MODE and the selected file. Generic v2 foreground programs validate segments and relocations, prepare owned code/data blocks, permissions and cache, then call their entry with the API table; return/exit results and cleanup are recorded. The fixed 16-byte return probe uses its separate closed calling convention and verifies the full 64-bit response. V1 files cannot execute. Resource details remain check-only; this build does not bind mount ownership and has no native two-slot state. Not camera acceptance.",
        ),
    }
    if request.mode == BuildMode::Exec && profile.services.native_card.is_none() {
        if profile.services.file_ops.open_write_create.is_some() {
            notes.push(
                "Ordinary-card state: the loader keeps SAFE_MODE, ENABLED and the interruption marker through the stock file services, so entering NLoader's page loads the extensions ENABLED names, in its order, once per boot. Presence is only reported when another file on the same card answers, and the marker carries its state in its content because this model has no checked delete, so an interrupted pass pauses the next boot. Writes are not atomic and saving ENABLED from the page is refused. A pass is carried on by the worker after every load it finishes, and by the menu task on a page visit, one of them at a time; so one visit finishes a pass whose extensions register nothing and clears its marker. An extension that registers a menu item needs a second visit: only the menu owner may publish it, and on the first visit the extension has not run yet, so the marker stays until then. The button escape asks for the same pause SAFE_MODE asks for, and on this body it is asked for by pressing OK on the NLoader row and taking DISP down before OK is released, holding it until the page appears: the menu does not act on OK while another button is already held, and a button taken down after the page has opened is too late. Nothing here is camera acceptance.",
            );
        } else {
            notes.push(
                "Resource autoload is unavailable: without the create/truncate open flags and the write wrapper the loader cannot record that a pass started, and it never starts one it cannot record.",
            );
        }
    }
    if request.mode == BuildMode::Exec && profile.services.code.is_some() {
        notes.push(
            "Firmware-code channel (ABI 5): a program may patch whole instructions inside the declared code window, through the writable alias of the pages the window translates into, and may install 16-byte detours whose overwritten bytes the loader keeps for removal. A hook is checked against the bytes the program was built for, and its handler must be executable code the loader owns: it outlives the call that installed it but never the memory it points into, so a foreground program's hooks are removed when its block goes back and only a resident extension can leave one in place. The cache maintenance uses the entry the profile names as its write-back, never the one a read ends with. The channel changes what the camera's own code does and nothing checks what the new code means.",
        );
    }
    match (version_bumped, profile.updater.version_literals.is_empty()) {
        (true, _) => {
            notes.push("Version literals applied: the flashed body reports the bumped version.");
        }
        (false, false) => {
            notes.push("Version literals declared but kept stock ([updater] bump_version = false); the package carries the stock version.");
        }
        (false, true) => notes.push("No version literals declared; version fields are stock."),
    }
    // Dev firmware: the core, built from the same staged sources.
    let dev = match dev_core {
        Some(path) => {
            let (bytes, core_report) = build_dev_core(
                &request.compiler,
                stage.path(),
                &core_sources,
                crate::stage_defines(request.mode),
                &identity,
                path,
            )?;
            notes.push(
                "Dev firmware: the module carries stage 0 only; the loader is CORE.NLC on the card (NLOADER/CORE.NLC), loaded and checked by stage 0 at every boot. No core, DISP at power-on, or a core whose last start never reported back: a stock boot. No NLoader row in the Setup menu.",
            );
            Some((path.to_owned(), bytes, core_report))
        }
        None => None,
    };
    let report = BuildReport {
        model: identity.model,
        firmware: identity.firmware,
        mode: request.mode,
        storage_root: profile.storage.root.clone(),
        input_sha256: sha256(input.input_bytes()),
        output_sha256: sha256(&output),
        blob_sha256: sha256(&linked.bytes),
        entry: linked.entry,
        sections: linked.sections,
        output: request.output.clone(),
        manifest: manifest_path.clone(),
        report: report_path.clone(),
        patch_counts: counts,
        version_bumped,
        installable: request.mode != BuildMode::Marker
            && matches!(request.source, BuildSource::Package { .. }),
        notes,
        bundle: bundle_report,
        dev_core: dev.as_ref().map(|(_, _, r)| r.clone()),
    };
    let mut outputs = vec![
        (manifest_path, serde_json::to_vec_pretty(&patches)?),
        (report_path, serde_json::to_vec_pretty(&report)?),
        (request.output.clone(), output),
    ];
    if let Some((path, bytes, _)) = dev {
        outputs.push((path, bytes));
    }
    publish(&outputs)?;
    // Read the published module back and compare it with the bytes this build
    // computed. The package path gets the same assurance by reopening its own
    // container above; a module has no container to reopen.
    if matches!(input, BuildInput::Module { .. }) && fs::read(&request.output)? != expected {
        return Err(Error::Object(
            "the published module differs from what this build computed".into(),
        ));
    }
    Ok(report)
}

/// The two edits that move the stock boot copy's end to the bundle span's
/// end: each site must hold its declared stock word; the new words keep
/// every bit of the stock MOVZ/MOVK but the immediate.
pub(crate) fn bundle_copy_patches(
    profile: &Profile,
    payload: &[u8],
    span: &nloader_profile::PlatformBundle,
) -> Result<Vec<Patch>> {
    let copy = span
        .copy
        .as_ref()
        .ok_or_else(|| Error::Object("the bundle span names no stock boot copy".into()))?;
    let words = copy
        .patched_words(span.end())
        .ok_or_else(|| Error::Object("the bundle copy end does not fit its pair".into()))?;
    let mut patches = Vec::new();
    for (n, (site, word)) in [copy.low_site, copy.high_site]
        .into_iter()
        .zip(words)
        .enumerate()
    {
        let file_offset = profile
            .memory
            .address_to_offset(site, 4)
            .map_err(|error| Error::Object(error.to_string()))?;
        let at = usize::try_from(file_offset)
            .map_err(|_| Error::Object("bundle copy offset exceeds host size".into()))?;
        let stock = payload
            .get(at..at + 4)
            .ok_or_else(|| Error::Object("bundle copy site exceeds module".into()))?;
        if copy.stock.get(4 * n..4 * n + 4) != Some(stock) {
            return Err(Error::Object(
                "bundle copy site does not hold the declared stock word".into(),
            ));
        }
        patches.push(Patch {
            site: Some(site),
            file_offset,
            kind: "bundle copy",
            stock: stock.to_vec(),
            new: word.to_le_bytes().to_vec(),
        });
    }
    Ok(patches)
}

fn publish(outputs: &[(PathBuf, Vec<u8>)]) -> Result<()> {
    let mut created = Vec::new();
    let result = (|| -> Result<()> {
        for (path, bytes) in outputs {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            fs::create_dir_all(parent)?;
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            temporary.write_all(bytes)?;
            temporary.as_file().sync_all()?;
            temporary
                .persist_noclobber(path)
                .map_err(|error| Error::Io(error.error))?;
            created.push(path);
        }
        Ok(())
    })();
    if result.is_err() {
        for path in created {
            let _ = fs::remove_file(path);
        }
    }
    result
}
