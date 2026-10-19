//! Independent, unlinked C layout evidence. No firmware linking or device reads.
use crate::{Error, Result, CORE_HEADERS};
use nloader_profile::{BuildMode, Profile};
use object::{Object, ObjectSection, ObjectSymbol, SectionFlags, SymbolSection};
use serde::Serialize;
use std::{collections::BTreeMap, ffi::OsStr, fs, path::Path};

const MAGIC: u64 = u64::from_le_bytes(*b"NLRLAY01");
const ABSENT: u64 = u64::MAX;
const SECTION: &str = ".rodata.nlr_runtime_layout";
// Expressions are compiled as C; none of the offsets below are host guesses.
const FIELDS: &[(&str, &str, &str)] = &[
    (
        "worker.id",
        "offsetof(struct nlr_runtime,load.worker.opaque)+NLR_WORKER_ID_OFFSET",
        "sizeof(uint32_t)",
    ),
    (
        "worker.name",
        "offsetof(struct nlr_runtime,load.worker.opaque)+NLR_WORKER_NAME_OFFSET",
        "NLR_TASK_NAME_SIZE",
    ),
    (
        "worker.self",
        "offsetof(struct nlr_runtime,load.worker.opaque)+NLR_WORKER_SELF_OFFSET",
        "sizeof(uint64_t)",
    ),
    (
        "worker.callback",
        "offsetof(struct nlr_runtime,load.worker.opaque)+NLR_WORKER_CALLBACK_OFFSET",
        "sizeof(uint64_t)",
    ),
    (
        "worker.flag",
        "offsetof(struct nlr_runtime,load.worker.opaque)+NLR_WORKER_FLAG_OFFSET",
        "sizeof(uint32_t)",
    ),
    (
        "load.svc",
        "offsetof(struct nlr_runtime,load.svc)",
        "sizeof(((struct nlr_runtime*)0)->load.svc)",
    ),
    (
        "load.state",
        "offsetof(struct nlr_runtime,load.state)",
        "sizeof(((struct nlr_runtime*)0)->load.state)",
    ),
    (
        "load.ready",
        "offsetof(struct nlr_runtime,load.ready)",
        "sizeof(((struct nlr_runtime*)0)->load.ready)",
    ),
    (
        "load.last_result",
        "offsetof(struct nlr_runtime,load.last_result)",
        "sizeof(((struct nlr_runtime*)0)->load.last_result)",
    ),
    (
        "load.stage",
        "offsetof(struct nlr_runtime,load.stage)",
        "sizeof(((struct nlr_runtime*)0)->load.stage)",
    ),
    (
        "trace.count",
        "offsetof(struct nlr_runtime,load.trace.count)",
        "sizeof(((struct nlr_runtime*)0)->load.trace.count)",
    ),
    (
        "trace.entries",
        "offsetof(struct nlr_runtime,load.trace.entries)",
        "sizeof(((struct nlr_runtime*)0)->load.trace.entries)",
    ),
    (
        "directory.count",
        "offsetof(struct nlr_runtime,directory.count)",
        "sizeof(((struct nlr_runtime*)0)->directory.count)",
    ),
    (
        "directory.usable",
        "offsetof(struct nlr_runtime,directory.usable)",
        "sizeof(((struct nlr_runtime*)0)->directory.usable)",
    ),
    (
        "directory_result",
        "offsetof(struct nlr_runtime,directory_result)",
        "sizeof(((struct nlr_runtime*)0)->directory_result)",
    ),
    (
        "checked",
        "offsetof(struct nlr_runtime,checked)",
        "sizeof(((struct nlr_runtime*)0)->checked)",
    ),
    (
        "check_result",
        "offsetof(struct nlr_runtime,check_result)",
        "sizeof(((struct nlr_runtime*)0)->check_result)",
    ),
    (
        "path",
        "offsetof(struct nlr_runtime,path)",
        "sizeof(((struct nlr_runtime*)0)->path)",
    ),
    (
        "program.prepared",
        "offsetof(struct nlr_runtime,load.program.prepared)",
        "sizeof(((struct nlr_runtime*)0)->load.program.prepared)",
    ),
    (
        "program.entry_started",
        "offsetof(struct nlr_runtime,load.program.entry_started)",
        "sizeof(((struct nlr_runtime*)0)->load.program.entry_started)",
    ),
    (
        "program.returned",
        "offsetof(struct nlr_runtime,load.program.returned)",
        "sizeof(((struct nlr_runtime*)0)->load.program.returned)",
    ),
    // The boot's autoload pass and its boot program (core/runtime.c): what
    // the QEMU boot fixture (tests/qemu/boot_start.py) reads beside the
    // card's own STATE.NLS and program log.
    (
        "autoload.phase",
        "offsetof(struct nlr_runtime,autoload.phase)",
        "sizeof(((struct nlr_runtime*)0)->autoload.phase)",
    ),
    (
        "autoload.result",
        "offsetof(struct nlr_runtime,autoload.result)",
        "sizeof(((struct nlr_runtime*)0)->autoload.result)",
    ),
    (
        "autoload.boot_escape",
        "offsetof(struct nlr_runtime,autoload.boot_escape)",
        "sizeof(((struct nlr_runtime*)0)->autoload.boot_escape)",
    ),
    (
        "autoload.boot_result",
        "offsetof(struct nlr_runtime,autoload.boot_result)",
        "sizeof(((struct nlr_runtime*)0)->autoload.boot_result)",
    ),
    (
        "autoload.boot_hold",
        "offsetof(struct nlr_runtime,autoload.boot_hold)",
        "sizeof(((struct nlr_runtime*)0)->autoload.boot_hold)",
    ),
    (
        "autoload.boot_decided",
        "offsetof(struct nlr_runtime,autoload.boot_decided)",
        "sizeof(((struct nlr_runtime*)0)->autoload.boot_decided)",
    ),
    (
        "autoload.boot_record",
        "offsetof(struct nlr_runtime,autoload.boot_record)",
        "sizeof(((struct nlr_runtime*)0)->autoload.boot_record)",
    ),
    (
        "autoload.boot_record_result",
        "offsetof(struct nlr_runtime,autoload.boot_record_result)",
        "sizeof(((struct nlr_runtime*)0)->autoload.boot_record_result)",
    ),
];
const POOL_FIELDS: &[(&str, &str, &str)] = &[
    (
        "private_text",
        "offsetof(struct nlr_runtime,private_text)",
        "sizeof(((struct nlr_runtime*)0)->private_text)",
    ),
    (
        "pool.owner",
        "offsetof(struct nlr_private_text_pool,owner)",
        "sizeof(((struct nlr_private_text_pool*)0)->owner)",
    ),
    (
        "pool.services",
        "offsetof(struct nlr_private_text_pool,services)",
        "sizeof(((struct nlr_private_text_pool*)0)->services)",
    ),
    (
        "pool.ready",
        "offsetof(struct nlr_private_text_pool,ready)",
        "sizeof(((struct nlr_private_text_pool*)0)->ready)",
    ),
    (
        "pool.failed",
        "offsetof(struct nlr_private_text_pool,failed)",
        "sizeof(((struct nlr_private_text_pool*)0)->failed)",
    ),
    (
        "pool.last_result",
        "offsetof(struct nlr_private_text_pool,last_result)",
        "sizeof(((struct nlr_private_text_pool*)0)->last_result)",
    ),
    (
        "pool.rejected_calls",
        "offsetof(struct nlr_private_text_pool,rejected_calls)",
        "sizeof(((struct nlr_private_text_pool*)0)->rejected_calls)",
    ),
    (
        "pool.descriptors",
        "offsetof(struct nlr_private_text_pool,descriptors)",
        "sizeof(((struct nlr_private_text_pool*)0)->descriptors)",
    ),
    (
        "pool.buffers",
        "offsetof(struct nlr_private_text_pool,buffers)",
        "sizeof(((struct nlr_private_text_pool*)0)->buffers)",
    ),
];

#[derive(Debug, Clone, Serialize)]
pub struct Field {
    pub offset: usize,
    pub bytes: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeLayout {
    pub schema: u32,
    pub target: &'static str,
    pub mode: BuildMode,
    pub feature_bits: u64,
    pub runtime_bytes: usize,
    pub pool_bytes: usize,
    pub registry_max_id: u32,
    pub trace_slots: usize,
    pub trace_entry_bytes: usize,
    pub descriptor_bytes: usize,
    pub descriptor_buffer_offset: usize,
    pub descriptor_length_offset: usize,
    pub descriptor_style_offset: usize,
    pub descriptor_reserved_offset: usize,
    pub descriptor_tail_offset: usize,
    pub pool_count: usize,
    pub buffer_bytes: usize,
    pub fields: BTreeMap<String, Field>,
    pub object_sha256: String,
    pub definition_sha256: String,
    pub headers_sha256: String,
    pub config_sha256: String,
    pub provided_layout: bool,
    pub physical_fresh: bool,
}
impl RuntimeLayout {
    pub fn field(&self, name: &str) -> Result<&Field> {
        self.fields
            .get(name)
            .ok_or_else(|| invalid(format!("layout field unavailable: {name}")))
    }
}
#[derive(Debug, Serialize)]
pub struct LayoutReport {
    pub layout: RuntimeLayout,
    pub compiler: String,
    pub mode_defines: Vec<String>,
    pub header_sha256: BTreeMap<String, String>,
    pub storage_root: Option<String>,
    pub generated_source_sha256: String,
    pub firmware_ready: bool,
}

fn invalid(text: impl Into<String>) -> Error {
    Error::Object(text.into())
}
fn mode_number(mode: BuildMode) -> u64 {
    match mode {
        BuildMode::Marker => 0,
        BuildMode::HookOnly => 1,
        BuildMode::Page => 2,
        BuildMode::LoadOnly => 3,
        BuildMode::PrepareOnly => 4,
        BuildMode::Exec => 5,
    }
}
fn decode_mode(value: u64) -> Result<BuildMode> {
    match value {
        0 => Ok(BuildMode::Marker),
        1 => Ok(BuildMode::HookOnly),
        2 => Ok(BuildMode::Page),
        3 => Ok(BuildMode::LoadOnly),
        4 => Ok(BuildMode::PrepareOnly),
        5 => Ok(BuildMode::Exec),
        _ => Err(invalid("unknown layout mode")),
    }
}
fn digest_words(hash: &str) -> Vec<u64> {
    hash.as_bytes()
        .chunks_exact(16)
        .map(|b| {
            let text = std::str::from_utf8(b).expect("hex digest");
            u64::from_str_radix(text, 16).expect("hex digest")
        })
        .collect()
}
fn words_digest(words: &[u64]) -> String {
    words.iter().map(|word| format!("{word:016x}")).collect()
}

pub fn preflight(output: &Path) -> Result<()> {
    if output.symlink_metadata().is_ok() {
        return Err(Error::OutputExists(output.to_path_buf()));
    }
    if output.file_name().is_none() {
        return Err(Error::InvalidOutput(output.to_path_buf()));
    }
    Ok(())
}

/// Builds a standalone constant-only object from the same staged headers and
/// configuration flags as firmware compilation. This is geometry evidence,
/// not profile validation, candidate acceptance, or a live reading capability.
pub fn compile(
    profile: &Profile,
    mode: BuildMode,
    compiler: &OsStr,
    output: &Path,
) -> Result<LayoutReport> {
    preflight(output)?;
    let validation = profile.validate(mode);
    if validation
        .issues
        .iter()
        .any(|issue| issue.field.starts_with("storage"))
    {
        return Err(Error::Validation(validation));
    }
    let native = mode == BuildMode::Exec && profile.services.native_card.is_some();
    let bitmap = mode == BuildMode::Exec && profile.services.bitmap.is_some();
    let paint = mode == BuildMode::Exec && profile.services.paint.is_some();
    let private = mode != BuildMode::Marker && profile.menu.private_text.is_some();
    let graphics = mode == BuildMode::Exec && profile.services.graphics.is_some();
    let bits = u64::from(native)
        | u64::from(bitmap) << 1
        | u64::from(paint) << 2
        | u64::from(private) << 3
        | u64::from(graphics) << 4;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let stage = tempfile::Builder::new()
        .prefix(".nloader-layout-")
        .tempdir_in(parent)?;
    crate::stage_core_headers(
        stage.path(),
        profile
            .storage
            .root
            .as_deref()
            .unwrap_or(crate::UNCONFIGURED_CARD_ROOT),
        &crate::CoreHeaderConfig::from_profile(profile, mode)?,
    )?;
    let config = fs::read(stage.path().join("include/nlr/card_config.h"))?;
    let mut header_bytes = Vec::new();
    let mut header_sha256 = BTreeMap::new();
    for (name, source) in CORE_HEADERS {
        header_bytes.extend((name.len() as u64).to_le_bytes());
        header_bytes.extend(name.as_bytes());
        header_bytes.extend((source.len() as u64).to_le_bytes());
        header_bytes.extend(source.as_bytes());
        header_sha256.insert((*name).into(), nloader_profile::sha256(source.as_bytes()));
    }
    let headers_hash = nloader_profile::sha256(&header_bytes);
    let config_hash = nloader_profile::sha256(&config);
    let mut source=String::from("#include <stddef.h>\n#include <stdint.h>\n#include \"nlr/runtime.h\"\n_Static_assert(sizeof(void*)==8,\"layout requires 64-bit pointers\");\n#define ABSENT UINT64_MAX\n__attribute__((used,section(\".rodata.nlr_runtime_layout\"))) const uint64_t nlr_runtime_layout[] = {\n");
    source.push_str(&format!("{MAGIC}ULL,1,{},{bits},sizeof(void*),sizeof(struct nlr_runtime),NLR_REGISTRY_IDS,NLR_TRACE_SLOTS,sizeof(union nlr_trace_entry),\n",mode_number(mode)));
    for (_, offset, bytes) in FIELDS {
        source.push_str(&format!("{offset},{bytes},\n"));
    }
    source.push_str("#if NLR_HAS_PRIVATE_TEXT\nsizeof(struct nlr_private_text_pool),\n");
    for (_, offset, bytes) in POOL_FIELDS {
        source.push_str(&format!("{offset},{bytes},\n"));
    }
    source.push_str("sizeof(struct nlr_private_text_descriptor),offsetof(struct nlr_private_text_descriptor,buffer),offsetof(struct nlr_private_text_descriptor,length),offsetof(struct nlr_private_text_descriptor,style),offsetof(struct nlr_private_text_descriptor,reserved),offsetof(struct nlr_private_text_descriptor,reserved_tail),NLR_PRIVATE_TEXT_COUNT,NLR_PRIVATE_TEXT_BYTES,\n#else\n0,\n");
    for _ in POOL_FIELDS {
        source.push_str("ABSENT,0,\n");
    }
    source.push_str("0,0,0,0,0,0,0,0,\n#endif\n");
    // Identity sections bind the exact generated source, headers and config.
    let source_hash = nloader_profile::sha256(source.as_bytes());
    for hash in [&source_hash, &headers_hash, &config_hash] {
        for word in digest_words(hash) {
            source.push_str(&format!("{word}ULL,"));
        }
    }
    source.push_str("\n};\n");
    fs::write(stage.path().join("runtime-layout.c"), &source)?;
    crate::compile(
        compiler,
        stage.path(),
        "runtime-layout.c",
        "runtime-layout.o",
        crate::stage_defines(mode),
    )?;
    let object = fs::read(stage.path().join("runtime-layout.o"))?;
    let mut layout = inspect(&object)?;
    layout.provided_layout = false;
    let version = std::process::Command::new(compiler)
        .arg("--version")
        .output()?;
    if !version.status.success() {
        return Err(invalid("cannot identify layout compiler"));
    }
    let report = LayoutReport {
        layout,
        compiler: String::from_utf8_lossy(&version.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .into(),
        mode_defines: crate::stage_defines(mode)
            .iter()
            .map(|s| (*s).into())
            .collect(),
        header_sha256,
        storage_root: profile.storage.root.clone(),
        generated_source_sha256: nloader_profile::sha256(source.as_bytes()),
        firmware_ready: false,
    };
    fs::write(
        stage.path().join("layout.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    fs::create_dir(output)?;
    let publish = (|| -> std::io::Result<()> {
        for name in ["runtime-layout.o", "runtime-layout.c", "layout.json"] {
            fs::rename(stage.path().join(name), output.join(name))?;
        }
        fs::rename(stage.path().join("include"), output.join("include"))?;
        Ok(())
    })();
    if let Err(error) = publish {
        let _ = fs::remove_dir_all(output);
        return Err(error.into());
    }
    Ok(report)
}

/// Validates the actual object rather than trusting its JSON sidecar.
pub fn inspect(bytes: &[u8]) -> Result<RuntimeLayout> {
    let file = object::File::parse(bytes).map_err(|e| invalid(e.to_string()))?;
    if file.format() != object::BinaryFormat::Elf
        || file.architecture() != object::Architecture::Aarch64
        || !file.is_64()
        || !file.is_little_endian()
        || file.kind() != object::ObjectKind::Relocatable
    {
        return Err(invalid("layout requires unlinked ELF64 LE AArch64"));
    }
    for section in file.sections() {
        if matches!(section.flags(),SectionFlags::Elf{sh_flags} if sh_flags&u64::from(object::elf::SHF_WRITE)!=0 || (sh_flags&u64::from(object::elf::SHF_EXECINSTR)!=0 && section.size()!=0))
            || section.relocations().next().is_some()
        {
            return Err(invalid("layout forbids writable sections and relocations"));
        }
    }
    if file.symbols().any(|s| s.section() == SymbolSection::Common) {
        return Err(invalid("layout forbids COMMON"));
    }
    let sections: Vec<_> = file
        .sections()
        .filter(|s| s.name().ok() == Some(SECTION))
        .collect();
    if sections.len() != 1 {
        return Err(invalid("layout needs exactly one constant section"));
    }
    let section = &sections[0];
    let data = section.data().map_err(|e| invalid(e.to_string()))?;
    let count = 9 + FIELDS.len() * 2 + 1 + POOL_FIELDS.len() * 2 + 8 + 12;
    if data.len() != count * 8 {
        return Err(invalid("layout table length differs"));
    }
    let symbols: Vec<_> = file
        .symbols()
        .filter(|s| s.name().ok() == Some("nlr_runtime_layout") && s.is_definition())
        .collect();
    if symbols.len() != 1
        || symbols[0].section() != SymbolSection::Section(section.index())
        || symbols[0].address() != section.address()
        || symbols[0].size() != data.len() as u64
    {
        return Err(invalid("layout constant symbol differs"));
    }
    let words: Vec<u64> = data
        .chunks_exact(8)
        .map(|x| u64::from_le_bytes(x.try_into().expect("eight bytes")))
        .collect();
    if words[0] != MAGIC
        || words[1] != 1
        || words[4] != 8
        || words[3] > 15
        || words[5] < 320
        || words[5] > 65536
        || words[6] != 768
        || words[7] != 16
        || words[8] != 8
    {
        return Err(invalid("unsupported layout schema or geometry"));
    }
    let mode = decode_mode(words[2])?;
    if mode != BuildMode::Exec && words[3] & 7 != 0 {
        return Err(invalid("native features require Exec layout"));
    }
    if mode == BuildMode::Marker && words[3] != 0 {
        return Err(invalid("Marker has no private features"));
    }
    let mut fields = BTreeMap::new();
    let mut index = 9;
    for (name, _, _) in FIELDS {
        let offset = words[index];
        let size = words[index + 1];
        index += 2;
        if size == 0 || offset.checked_add(size).is_none_or(|end| end > words[5]) {
            return Err(invalid(format!("field {name} exceeds Runtime")));
        }
        fields.insert(
            (*name).into(),
            Field {
                offset: offset as usize,
                bytes: size as usize,
            },
        );
    }
    let pool_bytes = words[index];
    index += 1;
    for (name, _, _) in POOL_FIELDS {
        let offset = words[index];
        let size = words[index + 1];
        index += 2;
        if words[3] & 8 == 0 {
            if offset != ABSENT || size != 0 {
                return Err(invalid("disabled pool fields present"));
            }
            continue;
        }
        let limit = if *name == "private_text" {
            words[5]
        } else {
            pool_bytes
        };
        if size == 0 || offset.checked_add(size).is_none_or(|end| end > limit) {
            return Err(invalid(format!("pool field {name} exceeds object")));
        }
        fields.insert(
            (*name).into(),
            Field {
                offset: offset as usize,
                bytes: size as usize,
            },
        );
    }
    let d = &words[index..index + 8];
    index += 8;
    if words[3] & 8 == 0 {
        if pool_bytes != 0 || d.iter().any(|x| *x != 0) {
            return Err(invalid("disabled pool geometry present"));
        }
    } else if !(8..=65536).contains(&pool_bytes)
        || d[0] != 24
        || d[6] != 68
        || d[7] != 51
        || d[1..6]
            .iter()
            .zip([8, 4, 4, 4, 4])
            .any(|(offset, width)| offset.checked_add(width).is_none_or(|end| end > d[0]))
    {
        return Err(invalid("unsupported private pool geometry"));
    }
    Ok(RuntimeLayout {
        schema: 1,
        target: "aarch64-none-elf",
        mode,
        feature_bits: words[3],
        runtime_bytes: words[5] as usize,
        pool_bytes: pool_bytes as usize,
        registry_max_id: words[6] as u32,
        trace_slots: words[7] as usize,
        trace_entry_bytes: words[8] as usize,
        descriptor_bytes: d[0] as usize,
        descriptor_buffer_offset: d[1] as usize,
        descriptor_length_offset: d[2] as usize,
        descriptor_style_offset: d[3] as usize,
        descriptor_reserved_offset: d[4] as usize,
        descriptor_tail_offset: d[5] as usize,
        pool_count: d[6] as usize,
        buffer_bytes: d[7] as usize,
        fields,
        definition_sha256: words_digest(&words[index..index + 4]),
        headers_sha256: words_digest(&words[index + 4..index + 8]),
        config_sha256: words_digest(&words[index + 8..index + 12]),
        object_sha256: nloader_profile::sha256(bytes),
        provided_layout: true,
        physical_fresh: false,
    })
}
