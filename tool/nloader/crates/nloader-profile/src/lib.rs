//! Shared, conservative profile schema. Parsing a draft does not authorize a build.
mod audit;
mod bitmap;
pub use bitmap::*;
mod bitmap_validation;
mod paint;
pub use paint::*;
mod graphics;
pub use graphics::*;
mod graphics_validation;
pub use graphics_validation::{validate_graphics, validate_graphics_bytes, GRAPHICS_BODIES};
mod time;
pub use time::*;
mod input;
pub use input::*;
mod input_validation;
pub use input_validation::{validate_input, validate_input_bytes, INPUT_BODIES};
mod boot_hooks;
pub use boot_hooks::*;
mod platform;
pub use platform::*;
mod capture;
mod paint_native_validation;
mod paint_validation;
mod time_validation;
pub use capture::*;
mod exec_validation;
mod exit_validation;
mod family;
pub use family::*;
mod mapping;
mod menu;
mod menu_refresh_validation;
mod private_text;
pub use private_text::*;
mod private_text_validation;
mod setup_cursor;
pub use setup_cursor::*;
mod program_arena;
pub use menu::*;
pub use program_arena::*;
mod native_card;
pub use native_card::*;
mod native_card_validation;
mod storage;
pub use storage::*;
mod validation;
pub use mapping::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, str::FromStr};
pub use validation::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid profile TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("cannot serialize profile: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("unsupported build mode: {0}")]
    Mode(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuildMode {
    Marker,
    HookOnly,
    Page,
    LoadOnly,
    PrepareOnly,
    Exec,
}
impl FromStr for BuildMode {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "marker" => Ok(Self::Marker),
            "hook-only" => Ok(Self::HookOnly),
            "page" => Ok(Self::Page),
            "load-only" => Ok(Self::LoadOnly),
            "prepare-only" => Ok(Self::PrepareOnly),
            "exec" => Ok(Self::Exec),
            _ => Err(Error::Mode(value.into())),
        }
    }
}
impl std::fmt::Display for BuildMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Marker => "marker",
            Self::HookOnly => "hook-only",
            Self::Page => "page",
            Self::LoadOnly => "load-only",
            Self::PrepareOnly => "prepare-only",
            Self::Exec => "exec",
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerKind {
    LegacyXor,
    AesCtr,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Identity {
    pub model: String,
    pub firmware: String,
    pub container: Option<ContainerKind>,
    pub stock_pkg: Option<String>,
    pub eg_module: Option<String>,
}
/// Half-open runtime address range, never a file offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}
impl AddressRange {
    pub fn contains(&self, start: u64, length: u64) -> bool {
        self.start < self.end
            && length != 0
            && start >= self.start
            && start.checked_add(length).is_some_and(|end| end <= self.end)
    }
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slack {
    pub start: u64,
    pub end: u64,
    pub require_zero: bool,
}
impl Slack {
    pub fn range(&self) -> AddressRange {
        AddressRange {
            start: self.start,
            end: self.end,
        }
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Memory {
    /// Explicit payload-to-runtime mapping; absent maps cannot authorize builds.
    pub segments: Vec<MemorySegment>,
    pub xip_base: Option<u64>,
    /// Decrypted module payload length (excludes its container CRC).
    pub module_size: Option<u64>,
    pub slack: Option<Slack>,
    pub link_base: Option<u64>,
    /// Reserved maximum output span, checked before invoking the compiler.
    pub link_size: Option<u64>,
    pub ram_pool: Option<AddressRange>,
    /// Coexistence budget for executed programs (M2-T2): whole execution
    /// blocks that resident extensions and running programs may hold
    /// together. A start that would exceed it is refused before any
    /// allocation. QEMU has verified a two-block allocation; the real
    /// device has so far only proven a single 2 MiB block (probe), so the
    /// declared budget must stay a refusal-safe claim until then.
    pub program_budget_blocks: Option<u32>,
    /// How many resource extensions may stay resident after their entry
    /// returned. Multi-extension coexistence is M2-T5; one is the current
    /// verified shape.
    pub program_max_resident: Option<u32>,
    /// Loader-owned storage for one complete program's relocations, image
    /// and initialized data. Absence preserves the original 64 KiB budget;
    /// the validated value controls both allocation and read capacity.
    pub program_arena_bytes: Option<u32>,
}
/// Entry prologue fingerprint for one service address (AUDIT B4): the bytes
/// the module must carry at the declared entry, so a mistyped address fails
/// validation instead of jumping anywhere on the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceFingerprint {
    pub eg_off: u64,
    pub stock: Vec<u8>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Services {
    pub fs_open: Option<u64>,
    pub fs_read: Option<u64>,
    pub fs_seek: Option<u64>,
    pub fs_close: Option<u64>,
    /// Write to an open file (fd, buffer, bytes, out_written): only the
    /// in-place overwrite of a program's settings file uses it.
    pub fs_write: Option<u64>,
    pub dcache_inv_pre: Option<u64>,
    pub dcache_inv_post: Option<u64>,
    /// Clean the data cache to the point of coherency: what this body does
    /// to make bytes it has just written visible to another master — the
    /// card's DMA behind a write, or instruction fetch after a code patch.
    /// It is named apart from `dcache_inv_post` on purpose: that one is the
    /// maintenance a read ends with, and on a model whose entry discards
    /// lines instead of writing them back, reusing it would lose exactly
    /// those writes without a word. A profile that writes files or patches
    /// code has to name the entry that writes back.
    pub dcache_clean: Option<u64>,
    pub worker_init: Option<u64>,
    pub worker_start: Option<u64>,
    pub flag_set: Option<u64>,
    pub registry_lookup: Option<u64>,
    pub mem_alloc: Option<u64>,
    pub mem_free: Option<u64>,
    pub exec: ExecutionServices,
    /// Optional audited physical exit hook and native task controls.
    pub exit: Option<ExitServices>,
    /// Optional native filesystem RPC. It supplies real operations and owner
    /// observations; atomic recovery and commit policy remain core behavior.
    pub native_card: Option<NativeCardServices>,
    pub bitmap: Option<BitmapServices>,
    pub paint: Option<PaintServices>,
    /// Optional ABI 4 program services: task delay, directory enumeration,
    /// the input task's scan hook and the GUI plane record. Each part is
    /// independent; an absent part leaves its API calls at -ENOSYS.
    pub program: Option<ProgramServices>,
    pub graphics: Option<GraphicsServices>,
    pub time: Option<TimeServices>,
    pub input: Option<InputServices>,
    /// Optional ABI 5 firmware-code channel: the window a card program may
    /// patch and the alias band those pages must translate into. The
    /// services it drives are the execution family's own (translate, query,
    /// cacheable, clean, invalidate), so only the bounds are declared here.
    pub code: Option<CodeServices>,
    /// Optional ABI 7 platform services: every control, the dials and the
    /// settings store (core/include/nlr/platform.h).
    pub platform: Option<PlatformServices>,
    /// Optional record of how much memory the model's allocator really
    /// granted. Needed on a model whose allocator may answer a request with
    /// less than it was asked for; without it the execution layer takes the
    /// allocator at its word.
    pub heap: Option<HeapServices>,
    /// Request operations the file wrappers submit. Each wrapper fills a
    /// request block on its stack and stores an operation number into it;
    /// validation decodes that number from the declared function and
    /// compares, so a wrapper for a different operation cannot pass for
    /// open, read, seek or close.
    pub file_ops: FileOperations,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileOperations {
    /// Stack offset of the operation word in the wrappers' request block.
    pub op_slot: Option<u32>,
    pub open: Option<u32>,
    pub read: Option<u32>,
    pub seek: Option<u32>,
    pub close: Option<u32>,
    pub write: Option<u32>,
    /// The open flags that open an existing file for reading and writing,
    /// creating and truncating nothing.
    pub open_read_write: Option<u32>,
    /// The open flags that write a file, create it when it is missing and
    /// truncate it when it is not, and the attribute word a created file
    /// gets. Both are needed before a program may write to the card and
    /// before the loader can keep its own state on an ordinary card.
    pub open_write_create: Option<u32>,
    pub create_attributes: Option<u32>,
}
/// ABI 5 firmware-code channel (see core/include/nlr/services.h). The code a
/// card program may patch runs from DRAM, and the mapping service keeps a
/// writable alias of those physical pages: `text` is the window a patch may
/// name, `alias` the band its pages must translate into. Both are
/// `[lo, hi)`; everything else the channel needs comes from
/// `services.exec`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CodeServices {
    pub text_lo: Option<u64>,
    pub text_hi: Option<u64>,
    pub alias_lo: Option<u64>,
    pub alias_hi: Option<u64>,
    /// Whether this body runs with SCTLR_EL1.A clear, so a doubleword may
    /// be loaded from an address that is only 4-byte aligned. A hook's
    /// detour reads the handler's address out of its own last eight bytes,
    /// so without this only a target that is 8-byte aligned can be hooked.
    /// It is a declared fact about the boot the profile describes, like
    /// every address here; core cannot read SCTLR_EL1 to check it, because
    /// the register is not readable where the host tests run and asking
    /// about it says nothing about the moment the hook is taken.
    pub unaligned_literals: Option<bool>,
}
/// Where the model's allocator keeps its own record of a block (see the
/// `grant_end` service in core/include/nlr/exec.h). All offsets are into the
/// manager object; the node pool is part of that object, so it needs no
/// address of its own. Nothing here is written, only read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeapServices {
    /// The manager object the loader's allocation entry uses.
    pub manager: Option<u64>,
    /// Offsets of the lists of allocated and (for evidence) free blocks.
    pub list_allocated: Option<u32>,
    pub list_free: Option<u32>,
    /// The node pool: its offset inside the manager, how many nodes it
    /// holds and how long a node is. A pointer outside it is refused, so a
    /// list changing under the walk can neither fault nor run away.
    pub node_pool: Option<u32>,
    pub node_count: Option<u32>,
    pub node_bytes: Option<u32>,
    /// Offsets inside one node.
    pub node_next: Option<u32>,
    pub node_base: Option<u32>,
    pub node_size: Option<u32>,
    /// The manager byte that says the returned pointer sits `guard_bytes`
    /// above the block the node records, and that distance.
    pub guard_flag: Option<u32>,
    pub guard_bytes: Option<u32>,
    /// The granule the allocator rounds a request up to before it looks for
    /// a node, so a request can be sized to a node it will fit in.
    pub round_bytes: Option<u32>,
}

/// ABI 4 program services (see core/include/nlr/services.h). Code entries are
/// stock functions and carry fingerprints under `program.<name>`; the rest
/// are the layouts and codes those functions use.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProgramServices {
    /// Task delay: `(milliseconds)`, gives the CPU away.
    pub task_delay: Option<u64>,
    /// Directory enumeration: `(dir, attribute mask, each(info))`.
    pub fs_enum: Option<u64>,
    pub enum_done: u32,
    pub mask_directories: u32,
    pub mask_files: u32,
    pub attr_directory: u32,
    pub info_short: u16,
    pub info_long: u16,
    pub info_attr: u16,
    pub info_size: u16,
    /// Bytes a long-name character: 2 for UTF-16LE, 1 (or 0) for 8-bit.
    pub info_long_unit: u16,
    /// The input task's per-scan callback slot (RAM) and its stock occupant.
    pub input_slot: Option<u64>,
    pub input_original: Option<u64>,
    /// Set when this body's slot is filled at run time rather than loaded
    /// from the module: the Z 6III's scan callback is registered by the
    /// camera's own startup, so the slot is in DRAM the image does not
    /// cover and its stock occupant cannot be read out of the module. The
    /// declaration then means the slot must lie outside every mapped
    /// segment, and the occupant is checked where it can be: core compares
    /// it with `input_original` before it installs anything (core/api.c).
    /// Left false, the slot must sit in declared RAM and the module must
    /// hold the declared occupant.
    pub input_slot_dynamic: bool,
    /// The scan object itself, which the callback is given: the buttons as
    /// they are right now, readable from any task without the hook's
    /// history. Only the autoload escape reads it this way.
    pub input_object: Option<u64>,
    pub bank_base: u32,
    pub bank_stride: u32,
    pub banks: u32,
    pub keep_bank: u32,
    pub keep_mask: u32,
    pub dial_offset: u32,
    pub dial_bytes: u32,
    /// `[bank, mask]` per NLR_KEY_* bit, in bit order (at most 15).
    pub keys: Vec<[u32; 2]>,
    /// The rear screen's scanout address registers (MMIO), colour and
    /// alpha: a low word, then a high word of which `scanout_high_mask`
    /// carries address bits 32 up. Bus addresses, `bus_offset` above the
    /// CPU's; the buffer they name must lie inside `[plane_lo, plane_hi)`.
    pub scanout_colour: Option<u64>,
    pub scanout_alpha: Option<u64>,
    pub scanout_high_mask: u32,
    pub bus_offset: u64,
    pub plane_lo: u64,
    pub plane_hi: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub alpha_stride: u32,
    /// User activity: holds off auto power-off. No arguments.
    pub activity: Option<u64>,
}

impl ProgramServices {
    /// Stock code entries by fingerprint name.
    pub fn entry(&self, name: &str) -> Option<u64> {
        match name {
            "task_delay" => self.task_delay,
            "fs_enum" => self.fs_enum,
            "input_original" => self.input_original,
            "activity" => self.activity,
            _ => None,
        }
    }
    pub fn entries(&self) -> [(&'static str, Option<u64>); 4] {
        [
            ("services.program.task_delay", self.task_delay),
            ("services.program.fs_enum", self.fs_enum),
            ("services.program.input_original", self.input_original),
            ("services.program.activity", self.activity),
        ]
    }
}

/// Optional Z8 worker controls. Absence leaves execution exit services null;
/// declaring the table requires every binding and its stock evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitServices {
    pub input_callback: u64,
    pub bank: u32,
    pub mask: u32,
    pub release_mask: u32,
    /// Native zero-key release action used only by the guarded exit redraw.
    pub menu_release_code: u32,
    pub menu_release_mapping: ExecutionTable,
    pub suspend: u64,
    pub resume: u64,
    pub terminate: u64,
    pub restart: u64,
    pub bodies: Vec<ExecutionBody>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionServices {
    /// Whole stock functions supporting the selected execution family.
    pub bodies: Vec<ExecutionBody>,
    /// Stock tables supporting the selected execution family.
    pub tables: Vec<ExecutionTable>,
    /// Complete owned translation granule used by the closed return probe.
    pub region_bytes: Option<u32>,
    /// Encodings the stock permission service accepts for one writable and
    /// one executable permission (M2 D1 step 4). The core only names the two
    /// semantics; what an encoding means in page tables stays adapter
    /// knowledge of the declared mapping family. Values are per model
    /// version and must be nonzero and distinct.
    pub flag_writable: Option<u32>,
    pub flag_executable: Option<u32>,
    /// Native broadcast TLB maintenance, separate from permission changes.
    pub tlb_sync: Option<u64>,
    /// Native cache hierarchy and line-size context.
    pub cache_manager: Option<u64>,
    /// Z8 native mapping manager, independently checked against both wrappers.
    pub manager: Option<u64>,
    /// Native address-region predicate used by the D-cache wrapper.
    pub cacheable: Option<u64>,
    pub page_protect: Option<u64>,
    pub page_query: Option<u64>,
    pub icache_inval: Option<u64>,
    pub mmu_translate: Option<u64>,
    /// Optional (z8_block_v1): the heap's own locked aligned entry
    /// `(heap, alignment, bytes) -> payload or 0`, so a program's regions
    /// are placed on their boundary and the slack around them goes back to
    /// the heap at once. Declared with `memalign_heap` and the
    /// `heap_memalign` / `heap_mspace_malloc` bodies; validation binds it to
    /// the heap `mem_alloc` draws on and `mem_free` returns to.
    pub memalign: Option<u64>,
    /// The word holding the heap handle `mem_alloc` uses for pool 0 (its
    /// pool table's first entry), read when a region is asked for.
    pub memalign_heap: Option<u64>,
}
/// A complete audited stock function, not just its entry fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBody {
    pub name: String,
    pub address: u64,
    pub length: u32,
    pub sha256: String,
}
/// A native table with explicit element width and little-endian values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTable {
    pub name: String,
    pub address: u64,
    pub element_bytes: u8,
    pub values: Vec<u64>,
}
/// Stock text and widget functions NLoader's own page calls. Every page
/// change goes through them, so the firmware keeps owning the widgets, the
/// text buffers, the font conversion and the redraw; no stock page is
/// hooked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ui {
    pub widget_find: Option<u64>,
    pub text_store: Option<u64>,
    pub text_bind: Option<u64>,
    /// Widget container inside a window record: the stock title chain adds
    /// this to the window it was handed.
    pub widget_container_offset: Option<u32>,
    /// Stock widget visibility setter `(widget, visible)`. Runtime-text
    /// elements are built hidden; the stock pages that title themselves from
    /// a text slot store, bind and then show the widget.
    pub widget_show: Option<u64>,
    /// A stock title chain doing exactly that (lookup in the container,
    /// store with the title format, bind, show). Validation decodes the
    /// container offset, the format and the four call targets from these
    /// bytes, so NLoader's page title follows the firmware's own sequence.
    pub title_chain: Option<ServiceFingerprint>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Task {
    pub core: Option<u32>,
    pub priority: Option<u32>,
    pub stack: Option<u64>,
    pub name: Option<String>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Checks {
    pub package_sha256: Option<String>,
    pub module_sha256: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Updater {
    pub filename_glob_class: Option<u32>,
    /// Version literals bumped at build time so the updater treats the
    /// package as an update. Locations are module-relative file offsets; the
    /// eg trailer copy is intentionally unmapped (never loaded to RAM).
    #[serde(default)]
    pub version_literals: Vec<VersionLiteral>,
    /// Whether the build applies the declared literals. The updater refuses
    /// a same-version package, so this stays true for flashable builds;
    /// setting it false produces a stock-version package for updater-behavior
    /// tests and failed-hook diagnosis.
    #[serde(default = "default_true")]
    pub bump_version: bool,
    pub trailer_fwver: Option<String>,
}

impl Default for Updater {
    fn default() -> Self {
        Self {
            filename_glob_class: None,
            version_literals: Vec::new(),
            bump_version: true,
            trailer_fwver: None,
        }
    }
}

fn default_true() -> bool {
    true
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionLiteral {
    pub eg_off: u64,
    pub stock: String,
    pub patched: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Device,
    FirmwareImage,
    StaticAnalysis,
    Snapshot,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Unconfirmed,
    Observed,
    Static,
    DeviceVerified,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub source: EvidenceSource,
    pub status: EvidenceStatus,
    pub model: String,
    pub firmware: String,
    pub rule: String,
    pub fragment_sha256: Option<String>,
    pub module_sha256: Option<String>,
    #[serde(default)]
    pub note: String,
}
impl Evidence {
    pub fn device_read(
        model: impl Into<String>,
        firmware: impl Into<String>,
        rule: impl Into<String>,
        fragment_sha256: impl Into<String>,
    ) -> Self {
        Self {
            source: EvidenceSource::Device,
            status: EvidenceStatus::Observed,
            model: model.into(),
            firmware: firmware.into(),
            rule: rule.into(),
            fragment_sha256: Some(fragment_sha256.into()),
            module_sha256: None,
            note: String::new(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub field: String,
    pub candidates: Vec<String>,
    pub reason: String,
}
/// Reserved capabilities are explicit and unavailable in this schema implementation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedCapability {}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub capture: Option<CaptureConfig>,
    pub schema: u32,
    #[serde(default)]
    pub abi: Abi,
    #[serde(default)]
    pub identity: Identity,
    #[serde(default)]
    pub memory: Memory,
    #[serde(default)]
    pub services: Services,
    #[serde(default)]
    pub storage: Storage,
    /// Entry prologue fingerprints keyed by the service field name; checked
    /// against the actual module bytes and required once a mode calls the
    /// service (AUDIT B4).
    #[serde(default)]
    pub service_fingerprints: BTreeMap<String, ServiceFingerprint>,
    #[serde(default)]
    pub ui: Ui,
    #[serde(default)]
    pub task: Task,
    #[serde(default)]
    pub updater: Updater,
    #[serde(default)]
    pub checks: Checks,
    #[serde(default)]
    pub menu: Menu,
    #[serde(default)]
    pub graphics: ReservedCapability,
    #[serde(default)]
    pub input: ReservedCapability,
    #[serde(default)]
    pub config: ReservedCapability,
    #[serde(default)]
    pub boot_hooks: BootHooks,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            schema: 1,
            capture: None,
            abi: Abi::default(),
            identity: Identity::default(),
            memory: Memory::default(),
            services: Services::default(),
            storage: Storage::default(),
            service_fingerprints: BTreeMap::new(),
            ui: Ui::default(),
            task: Task::default(),
            updater: Updater::default(),
            checks: Checks::default(),
            menu: Menu::default(),
            graphics: ReservedCapability::default(),
            input: ReservedCapability::default(),
            config: ReservedCapability::default(),
            boot_hooks: BootHooks::default(),
        }
    }
}
impl Profile {
    pub fn draft(model: impl Into<String>, firmware: impl Into<String>) -> Self {
        Self {
            identity: Identity {
                model: model.into(),
                firmware: firmware.into(),
                ..Identity::default()
            },
            ..Self::default()
        }
    }
    pub fn from_toml(value: &str) -> Result<Self, Error> {
        Ok(toml::from_str(value)?)
    }
    pub fn to_toml(&self) -> Result<String, Error> {
        Ok(toml::to_string_pretty(self)?)
    }
}
