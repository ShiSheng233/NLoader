use crate::*;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueKind {
    Missing,
    Invalid,
    Unsupported,
    IdentityMismatch,
    FingerprintMismatch,
    OutOfBounds,
    Conflict,
    Unconfirmed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub field: String,
    pub kind: IssueKind,
    pub message: String,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("profile validation failed: {issues:?}")]
pub struct ValidationReport {
    pub issues: Vec<ValidationIssue>,
}
impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }
    pub fn into_result(self) -> Result<(), Self> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(self)
        }
    }
    pub(crate) fn add(
        &mut self,
        field: impl Into<String>,
        kind: IssueKind,
        message: impl Into<String>,
    ) {
        self.issues.push(ValidationIssue {
            field: field.into(),
            kind,
            message: message.into(),
        });
    }
    pub(crate) fn require<T>(&mut self, field: &str, value: Option<T>) -> Option<T> {
        if value.is_none() {
            self.add(field, IssueKind::Missing, "required by selected build mode");
        }
        value
    }
}
/// Inputs from the independently validated container reader. No profile value is
/// substituted for an observed input identity or fingerprint.
pub struct ValidationContext<'a> {
    pub model: &'a str,
    pub firmware: &'a str,
    /// The official package, when one was supplied. `None` means only the
    /// module was given, so its recorded fingerprint stays unchecked here and
    /// the caller must say so in its own report.
    pub package: Option<&'a [u8]>,
    pub module_name: &'a str,
    pub module: &'a [u8],
}
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(crate) fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}
pub(crate) fn hash_matches(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

impl Profile {
    /// Checks declared requirements, not firmware bytes or real-device behavior.
    pub fn validate(&self, mode: BuildMode) -> ValidationReport {
        let mut report = ValidationReport::default();
        if self.schema != 1 {
            report.add(
                "schema",
                IssueKind::Unsupported,
                "only schema 1 is supported",
            );
        }
        for (field, value) in [
            ("identity.model", &self.identity.model),
            ("identity.firmware", &self.identity.firmware),
        ] {
            if value.trim().is_empty() {
                report.add(field, IssueKind::Missing, "identity must not be empty");
            }
        }
        // Which container it is matters only when one is written: see
        // `validate_package_output`.
        report.require("identity.container", self.identity.container);
        for (field, value) in [
            ("identity.stock_pkg", self.identity.stock_pkg.as_deref()),
            ("identity.eg_module", self.identity.eg_module.as_deref()),
        ] {
            if let Some(value) = report.require(field, value) {
                if value.trim().is_empty()
                    || value.contains(['/', '\\'])
                    || value == "."
                    || value == ".."
                {
                    report.add(
                        field,
                        IssueKind::Invalid,
                        "expected a nonempty file basename",
                    );
                }
            }
        }
        for (field, value) in [
            (
                "checks.package_sha256",
                self.checks.package_sha256.as_deref(),
            ),
            ("checks.module_sha256", self.checks.module_sha256.as_deref()),
        ] {
            if let Some(hash) = report.require(field, value) {
                if !valid_hash(hash) {
                    report.add(
                        field,
                        IssueKind::Invalid,
                        "expected 64 hexadecimal SHA-256 digits",
                    );
                }
            }
        }
        self.validate_families(mode, &mut report);
        self.validate_storage(mode, &mut report);
        self.validate_memory(&mut report);
        self.validate_program_arena(&mut report);
        self.validate_services(&mut report);
        self.validate_service_fingerprints(mode, &mut report);
        self.validate_task(mode, &mut report);
        self.validate_execution(mode, &mut report);
        self.validate_exit(&mut report);
        self.validate_native_card(mode, &mut report);
        self.validate_bitmap(mode, &mut report);
        self.validate_paint(mode, &mut report);
        self.validate_time(&mut report);
        self.validate_boot_hooks(mode, &mut report);
        self.validate_platform(&mut report);
        if let Some(input) = &self.services.input {
            crate::validate_input(self, input, &mut report);
            if self.services.native_card.is_none() {
                report.issues.push(ValidationIssue {
                    field: "services.input".into(),
                    kind: IssueKind::Conflict,
                    message: "input requires the audited native menu identity and current-window services".into(),
                });
            }
        }
        if let Some(graphics) = &self.services.graphics {
            crate::validate_graphics(self, graphics, mode, &mut report);
        }
        // Coexistence memory budget (M2-T2): the prepare and exec rungs
        // inject both limits into the execution services, so a missing or
        // vacuous declaration is refused instead of starting programs
        // without a budget. A budget of 1 is legal: a data-carrying program
        // then always takes the refusal path, never a validation failure.
        if matches!(mode, BuildMode::PrepareOnly | BuildMode::Exec) {
            for (field, value) in [
                (
                    "memory.program_budget_blocks",
                    self.memory.program_budget_blocks,
                ),
                (
                    "memory.program_max_resident",
                    self.memory.program_max_resident,
                ),
            ] {
                if let Some(value) = report.require(field, value) {
                    if value == 0 {
                        report.add(field, IssueKind::Invalid, "must be nonzero");
                    }
                }
            }
        }
        self.validate_updater(&mut report);
        self.validate_menu(&mut report);
        self.validate_setup_cursor(&mut report);
        self.validate_menu_refresh(&mut report);
        self.validate_private_text(mode, &mut report);
        match mode {
            BuildMode::Marker => {}
            // Every flashable rung installs the Setup entry row and NLoader's
            // own page and changes no stock page: the entry row and the page
            // are what these rungs consist of. Their bytes and the stock
            // functions they call are checked by the menu validation.
            BuildMode::HookOnly | BuildMode::Page => self.require_menu_page(&mut report),
            BuildMode::LoadOnly | BuildMode::PrepareOnly | BuildMode::Exec => {
                self.require_menu_page(&mut report);
                // These rungs show the directory as the list: without its
                // rows the page would fall back to one row, and the details
                // (operation, result, back) could never be drawn. Declared
                // rows bring the row-hide function and its stock bytes in
                // with them (menu validation).
                if self
                    .menu
                    .page
                    .as_ref()
                    .is_some_and(|p| p.row_slots.is_empty())
                {
                    report.add(
                        "menu.page.row_slots",
                        IssueKind::Missing,
                        "load-only and later show the program list: 64 row slots are required",
                    );
                }
                // The page constructs the worker and reads the card: every
                // called service, its entry fingerprint and the task
                // configuration are required (AUDIT B4/C4).
                for (field, value) in self.load_only_services() {
                    report.require(field, value);
                }
                // The file wrappers are told apart by the operation they
                // submit; every one load-only calls must be declared. Write
                // is optional: only a program's settings use it, and a
                // declared fs_write needs its operation (validate).
                report.require("services.file_ops.op_slot", self.services.file_ops.op_slot);
                for (field, value) in self.file_operations() {
                    if field != "services.file_ops.write" {
                        report.require(field, value.1);
                    }
                }
            }
        }
        report
    }

    /// The extra requirement a build that writes a package carries. The
    /// container writer is only exercised when one is resealed, so a
    /// module-only build never reaches it. The aes-ctr writer round-trips
    /// real packages byte for byte, but official update acceptance is
    /// unverified, so it stays out of package builds.
    pub fn validate_package_output(&self) -> ValidationReport {
        let mut report = ValidationReport::default();
        if let Some(container) = report.require("identity.container", self.identity.container) {
            if container != ContainerKind::LegacyXor {
                report.add(
                    "identity.container",
                    IssueKind::Unsupported,
                    "current container builder requires legacy-xor",
                );
            }
        }
        report
    }

    /// The extra requirements of dev firmware (an Exec build whose module
    /// gets stage 0 alone and loads the core from the card). Stage 0 and
    /// the core it loads run the boot pass from the boot checkpoint on the
    /// file store (`core/core_entry.c`, `core/stage0.c`); they do not take
    /// the native card store. A profile that declares that store would get
    /// a dev core asking the card through the wrong store, so the pair is
    /// refused until the dev core takes the store the profile declares.
    pub fn validate_dev_core(&self) -> ValidationReport {
        let mut report = ValidationReport::default();
        report.require("boot_hooks.autoload", self.boot_hooks.autoload.as_ref());
        if self.services.native_card.is_some() {
            report.add(
                "services.native_card",
                IssueKind::Unsupported,
                "dev firmware runs the boot pass on the file store with the boot \
                 checkpoint; a profile with a native card store cannot be built \
                 as dev firmware",
            );
        }
        report
    }

    pub fn validate_for(&self, mode: BuildMode, input: &ValidationContext<'_>) -> ValidationReport {
        let mut report = self.validate(mode);
        if self.identity.model != input.model || self.identity.firmware != input.firmware {
            report.add(
                "identity",
                IssueKind::IdentityMismatch,
                "input model or firmware differs from profile",
            );
        }
        if self.identity.eg_module.as_deref() != Some(input.module_name) {
            report.add(
                "identity.eg_module",
                IssueKind::IdentityMismatch,
                "input module name differs from profile",
            );
        }
        let mut fingerprints = Vec::with_capacity(2);
        if let Some(package) = input.package {
            fingerprints.push((
                "checks.package_sha256",
                self.checks.package_sha256.as_deref(),
                sha256(package),
            ));
        }
        fingerprints.push((
            "checks.module_sha256",
            self.checks.module_sha256.as_deref(),
            sha256(input.module),
        ));
        for (field, expected, actual) in fingerprints {
            if expected.is_some_and(|expected| !hash_matches(expected, &actual)) {
                report.add(
                    field,
                    IssueKind::FingerprintMismatch,
                    "input SHA-256 differs from profile",
                );
            }
        }
        if self.memory.module_size != Some(input.module.len() as u64) {
            report.add(
                "memory.module_size",
                IssueKind::IdentityMismatch,
                "input module length differs from profile",
            );
        }
        if let Some(slack) = &self.memory.slack {
            match runtime_slice(
                input.module,
                &self.memory,
                slack.start,
                slack.end.saturating_sub(slack.start),
            ) {
                Some(bytes) if bytes.iter().all(|byte| *byte == 0) => {}
                Some(_) => report.add(
                    "memory.slack",
                    IssueKind::Conflict,
                    "reserved firmware area is not all zero",
                ),
                None => report.add(
                    "memory.slack",
                    IssueKind::OutOfBounds,
                    "reserved firmware area cannot be read from input module",
                ),
            }
        }
        for (index, version) in self.updater.version_literals.iter().enumerate() {
            let actual = usize::try_from(version.eg_off).ok().and_then(|start| {
                start
                    .checked_add(version.stock.len())
                    .and_then(|end| input.module.get(start..end))
            });
            if actual != Some(version.stock.as_bytes()) {
                report.add(
                    format!("updater.version_literals[{index}]"),
                    IssueKind::Conflict,
                    "input version literal differs from stock bytes",
                );
            }
        }
        for (name, fingerprint) in &self.service_fingerprints {
            let actual = usize::try_from(fingerprint.eg_off).ok().and_then(|start| {
                start
                    .checked_add(fingerprint.stock.len())
                    .and_then(|end| input.module.get(start..end))
            });
            if actual != Some(fingerprint.stock.as_slice()) {
                report.add(
                    format!("service_fingerprints.{name}"),
                    IssueKind::Conflict,
                    "input service prologue differs from the fingerprint",
                );
            }
        }
        self.validate_file_operations(input.module, &mut report);
        if let Some(program) = &self.services.program {
            if let (Some(slot), Some(original)) = (program.input_slot, program.input_original) {
                /* Only a slot the image loads can be read here; a run-time
                 * slot is checked by core against the same declared
                 * occupant before it installs its own. */
                if !program.input_slot_dynamic
                    && runtime_slice(input.module, &self.memory, slot, 8)
                        != Some(original.to_le_bytes().as_slice())
                {
                    report.add(
                        "services.program.input_slot",
                        IssueKind::Conflict,
                        "the stock callback slot differs from the declared original occupant",
                    );
                }
            }
        }
        self.validate_execution_bytes(mode, input.module, &mut report);
        self.validate_exit_bytes(input.module, &mut report);
        self.validate_native_card_bytes(input.module, &mut report);
        self.validate_bitmap_bytes(input.module, &mut report);
        self.validate_paint_bytes(input.module, &mut report);
        self.validate_time_bytes(input.module, &mut report);
        self.validate_boot_hooks_bytes(input.module, &mut report);
        self.validate_platform_bytes(input.module, &mut report);
        if let Some(mapping) = &self.services.input {
            crate::validate_input_bytes(self, mapping, input.module, &mut report);
        }
        if let Some(graphics) = &self.services.graphics {
            crate::validate_graphics_bytes(self, graphics, input.module, &mut report);
        }
        self.validate_title_chain_bytes(input.module, &mut report);
        self.validate_menu_bytes(input.module, &mut report);
        self.validate_setup_cursor_bytes(input.module, &mut report);
        self.validate_menu_refresh_bytes(input.module, &mut report);
        self.validate_private_text_bytes(input.module, &mut report);
        report
    }

    /// The stock title chain NLoader's page entry follows: the declared
    /// bytes must be the module's, form the container at the declared
    /// offset, load the title format into the store's format register, and
    /// call lookup, store, bind and show in that order.
    fn validate_title_chain_bytes(&self, module: &[u8], report: &mut ValidationReport) {
        let (Some(chain), Some(page)) = (&self.ui.title_chain, &self.menu.page) else {
            return;
        };
        let actual = usize::try_from(chain.eg_off).ok().and_then(|start| {
            start
                .checked_add(chain.stock.len())
                .and_then(|end| module.get(start..end))
        });
        if actual != Some(chain.stock.as_slice()) {
            report.add(
                "ui.title_chain",
                IssueKind::Conflict,
                "input bytes differ from the declared stock title chain",
            );
            return;
        }
        let Ok(base) = self
            .memory
            .offset_to_address(chain.eg_off, chain.stock.len() as u64)
        else {
            return;
        };
        let words: Vec<(u64, u32)> = chain
            .stock
            .chunks_exact(4)
            .enumerate()
            .map(|(index, bytes)| {
                (
                    base + index as u64 * 4,
                    u32::from_le_bytes(bytes.try_into().expect("4 bytes")),
                )
            })
            .collect();
        if let Some(offset) = self.ui.widget_container_offset {
            let forms_container = words.iter().any(|(_, word)| {
                word & 0xffc0_0000 == 0x9100_0000
                    && (word >> 10) & 0xfff == offset
                    && (word >> 5) & 0x1f == word & 0x1f
            });
            if !forms_container {
                report.add(
                    "ui.widget_container_offset",
                    IssueKind::Conflict,
                    "the stock title chain does not form the container at this offset",
                );
            }
        }
        // The store's third argument is loaded into W2; the stock chain
        // uses the ORR-immediate form, other builds may use MOVZ.
        if page.title_format > 0xffff
            || !words
                .iter()
                .any(|(_, word)| w_register_constant(*word, 2) == Some(page.title_format))
        {
            report.add(
                "menu.page.title_format",
                IssueKind::Conflict,
                "the stock title chain does not store with this format",
            );
        }
        let mut targets = Vec::new();
        for (address, word) in &words {
            if word & 0xfc00_0000 == 0x9400_0000 {
                let immediate = (word & 0x03ff_ffff) as i32;
                let signed = (immediate << 6) >> 6; // sign-extend imm26
                targets.push(address.wrapping_add_signed(i64::from(signed) * 4));
            }
        }
        let mut last = None;
        for (field, value) in [
            ("ui.widget_find", self.ui.widget_find),
            ("ui.text_store", self.ui.text_store),
            ("ui.text_bind", self.ui.text_bind),
            ("ui.widget_show", self.ui.widget_show),
        ] {
            let Some(address) = value else {
                continue;
            };
            match targets.iter().position(|target| *target == address) {
                Some(index) if last.is_none_or(|previous| index > previous) => {
                    last = Some(index);
                }
                Some(_) => report.add(
                    field,
                    IssueKind::Conflict,
                    "the stock title chain calls this out of the lookup, store, bind, show order",
                ),
                None => report.add(
                    field,
                    IssueKind::Conflict,
                    "the stock title chain does not call this address",
                ),
            }
        }
    }

    fn validate_memory(&self, report: &mut ValidationReport) {
        report.require("memory.xip_base", self.memory.xip_base);
        report.require("memory.module_size", self.memory.module_size);
        let segments = match self.memory.validated_segments() {
            Ok(segments) => segments,
            Err(error) => {
                let kind = match error {
                    MappingError::Missing | MappingError::MissingSegments => IssueKind::Missing,
                    MappingError::InvalidModule | MappingError::InvalidSegment(_) => {
                        IssueKind::Invalid
                    }
                    MappingError::Overlap(_, _) | MappingError::XipBaseMismatch => {
                        IssueKind::Conflict
                    }
                    _ => IssueKind::OutOfBounds,
                };
                report.add("memory.segments", kind, error.to_string());
                Vec::new()
            }
        };
        let slack = report.require("memory.slack", self.memory.slack.as_ref());
        if let Some(slack) = slack {
            let range = slack.range();
            if range.start >= range.end
                || !self
                    .memory
                    .is_xip_range(range.start, range.end.saturating_sub(range.start))
            {
                report.add(
                    "memory.slack",
                    IssueKind::OutOfBounds,
                    "reserved firmware area must fit entirely in one XIP segment",
                );
            }
            if !slack.require_zero {
                report.add(
                    "memory.slack.require_zero",
                    IssueKind::Unsupported,
                    "nonzero firmware area cannot be used for loader allocation",
                );
            }
        }
        let link = report.require("memory.link_base", self.memory.link_base);
        let length = report.require("memory.link_size", self.memory.link_size);
        if let Some((base, size)) = link.zip(length) {
            if base % 4 != 0
                || !self.memory.is_xip_range(base, size)
                || !slack.is_some_and(|slack| slack.range().contains(base, size))
            {
                report.add(
                    "memory.link_base",
                    IssueKind::OutOfBounds,
                    "entire aligned link allocation must fit in reserved firmware space",
                );
            }
        }
        if let Some(ram) = self.memory.ram_pool {
            if ram.start == 0
                || ram.start >= ram.end
                || segments.iter().any(|segment| {
                    segment
                        .runtime_range()
                        .is_some_and(|range| range.overlaps(&ram))
                })
            {
                report.add(
                    "memory.ram_pool",
                    IssueKind::OutOfBounds,
                    "RAM pool is empty, invalid, or overlaps mapped firmware storage",
                );
            }
        }
    }
    /// The menu records every flashable rung installs. Their fields are
    /// checked by the menu validation once present.
    fn require_menu_page(&self, report: &mut ValidationReport) {
        report.require(
            "menu.setup.entry",
            self.menu
                .setup
                .as_ref()
                .and_then(|page| page.entry.as_ref()),
        );
        report.require("menu.text_platform", self.menu.text_platform.as_ref());
        report.require("menu.page", self.menu.page.as_ref());
    }

    pub(crate) fn service_addresses(&self) -> [(&'static str, Option<u64>); 24] {
        [
            ("services.fs_open", self.services.fs_open),
            ("services.fs_read", self.services.fs_read),
            ("services.fs_seek", self.services.fs_seek),
            ("services.fs_close", self.services.fs_close),
            ("services.fs_write", self.services.fs_write),
            ("services.dcache_inv_pre", self.services.dcache_inv_pre),
            ("services.dcache_inv_post", self.services.dcache_inv_post),
            ("services.dcache_clean", self.services.dcache_clean),
            ("services.worker_init", self.services.worker_init),
            ("services.worker_start", self.services.worker_start),
            ("services.flag_set", self.services.flag_set),
            ("services.registry_lookup", self.services.registry_lookup),
            ("services.mem_alloc", self.services.mem_alloc),
            ("services.mem_free", self.services.mem_free),
            (
                "services.exec.page_protect",
                self.services.exec.page_protect,
            ),
            ("services.exec.page_query", self.services.exec.page_query),
            (
                "services.exec.icache_inval",
                self.services.exec.icache_inval,
            ),
            (
                "services.exec.mmu_translate",
                self.services.exec.mmu_translate,
            ),
            ("services.exec.cacheable", self.services.exec.cacheable),
            ("services.exec.tlb_sync", self.services.exec.tlb_sync),
            ("ui.widget_find", self.ui.widget_find),
            ("ui.text_store", self.ui.text_store),
            ("ui.text_bind", self.ui.text_bind),
            ("ui.widget_show", self.ui.widget_show),
        ]
    }
    fn validate_services(&self, report: &mut ValidationReport) {
        if let Some(program) = &self.services.program {
            for (field, value) in program.entries() {
                if let Some(address) = value {
                    if address % 4 != 0 || !self.memory.is_xip_range(address, 4) {
                        report.add(
                            field,
                            IssueKind::OutOfBounds,
                            "program service must be aligned inside one target XIP segment",
                        );
                    }
                    if self
                        .memory
                        .slack
                        .as_ref()
                        .is_some_and(|slack| slack.range().contains(address, 4))
                    {
                        report.add(
                            field,
                            IssueKind::Conflict,
                            "stock program service points into reserved loader space",
                        );
                    }
                }
            }
            if program.keys.len() > 15 {
                report.add(
                    "services.program.keys",
                    IssueKind::Invalid,
                    "at most 15 keys: one per NLR_KEY_* bit",
                );
            }
            if program.input_slot.is_some() != program.input_original.is_some() {
                report.add(
                    "services.program.input_slot",
                    IssueKind::Invalid,
                    "the input slot and its stock occupant are declared together",
                );
            }
            if let Some(slot) = program.input_slot {
                let mapped = self.memory.segment_for_address(slot, 8);
                /* A slot the camera itself fills at run time is in DRAM the
                 * module does not cover, so it must be outside every mapped
                 * segment; one loaded with the image must be in declared RAM
                 * (and `validate_input` then reads the stock occupant there). */
                let placed = if program.input_slot_dynamic {
                    mapped.is_err()
                } else {
                    mapped.is_ok_and(|segment| segment.kind == crate::MemorySegmentKind::Ram)
                };
                if slot % 8 != 0 || !placed {
                    report.add(
                        "services.program.input_slot",
                        IssueKind::OutOfBounds,
                        if program.input_slot_dynamic {
                            "a run-time callback slot must be aligned and outside every mapped segment"
                        } else {
                            "the callback slot must be aligned inside declared initialized RAM"
                        },
                    );
                }
                /* One slot holds one callback: the program hook installed
                 * over the exit callback would drop MENU+DELETE, and which
                 * of the two wins would depend on installation order. */
                if self
                    .services
                    .exit
                    .as_ref()
                    .is_some_and(|exit| exit.input_callback == slot)
                {
                    report.add(
                        "services.program.input_slot",
                        IssueKind::Conflict,
                        "the program input slot is the exit callback's slot; \
                         declare the scan under services.platform.scan instead",
                    );
                }
                /* The bound is core's stack copy of the scan object
                 * (core/api.c), which holds four banks. */
                if !(1..=4).contains(&program.banks)
                    || program.bank_stride < 20
                    || program.bank_stride % 4 != 0
                    || program.bank_base % 4 != 0
                    || program.keep_bank >= program.banks
                    || program.keep_mask == 0
                    || program
                        .bank_base
                        .checked_add(program.banks.saturating_mul(program.bank_stride))
                        .is_none()
                    || program
                        .dial_offset
                        .checked_add(program.dial_bytes)
                        .is_none()
                    || program.dial_bytes > 32
                {
                    report.add(
                        "services.program.banks",
                        IssueKind::Invalid,
                        "input banks, retained exit controls and dial offsets must be bounded",
                    );
                }
                for [bank, mask] in &program.keys {
                    if *mask != 0
                        && (*bank >= program.banks
                            || (*bank == program.keep_bank && *mask & program.keep_mask != 0))
                    {
                        report.add(
                            "services.program.keys",
                            IssueKind::Conflict,
                            "keys must name declared banks and exclude the retained exit controls",
                        );
                    }
                }
            }
            if program.info_long_unit > 2 {
                report.add(
                    "services.program.info_long_unit",
                    IssueKind::Invalid,
                    "a long-name character is 1 byte (8-bit) or 2 (UTF-16LE)",
                );
            }
            if program.input_object.is_some() && program.input_slot.is_none() {
                report.add(
                    "services.program.input_object",
                    IssueKind::Invalid,
                    "the scan object belongs to a declared input slot",
                );
            }
            self.validate_escape_keys(program, report);
            validate_screen(program, report);
        }
        if self.services.fs_write.is_some()
            && (self.services.file_ops.write.is_none()
                || self.services.file_ops.open_read_write.is_none())
        {
            report.add(
                "services.fs_write",
                IssueKind::Invalid,
                "a write wrapper needs its operation and the read-write open flags",
            );
        }
        // Everything this loader writes has to leave the data cache before
        // another master reads it: the card's DMA behind a file write, an
        // instruction fetch after a code patch. Only the profile knows
        // which of a body's cache entries writes back instead of
        // discarding, and reusing the maintenance a read ends with happens
        // to be right on the Z 6III while silently losing every write on a
        // model where that entry is an invalidate.
        if (self.services.fs_write.is_some() || self.services.code.is_some())
            && self.services.dcache_clean.is_none()
        {
            report.add(
                "services.dcache_clean",
                IssueKind::Invalid,
                "writing files or patching code needs the D-cache entry that writes \
                 back to the point of coherency",
            );
        }
        // Creating a file needs the write wrapper as well, and the
        // attributes a created file gets are part of that declaration: a
        // create flag without them would make up the attribute word.
        if self.services.file_ops.open_write_create.is_some()
            && (self.services.fs_write.is_none()
                || self.services.file_ops.create_attributes.is_none())
        {
            report.add(
                "services.file_ops.open_write_create",
                IssueKind::Invalid,
                "creating a file needs the write wrapper and the created file's attributes",
            );
        }
        self.validate_code_window(report);
        self.validate_heap_record(report);
        for (field, value) in self.service_addresses() {
            if let Some(address) = value {
                if address % 4 != 0 || !self.memory.is_xip_range(address, 4) {
                    report.add(
                        field,
                        IssueKind::OutOfBounds,
                        "service function must be aligned inside one target XIP segment",
                    );
                }
                if self
                    .memory
                    .slack
                    .as_ref()
                    .is_some_and(|slack| slack.range().contains(address, 4))
                {
                    report.add(
                        field,
                        IssueKind::Conflict,
                        "stock service points into reserved loader space",
                    );
                }
            }
        }
    }
    /// The ABI 5 code channel's two windows. The patchable window is stock
    /// text, so it must sit inside one XIP segment and must not reach into
    /// the loader's own reserved space; the alias band is where those pages
    /// live in DRAM, so it must not be part of the module's image at all.
    /// The start-up escape's keys are read from one scan object: the
    /// program input slot's `input_object` (checked with the slot's banks
    /// above), or else the object under `[services.platform.scan]` (core
    /// `nlr_program_keys_now`). A key there must name one of that scan's
    /// banks and none of the bits the camera always keeps; a key with no
    /// object to read would never be seen held, which would make the escape
    /// look declared while it cannot work.
    fn validate_escape_keys(&self, program: &ProgramServices, report: &mut ValidationReport) {
        if !program.keys.iter().any(|[_, mask]| *mask != 0) {
            return;
        }
        if program.input_slot.is_some() && program.input_object.is_some() {
            return;
        }
        let scan = self
            .services
            .platform
            .as_ref()
            .and_then(|platform| platform.scan.as_ref())
            .filter(|scan| scan.object.is_some());
        let Some(scan) = scan else {
            report.add(
                "services.program.keys",
                IssueKind::Invalid,
                "keys need a scan object to be read from: services.program.input_object \
                 with its input slot, or services.platform.scan.object",
            );
            return;
        };
        for [bank, mask] in &program.keys {
            if *mask != 0
                && (*bank >= scan.banks || (*bank == scan.keep_bank && *mask & scan.keep_mask != 0))
            {
                report.add(
                    "services.program.keys",
                    IssueKind::Conflict,
                    "keys read from services.platform.scan must name its banks and \
                     exclude its kept bits",
                );
            }
        }
    }

    fn validate_code_window(&self, report: &mut ValidationReport) {
        let Some(code) = &self.services.code else {
            return;
        };
        let text_lo = report.require("services.code.text_lo", code.text_lo);
        let text_hi = report.require("services.code.text_hi", code.text_hi);
        let alias_lo = report.require("services.code.alias_lo", code.alias_lo);
        let alias_hi = report.require("services.code.alias_hi", code.alias_hi);
        if let (Some(lo), Some(hi)) = (text_lo, text_hi) {
            if hi <= lo || lo % 4 != 0 || hi % 4 != 0 {
                report.add(
                    "services.code.text_lo",
                    IssueKind::Invalid,
                    "the code window is a non-empty, instruction-aligned [lo, hi)",
                );
            } else if !self.memory.is_xip_range(lo, hi - lo) {
                report.add(
                    "services.code.text_lo",
                    IssueKind::OutOfBounds,
                    "the code window must lie inside one target XIP segment",
                );
            } else if self.memory.slack.as_ref().is_some_and(|slack| {
                slack
                    .range()
                    .overlaps(&crate::AddressRange { start: lo, end: hi })
            }) {
                report.add(
                    "services.code.text_lo",
                    IssueKind::Conflict,
                    "the code window reaches into reserved loader space",
                );
            }
        }
        if let (Some(lo), Some(hi)) = (alias_lo, alias_hi) {
            if hi <= lo || lo % 4096 != 0 || hi % 4096 != 0 {
                report.add(
                    "services.code.alias_lo",
                    IssueKind::Invalid,
                    "the alias band is a non-empty, page-aligned [lo, hi)",
                );
            } else if self.memory.segment_for_address(lo, 1).is_ok()
                || self.memory.segment_for_address(hi - 1, 1).is_ok()
            {
                report.add(
                    "services.code.alias_lo",
                    IssueKind::Conflict,
                    "the alias band is DRAM, not a mapped part of the module",
                );
            }
        }
        if self.services.exec.mmu_translate.is_none()
            || self.services.exec.page_query.is_none()
            || self.services.exec.icache_inval.is_none()
            || self.services.exec.manager.is_none()
            || self.services.dcache_clean.is_none()
        {
            report.add(
                "services.code",
                IssueKind::Invalid,
                "the code channel needs translate, query, the manager, the I-cache \
                 invalidation and the D-cache clean",
            );
        }
    }

    /// The allocator's own block record: every part is needed before the
    /// execution layer may believe a grant, the node pool must fit inside a
    /// plausible manager object, and a node must hold its three fields.
    fn validate_heap_record(&self, report: &mut ValidationReport) {
        let Some(heap) = &self.services.heap else {
            return;
        };
        let manager = report.require("services.heap.manager", heap.manager);
        let allocated = report.require("services.heap.list_allocated", heap.list_allocated);
        let pool = report.require("services.heap.node_pool", heap.node_pool);
        let count = report.require("services.heap.node_count", heap.node_count);
        let node_bytes = report.require("services.heap.node_bytes", heap.node_bytes);
        report.require("services.heap.node_next", heap.node_next);
        let base = report.require("services.heap.node_base", heap.node_base);
        let size = report.require("services.heap.node_size", heap.node_size);
        report.require("services.heap.guard_flag", heap.guard_flag);
        report.require("services.heap.guard_bytes", heap.guard_bytes);
        if let Some(address) = manager {
            // The manager is a live object in RAM, not a part of the module
            // image, and the loader reads it as 64-bit words.
            if address % 8 != 0 || self.memory.segment_for_address(address, 8).is_ok() {
                report.add(
                    "services.heap.manager",
                    IssueKind::OutOfBounds,
                    "the allocator's manager is an aligned object in RAM, outside the module image",
                );
            }
        }
        if let (Some(bytes), Some(next), Some(base), Some(size)) =
            (node_bytes, heap.node_next, base, size)
        {
            if bytes < 24
                || bytes % 8 != 0
                || [next, base, size]
                    .iter()
                    .any(|off| off % 8 != 0 || off + 8 > bytes)
                || next == base
                || base == size
                || next == size
            {
                report.add(
                    "services.heap.node_bytes",
                    IssueKind::Invalid,
                    "a node holds three distinct 64-bit fields inside its own length",
                );
            }
        }
        if let (Some(pool), Some(count), Some(bytes), Some(allocated)) =
            (pool, count, node_bytes, allocated)
        {
            let span = u64::from(count) * u64::from(bytes);
            if count == 0 || pool % 8 != 0 || u64::from(pool) <= u64::from(allocated) || span == 0 {
                report.add(
                    "services.heap.node_pool",
                    IssueKind::Invalid,
                    "the node pool follows the manager's own fields and holds at least one node",
                );
            }
        }
    }

    /// Declared file wrappers with the operation each must submit.
    fn file_operations(&self) -> [(&'static str, FileWrapper); 5] {
        let ops = &self.services.file_ops;
        [
            ("services.file_ops.open", (self.services.fs_open, ops.open)),
            ("services.file_ops.read", (self.services.fs_read, ops.read)),
            ("services.file_ops.seek", (self.services.fs_seek, ops.seek)),
            (
                "services.file_ops.close",
                (self.services.fs_close, ops.close),
            ),
            (
                "services.file_ops.write",
                (self.services.fs_write, ops.write),
            ),
        ]
    }

    /// Each declared file wrapper must store its declared operation into the
    /// request block: a 32-bit STR to [SP, #op_slot] of a register that a
    /// MOVZ or ORR-immediate loaded with that number earlier in the wrapper.
    fn validate_file_operations(&self, module: &[u8], report: &mut ValidationReport) {
        let Some(slot) = self.services.file_ops.op_slot else {
            return;
        };
        if slot % 4 != 0 || slot / 4 > 0xfff {
            report.add(
                "services.file_ops.op_slot",
                IssueKind::Invalid,
                "operation slot must be a 4-aligned 32-bit STR offset",
            );
            return;
        }
        // STR Wt, [SP, #slot]: size 10, unsigned offset, Rn = SP.
        let store = 0xb900_03e0u32 | ((slot / 4) << 10);
        for (field, (address, expected)) in self.file_operations() {
            let (Some(address), Some(expected)) = (address, expected) else {
                continue;
            };
            let Ok(offset) = self.memory.address_to_offset(address, 0x80) else {
                continue;
            };
            let Some(bytes) = usize::try_from(offset)
                .ok()
                .and_then(|start| module.get(start..start + 0x80))
            else {
                continue;
            };
            let words: Vec<u32> = bytes
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().expect("4 bytes")))
                .collect();
            let submitted = words.iter().enumerate().find_map(|(index, word)| {
                (word & 0xffff_ffe0 == store).then(|| {
                    let register = word & 0x1f;
                    words[..index]
                        .iter()
                        .rev()
                        .find_map(|earlier| w_register_constant(*earlier, register))
                })?
            });
            if submitted != Some(expected) {
                report.add(
                    field,
                    IssueKind::Conflict,
                    match submitted {
                        Some(actual) => format!(
                            "the wrapper at {address:#x} submits operation {actual}, not {expected}"
                        ),
                        None => format!("no operation store found in the wrapper at {address:#x}"),
                    },
                );
            }
        }
    }

    /// Service field names a load-only body calls, in check order.
    fn load_only_services(&self) -> [(&'static str, Option<u64>); 12] {
        [
            ("services.fs_open", self.services.fs_open),
            ("services.fs_read", self.services.fs_read),
            ("services.fs_seek", self.services.fs_seek),
            ("services.fs_close", self.services.fs_close),
            ("services.dcache_inv_pre", self.services.dcache_inv_pre),
            ("services.dcache_inv_post", self.services.dcache_inv_post),
            ("services.worker_init", self.services.worker_init),
            ("services.worker_start", self.services.worker_start),
            ("services.flag_set", self.services.flag_set),
            ("services.registry_lookup", self.services.registry_lookup),
            ("services.mem_alloc", self.services.mem_alloc),
            ("services.mem_free", self.services.mem_free),
        ]
    }

    fn validate_service_fingerprints(&self, mode: BuildMode, report: &mut ValidationReport) {
        if mode == BuildMode::Exec {
            if let Some(program) = &self.services.program {
                for (field, address) in program.entries() {
                    let name = field.strip_prefix("services.").expect("prefix");
                    if address.is_some() && !self.service_fingerprints.contains_key(name) {
                        report.add(format!("service_fingerprints.{name}"), IssueKind::Missing,
                            "execution calls this program service; an entry fingerprint is required");
                    }
                }
            }
        }
        // A fingerprint must name a declared service and sit exactly at its
        // address; otherwise the check would attest the wrong entry.
        for (name, fingerprint) in &self.service_fingerprints {
            let field = format!("service_fingerprints.{name}");
            let address = match name.as_str() {
                "fs_open" => self.services.fs_open,
                "fs_read" => self.services.fs_read,
                "fs_seek" => self.services.fs_seek,
                "fs_close" => self.services.fs_close,
                "fs_write" => self.services.fs_write,
                "dcache_inv_pre" => self.services.dcache_inv_pre,
                "dcache_inv_post" => self.services.dcache_inv_post,
                "dcache_clean" => self.services.dcache_clean,
                "worker_init" => self.services.worker_init,
                "worker_start" => self.services.worker_start,
                "flag_set" => self.services.flag_set,
                "registry_lookup" => self.services.registry_lookup,
                "mem_alloc" => self.services.mem_alloc,
                "mem_free" => self.services.mem_free,
                "exec.page_protect" => self.services.exec.page_protect,
                "exec.page_query" => self.services.exec.page_query,
                "exec.icache_inval" => self.services.exec.icache_inval,
                "exec.mmu_translate" => self.services.exec.mmu_translate,
                "exec.cacheable" => self.services.exec.cacheable,
                "exec.tlb_sync" => self.services.exec.tlb_sync,
                "exit.suspend" => self.services.exit.as_ref().map(|e| e.suspend),
                "exit.resume" => self.services.exit.as_ref().map(|e| e.resume),
                "exit.terminate" => self.services.exit.as_ref().map(|e| e.terminate),
                "exit.restart" => self.services.exit.as_ref().map(|e| e.restart),
                "widget_find" => self.ui.widget_find,
                "text_store" => self.ui.text_store,
                "text_bind" => self.ui.text_bind,
                "widget_show" => self.ui.widget_show,
                crate::BOOT_AUTOLOAD_FINGERPRINT => {
                    self.boot_hooks.autoload.as_ref().map(|call| call.callee)
                }
                crate::GUI_REDRAW_FINGERPRINT => {
                    self.services.platform.as_ref().and_then(|p| p.gui_redraw)
                }
                crate::ACTIVITY_FINGERPRINT => self
                    .services
                    .platform
                    .as_ref()
                    .and_then(|p| p.scan.as_ref())
                    .and_then(|s| s.activity),
                crate::TOUCH_FINGERPRINT => self
                    .services
                    .platform
                    .as_ref()
                    .and_then(|p| p.touch_original),
                crate::PROP_SET_FINGERPRINT => self
                    .services
                    .platform
                    .as_ref()
                    .and_then(|p| p.props.as_ref())
                    .and_then(|p| p.setter),
                crate::PROP_SET_BLOB_FINGERPRINT => self
                    .services
                    .platform
                    .as_ref()
                    .and_then(|p| p.props.as_ref())
                    .and_then(|p| p.setter_blob),
                other if other.starts_with("private_text.") => self
                    .menu
                    .private_text
                    .as_ref()
                    .and_then(|p| p.body(&other["private_text.".len()..]).map(|b| b.address)),
                other if other.starts_with("graphics.bitmap.") => self
                    .services
                    .graphics
                    .as_ref()
                    .and_then(|g| g.bitmap.entry(&other["graphics.bitmap.".len()..])),
                other if other.starts_with("paint.") => self
                    .services
                    .paint
                    .as_ref()
                    .and_then(|p| p.entry(&other["paint.".len()..])),
                other if other.starts_with("program.") => self
                    .services
                    .program
                    .as_ref()
                    .and_then(|p| p.entry(&other["program.".len()..])),
                other if other.starts_with("time.") => self
                    .services
                    .time
                    .as_ref()
                    .and_then(|time| time.entry(&other["time.".len()..])),
                other if other.starts_with("input.") => self
                    .services
                    .input
                    .as_ref()
                    .and_then(|input| input.entry(&other["input.".len()..])),
                other if other.starts_with("bitmap.") => self
                    .services
                    .bitmap
                    .as_ref()
                    .and_then(|b| b.entry(&other["bitmap.".len()..])),
                other if other.starts_with("native_card.") => self
                    .services
                    .native_card
                    .as_ref()
                    .and_then(|card| card.entry(&other["native_card.".len()..])),
                other => {
                    report.add(
                        &field,
                        IssueKind::Invalid,
                        format!("unknown service name {other}"),
                    );
                    continue;
                }
            };
            match (address, fingerprint.stock.len()) {
                (Some(address), len) if len > 0 => {
                    match self
                        .memory
                        .offset_to_address(fingerprint.eg_off, len as u64)
                    {
                        Ok(mapped) if mapped == address => {}
                        Ok(mapped) => report.add(
                            &field,
                            IssueKind::Conflict,
                            format!(
                                "fingerprint sits at {mapped:#x}, not at the declared {address:#x}"
                            ),
                        ),
                        Err(_) => report.add(
                            &field,
                            IssueKind::OutOfBounds,
                            "fingerprint offset does not map to memory",
                        ),
                    }
                }
                _ => report.add(
                    &field,
                    IssueKind::Invalid,
                    "fingerprint needs a nonempty stock and a declared service address",
                ),
            }
        }
        if matches!(
            mode,
            BuildMode::LoadOnly | BuildMode::PrepareOnly | BuildMode::Exec
        ) {
            for (field, _) in self.load_only_services() {
                let name = field.strip_prefix("services.").expect("prefix");
                if !self.service_fingerprints.contains_key(name) {
                    report.add(
                        format!("service_fingerprints.{name}"),
                        IssueKind::Missing,
                        "load-only calls this service; an entry fingerprint is required",
                    );
                }
            }
        }
        if matches!(
            mode,
            BuildMode::HookOnly
                | BuildMode::Page
                | BuildMode::LoadOnly
                | BuildMode::PrepareOnly
                | BuildMode::Exec
        ) && self
            .menu
            .setup
            .as_ref()
            .is_some_and(|page| page.entry.is_some())
            && !self.service_fingerprints.contains_key("text_store")
        {
            report.add(
                "service_fingerprints.text_store",
                IssueKind::Missing,
                "menu initialization calls the text writer; an entry fingerprint is required",
            );
        }
        if matches!(
            mode,
            BuildMode::HookOnly
                | BuildMode::Page
                | BuildMode::LoadOnly
                | BuildMode::PrepareOnly
                | BuildMode::Exec
        ) && self.menu.page.is_some()
        {
            for name in ["widget_find", "text_store", "text_bind", "widget_show"] {
                if !self.service_fingerprints.contains_key(name) {
                    report.add(
                        format!("service_fingerprints.{name}"),
                        IssueKind::Missing,
                        "the NLoader page entry calls this service; an entry fingerprint is required",
                    );
                }
            }
        }
    }

    fn validate_task(&self, mode: BuildMode, report: &mut ValidationReport) {
        // The core rejects these at init, but a wrong task configuration must
        // fail validation, not on the body (AUDIT C4). Required only for the
        // modes whose page constructs the worker; range checks apply
        // whenever a value is declared.
        let task = &self.task;
        let core = task.core;
        let priority = task.priority;
        if let Some(core) = core {
            if core > 3 {
                report.add(
                    "task.core",
                    IssueKind::OutOfBounds,
                    "task core exceeds the firmware creator bound (3)",
                );
            }
        }
        if let Some(priority) = priority {
            if priority == 0 || priority > 256 {
                report.add(
                    "task.priority",
                    IssueKind::OutOfBounds,
                    "task priority must be 1..=256",
                );
            }
        }
        if let Some(stack) = task.stack {
            if stack == 0 || stack > u32::MAX as u64 - 15 {
                report.add(
                    "task.stack",
                    IssueKind::OutOfBounds,
                    "task stack must be nonzero and fit the config field",
                );
            }
        }
        if matches!(
            mode,
            BuildMode::LoadOnly | BuildMode::PrepareOnly | BuildMode::Exec
        ) || (mode == BuildMode::Page && self.menu.private_text.is_some())
        {
            report.require("task.core", core);
            report.require("task.priority", priority);
            report.require("task.stack", task.stack);
            if let Some(name) = report.require("task.name", task.name.as_deref()) {
                let bytes = name.as_bytes();
                if bytes.is_empty() || bytes.len() > 8 {
                    report.add(
                        "task.name",
                        IssueKind::Invalid,
                        "task name must be 1..=8 bytes (registry copy is 8 wide)",
                    );
                }
            }
        }
    }

    fn validate_updater(&self, report: &mut ValidationReport) {
        let module_size = self.memory.module_size.unwrap_or(0);
        let mut file_ranges: Vec<(u64, u64)> = Vec::new();
        for (index, version) in self.updater.version_literals.iter().enumerate() {
            let field = format!("updater.version_literals[{index}]");
            if version.stock.is_empty() || version.stock.len() != version.patched.len() {
                report.add(
                    &field,
                    IssueKind::Invalid,
                    "version edit must be nonempty and preserve byte length",
                );
            }
            let end = version
                .eg_off
                .checked_add(version.stock.len() as u64)
                .filter(|end| *end <= module_size);
            if end.is_none() {
                report.add(
                    &field,
                    IssueKind::OutOfBounds,
                    "module-relative version offset exceeds target module",
                );
                continue;
            }
            let end = end.unwrap();
            if file_ranges
                .iter()
                .any(|(start, other_end)| version.eg_off < *other_end && *start < end)
            {
                report.add(
                    &field,
                    IssueKind::Conflict,
                    "version literals overlap each other in module file space",
                );
            }
            file_ranges.push((version.eg_off, end));
            // Runtime overlap checks apply only when the whole range maps to
            // one memory segment; the eg trailer copy is file-only by design.
            // A literal that merely straddles a segment boundary is neither
            // file-only nor mapped and is refused (AUDIT C1).
            match self
                .memory
                .offset_to_address(version.eg_off, version.stock.len() as u64)
                .ok()
                .and_then(|start| {
                    start
                        .checked_add(version.stock.len() as u64)
                        .map(|end| AddressRange { start, end })
                }) {
                Some(range) => {
                    if self
                        .memory
                        .slack
                        .as_ref()
                        .is_some_and(|slack| range.overlaps(&slack.range()))
                    {
                        report.add(
                            field,
                            IssueKind::Conflict,
                            "version edit overlaps another reserved edit",
                        );
                    }
                }
                None => {
                    // Unmapped is only legal when the range lies entirely
                    // outside every segment; straddling one is an error.
                    let straddles = self
                        .memory
                        .validated_segments()
                        .map(|segments| {
                            segments.iter().any(|segment| {
                                version.eg_off < segment.file_offset + segment.size
                                    && segment.file_offset < end
                            })
                        })
                        .unwrap_or(false);
                    if straddles {
                        report.add(
                            field,
                            IssueKind::Invalid,
                            "version literal straddles a segment boundary",
                        );
                    }
                }
            }
        }
    }
}
fn runtime_slice<'a>(
    bytes: &'a [u8],
    memory: &Memory,
    address: u64,
    length: u64,
) -> Option<&'a [u8]> {
    if length == 0 {
        return None;
    }
    let start = usize::try_from(memory.address_to_offset(address, length).ok()?).ok()?;
    let length = usize::try_from(length).ok()?;
    bytes.get(start..start.checked_add(length)?)
}

/// A declared file wrapper: its address and the request operation it must
/// submit.
type FileWrapper = (Option<u64>, Option<u32>);

/// The constant a 32-bit `MOVZ Wd, #imm16` or `ORR Wd, WZR, #bitmask` loads
/// into register `register`, or None for any other instruction. Both are
/// how compilers spell `mov wN, #imm`.
fn w_register_constant(word: u32, register: u32) -> Option<u32> {
    if word & 0x1f != register {
        return None;
    }
    if word & 0xffe0_0000 == 0x5280_0000 {
        return Some((word >> 5) & 0xffff);
    }
    // ORR (immediate), 32-bit, N = 0, Rn = WZR.
    if word & 0xffc0_03e0 == 0x3200_03e0 {
        let immr = (word >> 16) & 0x3f;
        let imms = (word >> 10) & 0x3f;
        let length = 5 - (!imms & 0x3f).leading_zeros().checked_sub(26)?;
        let size = 1u32 << length;
        let levels = size - 1;
        let ones = (imms & levels) + 1;
        if ones >= size {
            return None;
        }
        let element = (1u64 << ones) - 1;
        let rotation = immr & levels;
        let element =
            ((element >> rotation) | (element << (size - rotation))) & ((1u64 << size) - 1);
        let mut value = 0u64;
        let mut shift = 0;
        while shift < 32 {
            value |= element << shift;
            shift += size;
        }
        return Some(value as u32);
    }
    None
}

/// The screen: scanout registers are aligned word pairs, the alpha pair
/// only beside a colour pair, and the plane band holds a whole surface of
/// the declared geometry (4:2:2, two bytes a pixel; one alpha byte a pixel).
fn validate_screen(program: &ProgramServices, report: &mut ValidationReport) {
    let Some(colour) = program.scanout_colour else {
        if program.scanout_alpha.is_some() {
            report.add(
                "services.program.scanout_alpha",
                IssueKind::Invalid,
                "an alpha register pair needs the colour pair it belongs to",
            );
        }
        return;
    };
    for (field, value) in [
        ("services.program.scanout_colour", Some(colour)),
        ("services.program.scanout_alpha", program.scanout_alpha),
    ] {
        if let Some(address) = value {
            if address == 0 || address % 4 != 0 || address.checked_add(8).is_none() {
                report.add(
                    field,
                    IssueKind::OutOfBounds,
                    "a scanout register pair is two aligned 32-bit words",
                );
            }
        }
    }
    let rows = u64::from(program.height);
    let pixels = u64::from(program.stride) * rows;
    let alpha = u64::from(program.alpha_stride) * rows;
    let band = program.plane_hi.saturating_sub(program.plane_lo);
    if program.width == 0
        || program.width % 2 != 0
        || program.height == 0
        || u64::from(program.stride) < u64::from(program.width) * 2
        || pixels > u64::from(u32::MAX)
        || (program.scanout_alpha.is_some()
            && (program.alpha_stride < program.width || alpha > u64::from(u32::MAX)))
    {
        report.add(
            "services.program.width",
            IssueKind::Invalid,
            "the screen geometry does not describe a 4:2:2 surface (and its alpha plane)",
        );
    }
    if program.plane_lo == 0 || band < pixels.max(alpha) {
        report.add(
            "services.program.plane_lo",
            IssueKind::OutOfBounds,
            "the plane band must be a nonzero range that holds a whole surface",
        );
    }
}

#[cfg(test)]
mod constant_tests {
    use super::w_register_constant;

    #[test]
    fn decodes_both_spellings_of_mov_w() {
        assert_eq!(w_register_constant(0x3200_07e2, 2), Some(3)); /* orr w2, wzr, #3 */
        assert_eq!(w_register_constant(0x3200_03e1, 1), Some(1)); /* orr w1, wzr, #1 */
        assert_eq!(w_register_constant(0x5280_4402, 2), Some(0x220)); /* movz w2, #0x220 */
        assert_eq!(w_register_constant(0x3200_07e2, 1), None); /* other register */
        assert_eq!(w_register_constant(0x2a1f_03e1, 1), None); /* orr w1, wzr, wzr */
    }
}
