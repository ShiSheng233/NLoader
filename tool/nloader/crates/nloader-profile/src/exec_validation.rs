//! Execution-family contracts and profile-owned stock evidence. Complete
//! function hashes supplement entry fingerprints; semantic references bind
//! those functions, native contexts and tables to the services being called.
use crate::validation::{hash_matches, valid_hash};
use crate::{
    sha256, BuildMode, ExecutionBody, ExecutionTable, IssueKind, MmuFamily, Profile,
    ValidationReport,
};
use std::collections::BTreeSet;

// Minimum complete audited spans are family structure constraints. A profile
// cannot shrink evidence to a matching prologue when declaring a new image.
const REQUIRED_BODIES_Z63: &[(&str, u32)] = &[
    ("tlb_sync", 20),
    ("cache_dispatch", 20),
    ("protect_cache", 204),
    ("heap_alloc", 32),
    ("heap_free", 24),
    ("query", 48),
    ("protect", 92),
    ("translate", 108),
    ("icache_wrapper", 32),
    ("dcache_clean", 28),
    ("leaf_modify", 212),
    ("query_body", 172),
    ("protect_body", 500),
    ("cacheable", 76),
    ("icache_body", 136),
    ("table_walk", 280),
    ("worker_affinity", 276),
];
/// This image carries no attribute table: `leaf_modify` ORs its attribute
/// immediates in the dispatch arms themselves.
const REQUIRED_TABLES_Z63: &[(&str, u8, usize)] =
    &[("affinity_table", 4, 4), ("attribute_dispatch", 1, 11)];
const REQUIRED_BODIES: &[(&str, u32)] = &[
    ("tlb_sync", 88),
    ("cache_dispatch", 20),
    ("protect_cache", 224),
    ("heap_alloc", 64),
    ("heap_free", 112),
    ("query", 52),
    ("protect", 92),
    ("translate", 108),
    ("icache_wrapper", 36),
    ("dcache_clean", 128),
    ("leaf_modify", 204),
    ("query_body", 188),
    ("protect_body", 508),
    ("cacheable", 64),
    ("icache_body", 136),
    ("table_walk", 280),
    ("worker_affinity", 272),
];
const REQUIRED_TABLES: &[(&str, u8, usize)] = &[
    ("affinity_table", 4, 4),
    ("attribute_table", 4, 8),
    ("attribute_dispatch", 8, 11),
];
/// Bodies only an aligned-allocation declaration (`services.exec.memalign`)
/// brings, with the spans measured in the Z8 image: the heap's locked
/// aligned entry and the locked allocation `heap_alloc` calls.
const MEMALIGN_BODIES: &[(&str, u32)] = &[("heap_memalign", 116), ("heap_mspace_malloc", 96)];
fn execution(mode: BuildMode) -> bool {
    matches!(mode, BuildMode::PrepareOnly | BuildMode::Exec)
}

impl Profile {
    /// The complete stock functions this image's family needs, with the
    /// spans measured in that image. The spans exist so a profile cannot
    /// shrink its evidence to a matching prologue, so they are per family:
    /// the same service is not the same number of bytes in two images.
    fn required_bodies(&self) -> &'static [(&'static str, u32)] {
        match self.abi.mmu {
            Some(MmuFamily::Z63BlockV1) => REQUIRED_BODIES_Z63,
            _ => REQUIRED_BODIES,
        }
    }
    fn required_tables(&self) -> &'static [(&'static str, u8, usize)] {
        match self.abi.mmu {
            Some(MmuFamily::Z63BlockV1) => REQUIRED_TABLES_Z63,
            _ => REQUIRED_TABLES,
        }
    }
    pub(crate) fn validate_execution(&self, mode: BuildMode, report: &mut ValidationReport) {
        if !execution(mode) {
            return;
        }
        match self.abi.mmu {
            // Both families are the same mapping service; they differ only
            // in how the attribute dispatch encodes its arms.
            Some(MmuFamily::Z8BlockV1 | MmuFamily::Z63BlockV1) => {
                self.validate_block_execution(report)
            }
            None => {} // validate_families reports the missing selector.
        }
    }

    fn validate_block_execution(&self, report: &mut ValidationReport) {
        let e = &self.services.exec;
        if let Some(bytes) = report.require("services.exec.region_bytes", e.region_bytes) {
            if bytes != 0x200000 {
                report.add(
                    "services.exec.region_bytes",
                    IssueKind::Unsupported,
                    "z8_block_v1 requires a complete owned 2MiB L2 block",
                );
            }
        }
        let writable = report.require("services.exec.flag_writable", e.flag_writable);
        let executable = report.require("services.exec.flag_executable", e.flag_executable);
        // No byte in the image IS a permission encoding, so correctness is
        // carried by the audit inside the mapping adapter plus real runs;
        // validation can only refuse vacuous or collapsed declarations.
        if writable == Some(0) {
            report.add(
                "services.exec.flag_writable",
                IssueKind::Invalid,
                "permission encoding must be nonzero",
            );
        }
        if executable == Some(0) {
            report.add(
                "services.exec.flag_executable",
                IssueKind::Invalid,
                "permission encoding must be nonzero",
            );
        }
        if writable.is_some() && writable == executable {
            report.add(
                "services.exec.flag_executable",
                IssueKind::Invalid,
                "writable and executable encodings must differ",
            );
        }
        for (name, value, body) in [
            ("page_query", e.page_query, "query"),
            ("page_protect", e.page_protect, "protect"),
            ("mmu_translate", e.mmu_translate, "translate"),
            ("icache_inval", e.icache_inval, "icache_wrapper"),
            ("cacheable", e.cacheable, "cacheable"),
            ("tlb_sync", e.tlb_sync, "tlb_sync"),
        ] {
            let field = format!("services.exec.{name}");
            if let Some(address) = report.require(&field, value) {
                self.require_body_address(body, address, &field, report);
            }
            let fingerprint = format!("exec.{name}");
            if !self.service_fingerprints.contains_key(&fingerprint) {
                report.add(
                    format!("service_fingerprints.{fingerprint}"),
                    IssueKind::Missing,
                    "execution requires an entry fingerprint",
                );
            }
        }
        for (name, value, body) in [
            (
                "dcache_inv_post",
                self.services.dcache_inv_post,
                "dcache_clean",
            ),
            ("mem_alloc", self.services.mem_alloc, "heap_alloc"),
            ("mem_free", self.services.mem_free, "heap_free"),
        ] {
            let field = format!("services.{name}");
            if let Some(address) = report.require(&field, value) {
                self.require_body_address(body, address, &field, report);
            }
        }
        // The entry a profile names as its write-back must be the body the
        // execution checks know as the clean. Naming anything else would
        // be a write that quietly never reaches the card.
        if let Some(address) = self.services.dcache_clean {
            self.require_body_address("dcache_clean", address, "services.dcache_clean", report);
        }
        for (name, address) in [("manager", e.manager), ("cache_manager", e.cache_manager)] {
            if let Some(address) = report.require(&format!("services.exec.{name}"), address) {
                if address == 0 || address % 8 != 0 {
                    report.add(
                        format!("services.exec.{name}"),
                        IssueKind::Invalid,
                        "native context must be nonzero and aligned to 8 bytes",
                    );
                }
            }
        }
        // Core zero invokes a different scheduler path; this probe uses CPU0.
        if self.task.core != Some(1) {
            report.add(
                "task.core",
                IssueKind::Unsupported,
                "probe execution requires core=1 (CPU0 affinity)",
            );
        }
        let mut names = BTreeSet::new();
        for body in &e.bodies {
            let field = format!("services.exec.bodies.{}", body.name);
            let known = self.known_body(&body.name);
            if known.is_none() || !names.insert(body.name.as_str()) {
                report.add(
                    &field,
                    IssueKind::Invalid,
                    "unknown or duplicate execution body",
                );
            }
            if known.is_some_and(|length| body.length < length) {
                report.add(
                    &field,
                    IssueKind::Invalid,
                    "function evidence is shorter than the complete audited family span",
                );
            }
            if body.length == 0
                || body.length % 4 != 0
                || body.address % 4 != 0
                || !self
                    .memory
                    .is_xip_range(body.address, u64::from(body.length))
            {
                report.add(
                    &field,
                    IssueKind::OutOfBounds,
                    "whole function must be aligned and contained in target XIP",
                );
            }
            if !valid_hash(&body.sha256) {
                report.add(
                    &field,
                    IssueKind::Invalid,
                    "expected 64 hexadecimal SHA-256 digits",
                );
            }
        }
        for (name, _) in self.required_bodies() {
            if !names.contains(name) {
                report.add(
                    format!("services.exec.bodies.{name}"),
                    IssueKind::Missing,
                    "selected execution family requires this complete stock function",
                );
            }
        }
        self.validate_memalign(&names, report);
        let mut names = BTreeSet::new();
        for table in &e.tables {
            let field = format!("services.exec.tables.{}", table.name);
            let expected = self
                .required_tables()
                .iter()
                .find(|(name, _, _)| *name == table.name);
            if !names.insert(table.name.as_str()) || expected.is_none() {
                report.add(
                    &field,
                    IssueKind::Invalid,
                    "unknown or duplicate execution table",
                );
            }
            if !expected.is_some_and(|(_, width, count)| {
                *width == table.element_bytes && *count == table.values.len()
            }) {
                report.add(
                    &field,
                    IssueKind::Invalid,
                    "table shape differs from the selected family",
                );
            }
            let size = u64::from(table.element_bytes).checked_mul(table.values.len() as u64);
            // A byte-wide dispatch is as legitimate as a word-wide one;
            // what matters is that the span is mapped and aligned to its
            // own element.
            if !matches!(table.element_bytes, 1 | 4 | 8)
                || !size.is_some_and(|size| {
                    table.address % u64::from(table.element_bytes) == 0
                        && self.memory.address_to_offset(table.address, size).is_ok()
                })
            {
                report.add(
                    &field,
                    IssueKind::OutOfBounds,
                    "table must be aligned and mapped in the target module",
                );
            }
            if table.element_bytes == 4
                && table
                    .values
                    .iter()
                    .any(|value| *value > u64::from(u32::MAX))
            {
                report.add(
                    &field,
                    IssueKind::Invalid,
                    "table value exceeds its element width",
                );
            }
        }
        for (name, _, _) in self.required_tables() {
            if !names.contains(name) {
                report.add(
                    format!("services.exec.tables.{name}"),
                    IssueKind::Missing,
                    "selected execution family requires this native table",
                );
            }
        }
        if let Some(table) = self.execution_table("affinity_table") {
            if table.values.get(1) != Some(&1) {
                report.add(
                    "services.exec.tables.affinity_table",
                    IssueKind::Conflict,
                    "the selected task core must encode CPU0 affinity",
                );
            }
        }
        if let (Some(table), Some(body)) = (
            self.execution_table("attribute_dispatch"),
            self.execution_body("leaf_modify"),
        ) {
            let offsets = self
                .abi
                .mmu
                .is_some_and(crate::MmuFamily::dispatch_is_offsets);
            if table.values.iter().any(|value| {
                // Offsets are in instructions from a label inside the body;
                // addresses name the instruction outright.
                let address = if offsets {
                    match value
                        .checked_mul(4)
                        .and_then(|v| body.address.checked_add(v))
                    {
                        Some(address) => address,
                        None => return true,
                    }
                } else {
                    *value
                };
                address % 4 != 0
                    || address < body.address
                    || body
                        .address
                        .checked_add(u64::from(body.length))
                        .is_none_or(|end| address >= end)
            }) {
                report.add(
                    "services.exec.tables.attribute_dispatch",
                    IssueKind::Conflict,
                    "attribute dispatch entries must target instructions inside leaf_modify",
                );
            }
        }
    }

    /// The minimum audited span of an execution body this profile may
    /// declare, or None for a name the family does not know. The aligned
    /// entry's bodies are Z8 bodies.
    fn known_body(&self, name: &str) -> Option<u32> {
        self.required_bodies()
            .iter()
            .chain(if matches!(self.abi.mmu, Some(MmuFamily::Z8BlockV1)) {
                MEMALIGN_BODIES
            } else {
                &[]
            })
            .find(|(known, _)| *known == name)
            .map(|(_, length)| *length)
    }

    /// `services.exec.memalign` and `memalign_heap` come together, with both
    /// of their bodies, on the Z8 family only, and never beside a heap with
    /// grant books (`[services.heap]`): those exist because that heap may
    /// answer short and map past a grant, which its aligned entry would not
    /// survive either. The stock relations are checked against the image
    /// (validate_execution_bytes).
    fn validate_memalign(&self, bodies: &BTreeSet<&str>, report: &mut ValidationReport) {
        let e = &self.services.exec;
        match (e.memalign, e.memalign_heap) {
            (None, None) => {
                for (name, _) in MEMALIGN_BODIES {
                    if bodies.contains(name) {
                        report.add(
                            format!("services.exec.bodies.{name}"),
                            IssueKind::Invalid,
                            "aligned-allocation body declared without services.exec.memalign",
                        );
                    }
                }
            }
            (Some(entry), Some(heap)) => {
                if !matches!(self.abi.mmu, Some(MmuFamily::Z8BlockV1)) {
                    report.add(
                        "services.exec.memalign",
                        IssueKind::Unsupported,
                        "the aligned heap entry is audited for z8_block_v1 only",
                    );
                }
                if self.services.heap.is_some() {
                    report.add(
                        "services.exec.memalign",
                        IssueKind::Conflict,
                        "a heap with grant books does not take the aligned entry",
                    );
                }
                for (name, _) in MEMALIGN_BODIES {
                    if !bodies.contains(name) {
                        report.add(
                            format!("services.exec.bodies.{name}"),
                            IssueKind::Missing,
                            "the aligned entry requires this complete stock function",
                        );
                    }
                }
                if self
                    .execution_body("heap_memalign")
                    .is_none_or(|b| b.address != entry)
                {
                    report.add(
                        "services.exec.memalign",
                        IssueKind::Conflict,
                        "service entry differs from its complete stock function",
                    );
                }
                if heap == 0 || heap % 8 != 0 {
                    report.add(
                        "services.exec.memalign_heap",
                        IssueKind::Invalid,
                        "the heap handle word must be nonzero and aligned to 8 bytes",
                    );
                }
            }
            (entry, _) => report.add(
                if entry.is_some() {
                    "services.exec.memalign_heap"
                } else {
                    "services.exec.memalign"
                },
                IssueKind::Missing,
                "memalign and memalign_heap are declared together",
            ),
        }
    }

    fn require_body_address(
        &self,
        name: &str,
        address: u64,
        field: &str,
        report: &mut ValidationReport,
    ) {
        if self
            .execution_body(name)
            .is_some_and(|body| body.address != address)
        {
            report.add(
                field,
                IssueKind::Conflict,
                "service entry differs from its complete stock function",
            );
        }
    }

    pub(crate) fn validate_execution_bytes(
        &self,
        mode: BuildMode,
        module: &[u8],
        report: &mut ValidationReport,
    ) {
        if !execution(mode) {
            return;
        }
        match self.abi.mmu {
            Some(MmuFamily::Z8BlockV1 | MmuFamily::Z63BlockV1) => {}
            None => return,
        }
        for body in &self.services.exec.bodies {
            if !self
                .execution_slice(module, body.address, body.length as usize)
                .is_some_and(|bytes| hash_matches(&sha256(bytes), &body.sha256))
            {
                report.add(
                    format!("services.exec.bodies.{}", body.name),
                    IssueKind::FingerprintMismatch,
                    "complete stock function differs from the official image",
                );
            }
        }
        for table in &self.services.exec.tables {
            if !matches!(table.element_bytes, 1 | 4 | 8) {
                continue;
            }
            let bytes: Vec<_> = table
                .values
                .iter()
                .flat_map(|value| {
                    value
                        .to_le_bytes()
                        .into_iter()
                        .take(usize::from(table.element_bytes))
                })
                .collect();
            if self.execution_slice(module, table.address, bytes.len()) != Some(bytes.as_slice()) {
                report.add(
                    format!("services.exec.tables.{}", table.name),
                    IssueKind::FingerprintMismatch,
                    "native table differs from the official image",
                );
            }
        }
        // Decode pointer construction at the family's audited instruction
        // slots. The immediate bits carry model-specific addresses and are
        // never code constants. The slots themselves are per family: the
        // same service builds the same pointer at its own offsets, into
        // whichever register that image's compiler chose.
        let z63 = self
            .abi
            .mmu
            .is_some_and(crate::MmuFamily::dispatch_is_offsets);
        let slots: [(&str, &str, u32, [usize; 4]); 6] = if z63 {
            [
                ("manager", "query", 8, [4, 12, 20, 28]),
                ("manager", "protect", 9, [48, 56, 64, 72]),
                ("cache_manager", "icache_wrapper", 8, [0, 8, 16, 20]),
                ("cache_manager", "protect_body", 0, [140, 148, 156, 160]),
                (
                    "tables.affinity_table",
                    "worker_affinity",
                    8,
                    [112, 116, 120, 124],
                ),
                (
                    "tables.attribute_dispatch",
                    "leaf_modify",
                    10,
                    [104, 108, 112, 116],
                ),
            ]
        } else {
            [
                ("manager", "query", 9, [8, 12, 16, 20]),
                ("manager", "protect", 9, [48, 52, 56, 64]),
                ("cache_manager", "icache_wrapper", 8, [0, 4, 8, 12]),
                ("cache_manager", "protect_body", 0, [148, 152, 156, 160]),
                (
                    "tables.affinity_table",
                    "worker_affinity",
                    9,
                    [112, 116, 120, 124],
                ),
                (
                    "tables.attribute_dispatch",
                    "leaf_modify",
                    10,
                    [108, 112, 116, 120],
                ),
            ]
        };
        for (field, body, register, offsets) in slots {
            let expected = match field {
                "manager" => self.services.exec.manager,
                "cache_manager" => self.services.exec.cache_manager,
                "tables.affinity_table" => {
                    self.execution_table("affinity_table").map(|t| t.address)
                }
                _ => self
                    .execution_table("attribute_dispatch")
                    .map(|t| t.address),
            };
            if let (Some(expected), Some(body)) = (expected, self.execution_body(body)) {
                let actual = self
                    .execution_slice(module, body.address, body.length as usize)
                    .and_then(|bytes| decode_wide_address(bytes, register, offsets));
                if actual != Some(expected) {
                    report.add(
                        format!("services.exec.{field}"),
                        IssueKind::Conflict,
                        "declared address differs from the native function's pointer construction",
                    );
                }
            }
        }
        // Z8 also builds an attribute table pointer; images without that
        // table have nothing to decode.
        if let (Some(expected), Some(body)) = (
            self.execution_table("attribute_table").map(|t| t.address),
            self.execution_body("query_body"),
        ) {
            let actual = self
                .execution_slice(module, body.address, body.length as usize)
                .and_then(|bytes| decode_wide_address(bytes, 11, [108, 112, 116, 124]));
            if actual != Some(expected) {
                report.add(
                    "services.exec.tables.attribute_table",
                    IssueKind::Conflict,
                    "declared address differs from the native function's pointer construction",
                );
            }
        }
        for (source, target) in [
            ("query", "query_body"),
            ("protect", "protect_body"),
            ("translate", "table_walk"),
            ("query_body", "table_walk"),
            ("protect_body", "table_walk"),
            ("protect_body", "leaf_modify"),
            ("protect_body", "cache_dispatch"),
            ("cache_dispatch", "protect_cache"),
            ("icache_wrapper", "icache_body"),
        ] {
            if let (Some(source), Some(target)) =
                (self.execution_body(source), self.execution_body(target))
            {
                if !self
                    .execution_slice(module, source.address, source.length as usize)
                    .is_some_and(|bytes| branches_to(bytes, source.address, target.address))
                {
                    report.add(
                        format!("services.exec.bodies.{}", source.name),
                        IssueKind::Conflict,
                        format!(
                            "native function does not branch to declared {}",
                            target.name
                        ),
                    );
                }
            }
        }
        self.validate_memalign_bytes(module, report);
    }

    /// The aligned entry works on the heap the loader's blocks come from and
    /// go back to: `heap_alloc` (mem_alloc) builds the pool table whose first
    /// entry's handle `memalign_heap` names -- the loader always asks for
    /// pool 0 -- and calls `heap_mspace_malloc`; `heap_free` (mem_free)
    /// builds the same table to find the pool a block lies in; and the
    /// aligned entry takes the same heap lock as that allocation.
    fn validate_memalign_bytes(&self, module: &[u8], report: &mut ValidationReport) {
        let Some(heap) = self.services.exec.memalign_heap else {
            return;
        };
        let decode = |body: &str, register: u32, offsets: [usize; 4]| {
            self.execution_body(body).and_then(|b| {
                self.execution_slice(module, b.address, b.length as usize)
                    .and_then(|bytes| decode_wide_address(bytes, register, offsets))
            })
        };
        if decode("heap_alloc", 8, [4, 8, 12, 20]) != Some(heap) {
            report.add(
                "services.exec.memalign_heap",
                IssueKind::Conflict,
                "mem_alloc does not build the pool table this handle word heads",
            );
        }
        if decode("heap_free", 9, [0, 4, 8, 20]) != Some(heap) {
            report.add(
                "services.exec.memalign_heap",
                IssueKind::Conflict,
                "mem_free does not resolve blocks through the same pool table",
            );
        }
        if let (Some(alloc), Some(malloc)) = (
            self.execution_body("heap_alloc"),
            self.execution_body("heap_mspace_malloc"),
        ) {
            if !self
                .execution_slice(module, alloc.address, alloc.length as usize)
                .is_some_and(|bytes| branches_to(bytes, alloc.address, malloc.address))
            {
                report.add(
                    "services.exec.bodies.heap_alloc",
                    IssueKind::Conflict,
                    "native function does not branch to declared heap_mspace_malloc",
                );
            }
        }
        let lock = decode("heap_mspace_malloc", 21, [24, 28, 32, 36]);
        if lock.is_none_or(|lock| lock == 0)
            || decode("heap_memalign", 22, [36, 40, 44, 48]) != lock
        {
            report.add(
                "services.exec.memalign",
                IssueKind::Conflict,
                "the aligned entry does not take the allocation's heap lock",
            );
        }
    }

    fn execution_body(&self, name: &str) -> Option<&ExecutionBody> {
        self.services
            .exec
            .bodies
            .iter()
            .find(|body| body.name == name)
    }
    fn execution_table(&self, name: &str) -> Option<&ExecutionTable> {
        self.services
            .exec
            .tables
            .iter()
            .find(|table| table.name == name)
    }
    fn execution_slice<'a>(&self, module: &'a [u8], address: u64, size: usize) -> Option<&'a [u8]> {
        let offset = self.memory.address_to_offset(address, size as u64).ok()?;
        let start = usize::try_from(offset).ok()?;
        module.get(start..start.checked_add(size)?)
    }
}

fn decode_wide_address(bytes: &[u8], register: u32, offsets: [usize; 4]) -> Option<u64> {
    let mut value = 0;
    for (half, offset) in offsets.into_iter().enumerate() {
        let instruction = u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?);
        let opcode = if half == 0 { 0xd280_0000 } else { 0xf280_0000 };
        if instruction & 0xffe0_001f != opcode | ((half as u32) << 21) | register {
            return None;
        }
        value |= u64::from((instruction >> 5) & 0xffff) << (half * 16);
    }
    Some(value)
}
fn branches_to(bytes: &[u8], address: u64, target: u64) -> bool {
    bytes.chunks_exact(4).enumerate().any(|(index, bytes)| {
        let instruction = u32::from_le_bytes(bytes.try_into().expect("four bytes"));
        if instruction & 0x7c00_0000 != 0x1400_0000 {
            return false;
        }
        let displacement = i64::from(((instruction & 0x03ff_ffff) << 6) as i32) >> 4;
        address
            .checked_add(index as u64 * 4)
            .and_then(|pc| pc.checked_add_signed(displacement))
            == Some(target)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySegment, MemorySegmentKind, ServiceFingerprint};

    fn write_word(module: &mut [u8], offset: usize, word: u32) {
        module[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
    fn write_pointer(
        module: &mut [u8],
        start: usize,
        register: u32,
        slots: [usize; 4],
        address: u64,
    ) {
        for (half, slot) in slots.into_iter().enumerate() {
            let opcode = if half == 0 { 0xd280_0000 } else { 0xf280_0000 };
            let immediate = ((address >> (half * 16)) & 0xffff) as u32;
            write_word(
                module,
                start + slot,
                opcode | (half as u32) << 21 | immediate << 5 | register,
            );
        }
    }
    fn fixture() -> (Profile, Vec<u8>) {
        let mut p = Profile::draft("Synthetic", "1.0");
        p.abi.mmu = Some(MmuFamily::Z8BlockV1);
        p.task.core = Some(1);
        p.memory.module_size = Some(0x6000);
        p.memory.xip_base = Some(0x10000);
        p.memory.segments = vec![MemorySegment {
            file_offset: 0,
            runtime_start: 0x10000,
            size: 0x6000,
            kind: MemorySegmentKind::Xip,
        }];
        let mut module = vec![0; 0x6000];
        for (index, (name, length)) in REQUIRED_BODIES.iter().enumerate() {
            p.services.exec.bodies.push(ExecutionBody {
                name: (*name).into(),
                address: 0x10000 + index as u64 * 0x400,
                length: *length,
                sha256: String::new(),
            });
        }
        p.services.exec.page_query = Some(p.execution_body("query").unwrap().address);
        p.services.exec.page_protect = Some(p.execution_body("protect").unwrap().address);
        p.services.exec.mmu_translate = Some(p.execution_body("translate").unwrap().address);
        p.services.exec.icache_inval = Some(p.execution_body("icache_wrapper").unwrap().address);
        p.services.exec.cacheable = Some(p.execution_body("cacheable").unwrap().address);
        p.services.exec.tlb_sync = Some(p.execution_body("tlb_sync").unwrap().address);
        p.services.mem_alloc = Some(p.execution_body("heap_alloc").unwrap().address);
        p.services.mem_free = Some(p.execution_body("heap_free").unwrap().address);
        p.services.dcache_inv_post = Some(p.execution_body("dcache_clean").unwrap().address);
        p.services.exec.manager = Some(0x30000);
        p.services.exec.cache_manager = Some(0x30100);
        p.services.exec.region_bytes = Some(0x200000);
        p.services.exec.flag_writable = Some(0x21);
        p.services.exec.flag_executable = Some(0x34);
        let leaf = p.execution_body("leaf_modify").unwrap().address;
        for (index, (name, width, count)) in REQUIRED_TABLES.iter().enumerate() {
            p.services.exec.tables.push(ExecutionTable {
                name: (*name).into(),
                address: 0x15000 + index as u64 * 0x100,
                element_bytes: *width,
                values: vec![
                    if *name == "attribute_dispatch" {
                        leaf + 4
                    } else {
                        1
                    };
                    *count
                ],
            });
        }
        for name in [
            "page_query",
            "page_protect",
            "mmu_translate",
            "icache_inval",
            "cacheable",
            "tlb_sync",
        ] {
            p.service_fingerprints.insert(
                format!("exec.{name}"),
                ServiceFingerprint {
                    eg_off: 0,
                    stock: vec![0; 4],
                },
            );
        }
        for (name, register, offsets, expected) in [
            ("query", 9, [8, 12, 16, 20], 0x30000),
            ("protect", 9, [48, 52, 56, 64], 0x30000),
            ("icache_wrapper", 8, [0, 4, 8, 12], 0x30100),
            ("protect_body", 0, [148, 152, 156, 160], 0x30100),
            ("worker_affinity", 9, [112, 116, 120, 124], 0x15000),
            ("query_body", 11, [108, 112, 116, 124], 0x15100),
            ("leaf_modify", 10, [108, 112, 116, 120], 0x15200),
        ] {
            let body = p.execution_body(name).unwrap();
            write_pointer(
                &mut module,
                (body.address - 0x10000) as usize,
                register,
                offsets,
                expected,
            );
        }
        for (source, target, slot) in [
            ("query", "query_body", 40),
            ("protect", "protect_body", 88),
            ("translate", "table_walk", 40),
            ("query_body", "table_walk", 32),
            ("protect_body", "table_walk", 236),
            ("protect_body", "leaf_modify", 328),
            ("protect_body", "cache_dispatch", 172),
            ("cache_dispatch", "protect_cache", 12),
            ("icache_wrapper", "icache_body", 32),
        ] {
            let pc = p.execution_body(source).unwrap().address + slot;
            let target = p.execution_body(target).unwrap().address;
            let displacement = ((target as i64 - pc as i64) / 4) as u32 & 0x03ff_ffff;
            write_word(
                &mut module,
                (pc - 0x10000) as usize,
                0x1400_0000 | displacement,
            );
        }
        for body in &mut p.services.exec.bodies {
            let offset = (body.address - 0x10000) as usize;
            body.sha256 = sha256(&module[offset..offset + body.length as usize]);
        }
        for table in &p.services.exec.tables {
            let start = (table.address - 0x10000) as usize;
            for (index, value) in table.values.iter().enumerate() {
                let offset = start + index * usize::from(table.element_bytes);
                module[offset..offset + usize::from(table.element_bytes)]
                    .copy_from_slice(&value.to_le_bytes()[..usize::from(table.element_bytes)]);
            }
        }
        (p, module)
    }
    #[test]
    fn synthetic_addresses_satisfy_the_family_and_all_stock_relationships() {
        let (p, module) = fixture();
        let mut report = ValidationReport::default();
        p.validate_execution(BuildMode::Exec, &mut report);
        p.validate_execution_bytes(BuildMode::Exec, &module, &mut report);
        assert!(report.is_valid(), "{:?}", report.issues);
    }
    /// Everything the loader writes has to leave the data cache before
    /// another master reads it, and only the profile knows which of a
    /// body's cache entries writes back instead of discarding. The entry
    /// it names must be the clean the execution checks know.
    #[test]
    fn the_write_back_entry_must_be_the_clean_body() {
        let (mut p, module) = fixture();
        p.services.dcache_clean = p.services.dcache_inv_post;
        let mut report = ValidationReport::default();
        p.validate_execution(BuildMode::Exec, &mut report);
        p.validate_execution_bytes(BuildMode::Exec, &module, &mut report);
        assert!(report.is_valid(), "{:?}", report.issues);

        let (mut p, _module) = fixture();
        p.services.dcache_clean = p.services.mem_alloc;
        let mut report = ValidationReport::default();
        p.validate_execution(BuildMode::Exec, &mut report);
        assert!(!report.is_valid());
    }
    #[test]
    fn permission_encodings_must_exist_and_stay_distinct() {
        for variant in 0..4 {
            let (mut p, _module) = fixture();
            match variant {
                0 => p.services.exec.flag_writable = None,
                1 => p.services.exec.flag_executable = None,
                2 => p.services.exec.flag_executable = Some(0),
                _ => p.services.exec.flag_executable = p.services.exec.flag_writable,
            }
            let mut report = ValidationReport::default();
            p.validate_execution(BuildMode::Exec, &mut report);
            assert!(!report.is_valid(), "variant {variant}");
        }
    }
    #[test]
    fn missing_duplicate_short_and_corrupt_function_evidence_is_rejected() {
        for variant in 0..5 {
            let (mut p, module) = fixture();
            match variant {
                0 => {
                    p.services.exec.bodies.remove(0);
                }
                1 => p
                    .services
                    .exec
                    .bodies
                    .push(p.services.exec.bodies[0].clone()),
                2 => {
                    p.services.exec.bodies[0].length = 4;
                    p.services.exec.bodies[0].sha256 = sha256(&module[..4]);
                }
                3 => p.services.exec.bodies[0].sha256 = "0".repeat(64),
                _ => {
                    p.services.exec.page_query = Some(0x10000);
                }
            }
            let mut report = ValidationReport::default();
            p.validate_execution(BuildMode::Exec, &mut report);
            p.validate_execution_bytes(BuildMode::Exec, &module, &mut report);
            assert!(!report.is_valid(), "variant {variant}");
        }
    }
    #[test]
    fn matching_bytes_do_not_override_native_pointer_and_table_relationships() {
        for variant in 0..5 {
            let (mut p, module) = fixture();
            match variant {
                0 => p.services.exec.manager = Some(0x30200),
                1 => p.services.exec.cache_manager = Some(0x30200),
                2 => p.services.exec.tables[0].address += 4,
                3 => p.services.exec.tables[2].values[0] = 0x10000,
                _ => {
                    p.services.exec.tables.remove(0);
                }
            }
            let mut report = ValidationReport::default();
            p.validate_execution(BuildMode::Exec, &mut report);
            p.validate_execution_bytes(BuildMode::Exec, &module, &mut report);
            assert!(!report.is_valid(), "variant {variant}");
        }
    }

    /// The fixture plus an aligned entry: mem_alloc and mem_free build the
    /// pool table at 0x40000, mem_alloc calls the locked allocation, and
    /// that allocation and the aligned entry take the lock at 0x41000.
    fn memalign_fixture() -> (Profile, Vec<u8>) {
        let (mut p, mut module) = fixture();
        for (index, (name, length)) in MEMALIGN_BODIES.iter().enumerate() {
            p.services.exec.bodies.push(ExecutionBody {
                name: (*name).into(),
                address: 0x15400 + index as u64 * 0x400,
                length: *length,
                sha256: String::new(),
            });
        }
        p.services.exec.memalign = Some(0x15400);
        p.services.exec.memalign_heap = Some(0x40000);
        for (name, register, offsets, expected) in [
            ("heap_alloc", 8, [4, 8, 12, 20], 0x40000),
            ("heap_free", 9, [0, 4, 8, 20], 0x40000),
            ("heap_mspace_malloc", 21, [24, 28, 32, 36], 0x41000),
            ("heap_memalign", 22, [36, 40, 44, 48], 0x41000),
        ] {
            let body = p.execution_body(name).unwrap();
            write_pointer(
                &mut module,
                (body.address - 0x10000) as usize,
                register,
                offsets,
                expected,
            );
        }
        let pc = p.execution_body("heap_alloc").unwrap().address + 40;
        let target = p.execution_body("heap_mspace_malloc").unwrap().address;
        let displacement = ((target as i64 - pc as i64) / 4) as u32 & 0x03ff_ffff;
        write_word(
            &mut module,
            (pc - 0x10000) as usize,
            0x9400_0000 | displacement,
        );
        for body in &mut p.services.exec.bodies {
            let offset = (body.address - 0x10000) as usize;
            body.sha256 = sha256(&module[offset..offset + body.length as usize]);
        }
        (p, module)
    }

    #[test]
    fn the_aligned_entry_is_bound_to_the_loaders_heap() {
        let (p, module) = memalign_fixture();
        let mut report = ValidationReport::default();
        p.validate_execution(BuildMode::Exec, &mut report);
        p.validate_execution_bytes(BuildMode::Exec, &module, &mut report);
        assert!(report.is_valid(), "{:?}", report.issues);

        for variant in 0..10 {
            let (mut p, mut module) = memalign_fixture();
            let mut rehash = false;
            match variant {
                // declared halves, bodies and family
                0 => p.services.exec.memalign_heap = None,
                1 => p.services.exec.memalign = None,
                2 => {
                    p.services.exec.bodies.pop();
                }
                3 => p.services.exec.memalign = Some(0x15800),
                4 => p.abi.mmu = Some(MmuFamily::Z63BlockV1),
                5 => p.services.exec.memalign_heap = Some(0x40004),
                // the stock relations
                6 => p.services.exec.memalign_heap = Some(0x40008),
                7 => {
                    let at = (p.execution_body("heap_free").unwrap().address - 0x10000) as usize;
                    write_pointer(&mut module, at, 9, [0, 4, 8, 20], 0x40020);
                    rehash = true;
                }
                8 => {
                    let at =
                        (p.execution_body("heap_memalign").unwrap().address - 0x10000) as usize;
                    write_pointer(&mut module, at, 22, [36, 40, 44, 48], 0x42000);
                    rehash = true;
                }
                _ => {
                    let at = (p.execution_body("heap_alloc").unwrap().address - 0x10000) as usize;
                    write_word(&mut module, at + 40, 0);
                    rehash = true;
                }
            }
            if rehash {
                for body in &mut p.services.exec.bodies {
                    let offset = (body.address - 0x10000) as usize;
                    body.sha256 = sha256(&module[offset..offset + body.length as usize]);
                }
            }
            let mut report = ValidationReport::default();
            p.validate_execution(BuildMode::Exec, &mut report);
            p.validate_execution_bytes(BuildMode::Exec, &module, &mut report);
            assert!(!report.is_valid(), "variant {variant}");
        }

        // Its bodies alone, without the declaration, are refused.
        let (mut p, module) = memalign_fixture();
        p.services.exec.memalign = None;
        p.services.exec.memalign_heap = None;
        let mut report = ValidationReport::default();
        p.validate_execution(BuildMode::Exec, &mut report);
        p.validate_execution_bytes(BuildMode::Exec, &module, &mut report);
        assert!(!report.is_valid());
    }
}
