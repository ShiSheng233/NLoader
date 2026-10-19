//! Service families (PLAN 3.1). A family is the contract the address-free
//! code implements: calling conventions, object and record formats, the
//! bounds those formats accept, and which stock functions the local service
//! audit must cover. Addresses, hashes, table contents, and firmware event
//! and navigation codes stay in the profile, so a
//! model that declares a family still has its own values checked against
//! its own image instead of inheriting the first model's.
use crate::*;
use serde::{Deserialize, Serialize};

/// Families the profile declares under `[abi]`. Each is required from the
/// first rung whose code relies on it; an unknown name fails parsing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Abi {
    /// Menu engine: window/page/item/event record formats, element and
    /// handler block layout, the stock title chain and the row-hide call.
    pub ui: Option<UiFamily>,
    /// Worker and event-flag objects, the task configuration block and the
    /// registry lookup.
    pub task: Option<TaskFamily>,
    /// File wrappers submitting numbered request operations.
    pub fs: Option<FsFamily>,
    /// Page-permission, TLB and cache services used to run code.
    pub mmu: Option<MmuFamily>,
    /// How the stock allocator and release are called.
    pub mem: Option<MemFamily>,
}

/// The heap service's calling convention. Z8's allocator returns the payload
/// and picks a heap by index. Z 6III's takes the destination and returns a
/// status, refusing a null destination outright (`sub_40171490` begins with
/// that test), so its pointer can only come back through the argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemFamily {
    #[serde(rename = "z8_heap_v1")]
    Z8HeapV1,
    #[serde(rename = "z63_heap_v1")]
    Z63HeapV1,
}

impl MemFamily {
    /// Whether the allocator writes the payload through an out pointer.
    pub fn allocates_through_out(self) -> bool {
        matches!(self, Self::Z63HeapV1)
    }
}

/// The menu engine first decoded on Z8 C3.11. Bounds it accepts: record
/// sizes 96/80/44/32, element records of 0x44 bytes, five-slot handler
/// blocks, runtime text slots below 300 with 50-byte text, 64 list rows,
/// item IDs above 0x4dd3 and below 0xfffe, the selected row at window
/// +0x32 and list viewport bottoms of 424 or 480.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UiFamily {
    #[serde(rename = "z8_menu_v1")]
    Z8MenuV1,
    /// The same menu engine on Z 6III V2.00: identical window, page, item
    /// and event records, the same navigation dispatcher, the same single
    /// widget lookup in a container the page forms with an ADD, and the
    /// same title order. Two things differ, neither an address: the event
    /// lookup is four bytes longer, so its two later terminator compares
    /// sit further in, and a runtime-text title element leaves its first
    /// word zero instead of naming the slot.
    #[serde(rename = "z63_menu_v1")]
    Z63MenuV1,
}

impl UiFamily {
    /// Whether the title element's first word carries the runtime text
    /// slot. On Z 6III it does not: its one stock list page with a
    /// runtime-text title bar, window 0x584, leaves that word zero and is
    /// otherwise identical to a string title, so the word is the string
    /// resource and the slot can only come from the runtime bind.
    pub fn title_slot_in_element(self) -> bool {
        matches!(self, Self::Z8MenuV1)
    }
    /// Length of the stock event lookup and the offsets of its four
    /// terminator compares.
    pub fn lookup_shape(self) -> (u64, [usize; 4]) {
        match self {
            Self::Z8MenuV1 => (0xb0, [0x08, 0x34, 0x6c, 0x94]),
            Self::Z63MenuV1 => (0xb4, [0x08, 0x34, 0x78, 0x9c]),
        }
    }
}

/// The worker family first decoded on Z8 C3.11: 0x58-byte worker objects
/// with the flag object at +0x38 and the callback at +0x48, a 0x1c-byte
/// task configuration, task cores 0..=3, priorities 1..=256, names of at
/// most 8 bytes and registry IDs up to 0x300.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskFamily {
    #[serde(rename = "z8_worker_v1")]
    Z8WorkerV1,
    /// The same worker objects on Z 6III V2.00 -- same 0x58 bytes, same flag
    /// slot at +0x38, same callback at +0x48 -- with one difference at the
    /// wake. Its set entry is the kernel's own `set_flg(ID, FLGPTN)`: it
    /// bounds its first argument against the kernel's flag count and uses it
    /// to index the flag table, so the slot at worker+0x38 holds the created
    /// flag's **id**, not the object. Measured on a running body: the slot
    /// held an id, that id's table entry was the object the worker's task
    /// block named as what it waits on, and a Z8 shaped wake passing the
    /// slot's address was refused as a bad id while waking nothing.
    #[serde(rename = "z63_worker_v1")]
    Z63WorkerV1,
}

impl TaskFamily {
    /// Whether the flag slot at worker+0x38 holds a kernel id that the wake
    /// must load, rather than the flag object the stock entry consumes
    /// directly. An address passed where an id belongs is simply refused
    /// (E_ID) and nothing is woken, which is silent: the set entry's
    /// callers here ignore the result.
    pub fn flag_slot_is_id(self) -> bool {
        matches!(self, Self::Z63WorkerV1)
    }
}

/// The file family first decoded on Z8 C3.11: wrappers that store an
/// operation number into a request block on their stack; open takes
/// (path, 0, 0) for a plain read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsFamily {
    #[serde(rename = "z8_file_v1")]
    Z8FileV1,
}

/// The mapping family first audited on Z8 C3.11: a manager-owned
/// single-root page table (39-bit, 4 KiB granule, 192 table pages) whose
/// protect service keeps an existing complete 2 MiB L2 block, bit 29 of
/// the protect flags suppressing the native whole-cache maintenance, an
/// explicit broadcast TLB sync, and a region predicate gating D-cache
/// maintenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MmuFamily {
    #[serde(rename = "z8_block_v1")]
    Z8BlockV1,
    /// The same mapping service on Z 6III V2.00: one manager-owned root, a
    /// 39-bit 4 KiB regime, the complete 2 MiB L2 block kept by protect,
    /// bit 29 of the protect flags suppressing the native whole-cache
    /// maintenance, an explicit broadcast TLB sync and a region predicate
    /// gating D-cache maintenance -- all as on Z8. One thing differs: its
    /// leaf modifier dispatches through a table of byte offsets scaled by
    /// four, where Z8's holds addresses.
    #[serde(rename = "z63_block_v1")]
    Z63BlockV1,
}

impl MmuFamily {
    /// Whether `attribute_dispatch` holds instruction offsets rather than
    /// addresses. The base they are added to is an ADR inside the leaf
    /// modifier, which that body's own hash already fixes.
    pub fn dispatch_is_offsets(self) -> bool {
        matches!(self, Self::Z63BlockV1)
    }
}

impl Profile {
    /// Each rung needs the families its code relies on: the menu from
    /// hook-only on, the worker and file families from load-only on (the
    /// menu task reads the card; M2 execution rereads it on the worker),
    /// and the mapping family for prepare-only and exec.
    pub(crate) fn validate_families(&self, mode: BuildMode, report: &mut ValidationReport) {
        let (ui, worker, mmu) = match mode {
            BuildMode::Marker => (false, false, false),
            BuildMode::HookOnly | BuildMode::Page => (true, false, false),
            BuildMode::LoadOnly => (true, true, false),
            BuildMode::PrepareOnly | BuildMode::Exec => (true, true, true),
        };
        if ui {
            report.require("abi.ui", self.abi.ui);
        }
        if worker {
            report.require("abi.task", self.abi.task);
            report.require("abi.fs", self.abi.fs);
            // The runtime allocates as soon as the page builds it, so the
            // heap convention is required with them.
            report.require("abi.mem", self.abi.mem);
        }
        if mmu {
            report.require("abi.mmu", self.abi.mmu);
        }
    }
}
