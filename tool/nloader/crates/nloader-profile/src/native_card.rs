//! Native FILESRV RPC and raw filesystem primitives; no persistence claim.
use crate::{AddressRange, ExecutionBody};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeCardFamily {
    #[serde(rename = "z8_lowfil_rpc_v1")]
    Z8LowfilRpcV1,
}

/// The native dispatcher copies a caller-owned 0x118-byte frame but keeps its
/// user pointer. Core owns both objects until genuine completion is observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCardServices {
    pub family: NativeCardFamily,
    pub claim: u64,
    pub submit_frame: u64,
    /// Complete native op31 wrapper used as independent request-layout evidence;
    /// its temporary stack frame is never used by the persistent core RPC.
    pub submit_wrapper: u64,
    pub callback_table: u64,
    pub dispatcher: u64,
    pub dispatch_table: u64,
    pub callback_slot: u32,
    pub request_bytes: u32,
    pub request_volume_offset: u32,
    pub request_user_offset: u32,
    pub request_callback_offset: u32,
    pub request_operation_offset: u32,
    pub request_result_offset: u32,
    pub request_priority_offset: u32,
    pub operation: u32,
    pub mutex: u64,
    pub lock: u64,
    pub unlock: u64,
    pub open: u64,
    pub read: u64,
    pub write: u64,
    pub seek: u64,
    pub close: u64,
    pub stat: u64,
    pub fcb_get: u64,
    pub stat_bytes: u32,
    /// Only this exact, unmasked native reason establishes absence.
    pub not_found: u32,
    /// Existing-file writes: no creation, truncation, append or growth implied.
    pub write_flags: u32,
    pub file_mode: u32,
    pub create_flags: u32,
    /// Journal reads use the existing-file read/write lookup, which initializes
    /// the native FCB extent witness. This does not create or truncate a file.
    pub journal_read_flags: u32,
    pub volume_sync: u64,
    pub volume_index: u64,
    pub volume_ready: u64,
    /// The stock per-slot flush dispatcher (slot table entry +0x80), which
    /// the filesystem service calls after a stock write: one durability rule
    /// for every slot.
    pub slot_flush: u64,
    pub clean_source: u64,
    pub volume_lock: u64,
    pub volume_unlock: u64,
    pub low_unmount: u64,
    pub low_unmount_call_sites: Vec<u64>,
    pub rpc: NativeCardRpc,
    pub layout: NativeCardLayout,
    pub mount: NativeCardLifecycle,
    pub unmount: NativeCardLifecycle,
    pub menu: NativeCardMenu,
    pub bodies: Vec<ExecutionBody>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCardLayout {
    pub fcb_table: u64,
    pub fcb_volume_count: u32,
    pub fcb_slot_count: u32,
    pub fcb_volume_stride: u32,
    pub fcb_slot_stride: u32,
    pub fcb_flags_offset: u32,
    pub fcb_ready_mask: u32,
    pub fcb_reject_mask: u32,
    pub fcb_valid_size_offset: u32,
    pub fcb_data_size_offset: u32,
    pub fcb_first_cluster_offset: u32,
    pub fcb_last_cluster_offset: u32,
    pub fcb_no_fat_chain_offset: u32,
    /// Raw stat returns the valid-data length, not allocated space.
    pub stat_size_offset: u32,
    pub stat_attributes_offset: u32,
    pub runtime_ram: AddressRange,
    pub volume_table: u64,
    pub volume_sector_bytes_offset: u32,
    pub volume_cluster_sectors_offset: u32,
    pub volume_sector_shift_offset: u32,
    pub volume_cluster_shift_offset: u32,
    pub volume_cluster_heap_offset: u32,

    pub volume_count: u32,
    pub volume_stride: u32,
    pub volume_device_offset: u32,
    pub volume_name_offset: u32,
    /// Native readiness consumes one byte; neighbouring fields are populated.
    pub volume_state_offset: u32,
    /// Native LDRB: one byte. Bytes at +0x54 are the sector-size field.
    pub volume_type_offset: u32,
    pub exfat_type: u32,
    pub media_table: u64,
    pub media_count: u32,
    pub media_stride: u32,
    /// Native LDRH: the unsigned 16-bit stock slot of the media entry.
    pub media_slot_offset: u32,
    /// Stock storage slots: the slot table the per-slot flush indexes.
    pub slot_count: u32,
}

/// Original lifecycle calls execute unchanged. Hooks let NLoader count real
/// invocations; the count is NLoader state, not a claimed stock mount epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCardLifecycle {
    pub call_site: u64,
    pub callee: u64,
}

/// Original GuiMe checkpoint and a flag accepted without original dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCardMenu {
    pub call_site: u64,
    pub callee: u64,
    pub wake_mask: u32,
    pub target_context_offset: u32,
    pub worker_record: u64,
    pub worker_record_sha256: String,
    pub exit_menu: Option<NativeMenuExit>,
}

/// Observe the actual native wait output without changing its result or bits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCardRpc {
    pub wait_call_site: u64,
    pub wait_callee: u64,
    pub reply_flag: u64,
    pub shared_frame: u64,
}

/// Optional restoration of an original MENU event on its own GUI checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeMenuExit {
    pub dispatch: u64,
    pub current_window: u64,
    pub gui_state: u64,
    pub menu_press_code: u32,
    pub bodies: Vec<ExecutionBody>,
}
