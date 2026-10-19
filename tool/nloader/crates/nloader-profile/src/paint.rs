//! Optional observation of the original four-argument native text renderer.
use crate::{BitmapMode, ExecutionBody, ExecutionTable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaintFamily {
    #[serde(rename = "z8_text_paint_probe_v1")]
    Z8TextPaintProbeV1,
    #[serde(rename = "z8_text_native_bitmap_probe_v1")]
    Z8TextNativeBitmapProbeV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaintServices {
    pub family: PaintFamily,
    pub mode: BitmapMode,
    #[serde(default)]
    pub full_screen: bool,
    pub text_draw: u64,
    pub blit: u64,
    pub current_index: u64,
    pub current_surface: u64,
    pub current_window: u64,
    pub current_task: u64,
    pub clean_source: u64,
    pub widget_root: u64,
    pub surface_record: u64,
    pub surface_group: u32,
    pub surface_mapping: Option<PaintSurfaceMapping>,
    pub native_bitmap: Option<NativeBitmapMapping>,
    pub call_site: u64,
    pub original_callee: u64,
    pub gui_task_name: String,
    pub gui_task_config: u64,
    pub surface_case_table: ExecutionTable,
    pub bodies: Vec<ExecutionBody>,
}
/// Complete native translation chain. The tables describe request enums,
/// without asserting a final GPU register format or visible pixel output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBitmapMapping {
    pub translate: u64,
    pub draw: u64,
    pub target_setup: u64,
    pub target_restore: u64,
    pub source_translate: ExecutionTable,
    pub source_formats: ExecutionTable,
    pub target_formats: ExecutionTable,
    pub blend_modes: ExecutionTable,
}
/// The original group selector is only safe for the explicitly checked group.
/// This declaration records the real native record calculation, not a target
/// address captured during one boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaintSurfaceMapping {
    pub group_map: ExecutionTable,
    pub type_cases: ExecutionTable,
    pub record_base: u64,
    pub group_stride: u32,
    pub index_stride: u32,
    pub index_offset: u32,
}
impl PaintServices {
    pub fn entry(&self, name: &str) -> Option<u64> {
        Some(match name {
            "text_draw" => self.text_draw,
            "blit" => self.blit,
            "current_index" => self.current_index,
            "current_surface" => self.current_surface,
            "current_window" => self.current_window,
            "current_task" => self.current_task,
            "clean_source" => self.clean_source,
            "widget_root" => self.widget_root,
            "surface_record" => self.surface_record,
            "bitmap_translate" => self.native_bitmap.as_ref()?.translate,
            "bitmap_draw" => self.native_bitmap.as_ref()?.draw,
            "bitmap_target_setup" => self.native_bitmap.as_ref()?.target_setup,
            "bitmap_target_restore" => self.native_bitmap.as_ref()?.target_restore,
            name => self.bodies.iter().find(|b| b.name == name)?.address,
        })
    }
}
