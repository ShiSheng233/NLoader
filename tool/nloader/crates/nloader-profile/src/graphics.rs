//! Optional native self-canvas provider; separate from paint diagnostics.
use crate::{ExecutionBody, ExecutionTable, PaintServices};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphicsFamily {
    #[serde(rename = "z8_self_canvas_v1")]
    Z8SelfCanvasV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphicsServices {
    pub family: GraphicsFamily,
    /// Complete existing Z8 native bitmap and GUI identity evidence. This
    /// does not install its text-draw diagnostic hook.
    pub bitmap: PaintServices,
    pub canvas_id: u32,
    /// x, y, width, height in the existing content surface's local coordinates.
    pub destination: [u32; 4],
    pub surface_index: u32,
    /// Backing dimensions include native row padding, unlike the viewport.
    pub surface_size: [u32; 2],
    pub gui_state: u64,
    pub widget_find: u64,
    pub get_draw: u64,
    pub set_draw: u64,
    pub set_dirty: u64,
    pub get_visible: u64,
    pub set_visible: u64,
    pub window_render: u64,
    pub display_refresh: u64,
    pub display_abort: u64,
    pub submit: u64,
    pub fence: u64,
    /// A complete original type-4 element, used only as a constructor
    /// template. The output gets an independent ID and destination rect.
    pub canvas_element: ExecutionBody,
    pub element_cases: ExecutionTable,
    pub bodies: Vec<ExecutionBody>,
}

impl GraphicsServices {
    pub fn entry(&self, name: &str) -> Option<u64> {
        Some(match name {
            "widget_find" => self.widget_find,
            "get_draw" => self.get_draw,
            "set_draw" => self.set_draw,
            "set_dirty" => self.set_dirty,
            "get_visible" => self.get_visible,
            "set_visible" => self.set_visible,
            "window_render" => self.window_render,
            "display_refresh" => self.display_refresh,
            "display_abort" => self.display_abort,
            "submit" => self.submit,
            "fence" => self.fence,
            name => self.bodies.iter().find(|b| b.name == name)?.address,
        })
    }
}
