//! Optional native GUI diagnostic. Declaring it never establishes pixel output.
use crate::{ExecutionBody, ExecutionTable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitmapFamily {
    #[serde(rename = "z8_bitmap_probe_v1")]
    Z8BitmapProbeV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitmapMode {
    Trace,
    Checker,
    Rgb,
}
impl BitmapMode {
    pub fn pattern(self) -> u32 {
        match self {
            Self::Trace => 0,
            Self::Checker => 1,
            Self::Rgb => 2,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitmapServices {
    pub family: BitmapFamily,
    pub mode: BitmapMode,
    pub blit: u64,
    pub current_index: u64,
    pub current_surface: u64,
    pub current_window: u64,
    pub current_task: u64,
    pub clean_source: u64,
    pub call_site: u64,
    pub original_callee: u64,
    pub gui_task_name: String,
    pub gui_task_config: u64,
    pub surface_case_table: ExecutionTable,
    pub bodies: Vec<ExecutionBody>,
}
impl BitmapServices {
    pub fn entry(&self, name: &str) -> Option<u64> {
        Some(match name {
            "blit" => self.blit,
            "current_index" => self.current_index,
            "current_surface" => self.current_surface,
            "current_window" => self.current_window,
            "current_task" => self.current_task,
            "clean_source" => self.clean_source,
            name => self.bodies.iter().find(|b| b.name == name)?.address,
        })
    }
}
