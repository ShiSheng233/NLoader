//! Optional mapping from verified physical banks into stable application keys.
use crate::ExecutionBody;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputFamily {
    #[serde(rename = "z8_switch_banks_v1")]
    Z8SwitchBanksV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum InputKey {
    Up = 0,
    Down = 1,
    Left = 2,
    Right = 3,
    Ok = 4,
    Playback = 5,
    AfOn = 6,
    Disp = 7,
    Fn1 = 8,
    Fn2 = 9,
    ZoomIn = 10,
    ZoomOut = 11,
}

impl InputKey {
    pub fn bit(self) -> u32 {
        1u32 << self as u32
    }
    pub fn sources(self) -> (u32, &'static [&'static str]) {
        match self {
            Self::Up => (0, &["ID_SW0_UP", "ID_SW0_RIGHT_UP", "ID_SW0_LEFT_UP"]),
            Self::Down => (0, &["ID_SW0_DOWN", "ID_SW0_RIGHT_DOWN", "ID_SW0_LEFT_DOWN"]),
            Self::Left => (0, &["ID_SW0_LEFT", "ID_SW0_LEFT_UP", "ID_SW0_LEFT_DOWN"]),
            Self::Right => (0, &["ID_SW0_RIGHT", "ID_SW0_RIGHT_UP", "ID_SW0_RIGHT_DOWN"]),
            Self::Ok => (1, &["ID_SW1_OK"]),
            Self::Playback => (1, &["ID_SW1_PLAY"]),
            Self::AfOn => (0, &["ID_SW0_AF_ON"]),
            Self::Disp => (2, &["ID_SW2_DISP"]),
            Self::Fn1 => (0, &["ID_SW0_FUNCTION"]),
            Self::Fn2 => (2, &["ID_SW2_FN2"]),
            Self::ZoomIn => (1, &["ID_SW1_ZOOM"]),
            Self::ZoomOut => (1, &["ID_SW1_THUMBNAIL"]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputBinding {
    pub key: InputKey,
    pub bank: u32,
    pub mask: u32,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputKeyTable {
    pub bank: u32,
    pub address: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputServices {
    pub family: InputFamily,
    pub callback_slot: u64,
    pub current_task: u64,
    pub reserved: [u32; 3],
    pub key_tables: Vec<InputKeyTable>,
    pub bindings: Vec<InputBinding>,
    pub bodies: Vec<ExecutionBody>,
}

impl InputServices {
    pub fn entry(&self, name: &str) -> Option<u64> {
        self.bodies
            .iter()
            .find(|body| body.name == name)
            .map(|body| body.address)
    }
}
