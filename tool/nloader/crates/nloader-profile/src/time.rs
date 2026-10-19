//! Optional boot-relative clock and bounded native task waiting.
use crate::{ExecutionBody, ExecutionTable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeFamily {
    #[serde(rename = "z8_counter_delay_v1")]
    Z8CounterDelayV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeServices {
    pub family: TimeFamily,
    pub clock_us: u64,
    pub delay_ms: u64,
    pub counter_frequency_query: u64,
    pub counter_frequency_hz: u32,
    pub tick_period_us: u32,
    pub tick_period: ExecutionTable,
    pub bodies: Vec<ExecutionBody>,
}

impl TimeServices {
    pub fn entry(&self, name: &str) -> Option<u64> {
        Some(match name {
            "clock_us" => self.clock_us,
            "delay_ms" => self.delay_ms,
            "counter_frequency_query" => self.counter_frequency_query,
            name => self.bodies.iter().find(|body| body.name == name)?.address,
        })
    }
}
