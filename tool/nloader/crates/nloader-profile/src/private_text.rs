//! Exact native text routing; private tokens never alias the stock pool.
use crate::{ExecutionBody, ExecutionTable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivateTextFamily {
    #[serde(rename = "z8_private_ascii_namespace_v1")]
    Z8PrivateAsciiNamespaceV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateText {
    pub family: PrivateTextFamily,
    pub token_base: u32,
    pub token_count: u32,
    pub title_index: u32,
    pub status_index: u32,
    pub entry_index: u32,
    /// The Setup Apps row's label (decided 2026-10-17: the family is fixed at
    /// 68 tokens whether or not a profile declares that row).
    pub apps_index: u32,
    pub row_first_item: u32,
    pub entry_item_id: u32,
    /// The Apps row's item ID; the clamp keeps its token only on this item.
    pub apps_item_id: u32,
    pub ascii_flags: u32,
    pub styles: Vec<u32>,
    pub getter_call_sites: Vec<u64>,
    pub item_clamp: u64,
    /// The value-column clamp of the row value builder (`cmp w9,#0x12b`,
    /// which drops a row's +0x14 text slot whenever the row's label id is
    /// past the stock pool). Routed only for the exact private row label
    /// whose value is that row's own value token; required with
    /// `menu.page.rows`, whose rows with a value would otherwise show none.
    #[serde(default)]
    pub value_clamp: Option<u64>,
    pub strlen: u64,
    pub memcpy: u64,
    pub fallback_text: String,
    pub gui_task_name: String,
    pub gui_task_config: u64,
    pub registry_cases: ExecutionTable,
    /// Complete text primitives, entry guards and the independent GUI identity chain.
    pub bodies: Vec<ExecutionBody>,
}

impl PrivateText {
    pub fn body(&self, name: &str) -> Option<&ExecutionBody> {
        self.bodies.iter().find(|body| body.name == name)
    }
    pub fn contains(&self, token: u32) -> bool {
        token
            .checked_sub(self.token_base)
            .is_some_and(|n| n < self.token_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn namespace() -> PrivateText {
        PrivateText {
            family: PrivateTextFamily::Z8PrivateAsciiNamespaceV1,
            token_base: u32::from_be_bytes(*b"NL\0\0"),
            token_count: 68,
            title_index: 64,
            status_index: 65,
            entry_index: 66,
            apps_index: 67,
            row_first_item: 0x7f80,
            entry_item_id: 0x7ffe,
            apps_item_id: 0x7ffd,
            ascii_flags: 0x200,
            styles: vec![3, 4],
            getter_call_sites: vec![],
            item_clamp: 0,
            value_clamp: None,
            strlen: 0,
            memcpy: 0,
            fallback_text: "unavailable".into(),
            gui_task_name: "APPMENU".into(),
            gui_task_config: 0,
            registry_cases: ExecutionTable {
                name: "registry_cases".into(),
                address: 0,
                element_bytes: 8,
                values: vec![],
            },
            bodies: vec![],
        }
    }
    #[test]
    fn only_the_complete_positive_token_range_is_private() {
        let n = namespace();
        assert!(n.contains(n.token_base));
        assert!(n.contains(n.token_base + 66));
        assert!(n.contains(n.token_base + 67));
        for token in [
            0,
            66,
            299,
            65535,
            u32::MAX,
            n.token_base - 1,
            n.token_base + 68,
        ] {
            assert!(!n.contains(token));
        }
    }
    #[test]
    fn arithmetic_wrap_cannot_alias_a_private_token() {
        let mut n = namespace();
        n.token_base = u32::MAX - 2;
        assert!(n.contains(u32::MAX));
        assert!(!n.contains(0));
    }
    #[test]
    fn missing_body_never_falls_back_to_a_native_address() {
        assert!(namespace().body("runtime_getter").is_none());
    }
}
