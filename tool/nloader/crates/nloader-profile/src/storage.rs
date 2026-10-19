//! Explicit card location; no mode guesses a drive or directory.
use crate::{BuildMode, IssueKind, Profile, ValidationReport};
use serde::{Deserialize, Serialize};

pub const MAX_STORAGE_ROOT_BYTES: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Storage {
    /// Absolute A: or B: directory with a trailing backslash. A missing
    /// declaration is only legal while card access is compiled out.
    pub root: Option<String>,
}

impl Profile {
    pub(crate) fn validate_storage(&self, mode: BuildMode, report: &mut ValidationReport) {
        let Some(root) = self.storage.root.as_deref() else {
            if matches!(
                mode,
                BuildMode::LoadOnly | BuildMode::PrepareOnly | BuildMode::Exec
            ) {
                report.require::<&str>("storage.root", None);
            }
            return;
        };
        if !valid_storage_root(root) {
            report.add(
                "storage.root",
                IssueKind::Invalid,
                "expected an absolute A: or B: directory ending in a backslash, at most 64 bytes, with nonempty ASCII letter/digit/_/- components",
            );
        }
    }
}

fn valid_storage_root(root: &str) -> bool {
    if root.len() > MAX_STORAGE_ROOT_BYTES {
        return false;
    }
    let Some(path) = root
        .strip_prefix("A:\\")
        .or_else(|| root.strip_prefix("B:\\"))
    else {
        return false;
    };
    let Some(directory) = path.strip_suffix('\\') else {
        return false;
    };
    directory.split('\\').all(|component| {
        !component.is_empty()
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}
