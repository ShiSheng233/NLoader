use crate::{IssueKind, Profile, ValidationReport};

pub const MIN_PROGRAM_ARENA_BYTES: u32 = 64 * 1024;
pub const DEFAULT_PROGRAM_ARENA_BYTES: u32 = MIN_PROGRAM_ARENA_BYTES;
pub const MAX_PROGRAM_ARENA_BYTES: u32 = 1024 * 1024;
pub const PROGRAM_ARENA_ALIGNMENT: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("program arena {bytes} must be between 65536 and 1048576 bytes and aligned to 64 bytes")]
pub struct ProgramArenaError {
    pub bytes: u32,
}

/// This is a loader read-buffer budget, not an execution-block budget or
/// a claim that the original allocator has enough free memory at runtime.
pub fn resolve_program_arena_bytes(declared: Option<u32>) -> Result<u32, ProgramArenaError> {
    let bytes = declared.unwrap_or(DEFAULT_PROGRAM_ARENA_BYTES);
    if !(MIN_PROGRAM_ARENA_BYTES..=MAX_PROGRAM_ARENA_BYTES).contains(&bytes)
        || bytes & (PROGRAM_ARENA_ALIGNMENT - 1) != 0
    {
        return Err(ProgramArenaError { bytes });
    }
    Ok(bytes)
}

impl Profile {
    pub(crate) fn validate_program_arena(&self, report: &mut ValidationReport) {
        if let Err(error) = resolve_program_arena_bytes(self.memory.program_arena_bytes) {
            report.add(
                "memory.program_arena_bytes",
                IssueKind::Invalid,
                error.to_string(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BuildMode;

    #[test]
    fn absence_preserves_64k_and_accepts_bounded_complete_cache_lines() {
        assert_eq!(resolve_program_arena_bytes(None), Ok(65536));
        for bytes in [65536, 65600, 512 * 1024, 1024 * 1024] {
            assert_eq!(resolve_program_arena_bytes(Some(bytes)), Ok(bytes));
        }
        for bytes in [0, 64, 65535, 65537, 524289, 1048577, u32::MAX] {
            assert!(resolve_program_arena_bytes(Some(bytes)).is_err());
        }
    }

    #[test]
    fn declared_invalid_capacity_is_rejected_in_every_mode() {
        let mut profile = Profile::draft("Z8", "3.11");
        profile.memory.program_arena_bytes = Some(65537);
        for mode in [
            BuildMode::Marker,
            BuildMode::HookOnly,
            BuildMode::Page,
            BuildMode::LoadOnly,
            BuildMode::PrepareOnly,
            BuildMode::Exec,
        ] {
            assert!(profile
                .validate(mode)
                .issues
                .iter()
                .any(|issue| issue.field == "memory.program_arena_bytes"
                    && issue.kind == IssueKind::Invalid));
        }
    }
}
