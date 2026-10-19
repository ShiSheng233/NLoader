//! Boot-time entry points the firmware reaches by itself (`[boot_hooks]`).
//!
//! `autoload` names one stock call -- a branch-with-link the firmware makes
//! on its own, early in every boot and again and again afterwards, in a
//! task that may read the card -- and the function it calls. The Exec build
//! points that call at `nlr_boot_autoload_checkpoint` (core/boot_autoload.c),
//! which makes the original call itself and returns its result, so the
//! boot's autoload pass can open without anyone opening the NLoader page.
//! A model whose card has a mount-time owner (`services.native_card`)
//! already has its checkpoint and must not declare a second one.
use crate::{BuildMode, IssueKind, Profile, ValidationReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootHooks {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoload: Option<BootCall>,
}

/// One stock call: the site of its `BL` and the function it reaches. The
/// callee takes no arguments and returns one pointer-sized value, which
/// the checkpoint hands back unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootCall {
    pub call_site: u64,
    pub callee: u64,
}

/// The fingerprint key that pins the callee's entry.
pub const BOOT_AUTOLOAD_FINGERPRINT: &str = "boot_hooks.autoload";

fn word(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

impl Profile {
    pub(crate) fn validate_boot_hooks(&self, mode: BuildMode, report: &mut ValidationReport) {
        let Some(call) = &self.boot_hooks.autoload else {
            return;
        };
        let field = "boot_hooks.autoload";
        if call.call_site % 4 != 0
            || call.callee % 4 != 0
            || !self.memory.is_xip_range(call.call_site, 4)
            || !self.memory.is_xip_range(call.callee, 4)
        {
            report.add(
                field,
                IssueKind::OutOfBounds,
                "the stock call and its callee must be whole instructions in firmware text",
            );
        }
        // Only the Exec build installs it; the same profile still serves
        // the smaller stages, which leave the stock call alone.
        if mode != BuildMode::Exec {
            return;
        }
        if self.services.native_card.is_some() {
            report.add(
                field,
                IssueKind::Conflict,
                "a model with a mount-time card owner already has its checkpoint",
            );
        }
        if !self
            .service_fingerprints
            .contains_key(BOOT_AUTOLOAD_FINGERPRINT)
        {
            report.add(
                format!("service_fingerprints.{BOOT_AUTOLOAD_FINGERPRINT}"),
                IssueKind::Missing,
                "the checkpoint calls the stock callee itself; an entry fingerprint is required",
            );
        }
    }

    /// The site must hold a `BL` that reaches the declared callee in the
    /// official image: the checkpoint replaces exactly that call.
    pub(crate) fn validate_boot_hooks_bytes(&self, module: &[u8], report: &mut ValidationReport) {
        let Some(call) = &self.boot_hooks.autoload else {
            return;
        };
        let at = self
            .memory
            .address_to_offset(call.call_site, 4)
            .ok()
            .and_then(|offset| usize::try_from(offset).ok());
        let reaches = at
            .and_then(|at| module.get(at..at + 4))
            .and_then(word)
            .is_some_and(|w| {
                w & 0xfc00_0000 == 0x9400_0000
                    && call
                        .call_site
                        .checked_add_signed(i64::from(((w & 0x03ff_ffff) as i32) << 6 >> 6) * 4)
                        == Some(call.callee)
            });
        if !reaches {
            report.add(
                "boot_hooks.autoload.call_site",
                IssueKind::Conflict,
                "the call site does not hold a branch-with-link to the declared callee",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySegment, MemorySegmentKind, ServiceFingerprint};

    fn profile() -> Profile {
        let mut p = Profile::draft("Z6III", "2.00");
        p.memory.xip_base = Some(0x1000);
        p.memory.module_size = Some(0x1000);
        p.memory.segments = vec![MemorySegment {
            file_offset: 0,
            runtime_start: 0x1000,
            size: 0x1000,
            kind: MemorySegmentKind::Xip,
        }];
        p.boot_hooks.autoload = Some(BootCall {
            call_site: 0x1100,
            callee: 0x1800,
        });
        p.service_fingerprints.insert(
            BOOT_AUTOLOAD_FINGERPRINT.into(),
            ServiceFingerprint {
                eg_off: 0x800,
                stock: vec![0; 4],
            },
        );
        p
    }

    fn fields(p: &Profile, mode: BuildMode) -> Vec<String> {
        let mut report = ValidationReport::default();
        p.validate_boot_hooks(mode, &mut report);
        report.issues.iter().map(|i| i.field.clone()).collect()
    }

    #[test]
    fn declared_call_in_text_with_its_fingerprint_is_accepted() {
        assert!(fields(&profile(), BuildMode::Exec).is_empty());
        assert!(fields(&Profile::draft("Z6III", "2.00"), BuildMode::Exec).is_empty());
    }

    #[test]
    fn outside_text_misaligned_or_unfingerprinted_is_refused() {
        let mut p = profile();
        p.boot_hooks.autoload.as_mut().unwrap().call_site = 0x2100;
        assert_eq!(fields(&p, BuildMode::Page), ["boot_hooks.autoload"]);
        let mut p = profile();
        p.boot_hooks.autoload.as_mut().unwrap().callee = 0x1802;
        assert_eq!(fields(&p, BuildMode::Exec), ["boot_hooks.autoload"]);
        let mut p = profile();
        p.service_fingerprints.clear();
        assert_eq!(
            fields(&p, BuildMode::Exec),
            ["service_fingerprints.boot_hooks.autoload"]
        );
        // The smaller stages leave the stock call alone and need no pin.
        assert!(fields(&p, BuildMode::Page).is_empty());
    }

    #[test]
    fn site_must_branch_with_link_to_the_callee() {
        let p = profile();
        let mut module = vec![0u8; 0x1000];
        // BL from 0x1100 to 0x1800: (0x700 / 4) = 0x1c0.
        module[0x100..0x104].copy_from_slice(&(0x9400_0000u32 | 0x1c0).to_le_bytes());
        let mut report = ValidationReport::default();
        p.validate_boot_hooks_bytes(&module, &mut report);
        assert!(report.issues.is_empty());
        for wrong in [0x1400_0000u32 | 0x1c0, 0x9400_0000 | 0x1c1] {
            module[0x100..0x104].copy_from_slice(&wrong.to_le_bytes());
            let mut report = ValidationReport::default();
            p.validate_boot_hooks_bytes(&module, &mut report);
            assert_eq!(report.issues.len(), 1);
            assert_eq!(report.issues[0].field, "boot_hooks.autoload.call_site");
        }
    }
}
