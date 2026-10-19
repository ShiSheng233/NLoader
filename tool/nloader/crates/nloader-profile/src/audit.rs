//! Provenance belongs to the extraction report, not the reusable profile file.
use crate::validation::{hash_matches, valid_hash};
use crate::*;
use std::collections::BTreeMap;

impl Profile {
    /// Validate configuration plus extraction-time source records. This does
    /// not replace validate_for against the actual firmware bytes.
    pub fn validate_extraction(
        &self,
        mode: BuildMode,
        evidence: &BTreeMap<String, Evidence>,
        conflicts: &[Conflict],
    ) -> ValidationReport {
        let mut report = self.validate(mode);
        for conflict in conflicts {
            report.add(&conflict.field, IssueKind::Conflict, &conflict.reason);
        }
        let audit = ExtractionAudit {
            profile: self,
            evidence,
        };
        audit.validate_evidence(&mut report);
        for field in ["identity.model", "identity.firmware"] {
            audit.require_evidence(field, false, &mut report);
        }
        for field in [
            "memory.xip_base",
            "memory.module_size",
            "memory.segments",
            "memory.slack",
            "memory.link_base",
            "memory.link_size",
        ] {
            audit.require_evidence(field, true, &mut report);
        }
        if self.memory.ram_pool.is_some() {
            audit.require_evidence("memory.ram_pool", true, &mut report);
        }
        for (field, value) in self.service_addresses() {
            if value.is_some() {
                audit.require_evidence(field, true, &mut report);
            }
        }
        for index in 0..self.updater.version_literals.len() {
            audit.require_evidence(
                &format!("updater.version_literals[{index}]"),
                true,
                &mut report,
            );
        }
        report
    }
}
struct ExtractionAudit<'a> {
    profile: &'a Profile,
    evidence: &'a BTreeMap<String, Evidence>,
}
impl ExtractionAudit<'_> {
    fn validate_evidence(&self, report: &mut ValidationReport) {
        for (field, evidence) in self.evidence {
            let path = format!("evidence.{field}");
            if evidence.model != self.profile.identity.model
                || evidence.firmware != self.profile.identity.firmware
            {
                report.add(
                    &path,
                    IssueKind::IdentityMismatch,
                    "evidence belongs to a different model or firmware",
                );
            }
            if evidence.rule.trim().is_empty() {
                report.add(
                    &path,
                    IssueKind::Missing,
                    "evidence must identify its recognition rule or source version",
                );
            }
            for hash in [
                evidence.module_sha256.as_deref(),
                evidence.fragment_sha256.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                if !valid_hash(hash) {
                    report.add(&path, IssueKind::Invalid, "invalid evidence SHA-256");
                }
            }
            if let (Some(evidence_hash), Some(module_hash)) =
                (&evidence.module_sha256, &self.profile.checks.module_sha256)
            {
                if !hash_matches(evidence_hash, module_hash) {
                    report.add(
                        &path,
                        IssueKind::FingerprintMismatch,
                        "evidence module differs from profile module",
                    );
                }
            }
            if evidence.status == EvidenceStatus::DeviceVerified
                && evidence.source != EvidenceSource::Device
            {
                report.add(
                    &path,
                    IssueKind::Invalid,
                    "non-device evidence cannot claim device verification",
                );
            }
            if matches!(
                evidence.source,
                EvidenceSource::Device | EvidenceSource::FirmwareImage | EvidenceSource::Snapshot
            ) && evidence.fragment_sha256.is_none()
            {
                report.add(
                    &path,
                    IssueKind::Missing,
                    "byte evidence requires its collection fragment fingerprint",
                );
            }
        }
    }
    fn require_evidence(&self, field: &str, module_bound: bool, report: &mut ValidationReport) {
        match self.evidence.get(field) {
            None => report.add(
                format!("evidence.{field}"),
                IssueKind::Missing,
                "required field has no evidence",
            ),
            Some(evidence) => {
                if evidence.status == EvidenceStatus::Unconfirmed {
                    report.add(
                        format!("evidence.{field}"),
                        IssueKind::Unconfirmed,
                        "required field has not been confirmed",
                    );
                }
                if module_bound && evidence.module_sha256.is_none() {
                    report.add(
                        format!("evidence.{field}"),
                        IssueKind::Missing,
                        "address evidence must be bound to the target module fingerprint",
                    );
                }
            }
        }
    }
}
