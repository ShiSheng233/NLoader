use nloader_profile::*;
use std::collections::BTreeMap;

pub fn evidence_for(profile: &Profile) -> BTreeMap<String, Evidence> {
    let mut paths = vec![
        "identity.model".to_string(),
        "identity.firmware".into(),
        "memory.xip_base".into(),
        "memory.module_size".into(),
        "memory.segments".into(),
        "memory.slack".into(),
        "memory.link_base".into(),
        "memory.link_size".into(),
    ];
    if profile.memory.ram_pool.is_some() {
        paths.push("memory.ram_pool".into());
    }
    for index in 0..profile.updater.version_literals.len() {
        paths.push(format!("updater.version_literals[{index}]"));
    }
    paths
        .into_iter()
        .map(|path| {
            (
                path,
                Evidence {
                    source: EvidenceSource::FirmwareImage,
                    status: EvidenceStatus::Static,
                    model: profile.identity.model.clone(),
                    firmware: profile.identity.firmware.clone(),
                    rule: "synthetic-test-v1".into(),
                    fragment_sha256: profile.checks.module_sha256.clone(),
                    module_sha256: profile.checks.module_sha256.clone(),
                    note: "Synthetic evidence only".into(),
                },
            )
        })
        .collect()
}
