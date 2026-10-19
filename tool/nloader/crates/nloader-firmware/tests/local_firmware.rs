use nloader_firmware::{FirmwareIdentity, KeyFile, ModuleEdit};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::PathBuf};

/// Explicit local check; normal Cargo tests never read real firmware or keys.
#[test]
#[ignore = "requires explicit local firmware, key, and new validation output paths"]
fn stock_and_modified_package_checks() {
    let input = PathBuf::from(std::env::var_os("NLOADER_FIRMWARE").expect("set NLOADER_FIRMWARE"));
    let key_path =
        PathBuf::from(std::env::var_os("NLOADER_KEY_FILE").expect("set NLOADER_KEY_FILE"));
    let output = PathBuf::from(
        std::env::var_os("NLOADER_VALIDATION_OUTPUT").expect("set NLOADER_VALIDATION_OUTPUT"),
    );
    assert!(!output.exists(), "validation output must be new");
    let stock = fs::read(&input).unwrap();
    let stock_hash = hex::encode(Sha256::digest(&stock));
    let model = std::env::var("NLOADER_TEST_MODEL").unwrap_or_else(|_| "Z8".into());
    let (version, expected_hash, body_offset, digest_offset, module_prefix) = match model.as_str() {
        "Z8" => (
            "3.11",
            "d67413c2ede6b9ce8887175f20700bd9fbad2a973a4820968c45503d15d80d96",
            32,
            0,
            "eg2070_",
        ),
        "Z6III" => (
            "2.00",
            "b5c08335dc79d3d36d7bad0976434134db8ce160886d1c8c2935f3b185bcdbc9",
            0x260,
            0x240,
            "eg2010_",
        ),
        _ => panic!("no locally verified signature material for the requested test model"),
    };
    assert_eq!(stock_hash, expected_hash);
    let key = KeyFile::load(&key_path)
        .unwrap()
        .for_identity(&FirmwareIdentity {
            model: model.clone(),
            firmware: version.into(),
        })
        .unwrap();
    let original = key.unpack(&stock).unwrap();
    assert!(original.header_digest_verified());
    assert!(key.pack(&stock, &[]).unwrap() == stock);
    let module = original
        .modules()
        .iter()
        .find(|module| module.name.starts_with(module_prefix))
        .unwrap();
    let payload = original.payload(&module.name).unwrap();
    // This is an arbitrary container-validation edit, not a loader or a claim
    // that the chosen padding is safe to alter in firmware installed on a camera.
    let offset = payload
        .windows(32)
        .rposition(|bytes| bytes.iter().all(|byte| *byte == 0))
        .unwrap();
    let replacement = b"TEST";
    let modified = key
        .pack(
            &stock,
            &[ModuleEdit::Patch {
                module: module.name.clone(),
                offset,
                bytes: replacement.to_vec(),
            }],
        )
        .unwrap();
    let checked = key.unpack(&modified).unwrap();
    assert!(checked.header_digest_verified());
    assert_eq!(checked.modules(), original.modules());
    for entry in original.modules() {
        let before = original.payload(&entry.name).unwrap();
        let after = checked.payload(&entry.name).unwrap();
        if entry.name == module.name {
            assert_eq!(&after[offset..offset + replacement.len()], replacement);
            assert!(before[..offset] == after[..offset]);
            assert!(before[offset + replacement.len()..] == after[offset + replacement.len()..]);
        } else {
            assert!(before == after);
        }
    }
    let absolute = body_offset + module.body_offset + offset;
    let module_crc = body_offset + module.body_offset + module.payload_length();
    let allowed = [
        digest_offset..digest_offset + 20,
        absolute..absolute + replacement.len(),
        module_crc..module_crc + 2,
        stock.len() - 16..stock.len() - 14,
    ];
    let mut changed_bytes = 0;
    for (position, (before, after)) in stock.iter().zip(&modified).enumerate() {
        if before != after {
            assert!(
                allowed.iter().any(|range| range.contains(&position)),
                "unexpected edit at {position}"
            );
            changed_bytes += 1;
        }
    }
    assert!(changed_bytes >= replacement.len());
    assert!(stock[..digest_offset] == modified[..digest_offset]);
    assert!(
        stock[digest_offset + 20..body_offset + 32]
            == modified[digest_offset + 20..body_offset + 32]
    );
    assert!(fs::read(&input).unwrap() == stock);
    let parent = output.parent().unwrap();
    fs::create_dir_all(parent).unwrap();
    let mut temporary = tempfile::NamedTempFile::new_in(parent).unwrap();
    temporary.write_all(&modified).unwrap();
    temporary.as_file().sync_all().unwrap();
    temporary.persist_noclobber(&output).unwrap();
    let report = serde_json::json!({
        "stock_sha256": stock_hash,
        "model": model,
        "firmware": version,
        "modified_sha256": hex::encode(Sha256::digest(&modified)),
        "bytes": modified.len(),
        "module_count": checked.modules().len(),
        "modified_module": module.name,
        "module_offset": offset,
        "changed_bytes": changed_bytes,
        "roundtrip_identical": true,
        "all_checksums_verified": true,
        "only_expected_ranges_changed": true,
        "flash_ready": false,
        "purpose": "container validation with an arbitrary test edit",
    });
    let report_path = output.with_extension("report.json");
    let mut report_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(report_path)
        .unwrap();
    report_file
        .write_all(&serde_json::to_vec_pretty(&report).unwrap())
        .unwrap();
    report_file.sync_all().unwrap();
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
