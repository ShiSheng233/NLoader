use nloader_firmware::{
    crc16, pack, recover_key_file, recover_key_file_with_tables, unpack, Error, FirmwareIdentity,
    KeyFile, ModuleEdit,
};
use sha1::{Digest, Sha1};
use std::{fs, sync::OnceLock};

const HEADER: usize = 32;
const TRAILER: usize = 16;
const DIRECTORY_SIZE: usize = 80;
const MODULE_NAME: &str = "ex2070_031100.bi";
const COMPLETE_BODY_LENGTH: usize = 1 << 24;

fn identity() -> FirmwareIdentity {
    FirmwareIdentity {
        model: "Z8".into(),
        firmware: "3.11".into(),
    }
}

#[test]
fn supplied_tables_still_require_valid_input_checks_and_a_verified_signature() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("stock.bin");
    let table_path = temp.path().join("tables.json");
    let output = temp.path().join("local.json");
    let tables: Vec<Vec<u8>> = vec![
        (0..=255_u8)
            .map(|i| i.wrapping_mul(37).rotate_left(3) ^ 91)
            .collect(),
        (0..=255_u8).map(|i| i.wrapping_mul(53)).collect(),
        (0..=255_u8).map(|i| i.wrapping_mul(73)).collect(),
    ];
    fs::write(&table_path, serde_json::to_vec(&tables).unwrap()).unwrap();
    let stock = synthetic_package(1 << 16);
    fs::write(&input, &stock).unwrap();
    let report =
        recover_key_file_with_tables(&input, &identity(), &[], &table_path, &output).unwrap();
    assert_eq!(report.table_source, "provided");
    assert_eq!(report.target_model_packages_verified, 1);
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(saved["schema"], 1);
    assert!(saved["materials"]["legacy-xor"]["t1"].is_string());
    assert!(saved["keys"][0].get("t1").is_none());
    let key = KeyFile::load(&output)
        .unwrap()
        .legacy_xor(&identity())
        .unwrap();
    assert!(unpack(&stock, &key).is_ok());
    let next = temp.path().join("from-unified.json");
    let report = recover_key_file_with_tables(&input, &identity(), &[], &output, &next).unwrap();
    assert_eq!(report.table_source, "provided");
    assert!(KeyFile::load(&next)
        .unwrap()
        .legacy_xor(&identity())
        .is_ok());
    let mut damaged = stock.clone();
    damaged[0] ^= 1;
    fs::write(&input, &damaged).unwrap();
    let rejected = temp.path().join("rejected/key.json");
    assert!(
        recover_key_file_with_tables(&input, &identity(), &[], &table_path, &rejected).is_err()
    );
    assert!(!rejected.parent().unwrap().exists());
    fs::write(&input, stock).unwrap();
    fs::write(&table_path, b"not a table").unwrap();
    assert!(matches!(
        recover_key_file_with_tables(&input, &identity(), &[], &table_path, &rejected),
        Err(Error::KeyFile)
    ));
    assert!(!rejected.exists());
}

fn complete_fixture() -> &'static [u8] {
    static FIXTURE: OnceLock<Vec<u8>> = OnceLock::new();
    FIXTURE.get_or_init(|| synthetic_package(COMPLETE_BODY_LENGTH))
}

fn synthetic_package(body_length: usize) -> Vec<u8> {
    // All material is invented for this fixture. Zero padding supplies repeated
    // sectors in every covered table block, with no dependency on real firmware.
    let mut raw = vec![0; HEADER + body_length];
    let body = &mut raw[HEADER..];
    body[..32].fill(b' ');
    body[32..36].copy_from_slice(&1_u32.to_be_bytes());
    body[36..40].copy_from_slice(&(DIRECTORY_SIZE as u32).to_be_bytes());
    body[48..64].copy_from_slice(MODULE_NAME.as_bytes());
    body[64..68].copy_from_slice(&(DIRECTORY_SIZE as u32).to_be_bytes());
    let module_length = body_length - TRAILER - DIRECTORY_SIZE;
    body[68..72].copy_from_slice(&(module_length as u32).to_be_bytes());

    let seed = [0x13, 0x35, 0x57, 0x79, 0x8b, 0xad, 0xcf, 0xe1];
    let seed_offset = DIRECTORY_SIZE + 32;
    body[seed_offset..seed_offset + 8].copy_from_slice(&seed);
    body[seed_offset + 24..seed_offset + 32]
        .copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    let module_crc_offset = body_length - TRAILER - 2;
    let module_crc = crc16(&body[DIRECTORY_SIZE..module_crc_offset]);
    body[module_crc_offset..module_crc_offset + 2].copy_from_slice(&module_crc.to_be_bytes());
    let package_crc_offset = body_length - TRAILER;
    let package_crc = crc16(&body[..package_crc_offset]);
    body[package_crc_offset..package_crc_offset + 2].copy_from_slice(&package_crc.to_be_bytes());
    let mut key = seed;
    for (index, byte) in key.iter_mut().enumerate() {
        let i = index as u32;
        *byte ^= (0x51 + 0x37 * ((i + 1) * 0x260 + i * (i + 1) / 2)) as u8;
    }
    let mut digest = Sha1::new_with_prefix(&*body);
    digest.update(key);
    let signature = digest.finalize();
    for (index, byte) in body.iter_mut().enumerate().skip(32) {
        let t1 = (index as u8).wrapping_mul(37).rotate_left(3) ^ 91;
        let t2 = ((index >> 8) as u8).wrapping_mul(53);
        let t3 = ((index >> 16) as u8).wrapping_mul(73);
        *byte ^= t1 ^ t2 ^ t3;
    }
    raw[..20].copy_from_slice(&signature);
    raw
}

#[test]
fn recovered_file_supports_roundtrip_edits_deduplicates_sources_and_refuses_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let stock_path = temp.path().join("stock.bin");
    let duplicate_path = temp.path().join("same-bytes-another-name.bin");
    let key_path = temp.path().join("keys/local.json");
    let stock = complete_fixture();
    fs::write(&stock_path, stock).unwrap();
    fs::write(&duplicate_path, stock).unwrap();
    let report = recover_key_file(
        &stock_path,
        &identity(),
        &[stock_path.clone(), duplicate_path],
        &key_path,
    )
    .unwrap();
    assert_eq!(report.sources.len(), 1);
    assert_eq!(report.table_blocks, 256);
    assert_eq!(report.target_model_packages_verified, 1);
    assert!(report.sources[0].target_signature_verified);
    assert_eq!(report.sources[0].bytes, stock.len());
    assert_eq!(report.sources[0].module_count, 1);
    assert_eq!(report.key_file, key_path);
    assert_eq!(report.identity, identity());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let key_file = KeyFile::load(&key_path).unwrap();
    let key = key_file.legacy_xor(&identity()).unwrap();
    let original = unpack(stock, &key).unwrap();
    assert_eq!(original.modules().len(), 1);
    assert!(pack(stock, &key, &[]).unwrap() == stock);
    let offset = 1024;
    let replacement = [0x34, 0x56, 0x78];
    let patched = pack(
        stock,
        &key,
        &[ModuleEdit::Patch {
            module: MODULE_NAME.into(),
            offset,
            bytes: replacement.to_vec(),
        }],
    )
    .unwrap();
    let modified = unpack(&patched, &key).unwrap();
    let original_payload = original.payload(MODULE_NAME).unwrap();
    let modified_payload = modified.payload(MODULE_NAME).unwrap();
    assert_eq!(
        &modified_payload[offset..offset + replacement.len()],
        &replacement
    );
    assert!(original_payload[..offset] == modified_payload[..offset]);
    assert!(
        original_payload[offset + replacement.len()..]
            == modified_payload[offset + replacement.len()..]
    );
    assert!(patched != stock);
    assert!(fs::read(&stock_path).unwrap() == stock);

    let saved_key_bytes = fs::read(&key_path).unwrap();
    assert!(matches!(
        recover_key_file(&stock_path, &identity(), &[], &key_path),
        Err(Error::OutputExists)
    ));
    assert!(fs::read(&key_path).unwrap() == saved_key_bytes);
}

#[test]
fn incomplete_coverage_creates_no_key_file() {
    let temp = tempfile::tempdir().unwrap();
    let stock_path = temp.path().join("incomplete.bin");
    let output = temp.path().join("keys/incomplete.json");
    fs::write(&stock_path, synthetic_package(1 << 20)).unwrap();
    match recover_key_file(&stock_path, &identity(), &[], &output) {
        Err(Error::RecoveryCoverage { covered, missing }) => {
            assert_eq!(covered, 16);
            assert_eq!(missing, (16..=255).collect::<Vec<u8>>());
        }
        _ => panic!("expected incomplete table coverage"),
    }
    assert!(!output.exists());
    assert!(!output.parent().unwrap().exists());
}

#[test]
fn same_model_signature_conflict_creates_no_key_file() {
    let temp = tempfile::tempdir().unwrap();
    let stock_path = temp.path().join("stock.bin");
    let conflicting_path = temp.path().join("conflicting.bin");
    let output = temp.path().join("keys/conflicting.json");
    fs::write(&stock_path, complete_fixture()).unwrap();
    // A smaller second package shares the tables and has valid body checksums,
    // but its altered header cannot be verified with the target's recovered key.
    let mut conflicting = synthetic_package(1 << 20);
    conflicting[0] ^= 1;
    fs::write(&conflicting_path, conflicting).unwrap();
    assert!(matches!(
        recover_key_file(&stock_path, &identity(), &[conflicting_path], &output),
        Err(Error::Recovery(
            "same-model packages disagree on the signature key"
        ))
    ));
    assert!(!output.exists());
    assert!(!output.parent().unwrap().exists());
}
