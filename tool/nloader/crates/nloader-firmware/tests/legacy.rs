use nloader_firmware::{
    crc16, pack, pack_directory, unpack, unpack_directory, Error, FirmwareIdentity, KeyFile,
    ModuleEdit, PackageManifest,
};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

fn key_json() -> Vec<u8> {
    let fields = [
        (
            "t1",
            (0..256).map(|i| (i * 17 + 3) as u8).collect::<Vec<_>>(),
        ),
        ("t2", (0..256).map(|i| (i * 29 + 7) as u8).collect()),
        ("t3", (0..256).map(|i| (i * 43 + 11) as u8).collect()),
        ("k8", (0..8).collect()),
    ];
    let mut key = serde_json::json!({"scheme":"legacy-xor", "model":"Z8", "firmware":["test"], "firmware_sha256":{"test":"6c4d7963f00e19a643054dc8ab76c8f8dd70bbc0d08f97cc5636e4d35e4fde95"}, "self_check":{}});
    let mut material = serde_json::json!({"self_check": {}});
    for (name, bytes) in fields {
        let target = if name == "k8" {
            &mut key
        } else {
            &mut material
        };
        target[name] = hex::encode(&bytes).into();
        target["self_check"][name] = hex::encode(Sha256::digest(&bytes)).into();
    }
    serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "materials": {"legacy-xor": material},
        "keys": [key]
    }))
    .unwrap()
}

fn identity() -> FirmwareIdentity {
    FirmwareIdentity {
        model: "Z8".into(),
        firmware: "test".into(),
    }
}

fn key() -> nloader_firmware::LegacyXorKey {
    KeyFile::from_json(&key_json())
        .unwrap()
        .legacy_xor(&identity())
        .unwrap()
}

fn crypt(bytes: &mut [u8]) {
    for (i, byte) in bytes[32..].iter_mut().enumerate().skip(32) {
        *byte ^= ((i & 255) * 17 + 3) as u8
            ^ (((i >> 8) & 255) * 29 + 7) as u8
            ^ (((i >> 16) & 255) * 43 + 11) as u8;
    }
}

fn stock() -> Vec<u8> {
    let mut body = vec![b' '; 32];
    body.extend(2_u32.to_be_bytes());
    body.extend(112_u32.to_be_bytes());
    body.extend([0; 8]);
    let mut start = 112_u32;
    for (name, size) in [("ex2070_test.bi", 300_u32), ("eg2070_test.bi", 70000)] {
        let mut field = [0; 16];
        field[..name.len()].copy_from_slice(name.as_bytes());
        body.extend(field);
        body.extend(start.to_be_bytes());
        body.extend((size + 2).to_be_bytes());
        body.extend([0; 8]);
        start += size + 2;
    }
    for size in [300, 70000] {
        let payload: Vec<_> = (0..size).map(|i| (i * 13 + 5) as u8).collect();
        body.extend(&payload);
        body.extend(crc16(&payload).to_be_bytes());
    }
    body.extend(crc16(&body).to_be_bytes());
    body.extend([0; 14]);
    let mut digest = Sha1::new();
    digest.update(&body);
    digest.update([0, 1, 2, 3, 4, 5, 6, 7]);
    let mut result = digest.finalize().to_vec();
    result.extend(20..32);
    result.extend(body);
    crypt(&mut result);
    result
}

#[test]
fn fixed_upstream_reference_and_modified_roundtrip() {
    // Independently generated reference values; synthetic material only.
    let raw = stock();
    assert_eq!(raw.len(), 70464);
    assert_eq!(
        hex::encode(Sha256::digest(&raw)),
        "6c4d7963f00e19a643054dc8ab76c8f8dd70bbc0d08f97cc5636e4d35e4fde95"
    );
    assert_eq!(pack(&raw, &key(), &[]).unwrap(), raw);
    let edited = pack(
        &raw,
        &key(),
        &[ModuleEdit::Patch {
            module: "eg2070_test.bi".into(),
            offset: 65500,
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        }],
    )
    .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&edited)),
        "ce4c1b17e0981888f4c19a87f11f7ae9c1bacd2f9a572530deff5db60f8e38c4"
    );
    let before = unpack(&raw, &key()).unwrap();
    let after = unpack(&edited, &key()).unwrap();
    assert_eq!(
        &after.payload("eg2070_test.bi").unwrap()[65500..65504],
        &[0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(
        before.payload("ex2070_test.bi").unwrap(),
        after.payload("ex2070_test.bi").unwrap()
    );
    assert_eq!(&raw[20..64], &edited[20..64]);
    let module = &before.modules()[1];
    let allowed = [
        0..20,
        32 + module.body_offset + 65500..32 + module.body_offset + 65504,
        32 + module.body_offset + module.length - 2..32 + module.body_offset + module.length,
        raw.len() - 16..raw.len() - 14,
    ];
    for (index, (a, b)) in raw.iter().zip(&edited).enumerate() {
        assert!(a == b || allowed.iter().any(|range| range.contains(&index)));
    }
}

#[test]
fn rejects_invalid_material_without_disclosing_it() {
    let mut document: serde_json::Value = serde_json::from_slice(&key_json()).unwrap();
    document["materials"]["legacy-xor"]["t1"] = "secret-content".into();
    let error = KeyFile::from_json(&serde_json::to_vec(&document).unwrap())
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "invalid local key file");
    assert!(KeyFile::from_json(&key_json())
        .unwrap()
        .legacy_xor(&FirmwareIdentity {
            model: "Z9".into(),
            firmware: "test".into()
        })
        .is_err());
    assert_eq!(format!("{:?}", key()), "LegacyXorKey([redacted])");
    for field in ["t1", "k8"] {
        let mut document: serde_json::Value = serde_json::from_slice(&key_json()).unwrap();
        let target = if field == "k8" {
            &mut document["keys"][0]
        } else {
            &mut document["materials"]["legacy-xor"]
        };
        let mut bytes = hex::decode(target[field].as_str().unwrap()).unwrap();
        bytes[0] ^= 1;
        target[field] = hex::encode(&bytes).into();
        target["self_check"][field] = hex::encode(Sha256::digest(&bytes)).into();
        let wrong = KeyFile::from_json(&serde_json::to_vec(&document).unwrap())
            .unwrap()
            .legacy_xor(&identity())
            .unwrap();
        assert!(unpack(&stock(), &wrong).is_err());
    }
}

#[test]
fn rejects_corruption_and_out_of_payload_edits() {
    let raw = stock();
    for index in [0, 64, 112, 200, raw.len() - 16, raw.len() - 1] {
        let mut broken = raw.clone();
        broken[index] ^= 1;
        assert!(unpack(&broken, &key()).is_err());
    }
    for end in [0, 31, 64, 80, 100, raw.len() - 1] {
        assert!(unpack(&raw[..end], &key()).is_err());
    }
    for offset in [300, usize::MAX] {
        assert!(matches!(
            pack(
                &raw,
                &key(),
                &[ModuleEdit::Patch {
                    module: "ex2070_test.bi".into(),
                    offset,
                    bytes: vec![1]
                }]
            ),
            Err(Error::EditRange)
        ));
    }
    assert!(matches!(
        pack(
            &raw,
            &key(),
            &[ModuleEdit::Replace {
                module: "ex2070_test.bi".into(),
                bytes: vec![1]
            }]
        ),
        Err(Error::ReplacementLength)
    ));
    assert!(matches!(
        pack(
            &raw,
            &key(),
            &[ModuleEdit::Patch {
                module: "eg".into(),
                offset: 0,
                bytes: vec![1]
            }]
        ),
        Err(Error::Module)
    ));
    let mut duplicate = raw.clone();
    crypt(&mut duplicate);
    let name = duplicate[80..96].to_vec();
    duplicate[112..128].copy_from_slice(&name);
    crypt(&mut duplicate);
    assert!(matches!(
        unpack(&duplicate, &key()),
        Err(Error::Directory("duplicate module names"))
    ));
}

#[test]
fn directory_workflow_preserves_stock_and_checks_manifest() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let original = root.join("original.bin");
    let keys = root.join("keys.json");
    let folder = root.join("unpacked");
    fs::write(&original, stock()).unwrap();
    fs::write(&keys, key_json()).unwrap();
    let manifest = unpack_directory(&original, &keys, &identity(), &folder).unwrap();
    assert_eq!(manifest.header_digest_verified, Some(true));
    assert_eq!(
        manifest.source_file.as_deref(),
        Some(Path::new("../original.bin"))
    );
    assert!(!folder.join("stock.bin").exists());
    assert_eq!(
        fs::read(folder.join("modules/ex2070_test.bi")).unwrap(),
        unpack(&stock(), &key())
            .unwrap()
            .payload("ex2070_test.bi")
            .unwrap()
    );
    assert!(folder.join("modules/eg2070_test.bi").is_file());
    assert!(!folder.join("modules/00.bin").exists());
    assert!(!folder.join("modules/01.bin").exists());
    assert!(unpack_directory(&original, &keys, &identity(), &folder).is_err());
    let unchanged = root.join("unchanged.bin");
    pack_directory(&folder, &keys, &unchanged).unwrap();
    assert_eq!(fs::read(&unchanged).unwrap(), stock());
    assert!(pack_directory(&folder, &keys, &original).is_err());
    let payload = folder.join("modules/eg2070_test.bi");
    let mut bytes = fs::read(&payload).unwrap();
    bytes[65500..65504].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    fs::write(&payload, &bytes).unwrap();
    let changed = root.join("changed.bin");
    pack_directory(&folder, &keys, &changed).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(fs::read(&changed).unwrap())),
        "ce4c1b17e0981888f4c19a87f11f7ae9c1bacd2f9a572530deff5db60f8e38c4"
    );
    bytes.push(0);
    fs::write(&payload, &bytes).unwrap();
    let rejected = root.join("rejected.bin");
    assert!(pack_directory(&folder, &keys, &rejected).is_err());
    assert!(!rejected.exists());
    let manifest_file = folder.join("package.toml");
    let manifest = fs::read_to_string(&manifest_file).unwrap();
    fs::write(
        manifest_file,
        manifest.replace("ex2070_test.bi", "../bad_file.bin"),
    )
    .unwrap();
    assert!(matches!(
        pack_directory(&folder, &keys, &rejected),
        Err(Error::Manifest)
    ));
    assert_eq!(fs::read(original).unwrap(), stock());
}

#[test]
fn directory_pack_accepts_legacy_numbered_payloads() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let original = root.join("original.bin");
    let keys = root.join("keys.json");
    let folder = root.join("unpacked");
    fs::write(&original, stock()).unwrap();
    fs::write(&keys, key_json()).unwrap();
    let mut manifest = unpack_directory(&original, &keys, &identity(), &folder).unwrap();
    // Older directories embed stock.bin and have no source_file field.
    fs::copy(&original, folder.join("stock.bin")).unwrap();
    manifest.source_file = None;
    manifest.header_digest_verified = None;
    let encoded = toml::to_string_pretty(&manifest).unwrap();
    assert!(!encoded.contains("source_file"));
    assert!(!encoded.contains("header_digest_verified"));
    fs::write(folder.join("package.toml"), encoded).unwrap();
    fs::remove_file(&original).unwrap();
    for (index, module) in manifest.modules.iter().enumerate() {
        fs::rename(
            folder.join("modules").join(&module.name),
            folder.join("modules").join(format!("{index:02}.bin")),
        )
        .unwrap();
    }
    let output = root.join("unchanged.bin");
    pack_directory(&folder, &keys, &output).unwrap();
    assert_eq!(fs::read(output).unwrap(), stock());

    let payload = folder.join("modules/01.bin");
    let mut bytes = fs::read(&payload).unwrap();
    bytes[65500..65504].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    fs::write(payload, bytes).unwrap();
    let changed = root.join("changed.bin");
    pack_directory(&folder, &keys, &changed).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(fs::read(changed).unwrap())),
        "ce4c1b17e0981888f4c19a87f11f7ae9c1bacd2f9a572530deff5db60f8e38c4"
    );
}

#[test]
fn directory_pack_rejects_both_named_and_numbered_payloads() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let original = root.join("original.bin");
    let keys = root.join("keys.json");
    let folder = root.join("unpacked");
    fs::write(&original, stock()).unwrap();
    fs::write(&keys, key_json()).unwrap();
    unpack_directory(&original, &keys, &identity(), &folder).unwrap();
    fs::copy(
        folder.join("modules/eg2070_test.bi"),
        folder.join("modules/01.bin"),
    )
    .unwrap();
    let output = root.join("rejected.bin");
    assert!(matches!(
        pack_directory(&folder, &keys, &output),
        Err(Error::Directory(
            "both named and numbered module payload files exist"
        ))
    ));
    assert!(!output.exists());
    assert_eq!(fs::read(original).unwrap(), stock());
}

#[test]
fn directory_pack_rejects_missing_or_changed_referenced_stock() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let original = root.join("original.bin");
    let keys = root.join("keys.json");
    let folder = root.join("unpacked");
    fs::write(&original, stock()).unwrap();
    fs::write(&keys, key_json()).unwrap();
    unpack_directory(&original, &keys, &identity(), &folder).unwrap();
    // A leftover legacy copy must not override an explicit source reference.
    fs::copy(&original, folder.join("stock.bin")).unwrap();
    fs::remove_file(&original).unwrap();
    let rejected = root.join("rejected.bin");
    assert!(matches!(
        pack_directory(&folder, &keys, &rejected),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert!(!rejected.exists());

    let mut changed = stock();
    changed[500] ^= 1;
    fs::write(&original, changed).unwrap();
    assert!(matches!(
        pack_directory(&folder, &keys, &rejected),
        Err(Error::KeyIdentity)
    ));
    assert!(!rejected.exists());

    fs::write(&original, stock()).unwrap();
    let manifest_path = folder.join("package.toml");
    let mut manifest: PackageManifest =
        toml::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest.stock_sha256 = "00".repeat(32);
    fs::write(manifest_path, toml::to_string_pretty(&manifest).unwrap()).unwrap();
    assert!(matches!(
        pack_directory(&folder, &keys, &rejected),
        Err(Error::Manifest)
    ));
    assert!(!rejected.exists());
}

#[test]
fn relative_stock_reference_survives_moving_the_whole_workspace() {
    let temporary = tempfile::tempdir().unwrap();
    let workspace = temporary.path().join("workspace");
    fs::create_dir_all(workspace.join("stock")).unwrap();
    fs::create_dir_all(workspace.join("unpacked")).unwrap();
    let original = workspace.join("stock/original.bin");
    let keys = workspace.join("keys.json");
    let folder = workspace.join("unpacked/test");
    fs::write(&original, stock()).unwrap();
    fs::write(&keys, key_json()).unwrap();
    let manifest = unpack_directory(&original, &keys, &identity(), &folder).unwrap();
    assert_eq!(
        manifest.source_file.as_deref(),
        Some(Path::new("../../stock/original.bin"))
    );
    let moved = temporary.path().join("moved-workspace");
    fs::rename(workspace, &moved).unwrap();
    let output = moved.join("roundtrip.bin");
    pack_directory(
        &moved.join("unpacked/test"),
        &moved.join("keys.json"),
        &output,
    )
    .unwrap();
    assert_eq!(fs::read(output).unwrap(), stock());
}

#[test]
fn manifest_status_cannot_disable_signature_checks() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let original = root.join("original.bin");
    let keys = root.join("keys.json");
    let folder = root.join("unpacked");
    fs::write(&original, stock()).unwrap();
    fs::write(&keys, key_json()).unwrap();
    let mut manifest = unpack_directory(&original, &keys, &identity(), &folder).unwrap();
    manifest.header_digest_verified = Some(false);
    fs::write(
        folder.join("package.toml"),
        toml::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let valid_output = root.join("valid.bin");
    let checked = pack_directory(&folder, &keys, &valid_output).unwrap();
    assert_eq!(checked.header_digest_verified, Some(true));
    assert_eq!(fs::read(valid_output).unwrap(), stock());

    let mut document: serde_json::Value = serde_json::from_slice(&key_json()).unwrap();
    let wrong_suffix = [0_u8; 8];
    document["keys"][0]["k8"] = hex::encode(wrong_suffix).into();
    document["keys"][0]["self_check"]["k8"] = hex::encode(Sha256::digest(wrong_suffix)).into();
    fs::write(&keys, serde_json::to_vec(&document).unwrap()).unwrap();
    let rejected = root.join("rejected.bin");
    assert!(matches!(
        pack_directory(&folder, &keys, &rejected),
        Err(Error::Integrity("header digest"))
    ));
    assert!(!rejected.exists());
}

#[test]
fn crc_known_vector() {
    assert_eq!(crc16(b"123456789"), 0x31c3);
}

#[test]
fn binds_model_and_stock_version_identity() {
    let mut document: serde_json::Value = serde_json::from_slice(&key_json()).unwrap();
    document["keys"][0]["model"] = "Z9".into();
    let wrong_model = KeyFile::from_json(&serde_json::to_vec(&document).unwrap())
        .unwrap()
        .legacy_xor(&FirmwareIdentity {
            model: "Z9".into(),
            firmware: "test".into(),
        })
        .unwrap();
    assert!(matches!(
        unpack(&stock(), &wrong_model),
        Err(Error::KeyIdentity)
    ));

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let original = root.join("stock.bin");
    let keys = root.join("keys.json");
    let output = root.join("unpacked");
    fs::write(&original, stock()).unwrap();
    let mut document: serde_json::Value = serde_json::from_slice(&key_json()).unwrap();
    document["keys"][0]["firmware"] = serde_json::json!(["test", "other"]);
    document["keys"][0]["firmware_sha256"]["other"] = "00".repeat(32).into();
    fs::write(&keys, serde_json::to_vec(&document).unwrap()).unwrap();
    let wrong_version = FirmwareIdentity {
        model: "Z8".into(),
        firmware: "other".into(),
    };
    assert!(matches!(
        unpack_directory(&original, &keys, &wrong_version, &output),
        Err(Error::KeyIdentity)
    ));
    assert!(!output.exists());
    unpack_directory(&original, &keys, &identity(), &output).unwrap();
    let manifest = output.join("package.toml");
    fs::write(
        &manifest,
        fs::read_to_string(&manifest)
            .unwrap()
            .replace("firmware = \"test\"", "firmware = \"other\""),
    )
    .unwrap();
    let changed = root.join("changed.bin");
    assert!(matches!(
        pack_directory(&output, &keys, &changed),
        Err(Error::KeyIdentity)
    ));
    assert!(!changed.exists());
}
