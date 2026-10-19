use nloader_firmware::{Error, FirmwareIdentity, KeyFile};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;

fn record(model: &str, legacy: bool, has_signature: bool) -> Value {
    let mut record = json!({
        "scheme": if legacy { "legacy-xor" } else { "aes-ctr" },
        "model": model,
        "firmware": ["test"],
        "firmware_sha256": {"test": hex::encode(Sha256::digest([1_u8]))},
        "self_check": {}
    });
    if has_signature {
        let bytes = [23_u8; 8];
        record["k8"] = hex::encode(bytes).into();
        record["self_check"]["k8"] = hex::encode(Sha256::digest(bytes)).into();
    }
    record
}

fn material(fields: &[(&str, Vec<u8>)]) -> Value {
    let mut material = json!({"self_check": {}});
    for (name, bytes) in fields {
        material[name] = hex::encode(bytes).into();
        material["self_check"][name] = hex::encode(Sha256::digest(bytes)).into();
    }
    material
}

fn canonical_fixture() -> Value {
    json!({
        "schema": 1,
        "materials": {
            "legacy-xor": material(&[("t1", vec![7; 256]), ("t2", vec![11; 256]), ("t3", vec![13; 256])]),
            "aes-ctr": material(&[("key", vec![17; 32]), ("iv", vec![19; 16])])
        },
        "keys": [record("Z8", true, true), record("Z6III", false, true), record("ZR", false, false)]
    })
}

fn parse(value: &Value) -> nloader_firmware::Result<KeyFile> {
    KeyFile::from_json(&serde_json::to_vec(value).unwrap())
}

fn identity(model: &str) -> FirmwareIdentity {
    FirmwareIdentity {
        model: model.into(),
        firmware: "test".into(),
    }
}

#[test]
fn stores_current_format_without_changing_material_or_records() {
    let original = canonical_fixture();
    let temporary = tempfile::tempdir().unwrap();
    let first = temporary.path().join("first.json");
    let second = temporary.path().join("second.json");
    parse(&original).unwrap().write_canonical(&first).unwrap();
    let canonical: Value = serde_json::from_slice(&fs::read(&first).unwrap()).unwrap();
    assert_eq!(canonical["schema"], 1);
    assert_eq!(canonical["materials"].as_object().unwrap().len(), 2);
    assert_eq!(canonical, original);
    let reloaded = KeyFile::load(&first).unwrap();
    reloaded.write_canonical(&second).unwrap();
    assert_eq!(fs::read(first).unwrap(), fs::read(second).unwrap());
    assert_eq!(
        reloaded.for_identity(&identity("Z8")).unwrap().scheme(),
        "legacy-xor"
    );
    for model in ["Z6III", "ZR"] {
        assert_eq!(
            reloaded.for_identity(&identity(model)).unwrap().scheme(),
            "aes-ctr"
        );
    }
}

#[test]
fn shares_aes_material_and_preserves_unpack_only_records() {
    let canonical = canonical_fixture();
    for index in [1, 2] {
        assert!(canonical["keys"][index].get("key").is_none());
        assert!(canonical["keys"][index].get("iv").is_none());
    }
    assert!(canonical["keys"][1].get("k8").is_some());
    assert!(canonical["keys"][2].get("k8").is_none());
    assert!(canonical["keys"][2]["self_check"]
        .as_object()
        .unwrap()
        .is_empty());
    let file = parse(&canonical).unwrap();
    let zr = file.for_identity(&identity("ZR")).unwrap();
    assert!(matches!(zr.pack(&[], &[]), Err(Error::MissingSignatureKey)));
}

#[test]
fn rejects_unknown_fields_schemes_and_missing_shared_material() {
    let good = canonical_fixture();
    let mut invalid = Vec::new();
    let mut value = good.clone();
    value["extra"] = "untrusted".into();
    invalid.push(value);
    let mut value = good.clone();
    value["materials"]["extra"] = json!({});
    invalid.push(value);
    let mut value = good.clone();
    value["materials"]["aes-ctr"]["extra"] = "untrusted".into();
    invalid.push(value);
    let mut value = good.clone();
    value["keys"][0]["extra"] = "untrusted".into();
    invalid.push(value);
    let mut value = good.clone();
    value["keys"][1]["key"] = "17".repeat(32).into();
    invalid.push(value);
    let mut value = good.clone();
    value["keys"][1]["scheme"] = "unknown".into();
    invalid.push(value);
    let mut value = good.clone();
    value["materials"]
        .as_object_mut()
        .unwrap()
        .remove("aes-ctr");
    invalid.push(value);
    let mut value = good;
    value["materials"]
        .as_object_mut()
        .unwrap()
        .remove("legacy-xor");
    invalid.push(value);
    for value in invalid {
        assert!(matches!(parse(&value), Err(Error::KeyFile)));
    }
}

#[test]
fn rejects_other_schema_versions_and_flat_key_records() {
    let mut other_version = canonical_fixture();
    other_version["schema"] = 2.into();
    assert!(matches!(parse(&other_version), Err(Error::KeyFile)));

    let mut flat = canonical_fixture();
    for index in 0..3 {
        let scheme = flat["keys"][index]["scheme"].as_str().unwrap().to_owned();
        let material = flat["materials"][&scheme].as_object().unwrap().clone();
        for (name, value) in material {
            if name == "self_check" {
                flat["keys"][index]["self_check"]
                    .as_object_mut()
                    .unwrap()
                    .extend(value.as_object().unwrap().clone());
            } else {
                flat["keys"][index][name] = value;
            }
        }
    }
    flat.as_object_mut().unwrap().remove("materials");
    assert!(matches!(parse(&flat), Err(Error::KeyFile)));
}

#[test]
fn duplicate_identity_cannot_select_a_record() {
    let mut document = canonical_fixture();
    let duplicate = document["keys"][1].clone();
    document["keys"].as_array_mut().unwrap().push(duplicate);
    let file = parse(&document).unwrap();
    assert!(matches!(
        file.for_identity(&identity("Z6III")),
        Err(Error::KeyIdentity)
    ));
}

#[test]
fn writes_private_file_and_never_overwrites_an_existing_output() {
    let file = parse(&canonical_fixture()).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let output = temporary.path().join("nested/local.json");
    file.write_canonical(&output).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let before = fs::read(&output).unwrap();
    assert!(matches!(
        file.write_canonical(&output),
        Err(Error::OutputExists)
    ));
    assert_eq!(fs::read(&output).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = temporary.path().join("dangling.json");
        let destination = temporary.path().join("missing.json");
        symlink(&destination, &link).unwrap();
        assert!(matches!(
            file.write_canonical(&link),
            Err(Error::OutputExists)
        ));
        assert!(!destination.exists());
    }
}
