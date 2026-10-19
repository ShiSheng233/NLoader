use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use nloader_firmware::{
    crc16, pack_aes_ctr, unpack_aes_ctr, AesCtrKey, Error, FirmwareIdentity, KeyFile, ModuleEdit,
};
use sha1::Sha1;
use sha2::{Digest, Sha256};

const BODY_OFFSET: usize = 0x260;
const DIGEST_OFFSET: usize = 0x240;
const WRAPPER_MAGIC_HEX: &str = "420601f57f69308eab4d2a4ea3f486e256d93c6d8f165c968e99e4d20a029fb3";

struct Fixture {
    raw: Vec<u8>,
    body: Vec<u8>,
    model: &'static str,
    names: [String; 2],
    starts: [usize; 2],
    lengths: [usize; 2],
}

fn synthetic_key() -> [u8; 32] {
    std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
}

fn synthetic_iv() -> [u8; 16] {
    // Exercise a carry out of the low 64 bits before the encrypted directory.
    std::array::from_fn(|i| if i < 8 { 0x10 + i as u8 } else { 0xff })
}

fn synthetic_k8() -> [u8; 8] {
    std::array::from_fn(|i| i as u8 * 13 + 9)
}

fn fixture(aligned: bool) -> Fixture {
    let (model, names) = if aligned {
        ("ZR", ["ex2210_010100.b", "eg2210_010100.b"])
    } else {
        ("Z6III", ["ex2010_0200a0.bi", "eg2010_0200i1.bi"])
    };
    let starts = [112, if aligned { 160 } else { 147 }];
    let lengths = [35, 94];
    let trailer = if aligned { 256 } else { 241 };
    let mut body = vec![0; trailer + 16];
    body[..32].fill(b' ');
    body[32..36].copy_from_slice(&2_u32.to_be_bytes());
    body[36..40].copy_from_slice(&112_u32.to_be_bytes());
    for i in 0..2 {
        let record = 48 + i * 32;
        body[record..record + names[i].len()].copy_from_slice(names[i].as_bytes());
        body[record + 16..record + 20].copy_from_slice(&(starts[i] as u32).to_be_bytes());
        body[record + 20..record + 24].copy_from_slice(&(lengths[i] as u32).to_be_bytes());
        let (multiplier, addend) = if i == 0 { (19_u8, 11) } else { (23, 5) };
        for (j, byte) in body[starts[i]..starts[i] + lengths[i] - 2]
            .iter_mut()
            .enumerate()
        {
            *byte = (j as u8).wrapping_mul(multiplier).wrapping_add(addend);
        }
    }
    let mut prefix: Vec<u8> = (0..BODY_OFFSET)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(7))
        .collect();
    let magic = hex::decode(WRAPPER_MAGIC_HEX).unwrap();
    prefix[..32].copy_from_slice(&magic);
    for (i, byte) in magic.iter().rev().enumerate() {
        prefix[0x220 + i] = *byte;
    }
    seal_body(&mut body, starts, lengths);
    let raw = encode(&prefix, &body);
    Fixture {
        raw,
        body,
        model,
        names: names.map(String::from),
        starts,
        lengths,
    }
}

fn seal_body(body: &mut [u8], starts: [usize; 2], lengths: [usize; 2]) {
    for (start, length) in starts.into_iter().zip(lengths) {
        let at = start + length - 2;
        let crc = crc16(&body[start..at]);
        body[at..at + 2].copy_from_slice(&crc.to_be_bytes());
    }
    let at = body.len() - 16;
    let crc = crc16(&body[..at]);
    body[at..at + 2].copy_from_slice(&crc.to_be_bytes());
}

fn encode(prefix: &[u8], body: &[u8]) -> Vec<u8> {
    // Generate a complete stream from the body origin, then restore the literal
    // label. The production path instead seeks past the first two blocks.
    let mut encrypted = body.to_vec();
    let mut cipher =
        ctr::Ctr128BE::<Aes256>::new((&synthetic_key()).into(), (&synthetic_iv()).into());
    cipher.apply_keystream(&mut encrypted);
    encrypted[..32].copy_from_slice(&body[..32]);
    let mut digest = Sha1::new_with_prefix(body);
    digest.update(synthetic_k8());
    let mut raw = prefix[..BODY_OFFSET].to_vec();
    raw[DIGEST_OFFSET..DIGEST_OFFSET + 20].copy_from_slice(&digest.finalize());
    raw.extend(encrypted);
    raw
}

fn local_key(fixture: &Fixture) -> AesCtrKey {
    key_with_material(
        fixture,
        fixture.model,
        synthetic_key(),
        synthetic_iv(),
        synthetic_k8(),
    )
}

fn key_with_material(
    fixture: &Fixture,
    model: &str,
    key: [u8; 32],
    iv: [u8; 16],
    k8: [u8; 8],
) -> AesCtrKey {
    key_with_optional_material(fixture, model, key, iv, Some(k8))
}

fn key_with_optional_material(
    fixture: &Fixture,
    model: &str,
    key: [u8; 32],
    iv: [u8; 16],
    k8: Option<[u8; 8]>,
) -> AesCtrKey {
    let mut record = serde_json::json!({
        "schema": 1,
        "materials": {
            "aes-ctr": {
                "key": hex::encode(key), "iv": hex::encode(iv),
                "self_check": {
                    "key": hex::encode(Sha256::digest(key)),
                    "iv": hex::encode(Sha256::digest(iv))
                }
            }
        },
        "keys": [{
            "scheme": "aes-ctr", "model": model, "firmware": ["2.00"],
            "firmware_sha256": {"2.00": hex::encode(Sha256::digest(&fixture.raw))},
            "self_check": {}
        }]
    });
    if let Some(k8) = k8 {
        record["keys"][0]["k8"] = hex::encode(k8).into();
        record["keys"][0]["self_check"]["k8"] = hex::encode(Sha256::digest(k8)).into();
    }
    KeyFile::from_json(&serde_json::to_vec(&record).unwrap())
        .unwrap()
        .aes_ctr(&FirmwareIdentity {
            model: model.into(),
            firmware: "2.00".into(),
        })
        .unwrap()
}

#[test]
fn matches_independent_poc_for_original_and_patched_packages() {
    // These whole-package hashes were generated by the reference PoC's reseal
    // and OpenSSL stream functions using only the invented fixture material.
    let fixture = fixture(false);
    assert_eq!(
        hex::encode(Sha256::digest(&fixture.raw)),
        "213b57a0becbcfea4ae0f4f232216dcfec5c924c9aadb48e2596a598512c16a9"
    );
    let key = local_key(&fixture);
    let image = unpack_aes_ctr(&fixture.raw, &key).unwrap();
    assert!(image.header_digest_verified());
    assert_eq!(&image.plaintext()[BODY_OFFSET..], &fixture.body);
    assert_eq!(
        image.payload(&fixture.names[1]).unwrap(),
        &fixture.body[147..239]
    );
    assert!(pack_aes_ctr(&fixture.raw, &key, &[]).unwrap() == fixture.raw);
    let output = pack_aes_ctr(
        &fixture.raw,
        &key,
        &[ModuleEdit::Patch {
            module: fixture.names[1].clone(),
            offset: 7,
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        }],
    )
    .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&output)),
        "c57b4f22ef6ce5d27d2d096ab5ef89da923aaf93c513ade1689e50ca5fcfc75a"
    );
    assert_eq!(&output[..DIGEST_OFFSET], &fixture.raw[..DIGEST_OFFSET]);
    assert_eq!(
        &output[DIGEST_OFFSET + 20..BODY_OFFSET + 32],
        &fixture.raw[DIGEST_OFFSET + 20..BODY_OFFSET + 32]
    );
    let checked = unpack_aes_ctr(&output, &key).unwrap();
    assert_eq!(
        &checked.payload(&fixture.names[1]).unwrap()[7..11],
        &[0xde, 0xad, 0xbe, 0xef]
    );
}

#[test]
fn aligned_zr_preserves_gaps_rsa_blocks_and_uncovered_header_bytes() {
    let fixture = fixture(true);
    let key = local_key(&fixture);
    assert!(pack_aes_ctr(&fixture.raw, &key, &[]).unwrap() == fixture.raw);
    let output = pack_aes_ctr(
        &fixture.raw,
        &key,
        &[ModuleEdit::Patch {
            module: fixture.names[0].clone(),
            offset: 3,
            bytes: vec![0xa5],
        }],
    )
    .unwrap();
    let checked = unpack_aes_ctr(&output, &key).unwrap();
    let body = &checked.plaintext()[BODY_OFFSET..];
    assert_eq!(&body[147..160], &[0; 13]);
    assert_eq!(&body[254..256], &[0; 2]);
    assert_eq!(&output[0x20..0x220], &fixture.raw[0x20..0x220]);
    assert_eq!(&output[0x254..0x260], &fixture.raw[0x254..0x260]);
    assert_eq!(checked.payload(&fixture.names[0]).unwrap()[3], 0xa5);
}

#[test]
fn rejects_wrong_aes_key_iv_digest_key_and_model() {
    let fixture = fixture(false);
    let mut key = synthetic_key();
    key[0] ^= 1;
    let mut iv = synthetic_iv();
    iv[0] ^= 1;
    let mut k8 = synthetic_k8();
    k8[0] ^= 1;
    for wrong in [
        key_with_material(&fixture, fixture.model, key, synthetic_iv(), synthetic_k8()),
        key_with_material(&fixture, fixture.model, synthetic_key(), iv, synthetic_k8()),
        key_with_material(&fixture, fixture.model, synthetic_key(), synthetic_iv(), k8),
        key_with_material(
            &fixture,
            "ZR",
            synthetic_key(),
            synthetic_iv(),
            synthetic_k8(),
        ),
    ] {
        assert!(unpack_aes_ctr(&fixture.raw, &wrong).is_err());
        assert!(pack_aes_ctr(&fixture.raw, &wrong, &[]).is_err());
    }
}

#[test]
fn rejects_changed_payload_checksums_digest_wrapper_and_truncation() {
    let fixture = fixture(false);
    let key = local_key(&fixture);
    for offset in [
        0,
        0x220,
        DIGEST_OFFSET,
        BODY_OFFSET,
        BODY_OFFSET + 120,
        fixture.raw.len() - 16,
    ] {
        let mut damaged = fixture.raw.clone();
        damaged[offset] ^= 1;
        assert!(unpack_aes_ctr(&damaged, &key).is_err());
    }
    for length in [0, 31, BODY_OFFSET, BODY_OFFSET + 32, fixture.raw.len() - 1] {
        assert!(unpack_aes_ctr(&fixture.raw[..length], &key).is_err());
    }
    let mut body = fixture.body.clone();
    body[40] = 1;
    seal_body(&mut body, fixture.starts, fixture.lengths);
    let damaged = encode(&fixture.raw, &body);
    assert!(matches!(
        unpack_aes_ctr(&damaged, &key),
        Err(Error::Directory(_))
    ));
}

#[test]
fn rejects_nonzero_alignment_padding_even_when_signed_and_checksummed() {
    let fixture = fixture(true);
    let key = local_key(&fixture);
    for offset in [147, 254] {
        let mut body = fixture.body.clone();
        body[offset] = 1;
        seal_body(&mut body, fixture.starts, fixture.lengths);
        let damaged = encode(&fixture.raw, &body);
        assert!(unpack_aes_ctr(&damaged, &key).is_err());
    }
}

#[test]
fn rejects_signed_directory_gaps_that_are_not_short_alignment_padding() {
    let fixture = fixture(true);
    let key = local_key(&fixture);
    for second_start in [159_usize, 176] {
        let trailer = (second_start + fixture.lengths[1] + 15) & !15;
        let mut body = vec![0; trailer + 16];
        body[..147].copy_from_slice(&fixture.body[..147]);
        body[second_start..second_start + fixture.lengths[1]]
            .copy_from_slice(&fixture.body[160..254]);
        body[96..100].copy_from_slice(&(second_start as u32).to_be_bytes());
        seal_body(&mut body, [112, second_start], fixture.lengths);
        let damaged = encode(&fixture.raw, &body);
        assert!(matches!(
            unpack_aes_ctr(&damaged, &key),
            Err(Error::Directory(_))
        ));
    }
}

#[test]
fn edits_cannot_cross_module_checksums_or_select_abbreviated_names() {
    let fixture = fixture(false);
    let key = local_key(&fixture);
    for edit in [
        ModuleEdit::Patch {
            module: fixture.names[0].clone(),
            offset: 33,
            bytes: vec![1],
        },
        ModuleEdit::Patch {
            module: fixture.names[0].clone(),
            offset: usize::MAX,
            bytes: vec![1],
        },
        ModuleEdit::Patch {
            module: "ex2010".into(),
            offset: 0,
            bytes: vec![1],
        },
        ModuleEdit::Patch {
            module: fixture.names[0].clone(),
            offset: 0,
            bytes: vec![],
        },
        ModuleEdit::Replace {
            module: fixture.names[0].clone(),
            bytes: vec![1; 34],
        },
    ] {
        assert!(pack_aes_ctr(&fixture.raw, &key, &[edit]).is_err());
    }
    let output = pack_aes_ctr(
        &fixture.raw,
        &key,
        &[ModuleEdit::Replace {
            module: fixture.names[0].clone(),
            bytes: vec![0x5a; 33],
        }],
    )
    .unwrap();
    let checked = unpack_aes_ctr(&output, &key).unwrap();
    assert_eq!(checked.payload(&fixture.names[0]).unwrap(), &[0x5a; 33]);
}

#[test]
fn missing_digest_key_allows_explicitly_unverified_unpack_but_refuses_every_pack() {
    let fixture = fixture(true);
    let key = key_with_optional_material(
        &fixture,
        fixture.model,
        synthetic_key(),
        synthetic_iv(),
        None,
    );
    let image = unpack_aes_ctr(&fixture.raw, &key).unwrap();
    assert!(!image.header_digest_verified());
    assert_eq!(&image.plaintext()[BODY_OFFSET..], &fixture.body);
    assert_eq!(
        image.payload(&fixture.names[0]).unwrap(),
        &fixture.body[112..145]
    );
    // Even a byte-identical repack requires the missing digest material.
    assert!(matches!(
        pack_aes_ctr(&fixture.raw, &key, &[]),
        Err(Error::MissingSignatureKey)
    ));
    let edits = [ModuleEdit::Patch {
        module: fixture.names[0].clone(),
        offset: 0,
        bytes: vec![0xa5],
    }];
    assert!(matches!(
        pack_aes_ctr(&fixture.raw, &key, &edits),
        Err(Error::MissingSignatureKey)
    ));
    // Missing digest verification must never be reported as success. Ordinary
    // payload corruption still fails its independent module checksum.
    let mut changed_digest = fixture.raw.clone();
    changed_digest[DIGEST_OFFSET] ^= 1;
    let image = unpack_aes_ctr(&changed_digest, &key).unwrap();
    assert!(!image.header_digest_verified());
    let mut corrupt_payload = fixture.raw.clone();
    corrupt_payload[BODY_OFFSET + fixture.starts[0]] ^= 1;
    assert!(unpack_aes_ctr(&corrupt_payload, &key).is_err());
}
