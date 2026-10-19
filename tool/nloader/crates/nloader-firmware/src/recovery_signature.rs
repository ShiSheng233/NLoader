//! Header-digest recovery for validated Z8/Z9 Legacy XOR plaintext.
//!
//! Seeds come only from this input and candidates must reproduce its digest.
use crate::{Error, Result, HEADER};
use sha1::{Digest, Sha1};
use std::collections::HashSet;

const SHA1_IV_PREFIX: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const SEED_DISTANCE: usize = 24;
const MULTIPLIERS: [u32; 2] = [0x260, 0xd3];

/// Recover a unique digest key from a fully decrypted, unmodified container.
/// The original 32-byte header must precede the body, including its trailer.
pub(super) fn recover(plain: &[u8], model: &str) -> Result<[u8; 8]> {
    let expected_model = match model {
        "Z8" => "2070",
        "Z9" => "1990",
        _ => return Err(Error::KeyIdentity),
    };
    let body = plain.get(HEADER..).ok_or(Error::UnsupportedContainer)?;
    let modules = crate::validate_body(body)?;
    let first_name = &modules[0].name;
    if !first_name.as_bytes()[..2]
        .iter()
        .all(u8::is_ascii_alphabetic)
        || first_name.get(2..6) != Some(expected_model)
    {
        return Err(Error::KeyIdentity);
    }

    // Do not treat bytes in the header, directory, checksum or adjacent module
    // as a seed literal. Duplicate literals need not repeat the entire search.
    let mut seeds = HashSet::<[u8; 8]>::new();
    for module in modules {
        let payload = &body[module.body_offset..module.body_offset + module.payload_length()];
        for (position, window) in payload.windows(SHA1_IV_PREFIX.len()).enumerate() {
            if window == SHA1_IV_PREFIX && position >= SEED_DISTANCE {
                let offset = position - SEED_DISTANCE;
                let mut seed = [0; 8];
                seed.copy_from_slice(&payload[offset..offset + 8]);
                seeds.insert(seed);
            }
        }
    }
    if seeds.is_empty() {
        return Err(Error::Recovery("no supported digest seed locator"));
    }

    // Hash large firmware bodies once. Every candidate only extends this state
    // by eight bytes; importantly, the trailer remains part of the hash.
    let prefix = Sha1::new_with_prefix(body);
    let expected_digest = &plain[..20];
    let mut recovered = None;
    for seed in seeds {
        for multiplier in MULTIPLIERS {
            for a in 0..=u8::MAX {
                for b in 0..=u8::MAX {
                    let candidate = candidate_key(seed, a, b, multiplier);
                    let mut digest = prefix.clone();
                    digest.update(candidate);
                    if digest.finalize().as_slice() != expected_digest {
                        continue;
                    }
                    if recovered.is_some_and(|previous| previous != candidate) {
                        return Err(Error::Recovery("ambiguous digest key candidates"));
                    }
                    recovered = Some(candidate);
                }
            }
        }
    }
    recovered.ok_or(Error::Recovery("no candidate matches the header digest"))
}

fn candidate_key(seed: [u8; 8], a: u8, b: u8, multiplier: u32) -> [u8; 8] {
    let mut key = seed;
    let mut accumulator = u32::from(b);
    let mut step = u32::from(a) * multiplier;
    for byte in &mut key {
        accumulator = accumulator.wrapping_add(step);
        *byte ^= accumulator as u8;
        step = step.wrapping_add(u32::from(a));
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{reseal, signature, TRAILER};

    // Invented fixture material, unrelated to any camera's firmware or keys.
    const TEST_SEED: [u8; 8] = [0x11, 0x32, 0x57, 0x79, 0x91, 0xab, 0xcb, 0xde];
    const PAYLOAD_START: usize = 80;
    const PAYLOAD_LEN: usize = 128;

    fn fixture(model: &str, multiplier: u32) -> (Vec<u8>, [u8; 8]) {
        let mut key = TEST_SEED;
        // Independent closed form, rather than the production accumulator.
        for (i, byte) in key.iter_mut().enumerate() {
            let i = i as u32;
            *byte ^= (0x51 + 0x37 * ((i + 1) * multiplier + i * (i + 1) / 2)) as u8;
        }
        let mut body = vec![0; PAYLOAD_START + PAYLOAD_LEN + 2 + TRAILER];
        body[..32].fill(b' ');
        body[32..36].copy_from_slice(&1_u32.to_be_bytes());
        body[36..40].copy_from_slice(&(PAYLOAD_START as u32).to_be_bytes());
        let name = format!("ex{model}_031100.bi");
        body[48..48 + name.len()].copy_from_slice(name.as_bytes());
        body[64..68].copy_from_slice(&(PAYLOAD_START as u32).to_be_bytes());
        body[68..72].copy_from_slice(&((PAYLOAD_LEN + 2) as u32).to_be_bytes());
        body[PAYLOAD_START + 24..PAYLOAD_START + 32].copy_from_slice(&TEST_SEED);
        body[PAYLOAD_START + 48..PAYLOAD_START + 56].copy_from_slice(&SHA1_IV_PREFIX);
        let mut plain = vec![0; HEADER];
        plain.extend_from_slice(&body);
        seal(&mut plain, &key);
        (plain, key)
    }

    fn seal(plain: &mut [u8], key: &[u8; 8]) {
        let body = &mut plain[HEADER..];
        let modules = crate::parse_directory(body).unwrap();
        reseal(body, &modules);
        let digest = signature(body, key);
        plain[..20].copy_from_slice(&digest);
    }

    #[test]
    fn recovers_signed_z8_and_z9_bodies_with_both_stream_variants() {
        for (id, model, multiplier) in [("2070", "Z8", 0x260), ("1990", "Z9", 0xd3)] {
            let (plain, expected) = fixture(id, multiplier);
            // Do not include recovered or expected key bytes in failure output.
            assert!(recover(&plain, model).is_ok_and(|key| key == expected));
        }
    }

    #[test]
    fn refuses_wrong_or_unsupported_model_and_invalid_directory() {
        let (mut plain, _) = fixture("2070", 0x260);
        assert!(matches!(recover(&plain, "Z9"), Err(Error::KeyIdentity)));
        assert!(matches!(recover(&plain, "Z6III"), Err(Error::KeyIdentity)));
        plain[HEADER + 35] = 2;
        assert!(matches!(recover(&plain, "Z8"), Err(Error::Directory(_))));
        assert!(recover(&[], "Z8").is_err());
    }

    #[test]
    fn refuses_changed_header_digest() {
        let (mut plain, _) = fixture("2070", 0x260);
        plain[0] ^= 1;
        assert!(matches!(recover(&plain, "Z8"), Err(Error::Recovery(_))));
    }

    #[test]
    fn refuses_digest_that_excludes_the_trailer() {
        let (mut plain, key) = fixture("2070", 0x260);
        let digest = signature(&plain[HEADER..plain.len() - TRAILER], &key);
        plain[..20].copy_from_slice(&digest);
        assert!(matches!(recover(&plain, "Z8"), Err(Error::Recovery(_))));
    }

    #[test]
    fn refuses_missing_or_out_of_payload_seed_locator() {
        let (mut plain, key) = fixture("2070", 0x260);
        let payload_start = HEADER + PAYLOAD_START;
        plain[payload_start + 48..payload_start + 56].fill(0);
        seal(&mut plain, &key);
        assert!(matches!(recover(&plain, "Z8"), Err(Error::Recovery(_))));
        // A locator near the module start would take its seed from the directory.
        plain[payload_start + 8..payload_start + 16].copy_from_slice(&SHA1_IV_PREFIX);
        seal(&mut plain, &key);
        assert!(matches!(recover(&plain, "Z8"), Err(Error::Recovery(_))));
    }

    #[test]
    fn requires_payload_integrity_before_searching() {
        let (mut plain, _) = fixture("2070", 0x260);
        plain[HEADER + PAYLOAD_START] ^= 1;
        assert!(matches!(recover(&plain, "Z8"), Err(Error::Integrity(_))));
    }

    #[test]
    fn checks_multiple_locators_and_accepts_duplicate_literal() {
        let (mut plain, key) = fixture("2070", 0x260);
        let payload_start = HEADER + PAYLOAD_START;
        // A decoy and a second copy of the correct literal are both allowed;
        // only the header digest determines the recovered key.
        plain[payload_start..payload_start + 8].fill(0x42);
        plain[payload_start + 24..payload_start + 32].copy_from_slice(&SHA1_IV_PREFIX);
        plain[payload_start + 72..payload_start + 80].copy_from_slice(&TEST_SEED);
        plain[payload_start + 96..payload_start + 104].copy_from_slice(&SHA1_IV_PREFIX);
        // Preserve a duplicate occurrence with the same seed value.
        plain[payload_start + 40..payload_start + 48].copy_from_slice(&TEST_SEED);
        plain[payload_start + 64..payload_start + 72].copy_from_slice(&SHA1_IV_PREFIX);
        seal(&mut plain, &key);
        assert!(recover(&plain, "Z8").is_ok_and(|actual| actual == key));
    }
}
