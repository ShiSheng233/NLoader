//! AES-256-CTR wrapper with preserved outer metadata and wrapped-key blocks.
use crate::{AesCtrKey, Error, FirmwareImage, ModuleEdit, Result};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

const BODY_OFFSET: usize = 0x260;
const DIGEST_OFFSET: usize = 0x240;
const MIRROR_OFFSET: usize = 0x220;
const LABEL_LENGTH: usize = 32;

const WRAPPER_MAGIC: [u8; 32] = [
    0x42, 0x06, 0x01, 0xf5, 0x7f, 0x69, 0x30, 0x8e, 0xab, 0x4d, 0x2a, 0x4e, 0xa3, 0xf4, 0x86, 0xe2,
    0x56, 0xd9, 0x3c, 0x6d, 0x8f, 0x16, 0x5c, 0x96, 0x8e, 0x99, 0xe4, 0xd2, 0x0a, 0x02, 0x9f, 0xb3,
];

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Decrypt a newer wrapper and verify its directory and CRCs.
/// The header digest is checked only when the local key includes its suffix.
/// Wrapped RSA blocks are preserved; their cryptographic validity is not checked.
pub fn unpack(raw: &[u8], key: &AesCtrKey) -> Result<FirmwareImage> {
    check_wrapper(raw)?;
    let plain = transform(raw, key)?;
    let body = &plain[BODY_OFFSET..];
    let modules = crate::validate_body_aligned(body)?;
    let expected_model = match key.model.as_str() {
        "Z6III" => "2010",
        "ZR" => "2210",
        _ => return Err(Error::KeyIdentity),
    };
    if modules.first().and_then(|module| module.name.get(2..6)) != Some(expected_model) {
        return Err(Error::KeyIdentity);
    }
    if let Some(k8) = &key.k8 {
        if crate::signature(body, k8).as_slice() != &plain[DIGEST_OFFSET..DIGEST_OFFSET + 20] {
            return Err(Error::Integrity("header digest"));
        }
    }
    Ok(FirmwareImage {
        plain,
        modules,
        body_offset: BODY_OFFSET,
        header_digest_verified: key.k8.is_some(),
    })
}

/// Apply bounded payload edits, reseal every checksum and verify the result.
/// The input is never changed and no files are written by this function.
pub fn pack(raw: &[u8], key: &AesCtrKey, edits: &[ModuleEdit]) -> Result<Vec<u8>> {
    let k8 = key.k8.as_ref().ok_or(Error::MissingSignatureKey)?;
    let mut image = unpack(raw, key)?;
    let body = &mut image.plain[BODY_OFFSET..];
    crate::apply_edits(body, &image.modules, edits)?;
    crate::reseal(body, &image.modules);
    let digest = crate::signature(body, k8);
    image.plain[DIGEST_OFFSET..DIGEST_OFFSET + 20].copy_from_slice(&digest);
    let output = transform(&image.plain, key)?;
    let checked = unpack(&output, key)?;
    if checked.plain != image.plain || (edits.is_empty() && output != raw) {
        return Err(Error::OutputVerification);
    }
    Ok(output)
}

fn check_wrapper(raw: &[u8]) -> Result<()> {
    if raw.get(BODY_OFFSET..BODY_OFFSET + LABEL_LENGTH) != Some(&[b' '; LABEL_LENGTH]) {
        return Err(Error::UnsupportedContainer);
    }
    if raw[..LABEL_LENGTH] != WRAPPER_MAGIC {
        return Err(Error::UnsupportedContainer);
    }
    if !raw[MIRROR_OFFSET..MIRROR_OFFSET + LABEL_LENGTH]
        .iter()
        .rev()
        .eq(WRAPPER_MAGIC.iter())
    {
        return Err(Error::Integrity("wrapper magic mirror"));
    }
    Ok(())
}

fn transform(raw: &[u8], key: &AesCtrKey) -> Result<Vec<u8>> {
    let mut output = raw.to_vec();
    let mut cipher = Aes256Ctr::new((&key.key).into(), (&key.iv).into());
    // Literal spaces consume the first two counter blocks without encryption.
    cipher
        .try_seek(LABEL_LENGTH as u64)
        .map_err(|_| Error::Integrity("AES-CTR counter range"))?;
    cipher
        .try_apply_keystream(&mut output[BODY_OFFSET + LABEL_LENGTH..])
        .map_err(|_| Error::Integrity("AES-CTR stream length"))?;
    Ok(output)
}
