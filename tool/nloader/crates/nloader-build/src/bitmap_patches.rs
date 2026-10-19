//! Preserve the original native draw and insert one optional observation call.
use crate::{Error, Patch, Result};
use nloader_profile::Profile;
use std::collections::BTreeMap;
pub(crate) fn generate(
    profile: &Profile,
    payload: &[u8],
    symbols: &BTreeMap<String, u64>,
) -> Result<Vec<Patch>> {
    let Some(b) = &profile.services.bitmap else {
        return Ok(Vec::new());
    };
    let target = *symbols
        .get("nlr_bitmap_observe")
        .ok_or_else(|| Error::Object("bitmap observer is missing from linked image".into()))?;
    Ok(vec![crate::native_card_patches::branch_patch(
        profile,
        payload,
        "bitmap",
        b.call_site,
        b.original_callee,
        target,
    )?])
}
