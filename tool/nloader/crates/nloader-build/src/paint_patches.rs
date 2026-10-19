//! A single original BL is redirected through a matching four-argument observer.
use crate::{Error, Patch, Result};
use nloader_profile::Profile;
use std::collections::BTreeMap;
pub(crate) fn generate(
    profile: &Profile,
    payload: &[u8],
    symbols: &BTreeMap<String, u64>,
) -> Result<Vec<Patch>> {
    let Some(p) = &profile.services.paint else {
        return Ok(Vec::new());
    };
    let target = *symbols
        .get("nlr_paint_text_observe")
        .ok_or_else(|| Error::Object("paint observer is missing from linked image".into()))?;
    Ok(vec![crate::native_card_patches::branch_patch(
        profile,
        payload,
        "paint",
        p.call_site,
        p.original_callee,
        target,
    )?])
}
