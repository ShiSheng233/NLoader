//! Native lifecycle observations preserve the original callees and results.
use crate::{Error, Patch, Result};
use nloader_profile::Profile;
use std::collections::BTreeMap;

pub(crate) fn generate(
    profile: &Profile,
    payload: &[u8],
    symbols: &BTreeMap<String, u64>,
) -> Result<Vec<Patch>> {
    let Some(card) = &profile.services.native_card else {
        return Ok(Vec::new());
    };
    let mut patches = Vec::new();
    for (name, site, callee, symbol) in [
        (
            "mount",
            card.mount.call_site,
            card.mount.callee,
            "nlr_native_card_mount_observe",
        ),
        (
            "unmount",
            card.unmount.call_site,
            card.unmount.callee,
            "nlr_native_card_unmount_observe",
        ),
        (
            "menu",
            card.menu.call_site,
            card.menu.callee,
            "nlr_native_card_menu_checkpoint",
        ),
    ] {
        let target = *symbols
            .get(symbol)
            .ok_or_else(|| Error::Object(format!("native card image lacks {symbol}")))?;
        patches.push(branch_patch(profile, payload, name, site, callee, target)?);
    }
    let target = *symbols
        .get("nlr_native_card_reply_observe")
        .ok_or_else(|| Error::Object("native reply observer is missing".into()))?;
    patches.push(branch_patch(
        profile,
        payload,
        "reply",
        card.rpc.wait_call_site,
        card.rpc.wait_callee,
        target,
    )?);
    let target = *symbols
        .get("nlr_native_card_low_unmount_observe")
        .ok_or_else(|| Error::Object("native low-unmount observer is missing".into()))?;
    for &site in &card.low_unmount_call_sites {
        patches.push(branch_patch(
            profile,
            payload,
            "low unmount",
            site,
            card.low_unmount,
            target,
        )?);
    }
    Ok(patches)
}

pub(crate) fn branch_patch(
    profile: &Profile,
    payload: &[u8],
    name: &str,
    site: u64,
    callee: u64,
    target: u64,
) -> Result<Patch> {
    let base = profile
        .memory
        .link_base
        .ok_or_else(|| Error::Object("native card image lacks link base".into()))?;
    let size = profile
        .memory
        .link_size
        .ok_or_else(|| Error::Object("native card image lacks link size".into()))?;
    if target % 4 != 0
        || target < base
        || target
            >= base
                .checked_add(size)
                .ok_or_else(|| Error::Object("native card link range overflows".into()))?
    {
        return Err(Error::Object(format!(
            "native card {name} observation lies outside the owned image"
        )));
    }
    let offset = profile
        .memory
        .address_to_offset(site, 4)
        .map_err(|error| Error::Object(error.to_string()))?;
    let at = usize::try_from(offset)
        .map_err(|_| Error::Object("native card call offset exceeds host size".into()))?;
    let stock = payload
        .get(at..at + 4)
        .ok_or_else(|| Error::Object("native lifecycle call lies outside EG".into()))?
        .to_vec();
    let word = u32::from_le_bytes(stock.as_slice().try_into().unwrap());
    let old_delta = (((word & 0x03ffffff) as i32) << 6 >> 6) as i64 * 4;
    if word & 0xfc000000 != 0x94000000 || site.checked_add_signed(old_delta) != Some(callee) {
        return Err(Error::Object(format!(
            "native {name} call does not target its declared original function"
        )));
    }
    let delta = i64::try_from(target)
        .map_err(|_| Error::Object("native target overflows".into()))?
        - i64::try_from(site).map_err(|_| Error::Object("native call site overflows".into()))?;
    if delta % 4 != 0 || !(-(1 << 25)..(1 << 25)).contains(&(delta / 4)) {
        return Err(Error::Object(
            "native lifecycle branch exceeds BL range".into(),
        ));
    }
    Ok(Patch {
        site: Some(site),
        file_offset: offset,
        kind: "branch",
        stock,
        new: (0x94000000 | (((delta / 4) as u32) & 0x03ffffff))
            .to_le_bytes()
            .to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nloader_profile::{Memory, MemorySegment, MemorySegmentKind};
    fn profile() -> Profile {
        let mut p = Profile::draft("Z8", "3.11");
        p.memory = Memory {
            xip_base: Some(0x1000),
            module_size: Some(4),
            link_base: Some(0x2000),
            link_size: Some(0x1000),
            segments: vec![MemorySegment {
                file_offset: 0,
                runtime_start: 0x1000,
                size: 4,
                kind: MemorySegmentKind::Xip,
            }],
            ..Memory::default()
        };
        p
    }
    #[test]
    fn branch_preserves_original_call_and_uses_only_owned_destination() {
        let bytes = 0x94000040u32.to_le_bytes();
        let p = branch_patch(&profile(), &bytes, "menu", 0x1000, 0x1100, 0x2400).unwrap();
        assert_eq!(p.stock, bytes);
        assert_eq!(p.new, 0x94000500u32.to_le_bytes());
        assert_eq!(p.file_offset, 0);
        assert!(branch_patch(&profile(), &bytes, "menu", 0x1000, 0x1100, 0x3000).is_err());
        assert!(branch_patch(&profile(), &bytes, "menu", 0x1000, 0x1100, 0x2401).is_err());
    }
    #[test]
    fn changed_stock_callee_or_non_call_cannot_be_hooked() {
        assert!(branch_patch(
            &profile(),
            &0x94000040u32.to_le_bytes(),
            "mount",
            0x1000,
            0x1104,
            0x2400
        )
        .is_err());
        assert!(branch_patch(
            &profile(),
            &0x14000040u32.to_le_bytes(),
            "mount",
            0x1000,
            0x1100,
            0x2400
        )
        .is_err());
        assert!(branch_patch(&profile(), &[], "mount", 0x1000, 0x1100, 0x2400).is_err());
    }
}
