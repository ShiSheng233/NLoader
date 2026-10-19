//! Native page refresh retains the widget tree instead of navigating away.
use crate::paint_validation::{target, word};
use crate::validation::{hash_matches, valid_hash};
use crate::{sha256, IssueKind, Profile, UiFamily, ValidationReport};

impl Profile {
    pub(crate) fn validate_menu_refresh(&self, r: &mut ValidationReport) {
        let Some(refresh) = self.menu.page.as_ref().and_then(|p| p.refresh.as_ref()) else {
            return;
        };
        if self.identity.model != "Z8"
            || self.identity.firmware != "3.11"
            || self.abi.ui != Some(UiFamily::Z8MenuV1)
        {
            r.add(
                "menu.page.refresh",
                IssueKind::Unsupported,
                "native page refresh is audited only for the Z8 C3.11 menu family",
            );
        }
        let b = &refresh.body;
        if b.name != "page_refresh"
            || b.address != refresh.function
            || b.length != 712
            || !valid_hash(&b.sha256)
            || refresh.function % 4 != 0
            || !self.memory.is_xip_range(refresh.function, 712)
        {
            r.add(
                "menu.page.refresh.body",
                IssueKind::Invalid,
                "complete aligned native page refresh body must bind its explicit function",
            );
        }
        for (name, address) in [
            ("entry_dispatch", refresh.entry_dispatch),
            ("layout_changed", refresh.layout_changed),
            ("display_refresh", refresh.display_refresh),
        ] {
            if address % 4 != 0 || !self.memory.is_xip_range(address, 4) {
                r.add(
                    format!("menu.page.refresh.{name}"),
                    IssueKind::OutOfBounds,
                    "native refresh call target must be explicit original XIP code",
                );
            }
        }
        if self
            .menu
            .events
            .as_ref()
            .is_none_or(|e| e.nav_first != 0x68c)
        {
            r.add(
                "menu.page.refresh.navigation",
                IssueKind::Conflict,
                "in-place refresh requires the audited stay navigation sentinel",
            );
        }
    }
    pub(crate) fn validate_menu_refresh_bytes(&self, module: &[u8], r: &mut ValidationReport) {
        let Some(refresh) = self.menu.page.as_ref().and_then(|p| p.refresh.as_ref()) else {
            return;
        };
        let Some(bytes) = self
            .memory
            .address_to_offset(refresh.function, 712)
            .ok()
            .and_then(|o| usize::try_from(o).ok())
            .and_then(|o| module.get(o..o.checked_add(712)?))
        else {
            return;
        };
        if !hash_matches(&sha256(bytes), &refresh.body.sha256) {
            r.add(
                "menu.page.refresh.body",
                IssueKind::FingerprintMismatch,
                "native refresh complete body differs from the official image",
            );
        }
        let call = |offset, callee| {
            word(bytes, offset).and_then(|w| target(refresh.function + offset as u64, w))
                == Some(callee)
        };
        if word(bytes, 0xc) != Some(0xaa0003f3)
            || word(bytes, 0x94) != Some(0x79406274)
            || !call(0x9c, refresh.entry_dispatch)
            || word(bytes, 0x124) != Some(0x79406268)
            || word(bytes, 0x128) != Some(0x6b08029f)
            || !call(0x1a4, refresh.layout_changed)
            || word(bytes, 0x2ac) != Some(0x320007e1)
            || word(bytes, 0x2b0) != Some(0x32000be2)
            || !call(0x2b4, refresh.display_refresh)
            || word(bytes, 0x2c4) != Some(0xd65f03c0)
        {
            r.add("menu.page.refresh.semantics",IssueKind::Conflict,"refresh must preserve old count, call the original entry, relayout changed count and perform native display refresh");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ExecutionBody, Memory, MemorySegment, MemorySegmentKind, MenuEvents, MenuOwnPage,
        MenuPageRefresh, MenuPageRefreshFamily,
    };
    fn fixture() -> Profile {
        let mut p = Profile::draft("Z8", "3.11");
        p.abi.ui = Some(UiFamily::Z8MenuV1);
        p.memory = Memory {
            xip_base: Some(0x1000),
            module_size: Some(0x8000),
            segments: vec![MemorySegment {
                file_offset: 0,
                runtime_start: 0x1000,
                size: 0x8000,
                kind: MemorySegmentKind::Xip,
            }],
            ..Memory::default()
        };
        p.menu.events = Some(MenuEvents {
            activation: [1, 2, 3, 4],
            back: [5, 6, 7],
            ok: 8,
            terminator: 9,
            nav_first: 0x68c,
            nav_back: 0x68d,
            nav_reenter: 0x696,
            nav_last: 0x697,
            navigation_address: 0x1100,
            navigation_sha256: "00".repeat(32),
            lookup_address: 0x1200,
            lookup_sha256: "00".repeat(32),
        });
        p.menu.page = Some(MenuOwnPage {
            refresh: Some(MenuPageRefresh {
                family: MenuPageRefreshFamily::Z8ListPageRefreshV1,
                function: 0x2000,
                body: ExecutionBody {
                    name: "page_refresh".into(),
                    address: 0x2000,
                    length: 712,
                    sha256: "00".repeat(32),
                },
                entry_dispatch: 0x3000,
                layout_changed: 0x4000,
                display_refresh: 0x5000,
            }),
            window_id: 1,
            page_record: 0xb00000100,
            template_window: 2,
            template_page: 0xb00000200,
            row_event_table: 0x1300,
            row_template_event_table: 0x1400,
            title_slot: 1,
            title_format: 1,
            item_id: 1,
            item_flags: 0,
            item_slot: 2,
            item_style: 1,
            item_text: "test".into(),
            row_slots: vec![],
            row_hide: None,
            row_hide_stock: vec![],
            selected_offset: None,
            viewport_bottom: None,
            row_words: Vec::new(),
            style_page: None,
            dynamic_rows: false,
            detail_window_id: None,
            rows: None,
            keyboard: None,
            rebuild: None,
            caution: None,
        });
        p
    }
    fn report(p: &Profile) -> ValidationReport {
        let mut r = ValidationReport::default();
        p.validate_menu_refresh(&mut r);
        r
    }
    #[test]
    fn native_refresh_is_explicit_optional_and_short_or_misbound_input_is_refused() {
        let p = fixture();
        assert!(report(&p).is_valid());
        let mut old = p.clone();
        old.menu.page.as_mut().unwrap().refresh = None;
        assert!(report(&old).is_valid());
        let mut bad = p.clone();
        bad.menu
            .page
            .as_mut()
            .unwrap()
            .refresh
            .as_mut()
            .unwrap()
            .body
            .length = 16;
        assert!(!report(&bad).is_valid());
        let mut bad = p.clone();
        bad.menu
            .page
            .as_mut()
            .unwrap()
            .refresh
            .as_mut()
            .unwrap()
            .function += 4;
        assert!(!report(&bad).is_valid());
        let mut bad = p.clone();
        bad.menu.events.as_mut().unwrap().nav_first = 0x696;
        assert!(!report(&bad).is_valid());
        let mut bad = p.clone();
        bad.identity.firmware = "3.10".into();
        assert!(!report(&bad).is_valid());
        let mut r = ValidationReport::default();
        p.validate_menu_refresh_bytes(&vec![0; 0x8000], &mut r);
        assert!(r
            .issues
            .iter()
            .any(|i| i.field == "menu.page.refresh.semantics"));
    }
}
