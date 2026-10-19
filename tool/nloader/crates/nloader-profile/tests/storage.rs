use nloader_profile::{BuildMode, IssueKind, Profile, MAX_STORAGE_ROOT_BYTES};

const MODES: [BuildMode; 6] = [
    BuildMode::Marker,
    BuildMode::HookOnly,
    BuildMode::Page,
    BuildMode::LoadOnly,
    BuildMode::PrepareOnly,
    BuildMode::Exec,
];

fn storage_issues(profile: &Profile, mode: BuildMode) -> Vec<IssueKind> {
    profile
        .validate(mode)
        .issues
        .into_iter()
        .filter(|issue| issue.field == "storage.root")
        .map(|issue| issue.kind)
        .collect()
}

#[test]
fn card_access_requires_an_explicit_root_without_a_drive_default() {
    let profile = Profile::draft("Z8", "3.11");
    assert!(profile.storage.root.is_none());
    let roundtrip = Profile::from_toml(&profile.to_toml().unwrap()).unwrap();
    assert!(roundtrip.storage.root.is_none());
    for mode in MODES {
        let expected = if matches!(
            mode,
            BuildMode::LoadOnly | BuildMode::PrepareOnly | BuildMode::Exec
        ) {
            vec![IssueKind::Missing]
        } else {
            vec![]
        };
        assert_eq!(storage_issues(&roundtrip, mode), expected, "{mode}");
    }
}

#[test]
fn both_drives_and_nested_directories_roundtrip_at_the_byte_limit() {
    for root in [
        "A:\\NLOADER\\".to_owned(),
        "B:\\NLOADER\\".to_owned(),
        "A:\\TEST-12\\loader_v2\\".to_owned(),
        format!("B:\\{}\\", "X".repeat(MAX_STORAGE_ROOT_BYTES - 4)),
    ] {
        let mut profile = Profile::draft("Z8", "3.11");
        profile.storage.root = Some(root.clone());
        let roundtrip = Profile::from_toml(&profile.to_toml().unwrap()).unwrap();
        assert_eq!(roundtrip.storage.root.as_deref(), Some(root.as_str()));
        for mode in MODES {
            assert!(
                storage_issues(&roundtrip, mode).is_empty(),
                "{mode}: {root:?}"
            );
        }
    }
}

#[test]
fn every_mode_rejects_ambiguous_or_unsafe_card_roots() {
    let mut roots: Vec<String> = [
        "",
        "A:",
        "A:\\",
        "A:NLOADER\\",
        "C:\\NLOADER\\",
        "?:\\NLOADER\\",
        "a:\\NLOADER\\",
        "\\NLOADER\\",
        "A:/NLOADER/",
        "A:\\NLOADER",
        "A:\\NLOADER\\\\",
        "A:\\\\NLOADER\\",
        "A:\\.\\",
        "A:\\..\\",
        "A:\\NLOADER\\..\\",
        "A:\\has space\\",
        "A:\\quoted\"\\",
        "A:\\name/other\\",
        "A:\\名\\",
        "A:\\line\n\\",
        "A:\\nul\0\\",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    roots.push(format!("B:\\{}\\", "X".repeat(MAX_STORAGE_ROOT_BYTES - 3)));
    for root in roots {
        let mut profile = Profile::draft("Z8", "3.11");
        profile.storage.root = Some(root.clone());
        for mode in MODES {
            assert_eq!(
                storage_issues(&profile, mode),
                vec![IssueKind::Invalid],
                "{mode}: {root:?}"
            );
        }
    }
}

#[test]
fn storage_typos_and_nonstring_roots_fail_parsing() {
    for fields in [
        "rot = 'A:\\NLOADER\\'",
        "root = 1",
        "root = ['A:\\NLOADER\\']",
    ] {
        assert!(Profile::from_toml(&format!("schema = 1\n[storage]\n{fields}\n")).is_err());
    }
}
