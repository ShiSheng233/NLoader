use nloader_build::layout;
use nloader_profile::{BuildMode, Profile};
use object::{Object, ObjectSection};
use std::{ffi::OsStr, fs};

#[test]
fn layout_rejects_non_object_and_existing_output_without_compiler_access() {
    assert!(layout::inspect(b"not ELF metadata").is_err());
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("existing");
    fs::write(&out, b"keep").unwrap();
    let mut profile = Profile::draft("Z8", "3.11");
    profile.storage.root = Some("B:\\NLOADER\\".into());
    assert!(layout::compile(
        &profile,
        BuildMode::LoadOnly,
        OsStr::new("missing-clang"),
        &out
    )
    .is_err());
    assert_eq!(fs::read(out).unwrap(), b"keep");
}

#[test]
#[ignore = "requires Clang with AArch64 support; compiles only an independent constant object"]
fn runtime_layout_is_unlinked_readonly_and_rejects_tampered_geometry() {
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("layout");
    let mut profile = Profile::draft("Z8", "3.11");
    profile.storage.root = Some("B:\\NLOADER\\".into());
    let report = layout::compile(&profile, BuildMode::LoadOnly, OsStr::new("clang"), &out).unwrap();
    let bytes = fs::read(out.join("runtime-layout.o")).unwrap();
    let decoded = layout::inspect(&bytes).unwrap();
    assert_eq!(decoded.runtime_bytes, report.layout.runtime_bytes);
    assert!(!decoded.physical_fresh);
    assert!(decoded.provided_layout);
    assert_eq!(decoded.field("worker.name").unwrap().bytes, 8);
    assert_eq!(decoded.trace_slots, 16);
    assert!(
        decoded.field("trace.count").unwrap().offset
            < decoded.field("trace.entries").unwrap().offset
    );
    assert_eq!(
        nloader_profile::sha256(&fs::read(out.join("runtime-layout.c")).unwrap()),
        report.generated_source_sha256
    );
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let section = object
        .section_by_name(".rodata.nlr_runtime_layout")
        .unwrap();
    let (offset, _) = section.file_range().unwrap();
    for word in [0, 1, 4, 5, 6, 7, 8, 9, 10] {
        let mut bad = bytes.clone();
        let at = offset as usize + word * 8;
        bad[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            layout::inspect(&bad).is_err(),
            "accepted corrupted layout word {word}"
        );
    }
    #[cfg(unix)]
    {
        let dangling = d.path().join("dangling");
        std::os::unix::fs::symlink(d.path().join("missing"), &dangling).unwrap();
        assert!(layout::preflight(&dangling).is_err());
    }
}
