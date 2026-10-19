//! Host behavior tests for the camera-side core. They compile the real C
//! sources against a mock service table and run the resulting binary; no
//! firmware, key material or camera is involved. Clang is required, matching
//! the other compilation-gated tests in this crate.

use std::{fs, path::Path, process::Command};

/// The diagnostic ladder's stage switches, compiled into the same test source;
/// each binary asserts its own stage's page contract.
const STAGES: &[(&str, &str)] = &[
    ("", "hook-only"),
    ("-DNLR_STAGE_PAGE", "page"),
    ("-DNLR_STAGE_LOAD_ONLY", "load-only"),
    ("-DNLR_STAGE_PREPARE_ONLY", "prepare-only"),
    ("-DNLR_STAGE_EXEC", "exec"),
];

/// Optimization and sanitizer variants every stage binary must pass: the
/// unoptimized build, an -O1 build with ASan/UBSan, and the size-optimized
/// build the camera packages use.
const CONFIGS: &[(&str, bool)] = &[("-O0", false), ("-O1", true), ("-Os", false)];

const DEFAULT_CARD_ROOT: &str = r"B:\NLOADER\";
const ALTERNATE_CARD_ROOT: &str = r"A:\CUSTOM_LOADER\FILES\";

/// The loader/page ladder: the page, directory, load and probe layers plus
/// the api table and the worker-frame context assembly they link against.
const TEST_CORE_SOURCES: &[&str] = &[
    "exec.c",
    "api.c",
    "platform.c",
    "journal.c",
    "time.c",
    "input.c",
    "hook.c",
    "file_store.c",
    "program_context.S",
    "load.c",
    "manifest.c",
    "runtime.c",
    "menu_page.c",
    "test_core.c",
];

/// The generic-program ladder: the 64-byte header load path, the two-block
/// executor and the api table.
const TEST_PROGRAM_SOURCES: &[&str] = &[
    "exec.c",
    "api.c",
    "platform.c",
    "journal.c",
    "time.c",
    "input.c",
    "hook.c",
    "file_store.c",
    "program_context.S",
    "load.c",
    "manifest.c",
    "runtime.c",
    "boot_autoload.c",
    "test_program.c",
    "../sdk/examples/menu_extension.c",
];

fn assert_compiles_and_runs(
    stage: (&str, &str),
    sources: &[&str],
    binary_name: &str,
    optimization: &str,
    sanitizer: bool,
    expected_output: &str,
    card_root: &str,
) {
    let (stage_flag, stage_name) = stage;
    let core_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let directory = tempfile::tempdir().unwrap();
    let generated_include = directory.path().join("include");
    let generated_headers = generated_include.join("nlr");
    std::fs::create_dir_all(&generated_headers).unwrap();
    let escaped_root = card_root.replace('\\', "\\\\");
    std::fs::write(
        generated_headers.join("card_config.h"),
        format!("#define NLR_CARD_ROOT \"{escaped_root}\"\n#define NLR_HAS_NATIVE_CARD 0\n#define NLR_HAS_BITMAP 0\n#define NLR_HAS_PAINT 0\n#define NLR_HAS_PRIVATE_TEXT 0\n"),
    )
    .unwrap();
    let binary = directory.path().join(binary_name);
    let objects: Vec<_> = sources.iter().map(|name| core_root.join(name)).collect();
    let mut command = Command::new("clang");
    command
        .arg("-I")
        .arg(&generated_include)
        .arg("-I")
        .arg(core_root.join("include"))
        .arg("-I")
        .arg(core_root.join("../sdk"))
        .args(["-Wall", "-Wextra", "-Werror"]);
    command.arg(optimization);
    if sanitizer {
        command.arg("-fsanitize=address,undefined");
    }
    command.args(stage_flag.split_whitespace());
    let result = command
        .args(&objects)
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("clang should be available");
    assert!(
        result.status.success(),
        "core test compilation failed ({stage_name}, {optimization}):\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let run = Command::new(&binary).output().unwrap();
    assert!(
        run.status.success(),
        "core behavior tests failed ({stage_name}, {optimization}):\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&run.stdout).contains(expected_output),
        "unexpected test output ({stage_name}, {optimization}): {}",
        String::from_utf8_lossy(&run.stdout)
    );
}

#[test]
#[ignore = "requires clang"]
fn load_runtime_and_page_pass_mock_service_behaviour() {
    for (flag, name) in STAGES {
        for (optimization, sanitizer) in CONFIGS {
            assert_compiles_and_runs(
                (flag, name),
                TEST_CORE_SOURCES,
                "test_core",
                optimization,
                *sanitizer,
                "core behavior tests passed",
                DEFAULT_CARD_ROOT,
            );
        }
    }
}

/// The page ladder again with the stock in-place rebuild declared: actions
/// stay, and a shorter view is built at its own length.
#[test]
#[ignore = "requires clang"]
fn page_rebuild_builds_shorter_views_in_place() {
    for (flag, name) in [
        (
            "-DNLR_STAGE_LOAD_ONLY -DNLR_TEST_PAGE_REBUILD",
            "load-only-rebuild",
        ),
        (
            "-DNLR_STAGE_PREPARE_ONLY -DNLR_TEST_PAGE_REBUILD",
            "prepare-only-rebuild",
        ),
        ("-DNLR_STAGE_EXEC -DNLR_TEST_PAGE_REBUILD", "exec-rebuild"),
        (
            "-DNLR_STAGE_EXEC -DNLR_TEST_PAGE_REBUILD -DNLR_TEST_PAGES",
            "exec-pages",
        ),
        (
            "-DNLR_STAGE_EXEC -DNLR_TEST_PAGE_REBUILD -DNLR_TEST_PAGES \
             -DNLR_TEST_ENABLE_INVERTED",
            "exec-pages-inverted",
        ),
    ] {
        for (optimization, sanitizer) in CONFIGS {
            assert_compiles_and_runs(
                (flag, name),
                TEST_CORE_SOURCES,
                "test_core",
                optimization,
                *sanitizer,
                "core behavior tests passed",
                DEFAULT_CARD_ROOT,
            );
        }
    }
}

#[test]
#[ignore = "requires clang"]
fn generic_programs_pass_mock_service_behaviour() {
    for (flag, name) in STAGES {
        for (optimization, sanitizer) in CONFIGS {
            assert_compiles_and_runs(
                (flag, name),
                TEST_PROGRAM_SOURCES,
                "test_program",
                optimization,
                *sanitizer,
                "program behavior tests passed",
                DEFAULT_CARD_ROOT,
            );
        }
    }
}

/// A different card slot and multi-component directory must affect every
/// loader file path, while the program API still refuses other card roots.
#[test]
#[ignore = "requires clang"]
fn configured_card_root_preserves_loading_and_file_boundaries() {
    let maximum_root = format!("A:\\{}\\", "X".repeat(60));
    assert_eq!(maximum_root.len(), 64);
    for card_root in [ALTERNATE_CARD_ROOT, maximum_root.as_str()] {
        for (optimization, sanitizer) in CONFIGS {
            for (sources, binary_name, output) in [
                (TEST_CORE_SOURCES, "test_core", "core behavior tests passed"),
                (
                    TEST_PROGRAM_SOURCES,
                    "test_program",
                    "program behavior tests passed",
                ),
            ] {
                assert_compiles_and_runs(
                    ("-DNLR_STAGE_EXEC", "exec-alternate-root"),
                    sources,
                    binary_name,
                    optimization,
                    *sanitizer,
                    output,
                    card_root,
                );
            }
        }
    }
}

/// The loader's own state on an ordinary card and the firmware-code
/// channel, each driven on its own: no loader, no page, no worker, so
/// every refusal is visible by itself. Both stages are built, because the
/// code channel only reaches the camera in the execution build.
#[test]
#[ignore = "requires clang"]
fn store_and_code_channel_pass_mock_service_behaviour() {
    for (flag, name) in [("", "hook-only"), ("-DNLR_STAGE_EXEC", "exec")] {
        for (optimization, sanitizer) in CONFIGS {
            assert_compiles_and_runs(
                (flag, name),
                &["file_store.c", "hook.c", "manifest.c", "test_store.c"],
                "test_store",
                optimization,
                *sanitizer,
                "store and code channel tests passed",
                DEFAULT_CARD_ROOT,
            );
        }
    }
}

/// ABI 7's pure parts on their own: routes, the event ring, scans into
/// events, timers and the settings store reader (core/platform.c).
#[test]
#[ignore = "requires clang"]
fn platform_routes_events_timers_and_store() {
    for (optimization, sanitizer) in CONFIGS {
        assert_compiles_and_runs(
            ("", "platform"),
            &["platform.c", "test_platform.c"],
            "test_platform",
            optimization,
            *sanitizer,
            "platform behavior tests passed",
            DEFAULT_CARD_ROOT,
        );
    }
}

/// The loader's own log (core/journal.c): the formatter, the ring and its
/// lost lines, the file appended across boots and never truncated mid-boot.
#[test]
#[ignore = "requires clang"]
fn journal_lines_reach_the_file_in_order() {
    for (optimization, sanitizer) in CONFIGS {
        assert_compiles_and_runs(
            ("", "journal"),
            &["journal.c", "test_journal.c"],
            "test_journal",
            optimization,
            *sanitizer,
            "journal behavior tests passed",
            DEFAULT_CARD_ROOT,
        );
    }
}

/// Programs that describe themselves (NPLD v3): the
/// MANIFEST line a description stands for and the memory it declares.
#[test]
#[ignore = "requires clang"]
fn program_metadata_makes_manifest_lines_the_parser_takes() {
    for (optimization, sanitizer) in CONFIGS {
        assert_compiles_and_runs(
            ("", "metadata"),
            &["manifest.c", "test_meta.c"],
            "test_meta",
            optimization,
            *sanitizer,
            "metadata behavior tests passed",
            DEFAULT_CARD_ROOT,
        );
    }
}

/// Dev firmware's stage 0 (core/stage0.c): the checks a CORE.NLC must pass
/// before anything is allocated for it, and what the start mark says.
#[test]
#[ignore = "requires clang"]
fn stage0_checks_the_core_before_anything_is_allocated() {
    for (optimization, sanitizer) in CONFIGS {
        assert_compiles_and_runs(
            ("-DNLR_STAGE0_HOST_TEST", "stage0"),
            &["stage0.c", "manifest.c", "test_stage0.c"],
            "test_stage0",
            optimization,
            *sanitizer,
            "stage 0 behavior tests passed",
            DEFAULT_CARD_ROOT,
        );
    }
}

/// The executor's flat layout, which runs the dev core from one region.
#[test]
#[ignore = "requires clang"]
fn flat_layout_runs_a_core_from_one_region() {
    for (optimization, sanitizer) in CONFIGS {
        assert_compiles_and_runs(
            ("-DNLR_STAGE_EXEC", "flat"),
            &["exec.c", "program_context.S", "test_flat.c"],
            "test_flat",
            optimization,
            *sanitizer,
            "flat layout tests passed",
            DEFAULT_CARD_ROOT,
        );
    }
}

/// Isolated portable resource adapter: no worker assembly or firmware.
#[test]
fn resource_clones_preserve_native_layout_and_boot_ownership() {
    for (optimization, sanitizer) in CONFIGS {
        assert_compiles_and_runs(
            ("", "resources"),
            &["resource.c", "test_resource.c"],
            "test_resource",
            optimization,
            *sanitizer,
            "resource behavior tests passed",
            DEFAULT_CARD_ROOT,
        );
    }
}

/// The prefill trampoline runs natively on the arm64 host: argument
/// preservation across the body call, the body's descriptor and font writes,
/// and the return through the restored link register. The injected struct is
/// placed mid-page (see core/test_prefill.c) so a page-base-only address
/// formation would be caught instead of masked.
#[test]
#[ignore = "requires clang"]
fn prefill_trampoline_preserves_arguments_and_returns() {
    let core_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("test_prefill");
    let include = directory.path().join("include/nlr");
    fs::create_dir_all(&include).unwrap();
    fs::write(include.join("card_config.h"),
        "#define NLR_CARD_ROOT \"?:\\\\NLOADER\\\\\"\n#define NLR_HAS_NATIVE_CARD 0\n#define NLR_HAS_BITMAP 0\n#define NLR_HAS_PAINT 0\n#define NLR_HAS_PRIVATE_TEXT 0\n").unwrap();
    let sources: Vec<_> = [
        "menu_prefill_trampoline.S",
        "menu_prefill.c",
        "test_prefill.c",
    ]
    .iter()
    .map(|name| core_root.join(name))
    .collect();
    let result = Command::new("clang")
        .arg("-I")
        .arg(directory.path().join("include"))
        .arg("-I")
        .arg(core_root.join("include"))
        .args(["-Wall", "-Wextra", "-Werror", "-O0"])
        .args(&sources)
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("clang should be available");
    assert!(
        result.status.success(),
        "prefill test compilation failed:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let run = Command::new(&binary).output().unwrap();
    assert!(
        run.status.success(),
        "prefill trampoline tests failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("prefill trampoline tests passed"),
        "unexpected test output: {}",
        String::from_utf8_lossy(&run.stdout)
    );
}

/// Private text uses its own explicit build option in both static and dynamic
/// menu stages; neutral legacy tests cannot prove these owner/lifetime paths.
#[test]
#[ignore = "requires clang and sanitizer runtime"]
fn private_text_namespace_owner_and_lifetime() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
    let sources = [
        "exec.c",
        "api.c",
        "platform.c",
        "journal.c",
        "time.c",
        "input.c",
        "hook.c",
        "file_store.c",
        "program_context.S",
        "load.c",
        "manifest.c",
        "runtime.c",
        "resource.c",
        "menu_page.c",
        "menu_prefill.c",
        "text.c",
        "test_text.c",
    ];
    for stage in ["NLR_STAGE_HOOK_ONLY", "NLR_STAGE_PAGE"] {
        for (optimization, sanitizer) in [("-O0", false), ("-O1", true), ("-Os", false)] {
            let directory = tempfile::tempdir().unwrap();
            let include = directory.path().join("include/nlr");
            fs::create_dir_all(&include).unwrap();
            fs::write(include.join("card_config.h"), "#define NLR_CARD_ROOT \"A:\\\\NLOADER\\\\\"\n#define NLR_HAS_NATIVE_CARD 0\n#define NLR_HAS_BITMAP 0\n#define NLR_HAS_PAINT 0\n#define NLR_HAS_PRIVATE_TEXT 1\n").unwrap();
            let binary = directory.path().join("test_text");
            let mut command = Command::new("clang");
            command
                .arg("-I")
                .arg(directory.path().join("include"))
                .arg("-I")
                .arg(core.join("include"))
                .arg("-I")
                .arg(core.join("../sdk"))
                .args(["-Wall", "-Wextra", "-Werror", optimization])
                .arg(format!("-D{stage}"));
            if sanitizer {
                command.arg("-fsanitize=address,undefined");
            }
            let compile = command
                .args(sources.iter().map(|n| core.join(n)))
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                compile.status.success(),
                "private text {stage}/{optimization} compilation failed: {}",
                String::from_utf8_lossy(&compile.stderr)
            );
            let run = Command::new(&binary).output().unwrap();
            assert!(
                run.status.success(),
                "private text {stage}/{optimization} failed: {} {}",
                String::from_utf8_lossy(&run.stdout),
                String::from_utf8_lossy(&run.stderr)
            );
            assert!(
                String::from_utf8_lossy(&run.stdout).contains("private text"),
                "unexpected private text result"
            );
        }
    }
}
