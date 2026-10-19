# NLoader Architecture and Implementation Plan

NLoader is a firmware extension framework for Nikon EXPEED7 cameras. It repacks an official firmware image to install a persistent loader, adds native Setup menu entries, and loads applications and extensions from a storage card.

This document defines the architecture, implementation order, and acceptance criteria. It is a plan, not a claim that every capability is implemented or verified. Host tests, offline firmware checks, emulator sessions, and physical-camera results are separate evidence levels. A result applies only to the model, firmware version, build, and environment actually checked.

## 1. Goals and Scope

### 1.1 Target order

| Target | Role |
|---|---|
| Z8 C3.11 | First target for the build system, menus, loading, program execution, and DOOM |
| Z6III 2.00 | Migration target after the corresponding Z8 acceptance gates |
| Z9, Zf, Z5II, Z50II | Additional EXPEED7 targets requiring independent profiles and validation |

Older EXPEED generations are out of scope. Listing a target does not imply support. Addresses, layouts, and results from another camera or firmware revision cannot establish compatibility.

### 1.2 Product behavior

- Add **Apps** as the first Setup row and **NLoader** as the last. Preserve every original row, including hidden rows, its behavior, and relative order. Keep the official Firmware version page working.
- Use native menu records, fonts, input decoding, and drawing services where verified equivalents exist.
- During the load-only stage, list programs and validate files without executing them or enabling boot-time loading.
- At runtime, allow one foreground application alongside resident resource extensions and services. Use `hello` for minimal application acceptance and DOOM for full application acceptance.
- Initialize resource extensions in the saved order. Enabling, disabling, or reordering them affects the next verified restart, not the current session.
- Support a shell role for a replacement interface with explicit screen and input ownership.
- Report unsupported capabilities and failures explicitly. Missing fields or services are not replaced with guessed addresses or zero values.

The framework does not promise whole-camera isolation from unreviewed native programs, instant unloading of resident extensions, general dependency resolution, or automatic resolution of arbitrary extension interactions. Exclusive platform resources do require ownership checks; those checks are not a general compatibility guarantee.

### 1.3 Recovery limits

Reinstalling an accepted official firmware package can remove the loader while the official update process remains accessible. Same-version reinstall, downgrade rules, and version conflicts require physical-camera checks.

This is not a recovery guarantee for a camera that cannot boot or for interrupted flashing. `SAFE_MODE` and the boot escape prevent new loading; neither can undo already published resources or repair a failure before its check runs. Severe program faults may require a manual restart.

## 2. Architecture

### 2.1 Implementation boundaries

| Component | Responsibility |
|---|---|
| `core/` | Shared camera-side C loader, minimal necessary assembly, lifecycle and ownership rules |
| Profiles | Per-model and per-firmware addresses, layouts, original bytes, mappings, and capability declarations |
| ABI adapters | Calling-convention and service-family differences, without embedded firmware addresses |
| Host Rust workspace | Profile validation, firmware containers, compilation, linking, program packaging, and read-only device tools |
| Camera program SDK | C-compatible entry points, append-only API table, headers, and examples |
| Storage card | Programs, optional catalog overrides, settings, safety flags, and logs |

The only host workspace is `tool/nloader/`. The host SDK is distinct from the camera program SDK. Rust invokes the C/assembly toolchain; the camera loader is not rewritten in Rust. The production host workflow has no Python runtime dependency. Isolated emulator tooling may use Python.

### 2.2 Host crates

| Crate | Responsibility | Workspace dependencies |
|---|---|---|
| `nloader-profile` | Shared configuration types, schema and capability checks, verification against actual firmware bytes | None |
| `nloader-camera` | Enumeration, identity, transport, permitted reads, session cleanup | None |
| `nloader-profile-gen` | Read-only collection, snapshot replay, image comparison, missing-field reports; does not generate profiles | `camera`, `profile`, `firmware` |
| `nloader-firmware` | Containers, key files, recovery of supported key material, unpacking, checksums, repacking | None |
| `nloader-build` | Bindings, native menu records, compilation, restricted XIP linking, patches, program packaging | `profile`, `firmware` |
| `nloader-sdk` | Public host-library entry point combining the workspace capabilities | `camera`, `profile`, `profile-gen`, `firmware`, `build` |
| `nloader-cli` | `nloader` arguments and result presentation through the SDK | `sdk` |

Dependency names in the last column omit `nloader-`. Dependencies remain one-way. Libraries do not depend on the CLI. Container handling stays in `nloader-firmware`; collection and build tools share `nloader-profile` rather than defining separate configuration formats.

## 3. Profiles and Model Adaptation

### 3.1 Binding and validation

Profiles are maintained manually and selected at build time, not parsed on the camera. `profiles/schema.md` defines the configuration format. The first profile target is `profiles/z8/v3_11.toml`; later migration uses `profiles/z6iii/v2_00.toml`. Local profiles are not distributed as generated discoveries.

- Inject firmware services through `const struct nlr_services *`. Core must not contain model-specific firmware address constants.
- Keep file offsets, execution addresses, and temporary runtime-object addresses distinct.
- Put addresses and layouts in the profile; put calling conventions and service behavior in adapters.
- Record field rationale in profile comments. Comments are not validation evidence.
- Validate the official package and module identity, fingerprints, segment mappings, original patch bytes, original menu structures, version fields, alignment, and the complete reserved region.
- Required missing, conflicting, unsupported, or out-of-range fields reject the build. An empty optional section does not advertise support.
- Verify semantic relationships as well as byte matches: pointers must target the expected in-module arrays and counts must equal the independently known stock counts.

```sh
nloader profile validate --profile profiles/z8/v3_11.toml \
    --mode <mode> --firmware <stock-firmware> --key-file <local-key-file>
```

`build` repeats the same validation against actual input bytes. Reports and snapshots are not build credentials. Matching bytes do not prove call safety, ownership, update acceptance, or physical-camera operation.

### 3.2 Read-only collection

`profile discover` collects identity and missing-field reports. `profile discover --memory` reads only supported ranges under a fixed plan, checks repeated reads, and compares them with the official image. `profile replay` operates on saved snapshots without connecting to a camera.

Collection produces reports and snapshots, never a profile. It records mode changes and cleanup, reports unreadable ranges explicitly, and does not flash firmware, install helpers, write memory, or call unverified services to discover addresses. Live registry or heap traversal remains unavailable until readable mappings and object-retention rules are independently established. Runtime-layout checks use independently compiled C layouts and independently derived expectations; offline success does not replace a live trace.

### 3.3 New firmware workflow

1. Obtain the matching official package and verify container and module identity.
2. Analyze mappings, reserved space, services, menu records, task configuration, and original patch values.
3. Populate the profile with field rationale.
4. Validate it against the image, then complete host and package-level checks.
5. Run the applicable diagnostic ladder on the exact camera and firmware.
6. Associate observations with that profile and candidate build; retain read-only collection separately.

A firmware update repeats these checks. Old profiles and other models are analysis leads, not automatically supported configurations.

## 4. Menus and Load-Only Behavior

### 4.1 XIP and runtime state

The loader executes in place from reserved space in the firmware's `eg` module. The linker rejects writable static data, `.bss`, and COMMON storage. Compilation alone does not establish successful linking or operation.

Allocate runtime state through verified firmware services, register it, and rediscover it on re-entry. Initialization must be single-owner. Fixed RAM ranges require separate ownership, capacity, and lifetime verification.

### 4.2 Native menu integration

Generate native window, page, item, element, and event records on the host. Preserve complete original arrays rather than rebuilding unmodeled stock behavior from a few fields. Only records verified read-only may remain in XIP storage.

Use loader-owned text identifiers, descriptors, and buffers while reusing verified native font and text handling. Route only exact owned identifiers; all other reads and writes retain original behavior. An apparently unused stock text slot is not an ownership guarantee. Update GUI objects only from the confirmed GUI task, report preparation failure, and retain published buffers for the entire boot.

The program list supports up to 64 entries, native scrolling and navigation, details, and explicit failure reasons. Check actual screenshots for full names, short list status, complete detail errors, fixed-row prompts, and both short and full-capacity lists. String-buffer capacity does not prove single-line visibility. Preserve native short-list layout behavior.

The Apps entry opens compatible foreground programs directly. NLoader provides the master switch, plugin settings, details, About, and recovery when applicable. Keep the page stack in loader-owned RAM and reuse verified native windows. Program-published lists must appear even when published after the initial start action; their visibility must not depend on a timing race.

### 4.3 Manual load sequence

1. Check `<storage.root>SAFE_MODE` before other loader file operations.
2. Read the catalog; report no card, missing required input, parse failures, and read errors.
3. Check API, model, firmware, and program-kind compatibility.
4. Display the list; OK opens details and requests validation of the selected program.
5. Read the header and file, checking length, bounds, entry alignment, and CRC.
6. Display the result. Only execution modes may invoke an entry point.

Load-only mode checks one program at a time and never runs card code. Its direct menu-task reads require physical checks for blocking, absent cards, swaps, and failures. The worker may exist for runtime discovery without being used for load-only execution.

Opening a resource extension edits next-boot settings; it does not initialize it immediately. Re-entering a page must not initialize an extension twice. Display and launch use one stable, validated kind; temporary headers reread by the worker must not change the displayed action or invocation convention.

### 4.4 Disable behavior

A present `SAFE_MODE`, an asserted boot escape, or an unreliable disable-state read prevents new automatic execution. Turning the master switch off affects the next boot and hides Apps then; already resident resources remain until a verified restart. Recovery paths retain stock behavior.

## 5. Program Execution and Lifecycle

### 5.1 Program kinds

| Kind | Start | Lifetime and ownership |
|---|---|---|
| Foreground (`foreground` / `app`) | User selection | One at a time; cleanup only after execution and outstanding references stop |
| Resource extension (`resource_extension` / `extension`) | Saved boot order | Initialization returns, but published code, data, and callbacks remain resident |
| `service` | Saved boot order | Resident code and owned tasks, queues, timers, files, or devices |
| `shell` | Boot selection or explicit open | Foreground replacement interface with exclusive screen and routed input |

The names above distinguish lifecycle roles; encodings depend on the validated file version. Each file declares one kind. The catalog and executable declaration must agree whenever both are present. Missing, unknown, conflicting, or unsupported kinds reject execution. Do not infer kind from a name, directory, or cached list. Version-1 files are load diagnostics only.

```c
int32_t nlr_app_main(const struct nlr_api *api);
int32_t nlr_extension_init(const struct nlr_api *api);
```

A foreground return or `api->exit(code)` ends the application and enters cleanup; `exit` does not return to it. Extension return zero means initialization completed, not that its memory can be freed. Nonzero return stops later extensions and may mean partial publication. Report that distinction rather than claiming rollback. A timeout, missing return, or severe fault never proves safe release.

### 5.2 Execution memory

Programs use position-independent code and receive the API pointer in `x0`. Begin execution acceptance with a fixed 16-byte return probe:

`audit pages → prepare RW → clean D-cache → set RX → invalidate I-cache → call → verify response`

Preparation and execution run on the verified pinned worker, not the menu task. `prepare-only` exercises preparation and cleanup without calling the entry. Use a distinct challenge per probe run and verify the full 64-bit response.

Keep executable image and writable data/BSS in separately owned blocks. For the Z8 mapping family, permissions apply to a complete 2 MiB block: do not split a live mapping or make writable code executable. Account separately for image, data, BSS, temporary input, one foreground application, and all resident extensions. The bounded temporary input path allows at most 5 MiB of relocation, image, and initialized data; it does not enlarge execution-block or coexistence limits.

Test count limits, budget refusal, actual allocation failure, and release/permission-restoration failure separately. A smaller successful program does not prove a larger allocation. Failed cleanup retains actual ownership and prevents unsafe reuse.

### 5.3 Foreground exit

Reserve a global exit combination that does not conflict with system or shooting controls, and do not deliver it to programs. Physical input interception runs on the native input task; drawing and page restoration remain on the GUI task.

Normal exit requires the program to stop, all in-flight calls to cease referencing its resources, foreground resources to be reclaimed safely, and the list to be restored. Resident extensions remain active. Verify ordinary busy-loop exit independently, including input-edge handling, task termination/reactivation when required, SDK-call quiescence, return to the list, and another launch. Independent tasks do not provide whole-camera fault isolation.

### 5.4 Settings, autoload, and recovery

Newly discovered extensions default to disabled. Save an ordered, duplicate-free list; do not treat catalog order as execution permission or silently reorder dependencies. Show current-boot state separately from next-boot settings.

Autoload starts only after the card and target resources are ready, without requiring the user to open NLoader:

1. Confirm disable and escape conditions.
2. If a previous pass is still pending, pause all autoload.
3. Read and validate the saved list and current program declarations.
4. Reliably commit pending state before entering the first extension.
5. Initialize serially in saved order, rechecking each file.
6. Wait for GUI-side publication to finish before advancing an extension that queues native resource changes.
7. Clear pending only after every initialization and publication succeeds.

Worker-side registration queues owned requests; a natural GUI checkpoint publishes them only when the target page is quiescent. A queued request is not a completed publication. Failure, timeout, unconsumed publication, or uncertain save stops the pass and preserves the marker and possibly referenced memory. Completion must naturally wake the GUI task rather than depend on a page visit.

Explicit recovery only arms a later verified restart. It does not retry the current pass, unload residents, or replay partially effective extensions. Reject recovery while the worker, pending publication, uncertain storage, or failed cleanup still prevents safe transition. A valid restart must actually remove old references and reconstruct stock resource state; toggling the power switch is not assumed sufficient.

### 5.5 Drawing and input

Use verified native drawing entries from the correct GUI context, with explicit surface ownership and source lifetime. A worker may stage bounded text or pixels in owned RAM, but must not call arbitrary native drawing routines. Keep text refresh, pixel submission, page drawing, exclusive screen ownership, and full-screen operation as distinct capabilities. Return `-ENOSYS` when the required service is unsupported.

The SDK surface is 40 bytes and uses packed Y0/Y1/U/V for each pixel pair plus a separate per-pixel A8 plane. Acquire, present, and release are distinct operations; release does not implicitly submit a frame. Verify every actual native row object, not just declared capacity, on drawing and restoration.

Basic key events are `{ uint32_t key; uint32_t down; }`: one logical bit and a press/release value. Polling returns one event, no event, or a negative error without modifying output on failure or no event. The raw state represents currently held logical bits. Queue overflow reports lost history; consumers rebuild state from the current snapshot. Inherited held keys must not become synthetic presses on launch.

Basic input is available only to the confirmed current foreground owner and worker. Losing page ownership drops stale held state and reports busy. Preserve the stock callback and restore forwarded scan fields. Physical control direction, release, overflow, exit, re-entry, and routing require explicit checks.

### 5.6 Platform API scope

The camera API remains C-compatible and append-only. Reject incompatible experimental ABI 3 programs rather than silently treating them as compatible. Preserve supported earlier prefixes; ABI 6 adds native widgets, ABI 7 adds lifecycle/input/screen/property services, and ABI 8 adds named firmware/device access and event posting. `sdk/nlr.h` is the exact API contract.

| Family | Required scope and limits |
|---|---|
| A: Lifecycle | Owned tasks, one event queue per program, timers, declared memory reservations, card events; short work on firmware callbacks |
| B: Input | Per-control camera/program/both routing for verified buttons, joystick, dials, touch, and eye events; power remains with the camera; shared shutter behavior for shells |
| C: Screen | Rear/EVF claims only where verified, exclusive shell ownership, clean release and stock redraw, native rows, keyboard and caution dialogs; refuse an unsafe page-app claim |
| D: Properties | Named metadata, read and watch; writes only through a verified native settings path including GUI and derived-state updates, never a bare unverified store setter |
| E: Firmware points | Named fingerprinted hooks, functions, and typed tables; checked original bytes/CRC, ownership, restoration, and memory-location restrictions |
| F: Devices | Narrow named device access through native bus locking and an independently owned client identity |

Programs use names rather than model addresses. Unsupported controls, EVF geometry, property writes, hooks, and devices are not advertised. Repack-only tables reject runtime writes. Native callbacks copy bounded data or post events; longer work belongs on program tasks. Resource restoration waits for execution and references to stop. Raw code access, where exposed, is unstable and is not a release-program compatibility promise.

## 6. Card Storage and Program Formats

### 6.1 Root and files

The profile explicitly declares `[storage].root`, for example `B:\NLOADER\` for a physical-card configuration or `A:\NLOADER\` for an isolated emulator configuration. Accept only validated A:/B: roots, at most 64 bytes, with permitted ASCII directory components and a trailing backslash. Do not guess a default drive, search another slot, or change the drive secretly at runtime.

| Path under the root | Purpose |
|---|---|
| `SAFE_MODE` | Prevent new loading |
| `MANIFEST` | Catalog for older files and optional overrides for self-describing files |
| `APPS\*.NLB` | Program files |
| `STATE.NLS` | Native-card journal for enabled order, pending state, and supported boot records |
| `ENABLED`, `AUTOLOAD_PENDING` | Legacy migration input where applicable |
| `BOOT`, `BOOTRUN`, `MASTER` | Boot/master inputs or legacy records where supported; do not assume native journal durability for ordinary files |
| `LOGS\` | Logs |
| `CORE.NLC`, `CORERUN` | Development-core image and guard, development firmware only |

Derive every loader path from this root. SDK relative paths stay within it; absolute paths must resolve inside the same root. Reject traversal and cross-card access. Changing the root requires rebuilding and preparing the matching card layout.

### 6.2 Catalog and discovery

The legacy line-based MANIFEST accepts at most 64 entries, IDs up to 32 bytes, and printable ASCII display names up to 24 characters. Unsupported multilingual legacy names reject explicitly; English results do not establish another locale's behavior.

```text
# id | kind | name | file | min_abi | optional-model/firmware
menu_extension | resource_extension | Menu extension | APPS/MENU.NLB | 2 | z8/3.11
hello | foreground | Hello | APPS/HELLO.NLB | 2 | z8/3.11
```

Check kind, API, model, firmware, duplicates, paths, and syntax. The executable header owns CRC information; do not maintain a second checksum in the catalog. Legacy ENABLED is bounded ASCII text, one ID per nonempty line, accepting LF/CRLF and a missing final newline, without BOM, comments, or implicit trimming. Reject unknown, duplicate, or foreground IDs. Its limit is 64 entries and 4096 input bytes.

Version-3 self-describing files carry validated metadata: identity, kind, localized name/description, version, author, license, API/target requirements, memory, resource uses, settings, and optional icon. Build it from one program declaration rather than maintaining duplicate metadata. Keep version-2 programs usable with an explicit MANIFEST.

Discover card files in deterministic filename order and merge with bundle entries. Explicit catalog overrides take precedence; a card program overrides the same bundle ID. Duplicate programs do not both execute. `#!hide <id>` is case-insensitive for the ID and hides it from every source, launch, and recheck; hidden saved extensions are skipped. Unknown or malformed `#!` directives reject the catalog with a line number. Ordinary `#` comments remain comments. Hiding is a display/discovery override, not a security boundary.

### 6.3 Native-card persistence

Use one card identity rule on either slot: observed mount epoch, volume index, and exact media entry. Require mounted exFAT and a valid stock slot; volume index need not equal slot number. Invalidate identity on mount, unmount, or format. Do not infer SD identity from an NVMe object layout.

A native save succeeds only after the actual reply, filesystem sync, the stock per-slot device-flush path, and independent read-back all confirm the record. A successful stock no-op flush is not a claim of additional physical SD power-loss guarantees. Submitted requests with uncertain completion stop loading and further writes; keep their referenced memory. Do not fabricate success, resubmit blindly, or delete the journal to continue.

`STATE.NLS` is exactly 8192 bytes: two complete 4096-byte records with `NLRSTAT1`, format, size, increasing generation, pending flag, enabled count/IDs, whole-record IEEE CRC32, and zero reserved bytes. Choose the newer valid record. Pause on checked unknown formats, illegal semantics, generation exhaustion, equal-generation conflicts, unsupported layouts, or unreliable reads. Legacy settings migrate only when the new journal is reliably absent; never merge old and new authorities.

Format 2 adds `boot_mark` at `0x24`, signed `boot_result` at `0x28`, and a zero-padded 33-byte `boot_id` at `0x880`. Marks are none, run, ok, skipped, or failed. Only failed carries a nonzero result; a nonempty valid ID is required for any nonzero mark. Format-1 records remain readable as no boot record; normal subsequent commits migrate to format 2. Other commits preserve the boot record. Master/boot-selection consolidation requires an explicitly versioned migration, not an assumption that ordinary files already have journal durability.

Native request ownership must not depend on the caller being scheduled again: a loader card task submits non-worker tickets, collects replies, and releases the request; the worker submits its own requests. Menu/firmware-task queue waits are bounded at 250 ms and retried on a later checkpoint; loader-task queue waits are bounded at 3 seconds. Never make the filesystem task wait on its own card service.

Native reads own complete cache lines. Clean and invalidate after transfer, preserve partial-sector CPU copies, confirm seek positions, and use aligned low-level starts rather than relying on an emulator's missing cache model. Preserve caller-visible bytes, positions, and EOF semantics. A CRC failure remains a visible failed attempt, not a silent nonresponse.

### 6.4 Boot programs

After a successful autoload pass, resolve BOOT and validate the program. Confirm `run(id)` before queuing it. A previous unfinished run causes one skipped boot with a saved skipped result. A pre-entry rejection or error return records failure; normal completion, or continued operation after the defined 10-second observation interval on the program's worker, records success. At most one result is committed per boot.

Pending state must be clear for boot-record transitions. Only the matching run may complete; unrelated saves preserve it. Failed or uncertain saves prevent launch. `SAFE_MODE`, boot-time DISP, a paused pass, or a failed pass prevents BOOT reads and boot-record writes. Sample the escape before any file access and only after the input carrier is installed. Missing trustworthy boot state never authorizes execution.

### 6.5 Executable headers

All versions use magic `NPLD`. Reject inconsistent file sizes, unsupported flags, bad CRC, invalid boundaries, and an entry outside the image or not aligned to four bytes.

| Version | Contract |
|---|---|
| 1 | 32-byte load-diagnostic header; no execution; BSS must be zero |
| 2 diagnostic subset | 48-byte header, flags 1, foreground kind, fixed 16-byte probe, no data/BSS/relocations; exact instruction identity and dedicated challenge ABI |
| 2 general | 64-byte header, flags 0, explicit kind, image/data/BSS limits and relocation checks |
| 3 | Self-describing metadata covered by integrity checks, with the supported executable model |

The general v2 file order is header, relocation table, image, initialized data. Data length is derived from the complete file length; reserved words remain zero. Verify image, data, and relocation CRCs independently. The fixed 12-byte relocation entries contain offset, target, and kind: image ADRP-to-data, data ABS64-to-code, or data ABS64-to-data/BSS. Validate instruction form, segment-specific bounds and alignment, target exclusion of one-past-end, and overlapping writes within each destination segment. Reject unknown relocation kinds. Preserve original entries for independent checking.

Before every execution, reread current declarations and the file on the worker. Recheck identity, path, kind, and compatibility; list caches cannot authorize a changed file.

## 7. Build, Distribution, and Verification

### 7.1 Build pipeline

```sh
nloader build --profile <profile> --key-file <local-key-file> --mode <mode>
nloader unpack --firmware <stock-package> --key-file <local-key-file> --out <new-directory>
nloader pack --input <unpacked-directory> --key-file <local-key-file> --out <new-package>
```

1. Validate the profile against the exact official input.
2. Generate service bindings, native menu records, and a patch manifest.
3. Cross-compile core, necessary assembly, and bindings.
4. Perform restricted XIP linking; reject writable static storage and unsupported relocations.
5. Recheck original bytes and blank regions, then apply only approved edits.
6. Recompute the applicable module, package, and header integrity values.
7. Reopen and unpack the result, verifying every intended edit and rejecting edits outside the approved ranges.
8. Publish the package and manifest only after verification.

The patch manifest records intent, not independent proof. Construct expected bytes independently and check the final image without using the manifest as the expected result. Two builds from identical inputs must be byte-identical. Refuse existing output paths; failure must not leave a success-looking final artifact or overwrite stock input.

### 7.2 Containers and keys

Support `legacy-xor` for Z8/Z9 and `aes-ctr` for the applicable newer targets. AES container availability does not establish loader support on that body.

Keep real material in ignored local files, such as `tool/nloader/keys/local.json`, never in source, profiles, payloads, manifests, or logs. Missing, malformed, mismatched, or incomplete material fails explicitly; no built-in fallback. Shared container material and model-specific K8 are separate. AES key/IV availability alone cannot regenerate the header digest; permit only explicitly marked incomplete-digest unpacking where the input fingerprint and internal CRCs pass, and reject repacking without K8.

Legacy XOR recovery requires complete shared-table coverage or an explicitly verified import; a single official package need not cover all indices. Verify directory-relative offsets, names, payload lengths including CRC trailers, unique module selection, and equal-length replacements. Reseal module CRCs, package CRC, then `SHA1(decrypted body including trailer || K8)`, preserving unrelated header/trailer fields.

Unmodified unpack/pack must reproduce the input byte-for-byte. Also verify a genuinely modified package end to end; an unchanged round trip alone is insufficient. An unchanged aggregate CRC after repairing module CRCs is not itself a failure. Official firmware and keys are not distributed with the repository.

### 7.3 Release and development firmware

Release firmware embeds the loader and a verified, read-only program bundle with defaults. Card additions may override bundle programs. Validate blank-space placement and any extended boot-copy boundaries independently; prove the added DRAM range remains unused, assess boot cost, and check standby/resume. No-card bundled execution must not depend on a nonexistent persistent crash record; retain the boot escape.

Development firmware uses a minimal stage-0 loader for `CORE.NLC`, with independent version/integrity checks, owned executable memory, a failed-core guard, and the boot escape. Missing, corrupt, or failed cores must leave stock operation intact. Development card-loaded code is not the release trust model. Both variants require their own menu and recovery acceptance.

Loaded programs and required assets remain resident so card removal does not invalidate executing memory. File operations fail explicitly when the configured card is absent. Report card-in/out events. Keep logs in bounded memory until safe writes are available; unsaved settings without a card are session-only. Persistent internal-flash installation and DRAM cache across standby remain separate research tasks, not assumed capabilities.

### 7.4 Diagnostic and evidence levels

Use the ordered modes `marker`, `hook-only`, `page`, `load-only`, `prepare-only`, and `exec`. Record expected state and display for the exact target. A failed gate does not authorize the next one.

| Level | Required evidence |
|---|---|
| Host logic | Rust tests and host-compiled core tests for parsing, boundaries, transitions, ownership, and failures |
| Profile | Actual stock-byte and semantic checks; rejection of wrong identity, address, fingerprint, original bytes, and bounds |
| Package | Stock round trip, modified-package resealing, deterministic output, and independent final-image checks |
| QEMU | Exact emulator/firmware/card identities, native UI actions, actual screenshots, read-only observations, and stopped-card results |
| Physical camera | Applicable diagnostic ladder, storage/cache behavior, display/input, lifecycle, and update/restart behavior |

Ordinary tests must not automatically connect to a real camera. Physical flashing is performed by the user. Before and after flashing, read permitted patch sites and adjacent slots, compare bytes, and report unreadable ranges as missing evidence. Store local traces and screenshots under ignored `build/`.

### 7.5 QEMU requirements

Use only the pinned repository `z8-qemu/` submodule via `tests/qemu/run.py`. Prepare a fresh full 8 GiB MBR/exFAT image with `tests/qemu/prepare_card.py`; the native DesignWare PCIe/NVMe path exposes A:. This is not SD or physical-card validation.

- Give every session its own image and explicit control socket. Unmount host access before launch; never mount or modify the image on the host while the guest uses it.
- Keep stock input validation enabled. Independently verify a candidate EG and specify it using `--firmware` and `--firmware-sha256`; default stock input does not test a modified build.
- Use real native menu and drawing paths, not host file-request/card-write substitutes, timing substitutes, or host-rendered success images.
- Save actual screenshots and per-case results. Check original PNG RGB and crops if a display tool introduces artifacts. Batch inputs within the upstream eight-item queue.
- Interrupt tests only at independently verified actual instructions, record a real hit and observed state, and inspect the stopped card. A missed stop or failed observation is not a pass.
- Restart from the card image actually produced by the preceding stopped session, not a clean template. Decode journal records independently, including CRC, generation, IDs, pending, and boot state.
- Check prepare-only prompts and nonexecution separately from successful exec. Read-stage rejection is not a save-failure test; a host-full image with free guest clusters is not evidence of uncertain persistence.
- Terminate owned QEMU processes immediately after use and confirm `owned_qemu_stopped=true`. Never use broad process killing that affects other sessions.

QEMU menu sessions, process restart, and QMP stop do not prove physical cold start, power loss, cache coherence, real SD/CFexpress behavior, standby, or camera reboot semantics.

## 8. SDK and Example Acceptance

The camera SDK supplies headers, C-compatible startup, program packaging, and example declarations. API evolution appends fields without changing prior supported semantics. Files stay within the profile root; unsupported operations report failure. Millisecond time is a wrapping 32-bit boot-relative counter, not wall-clock time. Waiting yields in bounded intervals and honors exit; a failed void wait cannot pretend success.

| Example or case | Required behavior |
|---|---|
| Return probe | Actual prepared entry, distinct challenges, complete response check, permission restoration, refusal of altered probe instructions |
| `hello` | Independent foreground file; text and file access; normal return, error return, explicit exit, cleanup, and relaunch |
| `menu_extension` | Independent extension file; its own published test row survives init return, page exit/re-entry, and foreground exit without duplicate init |
| Enable/order | Current session unchanged after save; verified restart applies the saved order and removes disabled effects |
| Partial failure | Earlier extension remains, failing extension may be partially effective, later entries do not run, pending stays, next boot pauses |
| Type refusal | Missing/unknown/conflicting kind, unsupported header, wrong entry selection, and foreground-in-extension-list all reject before entry |
| Nonreturning program | Ordinary busy-loop escape checked separately; no release without confirmed stop; extension timeout is not successful init |
| DOOM | Real engine, WAD reads, actual controls and releases, visible frames, performance/memory budget, playable operation, normal exit and repeat launch with extensions preserved |

Successful file reads, a visible bitmap, a frame counter, or an isolated emulator program do not independently satisfy DOOM, full-screen, OpenGL, or physical-camera acceptance.

## 9. Implementation Stages and Acceptance

M0–M3 target Z8 C3.11. M4 migrates Z6III 2.00 using the same core source tree and independent evidence. Later program successes do not waive earlier gaps; current M0/M1 candidates must meet their own local and fresh-QEMU gates, while physical-only conditions remain open until actually checked.

### M0: Workspace, profile, and build foundation

| Task | Acceptance |
|---|---|
| T1 Workspace and C build entry | Separate crates in `tool/nloader/`; CLI uses SDK; camera C/assembly compilation works |
| T2 Shared profile contract | Build and collection use one type system; identity mismatch, missing/conflicting fields, unsupported capability, and bounds failures reject |
| T3 Z8 C3.11 profile | Manually justified fields; actual-image validation passes; incorrect addresses, fingerprints, ranges, and original values reject |
| T4 Standalone containers | Rust CLI and SDK unpack/pack, ignored external keys, stock and modified round trips, wrong-key rejection, independent algorithm checks; no production Python dependency |
| T5 Core diagnostics | Generated bindings, verified calls and state ownership, supported early diagnostic modes, independently verified patch ranges |
| T6 Read-only collection | Exact readable ranges, maintenance transitions, and cleanup; unreadable data reported, never replaced by zero or emitted as a profile |
| T7 Official update behavior | Physical same-version reinstall, downgrade, version-conflict and uninstall conditions established |

T3 depends on T2. Collection is a verification aid, not a prerequisite for manually maintained profiles. Byte validation is not runtime acceptance.

### M1: Menus and load checks

| Task | Acceptance |
|---|---|
| T1 Native layout | Target-specific menu/object records, owned text space, identifiers, and profile capabilities verified |
| T2 Generation and entry | Generated native records; Apps first, NLoader last; all original/hidden records and behaviors preserved |
| T3 List and navigation | Both base kinds displayed correctly; names, status, details, scrolling, directional/dial navigation, OK and back verified at short and 64-entry limits |
| T4 Disable and compatibility | Visible disabled state, no card, missing/malformed catalog, unsupported targets/API, illegal kinds, and reliable error presentation |
| T5 File validation | Headers, lengths, entry/data bounds, CRC, read failures and card changes; correct result; no diagnostic-file execution |

The separate playback-menu demo is not part of acceptance. M1 never executes card programs and does not depend on M2 execution.

### M2: Program execution and independent lifecycle checks

| Task | Acceptance |
|---|---|
| T1 Return probe | Fixed 16-byte probe executes on Z8 C3.11 and verifies its response after separate preparation acceptance |
| T2 Data and memory | Initialized data and BSS work; separate foreground/resident ownership and budgets; live references are never freed |
| T3 Foreground `hello` | Correct independent entry; text, reads, return/error/exit, ordinary busy-loop escape, cleanup and relaunch; resident extensions survive |
| T4 Executable and C ABI | Version-2 type/entry/data/relocation contracts, rejection rules, graphical lifetime, SDK entry selection, `.nlb` packaging and consistent generated catalog |
| T5 Resource extension | Correct independent init entry, persistent published test resource, ordered boot loading, restart-applied enable/disable/order; no general conflict solver |
| T6 Failure and restart | Partial publication, later-entry stop, retained marker/memory, next-boot pause, explicit recovery and verified resource-clearing restart |

T4 precedes formal T3/T5 packaging acceptance. Both examples load actual separate files and enter their respective functions. Test interruption before the first entry, between entries, and after the last success but before clearing pending; each must pause the next boot. Check failed/uncertain marker writes and successful completion independently.

### M3: DOOM

Complete the Z8 C3.11 port, WAD access, physical input mapping, graphics, and performance budget. Acceptance requires playable operation, normal return to the list, another launch, and preservation of loaded extensions. Independently verify engine limits, full-frame behavior, and memory constraints. Severe faults may require manual restart; that is not a substitute for normal-exit acceptance.

### M4: Z6III 2.00 migration

| Task | Acceptance |
|---|---|
| T1 Profile | Fresh official-image analysis and byte validation for Z6III 2.00 |
| T2 AES container | Same unpack/pack interface, explicit local key-material format, unchanged and modified package checks |
| T3 Adapters and diagnostics | Shared core without embedded addresses; model-specific service families and applicable diagnostic ladder verified |
| T4 Menu and loading | Repeat every applicable M1 gate on the Z6III layout |
| T5 Programs | Repeat foreground, extension, autoload, failure, restart and DOOM acceptance |
| T6 Update and uninstall | Model-specific version rules, uninstall path and actual resource-clearing restart verified |

Neither another model's results nor an earlier isolated proof establishes migration success.

### Platform phases

| Phase | Acceptance scope |
|---|---|
| P1: Usable replacement interface | Shell/service lifecycle, tasks/queue/reservations, routed controls including dials/joystick/touch where supported, exclusive rear-screen claim/release, named property read/watch, card-removal survival |
| P2: Settings and stability | Per-property verified native write path, named hooks/tables, address-free example migrations, verified EVF ownership, native stock-menu/i-menu extension |
| P3: Advanced features | Read-only physical-state collection first, then separately verified LUT preview, RAW pre-release, and open-gate behavior; no capability inferred from table discovery alone |

Development-core distribution supports ongoing work; release bundles are required before relying on card-independent operation. Every platform phase retains its physical-camera gates. A partial control map, unknown EVF stride, polling watch implementation, unverified property write, or read-only settings page is a stated limit, not completion of the corresponding feature.

## 10. Risks and Remaining Validation

| Risk | Required control |
|---|---|
| Wrong records, text ownership, or GUI context | Independent layout/instruction checks, owned buffers, exact routing, actual native screenshots and stock-page comparisons |
| Wrong profile or firmware revision | Identity/fingerprint/original-byte/semantic validation and no cross-model guessing |
| Cache, execution, allocation, or calling-convention errors | Separate prepare/probe/data stages, real failure cases, physical-camera checks |
| Extension partial effects or unsafe resource release | Explicit ownership, retained references, serial publication, pending guard and verified restart |
| Storage uncertainty or card swap | Stable observed identity, native replies/sync/slot flush/read-back, stop on uncertainty, actual stopped-card restart |
| Boot escape, no-card, or standby behavior | Stock recovery paths; physical key, removal, warm-resume, no-card and long-running checks |
| Screen/input mismatch | Actual release/restore, physical dial direction, touch, EVF geometry, shutter behavior and exit checks |
| Firmware update or flashing failure | User-performed flashing, before/after checks, known official-update limits; no unproven recovery guarantee |
| Key or firmware disclosure | Ignored local inputs/outputs; no real keys or official firmware in source distribution |

Local build success, package checks, or emulator success cannot close a physical-only gate. Reserve support claims for the exact behavior and environment actually exercised.
