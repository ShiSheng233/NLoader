use clap::{Parser, Subcommand};
use nloader_sdk as sdk;
use std::{ffi::OsString, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(name = "nloader", version, about = "NLoader host tools")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum FlashPhase {
    Pre,
    Post,
}

#[derive(Subcommand)]
enum Command {
    /// Compile independent C sizeof/offsetof evidence; no firmware is linked.
    RuntimeLayout {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        mode: sdk::profile::BuildMode,
        #[arg(long, default_value = "clang")]
        cc: OsString,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify only provided Runtime bytes; no physical pointer is read.
    #[command(group(clap::ArgGroup::new("trace_source").required(true).args(["snapshot", "qemu_result"])))]
    RuntimeTrace {
        #[arg(long)]
        layout_object: PathBuf,
        /// Pin the independently compiled layout object, not its JSON sidecar.
        #[arg(long)]
        layout_sha256: String,
        /// Independent candidate expectations; never derived from this dump.
        #[arg(long)]
        expectations: PathBuf,
        /// Full provided Snapshot JSON, explicitly offline/replayed.
        #[arg(long)]
        snapshot: Option<PathBuf>,
        #[arg(long, requires = "runtime")]
        qemu_result: Option<PathBuf>,
        #[arg(long, requires = "qemu_result")]
        runtime: Option<PathBuf>,
        #[arg(long, requires = "runtime")]
        pool: Option<PathBuf>,
        /// New result directory retaining provided bytes and refusal details.
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare only the approved 504 initialized-RAM bytes before/after manual
    /// flashing. This does not verify the installed NOR image or menu behavior.
    #[command(group(clap::ArgGroup::new("source").required(true).args(["camera", "snapshot"])))]
    FlashCheck {
        #[arg(long, value_enum)]
        phase: FlashPhase,
        #[arg(long)]
        profile: PathBuf,
        /// Matching independently verified official package.
        #[arg(long)]
        firmware: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        camera: Option<String>,
        /// Recorded raw MemoryCapture JSON; never a new device acquisition.
        #[arg(long)]
        snapshot: Option<PathBuf>,
        #[arg(long, required_if_eq("phase", "post"), requires_all = ["candidate_sha256", "candidate_eg_sha256"])]
        candidate: Option<PathBuf>,
        /// SHA from independent candidate package acceptance, not patch JSON.
        #[arg(long, requires = "candidate")]
        candidate_sha256: Option<String>,
        /// EG payload SHA from independent acceptance, not patch JSON.
        #[arg(long, requires = "candidate")]
        candidate_eg_sha256: Option<String>,
        /// New report JSON; its .snapshot.json companion preserves raw reads.
        #[arg(long)]
        out: PathBuf,
    },
    /// Build the fixed M2 return probe diagnostic file (not a general app).
    Probe {
        #[arg(long, default_value = "clang")]
        cc: OsString,
        #[arg(long)]
        out: PathBuf,
    },
    /// Package a general v2 camera program (.nlb) from sources or objects.
    Program {
        /// Program declaration JSON: id, kind, display_name, file, min_abi,
        /// and optional abi_version, entry_symbol, models.
        #[arg(long)]
        decl: PathBuf,
        /// C or assembly source compiled with --cc. Repeat as needed.
        #[arg(long = "source")]
        sources: Vec<PathBuf>,
        /// Prebuilt AArch64 ELF64 relocatable object. Repeat as needed.
        #[arg(long = "object")]
        objects: Vec<PathBuf>,
        /// Header search directory for --source compilations. Repeat as needed.
        #[arg(long = "include")]
        includes: Vec<PathBuf>,
        /// Clang executable with an AArch64 backend, used for --source.
        #[arg(long, default_value = "clang")]
        cc: OsString,
        /// New MANIFEST file receiving this program's entry line.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// New .nlb destination; an existing path is never replaced.
        #[arg(long)]
        out: PathBuf,
    },
    /// Build a selected diagnostic package after checking the profile and stock firmware.
    Build {
        #[arg(long)]
        profile: PathBuf,
        /// The official package, with --key-file. The output is a package.
        #[arg(long, requires = "key_file", conflicts_with = "eg_module")]
        firmware: Option<PathBuf>,
        #[arg(long, requires = "firmware")]
        key_file: Option<PathBuf>,
        /// The decrypted target module on its own, named as the profile names
        /// it. No container is opened: the output is a patched module for an
        /// emulator and nothing from this build can be flashed.
        #[arg(long)]
        eg_module: Option<PathBuf>,
        #[arg(long)]
        mode: sdk::profile::BuildMode,
        #[arg(long, default_value = "clang")]
        cc: OsString,
        #[arg(long)]
        out: PathBuf,
        /// A release bundle directory (programs that describe themselves,
        /// optional BOOT and ENABLED) placed in the firmware: exec only.
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Dev firmware (Exec only): the module gets stage 0 alone, and the
        /// loader is written here as CORE.NLC for NLOADER/ on the card.
        #[arg(long)]
        dev_core: Option<PathBuf>,
    },
    /// Recover or normalize local key files.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// List connected Nikon USB devices without opening a camera session.
    Cameras,
    /// Collect/replay audit evidence or validate a manually maintained profile.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Check that C and assembly compile to camera-target ELF objects.
    Toolchain {
        #[command(subcommand)]
        command: ToolchainCommand,
    },
    /// Validate and extract a Legacy XOR or AES-CTR package using a local key file.
    Unpack {
        #[arg(long)]
        firmware: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        /// Exact model identity used to select local key material (e.g. Z8).
        #[arg(long)]
        model: String,
        #[arg(long)]
        firmware_version: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Repack an extracted package, validate it, and create a new output file.
    Pack {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeysCommand {
    /// Save a normalized copy without changing any key values.
    Normalize {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Recover shared XOR tables and the selected model's signature key.
    Recover {
        /// Original target package; also contributes shared table observations.
        #[arg(long)]
        firmware: PathBuf,
        #[arg(long)]
        model: String,
        #[arg(long)]
        firmware_version: String,
        /// Additional original Legacy XOR packages for table coverage. Repeat as needed.
        #[arg(long = "source")]
        sources: Vec<PathBuf>,
        /// Existing unified key file, or a JSON array of three 256-byte XOR tables.
        #[arg(long)]
        xor_tables: Option<PathBuf>,
        /// New local key file. Existing files are never replaced.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    /// Read a selected camera's identity; save reports and raw snapshots only.
    Discover {
        /// Use the USB ID from `cameras`, or `auto` for exactly one device.
        #[arg(long)]
        camera: String,
        #[arg(long)]
        out: PathBuf,
        /// Matching official firmware for independently checked image evidence.
        #[arg(long, requires_all = ["key_file", "profile"])]
        firmware: Option<PathBuf>,
        #[arg(long, requires = "firmware")]
        key_file: Option<PathBuf>,
        /// Local profile containing reviewed image and collection inputs.
        #[arg(long, requires = "firmware")]
        profile: Option<PathBuf>,
        /// Read the supported RAM anchor using a maintenance session, then clean up.
        #[arg(long, requires_all = ["firmware", "key_file"])]
        memory: bool,
    },
    /// Replay captured evidence as reports/snapshots; never generate a profile.
    Replay {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, requires_all = ["key_file", "profile"])]
        firmware: Option<PathBuf>,
        #[arg(long, requires = "firmware")]
        key_file: Option<PathBuf>,
        /// Local profile containing reviewed image and collection inputs.
        #[arg(long, requires = "firmware")]
        profile: Option<PathBuf>,
    },
    /// Check declared profile requirements. With --firmware, also compare the
    /// profile with that official package's actual bytes; no device is used.
    Validate {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        mode: sdk::profile::BuildMode,
        #[arg(long, requires = "key_file")]
        firmware: Option<PathBuf>,
        #[arg(long, requires = "firmware")]
        key_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ToolchainCommand {
    /// Compile the diagnostic C and assembly sources; emits objects, not firmware.
    Check {
        /// Clang executable with an AArch64 backend.
        #[arg(long, default_value = "clang")]
        cc: OsString,
        /// New directory for marker.o, entry.o, bindings.o, and report.json.
        #[arg(long)]
        out: PathBuf,
    },
}

fn read_bounded(path: &std::path::Path, limit: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(format!("provided input exceeds its byte bound: {}", path.display()).into());
    }
    let data = std::fs::read(path)?;
    if data.len() as u64 > limit {
        return Err("provided input grew beyond its byte bound".into());
    }
    Ok(data)
}

fn run(cli: Cli) -> Result<bool, Box<dyn std::error::Error>> {
    match cli.command {
        Command::Probe { cc, out } => {
            let report = sdk::build::probe::build(&sdk::build::probe::ProbeBuildRequest {
                compiler: cc,
                output: out,
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Program {
            decl,
            sources,
            objects,
            includes,
            cc,
            manifest,
            out,
        } => {
            let declaration: sdk::build::program::ProgramMeta =
                serde_json::from_slice(&std::fs::read(&decl)?)?;
            let report =
                sdk::build::program::build::build(&sdk::build::program::ProgramBuildRequest {
                    compiler: cc,
                    declaration,
                    sources,
                    objects,
                    include_dirs: includes,
                    output: out,
                    manifest_output: manifest,
                })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Build {
            profile,
            firmware,
            key_file,
            eg_module,
            mode,
            cc,
            out,
            bundle,
            dev_core,
        } => {
            let source = match (firmware, key_file, eg_module) {
                (Some(firmware), Some(key_file), None) => {
                    sdk::build::BuildSource::Package { firmware, key_file }
                }
                (None, None, Some(path)) => sdk::build::BuildSource::Module { path },
                _ => {
                    return Err(
                        "give either --firmware with --key-file, or --eg-module alone".into(),
                    )
                }
            };
            let request = sdk::build::BuildRequest {
                profile,
                source,
                mode,
                compiler: cc,
                output: out,
                bundle,
            };
            let report = match dev_core {
                Some(core) => sdk::build::build_dev(&request, &core)?,
                None => sdk::build::build(&request)?,
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Keys { command } => match command {
            KeysCommand::Normalize { input, out } => {
                sdk::firmware::KeyFile::load(&input)?.write_canonical(&out)?;
                println!("Saved unified key file: {}", out.display());
            }
            KeysCommand::Recover {
                firmware,
                model,
                firmware_version,
                sources,
                xor_tables,
                out,
            } => {
                let identity = sdk::firmware::FirmwareIdentity {
                    model,
                    firmware: firmware_version,
                };
                let report = match xor_tables {
                    Some(path) => sdk::firmware::recover_key_file_with_tables(
                        &firmware, &identity, &sources, &path, &out,
                    )?,
                    None => sdk::firmware::recover_key_file(&firmware, &identity, &sources, &out)?,
                };
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        },
        Command::Cameras => {
            println!(
                "{}",
                serde_json::to_string_pretty(&sdk::camera::enumerate()?)?
            );
        }
        Command::RuntimeLayout {
            profile,
            mode,
            cc,
            out,
        } => {
            sdk::build::layout::preflight(&out)?;
            let report =
                sdk::build::layout::compile(&sdk::read_profile(&profile)?, mode, &cc, &out)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::RuntimeTrace {
            layout_object,
            layout_sha256,
            expectations,
            snapshot,
            qemu_result,
            runtime,
            pool,
            out,
        } => {
            sdk::runtime_trace::preflight(&out)?;
            let retained = vec![
                qemu_result
                    .as_ref()
                    .map(|p| ("qemu_result".to_owned(), p.clone(), 8 * 1024 * 1024)),
                snapshot
                    .as_ref()
                    .map(|p| ("provided_snapshot".to_owned(), p.clone(), 512 * 1024)),
                runtime
                    .as_ref()
                    .map(|p| ("runtime".to_owned(), p.clone(), 131072)),
                pool.as_ref()
                    .map(|p| ("pool".to_owned(), p.clone(), 131072)),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            let inputs = vec![
                Some((layout_object.clone(), 1024 * 1024)),
                Some((expectations.clone(), 16384)),
                snapshot.as_ref().map(|p| (p.clone(), 512 * 1024)),
                qemu_result.as_ref().map(|p| (p.clone(), 8 * 1024 * 1024)),
                runtime.as_ref().map(|p| (p.clone(), 65536)),
                pool.as_ref().map(|p| (p.clone(), 65536)),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            let attempt = (|| -> Result<_, Box<dyn std::error::Error>> {
                for (path, limit) in &inputs {
                    let metadata = std::fs::metadata(path)?;
                    if !metadata.is_file() || metadata.len() > *limit {
                        return Err("provided input failed its length/type preflight".into());
                    }
                }
                let object = read_bounded(&layout_object, 1024 * 1024)?;
                if sdk::profile::sha256(&object) != layout_sha256 {
                    return Err("provided layout object SHA256 differs".into());
                }
                let layout = sdk::build::layout::inspect(&object)?;
                let expected = serde_json::from_slice(&read_bounded(&expectations, 16384)?)?;
                let data = if let Some(path) = snapshot.as_ref() {
                    serde_json::from_slice(&read_bounded(path, 512 * 1024)?)?
                } else {
                    sdk::runtime_trace::from_qemu_result(
                        &serde_json::from_slice(&read_bounded(
                            qemu_result.as_ref().expect("clap source"),
                            8 * 1024 * 1024,
                        )?)?,
                        read_bounded(runtime.as_ref().expect("clap runtime"), 65536)?,
                        pool.as_deref()
                            .map(|path| read_bounded(path, 65536))
                            .transpose()?,
                    )?
                };
                Ok((sdk::runtime_trace::verify(&layout, &expected, &data), data))
            })();
            let (result, passed) = match attempt {
                Ok((report, data)) => {
                    let passed = report.status == sdk::runtime_trace::Status::MatchedProvided;
                    (
                        sdk::runtime_trace::write_outputs(&out, &report, &data)?,
                        passed,
                    )
                }
                Err(error) => {
                    let raw = runtime
                        .iter()
                        .chain(pool.iter())
                        .filter_map(|path| {
                            read_bounded(path, 65536)
                                .ok()
                                .map(|bytes| (path.display().to_string(), bytes))
                        })
                        .collect::<Vec<_>>();
                    let paths = inputs.into_iter().map(|(path, _)| path).collect::<Vec<_>>();
                    (
                        sdk::runtime_trace::write_input_failure(
                            &out,
                            &error.to_string(),
                            &paths,
                            &raw,
                        )?,
                        false,
                    )
                }
            };
            sdk::runtime_trace::retain_sources(&out, &retained)?;
            println!("{}", result.display());
            return Ok(passed);
        }
        Command::FlashCheck {
            phase,
            profile,
            firmware,
            key_file,
            camera,
            snapshot,
            candidate,
            candidate_sha256,
            candidate_eg_sha256,
            out,
        } => {
            sdk::readback::output_paths(&out)?;
            if matches!(phase, FlashPhase::Pre) && candidate.is_some() {
                return Err("pre check does not accept candidate inputs".into());
            }
            let profile = sdk::read_profile(&profile)?;
            let candidate = candidate
                .as_deref()
                .map(|package| sdk::readback::Candidate {
                    package,
                    package_sha256: candidate_sha256
                        .as_deref()
                        .expect("clap requires candidate SHA"),
                    eg_sha256: candidate_eg_sha256
                        .as_deref()
                        .expect("clap requires candidate EG SHA"),
                });
            let plan =
                sdk::readback::ReadbackPlan::prepare(&profile, &firmware, &key_file, candidate)?;
            let check = if let Some(snapshot) = snapshot {
                plan.replay(serde_json::from_slice(&std::fs::read(snapshot)?)?)
            } else {
                plan.capture(camera.as_deref().expect("clap requires one source"))?
            };
            let outputs = check.write_outputs(&out)?;
            println!("{}", serde_json::to_string_pretty(&outputs)?);
            eprintln!("Only the approved RAM bytes were compared; full firmware installation and UI restoration remain unverified.");
            return Ok(check.matched());
        }
        Command::Profile { command } => match command {
            ProfileCommand::Discover {
                camera,
                out,
                firmware,
                key_file,
                memory,
                profile,
            } => {
                sdk::discovery::output_paths(&out)?;
                let profile = profile.as_deref().map(sdk::read_profile).transpose()?;
                let discovery = match (firmware, key_file) {
                    (Some(firmware), Some(key_file)) if memory => {
                        sdk::discovery::discover_memory_with_firmware(
                            &camera,
                            &firmware,
                            &key_file,
                            profile.as_ref().expect("clap requires profile"),
                        )?
                    }
                    (Some(firmware), Some(key_file)) => sdk::discovery::discover_with_firmware(
                        &camera,
                        &firmware,
                        &key_file,
                        profile.as_ref().expect("clap requires profile"),
                    )?,
                    _ => sdk::discovery::discover(&camera)?,
                };
                let outputs = discovery.write_outputs(&out)?;
                println!("{}", serde_json::to_string_pretty(&outputs)?);
                eprintln!("Report and snapshot saved; no profile generated. Missing capabilities are listed separately.");
                return Ok(discovery.report.collection_succeeded());
            }
            ProfileCommand::Replay {
                snapshot,
                out,
                firmware,
                key_file,
                profile,
            } => {
                sdk::discovery::output_paths(&out)?;
                let profile = profile.as_deref().map(sdk::read_profile).transpose()?;
                let discovery = match (firmware, key_file) {
                    (Some(firmware), Some(key_file)) => sdk::replay_profile_with_firmware(
                        &snapshot,
                        &firmware,
                        &key_file,
                        profile.as_ref().expect("clap requires profile"),
                    )?,
                    _ => sdk::replay_profile(&snapshot)?,
                };
                let outputs = discovery.write_outputs(&out)?;
                println!("{}", serde_json::to_string_pretty(&outputs)?);
                eprintln!("Offline report and snapshot saved; no profile generated. This is not a new camera capture.");
                return Ok(discovery.report.collection_succeeded());
            }
            ProfileCommand::Validate {
                profile,
                mode,
                firmware,
                key_file,
            } => {
                let report = match (firmware, key_file) {
                    (Some(firmware), Some(key_file)) => {
                        sdk::validate_profile_with_firmware(&profile, mode, &firmware, &key_file)?
                    }
                    _ => sdk::read_profile(&profile)?.validate(mode),
                };
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(report.is_valid());
            }
        },
        Command::Toolchain { command } => match command {
            ToolchainCommand::Check { cc, out } => {
                let report = sdk::build::check_toolchain(&cc, &out)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        },
        Command::Unpack {
            firmware,
            key_file,
            model,
            firmware_version,
            out,
        } => {
            let identity = sdk::firmware::FirmwareIdentity {
                model,
                firmware: firmware_version,
            };
            let result = sdk::firmware::unpack_directory(&firmware, &key_file, &identity, &out)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Pack {
            input,
            key_file,
            out,
        } => {
            let result = sdk::firmware::pack_directory(&input, &key_file, &out)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }
    Ok(true)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
