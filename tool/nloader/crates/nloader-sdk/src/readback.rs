//! Bounded pre/post-flash comparisons. This never writes camera memory and
//! cannot establish the installed NOR image or restoration of the prior UI.
use crate::{camera, discovery, firmware, profile};
use serde::Serialize;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Firmware(#[from] firmware::Error),
    #[error(transparent)]
    Camera(#[from] camera::Error),
    #[error(transparent)]
    Discovery(#[from] discovery::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("readback plan rejected: {0}")]
    Plan(String),
    #[error("readback output already exists: {0}")]
    Exists(PathBuf),
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Pre,
    Post,
}

/// These explicit pins must come from the independently accepted candidate,
/// never from its patch manifest. Key material is not retained in the plan.
pub struct Candidate<'a> {
    pub package: &'a Path,
    pub package_sha256: &'a str,
    pub eg_sha256: &'a str,
}

// Four approved menu-derived requests, totaling 504 bytes.
// Only these subranges may differ in the accepted candidate. Every adjacent
// byte remains stock in the package and is compared without masking at runtime.
const EDITS: [(usize, usize, usize); 3] = [(0, 16, 18), (1, 96, 96), (2, 0, 80)];

pub struct ReadbackPlan {
    phase: Phase,
    requests: Vec<camera::MemoryReadRequest>,
    windows: profile::VerifiedReadWindows,
    expected: Vec<Vec<u8>>,
    stock_sha256: String,
    stock_eg_sha256: String,
    candidate_sha256: Option<String>,
    candidate_eg_sha256: Option<String>,
}

impl ReadbackPlan {
    pub fn prepare(
        profile: &profile::Profile,
        stock: &Path,
        key_file: &Path,
        candidate: Option<Candidate<'_>>,
    ) -> Result<Self> {
        if profile.identity.model != "Z8" || profile.identity.firmware != "3.11" {
            return Err(Error::Plan("only Z8 3.11 is supported".into()));
        }
        let identity = firmware::FirmwareIdentity {
            model: "Z8".into(),
            firmware: "3.11".into(),
        };
        let raw = fs::read(stock)?;
        let key = firmware::KeyFile::load(key_file)?.for_identity(&identity)?;
        key.verify_stock_identity(&raw)?;
        if profile.checks.package_sha256.as_deref() != Some(profile::sha256(&raw).as_str())
            || key.scheme() != "legacy-xor"
        {
            return Err(Error::Plan(
                "stock package fingerprint or target container differs".into(),
            ));
        }
        let image = key.unpack(&raw)?;
        let module = profile
            .identity
            .eg_module
            .as_deref()
            .ok_or_else(|| Error::Plan("missing EG module".into()))?;
        let stock_eg = image.payload(module)?;
        let windows = profile.verify_read_windows(stock_eg).map_err(Error::Plan)?;
        let requests = discovery::memory_requests(profile)?;
        validate_plan(profile, stock_eg, &requests)?;
        camera::validate_memory_requests(&requests, windows.windows())?;
        let stock_expected = expected_bytes(profile, stock_eg, &requests)?;
        let mut plan = Self {
            phase: Phase::Pre,
            requests,
            windows,
            expected: stock_expected,
            stock_sha256: profile::sha256(&raw),
            stock_eg_sha256: profile::sha256(stock_eg),
            candidate_sha256: None,
            candidate_eg_sha256: None,
        };
        if let Some(candidate) = candidate {
            let raw = fs::read(candidate.package)?;
            let package_hash = profile::sha256(&raw);
            require_hash(candidate.package_sha256, &package_hash, "candidate package")?;
            let changed = key.unpack(&raw)?;
            if image.modules() != changed.modules() {
                return Err(Error::Plan(
                    "candidate module directory differs from stock".into(),
                ));
            }
            for entry in image.modules().iter().filter(|entry| entry.name != module) {
                if image.payload(&entry.name)? != changed.payload(&entry.name)? {
                    return Err(Error::Plan(format!("non-EG module {} differs", entry.name)));
                }
            }
            let eg = changed.payload(module)?;
            let eg_hash = profile::sha256(eg);
            require_hash(candidate.eg_sha256, &eg_hash, "candidate EG")?;
            let expected = expected_bytes(profile, eg, &plan.requests)?;
            validate_neighbors(&plan.expected, &expected)?;
            plan.phase = Phase::Post;
            plan.expected = expected;
            plan.candidate_sha256 = Some(package_hash);
            plan.candidate_eg_sha256 = Some(eg_hash);
        }
        Ok(plan)
    }

    pub fn capture(&self, selector: &str) -> Result<ReadbackCheck> {
        let capture = camera::capture_memory(selector, &self.requests, &self.windows)?;
        Ok(self.compare(capture, false))
    }

    /// Offline evaluation retains the original evidence origin but is never
    /// presented as a new device read. Capture failure is not a byte mismatch.
    pub fn replay(&self, capture: camera::MemoryCapture) -> ReadbackCheck {
        self.compare(capture, true)
    }

    fn compare(&self, capture: camera::MemoryCapture, replayed: bool) -> ReadbackCheck {
        let problem = capture
            .validate()
            .err()
            .map(|e| e.to_string())
            .or_else(|| {
                (!capture.transactions.first().is_some_and(|record| {
                    record.operation == 0x1001
                        && record.error.is_none()
                        && record.reply.as_ref().is_some_and(|reply| {
                            reply.response_code == 0x2001
                                && reply.parameters.is_empty()
                                && reply.data == capture.raw_device_info
                        })
                }))
                .then(|| "fresh GetDeviceInfo response was not acknowledged".into())
            })
            .or_else(|| {
                (!capture.is_complete()).then(|| {
                    capture
                        .failure
                        .clone()
                        .unwrap_or_else(|| "capture or owned cleanup incomplete".into())
                })
            })
            .or_else(|| {
                (capture.requests != self.requests || capture.windows != self.windows.windows())
                    .then(|| "capture does not match the approved 504-byte plan".into())
            })
            .or_else(|| {
                (!capture.identity.as_ref().is_some_and(|id| {
                    matches!(id.model.as_str(), "Z 8" | "Z8") && id.device_version == "V3.11"
                }))
                .then(|| "fresh Z8 V3.11 identity missing".into())
            })
            .or_else(|| {
                (!capture.cleanup.transport_usable
                    || capture.cleanup.standard_session
                        != camera::SessionOwnership::CloseAcknowledged
                    || capture.cleanup.maintenance_session
                        != camera::SessionOwnership::CloseAcknowledged)
                    .then(|| "owned sessions were not both closed on a usable transport".into())
            });
        let mut comparisons = Vec::new();
        if problem.is_none() {
            for (index, request) in self.requests.iter().enumerate() {
                let observed: Vec<u8> = capture
                    .segments
                    .iter()
                    .filter(|s| s.request_index == index)
                    .flat_map(|s| s.bytes.iter().copied())
                    .collect();
                let expected = &self.expected[index];
                let differences = expected
                    .iter()
                    .zip(&observed)
                    .enumerate()
                    .filter_map(|(offset, (expected, observed))| {
                        (expected != observed).then_some(ByteDifference {
                            offset,
                            domain: byte_domain(index, offset),
                            expected: *expected,
                            observed: *observed,
                        })
                    })
                    .collect::<Vec<_>>();
                comparisons.push(Comparison {
                    site_matched: EDITS
                        .iter()
                        .any(|(r, _, _)| *r == index)
                        .then(|| !differences.iter().any(|d| d.domain == Domain::PatchSite)),
                    neighbors_matched: !differences
                        .iter()
                        .any(|d| d.domain == Domain::ProtectedNeighbor),
                    label: request.label.clone(),
                    address: request.address,
                    length: request.length,
                    expected_sha256: profile::sha256(expected),
                    observed_sha256: profile::sha256(&observed),
                    differences,
                });
            }
        }
        let status = if problem.is_some() {
            Status::CaptureFailed
        } else if comparisons.iter().any(|c| !c.differences.is_empty()) {
            Status::BytesMismatch
        } else {
            Status::Matched
        };
        let report = ReadbackReport { schema: 1, phase: self.phase, status, replayed,
            origin: capture.origin, stock_sha256: self.stock_sha256.clone(), stock_eg_sha256: self.stock_eg_sha256.clone(),
            candidate_sha256: self.candidate_sha256.clone(), candidate_eg_sha256: self.candidate_eg_sha256.clone(),
            reason: problem, comparisons,
            limitation: "Only the approved 504 initialized-RAM bytes were compared. Candidate acceptance is supplied by the caller, not established here. Consistent runtime differences remain unresolved, without masking. Installed NOR, menu behavior, physical SD access and prior UI restoration are not established.".into() };
        ReadbackCheck { report, capture }
    }
}

fn require_hash(declared: &str, actual: &str, name: &str) -> Result<()> {
    if declared != actual {
        return Err(Error::Plan(format!(
            "{name} SHA256 differs from its explicit accepted input"
        )));
    }
    Ok(())
}
fn validate_plan(
    profile: &profile::Profile,
    eg: &[u8],
    requests: &[camera::MemoryReadRequest],
) -> Result<()> {
    let setup = profile
        .menu
        .setup
        .as_ref()
        .ok_or_else(|| Error::Plan("missing reviewed Setup layout".into()))?;
    let page = profile
        .menu
        .page
        .as_ref()
        .ok_or_else(|| Error::Plan("missing reviewed loader page layout".into()))?;
    let sizes = profile
        .menu
        .record_sizes
        .ok_or_else(|| Error::Plan("missing menu record sizes".into()))?;
    if sizes.window != 96 || sizes.page != 80 || page.window_id != 1493 || setup.window_id != 663 {
        return Err(Error::Plan("unsupported initialized menu layout".into()));
    }
    let setup_window = profile
        .menu
        .window_address(setup.window_id)
        .ok_or_else(|| Error::Plan("missing Setup window".into()))?;
    let setup_record = expected_bytes(
        profile,
        eg,
        &[camera::MemoryReadRequest {
            label: "native Setup window".into(),
            address: setup_window,
            length: sizes.window,
        }],
    )?;
    if u16::from_le_bytes(setup_record[0][..2].try_into().unwrap()) != 2
        || u16::from_le_bytes(setup_record[0][2..4].try_into().unwrap()) != 663
        || u64::from_le_bytes(setup_record[0][80..88].try_into().unwrap()) != setup.page_address
    {
        return Err(Error::Plan(
            "Setup window does not point at the reviewed page".into(),
        ));
    }
    let window = profile
        .menu
        .window_address(page.window_id)
        .ok_or_else(|| Error::Plan("invalid window mapping".into()))?;
    if page.page_record
        != window
            .checked_add(96)
            .ok_or_else(|| Error::Plan("window overflow".into()))?
    {
        return Err(Error::Plan(
            "page record must use the adjacent reviewed hole".into(),
        ));
    }
    let neighbors = expected_bytes(
        profile,
        eg,
        &[camera::MemoryReadRequest {
            label: "native neighbor".into(),
            address: page.page_record,
            length: 192,
        }],
    )?;
    let record = &neighbors[0];
    if record[..96].iter().any(|byte| *byte != 0)
        || u16::from_le_bytes(record[96..98].try_into().unwrap()) != 5
        || u16::from_le_bytes(record[98..100].try_into().unwrap()) != 1495
    {
        return Err(Error::Plan(
            "stock page hole or native neighbor window differs".into(),
        ));
    }
    let battery_window = profile
        .menu
        .window_address(729)
        .ok_or_else(|| Error::Plan("missing native Battery window".into()))?;
    let battery = expected_bytes(
        profile,
        eg,
        &[camera::MemoryReadRequest {
            label: "native Battery window".into(),
            address: battery_window,
            length: sizes.window,
        }],
    )?;
    if u16::from_le_bytes(battery[0][0..2].try_into().unwrap()) != 2
        || u16::from_le_bytes(battery[0][2..4].try_into().unwrap()) != 729
    {
        return Err(Error::Plan(
            "native Battery window relationship differs".into(),
        ));
    }
    let handlers = u64::from_le_bytes(battery[0][40..48].try_into().unwrap());
    let derived = [
        (setup.page_address, sizes.page),
        (
            window
                .checked_sub(96)
                .ok_or_else(|| Error::Plan("window underflow".into()))?,
            sizes.window * 2,
        ),
        (page.page_record, sizes.window * 2),
        (handlers, profile::MENU_HANDLER_SLOTS as u32 * 8),
    ];
    if requests.len() != derived.len()
        || requests
            .iter()
            .zip(derived)
            .any(|(r, (address, length))| r.address != address || r.length != length)
    {
        return Err(Error::Plan("only the reviewed four-request 504-byte menu plan is supported; registry and General traces are unsupported".into()));
    }
    let bytes = expected_bytes(profile, eg, requests)?;
    if bytes[1][96..].iter().any(|byte| *byte != 0)
        || u16::from_le_bytes(bytes[1][..2].try_into().unwrap()) != 3
        || u16::from_le_bytes(bytes[1][2..4].try_into().unwrap()) != 1492
        || u64::from_le_bytes(bytes[0][16..24].try_into().unwrap()) != setup.items
        || u64::from_le_bytes(bytes[0][24..32].try_into().unwrap()) != setup.event_table
        || u32::from(u16::from_le_bytes(bytes[0][32..34].try_into().unwrap())) != setup.item_count
    {
        return Err(Error::Plan(
            "stock Setup fields or preceding native window differ from the reviewed layout".into(),
        ));
    }
    Ok(())
}
fn expected_bytes(
    profile: &profile::Profile,
    eg: &[u8],
    requests: &[camera::MemoryReadRequest],
) -> Result<Vec<Vec<u8>>> {
    requests
        .iter()
        .map(|r| {
            let offset = profile
                .memory
                .address_to_offset(r.address, u64::from(r.length))
                .map_err(|e| Error::Plan(e.to_string()))?;
            let start =
                usize::try_from(offset).map_err(|_| Error::Plan("image offset overflow".into()))?;
            let end = start
                .checked_add(r.length as usize)
                .ok_or_else(|| Error::Plan("image range overflow".into()))?;
            eg.get(start..end)
                .map(|b| b.to_vec())
                .ok_or_else(|| Error::Plan("mapped request exceeds EG".into()))
        })
        .collect()
}
fn validate_neighbors(stock: &[Vec<u8>], candidate: &[Vec<u8>]) -> Result<()> {
    for (index, (before, after)) in stock.iter().zip(candidate).enumerate() {
        for (offset, (old, new)) in before.iter().zip(after).enumerate() {
            if old != new
                && !EDITS.iter().any(|(request, start, length)| {
                    *request == index && offset >= *start && offset < start + length
                })
            {
                return Err(Error::Plan(format!(
                    "candidate changes protected neighbor at request {index} byte {offset}"
                )));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Matched,
    BytesMismatch,
    CaptureFailed,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    PatchSite,
    ProtectedNeighbor,
}
fn byte_domain(request: usize, offset: usize) -> Domain {
    if EDITS
        .iter()
        .any(|(r, start, length)| *r == request && offset >= *start && offset < start + length)
    {
        Domain::PatchSite
    } else {
        Domain::ProtectedNeighbor
    }
}
#[derive(Debug, Serialize)]
pub struct ByteDifference {
    pub offset: usize,
    pub domain: Domain,
    pub expected: u8,
    pub observed: u8,
}
#[derive(Debug, Serialize)]
pub struct Comparison {
    pub site_matched: Option<bool>,
    pub neighbors_matched: bool,
    pub label: String,
    pub address: u64,
    pub length: u32,
    pub expected_sha256: String,
    pub observed_sha256: String,
    pub differences: Vec<ByteDifference>,
}
#[derive(Debug, Serialize)]
pub struct ReadbackReport {
    pub schema: u32,
    pub phase: Phase,
    pub status: Status,
    pub replayed: bool,
    pub origin: camera::CaptureOrigin,
    pub stock_sha256: String,
    pub stock_eg_sha256: String,
    pub candidate_sha256: Option<String>,
    pub candidate_eg_sha256: Option<String>,
    pub reason: Option<String>,
    pub comparisons: Vec<Comparison>,
    pub limitation: String,
}
pub struct ReadbackCheck {
    pub report: ReadbackReport,
    pub capture: camera::MemoryCapture,
}
#[derive(Debug, Serialize)]
pub struct Outputs {
    pub report: PathBuf,
    pub snapshot: PathBuf,
}
impl ReadbackCheck {
    pub fn matched(&self) -> bool {
        self.report.status == Status::Matched
    }
    pub fn write_outputs(&self, out: &Path) -> Result<Outputs> {
        let paths = output_paths(out)?;
        let entries = [
            (&paths.report, serde_json::to_vec_pretty(&self.report)?),
            (&paths.snapshot, serde_json::to_vec_pretty(&self.capture)?),
        ];
        if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let mut created = Vec::new();
        let result = (|| -> std::io::Result<()> {
            for (path, data) in entries {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?;
                created.push(path.clone());
                file.write_all(&data)?;
                file.sync_all()?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            for path in created {
                let _ = fs::remove_file(path);
            }
            return Err(error.into());
        }
        Ok(paths)
    }
}
/// Must be called before device access; dangling symlinks also reserve names.
pub fn output_paths(out: &Path) -> Result<Outputs> {
    let paths = Outputs {
        report: out.to_path_buf(),
        snapshot: out.with_extension("snapshot.json"),
    };
    if paths.report == paths.snapshot {
        return Err(Error::Exists(out.to_path_buf()));
    }
    for path in [&paths.report, &paths.snapshot] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(Error::Exists(path.clone())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(paths)
}

#[cfg(test)]
#[path = "readback_tests.rs"]
mod tests;
