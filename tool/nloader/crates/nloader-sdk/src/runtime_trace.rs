//! Verification of explicitly provided bytes only. No pointer is followed on
//! a device. Layout is decoded from an independent constant-only AArch64 object.
use crate::{
    build::layout::RuntimeLayout,
    profile,
    readback::{Error, Result},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub const MAX_SNAPSHOT_BYTES: usize = 65536;
pub const MAX_CANDIDATES: usize = 768;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectations {
    pub schema: u32,
    /// Provided by independent candidate validation, never filled from a dump.
    pub candidate_eg_sha256: String,
    pub proof_reference: String,
    pub worker_name: String,
    pub callback: u64,
    pub services: u64,
    pub private_services: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Provided,
    QemuProvided,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pool {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub repeat: Option<Vec<u8>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub registry_id: u32,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub repeat: Option<Vec<u8>>,
    pub pool: Option<Pool>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: u32,
    pub source: Source,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    MatchedProvided,
    PartialProvided,
    NoCandidate,
    AmbiguousProvided,
    Refused,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    Layout,
    Length,
    Identity,
    Pointer,
    Sequence,
    Repeat,
    Pool,
    Budget,
    PhysicalMappingUnproven,
    Ambiguous,
}
#[derive(Debug, Serialize)]
pub struct TraceEntry {
    pub logical_sequence: u64,
    pub stored_sequence: u32,
    pub tag: u8,
    pub value: i32,
}
#[derive(Debug, Serialize)]
pub struct Decoded {
    pub registry_id: u32,
    pub address: u64,
    pub worker_flag_id: u32,
    pub state: u32,
    pub ready: u32,
    pub last_result: i32,
    pub stage: u32,
    pub directory_count: u32,
    pub directory_usable: u32,
    pub directory_result: i32,
    pub checked: u32,
    pub check_result: i32,
    pub program_prepared: u32,
    pub entry_started: u32,
    pub returned: u32,
    pub path: String,
    pub trace_count: u64,
    pub trace: Vec<TraceEntry>,
    pub pool_checked: bool,
    pub pool_ready: Option<u32>,
    pub pool_failed: Option<u32>,
    pub pool_result: Option<i32>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub status: Status,
    pub refusal: Option<Refusal>,
    pub reason: Option<String>,
    pub provided: bool,
    pub replayed: bool,
    pub physical_fresh: bool,
    pub live_pointer_reads: bool,
    pub candidate_scope: &'static str,
    pub expectations_provided: bool,
    pub snapshot_sha256: Option<String>,
    pub expectations_sha256: Option<String>,
    pub layout_object_sha256: String,
    pub candidate_eg_sha256: String,
    pub decoded: Option<Decoded>,
    pub limitation: &'static str,
}
const LIMITATION:&str="Only provided bytes and provided candidate expectations were checked. No live pointer was read. This does not prove a complete physical registry, installed firmware, current mappings, allocation lease or fresh physical-camera behavior.";
fn fail(kind: Refusal, message: impl Into<String>) -> (Refusal, String) {
    (kind, message.into())
}
fn scalar(
    layout: &RuntimeLayout,
    bytes: &[u8],
    name: &str,
    width: usize,
) -> std::result::Result<u64, (Refusal, String)> {
    let field = layout
        .field(name)
        .map_err(|e| fail(Refusal::Layout, e.to_string()))?;
    if field.bytes != width {
        return Err(fail(Refusal::Layout, format!("field {name} width differs")));
    }
    let end = field
        .offset
        .checked_add(width)
        .ok_or_else(|| fail(Refusal::Layout, "field overflow"))?;
    let data = bytes
        .get(field.offset..end)
        .ok_or_else(|| fail(Refusal::Length, format!("missing {name}")))?;
    let mut word = [0; 8];
    word[..width].copy_from_slice(data);
    Ok(u64::from_le_bytes(word))
}
fn span(address: u64, bytes: usize) -> bool {
    address != 0 && address & 7 == 0 && address.checked_add(bytes as u64).is_some()
}
fn validate_expectations(e: &Expectations) -> std::result::Result<[u8; 8], (Refusal, String)> {
    if e.schema != 1
        || e.candidate_eg_sha256.len() != 64
        || !e.candidate_eg_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || e.proof_reference.is_empty()
        || e.proof_reference.len() > 4096
        || e.callback == 0
        || e.callback & 3 != 0
        || e.services == 0
        || e.services & 7 != 0
        || e.worker_name.is_empty()
        || e.worker_name.len() > 8
        || !e.worker_name.is_ascii()
        || e.worker_name.as_bytes().contains(&0)
    {
        return Err(fail(
            Refusal::Identity,
            "invalid provided candidate expectations",
        ));
    }
    let mut name = [0; 8];
    name[..e.worker_name.len()].copy_from_slice(e.worker_name.as_bytes());
    Ok(name)
}

/// A refusal is a retained result, never an empty successful snapshot.
pub fn verify(layout: &RuntimeLayout, expected: &Expectations, snapshot: &Snapshot) -> Report {
    let bounded = snapshot.candidates.len() <= MAX_CANDIDATES
        && snapshot
            .candidates
            .iter()
            .try_fold(0usize, |sum, c| {
                sum.checked_add(c.bytes.len())
                    .and_then(|x| x.checked_add(c.repeat.as_ref().map_or(0, Vec::len)))
                    .and_then(|x| x.checked_add(c.pool.as_ref().map_or(0, |p| p.bytes.len())))
                    .and_then(|x| {
                        x.checked_add(
                            c.pool
                                .as_ref()
                                .and_then(|p| p.repeat.as_ref())
                                .map_or(0, Vec::len),
                        )
                    })
            })
            .is_some_and(|n| n <= MAX_SNAPSHOT_BYTES);
    let snapshot_hash = bounded.then(|| {
        profile::sha256(&serde_json::to_vec(snapshot).expect("serializable provided bytes"))
    });
    let oracle_hash = validate_expectations(expected).is_ok().then(|| {
        profile::sha256(&serde_json::to_vec(expected).expect("serializable bounded expectations"))
    });
    let mut report = Report {
        schema: 1,
        status: Status::Refused,
        refusal: None,
        reason: None,
        provided: true,
        replayed: true,
        physical_fresh: false,
        live_pointer_reads: false,
        candidate_scope: "provided_candidates_only",
        expectations_provided: true,
        snapshot_sha256: snapshot_hash,
        expectations_sha256: oracle_hash,
        layout_object_sha256: layout.object_sha256.clone(),
        candidate_eg_sha256: expected.candidate_eg_sha256.clone(),
        decoded: None,
        limitation: LIMITATION,
    };
    let outcome = verify_inner(layout, expected, snapshot);
    match outcome {
        Ok(None) => report.status = Status::NoCandidate,
        Ok(Some(decoded)) => {
            report.status = if decoded.ready == 0
                || decoded.pool_ready == Some(0)
                || decoded.pool_failed.is_some_and(|failed| failed != 0)
            {
                Status::PartialProvided
            } else {
                Status::MatchedProvided
            };
            report.decoded = Some(decoded);
        }
        Err((kind, reason)) => {
            if kind == Refusal::Ambiguous {
                report.status = Status::AmbiguousProvided;
            }
            report.refusal = Some(kind);
            report.reason = Some(reason);
        }
    }
    report
}
fn validate_layout(layout: &RuntimeLayout) -> std::result::Result<(), (Refusal, String)> {
    if layout.schema != 1
        || layout.target != "aarch64-none-elf"
        || layout.runtime_bytes < 320
        || layout.runtime_bytes > MAX_SNAPSHOT_BYTES
        || layout.pool_bytes > MAX_SNAPSHOT_BYTES
        || layout.registry_max_id != 768
        || layout.trace_slots != 16
        || layout.trace_entry_bytes != 8
    {
        return Err(fail(
            Refusal::Layout,
            "unsupported provided layout geometry",
        ));
    }
    for (name, field) in &layout.fields {
        let size = if name.starts_with("pool.") {
            layout.pool_bytes
        } else {
            layout.runtime_bytes
        };
        if field.bytes == 0
            || field
                .offset
                .checked_add(field.bytes)
                .is_none_or(|end| end > size)
        {
            return Err(fail(
                Refusal::Layout,
                format!("provided field {name} exceeds its object"),
            ));
        }
    }
    if layout.pool_bytes != 0
        && (layout.pool_count != 68
            || layout.buffer_bytes != 51
            || layout.descriptor_bytes != 24
            || [
                layout.descriptor_buffer_offset,
                layout.descriptor_length_offset,
                layout.descriptor_style_offset,
                layout.descriptor_reserved_offset,
                layout.descriptor_tail_offset,
            ]
            .iter()
            .zip([8, 4, 4, 4, 4])
            .any(|(offset, width)| {
                offset
                    .checked_add(width)
                    .is_none_or(|end| end > layout.descriptor_bytes)
            }))
    {
        return Err(fail(
            Refusal::Layout,
            "provided descriptor geometry exceeds its object",
        ));
    }
    Ok(())
}

fn verify_inner(
    layout: &RuntimeLayout,
    expected: &Expectations,
    snapshot: &Snapshot,
) -> std::result::Result<Option<Decoded>, (Refusal, String)> {
    validate_layout(layout)?;
    if snapshot.schema != 1 {
        return Err(fail(
            Refusal::Identity,
            "unsupported provided snapshot schema",
        ));
    }
    if snapshot.candidates.len() > MAX_CANDIDATES {
        return Err(fail(
            Refusal::Budget,
            "candidate count exceeds the registry bound",
        ));
    }
    let mut budget = 0usize;
    for c in &snapshot.candidates {
        budget = budget
            .checked_add(c.bytes.len())
            .and_then(|v| v.checked_add(c.repeat.as_ref().map_or(0, Vec::len)))
            .ok_or_else(|| fail(Refusal::Budget, "snapshot budget overflow"))?;
        if let Some(pool) = &c.pool {
            budget = budget
                .checked_add(pool.bytes.len())
                .and_then(|v| v.checked_add(pool.repeat.as_ref().map_or(0, Vec::len)))
                .ok_or_else(|| fail(Refusal::Budget, "pool budget overflow"))?;
        }
    }
    if budget > MAX_SNAPSHOT_BYTES {
        return Err(fail(Refusal::Budget, "provided bytes exceed 64 KiB budget"));
    }
    let name = validate_expectations(expected)?;
    if snapshot.candidates.is_empty() {
        return Ok(None);
    }
    if snapshot.candidates.len() != 1 {
        return Err(fail(Refusal::Ambiguous, "multiple provided candidates"));
    }
    let c = &snapshot.candidates[0];
    if c.registry_id == 0
        || c.registry_id > layout.registry_max_id
        || !span(c.address, layout.runtime_bytes)
    {
        return Err(fail(
            Refusal::Pointer,
            "invalid supplied registry ID/base/extent",
        ));
    }
    if c.bytes.len() != layout.runtime_bytes {
        return Err(fail(
            Refusal::Length,
            "Runtime size does not match the compiled layout",
        ));
    }
    if c.repeat.as_ref().is_some_and(|repeat| repeat != &c.bytes) {
        return Err(fail(Refusal::Repeat, "provided Runtime repeat differs"));
    }
    let v = |field: &str, width: usize| scalar(layout, &c.bytes, field, width);
    if v("worker.id", 4)? != u64::from(c.registry_id)
        || v("worker.self", 8)? != c.address
        || v("worker.callback", 8)? != expected.callback
        || v("load.svc", 8)? != expected.services
    {
        return Err(fail(
            Refusal::Identity,
            "provided worker ID/self/callback/services do not agree",
        ));
    }
    let field = layout
        .field("worker.name")
        .map_err(|e| fail(Refusal::Layout, e.to_string()))?;
    if field.bytes != 8 || c.bytes.get(field.offset..field.offset + 8) != Some(name.as_slice()) {
        return Err(fail(
            Refusal::Identity,
            "worker name differs from provided expectations",
        ));
    }
    let state = v("load.state", 4)? as u32;
    let ready = v("load.ready", 4)? as u32;
    let flag_id = v("worker.flag", 4)? as u32;
    if state > 4 || ready > 1 || (ready == 1 && (flag_id == 0 || flag_id > layout.registry_max_id))
    {
        return Err(fail(Refusal::Identity, "invalid runtime state/ready"));
    }
    let count = v("trace.count", 8)?;
    let entries = layout
        .field("trace.entries")
        .map_err(|e| fail(Refusal::Layout, e.to_string()))?;
    if entries.bytes != layout.trace_slots * layout.trace_entry_bytes
        || layout.trace_slots != 16
        || layout.trace_entry_bytes != 8
    {
        return Err(fail(Refusal::Layout, "unsupported trace geometry"));
    }
    let mut trace = Vec::new();
    let first = count
        .saturating_sub(layout.trace_slots as u64)
        .saturating_add(1);
    if count != 0 {
        for logical in first..=count {
            let slot = ((logical - 1) & (layout.trace_slots as u64 - 1)) as usize;
            let offset = entries.offset + slot * 8;
            let data = c
                .bytes
                .get(offset..offset + 8)
                .ok_or_else(|| fail(Refusal::Length, "missing trace entry"))?;
            let sequence_tag = u32::from_le_bytes(data[..4].try_into().expect("four bytes"));
            let sequence = sequence_tag >> 8;
            let tag = sequence_tag as u8;
            if sequence != ((logical & 0x00ff_ffff) as u32) || !(32..=126).contains(&tag) {
                return Err(fail(
                    Refusal::Sequence,
                    format!("trace slot {slot} does not publish logical sequence {logical}"),
                ));
            }
            trace.push(TraceEntry {
                logical_sequence: logical,
                stored_sequence: sequence,
                tag,
                value: i32::from_le_bytes(data[4..].try_into().expect("four bytes")),
            });
        }
    } else if c
        .bytes
        .get(entries.offset..entries.offset + entries.bytes)
        .is_none_or(|bytes| bytes.iter().any(|b| *b != 0))
    {
        return Err(fail(
            Refusal::Sequence,
            "empty trace has retained nonzero slots",
        ));
    }
    let path = layout
        .field("path")
        .map_err(|e| fail(Refusal::Layout, e.to_string()))?;
    let bytes = c
        .bytes
        .get(path.offset..path.offset + path.bytes)
        .ok_or_else(|| fail(Refusal::Length, "missing path"))?;
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| fail(Refusal::Length, "provided path is not terminated"))?;
    let path = std::str::from_utf8(&bytes[..end])
        .map_err(|_| fail(Refusal::Identity, "provided path is not UTF-8"))?
        .to_owned();
    if let Some(pool) = &c.pool {
        verify_pool(layout, expected, c, pool)?;
    }
    let pool_value = |field: &str| {
        c.pool
            .as_ref()
            .map(|pool| scalar(layout, &pool.bytes, field, 4))
            .transpose()
    };
    Ok(Some(Decoded {
        registry_id: c.registry_id,
        address: c.address,
        worker_flag_id: flag_id,
        state,
        ready,
        last_result: v("load.last_result", 4)? as u32 as i32,
        stage: v("load.stage", 4)? as u32,
        directory_count: v("directory.count", 4)? as u32,
        directory_usable: v("directory.usable", 4)? as u32,
        directory_result: v("directory_result", 4)? as u32 as i32,
        checked: v("checked", 4)? as u32,
        check_result: v("check_result", 4)? as u32 as i32,
        program_prepared: v("program.prepared", 4)? as u32,
        entry_started: v("program.entry_started", 4)? as u32,
        returned: v("program.returned", 4)? as u32,
        path,
        trace_count: count,
        trace,
        pool_checked: c.pool.is_some(),
        pool_ready: pool_value("pool.ready")?.map(|v| v as u32),
        pool_failed: pool_value("pool.failed")?.map(|v| v as u32),
        pool_result: pool_value("pool.last_result")?.map(|v| v as u32 as i32),
    }))
}
fn verify_pool(
    layout: &RuntimeLayout,
    expected: &Expectations,
    c: &Candidate,
    pool: &Pool,
) -> std::result::Result<(), (Refusal, String)> {
    if layout.pool_bytes == 0
        || pool.bytes.len() != layout.pool_bytes
        || !span(pool.address, layout.pool_bytes)
    {
        return Err(fail(
            Refusal::Pool,
            "provided pool length/base or layout differs",
        ));
    }
    if pool
        .repeat
        .as_ref()
        .is_some_and(|repeat| repeat != &pool.bytes)
    {
        return Err(fail(Refusal::Repeat, "provided pool repeat differs"));
    }
    if scalar(layout, &c.bytes, "private_text", 8)? != pool.address
        || scalar(layout, &pool.bytes, "pool.owner", 8)? != c.address
        || Some(scalar(layout, &pool.bytes, "pool.services", 8)?) != expected.private_services
    {
        return Err(fail(
            Refusal::Pool,
            "pool is not bound to provided Runtime/services",
        ));
    }
    if scalar(layout, &pool.bytes, "pool.ready", 4)? > 1
        || scalar(layout, &pool.bytes, "pool.failed", 4)? > 1
    {
        return Err(fail(Refusal::Pool, "invalid pool ready/failed"));
    }
    let runtime_end = c
        .address
        .checked_add(layout.runtime_bytes as u64)
        .ok_or_else(|| fail(Refusal::Pointer, "Runtime address overflow"))?;
    let pool_end = pool
        .address
        .checked_add(layout.pool_bytes as u64)
        .ok_or_else(|| fail(Refusal::Pointer, "pool address overflow"))?;
    if pool.address < runtime_end && c.address < pool_end {
        return Err(fail(Refusal::Pool, "separate supplied allocations overlap"));
    }
    let descriptors = layout
        .field("pool.descriptors")
        .map_err(|e| fail(Refusal::Layout, e.to_string()))?;
    let buffers = layout
        .field("pool.buffers")
        .map_err(|e| fail(Refusal::Layout, e.to_string()))?;
    if descriptors.bytes != layout.pool_count * layout.descriptor_bytes
        || buffers.bytes != layout.pool_count * layout.buffer_bytes
    {
        return Err(fail(Refusal::Layout, "pool array extent differs"));
    }
    for i in 0..layout.pool_count {
        let offset = descriptors.offset + i * layout.descriptor_bytes;
        let d = pool
            .bytes
            .get(offset..offset + layout.descriptor_bytes)
            .ok_or_else(|| fail(Refusal::Pool, "missing descriptor"))?;
        let read4 =
            |off: usize| u32::from_le_bytes(d[off..off + 4].try_into().expect("four bytes"));
        let length = read4(layout.descriptor_length_offset) as usize;
        let style = read4(layout.descriptor_style_offset);
        let pointer = u64::from_le_bytes(
            d[layout.descriptor_buffer_offset..layout.descriptor_buffer_offset + 8]
                .try_into()
                .expect("eight bytes"),
        );
        let start = buffers.offset + i * layout.buffer_bytes;
        let expected_pointer = pool
            .address
            .checked_add(start as u64)
            .ok_or_else(|| fail(Refusal::Pointer, "pool buffer address overflow"))?;
        if pointer != expected_pointer
            || length >= layout.buffer_bytes
            || !matches!(style, 3 | 4)
            || read4(layout.descriptor_reserved_offset) != 0
            || read4(layout.descriptor_tail_offset) != 0
            || pool.bytes.get(start + length) != Some(&0)
        {
            return Err(fail(
                Refusal::Pool,
                format!("descriptor {i} violates the private ownership/length contract"),
            ));
        }
    }
    Ok(())
}

/// No physical backend is authorized by these offline verification routines.
pub fn capture_from_device(_selector: &str) -> Result<()> {
    Err(Error::Plan(
        "runtime physical mapping and allocation lease are unproven; no device request sent".into(),
    ))
}

pub fn preflight(output: &Path) -> Result<()> {
    if output.symlink_metadata().is_ok() {
        return Err(Error::Exists(output.to_path_buf()));
    }
    if output.file_name().is_none() {
        return Err(Error::Plan("invalid output directory".into()));
    }
    Ok(())
}
pub fn write_outputs(output: &Path, report: &Report, snapshot: &Snapshot) -> Result<PathBuf> {
    preflight(output)?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let stage = tempfile::Builder::new()
        .prefix(".nloader-trace-")
        .tempdir_in(parent)?;
    for (name, data) in [
        ("report.json", serde_json::to_vec_pretty(report)?),
        ("provided-snapshot.json", serde_json::to_vec(snapshot)?),
    ] {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(stage.path().join(name))?;
        f.write_all(&data)?;
        f.sync_all()?;
    }
    fs::create_dir(output)?;
    let result = (|| -> std::io::Result<()> {
        for name in ["report.json", "provided-snapshot.json"] {
            fs::rename(stage.path().join(name), output.join(name))?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(output);
        return Err(error.into());
    }
    Ok(output.join("report.json"))
}

/// The Python collector's supplied JSON is evidence context, not an oracle:
/// decode fields from the raw file; never copy its decoded result into ours.
pub fn from_qemu_result(
    result: &serde_json::Value,
    runtime: Vec<u8>,
    pool: Option<Vec<u8>>,
) -> Result<Snapshot> {
    if runtime.len() > MAX_SNAPSHOT_BYTES
        || pool.as_ref().is_some_and(|p| p.len() > MAX_SNAPSHOT_BYTES)
        || runtime
            .len()
            .checked_add(pool.as_ref().map_or(0, Vec::len))
            .is_none_or(|n| n > MAX_SNAPSHOT_BYTES)
    {
        return Err(Error::Plan(
            "supplied Runtime/pool exceeds the offline byte budget".into(),
        ));
    }
    let r = result
        .get("runtime_snapshot")
        .ok_or_else(|| Error::Plan("missing provided QEMU runtime record".into()))?;
    if r.get("found").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(Error::Plan(
            "provided QEMU record has no captured runtime".into(),
        ));
    }
    let address = |object: &serde_json::Value, name: &str| -> Result<u64> {
        let value = object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::Plan(format!("missing supplied {name}")))?;
        let text = value
            .strip_prefix("0x")
            .ok_or_else(|| Error::Plan("provided address must be hexadecimal".into()))?;
        u64::from_str_radix(text, 16).map_err(|_| Error::Plan("invalid provided address".into()))
    };
    let names = r
        .get("named_candidates")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::Plan("missing supplied named candidates".into()))?;
    if names.len() != 1 {
        return Err(Error::Plan(format!(
            "ambiguous or absent provided named candidates: {}",
            names.len()
        )));
    }
    let id = r
        .get("registry_id")
        .and_then(serde_json::Value::as_u64)
        .and_then(|id| u32::try_from(id).ok())
        .ok_or_else(|| Error::Plan("invalid supplied registry ID".into()))?;
    let base = address(r, "address")?;
    if names[0]
        .get("registry_id")
        .and_then(serde_json::Value::as_u64)
        != Some(u64::from(id))
        || address(&names[0], "address")? != base
    {
        return Err(Error::Plan(
            "provided named candidate does not match the selected Runtime".into(),
        ));
    }
    if r.get("snapshot_sha256").and_then(serde_json::Value::as_str)
        != Some(profile::sha256(&runtime).as_str())
        || r.get("bytes").and_then(serde_json::Value::as_u64) != Some(runtime.len() as u64)
    {
        return Err(Error::Plan(
            "provided QEMU Runtime checksum/length differs".into(),
        ));
    }
    let pool = if let Some(bytes) = pool {
        let p = result
            .get("followed_snapshot")
            .ok_or_else(|| Error::Plan("missing supplied pool record".into()))?;
        if p.get("snapshot_sha256").and_then(serde_json::Value::as_str)
            != Some(profile::sha256(&bytes).as_str())
            || p.get("bytes").and_then(serde_json::Value::as_u64) != Some(bytes.len() as u64)
        {
            return Err(Error::Plan(
                "provided QEMU pool checksum/length differs".into(),
            ));
        }
        Some(Pool {
            address: address(p, "address")?,
            bytes,
            repeat: None,
        })
    } else {
        None
    };
    Ok(Snapshot {
        schema: 1,
        source: Source::QemuProvided,
        candidates: vec![Candidate {
            registry_id: id,
            address: base,
            bytes: runtime,
            repeat: None,
            pool,
        }],
    })
}

/// Failed input parsing preserves supplied Runtime/pool bytes, while opaque
/// metadata remains at its referenced source. It never manufactures a layout.
pub fn write_input_failure(
    output: &Path,
    reason: &str,
    sources: &[PathBuf],
    raw: &[(String, Vec<u8>)],
) -> Result<PathBuf> {
    preflight(output)?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let stage = tempfile::Builder::new()
        .prefix(".nloader-trace-refused-")
        .tempdir_in(parent)?;
    let report = serde_json::json!({"schema":1,"status":"refused","provided":true,"replayed":true,"physical_fresh":false,"live_pointer_reads":false,"reason":reason,"input_sources":sources,"retained_raw":raw.iter().enumerate().map(|(index,(source,bytes))|serde_json::json!({"source":source,"output":format!("provided-raw-{index}.bin"),"bytes":bytes.len(),"sha256":profile::sha256(bytes)})).collect::<Vec<_>>(),"limitation":LIMITATION});
    let report_bytes = serde_json::to_vec_pretty(&report)?;
    let mut names = vec!["report.json".to_owned()];
    fs::write(stage.path().join("report.json"), report_bytes)?;
    for (index, (_, bytes)) in raw.iter().enumerate() {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Plan("refusal retention byte bound exceeded".into()));
        }
        let name = format!("provided-raw-{index}.bin");
        fs::write(stage.path().join(&name), bytes)?;
        names.push(name);
    }
    fs::create_dir(output)?;
    let result = (|| -> std::io::Result<()> {
        for name in names {
            fs::rename(stage.path().join(&name), output.join(name))?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(output);
        return Err(error.into());
    }
    Ok(output.join("report.json"))
}

/// Retain bounded, explicitly provided source artifacts independently of
/// normalization, so an ambiguous/refused result cannot erase its inputs.
pub fn retain_sources(output: &Path, sources: &[(String, PathBuf, usize)]) -> Result<()> {
    let mut manifest = Vec::new();
    for (index, (role, path, limit)) in sources.iter().enumerate() {
        let entry = (|| -> Result<serde_json::Value> {
            let metadata = fs::metadata(path)?;
            if !metadata.is_file() || metadata.len() > *limit as u64 {
                return Err(Error::Plan("source exceeds its retention bound".into()));
            }
            let bytes = fs::read(path)?;
            if bytes.len() > *limit {
                return Err(Error::Plan("source grew beyond its retention bound".into()));
            }
            let filename = format!("provided-source-{index}.bin");
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output.join(&filename))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(
                serde_json::json!({"role":role,"source":path,"retained":filename,"bytes":bytes.len(),"sha256":profile::sha256(&bytes),"provided":true,"replayed":true,"physical_fresh":false}),
            )
        })();
        manifest.push(match entry{Ok(record)=>record,Err(error)=>serde_json::json!({"role":role,"source":path,"retained":null,"reason":error.to_string(),"provided":true,"replayed":true,"physical_fresh":false})});
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("provided-sources.json"))?;
    serde_json::to_writer_pretty(&mut file, &manifest)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(layout: &RuntimeLayout, bytes: &mut [u8], name: &str, value: u64) {
        let f = layout.field(name).unwrap();
        bytes[f.offset..f.offset + f.bytes].copy_from_slice(&value.to_le_bytes()[..f.bytes]);
    }
    fn material() -> (RuntimeLayout, Expectations, Snapshot) {
        // An invented layout for parser behavior. These are not Core offsets;
        // the separate AArch64 object tests establish the actual C geometry.
        let mut fields = std::collections::BTreeMap::new();
        for (name, offset, bytes) in [
            ("worker.id", 0, 4),
            ("worker.name", 16, 8),
            ("worker.self", 24, 8),
            ("worker.callback", 32, 8),
            ("worker.flag", 40, 4),
            ("load.svc", 48, 8),
            ("load.state", 56, 4),
            ("load.ready", 60, 4),
            ("load.last_result", 64, 4),
            ("load.stage", 68, 4),
            ("trace.count", 72, 8),
            ("trace.entries", 80, 128),
            ("directory.count", 208, 4),
            ("directory.usable", 212, 4),
            ("directory_result", 216, 4),
            ("checked", 220, 4),
            ("check_result", 224, 4),
            ("path", 228, 32),
            ("program.prepared", 260, 4),
            ("program.entry_started", 264, 4),
            ("program.returned", 268, 4),
        ] {
            fields.insert(
                name.to_owned(),
                crate::build::layout::Field { offset, bytes },
            );
        }
        let layout = RuntimeLayout {
            schema: 1,
            target: "aarch64-none-elf",
            mode: profile::BuildMode::LoadOnly,
            feature_bits: 0,
            runtime_bytes: 512,
            pool_bytes: 0,
            registry_max_id: 768,
            trace_slots: 16,
            trace_entry_bytes: 8,
            descriptor_bytes: 0,
            descriptor_buffer_offset: 0,
            descriptor_length_offset: 0,
            descriptor_style_offset: 0,
            descriptor_reserved_offset: 0,
            descriptor_tail_offset: 0,
            pool_count: 0,
            buffer_bytes: 0,
            fields,
            object_sha256: "synthetic-layout".into(),
            definition_sha256: "synthetic".into(),
            headers_sha256: "synthetic".into(),
            config_sha256: "synthetic".into(),
            provided_layout: true,
            physical_fresh: false,
        };
        // All coordinates below are synthetic, not camera RAM/XIP addresses.
        let e = Expectations {
            schema: 1,
            candidate_eg_sha256: "12".repeat(32),
            proof_reference: "synthetic independent expectations".into(),
            worker_name: "NLOADER".into(),
            callback: 0x1000,
            services: 0x2000,
            private_services: None,
        };
        let mut bytes = vec![0; layout.runtime_bytes];
        put(&layout, &mut bytes, "worker.id", 27);
        put(&layout, &mut bytes, "worker.flag", 28);
        put(&layout, &mut bytes, "worker.self", 0x3000);
        put(&layout, &mut bytes, "worker.callback", e.callback);
        put(&layout, &mut bytes, "load.svc", e.services);
        put(&layout, &mut bytes, "load.ready", 1);
        let name = layout.field("worker.name").unwrap();
        bytes[name.offset..name.offset + 8].copy_from_slice(b"NLOADER\0");
        let capture = Snapshot {
            schema: 1,
            source: Source::Provided,
            candidates: vec![Candidate {
                registry_id: 27,
                address: 0x3000,
                bytes,
                repeat: None,
                pool: None,
            }],
        };
        (layout, e, capture)
    }
    #[test]
    #[ignore = "requires the local M1 profile and AArch64 Clang; no device access"]
    fn actual_compiled_private_pool_has_strict_owner_and_buffer_bounds() {
        let d = tempfile::tempdir().unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
        let profile = crate::read_profile(
            &root.join("build/qemu-platform/z8-qemu-m1-private-text-clean-entry-a.toml"),
        )
        .unwrap();
        let layout = crate::build::layout::compile(
            &profile,
            profile::BuildMode::LoadOnly,
            std::ffi::OsStr::new("clang"),
            &d.path().join("layout"),
        )
        .unwrap()
        .layout;
        let (_, mut e, mut snapshot) = material();
        e.private_services = Some(0x2200);
        let c = &mut snapshot.candidates[0];
        c.bytes = vec![0; layout.runtime_bytes];
        for (name, value) in [
            ("worker.id", 27),
            ("worker.self", c.address),
            ("worker.callback", e.callback),
            ("worker.flag", 28),
            ("load.svc", e.services),
            ("load.ready", 1),
            ("private_text", 0x8000),
        ] {
            put(&layout, &mut c.bytes, name, value);
        }
        let name = layout.field("worker.name").unwrap();
        c.bytes[name.offset..name.offset + 8].copy_from_slice(b"NLOADER\0");
        let mut p = Pool {
            address: 0x8000,
            bytes: vec![0; layout.pool_bytes],
            repeat: None,
        };
        for (name, value) in [
            ("pool.owner", c.address),
            ("pool.services", e.private_services.unwrap()),
            ("pool.ready", 1),
        ] {
            put(&layout, &mut p.bytes, name, value);
        }
        let descriptors = layout.field("pool.descriptors").unwrap().offset;
        let buffers = layout.field("pool.buffers").unwrap().offset;
        for i in 0..layout.pool_count {
            let off = descriptors + i * layout.descriptor_bytes;
            let pointer = p.address + (buffers + i * layout.buffer_bytes) as u64;
            p.bytes
                [off + layout.descriptor_buffer_offset..off + layout.descriptor_buffer_offset + 8]
                .copy_from_slice(&pointer.to_le_bytes());
            p.bytes[off + layout.descriptor_style_offset..off + layout.descriptor_style_offset + 4]
                .copy_from_slice(&4u32.to_le_bytes());
        }
        c.pool = Some(p);
        assert_eq!(
            verify(&layout, &e, &snapshot).status,
            Status::MatchedProvided
        );
        for case in 0..5 {
            let mut bad = snapshot.clone();
            let pool = bad.candidates[0].pool.as_mut().unwrap();
            match case {
                0 => put(&layout, &mut pool.bytes, "pool.owner", 0),
                1 => pool.bytes.pop().map(|_| ()).unwrap(),
                2 => {
                    let off = descriptors + layout.descriptor_length_offset;
                    pool.bytes[off..off + 4]
                        .copy_from_slice(&(layout.buffer_bytes as u32).to_le_bytes());
                }
                3 => {
                    let off = descriptors + layout.descriptor_buffer_offset;
                    pool.bytes[off..off + 8].copy_from_slice(&0u64.to_le_bytes());
                }
                _ => put(&layout, &mut pool.bytes, "pool.failed", 1),
            };
            assert_ne!(verify(&layout, &e, &bad).status, Status::MatchedProvided);
        }
    }

    #[test]
    fn physical_backend_refuses_without_any_transport() {
        assert!(capture_from_device("not-a-device").is_err());
    }
    #[test]
    fn provided_trace_owner_sequence_wrap_partial_and_budget_are_checked() {
        let d = tempfile::tempdir().unwrap();
        let (layout, e, capture) = material();
        let report = verify(&layout, &e, &capture);
        assert_eq!(report.status, Status::MatchedProvided);
        assert!(
            !report.physical_fresh
                && report.provided
                && report.replayed
                && !report.live_pointer_reads
        );
        for case in 0..10 {
            let mut bad = capture.clone();
            match case {
                0 => bad.candidates[0].bytes.pop().map(|_| ()).unwrap(),
                1 => put(&layout, &mut bad.candidates[0].bytes, "worker.id", 28),
                2 => put(&layout, &mut bad.candidates[0].bytes, "worker.self", 0x3008),
                3 => put(
                    &layout,
                    &mut bad.candidates[0].bytes,
                    "worker.callback",
                    0x1004,
                ),
                4 => put(&layout, &mut bad.candidates[0].bytes, "load.svc", 0x2008),
                5 => bad.candidates.push(bad.candidates[0].clone()),
                6 => bad.candidates[0].repeat = Some(vec![1; layout.runtime_bytes]),
                7 => bad.candidates[0].address = u64::MAX - 7,
                8 => bad.candidates[0].bytes = vec![0; MAX_SNAPSHOT_BYTES + 1],
                _ => put(&layout, &mut bad.candidates[0].bytes, "trace.count", 1),
            };
            let report = verify(&layout, &e, &bad);
            assert_ne!(report.status, Status::MatchedProvided, "case {case}");
            assert!(report.refusal.is_some());
            if case == 0 {
                let out = d.path().join("failed");
                let path = write_outputs(&out, &report, &bad).unwrap();
                assert!(path.exists());
                let raw: Snapshot =
                    serde_json::from_slice(&fs::read(out.join("provided-snapshot.json")).unwrap())
                        .unwrap();
                assert_eq!(raw.candidates[0].bytes, bad.candidates[0].bytes);
                assert!(write_outputs(&out, &report, &bad).is_err());
            }
        }
        let mut malformed_layout = layout.clone();
        malformed_layout
            .fields
            .get_mut("trace.entries")
            .unwrap()
            .offset = usize::MAX;
        assert_eq!(
            verify(&malformed_layout, &e, &capture).refusal,
            Some(Refusal::Layout)
        );
        let mut partial = capture.clone();
        put(&layout, &mut partial.candidates[0].bytes, "load.ready", 0);
        assert_eq!(
            verify(&layout, &e, &partial).status,
            Status::PartialProvided
        );
        let mut wrap = capture.clone();
        let count = 0x0100_0005u64;
        put(&layout, &mut wrap.candidates[0].bytes, "trace.count", count);
        let entries = layout.field("trace.entries").unwrap();
        for seq in count - 15..=count {
            let slot = ((seq - 1) & 15) as usize;
            let offset = entries.offset + slot * 8;
            let tag = ((seq & 0x00ff_ffff) as u32) << 8 | u32::from(b'F');
            wrap.candidates[0].bytes[offset..offset + 4].copy_from_slice(&tag.to_le_bytes());
            wrap.candidates[0].bytes[offset + 4..offset + 8]
                .copy_from_slice(&(-2i32).to_le_bytes());
        }
        let report = verify(&layout, &e, &wrap);
        assert_eq!(report.status, Status::MatchedProvided);
        let decoded = report.decoded.unwrap();
        assert_eq!(decoded.trace.len(), 16);
        assert_eq!(decoded.trace[0].logical_sequence, count - 15);
        assert_eq!(decoded.trace[15].value, -2);
    }
}
