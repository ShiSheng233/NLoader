//! Bounded collection using explicit, firmware-verified read windows.
//! Callers must verify the windows against the matching official firmware.
use crate::memory_wire::*;
use crate::{
    enumerate, fingerprint, parse_device_info, select_device, CameraDevice, CaptureOrigin,
    DeviceInfo, Error, Result,
};
use serde::{Deserialize, Serialize};

mod evidence;

pub const MEMORY_RULE_VERSION: &str = "z8-c3.11-initialized-ram-v1";
pub const MAX_MEMORY_CAPTURE_BYTES: u32 = 64 * 1024;
const MAX_REQUESTS: usize = 64;
const CHUNK_BYTES: u32 = 1024;
const OK: u16 = 0x2001;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryReadRequest {
    pub label: String,
    pub address: u64,
    pub length: u32,
}

pub type MemoryReadWindow = nloader_profile::AddressRange;

pub fn validate_memory_requests(
    requests: &[MemoryReadRequest],
    windows: &[MemoryReadWindow],
) -> Result<()> {
    if windows.is_empty()
        || windows.len() > MAX_REQUESTS
        || windows
            .iter()
            .any(|window| window.start == 0 || window.start >= window.end)
        || windows.windows(2).any(|pair| pair[0].end > pair[1].start)
    {
        return Err(Error::Protocol(
            "memory capture requires ordered, non-overlapping read windows".into(),
        ));
    }
    if requests.is_empty() || requests.len() > MAX_REQUESTS {
        return Err(Error::Protocol(
            "memory capture requires 1..=64 requests".into(),
        ));
    }
    let mut total = 0u32;
    for request in requests {
        if request.label.is_empty() || request.label.len() > 128 {
            return Err(Error::Protocol(
                "memory request label must contain 1..=128 bytes".into(),
            ));
        }
        let end = request
            .address
            .checked_add(u64::from(request.length))
            .ok_or_else(|| Error::Protocol("memory address overflow".into()))?;
        let allowed = windows
            .iter()
            .any(|window| request.address >= window.start && end <= window.end);
        if request.length == 0 || !allowed {
            return Err(Error::Protocol(format!(
                "memory request {:?} is outside the verified initialized-data windows",
                request.label
            )));
        }
        total = total
            .checked_add(request.length)
            .ok_or_else(|| Error::Protocol("capture length overflow".into()))?;
        if total > MAX_MEMORY_CAPTURE_BYTES {
            return Err(Error::Protocol(
                "memory capture exceeds 64 KiB (128 KiB with consistency reads)".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryReply {
    pub transaction_id: u32,
    pub response_code: u16,
    pub parameters: Vec<u32>,
    pub data: Vec<u8>,
}

/// Each call must complete one request and consume its response, or return an
/// error. Any error invalidates the stream; collection never retries on it.
pub trait MemoryTransport {
    fn transact(
        &mut self,
        transaction_id: u32,
        operation: u16,
        parameters: &[u32],
    ) -> Result<MemoryReply>;
    fn release(&mut self) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryTransaction {
    pub transaction_id: u32,
    pub operation: u16,
    pub parameters: Vec<u32>,
    pub reply: Option<MemoryReply>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionOwnership {
    NotOpened,
    Owned,
    AlreadyOpen,
    Unknown,
    CloseAcknowledged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryCleanup {
    pub standard_session: SessionOwnership,
    pub maintenance_session: SessionOwnership,
    pub standard_close_attempted: bool,
    pub maintenance_close_attempted: bool,
    pub interface_released: bool,
    pub transport_usable: bool,
    pub errors: Vec<String>,
    /// F002 returns an acknowledgement without exposing every downstream
    /// cleanup result. Returning to the prior UI is not proven by this report.
    pub device_state_restored_verified: bool,
}
impl Default for MemoryCleanup {
    fn default() -> Self {
        Self {
            standard_session: SessionOwnership::NotOpened,
            maintenance_session: SessionOwnership::NotOpened,
            standard_close_attempted: false,
            maintenance_close_attempted: false,
            interface_released: false,
            transport_usable: true,
            errors: Vec::new(),
            device_state_restored_verified: false,
        }
    }
}
impl MemoryCleanup {
    pub fn acknowledged(&self) -> bool {
        self.interface_released
            && self.errors.is_empty()
            && matches!(
                self.standard_session,
                SessionOwnership::NotOpened | SessionOwnership::CloseAcknowledged
            )
            && matches!(
                self.maintenance_session,
                SessionOwnership::NotOpened | SessionOwnership::CloseAcknowledged
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySegment {
    pub request_index: usize,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub repeat_sha256: String,
    pub first_transaction_id: u32,
    pub repeat_transaction_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryCapture {
    pub schema: u32,
    pub rule: String,
    pub device: CameraDevice,
    pub origin: CaptureOrigin,
    pub identity: Option<DeviceInfo>,
    pub raw_device_info: Vec<u8>,
    pub identity_sha256: Option<String>,
    pub requests: Vec<MemoryReadRequest>,
    pub windows: Vec<MemoryReadWindow>,
    pub segments: Vec<MemorySegment>,
    pub transactions: Vec<MemoryTransaction>,
    pub failure: Option<String>,
    pub cleanup: MemoryCleanup,
}

fn is_target(identity: &DeviceInfo) -> bool {
    matches!(identity.model.as_str(), "Z 8" | "Z8") && identity.device_version == "V3.11"
}

pub fn capture_memory(
    selector: &str,
    requests: &[MemoryReadRequest],
    windows: &nloader_profile::VerifiedReadWindows,
) -> Result<MemoryCapture> {
    let windows = windows.windows();
    validate_memory_requests(requests, windows)?;
    let devices = enumerate()?;
    let device = select_device(&devices, selector)?.clone();
    let mut transport = crate::usb::UsbIdentity::open(&device)?;
    capture_memory_with_transport(
        device,
        &mut transport,
        requests,
        windows,
        CaptureOrigin::UsbDevice,
    )
}

pub fn capture_memory_with_transport(
    device: CameraDevice,
    transport: &mut impl MemoryTransport,
    requests: &[MemoryReadRequest],
    windows: &[MemoryReadWindow],
    origin: CaptureOrigin,
) -> Result<MemoryCapture> {
    if let Err(error) = validate_memory_requests(requests, windows) {
        transport.release()?;
        return Err(error);
    }
    let report = MemoryCapture {
        schema: 2,
        rule: MEMORY_RULE_VERSION.into(),
        device,
        origin,
        identity: None,
        raw_device_info: Vec::new(),
        identity_sha256: None,
        requests: requests.to_vec(),
        windows: windows.to_vec(),
        segments: Vec::new(),
        transactions: Vec::new(),
        failure: None,
        cleanup: MemoryCleanup::default(),
    };
    let mut session = Collector {
        transport,
        report,
        next_transaction: 1,
    };
    if let Err(error) = session.collect() {
        session.report.failure = Some(error.to_string());
    }
    session.cleanup();
    Ok(session.report)
}

struct Collector<'a, T> {
    transport: &'a mut T,
    report: MemoryCapture,
    next_transaction: u32,
}
impl<T: MemoryTransport> Collector<'_, T> {
    fn call(&mut self, operation: u16, parameters: &[u32]) -> Result<MemoryReply> {
        if !self.report.cleanup.transport_usable {
            return Err(Error::Protocol(
                "transport became unusable; no further camera command was sent".into(),
            ));
        }
        let transaction = if self.report.cleanup.standard_session == SessionOwnership::Owned {
            let next = self.next_transaction;
            self.next_transaction += 1;
            next
        } else {
            0
        };
        let result = self
            .transport
            .transact(transaction, operation, parameters)
            .and_then(|reply| {
                if reply.transaction_id != transaction {
                    return Err(Error::Protocol(
                        "response transaction does not match request".into(),
                    ));
                }
                Ok(reply)
            });
        let (reply, error) = match &result {
            Ok(reply) => (Some(reply.clone()), None),
            Err(error) => {
                self.report.cleanup.transport_usable = false;
                (None, Some(error.to_string()))
            }
        };
        self.report.transactions.push(MemoryTransaction {
            transaction_id: transaction,
            operation,
            parameters: parameters.to_vec(),
            reply,
            error,
        });
        result
    }

    fn collect(&mut self) -> Result<()> {
        let reply = self.call(0x1001, &[])?;
        check_standard(&reply)?;
        self.report.raw_device_info = reply.data;
        self.report.identity_sha256 = Some(fingerprint(&self.report.raw_device_info));
        let identity = parse_device_info(&self.report.raw_device_info)?;
        let target = is_target(&identity) && self.report.device.vendor_id == 0x04b0;
        self.report.identity = Some(identity);
        if !target {
            return Err(Error::Protocol(
                "memory collection requires Nikon Z8 V3.11".into(),
            ));
        }

        self.report.cleanup.standard_session = SessionOwnership::Unknown;
        let reply = self.call(OPEN_SESSION, &[1])?;
        if reply.response_code == 0x201e && reply.data.is_empty() {
            self.report.cleanup.standard_session = SessionOwnership::AlreadyOpen;
            return Err(Error::Protocol(
                "standard session is already open; ownership was not acquired".into(),
            ));
        }
        check_standard(&reply)?;
        require_no_data(&reply)?;
        self.report.cleanup.standard_session = SessionOwnership::Owned;

        self.report.cleanup.maintenance_session = SessionOwnership::Unknown;
        let reply = self.call(CONTROL, &[OPEN_INTERNAL, 0, 0, 0, 0])?;
        if internal_already_open(&reply) {
            self.report.cleanup.maintenance_session = SessionOwnership::AlreadyOpen;
            return Err(Error::Protocol(
                "maintenance session is already open; it will not be adopted or closed".into(),
            ));
        }
        check_internal(&reply)?;
        require_no_data(&reply)?;
        self.report.cleanup.maintenance_session = SessionOwnership::Owned;

        for index in 0..self.report.requests.len() {
            let request = self.report.requests[index].clone();
            let mut offset = 0;
            while offset < request.length {
                let length = (request.length - offset).min(CHUNK_BYTES);
                let address = request.address + u64::from(offset);
                let first = self.read(address, length)?;
                let repeated = self.read(address, length)?;
                if first.data != repeated.data {
                    return Err(Error::Protocol(format!(
                        "memory changed between consistency reads at {address:#x}"
                    )));
                }
                self.report.segments.push(MemorySegment {
                    request_index: index,
                    address,
                    sha256: fingerprint(&first.data),
                    repeat_sha256: fingerprint(&repeated.data),
                    bytes: first.data,
                    first_transaction_id: first.transaction_id,
                    repeat_transaction_id: repeated.transaction_id,
                });
                offset += length;
            }
        }
        Ok(())
    }

    fn read(&mut self, address: u64, length: u32) -> Result<MemoryReply> {
        let reply = self.call(READ, &read_parameters(address, length))?;
        check_internal(&reply)?;
        if reply.data.len() != length as usize {
            return Err(Error::Protocol(format!(
                "memory read returned {} bytes, expected {length}",
                reply.data.len()
            )));
        }
        Ok(reply)
    }

    fn cleanup(&mut self) {
        if self.report.cleanup.maintenance_session == SessionOwnership::Owned
            && self.report.cleanup.transport_usable
        {
            self.report.cleanup.maintenance_close_attempted = true;
            let result = self
                .call(CONTROL, &[CLOSE_INTERNAL, 0, 0, 0, 0])
                .and_then(|reply| {
                    check_internal(&reply)?;
                    require_no_data(&reply)
                });
            match result {
                Ok(()) => {
                    self.report.cleanup.maintenance_session = SessionOwnership::CloseAcknowledged
                }
                Err(error) => {
                    self.report.cleanup.maintenance_session = SessionOwnership::Unknown;
                    self.report
                        .cleanup
                        .errors
                        .push(format!("maintenance close: {error}"));
                }
            }
        }
        if self.report.cleanup.standard_session == SessionOwnership::Owned
            && self.report.cleanup.transport_usable
        {
            self.report.cleanup.standard_close_attempted = true;
            let result = self.call(CLOSE_SESSION, &[]).and_then(|reply| {
                check_standard(&reply)?;
                require_no_data(&reply)
            });
            match result {
                Ok(()) => {
                    self.report.cleanup.standard_session = SessionOwnership::CloseAcknowledged
                }
                Err(error) => {
                    self.report.cleanup.standard_session = SessionOwnership::Unknown;
                    self.report
                        .cleanup
                        .errors
                        .push(format!("standard close: {error}"));
                }
            }
        }
        if !self.report.cleanup.transport_usable
            && matches!(
                self.report.cleanup.standard_session,
                SessionOwnership::Owned | SessionOwnership::Unknown
            )
        {
            self.report.cleanup.errors.push(
                "session cleanup was not confirmed because the transport became unusable".into(),
            );
        }
        match self.transport.release() {
            Ok(()) => self.report.cleanup.interface_released = true,
            Err(error) => self
                .report
                .cleanup
                .errors
                .push(format!("USB interface release: {error}")),
        }
    }
}

fn read_parameters(address: u64, length: u32) -> [u32; 5] {
    [
        READ_MEMORY,
        address as u32,
        (address >> 32) as u32,
        length,
        0,
    ]
}
fn check_standard(reply: &MemoryReply) -> Result<()> {
    if reply.response_code != OK || !reply.parameters.is_empty() {
        return Err(Error::Protocol(format!(
            "standard response rejected: outer={:#06x}, parameters={:?}",
            reply.response_code, reply.parameters
        )));
    }
    Ok(())
}
fn check_internal(reply: &MemoryReply) -> Result<()> {
    if reply.response_code != OK || reply.parameters != [u32::from(OK), 0, 0, 0, 0] {
        return Err(Error::Protocol(format!(
            "maintenance response rejected: outer={:#06x}, parameters={:?}",
            reply.response_code, reply.parameters
        )));
    }
    Ok(())
}
fn internal_already_open(reply: &MemoryReply) -> bool {
    reply.response_code == OK && reply.parameters == [0x201e, 0, 0, 0, 0] && reply.data.is_empty()
}
fn require_no_data(reply: &MemoryReply) -> Result<()> {
    if !reply.data.is_empty() {
        return Err(Error::Protocol(
            "unexpected data in session response".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
