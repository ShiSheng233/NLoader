//! Nikon USB identification and bounded Z8 C3.11 memory collection.
//! Identity reads do not enter maintenance mode. Memory collection owns and
//! cleans up its own sessions and never exposes memory writes or shell commands.
mod memory;
mod memory_wire;
mod protocol;
mod usb;

pub use memory::*;

pub use protocol::{parse_device_info, DeviceInfo};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use usb::{capture_identity, enumerate};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("USB: {0}")]
    Usb(#[from] rusb::Error),
    #[error("invalid PTP data: {0}")]
    Protocol(String),
    #[error("camera selector {0:?} did not match a connected Nikon device")]
    NotFound(String),
    #[error("camera selector {0:?} is ambiguous; use the USB identifier")]
    Ambiguous(String),
    #[error("camera rejected GetDeviceInfo: {0:#06x}")]
    Rejected(u16),
    #[error("capture failed: {capture}; USB cleanup failed: {cleanup}")]
    Cleanup { capture: String, cleanup: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CameraDevice {
    /// Ephemeral USB identity, valid only while this device remains connected.
    pub id: String,
    pub bus: u8,
    pub address: u8,
    pub vendor_id: u16,
    pub product_id: u16,
}

pub fn select_device<'a>(devices: &'a [CameraDevice], selector: &str) -> Result<&'a CameraDevice> {
    let matches: Vec<_> = devices
        .iter()
        .filter(|device| device.id == selector || selector == "auto")
        .collect();
    match matches.as_slice() {
        [device] => Ok(device),
        [] => Err(Error::NotFound(selector.into())),
        _ => Err(Error::Ambiguous(selector.into())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureOrigin {
    UsbDevice,
    SyntheticFixture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupReport {
    pub interface_released: bool,
    pub maintenance_mode_entered: bool,
    pub session_opened: bool,
}

/// Raw evidence is retained, so replay never trusts separately edited identity fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CameraSnapshot {
    pub schema: u32,
    pub device: CameraDevice,
    pub origin: CaptureOrigin,
    pub device_info: DeviceInfo,
    pub raw_device_info: Vec<u8>,
    pub sha256: String,
    pub cleanup: CleanupReport,
}

impl CameraSnapshot {
    pub fn from_raw(
        device: CameraDevice,
        raw: Vec<u8>,
        origin: CaptureOrigin,
        cleanup: CleanupReport,
    ) -> Result<Self> {
        let device_info = parse_device_info(&raw)?;
        Ok(Self {
            schema: 1,
            device,
            origin,
            device_info,
            sha256: fingerprint(&raw),
            raw_device_info: raw,
            cleanup,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || fingerprint(&self.raw_device_info) != self.sha256
            || parse_device_info(&self.raw_device_info)? != self.device_info
        {
            return Err(Error::Protocol(
                "snapshot identity or fingerprint differs from raw evidence".into(),
            ));
        }
        if !self.cleanup.interface_released
            || self.cleanup.maintenance_mode_entered
            || self.cleanup.session_opened
        {
            return Err(Error::Protocol(
                "snapshot cleanup does not match the identity-only capture rule".into(),
            ));
        }
        Ok(())
    }
}

pub fn fingerprint(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Narrow seam for transport tests and future supported transports. Implementors
/// must restrict the request to standard GetDeviceInfo outside a PTP session.
pub trait IdentityTransport {
    fn read_device_info(&mut self) -> Result<Vec<u8>>;
    fn release(&mut self) -> Result<()>;
}

pub fn capture_with_transport(
    device: CameraDevice,
    transport: &mut impl IdentityTransport,
    origin: CaptureOrigin,
) -> Result<CameraSnapshot> {
    let capture = transport.read_device_info().and_then(|raw| {
        CameraSnapshot::from_raw(
            device,
            raw,
            origin,
            CleanupReport {
                interface_released: true,
                maintenance_mode_entered: false,
                session_opened: false,
            },
        )
    });
    let cleanup = transport.release();
    match (capture, cleanup) {
        (Ok(snapshot), Ok(())) => Ok(snapshot),
        (Err(error), Ok(())) => Err(error),
        (result, Err(cleanup)) => Err(Error::Cleanup {
            capture: result.err().map_or_else(
                || "successful identity read".into(),
                |error| error.to_string(),
            ),
            cleanup: cleanup.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct FailingTransport {
        released: bool,
        cleanup_fails: bool,
    }
    impl IdentityTransport for FailingTransport {
        fn read_device_info(&mut self) -> Result<Vec<u8>> {
            Ok(vec![0])
        }
        fn release(&mut self) -> Result<()> {
            self.released = true;
            if self.cleanup_fails {
                Err(Error::Usb(rusb::Error::NoDevice))
            } else {
                Ok(())
            }
        }
    }
    fn device() -> CameraDevice {
        CameraDevice {
            id: "usb:001:002".into(),
            bus: 1,
            address: 2,
            vendor_id: 0x04b0,
            product_id: 0,
        }
    }
    #[test]
    fn releases_interface_after_parse_failure_and_reports_cleanup_failure() {
        for cleanup_fails in [false, true] {
            let mut transport = FailingTransport {
                released: false,
                cleanup_fails,
            };
            let result =
                capture_with_transport(device(), &mut transport, CaptureOrigin::SyntheticFixture);
            assert!(transport.released);
            assert!(result.is_err());
            assert_eq!(matches!(result, Err(Error::Cleanup { .. })), cleanup_fails);
        }
    }
    #[test]
    fn multiple_cameras_require_explicit_selection() {
        let first = device();
        let mut second = first.clone();
        second.id = "usb:001:003".into();
        second.address = 3;
        let devices = [first, second];
        assert!(matches!(
            select_device(&devices, "auto"),
            Err(Error::Ambiguous(_))
        ));
        assert_eq!(select_device(&devices, "usb:001:003").unwrap().address, 3);
        assert!(select_device(&devices, "missing").is_err());
    }
}
