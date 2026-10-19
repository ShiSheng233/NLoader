use crate::protocol::{decode_container, request, MAX_CONTAINER, OK};
use crate::{
    capture_with_transport, select_device, CameraDevice, CameraSnapshot, CaptureOrigin, Error,
    IdentityTransport, Result,
};
use rusb::{Context, DeviceHandle, Direction, TransferType, UsbContext};
use std::time::{Duration, Instant};

const NIKON_VENDOR: u16 = 0x04b0;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Enumerates descriptors without claiming interfaces or sending camera commands.
pub fn enumerate() -> Result<Vec<CameraDevice>> {
    let context = Context::new()?;
    let mut cameras = Vec::new();
    for device in context.devices()?.iter() {
        let descriptor = device.device_descriptor()?;
        if descriptor.vendor_id() != NIKON_VENDOR {
            continue;
        }
        cameras.push(CameraDevice {
            id: format!("usb:{:03}:{:03}", device.bus_number(), device.address()),
            bus: device.bus_number(),
            address: device.address(),
            vendor_id: descriptor.vendor_id(),
            product_id: descriptor.product_id(),
        });
    }
    cameras.sort_by_key(|device| (device.bus, device.address));
    Ok(cameras)
}

pub fn capture_identity(selector: &str) -> Result<CameraSnapshot> {
    let devices = enumerate()?;
    let selected = select_device(&devices, selector)?.clone();
    let mut transport = UsbIdentity::open(&selected)?;
    capture_with_transport(selected, &mut transport, CaptureOrigin::UsbDevice)
}

pub(crate) struct UsbIdentity {
    handle: DeviceHandle<Context>,
    interface: u8,
    input: u8,
    output: u8,
    released: bool,
}

impl UsbIdentity {
    pub(crate) fn open(target: &CameraDevice) -> Result<Self> {
        let context = Context::new()?;
        for device in context.devices()?.iter() {
            if device.bus_number() != target.bus || device.address() != target.address {
                continue;
            }
            let descriptor = device.device_descriptor()?;
            if descriptor.vendor_id() != target.vendor_id
                || descriptor.product_id() != target.product_id
            {
                continue;
            }
            let config = device.active_config_descriptor()?;
            for interface in config.interfaces() {
                for descriptor in interface.descriptors() {
                    if descriptor.class_code() != 6
                        || descriptor.sub_class_code() != 1
                        || descriptor.protocol_code() != 1
                        || descriptor.setting_number() != 0
                    {
                        continue;
                    }
                    let mut input = None;
                    let mut output = None;
                    for endpoint in descriptor.endpoint_descriptors() {
                        if endpoint.transfer_type() != TransferType::Bulk {
                            continue;
                        }
                        match endpoint.direction() {
                            Direction::In => input = Some(endpoint.address()),
                            Direction::Out => output = Some(endpoint.address()),
                        }
                    }
                    if let (Some(input), Some(output)) = (input, output) {
                        let handle = device.open()?;
                        handle.claim_interface(descriptor.interface_number())?;
                        return Ok(Self {
                            handle,
                            interface: descriptor.interface_number(),
                            input,
                            output,
                            released: false,
                        });
                    }
                }
            }
            return Err(Error::Protocol(
                "no default Still Image interface with bulk endpoints".into(),
            ));
        }
        Err(Error::NotFound(target.id.clone()))
    }

    fn remaining(deadline: Instant) -> Result<Duration> {
        // libusb treats a zero millisecond timeout as unlimited.
        deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .map(|duration| duration.max(Duration::from_millis(1)))
            .ok_or(Error::Usb(rusb::Error::Timeout))
    }

    fn read_container(&mut self, pending: &mut Vec<u8>, deadline: Instant) -> Result<Vec<u8>> {
        loop {
            if pending.len() >= 4 {
                let length = u32::from_le_bytes(pending[..4].try_into().unwrap()) as usize;
                if !(12..=MAX_CONTAINER).contains(&length) {
                    return Err(Error::Protocol(
                        "container exceeds size limit or lacks header".into(),
                    ));
                }
                if pending.len() >= length {
                    return Ok(pending.drain(..length).collect());
                }
            }
            let mut packet = [0u8; 16 * 1024];
            let count =
                self.handle
                    .read_bulk(self.input, &mut packet, Self::remaining(deadline)?)?;
            // Zero length USB packets are legal transfer terminators. The single
            // transaction deadline prevents an endless stream from hanging us.
            pending.extend_from_slice(&packet[..count]);
            if pending.len() > MAX_CONTAINER + packet.len() {
                return Err(Error::Protocol("receive buffer exceeds limit".into()));
            }
        }
    }
}

impl IdentityTransport for UsbIdentity {
    fn read_device_info(&mut self) -> Result<Vec<u8>> {
        let deadline = Instant::now() + TIMEOUT;
        let command = request();
        let written = self
            .handle
            .write_bulk(self.output, &command, Self::remaining(deadline)?)?;
        if written != command.len() {
            return Err(Error::Protocol("short GetDeviceInfo write".into()));
        }
        let mut pending = Vec::new();
        let mut data = None;
        loop {
            let raw = self.read_container(&mut pending, deadline)?;
            let container = decode_container(&raw)?;
            match container.kind {
                2 => {
                    if data.is_some() {
                        return Err(Error::Protocol("duplicate DeviceInfo data phase".into()));
                    }
                    data = Some(container.body.to_vec());
                }
                3 => {
                    if container.code != OK {
                        return Err(Error::Rejected(container.code));
                    }
                    if !pending.is_empty() {
                        return Err(Error::Protocol("unexpected data after response".into()));
                    }
                    return data
                        .ok_or_else(|| Error::Protocol("missing DeviceInfo data phase".into()));
                }
                _ => unreachable!(),
            }
        }
    }

    fn release(&mut self) -> Result<()> {
        if !self.released {
            self.handle.release_interface(self.interface)?;
            self.released = true;
        }
        Ok(())
    }
}

impl crate::MemoryTransport for UsbIdentity {
    fn transact(
        &mut self,
        transaction_id: u32,
        operation: u16,
        parameters: &[u32],
    ) -> Result<crate::MemoryReply> {
        let command = crate::memory_wire::command(transaction_id, operation, parameters)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let written = self
            .handle
            .write_bulk(self.output, &command, Self::remaining(deadline)?)?;
        if written != command.len() {
            return Err(Error::Protocol("short memory-capture command write".into()));
        }
        let mut pending = Vec::new();
        let mut decoder = crate::memory_wire::ReplyDecoder::new(transaction_id, operation);
        loop {
            let raw = self.read_container(&mut pending, deadline)?;
            if let Some(reply) = decoder.accept(&raw)? {
                if !pending.is_empty() {
                    return Err(Error::Protocol(
                        "unexpected data after memory-capture response".into(),
                    ));
                }
                return Ok(reply);
            }
        }
    }

    fn release(&mut self) -> Result<()> {
        IdentityTransport::release(self)
    }
}

impl Drop for UsbIdentity {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
