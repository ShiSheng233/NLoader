//! PTP DeviceInfo wire parsing.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

pub(crate) const GET_DEVICE_INFO: u16 = 0x1001;
pub(crate) const OK: u16 = 0x2001;
pub(crate) const MAX_CONTAINER: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub standard_version: u16,
    pub vendor_extension_id: u32,
    pub vendor_extension_version: u16,
    pub vendor_extension_description: String,
    pub functional_mode: u16,
    pub operations: Vec<u16>,
    pub events: Vec<u16>,
    pub properties: Vec<u16>,
    pub capture_formats: Vec<u16>,
    pub image_formats: Vec<u16>,
    pub manufacturer: String,
    pub model: String,
    pub device_version: String,
    pub serial: String,
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| Error::Protocol("length overflow".into()))?;
        let bytes = self.bytes.get(self.position..end).ok_or_else(|| {
            Error::Protocol(format!("truncated dataset at byte {}", self.position))
        })?;
        self.position = end;
        Ok(bytes)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<String> {
        let length = usize::from(self.take(1)?[0]);
        if length == 0 {
            return Ok(String::new());
        }
        let units: Vec<_> = self
            .take(length * 2)?
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        if units.last() != Some(&0) || units[..length - 1].contains(&0) {
            return Err(Error::Protocol("invalid string terminator".into()));
        }
        String::from_utf16(&units[..length - 1])
            .map_err(|_| Error::Protocol("invalid UTF-16".into()))
    }
    fn array(&mut self) -> Result<Vec<u16>> {
        let count = self.u32()? as usize;
        let length = count
            .checked_mul(2)
            .ok_or_else(|| Error::Protocol("array length overflow".into()))?;
        Ok(self
            .take(length)?
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect())
    }
}

pub fn parse_device_info(bytes: &[u8]) -> Result<DeviceInfo> {
    if bytes.len() > MAX_CONTAINER {
        return Err(Error::Protocol("DeviceInfo exceeds size limit".into()));
    }
    let mut r = Reader { bytes, position: 0 };
    let info = DeviceInfo {
        standard_version: r.u16()?,
        vendor_extension_id: r.u32()?,
        vendor_extension_version: r.u16()?,
        vendor_extension_description: r.string()?,
        functional_mode: r.u16()?,
        operations: r.array()?,
        events: r.array()?,
        properties: r.array()?,
        capture_formats: r.array()?,
        image_formats: r.array()?,
        manufacturer: r.string()?,
        model: r.string()?,
        device_version: r.string()?,
        serial: r.string()?,
    };
    if r.position != bytes.len() {
        return Err(Error::Protocol("trailing bytes in DeviceInfo".into()));
    }
    Ok(info)
}

pub(crate) fn request() -> [u8; 12] {
    [12, 0, 0, 0, 1, 0, 1, 16, 0, 0, 0, 0]
}

pub(crate) struct Container<'a> {
    pub kind: u16,
    pub code: u16,
    pub body: &'a [u8],
}
pub(crate) fn decode_container(bytes: &[u8]) -> Result<Container<'_>> {
    let mut r = Reader { bytes, position: 0 };
    let length = r.u32()? as usize;
    let kind = r.u16()?;
    let code = r.u16()?;
    let transaction = r.u32()?;
    if !(12..=MAX_CONTAINER).contains(&length)
        || length != bytes.len()
        || transaction != 0
        || !matches!(kind, 2 | 3)
    {
        return Err(Error::Protocol(
            "invalid container length, transaction, or type".into(),
        ));
    }
    if kind == 2 && code != GET_DEVICE_INFO {
        return Err(Error::Protocol("unexpected data operation code".into()));
    }
    if kind == 3 && length != 12 {
        return Err(Error::Protocol(
            "GetDeviceInfo response has unexpected parameters".into(),
        ));
    }
    Ok(Container {
        kind,
        code,
        body: &bytes[12..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utf16_and_terminator_are_validated() {
        let mut bytes = vec![5];
        for unit in "尼📷康".encode_utf16().chain([0]) {
            bytes.extend(unit.to_le_bytes());
        }
        assert_eq!(
            Reader {
                bytes: &bytes,
                position: 0
            }
            .string()
            .unwrap(),
            "尼📷康"
        );
        assert!(Reader {
            bytes: &[1, 65, 0],
            position: 0
        }
        .string()
        .is_err());
        assert!(Reader {
            bytes: &[2, 0, 216, 0, 0],
            position: 0
        }
        .string()
        .is_err());
    }
    #[test]
    fn oversized_counts_and_truncated_headers_are_rejected() {
        assert!(Reader {
            bytes: &[255; 4],
            position: 0
        }
        .array()
        .is_err());
        for length in 0..12 {
            assert!(decode_container(&request()[..length]).is_err());
        }
        let mut response = request();
        response[4] = 3;
        response[6] = 1;
        response[7] = 32;
        assert_eq!(decode_container(&response).unwrap().code, OK);
        response[8] = 1;
        assert!(decode_container(&response).is_err());
    }
}
