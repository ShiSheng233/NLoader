use crate::{Error, MemoryReply, Result};

pub(crate) const OPEN_SESSION: u16 = 0x1002;
pub(crate) const CLOSE_SESSION: u16 = 0x1003;
pub(crate) const CONTROL: u16 = 0x94fd;
pub(crate) const READ: u16 = 0x94ff;
pub(crate) const OPEN_INTERNAL: u32 = 0xf001;
pub(crate) const CLOSE_INTERNAL: u32 = 0xf002;
pub(crate) const READ_MEMORY: u32 = 0xf032;

pub(crate) fn command(transaction: u32, operation: u16, parameters: &[u32]) -> Result<Vec<u8>> {
    let allowed = match operation {
        0x1001 | CLOSE_SESSION => parameters.is_empty(),
        OPEN_SESSION => parameters == [1],
        CONTROL => {
            parameters.len() == 5
                && matches!(parameters[0], OPEN_INTERNAL | CLOSE_INTERNAL)
                && parameters[1..] == [0; 4]
        }
        READ => {
            parameters.len() == 5
                && parameters[0] == READ_MEMORY
                && (1..=1024).contains(&parameters[3])
                && parameters[4] == 0
        }
        _ => false,
    };
    if !allowed {
        return Err(Error::Protocol(
            "operation is outside the memory capture allowlist".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(12 + parameters.len() * 4);
    bytes.extend((12 + parameters.len() as u32 * 4).to_le_bytes());
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(operation.to_le_bytes());
    bytes.extend(transaction.to_le_bytes());
    for parameter in parameters {
        bytes.extend(parameter.to_le_bytes());
    }
    Ok(bytes)
}

pub(crate) struct ReplyDecoder {
    transaction: u32,
    operation: u16,
    data: Option<Vec<u8>>,
}
impl ReplyDecoder {
    pub(crate) fn new(transaction: u32, operation: u16) -> Self {
        Self {
            transaction,
            operation,
            data: None,
        }
    }
    pub(crate) fn accept(&mut self, raw: &[u8]) -> Result<Option<MemoryReply>> {
        if raw.len() < 12 {
            return Err(Error::Protocol("truncated response header".into()));
        }
        let length = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
        let kind = u16::from_le_bytes(raw[4..6].try_into().unwrap());
        let code = u16::from_le_bytes(raw[6..8].try_into().unwrap());
        let transaction = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        if length != raw.len()
            || length > crate::protocol::MAX_CONTAINER
            || transaction != self.transaction
        {
            return Err(Error::Protocol(
                "container length or transaction does not match".into(),
            ));
        }
        let body = &raw[12..];
        match kind {
            2 => {
                if code != self.operation
                    || !matches!(self.operation, 0x1001 | READ)
                    || self.data.is_some()
                {
                    return Err(Error::Protocol(
                        "unexpected or duplicate data container".into(),
                    ));
                }
                self.data = Some(body.to_vec());
                Ok(None)
            }
            3 => {
                if body.len() % 4 != 0 || body.len() > 20 {
                    return Err(Error::Protocol("invalid response parameter count".into()));
                }
                let parameters = body
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect();
                Ok(Some(MemoryReply {
                    transaction_id: transaction,
                    response_code: code,
                    parameters,
                    data: self.data.take().unwrap_or_default(),
                }))
            }
            _ => Err(Error::Protocol("unexpected USB container type".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn container(kind: u16, code: u16, transaction: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend((12 + body.len() as u32).to_le_bytes());
        bytes.extend(kind.to_le_bytes());
        bytes.extend(code.to_le_bytes());
        bytes.extend(transaction.to_le_bytes());
        bytes.extend(body);
        bytes
    }
    #[test]
    fn decoder_checks_transaction_operation_and_duplicate_data() {
        let mut decoder = ReplyDecoder::new(7, READ);
        assert!(decoder.accept(&container(2, READ, 8, &[1])).is_err());
        assert!(decoder.accept(&container(2, CONTROL, 7, &[1])).is_err());
        assert!(decoder
            .accept(&container(2, READ, 7, &[1]))
            .unwrap()
            .is_none());
        assert!(decoder.accept(&container(2, READ, 7, &[1])).is_err());
        let reply = decoder
            .accept(&container(3, 0x2001, 7, &0x2001u32.to_le_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(reply.data, [1]);
        assert_eq!(reply.parameters, [0x2001]);
    }
    #[test]
    fn decoder_and_command_reject_invalid_shapes_and_writes() {
        let mut decoder = ReplyDecoder::new(1, CONTROL);
        assert!(decoder.accept(&container(2, CONTROL, 1, &[1])).is_err());
        assert!(decoder.accept(&container(3, 0x2001, 1, &[1])).is_err());
        assert!(decoder.accept(&container(3, 0x2001, 1, &[0; 24])).is_err());
        assert!(command(1, 0x94fe, &[0xf033, 0, 0, 4, 0]).is_err());
        assert!(command(1, 0x92f0, &[]).is_err());
        assert!(command(1, READ, &[READ_MEMORY, 0, 0, 1025, 0]).is_err());
    }
}
