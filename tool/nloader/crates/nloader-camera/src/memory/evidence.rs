//! Consistency checks for recorded reads and session cleanup evidence.
use super::*;

impl MemoryCapture {
    pub fn is_complete(&self) -> bool {
        self.failure.is_none()
            && self.cleanup.acknowledged()
            && self.validate().is_ok()
            && self.requests.iter().enumerate().all(|(index, request)| {
                self.segments
                    .iter()
                    .filter(|segment| segment.request_index == index)
                    .map(|segment| segment.bytes.len() as u64)
                    .sum::<u64>()
                    == u64::from(request.length)
            })
    }

    /// Validates recorded evidence without treating replay as new device proof.
    pub fn validate(&self) -> Result<()> {
        validate_memory_requests(&self.requests, &self.windows)?;
        if self.schema != 2 || self.rule != MEMORY_RULE_VERSION {
            return Err(Error::Protocol(
                "unknown memory capture schema or rule".into(),
            ));
        }
        self.validate_trace()?;
        if !self.raw_device_info.is_empty() {
            let identity = parse_device_info(&self.raw_device_info)?;
            if self.identity.as_ref() != Some(&identity)
                || self.identity_sha256.as_deref()
                    != Some(fingerprint(&self.raw_device_info).as_str())
            {
                return Err(Error::Protocol(
                    "memory capture identity evidence differs".into(),
                ));
            }
        } else if self.identity.is_some()
            || self.identity_sha256.is_some()
            || !self.segments.is_empty()
        {
            return Err(Error::Protocol(
                "memory capture lacks raw identity evidence".into(),
            ));
        }
        if !self.segments.is_empty()
            && (!self.identity.as_ref().is_some_and(is_target) || self.device.vendor_id != 0x04b0)
        {
            return Err(Error::Protocol("memory capture is not Z8 V3.11".into()));
        }
        let mut offsets = vec![0u64; self.requests.len()];
        for segment in &self.segments {
            let request = self
                .requests
                .get(segment.request_index)
                .ok_or_else(|| Error::Protocol("segment refers to an unknown request".into()))?;
            let offset = &mut offsets[segment.request_index];
            let expected_length =
                (u64::from(request.length).saturating_sub(*offset)).min(u64::from(CHUNK_BYTES));
            if segment.address != request.address + *offset
                || segment.bytes.len() as u64 != expected_length
                || expected_length == 0
                || fingerprint(&segment.bytes) != segment.sha256
                || segment.repeat_sha256 != segment.sha256
            {
                return Err(Error::Protocol(
                    "memory segment range or consistency evidence differs".into(),
                ));
            }
            for transaction_id in [segment.first_transaction_id, segment.repeat_transaction_id] {
                let records: Vec<_> = self
                    .transactions
                    .iter()
                    .filter(|record| record.transaction_id == transaction_id)
                    .collect();
                if records.len() != 1 {
                    return Err(Error::Protocol(
                        "memory segment transaction is missing or ambiguous".into(),
                    ));
                }
                let record = records[0];
                if record.operation != READ
                    || record.parameters != read_parameters(segment.address, expected_length as u32)
                    || record.error.is_some()
                {
                    return Err(Error::Protocol(
                        "memory segment request evidence differs".into(),
                    ));
                }
                let reply = record
                    .reply
                    .as_ref()
                    .ok_or_else(|| Error::Protocol("memory segment has no response".into()))?;
                check_internal(reply)?;
                if reply.transaction_id != transaction_id || reply.data != segment.bytes {
                    return Err(Error::Protocol(
                        "memory segment response evidence differs".into(),
                    ));
                }
            }
            if segment.first_transaction_id == segment.repeat_transaction_id {
                return Err(Error::Protocol(
                    "consistency read must use a separate transaction".into(),
                ));
            }
            *offset += expected_length;
        }
        Ok(())
    }

    fn validate_trace(&self) -> Result<()> {
        let mut standard = SessionOwnership::NotOpened;
        let mut maintenance = SessionOwnership::NotOpened;
        let mut standard_close = false;
        let mut maintenance_close = false;
        let mut usable = true;
        let mut next = 1;
        let mut identity_recorded = false;
        let mut identity_acknowledged = false;
        for record in &self.transactions {
            command(record.transaction_id, record.operation, &record.parameters)?;
            let expected = if standard == SessionOwnership::Owned {
                let id = next;
                next += 1;
                id
            } else {
                0
            };
            if !usable
                || record.transaction_id != expected
                || record.reply.is_some() == record.error.is_some()
            {
                return Err(Error::Protocol(
                    "memory transaction sequence or outcome is inconsistent".into(),
                ));
            }
            if record
                .reply
                .as_ref()
                .is_some_and(|reply| reply.transaction_id != record.transaction_id)
            {
                return Err(Error::Protocol(
                    "recorded response transaction differs".into(),
                ));
            }
            if record.operation == 0x1001 {
                if standard != SessionOwnership::NotOpened || identity_recorded {
                    return Err(Error::Protocol(
                        "identity was read in an unexpected session".into(),
                    ));
                }
                identity_recorded = true;
                if let Some(reply) = &record.reply {
                    identity_acknowledged = check_standard(reply).is_ok();
                    if identity_acknowledged && reply.data != self.raw_device_info {
                        return Err(Error::Protocol(
                            "raw identity differs from recorded response".into(),
                        ));
                    }
                }
            }
            if record.operation == OPEN_SESSION {
                if standard != SessionOwnership::NotOpened
                    || !identity_recorded
                    || !identity_acknowledged
                    || !self.identity.as_ref().is_some_and(is_target)
                    || self.device.vendor_id != 0x04b0
                {
                    return Err(Error::Protocol(
                        "standard session lacks a successful fresh identity response or was already opened".into(),
                    ));
                }
                standard = SessionOwnership::Unknown;
                if let Some(reply) = &record.reply {
                    if reply.response_code == 0x201e && reply.data.is_empty() {
                        standard = SessionOwnership::AlreadyOpen;
                    } else if check_standard(reply).is_ok() && require_no_data(reply).is_ok() {
                        standard = SessionOwnership::Owned;
                    }
                }
            }
            if matches!(record.operation, CONTROL | READ | CLOSE_SESSION)
                && standard != SessionOwnership::Owned
            {
                return Err(Error::Protocol(
                    "maintenance command lacks an owned standard session".into(),
                ));
            }
            if record.operation == CONTROL && record.parameters[0] == OPEN_INTERNAL {
                if maintenance != SessionOwnership::NotOpened {
                    return Err(Error::Protocol(
                        "maintenance session was opened more than once".into(),
                    ));
                }
                maintenance = SessionOwnership::Unknown;
                if let Some(reply) = &record.reply {
                    if internal_already_open(reply) {
                        maintenance = SessionOwnership::AlreadyOpen;
                    } else if check_internal(reply).is_ok() && require_no_data(reply).is_ok() {
                        maintenance = SessionOwnership::Owned;
                    }
                }
            }
            if record.operation == READ {
                if maintenance != SessionOwnership::Owned {
                    return Err(Error::Protocol(
                        "memory read lacks an owned maintenance session".into(),
                    ));
                }
                let address =
                    u64::from(record.parameters[1]) | (u64::from(record.parameters[2]) << 32);
                let length = u64::from(record.parameters[3]);
                if !self.requests.iter().any(|request| {
                    address >= request.address
                        && address
                            .checked_add(length)
                            .is_some_and(|end| end <= request.address + u64::from(request.length))
                }) {
                    return Err(Error::Protocol(
                        "recorded memory read is outside the requested ranges".into(),
                    ));
                }
            }
            if record.operation == CONTROL && record.parameters[0] == CLOSE_INTERNAL {
                if maintenance != SessionOwnership::Owned {
                    return Err(Error::Protocol(
                        "maintenance close did not own its session".into(),
                    ));
                }
                maintenance_close = true;
                maintenance = if record.reply.as_ref().is_some_and(|reply| {
                    check_internal(reply).is_ok() && require_no_data(reply).is_ok()
                }) {
                    SessionOwnership::CloseAcknowledged
                } else {
                    SessionOwnership::Unknown
                };
            }
            if record.operation == CLOSE_SESSION {
                standard_close = true;
                standard = if record.reply.as_ref().is_some_and(|reply| {
                    check_standard(reply).is_ok() && require_no_data(reply).is_ok()
                }) {
                    SessionOwnership::CloseAcknowledged
                } else {
                    SessionOwnership::Unknown
                };
            }
            if record.error.is_some() {
                usable = false;
            }
        }
        if standard != self.cleanup.standard_session
            || maintenance != self.cleanup.maintenance_session
            || usable != self.cleanup.transport_usable
            || standard_close != self.cleanup.standard_close_attempted
            || maintenance_close != self.cleanup.maintenance_close_attempted
            || self.cleanup.device_state_restored_verified
        {
            return Err(Error::Protocol(
                "cleanup claim differs from transaction evidence".into(),
            ));
        }
        Ok(())
    }
}
