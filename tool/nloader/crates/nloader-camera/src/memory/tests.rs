use super::*;

#[derive(Clone, Copy)]
enum Fault {
    Timeout,
    AlreadyOpen,
    OuterFailure,
    InnerFailure,
    MissingParameters,
    ShortRead,
    DifferentRead,
    WrongTransaction,
    DataInControl,
}
#[derive(Default)]
struct Mock {
    calls: Vec<(u32, u16, Vec<u32>)>,
    faults: Vec<(usize, Fault)>,
    version: Option<&'static str>,
    released: usize,
    release_fails: bool,
}
impl MemoryTransport for Mock {
    fn transact(
        &mut self,
        transaction: u32,
        operation: u16,
        parameters: &[u32],
    ) -> Result<MemoryReply> {
        command(transaction, operation, parameters)?;
        let index = self.calls.len();
        self.calls
            .push((transaction, operation, parameters.to_vec()));
        let data = match operation {
            0x1001 => identity_bytes(self.version.unwrap_or("V3.11")),
            READ => (0..parameters[3])
                .map(|offset| parameters[1].wrapping_add(offset) as u8)
                .collect(),
            _ => Vec::new(),
        };
        let mut reply = MemoryReply {
            transaction_id: transaction,
            response_code: OK,
            parameters: if matches!(operation, READ | CONTROL) {
                vec![u32::from(OK), 0, 0, 0, 0]
            } else {
                Vec::new()
            },
            data,
        };
        if let Some((_, fault)) = self.faults.iter().find(|(at, _)| *at == index) {
            match fault {
                Fault::Timeout => return Err(Error::Usb(rusb::Error::Timeout)),
                Fault::AlreadyOpen => {
                    if operation == OPEN_SESSION {
                        reply.response_code = 0x201e;
                    } else {
                        reply.parameters[0] = 0x201e;
                    }
                }
                Fault::OuterFailure => reply.response_code = 0xa004,
                Fault::InnerFailure => reply.parameters[0] = 0x201d,
                Fault::MissingParameters => reply.parameters.clear(),
                Fault::ShortRead => {
                    reply.data.pop();
                }
                Fault::DifferentRead => reply.data[0] ^= 1,
                Fault::WrongTransaction => reply.transaction_id += 1,
                Fault::DataInControl => reply.data.push(1),
            }
        }
        Ok(reply)
    }
    fn release(&mut self) -> Result<()> {
        self.released += 1;
        if self.release_fails {
            Err(Error::Usb(rusb::Error::NoDevice))
        } else {
            Ok(())
        }
    }
}

fn identity_bytes(version: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(100u16.to_le_bytes());
    bytes.extend(10u32.to_le_bytes());
    bytes.extend(100u16.to_le_bytes());
    bytes.push(0);
    bytes.extend(0u16.to_le_bytes());
    for _ in 0..5 {
        bytes.extend(0u32.to_le_bytes());
    }
    for value in ["NIKON", "Z 8", version, "MOCK"] {
        bytes.push((value.encode_utf16().count() + 1) as u8);
        for unit in value.encode_utf16().chain([0]) {
            bytes.extend(unit.to_le_bytes());
        }
    }
    bytes
}
fn device() -> CameraDevice {
    CameraDevice {
        id: "fixture:z8".into(),
        bus: 0,
        address: 0,
        vendor_id: 0x04b0,
        product_id: 0,
    }
}
fn windows() -> Vec<MemoryReadWindow> {
    vec![
        MemoryReadWindow {
            start: 0x10000,
            end: 0x40000,
        },
        MemoryReadWindow {
            start: 0x43001,
            end: 0x50000,
        },
    ]
}
fn validate_memory_requests(requests: &[MemoryReadRequest]) -> Result<()> {
    super::validate_memory_requests(requests, &windows())
}
fn request(length: u32) -> MemoryReadRequest {
    MemoryReadRequest {
        label: "window-table".into(),
        address: 0x18000,
        length,
    }
}
fn capture(mock: &mut Mock, length: u32) -> MemoryCapture {
    capture_memory_with_transport(
        device(),
        mock,
        &[request(length)],
        &windows(),
        CaptureOrigin::SyntheticFixture,
    )
    .unwrap()
}
fn has_internal(mock: &Mock, inner: u32) -> bool {
    mock.calls.iter().any(|(_, operation, parameters)| {
        *operation == CONTROL && parameters.first() == Some(&inner)
    })
}

#[test]
fn bounded_requests_reject_protected_endpoints_xip_mmio_bss_and_overflow() {
    for (address, length) in [
        (0x40000, 1),
        (0x43000, 1),
        (0x3ffff, 2),
        (0x4ffff, 2),
        (0x51000, 1),
        (0x8000, 8),
        (0xd000000, 4),
        (u64::MAX, 2),
        (0x10000, 0),
    ] {
        assert!(
            validate_memory_requests(&[MemoryReadRequest {
                address,
                length,
                label: "invalid".into()
            }])
            .is_err(),
            "accepted {address:#x}+{length}"
        );
    }
    for (address, length) in [(0x10000, 1), (0x3ffff, 1), (0x43001, 1), (0x4ffff, 1)] {
        assert!(validate_memory_requests(&[MemoryReadRequest {
            address,
            length,
            label: "boundary".into()
        }])
        .is_ok());
    }
    assert!(validate_memory_requests(&[request(MAX_MEMORY_CAPTURE_BYTES + 1)]).is_err());
    assert!(validate_memory_requests(&vec![request(1); 65]).is_err());
    assert!(validate_memory_requests(&[request(40_000), request(40_000)]).is_err());
}

#[test]
fn chunks_have_two_identical_reads_and_owned_sessions_close_in_order() {
    let mut mock = Mock::default();
    let report = capture(&mut mock, 1500);
    assert!(report.is_complete(), "{report:#?}");
    report.validate().unwrap();
    assert_eq!(
        report
            .segments
            .iter()
            .map(|segment| segment.bytes.len())
            .collect::<Vec<_>>(),
        [1024, 476]
    );
    assert_eq!(
        mock.calls
            .iter()
            .map(|(transaction, _, _)| *transaction)
            .collect::<Vec<_>>(),
        [0, 0, 1, 2, 3, 4, 5, 6, 7]
    );
    assert_eq!(mock.calls[7].1, CONTROL);
    assert_eq!(mock.calls[7].2, [CLOSE_INTERNAL, 0, 0, 0, 0]);
    assert_eq!(mock.calls[8].1, CLOSE_SESSION);
    assert_eq!(mock.released, 1);
    assert_eq!(
        report.cleanup.maintenance_session,
        SessionOwnership::CloseAcknowledged
    );
    assert!(!report.cleanup.device_state_restored_verified);
}

#[test]
fn wrong_firmware_stops_before_opening_a_session() {
    let mut mock = Mock {
        version: Some("V3.01"),
        ..Mock::default()
    };
    let report = capture(&mut mock, 192);
    assert!(report.failure.is_some());
    assert_eq!(mock.calls.len(), 1);
    assert_eq!(mock.released, 1);
    assert_eq!(report.cleanup.standard_session, SessionOwnership::NotOpened);
}

#[test]
fn already_open_sessions_are_not_adopted_or_closed() {
    let mut mock = Mock {
        faults: vec![(1, Fault::AlreadyOpen)],
        ..Mock::default()
    };
    let report = capture(&mut mock, 192);
    assert_eq!(mock.calls.len(), 2);
    assert!(!report.cleanup.standard_close_attempted);
    assert_eq!(
        report.cleanup.standard_session,
        SessionOwnership::AlreadyOpen
    );
    let mut mock = Mock {
        faults: vec![(2, Fault::AlreadyOpen)],
        ..Mock::default()
    };
    let report = capture(&mut mock, 192);
    assert!(!has_internal(&mock, CLOSE_INTERNAL));
    assert_eq!(mock.calls.last().unwrap().1, CLOSE_SESSION);
    assert_eq!(
        report.cleanup.maintenance_session,
        SessionOwnership::AlreadyOpen
    );
    assert!(!report.is_complete());
}

#[test]
fn timeout_stops_commands_and_preserves_unknown_ownership() {
    for at in [1, 2, 3] {
        let mut mock = Mock {
            faults: vec![(at, Fault::Timeout)],
            ..Mock::default()
        };
        let report = capture(&mut mock, 192);
        assert_eq!(mock.calls.len(), at + 1);
        assert_eq!(mock.released, 1);
        assert!(report.failure.is_some());
        assert!(!report.cleanup.transport_usable);
        assert!(!report.cleanup.errors.is_empty());
        if at == 1 {
            assert_eq!(report.cleanup.standard_session, SessionOwnership::Unknown);
        }
        if at == 2 {
            assert_eq!(
                report.cleanup.maintenance_session,
                SessionOwnership::Unknown
            );
        }
        if at == 3 {
            assert_eq!(report.cleanup.maintenance_session, SessionOwnership::Owned);
        }
    }
}

#[test]
fn failed_reads_are_not_zero_filled_and_still_cleanup_when_stream_is_usable() {
    for fault in [
        Fault::OuterFailure,
        Fault::InnerFailure,
        Fault::MissingParameters,
        Fault::ShortRead,
    ] {
        let mut mock = Mock {
            faults: vec![(3, fault)],
            ..Mock::default()
        };
        let report = capture(&mut mock, 192);
        assert!(report.failure.is_some());
        assert!(report.segments.is_empty());
        assert!(has_internal(&mock, CLOSE_INTERNAL));
        assert!(report.cleanup.acknowledged());
        assert!(!report.is_complete());
    }
}

#[test]
fn consistency_failure_preserves_only_previous_complete_chunks() {
    let mut mock = Mock {
        faults: vec![(6, Fault::DifferentRead)],
        ..Mock::default()
    };
    let report = capture(&mut mock, 1500);
    assert!(report.failure.as_ref().unwrap().contains("changed"));
    assert_eq!(report.segments.len(), 1);
    assert_eq!(report.segments[0].bytes.len(), 1024);
    assert!(has_internal(&mock, CLOSE_INTERNAL));
    assert!(!report.is_complete());
    assert_ne!(
        report.transactions[5].reply.as_ref().unwrap().data,
        report.transactions[6].reply.as_ref().unwrap().data
    );
}

#[test]
fn wrong_transaction_invalidates_stream_and_cleanup_does_not_guess() {
    let mut mock = Mock {
        faults: vec![(3, Fault::WrongTransaction)],
        ..Mock::default()
    };
    let report = capture(&mut mock, 192);
    assert_eq!(mock.calls.len(), 4);
    assert!(!report.cleanup.transport_usable);
    assert!(!report.cleanup.maintenance_close_attempted);
    assert!(report.cleanup.interface_released);
}

#[test]
fn unconfirmed_maintenance_open_is_not_owned() {
    for fault in [
        Fault::MissingParameters,
        Fault::DataInControl,
        Fault::OuterFailure,
    ] {
        let mut mock = Mock {
            faults: vec![(2, fault)],
            ..Mock::default()
        };
        let report = capture(&mut mock, 192);
        assert_eq!(
            report.cleanup.maintenance_session,
            SessionOwnership::Unknown
        );
        assert!(!has_internal(&mock, CLOSE_INTERNAL));
        assert!(!report.is_complete());
    }
}

#[test]
fn cleanup_failures_are_not_claimed_as_completed() {
    let mut mock = Mock {
        faults: vec![(5, Fault::Timeout)],
        ..Mock::default()
    };
    let report = capture(&mut mock, 192);
    assert!(report.failure.is_none());
    assert!(!report.is_complete());
    assert_eq!(
        report.cleanup.maintenance_session,
        SessionOwnership::Unknown
    );
    assert!(!report.cleanup.standard_close_attempted);
    assert!(!report.cleanup.errors.is_empty());
    let mut mock = Mock {
        release_fails: true,
        ..Mock::default()
    };
    let report = capture(&mut mock, 192);
    assert!(!report.cleanup.interface_released);
    assert!(!report.is_complete());
}

#[test]
fn replay_rejects_changed_bytes_hashes_and_request_links() {
    let report = capture(&mut Mock::default(), 192);
    let mut changed = report.clone();
    changed.segments[0].bytes[0] ^= 1;
    assert!(changed.validate().is_err());
    let mut changed = report.clone();
    changed.segments[0].repeat_transaction_id = changed.segments[0].first_transaction_id;
    assert!(changed.validate().is_err());
    let mut changed = report.clone();
    changed.transactions[3].parameters[1] += 1;
    assert!(changed.validate().is_err());
    let mut changed = report;
    changed.identity.as_mut().unwrap().device_version = "V3.01".into();
    assert!(changed.validate().is_err());
}

#[test]
fn replay_rejects_removed_session_evidence_and_unproven_cleanup_claims() {
    let report = capture(&mut Mock::default(), 192);
    for index in [0, 1, 2, 5, 6] {
        let mut changed = report.clone();
        changed.transactions.remove(index);
        assert!(
            changed.validate().is_err(),
            "accepted missing transaction {index}"
        );
        assert!(!changed.is_complete());
    }
    let mut changed = report.clone();
    changed.cleanup.device_state_restored_verified = true;
    assert!(changed.validate().is_err());
    let mut changed = report;
    changed.cleanup.maintenance_close_attempted = false;
    assert!(changed.validate().is_err());
}

#[test]
fn replay_rejects_failed_identity_ack_before_later_owned_reads() {
    let report = capture(&mut Mock::default(), 192);
    assert!(report.is_complete());
    for case in 0..2 {
        let mut changed = report.clone();
        let reply = changed.transactions[0].reply.as_mut().unwrap();
        if case == 0 {
            reply.response_code = 0x2002;
        } else {
            reply.parameters.push(0x2001);
        }
        assert!(changed.validate().is_err());
        assert!(!changed.is_complete());
    }
}
