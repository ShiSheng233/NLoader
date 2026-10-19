//! Synthetic test materials only; not firmware or physical-device evidence.
use super::sdk::{camera, firmware, profile};
use profile::{
    sha256, AddressRange, CaptureConfig, CaptureFragment, CaptureRequest, CaptureSlot,
    MemorySegment, MemorySegmentKind, Profile,
};
use sha1::{Digest, Sha1};
use std::path::Path;
const SUB_W20_W8_W19: [u8; 4] = [0x14, 0x01, 0x13, 0x4b];
pub const REQUESTS: [(u64, u32); 4] = [
    (0x20c2040, 80),
    (0x210fc40, 192),
    (0x210fd00, 192),
    (0x20e4f20, 40),
];
fn endpoint(bytes: &mut [u8], offsets: [usize; 4], register: u32, value: u64) {
    for (index, offset) in offsets.into_iter().enumerate() {
        let opcode = if index == 0 { 0xd280_0000 } else { 0xf280_0000 };
        let word = opcode
            | ((index as u32) << 21)
            | (((value >> (index * 16)) as u32 & 65535) << 5)
            | register;
        bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
}
pub fn profile_fixture() -> (Profile, Vec<u8>) {
    let mut payload = vec![0; 0x2f2950];
    endpoint(&mut payload, [12, 16, 28, 32], 8, 0x22ad000);
    endpoint(&mut payload, [44, 48, 52, 56], 8, 0x22ac000);
    for (offset, word) in [
        (36, 0xeb08029fu32),
        (40, 0x540000e8),
        (60, 0xeb08027f),
        (64, 0x54000302),
    ] {
        payload[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
    let copy = &mut payload[0x100..0x140];
    endpoint(copy, [0, 4, 12, 20], 8, 0x22f1950);
    endpoint(copy, [8, 16, 24, 32], 19, 0x22ad000);
    endpoint(copy, [28, 36, 44, 48], 2, 0x12ae000);
    copy[40..44].copy_from_slice(&SUB_W20_W8_W19);
    for (offset, word) in [(52, 0xaa1303e1u32), (56, 0x2a1403e3)] {
        copy[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
    for (offset, value) in [(0x148, 0x1000u64), (0xd0, 0x2ad000), (0xd8, 0x2000000)] {
        payload[0x200 + offset..0x208 + offset].copy_from_slice(&value.to_le_bytes());
    }
    let fragment = |name: &str, start: usize, length: usize| CaptureFragment {
        name: name.into(),
        file_offset: start as u64,
        length: length as u64,
        sha256: sha256(&payload[start..start + length]),
    };
    let mut profile = Profile::draft("Z8", "3.11");
    profile.memory.module_size = Some(payload.len() as u64);
    profile.memory.xip_base = Some(0x1000000);
    profile.memory.segments = vec![
        MemorySegment {
            file_offset: 0,
            runtime_start: 0x1000000,
            size: 0x1000,
            kind: MemorySegmentKind::Xip,
        },
        MemorySegment {
            file_offset: 0x1000,
            runtime_start: 0x2000000,
            size: 0x2ad000,
            kind: MemorySegmentKind::Ram,
        },
        MemorySegment {
            file_offset: 0x2ae000,
            runtime_start: 0x22ad000,
            size: 0x44950,
            kind: MemorySegmentKind::Ram,
        },
    ];
    profile.checks.module_sha256 = Some(sha256(&payload));
    profile.capture = Some(CaptureConfig {
        family: "z8_readonly_v1".into(),
        windows: vec![
            AddressRange {
                start: 0x2000000,
                end: 0x22ac000,
            },
            AddressRange {
                start: 0x22ad001,
                end: 0x22f1950,
            },
        ],
        requests: vec![CaptureRequest {
            label: "fixture".into(),
            address: 0x2000,
            length: 16,
        }],
        range_check: fragment("range_check", 0, 0xf0),
        slot: CaptureSlot {
            descriptor_offset: 0x200,
            region_getter_offset: 0,
            overlay_getter_offset: 0,
            flash_table_offset: 0,
            flash_record_count: 0,
            region_count: 0,
            overlay_count: 0,
            instruction_windows: vec![fragment("late_data_copy", 0x100, 0x40)],
        },
    });
    profile.identity.eg_module = Some("eg2070_test.bi".into());
    profile.capture.as_mut().unwrap().requests = REQUESTS
        .iter()
        .enumerate()
        .map(|(index, (address, length))| CaptureRequest {
            label: format!("request{index}"),
            address: *address,
            length: *length,
        })
        .collect();
    profile.menu = serde_json::from_value(serde_json::json!({
            "window_table": 0x20eccc0u64, "record_sizes": {"window":96,"page":80,"item":44,"event":32},
            "setup": {"window_id":663,"page_address":REQUESTS[0].0,"items":0x1001000u64,"item_count":44,"event_table":0x1001100u64,"layout":0x1001200u64},
            "page": {"window_id":1493,"page_record":REQUESTS[2].0,"template_window":1,"template_page":0,"row_event_table":0,"row_template_event_table":0,"title_slot":0,"title_format":3,"item_id":1,"item_flags":0,"item_slot":1,"item_style":4,"item_text":"fixture"}
        })).unwrap();
    let mapping = profile.memory.clone();
    let mut put = |address: u64, data: &[u8]| {
        let offset = mapping
            .address_to_offset(address, data.len() as u64)
            .unwrap() as usize;
        payload[offset..offset + data.len()].copy_from_slice(data);
    };
    put(REQUESTS[0].0 + 16, &0x1001000u64.to_le_bytes());
    put(REQUESTS[0].0 + 24, &0x1001100u64.to_le_bytes());
    put(REQUESTS[0].0 + 32, &44u16.to_le_bytes());
    put(REQUESTS[1].0, &3u16.to_le_bytes());
    put(REQUESTS[1].0 + 2, &1492u16.to_le_bytes());
    put(REQUESTS[2].0 + 96, &5u16.to_le_bytes());
    put(REQUESTS[2].0 + 98, &1495u16.to_le_bytes());
    let setup = profile.menu.window_address(663).unwrap();
    put(setup, &2u16.to_le_bytes());
    put(setup + 2, &663u16.to_le_bytes());
    put(setup + 80, &REQUESTS[0].0.to_le_bytes());
    let battery = profile.menu.window_address(729).unwrap();
    put(battery, &2u16.to_le_bytes());
    put(battery + 2, &729u16.to_le_bytes());
    put(battery + 40, &REQUESTS[3].0.to_le_bytes());
    put(REQUESTS[3].0, &0x1001800u64.to_le_bytes());
    profile.checks.module_sha256 = Some(sha256(&payload));
    (profile, payload)
}

pub fn package(eg: &[u8], other: u8) -> Vec<u8> {
    let mut body = vec![b' '; 32];
    body.extend(2u32.to_be_bytes());
    body.extend(112u32.to_be_bytes());
    body.extend([0; 8]);
    let mut start = 112u32;
    for (name, size) in [("ex2070_test.bi", 16usize), ("eg2070_test.bi", eg.len())] {
        let mut field = [0; 16];
        field[..name.len()].copy_from_slice(name.as_bytes());
        body.extend(field);
        body.extend(start.to_be_bytes());
        body.extend((size as u32 + 2).to_be_bytes());
        body.extend([0; 8]);
        start += size as u32 + 2;
    }
    for data in [vec![other; 16], eg.to_vec()] {
        body.extend(&data);
        body.extend(firmware::crc16(&data).to_be_bytes());
    }
    body.extend(firmware::crc16(&body).to_be_bytes());
    body.extend([0; 14]);
    let mut digest = Sha1::new();
    digest.update(&body);
    digest.update([0; 8]);
    let mut raw = digest.finalize().to_vec();
    raw.extend([0; 12]);
    raw.extend(body);
    raw
}
pub fn key_json(stock: &[u8]) -> Vec<u8> {
    let tables = "00".repeat(256);
    let signature = "00".repeat(8);
    serde_json::to_vec(&serde_json::json!({"schema":1,"materials":{"legacy-xor":{"t1":tables,"t2":tables,"t3":tables,"self_check":{"t1":sha256(&[0;256]),"t2":sha256(&[0;256]),"t3":sha256(&[0;256])}}},"keys":[{"scheme":"legacy-xor","model":"Z8","firmware":["3.11"],"firmware_sha256":{"3.11":sha256(stock)},"k8":signature,"self_check":{"k8":sha256(&[0;8])}}]})).unwrap()
}
pub fn files(directory: &Path) -> (Profile, Vec<u8>) {
    let (mut profile, eg) = profile_fixture();
    let stock = package(&eg, 1);
    profile.checks.package_sha256 = Some(sha256(&stock));
    std::fs::write(directory.join("stock.bin"), &stock).unwrap();
    std::fs::write(directory.join("key.json"), key_json(&stock)).unwrap();
    std::fs::write(directory.join("profile.toml"), profile.to_toml().unwrap()).unwrap();
    (profile, eg)
}
fn device_info() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(100u16.to_le_bytes());
    b.extend(10u32.to_le_bytes());
    b.extend(100u16.to_le_bytes());
    b.push(0);
    b.extend(0u16.to_le_bytes());
    b.extend(1u32.to_le_bytes());
    b.extend(0x1001u16.to_le_bytes());
    for _ in 0..4 {
        b.extend(0u32.to_le_bytes());
    }
    for text in ["NIKON", "Z 8", "V3.11", "SYNTHETIC-ONLY"] {
        b.push((text.encode_utf16().count() + 1) as u8);
        for unit in text.encode_utf16().chain([0]) {
            b.extend(unit.to_le_bytes());
        }
    }
    b
}
pub fn capture(
    profile: &Profile,
    eg: &[u8],
    unstable: bool,
    cleanup_error: bool,
) -> camera::MemoryCapture {
    struct Transport<'a> {
        profile: &'a Profile,
        eg: &'a [u8],
        reads: usize,
        unstable: bool,
        cleanup_error: bool,
    }
    impl camera::MemoryTransport for Transport<'_> {
        fn transact(
            &mut self,
            transaction_id: u32,
            operation: u16,
            parameters: &[u32],
        ) -> camera::Result<camera::MemoryReply> {
            let mut reply = camera::MemoryReply {
                transaction_id,
                response_code: 0x2001,
                parameters: Vec::new(),
                data: Vec::new(),
            };
            match operation {
                0x1001 => reply.data = device_info(),
                0x94fd => {
                    reply.parameters = vec![
                        if parameters[0] == 0xf002 && self.cleanup_error {
                            0xa001
                        } else {
                            0x2001
                        },
                        0,
                        0,
                        0,
                        0,
                    ]
                }
                0x94ff => {
                    self.reads += 1;
                    reply.parameters = vec![0x2001, 0, 0, 0, 0];
                    let address = u64::from(parameters[1]) | (u64::from(parameters[2]) << 32);
                    let offset = self
                        .profile
                        .memory
                        .address_to_offset(address, u64::from(parameters[3]))
                        .unwrap() as usize;
                    reply.data = self.eg[offset..offset + parameters[3] as usize].to_vec();
                    if self.unstable && self.reads == 2 {
                        reply.data[0] ^= 1;
                    }
                }
                _ => {}
            };
            Ok(reply)
        }
        fn release(&mut self) -> camera::Result<()> {
            Ok(())
        }
    }
    let mut transport = Transport {
        profile,
        eg,
        reads: 0,
        unstable,
        cleanup_error,
    };
    let requests = super::sdk::discovery::memory_requests(profile).unwrap();
    let windows = profile.capture.as_ref().unwrap().windows.clone();
    camera::capture_memory_with_transport(
        camera::CameraDevice {
            id: "fixture:z8".into(),
            bus: 0,
            address: 0,
            vendor_id: 0x04b0,
            product_id: 0,
        },
        &mut transport,
        &requests,
        &windows,
        camera::CaptureOrigin::SyntheticFixture,
    )
    .unwrap()
}
