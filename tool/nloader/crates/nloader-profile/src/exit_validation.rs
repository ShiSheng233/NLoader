//! Optional physical exit bindings retain profile-owned complete stock evidence.
use crate::validation::{hash_matches, valid_hash};
use crate::{sha256, ExecutionBody, IssueKind, Profile, TaskFamily, ValidationReport};
use std::collections::BTreeSet;

// Complete C3.11 family spans, not entry-only evidence. Addresses and hashes
// remain profile data; these lengths describe the adapter's audited ABI.
const REQUIRED_BODIES: &[(&str, u32)] = &[
    ("suspend", 0x1d0),
    ("resume", 0x190),
    ("terminate", 0x284),
    ("restart", 0x18c),
    ("input_register", 44),
    ("input_worker", 0x778),
    ("input_bank", 28),
    ("worker_init", 88),
    ("worker_create", 0x114),
    ("input_action", 192),
];

fn instruction(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn instructions_match(bytes: &[u8], offset: usize, expected: &[u32]) -> bool {
    expected
        .iter()
        .enumerate()
        .all(|(index, word)| instruction(bytes, offset + index * 4) == Some(*word))
}

impl Profile {
    pub(crate) fn validate_exit(&self, report: &mut ValidationReport) {
        let Some(exit) = &self.services.exit else {
            return;
        };
        if self.abi.task != Some(TaskFamily::Z8WorkerV1) {
            report.add(
                "abi.task",
                IssueKind::Unsupported,
                "exit controls require z8_worker_v1",
            );
        }
        if self.task.core != Some(1) {
            report.add(
                "task.core",
                IssueKind::Unsupported,
                "physical exit requires CPU0 affinity (core=1); ter_tsk refuses another PCB",
            );
        }
        if !self
            .task
            .priority
            .is_some_and(|priority| priority > 27 && priority <= 256)
        {
            report.add(
                "task.priority",
                IssueKind::Unsupported,
                "physical exit worker must run below GUI priority 25 and Menu priority 27",
            );
        }
        if exit.input_callback == 0 || exit.input_callback % 8 != 0 {
            report.add(
                "services.exit.input_callback",
                IssueKind::Invalid,
                "callback slot must be nonzero and qword aligned",
            );
        }
        if exit.bank != 1 || exit.mask != 0xc000 {
            report.add(
                "services.exit.bank",
                IssueKind::Unsupported,
                "audited MENU+DELETE chord is bank 1 mask 0xc000",
            );
        }
        let mapping = &exit.menu_release_mapping;
        if exit.release_mask != 0x8000
            || exit.menu_release_code != 0x279
            || mapping.name != "menu_release"
            || mapping.element_bytes != 4
            || mapping.values != [0, u64::from(exit.menu_release_code)]
            || mapping.address % 4 != 0
            || !self.memory.is_xip_range(mapping.address, 8)
        {
            report.add("services.exit.menu_release_mapping", IssueKind::Conflict, "release notification requires MENU bit 0x8000 and the native zero-key action mapping");
        }
        let mut names = BTreeSet::new();
        for body in &exit.bodies {
            let field = format!("services.exit.bodies.{}", body.name);
            let required = REQUIRED_BODIES.iter().find(|(name, _)| *name == body.name);
            if required.is_none() || !names.insert(body.name.as_str()) {
                report.add(&field, IssueKind::Invalid, "unknown or duplicate exit body");
            }
            if required.is_some_and(|(_, minimum)| body.length < *minimum) {
                report.add(
                    &field,
                    IssueKind::Invalid,
                    "evidence is shorter than the complete audited function",
                );
            }
            if body.length == 0
                || body.length % 4 != 0
                || body.address % 4 != 0
                || !self
                    .memory
                    .is_xip_range(body.address, u64::from(body.length))
            {
                report.add(
                    &field,
                    IssueKind::OutOfBounds,
                    "complete exit function must be aligned and contained in XIP",
                );
            }
            if self.memory.slack.as_ref().is_some_and(|slack| {
                slack.range().overlaps(&crate::AddressRange {
                    start: body.address,
                    end: body.address.saturating_add(u64::from(body.length)),
                })
            }) {
                report.add(
                    &field,
                    IssueKind::Conflict,
                    "stock exit evidence overlaps reserved loader space",
                );
            }
            if !valid_hash(&body.sha256) {
                report.add(
                    &field,
                    IssueKind::Invalid,
                    "expected 64 hexadecimal SHA-256 digits",
                );
            }
        }
        for (name, _) in REQUIRED_BODIES {
            if !names.contains(name) {
                report.add(
                    format!("services.exit.bodies.{name}"),
                    IssueKind::Missing,
                    "exit services require this complete stock function",
                );
            }
        }
        for (name, address) in [
            ("suspend", exit.suspend),
            ("resume", exit.resume),
            ("terminate", exit.terminate),
            ("restart", exit.restart),
        ] {
            if !self
                .exit_body(name)
                .is_some_and(|body| body.address == address)
            {
                report.add(
                    format!("services.exit.{name}"),
                    IssueKind::Conflict,
                    "service entry differs from its complete function evidence",
                );
            }
            let fingerprint = format!("exit.{name}");
            if !self.service_fingerprints.contains_key(&fingerprint) {
                report.add(
                    format!("service_fingerprints.{fingerprint}"),
                    IssueKind::Missing,
                    "exit service requires an entry fingerprint",
                );
            }
        }
        if !self
            .exit_body("worker_init")
            .is_some_and(|body| Some(body.address) == self.services.worker_init)
        {
            report.add(
                "services.worker_init",
                IssueKind::Conflict,
                "exit controls require evidence for the selected worker creator",
            );
        }
    }

    fn exit_body(&self, name: &str) -> Option<&ExecutionBody> {
        self.services
            .exit
            .as_ref()?
            .bodies
            .iter()
            .find(|body| body.name == name)
    }

    fn exit_slice<'a>(&self, module: &'a [u8], body: &ExecutionBody) -> Option<&'a [u8]> {
        let offset = self
            .memory
            .address_to_offset(body.address, u64::from(body.length))
            .ok()?;
        let start = usize::try_from(offset).ok()?;
        module.get(start..start.checked_add(body.length as usize)?)
    }

    pub(crate) fn validate_exit_bytes(&self, module: &[u8], report: &mut ValidationReport) {
        let Some(exit) = &self.services.exit else {
            return;
        };
        for body in &exit.bodies {
            if !self
                .exit_slice(module, body)
                .is_some_and(|bytes| hash_matches(&sha256(bytes), &body.sha256))
            {
                report.add(
                    format!("services.exit.bodies.{}", body.name),
                    IssueKind::FingerprintMismatch,
                    "complete exit function differs from the official image",
                );
            }
        }
        let words = |name: &str| {
            self.exit_body(name)
                .and_then(|body| self.exit_slice(module, body))
        };
        let mapping = &exit.menu_release_mapping;
        let mapping_matches = self
            .memory
            .address_to_offset(mapping.address, 8)
            .ok()
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| module.get(offset..offset.checked_add(8)?))
            .is_some_and(|bytes| instructions_match(bytes, 0, &[0, exit.menu_release_code]));
        if !mapping_matches {
            report.add(
                "services.exit.menu_release_mapping",
                IssueKind::FingerprintMismatch,
                "native zero-key release mapping differs from stock",
            );
        }
        let action_matches = words("input_action").is_some_and(|bytes| {
            [8usize, 12, 16, 24]
                .into_iter()
                .enumerate()
                .all(|(half, offset)| {
                    let base = if half == 0 { 0xd2800000 } else { 0xf2800000 };
                    instruction(bytes, offset)
                        == Some(
                            base | ((half as u32) << 21)
                                | (((mapping.address >> (half * 16)) as u32 & 0xffff) << 5)
                                | 19,
                        )
                })
                && instructions_match(bytes, 0x34, &[0x8b204e68, 0xb9400513])
        });
        if !action_matches {
            report.add(
                "services.exit.bodies.input_action",
                IssueKind::Conflict,
                "native action lookup does not read the declared release mapping",
            );
        }
        // Registration writes the callback and its context into consecutive
        // qwords. Bind the writable slot to these instructions, not a guessed
        // BSS range (the slot is outside the initialized-data segments).
        let slot = exit.input_callback;
        let register = words("input_register");
        let registration_matches = register.is_some_and(|w| {
            let mut expected = [0u32; 11];
            for half in 0..4 {
                for (index, (reg, address)) in [(8, slot), (9, slot.saturating_add(8))]
                    .into_iter()
                    .enumerate()
                {
                    let base = if half == 0 { 0xd2800000 } else { 0xf2800000 };
                    expected[half * 2 + index] = base
                        | ((half as u32) << 21)
                        | (((address >> (half * 16)) as u32 & 0xffff) << 5)
                        | reg;
                }
            }
            expected[8..].copy_from_slice(&[0xf9000100, 0xf9000121, 0xd65f03c0]);
            instructions_match(w, 0, &expected)
        });
        if !registration_matches {
            report.add(
                "services.exit.input_callback",
                IssueKind::Conflict,
                "stock registration does not write the declared callback/context slot",
            );
        }
        // The physical worker loads that same slot, preserves combined+0 as
        // the original context, and calls callback(combined).
        let invocation_matches = words("input_worker").is_some_and(|w| {
            let mut expected = [0u32; 5];
            for (half, word) in expected[..4].iter_mut().enumerate() {
                let base = if half == 0 { 0xd2800000 } else { 0xf2800000 };
                *word = base
                    | ((half as u32) << 21)
                    | (((slot >> (half * 16)) as u32 & 0xffff) << 5)
                    | 8;
            }
            expected[4] = 0xf9400108;
            instructions_match(w, 0x61c, &expected)
                && instructions_match(w, 0x65c, &[0xaa1403e0, 0xf9400129, 0xf9000289, 0xd63f0100])
        });
        if !invocation_matches {
            report.add(
                "services.exit.bodies.input_worker",
                IssueKind::Conflict,
                "physical callback invocation differs from the combined-record ABI",
            );
        }
        if !words("input_bank").is_some_and(|w| {
            instructions_match(
                w,
                0,
                &[
                    u32::from_le_bytes([0x48, 0, 1, 0x4a]),
                    0x29000801,
                    0x0a010109,
                    0x0a02010a,
                    0x29012408,
                    0xb900100a,
                    0xd65f03c0,
                ],
            )
        }) {
            report.add(
                "services.exit.bodies.input_bank",
                IssueKind::Conflict,
                "combined bank must carry five current/previous/changed/pressed/released words",
            );
        }
        // Native creation returns a kernel id in w0, saved in w22 then at
        // wrapper+0 and registered with the SAME id (w1=w22, x2=wrapper).
        if !words("worker_create").is_some_and(|w| {
            instruction(w, 0x90) == Some(0x2a0003f6)
                && instruction(w, 0x98) == Some(0xb9000276)
                && instructions_match(w, 0xc8, &[0x2a1f03e0, 0x2a1603e1, 0xaa1303e2])
        }) {
            report.add(
                "services.exit.bodies.worker_create",
                IssueKind::Conflict,
                "worker registry and wrapper+0 must use the returned kernel task id",
            );
        }
        let init = self.exit_body("worker_init");
        let create = self.exit_body("worker_create");
        if !init.zip(create).is_some_and(|(init, create)| {
            words("worker_init")
                .and_then(|w| instruction(w, 84))
                .is_some_and(|word| {
                    word & 0xfc000000 == 0x14000000
                        && (init.address as i64
                            + 84
                            + ((((word & 0x03ffffff) as i32) << 6 >> 6) as i64 * 4))
                            == create.address as i64
                })
        }) {
            report.add(
                "services.exit.bodies.worker_init",
                IssueKind::Conflict,
                "selected worker initializer must tail-call the audited native creator",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BuildMode, ExitServices, MemorySegment, MemorySegmentKind, ServiceFingerprint};

    fn put(module: &mut [u8], address: u64, offset: usize, words: &[u32]) {
        let start = (address - 0x10000) as usize + offset;
        for (index, word) in words.iter().enumerate() {
            module[start + index * 4..start + index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
    }

    fn fixture() -> (Profile, Vec<u8>) {
        let mut p = Profile::default();
        let mut module = vec![0u8; 0x8000];
        p.abi.task = Some(TaskFamily::Z8WorkerV1);
        p.task.core = Some(1);
        p.task.priority = Some(32);
        p.memory.xip_base = Some(0x10000);
        p.memory.module_size = Some(module.len() as u64);
        p.memory.segments = vec![MemorySegment {
            file_offset: 0,
            runtime_start: 0x10000,
            size: module.len() as u64,
            kind: MemorySegmentKind::Xip,
        }];
        let bodies = REQUIRED_BODIES
            .iter()
            .enumerate()
            .map(|(index, (name, length))| ExecutionBody {
                name: (*name).into(),
                address: 0x10000 + index as u64 * 0x800,
                length: *length,
                sha256: String::new(),
            })
            .collect::<Vec<_>>();
        p.services.worker_init = Some(bodies[7].address);
        p.services.exit = Some(ExitServices {
            input_callback: 0x70008,
            bank: 1,
            mask: 0xc000,
            release_mask: 0x8000,
            menu_release_code: 0x279,
            menu_release_mapping: crate::ExecutionTable {
                name: "menu_release".into(),
                address: 0x17ff0,
                element_bytes: 4,
                values: vec![0, 0x279],
            },
            suspend: bodies[0].address,
            resume: bodies[1].address,
            terminate: bodies[2].address,
            restart: bodies[3].address,
            bodies,
        });
        let slot = p.services.exit.as_ref().unwrap().input_callback;
        let mut registration = Vec::new();
        for half in 0..4 {
            for (reg, address) in [(8, slot), (9, slot + 8)] {
                let base = if half == 0 { 0xd2800000 } else { 0xf2800000 };
                registration.push(
                    base | (half << 21) | (((address >> (half * 16)) as u32 & 0xffff) << 5) | reg,
                );
            }
        }
        registration.extend([0xf9000100, 0xf9000121, 0xd65f03c0]);
        put(
            &mut module,
            p.exit_body("input_register").unwrap().address,
            0,
            &registration,
        );
        let worker = p.exit_body("input_worker").unwrap().address;
        let invocation = (0..4)
            .map(|half| {
                let base = if half == 0 { 0xd2800000 } else { 0xf2800000 };
                base | (half << 21) | (((slot >> (half * 16)) as u32 & 0xffff) << 5) | 8
            })
            .chain([0xf9400108])
            .collect::<Vec<_>>();
        put(&mut module, worker, 0x61c, &invocation);
        put(
            &mut module,
            worker,
            0x65c,
            &[0xaa1403e0, 0xf9400129, 0xf9000289, 0xd63f0100],
        );
        put(
            &mut module,
            p.exit_body("input_bank").unwrap().address,
            0,
            &[
                u32::from_le_bytes([0x48, 0, 1, 0x4a]),
                0x29000801,
                0x0a010109,
                0x0a02010a,
                0x29012408,
                0xb900100a,
                0xd65f03c0,
            ],
        );
        let create = p.exit_body("worker_create").unwrap().address;
        put(&mut module, create, 0x90, &[0x2a0003f6]);
        put(&mut module, create, 0x98, &[0xb9000276]);
        put(
            &mut module,
            create,
            0xc8,
            &[0x2a1f03e0, 0x2a1603e1, 0xaa1303e2],
        );
        let init = p.exit_body("worker_init").unwrap().address;
        put(
            &mut module,
            init,
            84,
            &[0x14000000 | (((create as i64 - init as i64 - 84) / 4) as u32 & 0x03ffffff)],
        );
        let mapping = p
            .services
            .exit
            .as_ref()
            .unwrap()
            .menu_release_mapping
            .address;
        put(&mut module, mapping, 0, &[0, 0x279]);
        let action = p.exit_body("input_action").unwrap().address;
        for (half, offset) in [8usize, 12, 16, 24].into_iter().enumerate() {
            let base = if half == 0 { 0xd2800000 } else { 0xf2800000 };
            put(
                &mut module,
                action,
                offset,
                &[base
                    | ((half as u32) << 21)
                    | (((mapping >> (half * 16)) as u32 & 0xffff) << 5)
                    | 19],
            );
        }
        put(&mut module, action, 0x34, &[0x8b204e68, 0xb9400513]);
        for body in &mut p.services.exit.as_mut().unwrap().bodies {
            let offset = (body.address - 0x10000) as usize;
            body.sha256 = sha256(&module[offset..offset + body.length as usize]);
            if ["suspend", "resume", "terminate", "restart"].contains(&body.name.as_str()) {
                p.service_fingerprints.insert(
                    format!("exit.{}", body.name),
                    ServiceFingerprint {
                        eg_off: offset as u64,
                        stock: module[offset..offset + 24].to_vec(),
                    },
                );
            }
        }
        (p, module)
    }

    #[test]
    fn old_profiles_accept_absent_exit() {
        let p = Profile::from_toml("schema = 1").unwrap();
        assert!(p.services.exit.is_none());
        let mut report = ValidationReport::default();
        p.validate_exit(&mut report);
        p.validate_exit_bytes(&[], &mut report);
        assert!(report.is_valid());
    }

    #[test]
    fn complete_optional_exit_round_trips_and_validates() {
        let (p, module) = fixture();
        assert_eq!(Profile::from_toml(&p.to_toml().unwrap()).unwrap(), p);
        let mut report = ValidationReport::default();
        p.validate_exit(&mut report);
        p.validate_exit_bytes(&module, &mut report);
        assert!(report.is_valid(), "{:?}", report.issues);
    }

    #[test]
    fn incomplete_or_unknown_optional_fields_fail_parsing() {
        assert!(Profile::from_toml("schema = 1\n[services.exit]\nbank = 1").is_err());
        let (p, _) = fixture();
        assert!(Profile::from_toml(
            &p.to_toml()
                .unwrap()
                .replace("bank = 1", "bank = 1\ninvented = 1")
        )
        .is_err());
    }

    #[test]
    fn exit_requires_complete_evidence_and_responsive_cpu0_worker() {
        for variant in 0..8 {
            let (mut p, _) = fixture();
            match variant {
                0 => {
                    p.services.exit.as_mut().unwrap().bodies.remove(0);
                }
                1 => p.services.exit.as_mut().unwrap().bodies[0].length = 24,
                2 => {
                    p.service_fingerprints.remove("exit.terminate");
                }
                3 => p.services.exit.as_mut().unwrap().terminate += 4,
                4 => p.task.core = Some(2),
                5 => p.task.priority = Some(27),
                6 => p.services.exit.as_mut().unwrap().mask = 0x8000,
                _ => p.services.exit.as_mut().unwrap().input_callback += 1,
            }
            let mut report = ValidationReport::default();
            p.validate_exit(&mut report);
            assert!(!report.is_valid(), "variant {variant}");
        }
    }

    #[test]
    fn body_tampering_and_semantic_misbinding_are_refused() {
        for variant in 0..4 {
            let (mut p, mut module) = fixture();
            match variant {
                0 => module[0] ^= 1,
                1 => p.services.exit.as_mut().unwrap().input_callback += 8,
                2 => {
                    let body = p.exit_body("worker_create").unwrap().clone();
                    put(&mut module, body.address, 0x98, &[0xb9000676]);
                    p.services
                        .exit
                        .as_mut()
                        .unwrap()
                        .bodies
                        .iter_mut()
                        .find(|b| b.name == body.name)
                        .unwrap()
                        .sha256 = sha256(
                        &module[(body.address - 0x10000) as usize
                            ..(body.address - 0x10000) as usize + body.length as usize],
                    );
                }
                _ => {
                    let body = p.exit_body("input_bank").unwrap().clone();
                    put(&mut module, body.address, 0, &[0]);
                    p.services
                        .exit
                        .as_mut()
                        .unwrap()
                        .bodies
                        .iter_mut()
                        .find(|b| b.name == body.name)
                        .unwrap()
                        .sha256 = sha256(
                        &module[(body.address - 0x10000) as usize
                            ..(body.address - 0x10000) as usize + body.length as usize],
                    );
                }
            }
            let mut report = ValidationReport::default();
            p.validate_exit_bytes(&module, &mut report);
            assert!(!report.is_valid(), "variant {variant}");
        }
    }

    #[test]
    fn task_fingerprint_must_map_to_its_declared_entry() {
        let (mut p, _) = fixture();
        p.service_fingerprints
            .get_mut("exit.resume")
            .unwrap()
            .eg_off += 4;
        assert!(p.validate(BuildMode::Marker).issues.iter().any(|issue| {
            issue.field == "service_fingerprints.exit.resume" && issue.kind == IssueKind::Conflict
        }));
    }

    #[test]
    fn release_mapping_and_menu_bit_are_checked_against_stock() {
        for variant in 0..4 {
            let (mut p, mut module) = fixture();
            match variant {
                0 => p.services.exit.as_mut().unwrap().release_mask = 0x4000,
                1 => p.services.exit.as_mut().unwrap().menu_release_code = 0x27e,
                2 => put(&mut module, 0x17ff0, 4, &[0x27e]),
                _ => {
                    p.services
                        .exit
                        .as_mut()
                        .unwrap()
                        .menu_release_mapping
                        .address += 8
                }
            }
            let mut report = ValidationReport::default();
            p.validate_exit(&mut report);
            p.validate_exit_bytes(&module, &mut report);
            assert!(!report.is_valid(), "variant {variant}");
        }
    }
}
