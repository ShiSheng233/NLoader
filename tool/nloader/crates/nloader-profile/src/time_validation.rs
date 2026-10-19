//! Original clock, tick conversion and blocking-delay evidence.
use crate::validation::{hash_matches, valid_hash};
use crate::{sha256, AddressRange, IssueKind, Profile, ValidationReport};
use std::collections::BTreeSet;

pub(crate) const TIME_BODIES: &[(&str, u32)] = &[
    ("clock_us", 28),
    ("counter_frequency_query", 24),
    ("counter_boot", 248),
    ("delay_ms", 368),
    ("delay_wakeup", 328),
    ("deadline_insert", 72),
    ("tick_setup", 172),
    ("tick_callback", 84),
    ("tick_queue_advance", 512),
    ("timer_register", 32),
    ("timer_enqueue", 196),
    ("timer_periodic_dispatch", 328),
];

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
fn words(bytes: &[u8], at: usize, expected: &[u32]) -> bool {
    expected
        .iter()
        .enumerate()
        .all(|(n, v)| word(bytes, at + n * 4) == Some(*v))
}
fn materializes(bytes: &[u8], offsets: [usize; 4], register: u32, value: u64) -> bool {
    offsets.iter().enumerate().all(|(n, at)| {
        word(bytes, *at)
            == Some(
                (if n == 0 { 0xd2800000 } else { 0xf2800000 })
                    | ((n as u32) << 21)
                    | (((value >> (n * 16)) as u32 & 65535) << 5)
                    | register,
            )
    })
}
fn branches(bytes: &[u8], at: usize, base: u64, destination: u64, link: bool) -> bool {
    word(bytes, at).is_some_and(|w| {
        w & 0xfc000000 == if link { 0x94000000 } else { 0x14000000 }
            && base.checked_add(at as u64).and_then(|site| {
                site.checked_add_signed(i64::from(((w & 0x03ffffff) as i32) << 6 >> 6) * 4)
            }) == Some(destination)
    })
}

impl Profile {
    pub(crate) fn validate_time(&self, report: &mut ValidationReport) {
        let Some(time) = &self.services.time else {
            return;
        };
        if self.identity.model != "Z8"
            || self.identity.firmware != "3.11"
            || time.counter_frequency_hz != 24_000_000
            || time.tick_period_us != 1000
        {
            report.add(
                "services.time",
                IssueKind::Unsupported,
                "time family requires Z8 C3.11, the 24 MHz counter and original 1 ms tick",
            );
        }
        let table = &time.tick_period;
        if table.name != "tick_period"
            || table.element_bytes != 4
            || table.address % 8 != 0
            || table.values != [1, 1000]
            || self.memory.address_to_offset(table.address, 8).is_err()
        {
            report.add(
                "services.time.tick_period",
                IssueKind::Conflict,
                "original periodic mode and microsecond period must be independently mapped",
            );
        }
        let mut seen = BTreeSet::new();
        for body in &time.bodies {
            if !seen.insert(body.name.as_str())
                || TIME_BODIES
                    .iter()
                    .find(|(name, _)| *name == body.name)
                    .is_none_or(|(_, size)| *size != body.length)
                || body.address % 4 != 0
                || !valid_hash(&body.sha256)
                || !self
                    .memory
                    .is_xip_range(body.address, u64::from(body.length))
                || time.entry(&body.name) != Some(body.address)
            {
                report.add(
                    format!("services.time.bodies.{}", body.name),
                    IssueKind::Invalid,
                    "time evidence must name one complete, aligned original function",
                );
            }
            if self.memory.slack.as_ref().is_some_and(|slack| {
                slack.range().overlaps(&AddressRange {
                    start: body.address,
                    end: body.address.saturating_add(u64::from(body.length)),
                })
            }) {
                report.add(
                    format!("services.time.bodies.{}", body.name),
                    IssueKind::Conflict,
                    "original time evidence overlaps loader reservation",
                );
            }
        }
        for (name, _) in TIME_BODIES {
            if !seen.contains(name)
                || !self
                    .service_fingerprints
                    .contains_key(&format!("time.{name}"))
            {
                report.add(
                    format!("services.time.bodies.{name}"),
                    IssueKind::Missing,
                    "time services require the complete function and entry fingerprint",
                );
            }
        }
    }

    pub(crate) fn validate_time_bytes(&self, module: &[u8], report: &mut ValidationReport) {
        let Some(time) = &self.services.time else {
            return;
        };
        let slice = |address, size| {
            let at = usize::try_from(self.memory.address_to_offset(address, size).ok()?).ok()?;
            module.get(at..at.checked_add(size as usize)?)
        };
        let body = |name: &str| {
            time.bodies
                .iter()
                .find(|b| b.name == name)
                .and_then(|b| slice(b.address, u64::from(b.length)))
        };
        for evidence in &time.bodies {
            if !slice(evidence.address, u64::from(evidence.length))
                .is_some_and(|bytes| hash_matches(&sha256(bytes), &evidence.sha256))
            {
                report.add(
                    format!("services.time.bodies.{}", evidence.name),
                    IssueKind::Conflict,
                    "complete time function differs from the official image",
                );
            }
        }
        let entry = |name| time.entry(name).unwrap_or(0);
        let matches = |name, check: &dyn Fn(&[u8]) -> bool| body(name).is_some_and(check);
        let checks = [
            (
                "clock_us",
                matches("clock_us", &|b| {
                    words(
                        b,
                        0,
                        &[
                            0xb201f3e8, 0xd53be029, 0xf2955568, 0x9bc87d28, 0xd344fd08, 0xf9000008,
                            0xd65f03c0,
                        ],
                    )
                }),
            ),
            (
                "counter_frequency_query",
                matches("counter_frequency_query", &|b| {
                    words(
                        b,
                        0,
                        &[
                            0xd5033f9f, 0xd5033fdf, 0xd53be008, 0x92407d08, 0xf9000408, 0xd65f03c0,
                        ],
                    )
                }),
            ),
            (
                "counter_boot",
                matches("counter_boot", &|b| {
                    word(b, 0x80) == Some(0x5286c00e)
                        && word(b, 0x90) == Some(0x72a02dce)
                        && word(b, 0x9c) == Some(0xd51be00e)
                        && words(b, 0xb0, &[0xd53be008, 0x6b0e011f, 0x540001e1])
                        && word(b, 0xf4) == Some(0x14000000)
                }),
            ),
            (
                "delay_ms",
                matches("delay_ms", &|b| {
                    words(b, 0x20, &[0xd538d089, 0xb9405129, 0xd51b4228, 0x350008e9])
                        && word(b, 0x34) == Some(0x373808a8)
                        && word(b, 0x50) == Some(0xb9401508)
                        && materializes(b, [0xf4, 0xf8, 0xfc, 0x100], 8, entry("delay_wakeup"))
                        && word(b, 0x110) == Some(0x8b334122)
                        && branches(b, 0x114, time.delay_ms, entry("deadline_insert"), true)
                        && word(b, 0x134) == Some(0xb9403e80)
                        && word(b, 0x148) == Some(0x321b77e0)
                        && word(b, 0x164) == Some(0x321b77e0)
                }),
            ),
            (
                "delay_wakeup",
                matches("delay_wakeup", &|b| {
                    word(b, 0x18) == Some(0xb9003e7f) && word(b, 0x144) == Some(0xd65f03c0)
                }),
            ),
            (
                "deadline_insert",
                matches("deadline_insert", &|b| {
                    word(b, 0x10) == Some(0xaa0203f3) && word(b, 0x38) == Some(0xa9005513)
                }),
            ),
            (
                "tick_setup",
                matches("tick_setup", &|b| {
                    materializes(b, [0x64, 0x68, 0x6c, 0x70], 8, time.tick_period.address)
                        && materializes(b, [0x74, 0x78, 0x7c, 0x84], 9, entry("tick_callback"))
                        && word(b, 0x80) == Some(0xfd400100)
                        && word(b, 0x98) == Some(0xfd000e60)
                        && branches(b, 0xa8, entry("tick_setup"), entry("timer_register"), false)
                }),
            ),
            (
                "tick_callback",
                matches("tick_callback", &|b| {
                    branches(
                        b,
                        0x38,
                        entry("tick_callback"),
                        entry("tick_queue_advance"),
                        true,
                    )
                }),
            ),
            (
                "tick_queue_advance",
                matches("tick_queue_advance", &|b| {
                    words(
                        b,
                        0x9c,
                        &[0xf9400a69, 0xb9401a68, 0x9100052a, 0xf9000269, 0xf9000a6a],
                    )
                }),
            ),
            (
                "timer_register",
                matches("timer_register", &|b| {
                    branches(
                        b,
                        0x1c,
                        entry("timer_register"),
                        entry("timer_enqueue"),
                        false,
                    )
                }),
            ),
            (
                "timer_enqueue",
                matches("timer_enqueue", &|b| {
                    word(b, 0x18) == Some(0xb9401e96)
                        && materializes(b, [0x6c, 0x70, 0x74, 0x78], 9, 0x431bde82d7b634db)
                        && words(b, 0x7c, &[0x9b167d08, 0x9bc97d08, 0x8b484808, 0xf9000a88])
                }),
            ),
            (
                "timer_periodic_dispatch",
                matches("timer_periodic_dispatch", &|b| {
                    materializes(b, [0x78, 0x7c, 0x80, 0x88], 25, 0x431bde82d7b634db)
                        && words(b, 0x9c, &[0xb9401ec8, 0xf9400689, 0x9b087d28, 0x9bd97d09])
                        && word(b, 0xb0) == Some(0xd352fd29)
                }),
            ),
        ];
        for (name, valid) in checks {
            if !valid {
                report.add(
                    format!("services.time.bodies.{name}"),
                    IssueKind::Conflict,
                    "original clock units, result propagation or tick linkage differ",
                );
            }
        }
        if !slice(time.tick_period.address, 8).is_some_and(|b| words(b, 0, &[1, 1000])) {
            report.add(
                "services.time.tick_period",
                IssueKind::Conflict,
                "the actual original timer must be periodic at 1000 microseconds",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ExecutionBody, ExecutionTable, MemorySegment, MemorySegmentKind, TimeFamily, TimeServices,
    };

    #[test]
    fn absent_time_is_optional_and_unknown_fields_are_rejected() {
        let profile = Profile::default();
        let mut report = ValidationReport::default();
        profile.validate_time(&mut report);
        profile.validate_time_bytes(&[], &mut report);
        assert!(report.is_valid());
        assert!(Profile::from_toml("schema=1\n[services.time]\nfamily='unknown'").is_err());
    }

    #[test]
    fn missing_functions_frequency_and_period_cannot_authorize_time() {
        let mut profile = Profile::default();
        profile.services.time = Some(TimeServices {
            family: TimeFamily::Z8CounterDelayV1,
            clock_us: 0,
            delay_ms: 0,
            counter_frequency_query: 0,
            counter_frequency_hz: 24_000_001,
            tick_period_us: 999,
            tick_period: ExecutionTable {
                name: "tick_period".into(),
                address: 0,
                element_bytes: 4,
                values: vec![1, 999],
            },
            bodies: vec![],
        });
        let mut report = ValidationReport::default();
        profile.validate_time(&mut report);
        profile.validate_time_bytes(&[], &mut report);
        assert!(!report.is_valid());
        assert!(report
            .issues
            .iter()
            .any(|e| e.field == "services.time.tick_period"));
        assert!(report
            .issues
            .iter()
            .any(|e| e.field == "services.time.bodies.clock_us"));
        let malformed = ExecutionBody {
            name: "clock_us".into(),
            address: 0,
            length: 4,
            sha256: "00".repeat(32),
        };
        profile.services.time.as_mut().unwrap().bodies = vec![malformed.clone(), malformed];
        let mut report = ValidationReport::default();
        profile.validate_time(&mut report);
        assert!(!report.is_valid());
    }

    #[test]
    fn rehashed_clock_changes_and_misbound_periods_are_still_refused() {
        let mut profile = Profile::default();
        let mut module = vec![0u8; 0x3000];
        profile.memory.xip_base = Some(0x1000);
        profile.memory.module_size = Some(module.len() as u64);
        profile.memory.segments = vec![MemorySegment {
            file_offset: 0,
            runtime_start: 0x1000,
            size: module.len() as u64,
            kind: MemorySegmentKind::Xip,
        }];
        // Synthetic isolated ABI specimens; unrelated required functions are
        // deliberately absent and must remain reported as missing evidence.
        let specimens: [(&str, u64, &[u32]); 2] = [
            (
                "clock_us",
                0x1000,
                &[
                    0xb201f3e8, 0xd53be029, 0xf2955568, 0x9bc87d28, 0xd344fd08, 0xf9000008,
                    0xd65f03c0,
                ],
            ),
            (
                "counter_frequency_query",
                0x2000,
                &[
                    0xd5033f9f, 0xd5033fdf, 0xd53be008, 0x92407d08, 0xf9000408, 0xd65f03c0,
                ],
            ),
        ];
        let mut bodies = Vec::new();
        for (name, address, instructions) in specimens {
            let bytes: Vec<_> = instructions.iter().flat_map(|v| v.to_le_bytes()).collect();
            let at = (address - 0x1000) as usize;
            module[at..at + bytes.len()].copy_from_slice(&bytes);
            bodies.push(ExecutionBody {
                name: name.into(),
                address,
                length: bytes.len() as u32,
                sha256: sha256(&bytes),
            });
        }
        module[0x2000..0x2008].copy_from_slice(&[1, 0, 0, 0, 232, 3, 0, 0]);
        profile.services.time = Some(TimeServices {
            family: TimeFamily::Z8CounterDelayV1,
            clock_us: 0x1000,
            delay_ms: 0x4000,
            counter_frequency_query: 0x2000,
            counter_frequency_hz: 24_000_000,
            tick_period_us: 1000,
            tick_period: ExecutionTable {
                name: "tick_period".into(),
                address: 0x3000,
                element_bytes: 4,
                values: vec![1, 1000],
            },
            bodies,
        });
        let check = |p: &Profile, bytes: &[u8], field: &str| {
            let mut report = ValidationReport::default();
            p.validate_time_bytes(bytes, &mut report);
            report.issues.iter().any(|issue| issue.field == field)
        };
        assert!(!check(&profile, &module, "services.time.bodies.clock_us"));
        assert!(!check(
            &profile,
            &module,
            "services.time.bodies.counter_frequency_query"
        ));
        assert!(!check(&profile, &module, "services.time.tick_period"));
        for (index, at) in [(0, 16), (0, 20), (1, 0x1008), (1, 0x1010)] {
            let mut altered = module.clone();
            altered[at] ^= 32;
            let mut changed = profile.clone();
            let body = &mut changed.services.time.as_mut().unwrap().bodies[index];
            let offset = (body.address - 0x1000) as usize;
            body.sha256 = sha256(&altered[offset..offset + body.length as usize]);
            let field = format!("services.time.bodies.{}", body.name);
            assert!(check(&changed, &altered, &field));
        }
        let mut altered = module.clone();
        altered[0x2004] ^= 1;
        assert!(check(&profile, &altered, "services.time.tick_period"));
        let mut changed = profile.clone();
        changed.services.time.as_mut().unwrap().tick_period.address += 4;
        assert!(check(&changed, &module, "services.time.tick_period"));
    }
}
