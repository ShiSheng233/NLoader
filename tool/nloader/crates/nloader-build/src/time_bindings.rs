//! Time adapters use only independently validated profile-owned addresses.
use nloader_profile::Profile;

pub(crate) fn generate(profile: &Profile) -> String {
    let Some(time) = &profile.services.time else {
        return String::new();
    };
    format!(
        r#"
#if defined(NLR_STAGE_EXEC)
static int32_t nlr_model_clock_ms(uint64_t *out)
{{
    if (!out) return NLR_NOT_READY;
    uint64_t frequency[2] = {{0, 0}};
    void (*query)(void *) = (void *)0x{query:x}UL;
    query(frequency);
    if (frequency[1] != {frequency}u) return NLR_NOT_READY;
    uint64_t microseconds = 0;
    void (*clock_us)(uint64_t *) = (void *)0x{clock:x}UL;
    clock_us(&microseconds);
    *out = microseconds / 1000u;
    return NLR_OK;
}}
static int32_t nlr_model_delay_ms(uint32_t ms)
{{
    if (!ms || ms > 10u) return NLR_NOT_READY;
    int32_t (*delay)(uint32_t) = (void *)0x{delay:x}UL;
    return delay(ms);
}}
static const struct nlr_time_services nlr_model_time_services = {{
    .clock_ms = nlr_model_clock_ms,
    .delay_ms = nlr_model_delay_ms,
}};
#endif
"#,
        query = time.counter_frequency_query,
        frequency = time.counter_frequency_hz,
        clock = time.clock_us,
        delay = time.delay_ms,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nloader_profile::{ExecutionTable, TimeFamily, TimeServices};
    use std::{fs, path::Path, process::Command};

    #[test]
    fn generated_time_uses_output_clock_abi_and_preserves_wait_failure() {
        let mut profile = Profile::default();
        assert!(generate(&profile).is_empty());
        profile.services.time = Some(TimeServices {
            family: TimeFamily::Z8CounterDelayV1,
            clock_us: 0x1110,
            delay_ms: 0x2220,
            counter_frequency_query: 0x3330,
            counter_frequency_hz: 24_000_000,
            tick_period_us: 1000,
            tick_period: ExecutionTable {
                name: "tick_period".into(),
                address: 0,
                element_bytes: 4,
                values: vec![1, 1000],
            },
            bodies: vec![],
        });
        let generated = generate(&profile)
            .replace("(void *)0x1110UL", "clock_stub")
            .replace("(void *)0x2220UL", "delay_stub")
            .replace("(void *)0x3330UL", "frequency_stub");
        let prefix = r#"
#define NLR_STAGE_EXEC
#include "nlr/services.h"
static uint64_t micros, frequency = 24000000;
static int32_t wait_result;
static uint32_t calls, waited;
static void clock_stub(uint64_t *out) { *out = micros; }
static void frequency_stub(void *out) { ((uint64_t *)out)[1] = frequency; }
static int32_t delay_stub(uint32_t ms) { calls++; waited = ms; return wait_result; }
"#;
        let suffix = r#"
int main(void) {
    uint64_t out = 77;
    micros = 1234999;
    if (nlr_model_time_services.clock_ms(&out) || out != 1234) return 1;
    frequency++;
    if (!nlr_model_time_services.clock_ms(&out) || out != 1234) return 2;
    frequency--;
    micros = UINT64_MAX;
    if (nlr_model_time_services.clock_ms(&out) || out != UINT64_MAX / 1000) return 3;
    if (!nlr_model_time_services.clock_ms(0)) return 4;
    if (!nlr_model_time_services.delay_ms(0) || !nlr_model_time_services.delay_ms(11) || calls) return 5;
    wait_result = -25;
    if (nlr_model_time_services.delay_ms(10) != -25 || calls != 1 || waited != 10) return 6;
    wait_result = 0;
    if (nlr_model_time_services.delay_ms(1) || calls != 2 || waited != 1) return 7;
    return 0;
}
"#;
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("time-bindings.c");
        let binary = directory.path().join("time-bindings");
        fs::write(&source, format!("{prefix}{generated}{suffix}")).unwrap();
        let include = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core/include");
        let compiled = Command::new("clang")
            .args(["-Wall", "-Wextra", "-Werror", "-Os"])
            .arg("-I")
            .arg(include)
            .arg(source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(Command::new(binary).status().unwrap().success());
    }
}
