//! Read-only stable-key mappings from the independently validated profile.
use nloader_profile::Profile;

pub(crate) fn generate(profile: &Profile) -> String {
    let Some(input) = &profile.services.input else {
        return String::new();
    };
    let mut out = String::from("\n#if defined(NLR_STAGE_EXEC)\n#include \"nlr/input.h\"\nstatic const struct nlr_input_binding nlr_model_input_bindings[] = {\n");
    for binding in &input.bindings {
        out.push_str(&format!(
            "    {{ {}u, {}u, 0x{:x}u }},\n",
            binding.key.bit(),
            binding.bank,
            binding.mask
        ));
    }
    out.push_str(&format!(
        "}};\nstatic const struct nlr_input_services nlr_model_input_services = {{\n    .bindings = nlr_model_input_bindings,\n    .count = {}u,\n    .reserved = {{ 0x{:x}u, 0x{:x}u, 0x{:x}u }},\n    .current_task = (void *)0x{:x}UL,\n}};\n#endif\n",
        input.bindings.len(), input.reserved[0], input.reserved[1], input.reserved[2], input.current_task));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use nloader_profile::{InputBinding, InputFamily, InputKey, InputServices};
    use std::{fs, path::Path, process::Command};

    #[test]
    fn generated_mapping_preserves_masks_and_worker_query() {
        let mut profile = Profile::default();
        assert!(generate(&profile).is_empty());
        profile.services.input = Some(InputServices {
            family: InputFamily::Z8SwitchBanksV1,
            callback_slot: 0x1000,
            current_task: 0x2000,
            reserved: [0, 0xc000, 0],
            bindings: vec![InputBinding {
                key: InputKey::Up,
                bank: 0,
                mask: 0x2a,
                sources: vec![],
            }],
            key_tables: vec![],
            bodies: vec![],
        });
        let generated = generate(&profile).replace("(void *)0x2000UL", "task_query");
        let source = format!(
            r#"
#define NLR_STAGE_EXEC
#include "nlr/input.h"
static int32_t task_query(uint32_t *out) {{ *out = 23; return -25; }}
{generated}
int main(void) {{
    uint32_t raw[3] = {{0x8, 0xc000, 0}}, held = 0, masks[3] = {{0}}, task = 0;
    if (nlr_input_map(&nlr_model_input_services, raw, &held) || held != NLR_KEY_UP) return 1;
    if (nlr_input_suppression_masks(&nlr_model_input_services, masks)) return 2;
    if (masks[0] != 0x2a || masks[1] || masks[2]) return 3;
    if (nlr_model_input_services.current_task(&task) != -25 || task != 23) return 4;
    return 0;
}}
"#
        );
        let directory = tempfile::tempdir().unwrap();
        let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../core");
        let file = directory.path().join("input-bindings.c");
        let binary = directory.path().join("input-bindings");
        fs::write(&file, source).unwrap();
        let compiled = Command::new("clang")
            .args(["-Wall", "-Wextra", "-Werror", "-Os"])
            .arg("-I")
            .arg(core.join("include"))
            .arg(file)
            .arg(core.join("input.c"))
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
