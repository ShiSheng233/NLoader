#!/usr/bin/env python3
"""Recompile bounded Runtime field offsets for data/allocation observations."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests/qemu"))
from observe_runtime import validate_specification


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-spec", type=Path, required=True)
    parser.add_argument("--additional-spec", type=Path)
    parser.add_argument("--select-fields", type=Path, help="Explicit JSON list retaining a bounded subset")
    parser.add_argument("--config-include", type=Path, required=True)
    parser.add_argument("--mode", choices=("exec", "prepare-only"), required=True)
    parser.add_argument("--budget", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    base = json.loads(args.base_spec.read_text())
    validate_specification(base)
    references = [base]
    if args.additional_spec:
        additional = json.loads(args.additional_spec.read_text())
        validate_specification(additional)
        if additional["layout"]["size"] != base["layout"]["size"]:
            raise ValueError("Additional observation has a different Runtime size")
        references.append(additional)
    args.out.mkdir(parents=True, exist_ok=False)
    fields = {name: {k: v for k, v in field.items() if k != "offset"}
              for name, field in base["layout"]["fields"].items()}
    for reference in references[1:]:
        for name, field in reference["layout"]["fields"].items():
            declaration = {k: v for k, v in field.items() if k != "offset"}
            if name in fields and fields[name] != declaration:
                raise ValueError("Conflicting observation declaration: " + name)
            fields[name] = declaration
    if args.additional_spec:
        for n in range(8):
            fields[f"menu_registration.{n}.state"] = {"type": "u32"}
    if args.budget:
        fields["recovery_view"] = {"type": "u32"}
        fields["saved_enabled.count"] = {"type": "u32"}
        for n in range(4):
            fields[f"saved_enabled.id.{n}"] = {"type": "cstring", "length": 33}
        for n in range(4):
            for member, kind in (("kind", "u32"), ("failed", "u32"), ("uncertain", "u32"),
                                 ("code_block", "u64"), ("code_bytes", "u32"),
                                 ("data_block", "u64"), ("data_bytes", "u32")):
                fields[f"resident.{n}.{member}"] = {"type": kind}
            fields[f"resident.{n}.id"] = {"type": "cstring", "length": 33}
    else:
        for n in range(16):
            fields[f"load.program.api_allocation.{n}"] = {"type": "u64"}
            fields[f"load.program.api_file.{n}"] = {"type": "i32"}
    for name in ("data_bytes", "bss_bytes", "reloc_bytes"):
        fields["load." + name] = {"type": "u32"}
    if args.select_fields:
        selected = json.loads(args.select_fields.read_text())
        if (not isinstance(selected, list) or not selected or
                any(not isinstance(name, str) for name in selected) or
                len(set(selected)) != len(selected) or not set(selected) <= fields.keys()):
            raise ValueError("Field selection must name distinct declared fields")
        fields = {name: fields[name] for name in selected}
    expressions = []
    for name in fields:
        member = {"load.services": "load.svc", "worker_callback": "load.worker.opaque",
                  "trace": "load.trace", "text": "text.words"}.get(name, name)
        member = re.sub(r"\.([0-9]+)(?=\.|$)", r"[\1]", member)
        expression = "offsetof(struct nlr_runtime," + member + ")"
        if name == "worker_callback":
            expression += "+NLR_WORKER_CALLBACK_OFFSET"
        expressions.append(expression)
    source = args.out / "offsets.c"
    source.write_text('#include <stddef.h>\n#include "nlr/runtime.h"\n'
                      'const uint64_t offsets[]={sizeof(struct nlr_runtime),'
                      + ",".join(expressions) + '};\n')
    obj = args.out / "offsets.o"
    flags = ["--target=aarch64-none-elf", "-march=armv8-a", "-ffreestanding", "-fno-builtin",
             "-Os", "-DNLR_STAGE_" + args.mode.upper().replace("-", "_"),
             "-I" + str(args.config_include.resolve()), "-I" + str(ROOT / "core/include"), "-c"]
    subprocess.run(["/opt/homebrew/opt/llvm/bin/clang", *flags, str(source), "-o", str(obj)], check=True)
    with obj.open("rb") as stream:
        elf = ELFFile(stream)
        symbols = list(elf.get_section_by_name(".symtab").iter_symbols())
        if any(s["st_shndx"] == "SHN_COMMON" for s in symbols):
            raise ValueError("Layout object contains COMMON")
        if any(s["sh_type"] in ("SHT_REL", "SHT_RELA") for s in elf.iter_sections()):
            raise ValueError("Layout object unexpectedly has relocations")
        symbol = next(s for s in symbols if s.name == "offsets")
        section = elf.get_section(symbol["st_shndx"])
        if not section["sh_flags"] & 2 or section["sh_flags"] & 5:
            raise ValueError("Layout constants must be allocated read-only data")
        raw = section.data()[symbol["st_value"]:symbol["st_value"] + symbol["st_size"]]
        values = struct.unpack("<" + str(len(raw) // 8) + "Q", raw)
    if len(values) != len(fields) + 1 or values[0] != base["layout"]["size"]:
        raise ValueError("Current compiled Runtime shape differs from the candidate")
    for (name, field), offset in zip(fields.items(), values[1:]):
        field["offset"] = offset
        for reference in references:
            if name in reference["layout"]["fields"] and field != reference["layout"]["fields"][name]:
                raise ValueError("Declaration differs from actual source: " + name)
    spec = dict(base, layout={"size": values[0], "fields": fields})
    validate_specification(spec)
    (args.out / "runtime-spec.json").write_text(json.dumps(spec, indent=2) + "\n")
    inputs = [source, obj, args.base_spec, *args.config_include.rglob("*.h"),
              *(ROOT / "core/include").rglob("*.h")]
    if args.additional_spec:
        inputs.append(args.additional_spec)
    if args.select_fields:
        inputs.append(args.select_fields)
    receipt = {"mode": args.mode, "runtime_bytes": values[0], "fields": len(fields),
               "compile_flags": flags, "additional_runtime_bytes": 0,
               "files_sha256": {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}}
    (args.out / "layout-evidence.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"bytes": values[0], "fields": len(fields), "output": str(args.out)}))


if __name__ == "__main__":
    main()
