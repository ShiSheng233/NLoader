#!/usr/bin/env python3
"""Build deterministic M2 diagnostic programs and independent card folders."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
PROGRAMS = ("data_app", "api_limits", "extension_one", "extension_two",
            "extension_three", "code_fourth", "fio_loop")


def audit_program(data):
    if len(data) < 64:
        raise ValueError("Truncated program")
    h = struct.unpack("<16I", data[:64])
    if h[0:3] != (0x444C504E, 0x00400002, 0) or h[6] != 2 or h[8] not in (1, 2):
        raise ValueError("Expected the independently declared generic ABI2 header")
    image_size, bss_size, entry, reloc_size = h[3], h[4], h[5], h[9]
    image_start = 64 + reloc_size
    data_start = image_start + image_size
    if reloc_size % 12 or entry % 4 or image_size < 4 or entry > image_size - 4:
        raise ValueError("Invalid entry or relocation table")
    if data_start > len(data) or any(h[n] for n in (10, 11, 14, 15)):
        raise ValueError("Invalid segment bounds/reserved field")
    reloc, image, writable = data[64:image_start], data[image_start:data_start], data[data_start:]
    if (zlib.crc32(image), zlib.crc32(writable), zlib.crc32(reloc)) != (h[7], h[12], h[13]):
        raise ValueError("Program CRC mismatch")
    entries = []
    for offset, target, kind in struct.iter_unpack("<III", reloc):
        if kind == 0:
            if offset % 4 or offset + 4 > len(image) or target >= len(writable) + bss_size:
                raise ValueError("Invalid ADRP relocation bounds")
            instruction = struct.unpack_from("<I", image, offset)[0]
            if instruction & 0x9F000000 != 0x90000000:
                raise ValueError("Expected an actual ADRP instruction")
        elif kind == 1:
            if offset + 8 > len(writable) + bss_size or target >= len(image):
                raise ValueError("Invalid ABS64 relocation bounds")
        else:
            raise ValueError("Unexpected relocation kind")
        entries.append({"offset": offset, "target": target, "kind": kind})
    return {"sha256": hashlib.sha256(data).hexdigest(), "file_bytes": len(data),
            "image_bytes": image_size, "data_bytes": len(writable), "bss_bytes": bss_size,
            "entry_offset": entry, "kind": h[8], "relocations": entries}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cli", type=Path, default=ROOT / "tool/nloader/target/debug/nloader")
    parser.add_argument("--cc", default="/opt/homebrew/opt/llvm/bin/clang")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    programs = args.out / "programs"
    programs.mkdir()
    records = {}
    for name in PROGRAMS:
        declaration = json.loads((HERE / (name + ".json")).read_text())
        copies = []
        for iteration in (1, 2):
            output = programs / f"{name}-{iteration}.NLB"
            manifest = programs / f"{name}-{iteration}.MANIFEST"
            command = [str(args.cli.resolve()), "program", "--decl", str(HERE / (name + ".json")),
                       "--source", str(ROOT / "sdk/crt0.s"), "--source", str(HERE / (name + ".c")),
                       "--include", str(ROOT / "sdk"), "--cc", args.cc,
                       "--out", str(output), "--manifest", str(manifest)]
            completed = subprocess.run(command, check=True, capture_output=True, text=True, cwd=ROOT)
            (programs / f"{name}-{iteration}.build.json").write_text(completed.stdout)
            copies.append(output.read_bytes())
        if copies[0] != copies[1]:
            raise ValueError("Nondeterministic program: " + name)
        record = audit_program(copies[0])
        if name in ("data_app", "extension_one", "extension_two", "extension_three"):
            if not record["data_bytes"] or record["bss_bytes"] != 148:
                raise ValueError("Data/BSS fixture did not keep its declared storage")
            if {entry["kind"] for entry in record["relocations"]} != {0, 1}:
                raise ValueError("Data fixture lost one of its two relocation classes")
        records[name] = dict(record, declaration=declaration, two_builds_identical=True)
    cases = {}

    def card(name, selected, mode=None, enabled=None, files=None, expected_text=None):
        folder = args.out / "cards" / name
        apps = folder / "NLOADER/APPS"
        apps.mkdir(parents=True)
        lines = []
        for program in selected:
            filename = Path(records[program]["declaration"]["file"]).name
            shutil.copyfile(programs / f"{program}-1.NLB", apps / filename)
            lines.append((programs / f"{program}-1.MANIFEST").read_text())
        (apps.parent / "MANIFEST").write_text("".join(lines))
        if mode is not None:
            (apps.parent / "MODE.TXT").write_text(mode)
        if enabled is not None:
            (apps.parent / "ENABLED").write_text("".join(records[p]["declaration"]["id"] + "\n" for p in enabled))
        for filename, content in (files or {}).items():
            (apps.parent / filename).write_bytes(content)
        cases[name] = {"folder": str(folder.resolve()), "programs": selected, "mode": mode,
                       "enabled": enabled, "files": {
                           str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in folder.rglob("*") if p.is_file()}}
        if expected_text is not None:
            cases[name]["expected_text"] = expected_text

    for suffix, mode in (("return", "R"), ("exit", "E"), ("hold", "H")):
        card("data-" + suffix, ["data_app"], mode)
        card("alloc-" + suffix, ["api_limits"], "A" + mode)
        card("files-" + suffix, ["api_limits"], "F" + mode)
    card("unsupported", ["api_limits"], "UR")
    card("file-service", ["fio_loop"], "IH", files={"FIO.TXT": bytes(range(256)) * 32},
         expected_text="File service loop")
    card("budget-fit", ["extension_one", "extension_two", "data_app"], "R",
         ["extension_one", "extension_two"])
    card("budget-full", ["extension_one", "extension_two", "extension_three", "data_app"], "R",
         ["extension_one", "extension_two", "extension_three"])
    record = {"programs": records, "cases": cases, "actual_qemu_verified": False}
    (args.out / "materials.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"programs": len(records), "cards": len(cases), "out": str(args.out)}))


if __name__ == "__main__":
    main()
