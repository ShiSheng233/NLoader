#!/usr/bin/env python3
"""Create independently specified invalid v2 files; never patch a live card."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

from materials import audit_program


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--program", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    original = args.program.read_bytes()
    audit = audit_program(original)
    args.out.mkdir(parents=True, exist_ok=False)
    apps = args.out / "card-files/NLOADER/APPS"
    apps.mkdir(parents=True)
    entries = []

    def add(name, payload, check_result, execution_result=None, executor="program"):
        index = len(entries)
        filename = f"C{index:02d}.NLB"
        (apps / filename).write_bytes(payload)
        entries.append({"index": index, "id": "case" + str(index), "name": name,
                        "file": "APPS/" + filename, "sha256": hashlib.sha256(payload).hexdigest(),
                        "check_result": check_result, "execution_result": execution_result,
                        "executor": executor})

    def word(offset, value):
        data = bytearray(original)
        struct.pack_into("<I", data, offset, value)
        return data

    add("Valid data control", original, 0, 0)
    data = bytearray(original)
    data[0] = ord('X')
    add("Bad magic", data, -2)
    for name, offset, value, result in [
        ("Bad version", 4, (64 << 16) | 3, -2),
        ("Bad header size", 4, (65 << 16) | 2, -2),
        ("Bad flags", 8, 2, -2),
        ("Empty image", 12, 0, -3),
        ("Huge BSS", 16, 0x200001, -3),
        ("Unaligned entry", 20, 1, -3),
        ("Entry outside image", 20, audit["image_bytes"], -3),
        ("Newer ABI", 24, 99, -2),
        ("Wrong manifest kind", 32, 1, -2),
        ("Unknown kind", 32, 3, -2),
        ("Missing kind", 32, 0, -2),
        ("Partial relocation", 36, 1, -2),
        ("Reserved field", 40, 1, -2),
        ("Image CRC", 28, 0, -4),
        ("Data CRC", 48, 0, -4),
        ("Relocation CRC", 52, 0, -4),
    ]:
        add(name, word(offset, value), result)
    add("Truncated header", original[:48], -3)
    reloc_size = struct.unpack_from("<I", original, 36)[0]
    image_start = 64 + reloc_size
    add("Truncated image", original[:image_start + audit["image_bytes"] - 1], -3)

    def relocation(name, kind_wanted, component, value):
        data = bytearray(original)
        entry = next(n for n, row in enumerate(audit["relocations"]) if row["kind"] == kind_wanted)
        struct.pack_into("<I", data, 64 + entry * 12 + component * 4, value)
        struct.pack_into("<I", data, 52, zlib.crc32(data[64:image_start]))
        add(name, data, -3 if component != 2 else -2)

    relocation("Unknown relocation", 0, 2, 99)
    relocation("ADRP outside image", 0, 0, audit["image_bytes"])
    relocation("ADRP unaligned", 0, 0, 1)
    relocation("ADRP target outside", 0, 1, audit["data_bytes"] + audit["bss_bytes"])
    relocation("ABS64 outside data", 1, 0, audit["data_bytes"] + audit["bss_bytes"] - 4)
    relocation("ABS64 outside image", 1, 1, audit["image_bytes"])
    data = bytearray(original)
    entry = next(row for row in audit["relocations"] if row["kind"] == 0)
    struct.pack_into("<I", data, image_start + entry["offset"], 0xD503201F)  # A real NOP, not ADRP.
    struct.pack_into("<I", data, 28, zlib.crc32(data[image_start:image_start + audit["image_bytes"]]))
    add("Non ADRP instruction", data, 0, -2)

    # Legacy v1 is a valid check-only diagnostic, never an executable probe.
    code = struct.pack("<I", 0xD65F03C0)
    header = struct.pack("<8I", 0x444C504E, 0x00200001, 0, 4, 0, 0, 0, zlib.crc32(code))
    add("Legacy check only", header + code, 0)
    probe = args.probe.read_bytes()
    if len(probe) != 64 or probe[:8] != b'NPLD\x02\x00\x30\x00':
        raise ValueError("Expected the separately built closed probe")
    if probe[48:] != struct.pack("<4I", 0x93C04400, 0xCA003400, 0x910C4400, 0xD65F03C0):
        raise ValueError("Probe instruction identity mismatch")
    add("Valid return probe", probe, 0, 0, "probe")
    changed = bytearray(probe)
    struct.pack_into("<I", changed, 48, 0xD503201F)
    struct.pack_into("<I", changed, 28, zlib.crc32(changed[48:]))
    add("Changed closed probe", changed, -2, None, "probe")
    lines = [f'{e["id"]} | foreground | {e["name"]} | {e["file"]} | 2 | z8/3.11\n' for e in entries]
    (apps.parent / "MANIFEST").write_text("".join(lines))
    (apps.parent / "MODE.TXT").write_text("R")
    (args.out / "catalog.json").write_text(json.dumps({
        "source_program_sha256": audit["sha256"], "entries": entries,
        "mutations_preboot_only": True, "actual_qemu_verified": False}, indent=2) + "\n")
    print(json.dumps({"entries": len(entries), "out": str(args.out)}))


if __name__ == "__main__":
    main()
