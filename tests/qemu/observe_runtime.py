#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Read one paused guest's NLoader runtime through its existing qtest connection.

The caller supplies independently obtained addresses and C-layout offsets::

    {"registry_base": "0x...", "max_id": 768, "worker_name": "NLOADER",
     "layout": {"size": 1234, "fields": {
         "load.state": {"offset": 12, "type": "u32"},
         "path": {"offset": 100, "type": "cstring", "length": 76},
         "load.trace": {"offset": 200, "type": "trace", "slots": 16}}}}

Offsets above are illustrative only. There is no address, layout, execution,
or file-service fallback. capture() does not pause/resume the guest itself.
"""
import hashlib
from pathlib import Path
import re
import struct

RAM_START = 0xA00000000
RAM_END = 0xA20000000
MAX_RUNTIME_BYTES = 65536
MAX_REGISTRY_ID = 0x300
REGISTRY_ENTRY_BYTES = 16
REGISTRY_POINTER_OFFSET = 8
WORKER_BYTES = 0x58
WORKER_NAME_OFFSET = 0x1D
WORKER_NAME_BYTES = 8
WORKER_SELF_OFFSET = 0x28
MAX_TRACE_SLOTS = 16

SCALARS = {"u32": (4, "<I"), "i32": (4, "<i"),
           "u64": (8, "<Q"), "i64": (8, "<q")}


def bounded_integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def check_ram_span(address, length):
    if not RAM_START <= address < RAM_END or not 0 < length <= RAM_END - address:
        raise ValueError(f"Read outside permitted high RAM: {address:#x}+{length:#x}")


def read_exact(guest, address, length):
    check_ram_span(address, length)
    data = guest.read_bytes(address, length)
    if not isinstance(data, (bytes, bytearray)) or len(data) != length:
        raise ValueError(f"Short or invalid guest read at {address:#x}: expected {length} bytes")
    return bytes(data)


def validate_specification(specification):
    if not isinstance(specification, dict):
        raise ValueError("Snapshot specification must be an object")
    if set(specification) != {"registry_base", "max_id", "worker_name", "layout"}:
        raise ValueError("Snapshot specification requires registry_base, max_id, worker_name and layout")
    base = specification["registry_base"]
    if not isinstance(base, str) or not re.fullmatch(r"0[xX][0-9a-fA-F]+", base):
        raise ValueError("registry_base must be an explicit hexadecimal string")
    base = int(base, 16)
    if base & 7:
        raise ValueError("registry_base must be 8-byte aligned")
    max_id = bounded_integer(specification["max_id"], "max_id", 1, MAX_REGISTRY_ID)
    check_ram_span(base, (max_id + 1) * REGISTRY_ENTRY_BYTES)
    name = specification["worker_name"]
    if not isinstance(name, str) or not name or not name.isascii() or "\0" in name:
        raise ValueError("worker_name must be nonempty ASCII without NUL")
    name = name.encode("ascii")
    if len(name) > WORKER_NAME_BYTES:
        raise ValueError("worker_name exceeds the worker family's 8 bytes")
    size, fields = validate_layout(specification["layout"])
    return base, max_id, name.ljust(WORKER_NAME_BYTES, b"\0"), size, fields


def validate_layout(layout):
    if not isinstance(layout, dict) or set(layout) != {"size", "fields"}:
        raise ValueError("layout requires size and fields")
    size = bounded_integer(layout["size"], "layout.size", WORKER_BYTES, MAX_RUNTIME_BYTES)
    fields = layout["fields"]
    if not isinstance(fields, dict) or not 1 <= len(fields) <= 128:
        raise ValueError("layout.fields must contain 1..128 named fields")
    for field_name, declaration in fields.items():
        if not isinstance(field_name, str) or not re.fullmatch(r"[A-Za-z0-9_.]{1,128}", field_name):
            raise ValueError("Invalid layout field name")
        if not isinstance(declaration, dict):
            raise ValueError(f"{field_name} declaration must be an object")
        kind = declaration.get("type")
        if not isinstance(kind, str):
            raise ValueError(f"{field_name}.type must be a supported type name")
        if kind in SCALARS:
            length = SCALARS[kind][0]
            keys = {"offset", "type"}
        elif kind in ("cstring", "bytes"):
            length = bounded_integer(declaration.get("length"), f"{field_name}.length", 1, size)
            keys = {"offset", "type", "length"}
        elif kind == "trace":
            slots = bounded_integer(declaration.get("slots"), f"{field_name}.slots", 1, MAX_TRACE_SLOTS)
            if slots & (slots - 1):
                raise ValueError(f"{field_name}.slots must be a power of two")
            length = 8 + slots * 8
            keys = {"offset", "type", "slots"}
        else:
            raise ValueError(f"Unsupported field type for {field_name}: {kind!r}")
        if set(declaration) != keys:
            raise ValueError(f"Unexpected or missing layout keys for {field_name}")
        offset = bounded_integer(declaration["offset"], f"{field_name}.offset", 0, size - 1)
        if length > size - offset:
            raise ValueError(f"{field_name} exceeds layout.size")
    return size, fields


def decode_trace(snapshot, declaration):
    offset, slots = declaration["offset"], declaration["slots"]
    count = struct.unpack_from("<Q", snapshot, offset)[0]
    entries = []
    for slot in range(slots):
        # The C union stores seq_tag first, then the signed value. Decode
        # these actual memory fields rather than interpreting packed shifts.
        seq_tag, value = struct.unpack_from("<Ii", snapshot, offset + 8 + slot * 8)
        tag = seq_tag & 0xFF
        entries.append({"slot": slot, "sequence": seq_tag >> 8,
                        "tag_byte": tag, "tag": chr(tag) if 32 <= tag <= 126 else None,
                        "value": value})
    ordered = []
    for sequence in range(max(1, count - slots + 1), count + 1):
        entry = dict(entries[(sequence - 1) & (slots - 1)])
        entry["expected_sequence"] = sequence & 0xFFFFFF
        entry["sequence_matches"] = entry["sequence"] == entry["expected_sequence"]
        ordered.append(entry)
    return {"count": count, "entries": entries, "ordered": ordered,
            "all_retained_sequences_match": all(row["sequence_matches"] for row in ordered)}


def decode_fields(snapshot, fields):
    decoded = {}
    for name, declaration in fields.items():
        kind, offset = declaration["type"], declaration["offset"]
        if kind in SCALARS:
            decoded[name] = struct.unpack_from(SCALARS[kind][1], snapshot, offset)[0]
        elif kind == "trace":
            decoded[name] = decode_trace(snapshot, declaration)
        else:
            data = snapshot[offset:offset + declaration["length"]]
            if kind == "cstring":
                if b"\0" not in data:
                    raise ValueError(f"{name} has no NUL within its declared field")
                decoded[name] = data.split(b"\0", 1)[0].decode("utf-8")
            else:
                decoded[name] = data.hex()
    return decoded


def capture(guest, specification, *, persist=True):
    """Return observed fields; only a unique verified worker produces a dump.

    The guest must already be paused. Invalid specifications/pointers, short
    reads, read faults and ambiguous matches raise instead of manufacturing
    a runtime or silently discarding a fault. A normal absent worker returns
    found=False with a reason and produces no runtime-final.bin.
    """
    base, max_id, name, size, fields = validate_specification(specification)
    registry = read_exact(guest, base, (max_id + 1) * REGISTRY_ENTRY_BYTES)
    matches, named = [], []
    for registry_id in range(1, max_id + 1):
        pointer = struct.unpack_from("<Q", registry,
                                     registry_id * REGISTRY_ENTRY_BYTES + REGISTRY_POINTER_OFFSET)[0]
        if pointer == 0:
            continue
        if pointer & 7:
            raise ValueError(f"Unaligned type-0 registry pointer at ID {registry_id}: {pointer:#x}")
        # As in core's family filter, check ID before reading name, and name
        # before reading self: unrelated shorter task records are not workers.
        object_id = struct.unpack("<I", read_exact(guest, pointer, 4))[0]
        if object_id != registry_id:
            continue
        observed_name = read_exact(guest, pointer + WORKER_NAME_OFFSET, WORKER_NAME_BYTES)
        if observed_name != name:
            continue
        self_pointer = struct.unpack("<Q", read_exact(guest, pointer + WORKER_SELF_OFFSET, 8))[0]
        named.append({"registry_id": registry_id, "address": hex(pointer),
                      "self_pointer": hex(self_pointer), "self_matches": self_pointer == pointer})
        if self_pointer == pointer:
            matches.append((registry_id, pointer))
    if len(matches) > 1:
        raise RuntimeError(f"Ambiguous NLoader runtime: {len(matches)} matching type-0 workers")
    if not matches:
        reason = "Named worker found but self pointer did not match" if named else "No matching worker in type-0 registry"
        return {"found": False, "reason": reason, "registry_base": hex(base),
                "max_id": max_id, "named_candidates": named}
    registry_id, pointer = matches[0]
    snapshot = read_exact(guest, pointer, size)
    decoded = decode_fields(snapshot, fields)
    destination = Path(guest.out) / "runtime-final.bin" if persist else None
    if destination is not None:
        with destination.open("xb") as stream:
            stream.write(snapshot)
    return {"found": True, "reason": "Unique named worker with matching self pointer",
            "registry_base": hex(base), "registry_id": registry_id,
            "address": hex(pointer), "bytes": size,
            "snapshot": str(destination.resolve()) if destination else None,
            "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
            "named_candidates": named, "fields": decoded}


def validate_follow(specification, runtime_specification):
    if not isinstance(specification, dict) or set(specification) != {
            "source_field", "alignment", "magic", "layout"}:
        raise ValueError("Follow specification requires source_field, alignment, magic and layout")
    field = specification["source_field"]
    _, _, _, _, runtime_fields = validate_specification(runtime_specification)
    if field not in runtime_fields or runtime_fields[field]["type"] != "u64":
        raise ValueError("Follow source must be an observed u64 runtime field")
    alignment = specification["alignment"]
    if type(alignment) is not int or alignment not in (8, 16, 32, 64):
        raise ValueError("Follow alignment must be 8, 16, 32 or 64")
    size, fields = validate_layout(specification["layout"])
    magic = specification["magic"]
    if not isinstance(magic, dict) or set(magic) != {"field", "value"}:
        raise ValueError("Follow magic requires field and value")
    if magic["field"] not in fields or fields[magic["field"]]["type"] != "u64":
        raise ValueError("Follow magic must name a declared u64 field")
    if type(magic["value"]) is not int or not 0 <= magic["value"] < 2**64:
        raise ValueError("Follow magic must be an explicit u64 integer")
    return field, alignment, magic, size, fields


def capture_followed(guest, runtime, specification, runtime_specification, *, persist=True):
    field, alignment, magic, size, fields = validate_follow(specification, runtime_specification)
    if not runtime.get("found"):
        return {"found": False, "reason": "No verified parent runtime"}
    pointer = runtime["fields"][field]
    if pointer == 0:
        return {"found": False, "reason": "Observed pointer is null", "source_field": field}
    if pointer % alignment:
        raise ValueError("Followed pointer does not meet declared alignment")
    snapshot = read_exact(guest, pointer, size)
    decoded = decode_fields(snapshot, fields)
    if decoded[magic["field"]] != magic["value"]:
        raise ValueError("Followed object magic does not match")
    destination = Path(guest.out) / "follow-final.bin" if persist else None
    if destination is not None:
        with destination.open("xb") as stream:
            stream.write(snapshot)
    return {"found": True, "source_field": field, "address": hex(pointer), "bytes": size,
            "snapshot": str(destination.resolve()) if destination else None,
            "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(), "fields": decoded}
