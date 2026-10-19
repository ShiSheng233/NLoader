# SPDX-License-Identifier: GPL-2.0-or-later
"""Bounded fixed-RAM diagnostics at an existing paused screen capture.

No pause, resume, register, input, or guest-write operation belongs here.
"""
import hashlib
import math
import re

from observe_runtime import bounded_integer, check_ram_span, read_exact

MAX_REGIONS = 8
MAX_REGION_BYTES = 4096
MAX_TOTAL_BYTES = 32768


def validate(specification, firmware_sha256):
    if not isinstance(specification, dict) or set(specification) != {"firmware_sha256", "regions"}:
        raise ValueError("Memory samples require firmware_sha256 and regions")
    digest = specification["firmware_sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or digest != firmware_sha256:
        raise ValueError("Memory samples candidate SHA256 mismatch")
    regions = specification["regions"]
    if not isinstance(regions, list) or not 1 <= len(regions) <= MAX_REGIONS:
        raise ValueError("Memory samples require 1..8 fixed RAM regions")
    labels, total, anchor_bytes = set(), 0, 0
    for region in regions:
        if not isinstance(region, dict) or set(region) != {"label", "address", "length", "anchors"}:
            raise ValueError("Memory sample region requires label, address, length and anchors")
        label = region["label"]
        if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", label) or label in labels:
            raise ValueError("Memory sample labels must be unique bounded ASCII names")
        labels.add(label)
        address = region["address"]
        if not isinstance(address, str) or not re.fullmatch(r"0[xX][0-9a-fA-F]+", address):
            raise ValueError("Memory sample address must be explicit hexadecimal RAM")
        length = bounded_integer(region["length"], "sample length", 1, MAX_REGION_BYTES)
        check_ram_span(int(address, 16), length)
        total += length
        anchors = region["anchors"]
        if not isinstance(anchors, list) or len(anchors) > 4:
            raise ValueError("At most four short anchors per region are allowed")
        for anchor in anchors:
            if not isinstance(anchor, dict) or set(anchor) != {"offset", "hex"}:
                raise ValueError("Memory anchor requires offset and hex")
            raw = anchor["hex"]
            if not isinstance(raw, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,32}", raw):
                raise ValueError("Memory anchor must contain 1..32 exact bytes")
            offset = bounded_integer(anchor["offset"], "anchor offset", 0, length - 1)
            size = len(raw) // 2
            if offset + size > length:
                raise ValueError("Memory anchor exceeds its region")
            anchor_bytes += size
    if total > MAX_TOTAL_BYTES or anchor_bytes > 128:
        raise ValueError("Memory samples exceed the total read or anchor budget")
    return regions


def capture(guest, runtime, specification, firmware_sha256, pipeline_row, pipeline_index):
    """Read only after capture() found the unique runtime at this same pause.

    The caller is run.py's existing observe-live callback, after upstream has
    paused and captured the LCD row and screenshot, before its existing cont.
    Store hex on that pipeline row so later frames cannot replace the evidence.
    """
    report = {"captured": False, "pipeline_index": pipeline_index,
              "virtual_seconds": pipeline_row.get("virtual_seconds"),
              "lcd": dict(pipeline_row.get("lcd", {})), "regions": []}
    pipeline_row["memory_samples"] = report
    try:
        regions = validate(specification, firmware_sha256)
        if runtime.get("found") is not True:
            report["reason"] = "No unique verified runtime at this paused capture"
            return report
        state = runtime.get("fields", {}).get("load.state")
        if type(state) is not int or state != 0:
            report["reason"] = "Runtime load.state is not idle"
            return report
        timestamp = report["virtual_seconds"]
        if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or timestamp < 0 or not report["lcd"]:
            raise ValueError("Memory samples require this capture's LCD state and virtual time")
        report.update(runtime_address=runtime["address"], runtime_snapshot_sha256=runtime["snapshot_sha256"],
                      firmware_sha256=firmware_sha256)
        # Validate object identity before touching the remaining fixed regions.
        for region in sorted(regions, key=lambda item: not item["anchors"]):
            data = read_exact(guest, int(region["address"], 16), region["length"])
            item = {"label": region["label"], "address": region["address"], "length": len(data),
                    "hex": data.hex(), "sha256": hashlib.sha256(data).hexdigest(), "anchors_verified": False}
            report["regions"].append(item)
            for anchor in region["anchors"]:
                expected = bytes.fromhex(anchor["hex"])
                if data[anchor["offset"]:anchor["offset"] + len(expected)] != expected:
                    raise ValueError(f"Memory anchor mismatch in {region['label']} at {anchor['offset']:#x}")
            item["anchors_verified"] = True
        report["captured"] = True
    except Exception as error:
        report["error"] = str(error)
    return report
