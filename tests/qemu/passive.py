# SPDX-License-Identifier: GPL-2.0-or-later
"""Bounded, one-shot instruction observations on the runner's owned debugger.

Breakpoints only pause and resume original execution. No registers, RAM,
function results or firmware flags are changed by this observer.
"""
import re
from pathlib import Path
from observe_runtime import read_exact


class StopAtPassive(Exception):
    """End the owned session while the selected instruction is still paused."""

    def __init__(self, label):
        self.label = label
        super().__init__(f"Intentional stop at passive point: {label}")


def validate_stop_label(points, label):
    if label is not None and (not points or label not in {point["label"] for point in points}):
        raise ValueError("Stop label must name an explicit passive point")


def validate(points, firmware):
    if not isinstance(points, list) or not 1 <= len(points) <= 16:
        raise ValueError("Use 1..16 explicit passive points")
    labels, addresses = set(), set()
    with firmware.open("rb") as source:
        for point in points:
            if not isinstance(point, dict) or not {"label", "address", "expected", "reads"} <= set(point) <= {
                    "label", "address", "expected", "reads", "after"}:
                raise ValueError("Invalid passive point fields")
            label = point["label"]
            if not isinstance(label, str) or not re.fullmatch(r"[a-z0-9_-]{1,48}", label) or label in labels:
                raise ValueError("Invalid or duplicate passive label")
            if point.get("after") is not None and point["after"] not in labels:
                raise ValueError("Passive trigger must be an earlier point")
            address = int(point["address"], 16)
            expected = bytes.fromhex(point["expected"])
            if address % 4 or address in addresses or len(expected) != 4 or not 0 <= address - 0x40160000 <= firmware.stat().st_size - 4:
                raise ValueError("Passive point must be one unique candidate instruction")
            source.seek(address - 0x40160000)
            if source.read(4) != expected:
                raise ValueError("Passive instruction does not match the verified candidate")
            reads = point["reads"]
            if not isinstance(reads, list) or len(reads) > 8:
                raise ValueError("Use at most eight bounded passive reads")
            names = set()
            for item in reads:
                if not isinstance(item, dict) or set(item) not in ({"label", "address", "length"}, {"label", "register", "offset", "length"}):
                    raise ValueError("Invalid passive read fields")
                name = item["label"]
                if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_-]{1,48}", name) or name in names:
                    raise ValueError("Invalid passive read label")
                if type(item["length"]) is not int or not 1 <= item["length"] <= 4096:
                    raise ValueError("Passive read must be 1..4096 bytes")
                if "register" in item:
                    if not re.fullmatch(r"X(?:[0-2][0-9]|30)|SP", item["register"]) or type(item["offset"]) is not int or not -4096 <= item["offset"] <= 4096:
                        raise ValueError("Invalid passive read register/offset")
                else:
                    from observe_runtime import check_ram_span
                    check_ram_span(int(item["address"], 16), item["length"])
                names.add(name)
            labels.add(label); addresses.add(address)


class Observer:
    def __init__(self, guest, points, stop_label=None):
        self.guest = guest
        self.points = points
        validate_stop_label(points, stop_label)
        self.stop_label = stop_label
        self.armed = {}
        self.seen = set()
        self.started = False

    def arm(self):
        if self.started:
            return
        self.started = True
        for point in self.points:
            if point.get("after") is None:
                self.arm_point(point)

    def arm_point(self, point):
        address = int(point["address"], 16)
        if self.guest.read_bytes(address, 4) != bytes.fromhex(point["expected"]):
            raise ValueError("Passive instruction changed in the actual mapped candidate")
        self.guest.rsp(f"Z1,{address:x},4", expect_ok=True)
        self.armed[address] = point

    def handle(self):
        handled = False
        for cpu in range(4):
            if not self.armed:
                break
            raw = self.guest.qmp.hmp("info registers", cpu)
            registers = {key: int(value, 16) for key, value in
                         re.findall(r"\b(X\d\d|PC|SP)=([0-9a-fA-F]+)", raw)}
            point = self.armed.get(registers["PC"])
            if point is None:
                continue
            self.guest.rsp(f"z1,{registers['PC']:x},4", expect_ok=True)
            del self.armed[registers["PC"]]
            handled = True
            self.seen.add(point["label"])
            record = {"label": point["label"], "cpu": cpu,
                      "registers": raw, "reads": {}, "registers_changed": False}
            for item in point["reads"]:
                address = int(item["address"], 16) if "address" in item else registers[item["register"]] + item["offset"]
                try:
                    data = read_exact(self.guest, address, item["length"])
                    path = Path(self.guest.out) / f"passive-{point['label']}-{item['label']}.bin"
                    with path.open("xb") as stream:
                        stream.write(data)
                    record["reads"][item["label"]] = {"address": hex(address), "hex": data.hex(), "file": str(path)}
                except Exception as error:
                    record["reads"][item["label"]] = {"address": hex(address), "error": repr(error)}
            self.guest.data.setdefault("passive_observations", []).append(record)
            if point["label"] == self.stop_label:
                self.guest.data["passive_stop"] = {
                    "requested_label": self.stop_label, "hit": True,
                    "intentional": True, "address": hex(registers["PC"]),
                    "cpu": cpu, "resume_after_hit": False,
                    "registers_changed": False,
                }
                raise StopAtPassive(self.stop_label)
            for next_point in self.points:
                if next_point.get("after") == point["label"]:
                    self.arm_point(next_point)
        return handled

    def close(self):
        for address in self.armed:
            self.guest.rsp(f"z1,{address:x},4", expect_ok=True)
        self.guest.data["passive_unhit"] = [point["label"] for point in self.points if point["label"] not in self.seen]
        self.armed.clear()
