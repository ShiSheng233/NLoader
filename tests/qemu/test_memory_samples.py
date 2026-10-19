"""Host-only bounds and failure tests; never launch a guest."""
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest

from memory_samples import capture, validate
from observe_runtime import RAM_END, RAM_START

HASH = "a" * 64


def specification():
    return {"firmware_sha256": HASH, "regions": [
        {"label": "pixels", "address": hex(RAM_START + 0x1000), "length": 4, "anchors": []},
        {"label": "record", "address": hex(RAM_START + 0x2000), "length": 8,
         "anchors": [{"offset": 0, "hex": "01000000"}]},
    ]}


class Guest:
    def __init__(self):
        self.calls = []
        self.data = {RAM_START + 0x1000: b"\x11\x22\x33\xff",
                     RAM_START + 0x2000: b"\x01\0\0\0\0\0\0\0"}

    def read_bytes(self, address, length):
        self.calls.append((address, length))
        return self.data[address]


class MemorySamplesTests(unittest.TestCase):
    def setUp(self):
        self.spec = specification()
        self.guest = Guest()
        self.runtime = {"found": True, "address": hex(RAM_START + 0x3000),
                        "snapshot_sha256": "b" * 64, "fields": {"load.state": 0}}
        self.row = {"virtual_seconds": 12.375, "lcd": {"color": RAM_START + 0x1000, "alpha": RAM_START + 0x4000, "frames": 123}}

    def capture(self):
        return capture(self.guest, self.runtime, self.spec, HASH, self.row, 17)

    def test_read_only_same_pause_evidence(self):
        result = self.capture()
        self.assertTrue(result["captured"])
        self.assertIs(result, self.row["memory_samples"])
        self.assertEqual(result["virtual_seconds"], 12.375)
        self.assertEqual(result["lcd"], self.row["lcd"])
        self.assertIsNot(result["lcd"], self.row["lcd"])
        self.assertEqual(result["pipeline_index"], 17)
        self.assertEqual(result["regions"][1]["hex"], "112233ff")
        self.assertEqual(result["regions"][1]["sha256"], hashlib.sha256(b"\x11\x22\x33\xff").hexdigest())
        self.assertEqual(self.guest.calls, [(RAM_START + 0x2000, 8), (RAM_START + 0x1000, 4)])

    def test_busy_or_unverified_runtime_never_reads(self):
        for runtime in [{"found": False}, {"found": True, "fields": {}},
                        {"found": True, "fields": {"load.state": 1}},
                        {"found": True, "fields": {"load.state": False}}]:
            with self.subTest(runtime=runtime):
                self.runtime = runtime
                self.assertFalse(self.capture()["captured"])
        self.assertEqual(self.guest.calls, [])

    def test_anchor_failure_preserves_raw_evidence_and_stops_other_reads(self):
        self.guest.data[RAM_START + 0x2000] = bytes(8)
        result = self.capture()
        self.assertFalse(result["captured"])
        self.assertIn("anchor mismatch", result["error"])
        self.assertEqual(result["regions"][0]["hex"], "00" * 8)
        self.assertEqual(self.guest.calls, [(RAM_START + 0x2000, 8)])

    def test_short_read_and_fault_are_explicit(self):
        for value in [bytes(7), None]:
            self.guest.data[RAM_START + 0x2000] = value
            result = self.capture()
            self.assertFalse(result["captured"])
            self.assertIn("Short or invalid", result["error"])
        del self.guest.data[RAM_START + 0x2000]
        self.assertIn("error", self.capture())

    def test_candidate_and_malformed_schema_rejected(self):
        bad_specs = [None, {}, {**self.spec, "unexpected": 1},
                     {**self.spec, "firmware_sha256": "b" * 64},
                     {**self.spec, "firmware_sha256": HASH.upper()},
                     {**self.spec, "regions": []},
                     {**self.spec, "regions": self.spec["regions"] * 5}]
        for item in bad_specs:
            with self.subTest(item=item):
                with self.assertRaises(ValueError):
                    validate(item, HASH)

    def test_region_bounds_and_labels(self):
        changes = [{"length": 4097}, {"length": 0}, {"length": True},
                   {"address": hex(RAM_END)}, {"address": hex(RAM_END - 1)},
                   {"address": hex(RAM_START - 1)}, {"address": "0x15486864"},
                   {"address": RAM_START}, {"label": "record"}, {"label": "../pixel"}]
        for change in changes:
            spec = copy.deepcopy(self.spec)
            spec["regions"][0].update(change)
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    validate(spec, HASH)

    def test_anchor_bounds_and_exact_budget(self):
        for anchor in [{"offset": 7, "hex": "0000"}, {"offset": -1, "hex": "00"},
                       {"offset": 0, "hex": "0"}, {"offset": 0, "hex": "zz"},
                       {"offset": 0, "hex": "00" * 33}]:
            spec = copy.deepcopy(self.spec)
            spec["regions"][1]["anchors"] = [anchor]
            with self.assertRaises(ValueError):
                validate(spec, HASH)
        maximum = {"firmware_sha256": HASH, "regions": [
            {"label": f"r{i}", "address": hex(RAM_START + i * 4096), "length": 4096, "anchors": []}
            for i in range(8)]}
        self.assertEqual(sum(r["length"] for r in validate(maximum, HASH)), 32768)

    def test_missing_same_pause_metadata_reads_nothing(self):
        self.row.pop("virtual_seconds")
        result = self.capture()
        self.assertIn("LCD state and virtual time", result["error"])
        self.assertEqual(self.guest.calls, [])

    def test_cli_requires_existing_live_observation(self):
        command = [sys.executable, str(Path(__file__).with_name("run.py")),
                   "--stock-firmware", "/missing", "--firmware", "/missing", "--firmware-sha256", HASH,
                   "--qemu", "/missing", "--raw", "/missing", "--output", "/missing",
                   "--memory-samples", "/missing-spec"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Memory samples require --observe-live", result.stderr)


if __name__ == "__main__":
    unittest.main()
