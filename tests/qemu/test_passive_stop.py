"""Host-only control-flow checks; never launches QEMU or a camera session."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "z8-qemu/tools"))
from passive import Observer, StopAtPassive, validate, validate_stop_label
import controls

spec = importlib.util.spec_from_file_location("nlr_owned_runner", HERE / "run.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class FakeGuest:
    def __init__(self, directory):
        self.out = Path(directory)
        self.data = {}
        self.events = []
        self.qmp = self

    def __enter__(self):
        self.events.append("enter")
        return self

    def __exit__(self, *_):
        self.events.append("quit")

    def command(self, name, **_):
        self.events.append(name)

    def hmp(self, *_):
        return "PC=0000000040160000 X00=0000000a00001000 SP=0000000a00002000"

    def read_bytes(self, *_):
        return bytes.fromhex("1f2003d5")

    def rsp(self, packet, **_):
        self.events.append(packet)

    def log(self):
        return ""

    def check(self, _, passed):
        if not passed:
            raise AssertionError("Guest check failed")
        self.events.append("check")


class PassiveStopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.guest = FakeGuest(self.temp.name)
        self.point = {"label": "cut", "address": "0x40160000", "expected": "1f2003d5", "reads": []}

    def execute(self, stream, label="cut"):
        def final_observation():
            self.guest.command("stop")
            self.guest.events.append("snapshot")
        runner.run_owned_session(self.guest, lambda _: None, stream, 1, None, label, final_observation)

    def test_selected_real_observer_never_reaches_continue_and_always_cleans_up(self):
        observer = Observer(self.guest, [self.point], "cut")
        observer.arm()
        def stream(*_):
            observer.handle()
            self.guest.command("cont")
        self.execute(stream)
        self.assertNotIn("cont", self.guest.events)
        self.assertEqual(self.guest.events[-3:], ["stop", "snapshot", "quit"])
        self.assertTrue(self.guest.data["passive_stop"]["hit"])
        self.assertFalse(self.guest.data["passive_stop"]["resume_after_hit"])
        self.assertEqual(len(self.guest.data["passive_observations"]), 1)

    def test_peer_does_not_swallow_stop_or_call_original_handler(self):
        class BasePeer:
            def __init__(base, guest):
                base.g = guest
            def handle(base):
                base.g.events.append("original-handler")
                return True
        controller = type("Controller", (), {"arm_passive": None})()
        with patch.object(controls, "UpstreamPeer", BasePeer):
            peer = controls.make_peer(controller, [self.point], "cut")(self.guest)
        peer.passive.arm()
        with self.assertRaises(StopAtPassive):
            peer.handle()
            self.guest.command("cont")
        self.assertNotIn("original-handler", self.guest.events)
        self.assertNotIn("cont", self.guest.events)

    def test_stream_start_arms_in_peer_init_before_any_continue(self):
        class BasePeer:
            def __init__(base, guest):
                base.g = guest
                guest.events.append("peer-init")
        controller = type("Controller", (), {"arm_passive": None})()
        self.guest.events.append("boot-returned")
        with patch.object(controls, "UpstreamPeer", BasePeer):
            peer = controls.make_peer(controller, [self.point], "cut", "stream-start")(self.guest)
        self.assertTrue(peer.passive.started)
        self.assertEqual(self.guest.events[:3], ["boot-returned", "peer-init", "Z1,40160000,4"])
        self.assertNotIn("cont", self.guest.events)

    def test_default_peer_does_not_arm_before_runtime_discovery_callback(self):
        class BasePeer:
            def __init__(base, guest):
                base.g = guest
        controller = type("Controller", (), {"arm_passive": None})()
        with patch.object(controls, "UpstreamPeer", BasePeer):
            peer = controls.make_peer(controller, [self.point], "cut")(self.guest)
        self.assertFalse(peer.passive.started)
        self.assertEqual(self.guest.events, [])
        controller.arm_passive()
        self.assertTrue(peer.passive.started)
        self.assertEqual(self.guest.events, ["Z1,40160000,4"])

    def test_unknown_arming_mode_rejected_before_peer_creation(self):
        with self.assertRaisesRegex(ValueError, "arming mode"):
            controls.make_peer(object(), [self.point], "cut", "boot-before")
        self.assertEqual(self.guest.events, [])

    def test_default_observation_resumes_original_execution(self):
        observer = Observer(self.guest, [self.point])
        observer.arm()
        def stream(*_):
            self.assertTrue(observer.handle())
            self.guest.command("cont")
        self.execute(stream, None)
        self.assertIn("cont", self.guest.events)
        self.assertNotIn("passive_stop", self.guest.data)
        self.assertEqual(self.guest.events[-3:], ["stop", "snapshot", "quit"])

    def test_unhit_target_is_failure_with_final_reads_and_quit(self):
        with self.assertRaisesRegex(RuntimeError, "not hit"):
            self.execute(lambda *_: None)
        self.assertFalse(self.guest.data["passive_stop"]["hit"])
        self.assertEqual(self.guest.events[-3:], ["stop", "snapshot", "quit"])

    def test_ordinary_error_is_not_intentional_success(self):
        def stream(*_):
            raise ValueError("Original stream failure")
        with self.assertRaisesRegex(ValueError, "Original stream failure"):
            self.execute(stream)
        self.assertNotIn("passive_stop", self.guest.data)
        self.assertEqual(self.guest.events[-3:], ["stop", "snapshot", "quit"])

    def test_stop_exception_without_real_observation_is_not_success(self):
        def stream(*_):
            raise StopAtPassive("cut")
        with self.assertRaisesRegex(RuntimeError, "Unexpected"):
            self.execute(stream)
        self.assertEqual(self.guest.events[-3:], ["stop", "snapshot", "quit"])

    def test_boot_failure_still_observes_and_quits(self):
        def boot(_):
            raise ValueError("Boot failed")
        with self.assertRaisesRegex(ValueError, "Boot failed"):
            runner.run_owned_session(
                self.guest, boot, lambda *_: None, 1, None, None,
                lambda: self.guest.events.extend(["stop", "snapshot"]),
            )
        self.assertEqual(self.guest.events[-3:], ["stop", "snapshot", "quit"])

    def test_final_read_failure_cannot_skip_owned_quit(self):
        def final_observation():
            self.guest.events.append("stop")
            raise ValueError("Final read failed")
        with self.assertRaisesRegex(ValueError, "Final read failed"):
            runner.run_owned_session(
                self.guest, lambda _: None, lambda *_: None, 1, None, None,
                final_observation,
            )
        self.assertEqual(self.guest.events[-2:], ["stop", "quit"])

    def test_validation_rejects_unknown_labels_and_wrong_instruction_before_guest(self):
        firmware = Path(self.temp.name) / "candidate.eg"
        firmware.write_bytes(bytes.fromhex("1f2003d5"))
        validate([self.point], firmware)
        validate_stop_label([self.point], "cut")
        for points, label in ((None, "cut"), ([self.point], "unknown"), ([], "")):
            with self.assertRaises(ValueError):
                validate_stop_label(points, label)
        wrong = dict(self.point, expected="00000000")
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate([wrong], firmware)
        self.assertEqual(self.guest.events, [])


if __name__ == "__main__":
    unittest.main()
