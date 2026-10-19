"""Native MCU contact and hold tests; no QEMU or device is started."""
from pathlib import Path
import queue
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parents[1] / "z8-qemu/tools")]
from boot_z8 import key_body
from mcu_frames import frames
import controls


class NativeControlsTests(unittest.TestCase):
    def setUp(self):
        self.control = controls.Control.__new__(controls.Control)
        self.control.queue = queue.Queue(maxsize=8)
        self.control.pending_chord = None
        self.control.held_keys = set()

    def press(self, name):
        self.control.queue.put_nowait(controls.BUTTONS[name])
        offset = self.control.next_button()
        body = bytearray(key_body())
        body[offset] = 1
        complete, record = self.control.complete_chord(body, 2)
        packet, = frames(complete, family=2)
        self.assertEqual(packet[:4], bytes([2, 1, 124, 0]))
        self.assertEqual(packet[8:132], complete)
        self.assertEqual(sum(packet) & 255, 255)
        self.assertEqual(bytes.fromhex(record["body_hex"]), complete)
        self.assertEqual(bytes.fromhex(record["source_body_hex"]), body)
        return complete, record, offset

    def test_raw_contacts_not_decoded_bank_masks(self):
        expected = {"up": 0x24, "down": 0x25, "left": 0x23, "right": 0x22,
                    "ok": 0x4A, "playback": 0x44, "af-on": 0x1B, "disp": 0x53,
                    "fn1": 0x3B, "fn2": 0x3C, "zoom-in": 0x4B, "zoom-out": 0x4C}
        self.assertEqual(controls.KEY_OFFSETS, expected)
        for name, contact in expected.items():
            with self.subTest(name=name):
                complete, record, offset = self.press(name)
                original = bytearray(key_body())
                original[contact] = 1
                self.assertEqual(complete, original)
                self.assertEqual(offset, contact)
                self.assertEqual(record["button"], name)

    def test_all_twelve_contacts_can_be_held_and_released(self):
        for name, contact in controls.KEY_OFFSETS.items():
            with self.subTest(name=name):
                self.press("hold-" + name)
                automatic, record = self.control.complete_chord(key_body(), 2)
                self.assertEqual(automatic[contact], 1)
                self.assertEqual(record["button"], "retain-held-keys")
                complete, _, offset = self.press("release-keys")
                self.assertEqual(offset, 0)
                self.assertEqual(complete, key_body())
                self.assertEqual(self.control.held_keys, set())

    def test_half_press_can_be_held_and_released(self):
        self.assertEqual(controls.BUTTONS["half"], 7)
        self.press("hold-half")
        for _ in range(2):
            automatic, record = self.control.complete_chord(key_body(), 2)
            self.assertEqual(automatic[7], 1)
            self.assertEqual(record["button"], "retain-held-keys")
        complete, _, _ = self.press("release-keys")
        self.assertEqual(complete, key_body())
        self.assertEqual(self.control.held_keys, set())

    def test_movement_fire_and_run_survive_automatic_release_and_tap(self):
        for name in ["hold-up", "hold-fire", "hold-fn1"]:
            self.press(name)
            body, _ = self.control.complete_chord(key_body(), 2)
            self.assertTrue(all(body[offset] == 1 for offset in self.control.held_keys))
        body, _, _ = self.press("right")
        self.assertEqual({offset for offset in range(5, 124) if body[offset]}, {0x24, 0x1B, 0x3B, 0x22})
        body, _ = self.control.complete_chord(key_body(), 2)
        self.assertEqual({offset for offset in range(5, 124) if body[offset]}, {0x24, 0x1B, 0x3B})
        body, record, _ = self.press("release-keys")
        self.assertEqual(body, key_body())
        self.assertEqual(record["held_offsets"], [])

    def test_release_never_synthesizes_menu_even_in_source_body(self):
        for name in ["hold-menu", "hold-delete", "hold-fire", "hold-left"]:
            self.press(name)
        body, record, offset = self.press("release-keys")
        self.assertEqual(offset, 0)
        self.assertEqual(bytes.fromhex(record["source_body_hex"]), key_body())
        self.assertEqual(body, key_body())
        self.assertEqual(body[0x43], 0)
        self.assertEqual(body[0x45], 0)

    def test_old_chord_and_ordered_hold_semantics(self):
        body, record, _ = self.press("menu-delete")
        self.assertEqual((body[0x43], body[0x45]), (1, 1))
        self.assertEqual(record["button"], "menu-delete")
        released, _ = self.control.complete_chord(key_body(), 2)
        self.assertEqual(released, key_body())
        for first, second in [("hold-menu", "hold-delete"), ("hold-delete", "hold-menu")]:
            self.press(first)
            self.control.complete_chord(key_body(), 2)
            body, _, _ = self.press(second)
            self.assertEqual((body[0x43], body[0x45]), (1, 1))
            body, _, _ = self.press("release-keys")
            self.assertEqual(body, key_body())

    def test_rotations_remain_signed_and_preserve_holds(self):
        self.press("hold-fire")
        for name, value in [("axis0-negative", 255), ("axis0-positive", 1)]:
            body, record, _ = self.press(name)
            self.assertEqual(body[0x0B], value)
            self.assertEqual(body[0x1B], 1)
            self.assertEqual(record["axis"], "axis0")

    def test_invalid_frames_and_unconsumed_request_fail(self):
        self.control.queue.put_nowait(controls.HOLD_MENU)
        self.control.next_button()
        with self.assertRaises(RuntimeError):
            self.control.next_button()
        other = b"unrelated"
        self.assertEqual(self.control.complete_chord(other, 1), (other, None))
        self.assertEqual(self.control.pending_chord, controls.HOLD_MENU)
        for body in [bytes(124), key_body()[:-1], key_body()]:
            self.control.pending_chord = controls.HOLD_MENU
            with self.assertRaises(ValueError):
                self.control.complete_chord(body, 2)
            self.assertEqual(self.control.held_keys, set())
        self.control.queue.put_nowait(("hold", 0x7B))
        with self.assertRaises(ValueError):
            self.control.next_button()

    def test_original_http_token_ready_and_eight_slot_queue(self):
        class Server:
            def __init__(self, address, handler):
                self.handler = handler
            def serve_forever(self):
                raise AssertionError("No real server in this test")

        with patch("control.ThreadingHTTPServer", Server), patch("control.threading.Thread"):
            controller = controls.Control(0)
        controller.ready = True
        controller.display_active = True
        controller.ui_mode = 1

        def post(name, token):
            handler = controller.server.handler.__new__(controller.server.handler)
            handler.path = "/button/" + name
            handler.headers = {"X-Control-Token": token}
            responses = []
            handler.send = lambda code, *_: responses.append(code)
            handler.do_POST()
            return responses[0]

        self.assertEqual(post("hold-fire", "wrong-session"), 403)
        self.assertEqual(controller.queue.qsize(), 0)
        controller.display_active = False
        self.assertEqual(post("hold-fire", controller.token), 503)
        controller.display_active = True
        for _ in range(8):
            self.assertEqual(post("hold-fire", controller.token), 202)
        self.assertEqual(post("release-keys", controller.token), 429)
        self.assertEqual(controller.queue.qsize(), 8)
        self.assertEqual(post("unknown", controller.token), 400)


if __name__ == "__main__":
    unittest.main()
