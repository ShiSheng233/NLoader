# SPDX-License-Identifier: GPL-2.0-or-later
"""Extend native MCU inputs without changing the pinned upstream stream."""
from control import BUTTONS, Control as UpstreamControl
from service_z8_mcu import Peer as UpstreamPeer

MENU_OFFSET = 0x43
DELETE_OFFSET = 0x45
KEY_BODY_BYTES = 124
KEY_FAMILY = 2
MENU_DELETE = (MENU_OFFSET, DELETE_OFFSET)

# Original Z8 decoder 41020844 reads these raw bytes and produces bank-1
# MENU 0x8000 / DELETE 0x4000. Both levels belong in one complete MCU body;
# sending MENU first lets the native GUI consume it before the chord exists.
# Upstream's HTTP handler reads this dictionary when queuing each request.
HOLD_MENU = ("hold", MENU_OFFSET)
HOLD_DELETE = ("hold", DELETE_OFFSET)
# The upstream stream writes 1 at the returned offset before serialization.
# Offset 0 is the already-1 report type, so release does not synthesize MENU.
RELEASE_KEYS = ("release", 0)
KEY_OFFSETS = {
    "up": 0x24, "down": 0x25, "left": 0x23, "right": 0x22, "ok": 0x4A,
    "playback": 0x44, "af-on": 0x1B, "disp": 0x53,
    "fn1": 0x3B, "fn2": 0x3C, "zoom-in": 0x4B, "zoom-out": 0x4C,
}
# These are byte positions in the original 124-byte MCU report, not the
# decoder's output bank masks. AF-ON supplies the diagnostic fire contact.
HOLD_KEYS = {("hold", offset): "hold-" + name for name, offset in KEY_OFFSETS.items()}
HOLD_KEYS.update({HOLD_MENU: "hold-menu", HOLD_DELETE: "hold-delete"})
# Upstream's "half" (raw byte 7) is one pressed report; a held half press
# keeps that byte at 1 in every report until release-keys, as a finger on
# the shutter does, so an observation can see a scan while it is down.
HOLD_HALF = ("hold", BUTTONS["half"])
HOLD_KEYS[HOLD_HALF] = "hold-half"
PRESS_NAMES = {offset: name for name, offset in {**BUTTONS, **KEY_OFFSETS, "delete": DELETE_OFFSET}.items()
               if isinstance(offset, int)}
AXIS0_OFFSET = 0x0B
AXIS0_NEGATIVE = ("axis0", AXIS0_OFFSET, -1)
AXIS0_POSITIVE = ("axis0", AXIS0_OFFSET, 1)
ROTATIONS = {AXIS0_NEGATIVE: "axis0-negative",
             AXIS0_POSITIVE: "axis0-positive"}
# The original decoder reads this as s8, not a switch Boolean. Its first
# logical navigation axis maps sign to 0x29D/0x29E through the native menu
# converters. The physical dial identity and distance per report are unknown.
BUTTONS.update({"delete": DELETE_OFFSET, "menu-delete": MENU_DELETE,
                "hold-menu": HOLD_MENU, "hold-delete": HOLD_DELETE,
                "release-keys": RELEASE_KEYS,
                "axis0-negative": AXIS0_NEGATIVE,
                "axis0-positive": AXIS0_POSITIVE})
BUTTONS.update(KEY_OFFSETS)
BUTTONS.update({name: command for command, name in HOLD_KEYS.items()})
BUTTONS.update({"fire": KEY_OFFSETS["af-on"], "hold-fire": ("hold", KEY_OFFSETS["af-on"])})


class Control(UpstreamControl):
    def __init__(self, port):
        self.pending_chord = None
        self.held_keys = set()
        self.display_active = False
        self.ui_mode = None
        self.observe = None
        self.runtime_snapshot = None
        self.arm_passive = None
        super().__init__(port)

    def publish(self, path, row, ready=False):
        self.display_active = bool(row["lcd"].get("active", False))
        control = bytes.fromhex(row["ui_control_hex"])
        self.ui_mode = int.from_bytes(control[4:8], "little")
        if self.observe:
            try:
                self.runtime_snapshot = self.observe()
                if self.runtime_snapshot.get("found") and self.arm_passive:
                    self.arm_passive()
            except Exception as error:
                self.runtime_snapshot = {"found": False, "error": repr(error)}
        super().publish(path, row, ready)

    def status(self):
        status = super().status()
        status["display_active"] = self.display_active
        status["ui_mode"] = self.ui_mode
        status["held_mcu_offsets"] = sorted(self.held_keys)
        if self.runtime_snapshot is not None:
            status["runtime_snapshot"] = self.runtime_snapshot
        if status["ready"] and not self.display_active:
            status["ready"] = False
            status["state"] = "Original display is inactive; controls paused"
        return status

    def next_button(self):
        if self.pending_chord is not None:
            raise RuntimeError("Previous MCU chord has not been queued")
        button = super().next_button()
        if button is None:
            return None
        if isinstance(button, int) and button in PRESS_NAMES:
            self.pending_chord = ("press", button)
            return button
        if button not in (MENU_DELETE, RELEASE_KEYS) and button not in HOLD_KEYS and button not in ROTATIONS:
            raise ValueError("Unsupported MCU input")
        self.pending_chord = button
        # Upstream stream sets the first raw byte; the peer adds the second
        # before the original serializer queues this same physical snapshot.
        return button[0] if button == MENU_DELETE else button[1]

    def complete_chord(self, body, family):
        if family != KEY_FAMILY:
            return body, None
        chord = self.pending_chord
        self.pending_chord = None
        source = bytes(body)
        if len(source) != KEY_BODY_BYTES:
            raise ValueError("Expected a complete physical MCU key snapshot")
        if chord is None and not self.held_keys:
            return body, None
        if source[0] != 1 or source[4] != 1:
            raise ValueError("Input requires the complete native type-1 key body")
        offset = chord[0] if chord == MENU_DELETE else chord[1] if chord else None
        if offset is not None and source[offset] != 1:
            raise ValueError("Input requires a complete pressed MCU body")
        combined = bytearray(source)
        rotation = chord in ROTATIONS
        if rotation:
            if source[0] != 1 or source[4] != 1:
                raise ValueError("Rotation requires the complete native type-1 key body")
            combined[chord[1]] = chord[2] & 0xFF
        elif chord == RELEASE_KEYS:
            for held in self.held_keys:
                combined[held] = 0
            self.held_keys.clear()
            combined[MENU_OFFSET] = combined[DELETE_OFFSET] = 0
        elif chord in HOLD_KEYS:
            self.held_keys.add(chord[1])
        elif chord == MENU_DELETE:
            combined[DELETE_OFFSET] = 1
        for offset in self.held_keys:
            combined[offset] = 1
        record = {
            "button": ROTATIONS[chord] if rotation else
                      "menu-delete" if chord == MENU_DELETE else
                      "release-keys" if chord == RELEASE_KEYS else
                      HOLD_KEYS[chord] if chord in HOLD_KEYS else
                      PRESS_NAMES[chord[1]] if chord and chord[0] == "press" else "retain-held-keys",
            "family": family,
            "held_offsets": sorted(self.held_keys),
            "source_body_hex": source.hex(),
            "body_hex": combined.hex(),
        }
        if rotation:
            record.update(axis="axis0", raw_offset=chord[1], signed_delta=chord[2])
        return bytes(combined), record


def make_peer(controller, passive_points=None, stop_label=None, passive_arm="runtime"):
    """Bind one controller to one session's unchanged native MCU peer."""
    if passive_arm not in ("runtime", "stream-start"):
        raise ValueError("Unsupported passive arming mode")
    if controller is None:
        return UpstreamPeer

    class Peer(UpstreamPeer):
        def __init__(self, *args, **kwargs):
            self.passive = None
            super().__init__(*args, **kwargs)
            from passive import Observer
            self.passive = Observer(self.g, passive_points, stop_label) if passive_points else None
            if self.passive:
                controller.arm_passive = self.passive.arm
                if passive_arm == "stream-start":
                    # The pinned stream constructs this Peer after boot has
                    # returned and before its first cont. Check mapped bytes;
                    # dynamic RAM reads still happen only at an actual hit.
                    self.passive.arm()

        def handle(self):
            observed = self.passive.handle() if self.passive else False
            return super().handle() or observed

        def close(self):
            if self.passive:
                self.passive.close()
            super().close()

        def enqueue_external(self, body, family):
            complete, record = controller.complete_chord(body, family)
            result = super().enqueue_external(complete, family)
            if record is not None:
                key = "native_rotation_inputs" if "axis" in record else "native_chord_inputs"
                self.g.data.setdefault(key, []).append(record)
            return result

    return Peer
