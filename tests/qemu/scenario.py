#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Drive one owned native-menu session without outliving its idle timeout.

This records actual inputs and screenshots; it does not declare application
acceptance. Check the runner's runtime snapshot and the captured pixels.
"""
import argparse
import json
from pathlib import Path
import time
import urllib.error
import urllib.request


class NativeSession:
    def __init__(self, output, timeout):
        self.output = output.resolve()
        self.timeout = timeout
        self.session = json.loads((output / "session.json").read_text())
        self.url = self.session["controller_url"]
        if not self.url:
            raise ValueError("Interactive session required")
        self.url = self.url.rstrip("/")
        control = self.get("/control-session")
        if control["session"] != self.session["session"]:
            raise ValueError("Control port belongs to a different session")
        self.token = control["token"]
        self.records = []
        self.number = 0

    def get(self, route):
        with urllib.request.urlopen(self.url + route, timeout=10) as response:
            return json.loads(response.read())

    def post(self, route):
        request = urllib.request.Request(self.url + route, method="POST",
                                         headers={"X-Control-Token": self.token})
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status

    def wait(self, predicate):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            state = self.get("/state")
            if state["session"] != self.session["session"]:
                raise RuntimeError("Emulator session changed")
            if predicate(state):
                return state
            if state.get("display_active") is False and state.get("ui_mode") == 0:
                # Startup has never been ready; a previously ready menu can
                # close normally. Preserve that result rather than fake input.
                if self.records:
                    raise RuntimeError("Original menu/display closed before this action")
            time.sleep(0.2)
        raise TimeoutError("Native controls did not reach the requested state")

    def buttons(self, buttons, settle=2.0):
        # Reject before posting anything: the upstream queue has eight slots.
        # A larger batch otherwise leaves a partially delivered input sequence.
        if not 1 <= len(buttons) <= 8:
            raise ValueError("Send one to eight buttons per batch")
        state = self.wait(lambda item: item["ready"] and item.get("ui_mode", 1) == 1)
        for button in buttons:
            self.post("/button/" + button)
        target = state["sent_inputs"] + len(buttons)
        delivered = self.wait(lambda item: item["sent_inputs"] >= target and item["queued_inputs"] == 0)
        state = self.wait(lambda item: item["virtual_seconds"] >= delivered["virtual_seconds"] + settle)
        self.records.append({"buttons": buttons, "after": state})
        print(json.dumps({"buttons": buttons, "virtual_seconds": state["virtual_seconds"]}), flush=True)
        return state

    def capture(self, label):
        self.number += 1
        path = self.output / f"scenario-{self.number:02d}-{label}.png"
        with urllib.request.urlopen(self.url + "/frame.png", timeout=10) as response:
            pixels = response.read()
        if not pixels.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("Expected original display PNG")
        with path.open("xb") as stream:
            stream.write(pixels)
        self.records.append({"screenshot": str(path), "state": self.get("/state")})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="Existing owned runner directory")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--run", action="store_true", help="Open the checked foreground application")
    parser.add_argument("--chord-exit", action="store_true")
    parser.add_argument("--chord-order", choices=("simultaneous", "menu-first", "delete-first"),
                        default="simultaneous")
    parser.add_argument("--repeat", type=int, default=1,
                        help="Run the same foreground program again through its native detail page")
    parser.add_argument("--stop", action="store_true", help="Stop owned QEMU after saving input records")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 300:
        parser.error("Use 1..300 seconds")
    if not 1 <= args.repeat <= 3 or (args.repeat != 1 and not args.run):
        parser.error("Repeat requires --run and a count of 1..3")
    destination = args.output / "scenario-inputs.json"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Scenario inputs already exist")
    session = NativeSession(args.output, args.timeout)
    error = None
    try:
        session.wait(lambda item: item["ready"] and item.get("ui_mode", 1) == 1)
        session.capture("initial-menu")
        session.buttons(["left", "down", "down", "down", "down", "right", "up", "up"])
        session.capture("nloader-selected")
        session.buttons(["ok"])
        session.capture("program-list")
        session.buttons(["ok"])
        session.capture("checked-detail")
        if args.run:
            for attempt in range(args.repeat):
                if attempt:
                    session.buttons(["ok" if args.chord_exit else "up"], settle=1)
                session.buttons(["ok"], settle=4)
                session.capture(f"after-open-{attempt + 1}")
                session.buttons(["ok"], settle=2)
                session.capture(f"refreshed-result-{attempt + 1}")
                if args.chord_exit:
                    if args.chord_order == "simultaneous":
                        session.buttons(["menu-delete"], settle=4)
                    else:
                        first, second = ("menu", "delete") if args.chord_order == "menu-first" else ("delete", "menu")
                        session.buttons(["hold-" + first], settle=1)
                        session.capture(f"first-held-{attempt + 1}")
                        session.buttons(["hold-" + second], settle=1)
                        session.buttons(["release-keys"], settle=4)
                    session.capture(f"after-chord-{attempt + 1}")
        if not args.chord_exit:
            session.buttons(["left"], settle=2)
        session.capture("navigation-after-program")
    except BaseException as exception:
        error = repr(exception)
        raise
    finally:
        with destination.open("x") as stream:
            stream.write(json.dumps({"session": session.session, "inputs": session.records,
                                      "error": error, "program_acceptance": "separate runtime and pixel verification required"}, indent=2) + "\n")
        if args.stop:
            try:
                session.post("/stop")
            except urllib.error.URLError:
                if error is None:
                    raise


if __name__ == "__main__":
    main()
