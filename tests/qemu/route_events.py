#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Family B (ABI 7) route, standby and touch-slot QEMU fixture for the Z 8.

Runs ROUTEDEMO (a program over the menu) or ROUTESHL (the same code as a
shell) from sdk/examples/routedemo, presses keys through the native
controller, and records what the program logged, what the camera showed and
what stock instructions observed:

  --mode menu     ROUTEDEMO: UP routed to the camera, DOWN to both, LEFT the
                  program's; the half press first with the default route
                  (hidden over the menu), then routed to both (FN1); MENU +
                  DELETE stops it.
  --mode shell    ROUTESHL: the half press with the shell's default (shared),
                  then routed to the program (FN2); MENU and DELETE routed to
                  the camera (ZOOM_OUT), then MENU + DELETE stops it.
  --mode standby  ROUTEDEMO held with no key (--standby-press none), a key
                  the program hides (left) or a key routed to the camera (up)
                  pressed --press-after seconds after it runs; the screen's
                  state is polled until the display goes off.

Every mode arms one-shot read-only instruction observations (runner
--passive-points, --passive-arm stream-start): the program's first
queue_wait reads the touch slot and the eye state while the program holds
the input; the touch hook and the stock touch occupant (both expected unhit:
the emulator has no touch source); the input hook install; and, per mode,
either the activity signal (with its caller in X30), or the program's
route calls in order with the banks the stock exit-callback occupant
receives after each marker, the program's route call on the half press
(what the camera saw of it before and after its re-route). The runner reads the touch
slot and the eye state again after the owned stop (--read-range).

The card log APPS/<NAME>.LOG is read from the stopped card image afterwards
(z8-qemu tools/extract_card_file.py).  This records actual inputs,
screenshots and observations; it does not judge them and is not a
real-camera result.  One owned session per run; the output must be new.
"""
import argparse, hashlib, json, subprocess, sys, time, traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "qemu"))
from scenario import NativeSession

EG_BASE = 0x40160000


def word(eg, address):
    return eg[address - EG_BASE:address - EG_BASE + 4].hex()


def points(eg, build, profile, mode, exit_original):
    """The passive points, from the build's own section table (core) and the
    profile (stock); the expected words are read from the EG under test."""
    sections = {s["name"]: s["address"] for s in json.loads(build.read_text())["sections"]}
    def core(name):
        return sections[".text." + name]
    import tomllib
    platform = tomllib.loads(profile.read_text())["services"]["platform"]
    slot, eye = platform["touch_slot"], platform["eye_state"]
    activity = platform["scan"]["activity"]
    # The scan object between scans holds the physical banks (the pass puts
    # them back after the stock occupant has run).
    physical = [{"label": "physical", "address": hex(platform["scan"]["object"] + 8), "length": 60}]
    state = [{"label": "touch_slot", "address": hex(slot), "length": 8},
             {"label": "eye_state", "address": hex(eye), "length": 4}]
    out = [
        {"label": "install", "address": hex(core("nlr_program_io_install")), "reads": state},
        {"label": "qw", "address": hex(core("api_queue_wait")), "reads": state},
        {"label": "touch-hook", "address": hex(core("program_touch")), "reads": []},
        {"label": "touch-stock", "address": hex(platform["touch_original"]), "reads": []},
    ]
    if mode == "standby":
        out.append({"label": "activity", "address": hex(activity), "after": "qw", "reads": []})
    else:
        # The program's route calls in order, one per call, on straight-line
        # instructions of api_input_route's prologue (0x00..0x20, no branch):
        # UP, DOWN at start; the marker on the first half press (held); the
        # half press's re-route (FN1 or FN2); the marker on the second half
        # press. Each point is armed by the previous hit and sits at a LOWER
        # address, so the call that armed it has already passed it and only
        # the next call can hit it. After each marker, the stock occupant of
        # the exit callback slot shows the banks the camera receives after
        # the loader's pass (X0+8); at the marker the scan object holds the
        # physical banks.
        route = core("api_input_route")
        stock_cb = exit_original
        banks = [{"label": "banks", "register": "X00", "offset": 8, "length": 60}]
        out += [
            {"label": "route-up", "address": hex(route + 0x20), "after": "qw", "reads": []},
            {"label": "route-down", "address": hex(route + 0x1c), "after": "route-up", "reads": []},
            {"label": "mark-1", "address": hex(route + 0x18), "after": "route-down", "reads": physical},
            {"label": "camera-1", "address": hex(stock_cb), "after": "mark-1", "reads": banks},
            {"label": "route-half", "address": hex(route + 0x14), "after": "camera-1", "reads": []},
            {"label": "mark-2", "address": hex(route + 0x10), "after": "route-half", "reads": physical},
            {"label": "camera-2", "address": hex(stock_cb + 4), "after": "mark-2", "reads": banks},
        ]
    for p in out:
        p["expected"] = word(eg, int(p["address"], 16))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eg", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True, help="the package's build json")
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--card", type=Path, required=True)
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--mode", choices=("menu", "shell", "standby"), required=True)
    parser.add_argument("--standby-press", choices=("none", "left", "up"), default="none")
    parser.add_argument("--press-after", type=float, default=30.0)
    parser.add_argument("--setup-ups", type=int, default=1)
    parser.add_argument("--exit-original", default="0x40d540b4",
                        help="the stock occupant of the exit callback slot (QEMU "
                             "qemu-b5-002: input_worker blr x8); the runtime's "
                             "exit_original_input is recorded to confirm it")
    args = parser.parse_args()
    if not 1 <= args.setup_ups <= 2:
        raise SystemExit("refusing: --setup-ups must be 1 or 2")
    if args.out.exists():
        raise SystemExit(f"refusing: {args.out} exists")
    eg_path = args.eg.resolve()
    eg = eg_path.read_bytes()
    digest = hashlib.sha256(eg).hexdigest()
    plan = points(eg, args.build, args.profile, args.mode, int(args.exit_original, 16))
    points_file = args.out.with_name(args.out.name + "-points.json")
    with points_file.open("x") as stream:
        json.dump(plan, stream, indent=1)
    import tomllib
    platform = tomllib.loads(args.profile.read_text())["services"]["platform"]
    command = [sys.executable, "tests/qemu/run.py",
               "--stock-firmware", "firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi",
               "--firmware", str(eg_path), "--firmware-sha256", digest,
               "--qemu", "build/qemu-platform/qemu-build/qemu-system-aarch64",
               "--raw", "build/qemu-platform/liveview.raw",
               "--card-template", str(args.card), "--card-interface", "nvme",
               "--output", str(args.out), "--port", str(args.port), "--seconds", "1800",
               "--passive-points", str(points_file), "--passive-arm", "stream-start",
               "--read-range", "touch_slot:%#x:8" % platform["touch_slot"],
               "--read-range", "eye_state:%#x:4" % platform["eye_state"]]
    if args.spec:
        command += ["--snapshot-spec", str(args.spec), "--observe-live"]
    error = None
    session = None
    records = []
    timeline = []

    def fields(state):
        return state.get("runtime_snapshot", {}).get("fields", {})

    def press(names, settle=0.8):
        before = session.get("/state")
        for name in names:
            session.post("/button/" + name)
        target = before["sent_inputs"] + len(names)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            state = session.get("/state")
            if state["sent_inputs"] >= target and state.get("queued_inputs") == 0:
                break
            time.sleep(0.2)
        end = state["virtual_seconds"] + settle
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            state = session.get("/state")
            if state["virtual_seconds"] >= end:
                break
            time.sleep(0.2)
        timeline.append({"pressed": names, "virtual_seconds": state["virtual_seconds"]})
        return state

    def capture(label):
        session.capture(label)
        state = session.get("/state")
        view = fields(state)
        records.append({"label": label, "virtual_seconds": state.get("virtual_seconds"),
                        "ui_mode": state.get("ui_mode"),
                        "display_active": state.get("display_active"),
                        "load_state": view.get("load.state"),
                        "result": view.get("load.last_result"),
                        "returned": view.get("load.program.returned"),
                        "exit_original_input": view.get("exit_original_input")})
        print(json.dumps(records[-1]), flush=True)
        return state

    def wait_load(value, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if fields(session.get("/state")).get("load.state") == value:
                return True
            time.sleep(.2)
        return False

    with args.out.with_name(args.out.name + "-runner.log").open("x") as log:
        runner = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 180
            while not (args.out / "session.json").exists():
                if runner.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("owned runner did not start")
                time.sleep(.2)
            session = NativeSession(args.out, 300)
            session.wait(lambda s: s.get("ready") and s.get("ui_mode") == 1)
            capture("original-menu")
            press(["left", "down", "down", "down", "down", "right"]
                  + ["up"] * args.setup_ups, .6)
            press(["ok"], .6)                           # the NLoader entry
            capture("program-list")
            press(["ok"], .6)                           # the program's details
            capture("details")
            press(["ok"], .2)                           # run it
            wait_load(2)
            press([], 2.0)
            running = capture("running")
            if args.mode == "menu":
                # The details page opens on its first row: DOWN first, so
                # the camera-only UP has a row to move back to.
                press(["down"], .8)
                capture("down-both")
                press(["up"], .8)
                capture("up-camera")
                press(["left"], .8)
                capture("left-program")
                # UP (the camera's) held while the half press (hidden) makes
                # the first marker: camera-1 shows both bits as the camera
                # receives them.
                press(["hold-up"], .6)
                capture("up-held")
                press(["hold-half"], .4)                # held until release-keys
                press(["release-keys"], .8)
                capture("half-default")
                press(["fn1"], .8)                      # half -> both
                press(["hold-half"], .4)
                press(["release-keys"], 1.5)
                capture("half-both")
                press(["menu-delete"], .8)
                wait_load(0)
                press([], 2.0)
                capture("returned")
            elif args.mode == "shell":
                press(["hold-half"], .4)                # held until release-keys
                press(["release-keys"], .8)
                capture("half-default")
                press(["fn2"], .8)                      # half -> program
                press(["hold-half"], .4)
                press(["release-keys"], .8)
                capture("half-program")
                press(["zoom-out"], .8)
                press(["menu-delete"], .8)
                wait_load(0)
                press([], 2.0)
                capture("returned")
            else:
                start = running["virtual_seconds"]
                pressed = None
                shot = {30: False, 60: False}
                deadline = time.monotonic() + 900
                while time.monotonic() < deadline:
                    state = session.get("/state")
                    rel = state["virtual_seconds"] - start
                    timeline.append({"virtual_seconds": state["virtual_seconds"], "rel": round(rel, 1),
                                     "ui_mode": state.get("ui_mode"),
                                     "display_active": state.get("display_active"),
                                     "load_state": fields(state).get("load.state")})
                    if pressed is None and args.standby_press != "none" and rel >= args.press_after:
                        press([args.standby_press], .4)
                        pressed = session.get("/state")["virtual_seconds"] - start
                        timeline.append({"standby_press": args.standby_press, "rel": round(pressed, 1)})
                        capture("after-press")
                    if state.get("display_active") is False:
                        capture("display-off")
                        break
                    if rel > 400:
                        break
                    time.sleep(2.0)
                # With the display off the controller refuses keys (any key
                # would also be the program's, hidden from the camera): the
                # owned stop ends the session with the program still held.
                if session.get("/state").get("display_active"):
                    press(["menu-delete"], .8)
                    wait_load(0)
                    capture("returned")
        except BaseException as exc:
            error = repr(exc)
            traceback.print_exc()
            if session:
                try:
                    capture("failure-state")
                except BaseException:
                    pass
        finally:
            if session:
                try:
                    session.post("/stop")
                except BaseException:
                    pass
            try:
                runner.wait(timeout=180)
            except subprocess.TimeoutExpired:
                runner.terminate()
                runner.wait(timeout=30)
    if not (args.out / "result.json").exists():
        raise SystemExit(f"the runner left no session (see {args.out.name}-runner.log): {error}")
    (args.out / "route-events-observations.json").write_text(
        json.dumps({"error": error, "mode": args.mode, "standby_press": args.standby_press,
                    "observations": records, "timeline": timeline,
                    "runner_exit_code": runner.returncode}, indent=2))
    result = json.loads((args.out / "result.json").read_text())
    print(json.dumps({"error": error,
                      "owned_qemu_stopped": result.get("owned_qemu_stopped")}, indent=1))
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
