#!/usr/bin/env python3
"""Z 8 QEMU fixture for the shell path and the rear screen (ABI 7 families
A, C and D): open SCRDEMO (sdk/examples/scrdemo, a shell) from the NLoader
page, let it claim, draw, release and claim the screen again, and capture
the native screen at each step.

  run:    tests/qemu/screen_shell.py --eg <verified EG> --card <card.raw>
              --out <new dir> [--port N] [--spec runtime-spec.json]
  check:  the screenshots must show the menu closing to live view on open,
          three opaque bands (red, green, blue) after the first claim, the
          camera's own screen after the release, one grey band after the
          second claim and the camera's screen after the program ends; the
          card log APPS/SCRDEMO.LOG must carry `claim 0 ...`, `present 0`,
          `release 0` twice and `done`.

The card image is a fresh copy holding NLOADER/MANIFEST and APPS/SCRDEMO.NLB,
made by prepare_card.py.  This records actual inputs, screenshots and the
observed UI state; it does not judge pixels and is not a real-camera result.
"""
import argparse, hashlib, json, subprocess, sys, time, traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "qemu"))
from scenario import NativeSession


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eg", type=Path, required=True,
                        help="independently verified EG")
    parser.add_argument("--card", type=Path, required=True,
                        help="fresh card image with SCRDEMO")
    parser.add_argument("--spec", type=Path,
                        help="the candidate's runtime-spec, for load.state")
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    parser.add_argument("--port", type=int, default=8875)
    parser.add_argument("--setup-ups", type=int, default=2,
                        help="up presses from the Setup top to the NLoader row: "
                             "2 with NLoader before Firmware version (the hidden "
                             "last row is skipped), 1 with NLoader the last row "
                             "and Apps the first")
    parser.add_argument("--apps", action="store_true",
                        help="open the program from the Setup page's first row, "
                             "Apps; "
                             "the program must be the first application listed")
    args = parser.parse_args()
    if not 1 <= args.setup_ups <= 2:  # one batch holds at most 8 keys
        raise SystemExit("refusing: --setup-ups must be 1 or 2")
    eg = args.eg.resolve()
    digest = hashlib.sha256(eg.read_bytes()).hexdigest()
    if args.out.exists():
        raise SystemExit(f"refusing: {args.out} exists")
    command = [sys.executable, "tests/qemu/run.py",
               "--stock-firmware", "firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi",
               "--firmware", str(eg), "--firmware-sha256", digest,
               "--qemu", "build/qemu-platform/qemu-build/qemu-system-aarch64",
               "--raw", "build/qemu-platform/liveview.raw",
               "--card-template", str(args.card), "--card-interface", "nvme",
               "--output", str(args.out), "--port", str(args.port), "--seconds", "1800"]
    if args.spec:
        command += ["--snapshot-spec", str(args.spec), "--observe-live"]
    error = None
    session = None
    records = []

    def fields(state):
        return state.get("runtime_snapshot", {}).get("fields", {})

    def settle(seconds):
        """Wait `seconds` of guest time."""
        end = session.get("/state")["virtual_seconds"] + seconds
        deadline = time.monotonic() + 60 + seconds * 4
        while time.monotonic() < deadline:
            state = session.get("/state")
            if state["virtual_seconds"] >= end:
                return state
            time.sleep(0.2)
        raise RuntimeError("guest time did not advance")

    def press(names, wait=0.8):
        """Send keys without the native session's menu-mode gate: once the
        shell runs the stock UI state word legitimately leaves the menu
        mode, and the keys still go through the MCU path."""
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
        return settle(wait)

    def capture(label):
        session.capture(label)
        state = session.get("/state")
        view = fields(state)
        records.append({"label": label, "virtual_seconds": state.get("virtual_seconds"),
                        "ui_mode": state.get("ui_mode"),
                        "display_active": state.get("display_active"),
                        "load_state": view.get("load.state"),
                        "result": view.get("load.last_result"),
                        "returned": view.get("load.program.returned")})
        print(json.dumps(records[-1]), flush=True)
        return state

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
            if args.apps:
                press(["left", "down", "down", "down", "down", "right"], .6)
                press(["ok"], .6)                       # Apps: the list
                capture("program-list")
                capture("checked")                      # OK on a row opens it
            else:
                press(["left", "down", "down", "down", "down", "right"]
                      + ["up"] * args.setup_ups, .6)
                press(["ok"], .6)                       # the NLoader entry
                capture("program-list")
                press(["ok"], .6)                       # check the program
                capture("checked")
            press(["ok"], .2)                           # open the shell
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if fields(session.get("/state")).get("load.state") == 2:
                    break
                time.sleep(.2)
            capture("opened")
            settle(3)
            capture("first-claim")                      # bands, ~3 s in
            settle(6)
            capture("first-claim-later")
            settle(6)
            capture("released")                         # release at ~12 s
            settle(6)
            capture("released-later")
            settle(5)
            capture("second-claim")                     # second claim at ~20 s
            settle(10)
            capture("after-second-release")
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if fields(session.get("/state")).get("load.state") == 0:
                    break
                time.sleep(.2)
            settle(2)
            capture("ended")
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
    (args.out / "screen-shell-observations.json").write_text(
        json.dumps({"error": error, "observations": records,
                    "runner_exit_code": runner.returncode}, indent=2))
    result = json.loads((args.out / "result.json").read_text())
    print(json.dumps({"error": error,
                      "owned_qemu_stopped": result.get("owned_qemu_stopped")}, indent=1))
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
