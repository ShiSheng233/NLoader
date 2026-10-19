#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Family B (ABI 7 controls) QEMU fixture: run CTLDEMO from the NLoader list,

press every control the native controller can send, stop it with the exit
chord, and leave the session for the card log's extraction:

  drive:  this script starts the repository runner (tests/qemu/run.py) with
          an owned session, drives the real menu, and stops QEMU;
  read:   after the session, tools/z8-qemu's extract_card_file.py reads
          NLOADER/APPS/CTLDEMO.LOG out of the stopped card image;
  check:  the log must carry one `ev` line per control the host pressed,
          with the control's NLR_CTL_* number and 1/0 for press/release.
          Screenshots and the runner's result.json stay for review.

The program under test is sdk/examples/ctldemo (build.sh), placed on a card
by prepare_card.py.  This records actual inputs and screenshots; it does not
declare application acceptance by itself.  One owned session per run; the
output directory must be new.
"""
import argparse, hashlib, json, subprocess, sys, time, traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "qemu"))
from scenario import NativeSession


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eg", type=Path, required=True,
                        help="the verified EG payload to run")
    parser.add_argument("--card", type=Path, required=True,
                        help="a prepared card image (A:\\NLOADER with CTLDEMO)")
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

    def press(names, settle=0.8):
        """Send keys without the native session's menu-mode gate: while the
        program owns the input the stock UI state word legitimately leaves
        the menu mode, and the keys still go through the MCU path."""
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
        return state

    def capture(label):
        session.capture(label)
        state = session.get("/state")
        view = fields(state)
        records.append({"label": label, "load_state": view.get("load.state"),
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
            press(["ok"], .2)                           # run it
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if fields(session.get("/state")).get("load.state") == 2:
                    break
                time.sleep(.2)
            capture("running")
            press(["up", "down", "left", "right", "ok", "playback", "disp", "fn1"], .8)
            capture("keys-1")
            press(["fn2", "zoom-in", "zoom-out", "af-on"], .8)
            capture("keys-2")
            press(["half"], .4)
            press(["release-keys"], .8)
            capture("half")
            press(["menu-delete"], .8)                  # the loader's stop chord
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if fields(session.get("/state")).get("load.state") == 0:
                    break
                time.sleep(.2)
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
    (args.out / "ctl-events-observations.json").write_text(
        json.dumps({"error": error, "observations": records,
                    "runner_exit_code": runner.returncode}, indent=2))
    result = json.loads((args.out / "result.json").read_text())
    print(json.dumps({"error": error,
                      "owned_qemu_stopped": result.get("owned_qemu_stopped")}, indent=1))
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
