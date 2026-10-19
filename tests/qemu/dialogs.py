#!/usr/bin/env python3
"""Z 8 QEMU fixture for the camera's keyboard and caution box (ABI 6
ui_input / ui_caution, profile [menu.page.keyboard] / [menu.page.caution]):
open the DIALOGS fixture (tests/qemu/dialogs) from the NLoader page, then
type into the keyboard and save, type and give up with MENU, and answer a
Yes / No question with No and with Yes, a message with OK and a question
with MENU, capturing the native screen at each step.

  run:    tests/qemu/dialogs.py --eg <verified EG> --card <card.raw>
              --out <new dir> [--port N] [--apps] [--steps STEPS]
  check:  each screenshot against its label (the keyboard over the page,
          the typed text, the page row "Name: ..." after save and unchanged
          after MENU, the caution box with its text and Yes / No or OK, the
          cursor on No), and the card log APPS/DIALOGS.LOG for the program's
          own answers (input <len> <name>, question 0/1/-..., message 1).

STEPS overrides the built-in sequence: items separated by ';', each
`keys:a,b,c` (at most eight keys, sent through the MCU path), `cap:label`
or `wait:seconds` (guest time). The built-in sequence starts at the
original menu. The card is a fresh copy made by prepare_card.py holding
NLOADER/MANIFEST and APPS/DIALOGS.NLB. This records inputs, screenshots and
UI state; it does not judge pixels and is not a real-camera result.
"""
import argparse, hashlib, json, subprocess, sys, time, traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "qemu"))
from scenario import NativeSession

# From the original menu to the program's page: Setup, the NLoader row
# (last; one up from the top), the list, the checked program, open.
OPEN = ("keys:left,down,down,down,down,right,up;wait:1;keys:ok;wait:1;cap:program-list;"
        "keys:ok;wait:1;cap:checked;keys:ok;wait:3;cap:dialogs-page")
# The keyboard: open on "Name: NL", type two characters, save; open again,
# type, give up with MENU.
KEYBOARD = ("keys:ok;wait:2;cap:keyboard-open;keys:ok;wait:1;keys:right,ok;wait:1;"
            "cap:keyboard-typed;keys:zoom-in;wait:3;cap:after-save;"
            "keys:ok;wait:2;cap:keyboard-again;keys:right,right,ok;wait:1;"
            "cap:keyboard-typed-again;keys:menu;wait:3;cap:after-menu")
# The caution box: a question answered No (cursor starts on No), a question
# answered Yes, a message confirmed with OK, a question left with MENU.
CAUTION = ("keys:down;wait:1;keys:ok;wait:2;cap:question-open;keys:ok;wait:3;"
           "cap:after-no;keys:ok;wait:2;cap:question-again;keys:up;wait:1;"
           "cap:question-on-yes;keys:ok;wait:3;cap:after-yes;"
           "keys:down;wait:1;keys:ok;wait:2;cap:message-open;keys:ok;wait:3;"
           "cap:after-ok;keys:up;wait:1;keys:ok;wait:2;cap:question-third;"
           "keys:menu;wait:3;cap:after-question-menu")
# With the page stack on, the Apps row (Setup's first) opens the program
# list and OK on a row opens the program at once.
OPEN_APPS = ("keys:left,down,down,down,down,right;wait:1;keys:ok;wait:1;cap:program-list;"
             "keys:ok;wait:3;cap:dialogs-page")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eg", type=Path, required=True, help="independently verified EG")
    parser.add_argument("--card", type=Path, required=True, help="fresh card image with DIALOGS")
    parser.add_argument("--spec", type=Path, help="the candidate's runtime-spec")
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    parser.add_argument("--port", type=int, default=8876)
    parser.add_argument("--steps", help="override the built-in sequence")
    parser.add_argument("--apps", action="store_true",
                        help="open the program from the Apps row (profiles with the page stack)")
    parser.add_argument("--passive-points", type=Path,
                        help="read-only instruction observations (tests/qemu/passive.py), "
                             "armed at stream start")
    parser.add_argument("--read-range", action="append", default=[],
                        help="LABEL:ADDRESS:LENGTH of high RAM the runner reads at the end, "
                             "after the last step (run.py --read-range); repeatable")
    args = parser.parse_args()
    sequence = args.steps or ";".join((OPEN_APPS if args.apps else OPEN, KEYBOARD, CAUTION))
    steps = [s.strip() for s in sequence.split(";") if s.strip()]
    for step in steps:
        kind, _, value = step.partition(":")
        if kind not in ("keys", "cap", "wait") or not value:
            raise SystemExit(f"refusing: bad step {step!r}")
        if kind == "keys" and not 1 <= len(value.split(",")) <= 8:
            raise SystemExit(f"refusing: {step!r}: one batch holds one to eight keys")
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
    if args.passive_points:
        command += ["--passive-points", str(args.passive_points), "--passive-arm", "stream-start"]
    for declaration in args.read_range:
        command += ["--read-range", declaration]
    error = None
    session = None
    records = []

    def settle(seconds):
        end = session.get("/state")["virtual_seconds"] + seconds
        deadline = time.monotonic() + 60 + seconds * 4
        while time.monotonic() < deadline:
            state = session.get("/state")
            if state["virtual_seconds"] >= end:
                return state
            time.sleep(0.2)
        raise RuntimeError("guest time did not advance")

    def press(names):
        """Keys through the MCU path, without the menu-mode gate (the
        keyboard and the caution box are windows of their own)."""
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
        else:
            raise RuntimeError(f"keys {names} were not consumed")
        records.append({"keys": names, "virtual_seconds": state.get("virtual_seconds")})
        print(json.dumps(records[-1]), flush=True)

    def capture(label):
        session.capture(label)
        state = session.get("/state")
        records.append({"label": label, "virtual_seconds": state.get("virtual_seconds"),
                        "ui_mode": state.get("ui_mode"),
                        "display_active": state.get("display_active")})
        print(json.dumps(records[-1]), flush=True)

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
            for step in steps:
                kind, _, value = step.partition(":")
                if kind == "keys":
                    press(value.split(","))
                elif kind == "wait":
                    settle(float(value))
                else:
                    capture(value)
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
    if not args.out.is_dir():
        raise SystemExit(f"the runner made no session: see {args.out.name}-runner.log ({error})")
    (args.out / "dialogs-observations.json").write_text(
        json.dumps({"error": error, "steps": steps, "observations": records,
                    "runner_exit_code": runner.returncode}, indent=2))
    result = json.loads((args.out / "result.json").read_text())
    print(json.dumps({"error": error,
                      "owned_qemu_stopped": result.get("owned_qemu_stopped")}, indent=1))
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
