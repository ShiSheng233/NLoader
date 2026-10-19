#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Z 8 QEMU fixture for programs that describe themselves and for the
platform layer's refusals and named tables, with the PLATTEST programs (sdk/examples/plattest).

  run:  tests/qemu/plat_tables.py --eg <verified EG> --card <card.raw>
            --plan nomanifest|override --out <new dir>
            [--spec runtime-spec.json] [--port N] [--setup-ups 1]

Plans (the card is a fresh prepare_card.py image; rows as the loader lists
them -- MANIFEST lines first, then the described programs of APPS in name
order, then the release bundle's):

  nomanifest  NLOADER/APPS holds PLATBIG, PLATTEST, PLATV2, PLATZ6 and ZDUP;
              there is no MANIFEST.  Expected rows: Big reservation,
              Platform test, Other body, then the bundle's Screen demo
              (PLATV2 is v2 and unnamed; ZDUP repeats PLATTEST's id).
              Runs Platform test twice, Big reservation once, and opens
              Other body's details.
  nocard      no card device at all (run.py --card-state absent): opens the
              NLoader page twice; the camera must stay the stock one, the
              autoload pass must not start and nothing may be held.
  override    the same APPS plus a MANIFEST that renames plattest
              ("Renamed test") and names platv2.  Expected rows: Renamed
              test, Platform v2, Big reservation, Other body, Screen demo.
              Runs Platform v2 and Renamed test.

After the runner has stopped QEMU, NLOADER/APPS/PLATTEST.LOG and the
loader's own NLOADER/LOADER.LOG (which programs may read but not write) are
read from the stopped card with z8-qemu's extract_card_file.py.  This records the
actual inputs, screenshots, observed state and the program's own log; it
does not judge pixels and is not a real-camera result.
"""
import argparse, hashlib, json, subprocess, sys, time, traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "qemu"))
from scenario import NativeSession

# (label, keys, kind): kind "run" waits for the program to start and end
PLANS = {
    "nomanifest": [
        ("program-list", ["ok"], None),
        ("row-platform-test", ["down"], None),
        ("details-1", ["ok"], None),
        ("run-1", ["ok"], "run"),
        ("run-2", ["ok"], "run"),
        ("back-to-list", ["left"], None),
        ("row-big", ["up"], None),
        ("details-big", ["ok"], None),
        ("run-big", ["ok"], "run"),
        ("back-to-list-2", ["left"], None),
        ("row-other-body", ["down", "down"], None),
        ("details-other-body", ["ok"], None),
        ("run-other-body", ["ok"], "maybe"),
    ],
    # no card at all (run.py --card-state absent): the camera stays the
    # stock one; the NLoader page opens and says so, nothing is started
    "nocard": [
        ("nloader-page", ["ok"], None),
        ("nloader-page-later", [], None),
        ("back-to-setup", ["left"], None),
        ("nloader-again", ["ok"], None),
    ],
    "override": [
        ("program-list", ["ok"], None),
        ("row-v2", ["down"], None),
        ("details-v2", ["ok"], None),
        ("run-v2", ["ok"], "run"),
        ("back-to-list", ["left"], None),
        ("row-renamed", ["up"], None),
        ("details-renamed", ["ok"], None),
        ("run-renamed", ["ok"], "run"),
    ],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eg", type=Path, required=True)
    parser.add_argument("--card", type=Path,
                        help="card template; omitted only with --plan nocard")
    parser.add_argument("--plan", choices=sorted(PLANS), required=True)
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8876)
    parser.add_argument("--setup-ups", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.setup_ups <= 2:
        raise SystemExit("refusing: --setup-ups must be 1 or 2")
    if args.out.exists():
        raise SystemExit(f"refusing: {args.out} exists")
    if (args.plan == "nocard") != (args.card is None):
        raise SystemExit("refusing: --card is required, and absent only with --plan nocard")
    eg = args.eg.resolve()
    digest = hashlib.sha256(eg.read_bytes()).hexdigest()
    command = [sys.executable, "tests/qemu/run.py",
               "--stock-firmware", "firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi",
               "--firmware", str(eg), "--firmware-sha256", digest,
               "--qemu", "build/qemu-platform/qemu-build/qemu-system-aarch64",
               "--raw", "build/qemu-platform/liveview.raw",
               *(["--card-template", str(args.card)] if args.card else ["--card-state", "absent"]),
               "--card-interface", "nvme",
               "--output", str(args.out), "--port", str(args.port), "--seconds", "1800"]
    if args.spec:
        command += ["--snapshot-spec", str(args.spec), "--observe-live"]
    error = None
    session = None
    records = []

    def fields(state):
        return state.get("runtime_snapshot", {}).get("fields", {})

    def settle(seconds):
        end = session.get("/state")["virtual_seconds"] + seconds
        deadline = time.monotonic() + 60 + seconds * 4
        while time.monotonic() < deadline:
            state = session.get("/state")
            if state["virtual_seconds"] >= end:
                return state
            time.sleep(0.2)
        raise RuntimeError("guest time did not advance")

    def press(names, wait=0.8):
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

    def load_state():
        return fields(session.get("/state")).get("load.state")

    def capture(label, keys):
        session.capture(label)
        state = session.get("/state")
        view = fields(state)
        records.append({"label": label, "keys": keys,
                        "virtual_seconds": state.get("virtual_seconds"),
                        "ui_mode": state.get("ui_mode"),
                        "load_state": view.get("load.state"),
                        "result": view.get("load.last_result"),
                        "returned": view.get("load.program.returned"),
                        "directory_count": view.get("directory.count"),
                        "directory_result": view.get("directory_result")})
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
            capture("original-menu", [])
            press(["left", "down", "down", "down", "down", "right"]
                  + ["up"] * args.setup_ups, .6)
            capture("setup-nloader", [])
            for label, keys, kind in PLANS[args.plan]:
                press(keys, .2 if kind else .8)
                if kind:
                    deadline = time.monotonic() + 30
                    started = False
                    while time.monotonic() < deadline:
                        if load_state() == 2:
                            started = True
                            break
                        time.sleep(.2)
                    if not started and kind == "run":
                        raise RuntimeError(label + ": the program did not start")
                    if started:
                        settle(1.5)
                        capture(label + "-running", keys)
                        deadline = time.monotonic() + 120
                        while time.monotonic() < deadline and load_state() != 0:
                            time.sleep(.2)
                        if load_state() != 0:
                            raise RuntimeError(label + ": the program did not end")
                    settle(1.5)
                capture(label, keys)
        except BaseException as exc:
            error = repr(exc)
            traceback.print_exc()
            if session:
                try:
                    capture("failure-state", [])
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
    extraction = {}
    card = args.out / "card.raw"
    for name, path in (("PLATTEST.LOG", "NLOADER/APPS/PLATTEST.LOG"),
                       ("LOADER.LOG", "NLOADER/LOADER.LOG")):
        if not card.exists():
            break
        out = args.out.with_name(args.out.name + "-" + name)
        done = subprocess.run([sys.executable, "z8-qemu/tools/extract_card_file.py",
                               "--volume", str(card), "--file", path,
                               "--output", str(out)], capture_output=True, text=True)
        extraction[name] = {"returncode": done.returncode, "stdout": done.stdout[-2000:],
                            "stderr": done.stderr[-2000:]}
    (args.out / "plat-tables-observations.json").write_text(
        json.dumps({"plan": args.plan, "error": error, "observations": records,
                    "extraction": extraction, "runner_exit_code": runner.returncode},
                   indent=2))
    result = json.loads((args.out / "result.json").read_text())
    print(json.dumps({"error": error,
                      "owned_qemu_stopped": result.get("owned_qemu_stopped")}, indent=1))
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
