#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Z 8 QEMU fixture for MANIFEST hiding, the enabled list on cards with and
without MANIFEST, and the boot with no card or no loader directory.

  run:  tests/qemu/card_cases.py --eg <verified EG> [--card <card.raw>]
            --plan <plan> --out <new dir> --spec runtime-spec.json
            [--port N] [--setup-ups 1] [--passive-points points.json]

Plans (cards are fresh prepare_card.py images, or the stopped card of the
session before, never the template again):

  hide        MANIFEST "#!hide platbig", "#!hide STORESPY", "#!hide scrdemo";
              APPS PLATTEST, PLATBIG, SPY; BOOT names scrdemo, ENABLED names
              storespy.  Expected: no boot program, nothing loaded, one row
              (Platform test), which still runs.
  enable      a card whose APPS hold PLATTEST and a described extension
              (SPY, or the lighter SVCDEMO; with or without a MANIFEST that
              names only plattest): the extension's row (the second), its
              page under Plugin settings, "Enabled" switched on and saved by id.
  enabled     the stopped card of "enable" (or of the "enabled" before it):
              the pass loads the one enabled extension at boot, then the
              page is opened to show it.
  nocard      no card device (run.py --card-state absent), a package whose
              bundle has a BOOT: the bundle's boot program starts on its own
              after the card has been asked on the power-of-two turns.
  nodir       a card without NLOADER at all: the bundle's boot program
              starts at once and nothing is written to the card.
  master      NLOADER/MASTER "off" and an extension: with a bundle BOOT
              nothing starts, and the root page shows the switch Off.
  boot        NLOADER/BOOT names a program on the card (BOOTDEMO, or the
              ABI8TEST shell): it starts after the pass and runs to its end.
  boot-toggle Plugin settings' first program: Start at boot switched on and
              written to NLOADER/BOOT (the next boot on the stopped card is a
              "boot" session).
  legacy      no MANIFEST, no STATE.NLS, an old ENABLED naming a described
              extension: migrated by id and loaded at boot.
  details     APPS with FWDUMP second in Plugin settings: its Details page,
              whose description is longer than one row.

The boot asks (autoload.boot_turns, boot_asks, boot_done) are sampled from
the observed Runtime.  After the runner has stopped QEMU, NLOADER/STATE.NLS,
NLOADER/APPS/SPY.LOG and NLOADER/LOADER.LOG are read from the stopped card
with z8-qemu's extract_card_file.py when there is a card.  This records
inputs, screenshots and observed state; it does not judge pixels and is not
a real-camera result.
"""
import argparse, hashlib, json, subprocess, sys, time, traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "qemu"))
from scenario import NativeSession

TO_NLOADER = "to-nloader"  # the Setup menu's NLoader row (the root page), from the stock menu
TO_APPS = "to-apps"        # the Setup menu's Apps row (the program list), from the stock menu

# Steps: ("keys", label, [keys]) presses and captures; ("until", label,
# {field: value}, seconds) waits for observed fields and captures;
# ("run", label, [keys]) presses and waits for a program to start and end;
# ("samples", seconds) records the boot-ask fields every second;
# ("watch", label, seconds, count) captures every `seconds`, `count` times;
# ("active", label, seconds, count) half-presses and captures every
# `seconds`, at most `count` times, until the program has ended.
# With the loader's pages the NLoader row opens the
# root page: NLoader On/Off, a state line, Plugin settings, About; Plugin
# settings lists the programs in directory order, and an extension's page
# starts with its Enabled switch.
PLANS = {
    "hide": [
        ("until", "boot-settled", {"autoload.phase": 4}, 120),
        (TO_APPS,),
        ("run", "run-platform-test", ["ok"]),
        ("keys", "list-after-run", []),
        ("keys", "back-to-setup", ["left"]),
        ("keys", "nloader-root", ["up", "ok"]),
        ("keys", "plugin-settings", ["down", "ok"]),
    ],
    "enable": [
        ("until", "boot-settled", {"autoload.phase": 4}, 120),
        (TO_NLOADER,),
        ("keys", "plugin-settings", ["down", "ok"]),
        ("keys", "extension-page", ["down", "ok"]),
        ("keys", "enabled-switched", ["ok"]),
        ("until", "saved", {"enabled_save_result": 0, "saved_enabled.count": 1}, 60),
        ("keys", "back-to-plugins", ["left"]),
    ],
    # (the pass is sampled for 20 s first; the page visit then also lets
    # the loader write its log, whatever the pass did)
    "enabled": [
        ("samples", 20),
        (TO_NLOADER,),
        ("keys", "plugin-settings", ["down", "ok"]),
        ("keys", "extension-page", ["down", "ok"]),
        ("until", "loaded-at-boot", {"autoload.phase": 4, "autoload.enabled.count": 1}, 60),
    ],
    # A program's Details with text longer than a row: on a card whose APPS
    # hold FWDUMP (second in Plugin settings) its description needs more
    # than one line; the page shows it over rows of their own. Nothing is
    # run (whether FWDUMP is refused for camera memory depends on the heap).
    "details": [
        ("until", "boot-settled", {"autoload.phase": 4}, 120),
        (TO_NLOADER,),
        ("keys", "plugin-settings", ["down", "ok"]),
        ("keys", "plugin-fwdump", ["down", "ok"]),
        ("keys", "on-details", ["up"]),
        ("keys", "details", ["ok"]),
        ("keys", "details-end", ["up"]),
    ],
    # the same boot left alone: only the loader's own checkpoint carries
    # the pass (no page visit until it is done)
    "enabled-alone": [
        ("until", "loaded-at-boot", {"autoload.phase": 4, "autoload.enabled.count": 1}, 180),
        (TO_NLOADER,),
        ("keys", "plugin-settings", ["down", "ok"]),
        ("keys", "extension-page", ["down", "ok"]),
    ],
    # QEMU starts in the menu (the runner opens it), where the boot
    # program's screen_claim waits for live view: the half press leaves the
    # menu as on a camera, then SCRDEMO claims, draws and ends by itself.
    "nocard": [
        ("samples", 2),
        ("until", "bundle-started", {"autoload.boot_bundled": 1, "load.state": 2}, 300),
        ("keys", "to-live-view", ["half"]),
        ("samples", 4),
        ("keys", "shell-drawing", []),
        ("until", "bundle-ended", {"load.state": 0}, 120),
        ("samples", 3),
        ("keys", "after-bundle", []),
    ],
    # the same, with a screenshot every 4 guest seconds for a minute after
    # the half press, to see where the boot program's run goes
    "nocard-watch": [
        ("until", "bundle-started", {"autoload.boot_bundled": 1, "load.state": 2}, 300),
        ("keys", "to-live-view", ["half"]),
        ("watch", "run", 4, 15),
        ("until", "bundle-ended", {"load.state": 0}, 60),
    ],
    # no card, DISP pressed (and let go) after the power-on window while
    # the boot still asks for a card: not the escape, nothing latched, and
    # the bundle's boot program still starts and ends
    "nocard-disp": [
        ("samples", 8),  # past NLR_BOOT_ESCAPE_MS (4 s) after the first look
        ("keys", "disp-pressed", ["disp"]),
        ("samples", 2),
        ("until", "bundle-started", {"autoload.boot_bundled": 1, "load.state": 2}, 300),
        ("keys", "to-live-view", ["half"]),
        ("samples", 4),
        ("keys", "shell-drawing", []),
        ("until", "bundle-ended", {"load.state": 0}, 120),
        ("samples", 3),
        ("keys", "after-bundle", []),
    ],
    # the same with a half press every 8 guest seconds (the shell shares
    # it with the camera): user activity, so the camera's standby timer
    # never runs out while the boot program runs
    "nocard-active": [
        ("until", "bundle-started", {"autoload.boot_bundled": 1, "load.state": 2}, 300),
        ("keys", "to-live-view", ["half"]),
        ("active", "run", 8, 8),
        ("until", "bundle-ended", {"load.state": 0}, 60),
        ("samples", 3),
        ("keys", "after-bundle", []),
    ],
    "nodir-watch": [
        ("until", "bundle-started", {"autoload.boot_bundled": 1, "load.state": 2}, 300),
        ("keys", "to-live-view", ["half"]),
        ("watch", "run", 4, 15),
        ("until", "bundle-ended", {"load.state": 0}, 60),
    ],
    "nodir": [
        ("until", "bundle-started", {"autoload.boot_bundled": 1, "load.state": 2}, 300),
        ("keys", "to-live-view", ["half"]),
        ("samples", 4),
        ("keys", "shell-drawing", []),
        ("until", "bundle-ended", {"load.state": 0}, 120),
        ("samples", 3),
        ("keys", "after-bundle", []),
    ],
    # NLOADER/BOOT names a program on the card: it starts once the pass is
    # done (a shell waits for live view: the half press), runs and ends.
    "boot": [
        ("until", "boot-decided", {"autoload.boot_decided": 1}, 180),
        ("samples", 3),
        ("keys", "to-live-view", ["half"]),
        ("until", "boot-ended", {"load.state": 0, "autoload.boot_result": 0}, 180),
        ("samples", 2),
        ("keys", "after-boot", []),
    ],
    # Plugin settings' first program, an app: "Start at boot" switched on
    # and written to NLOADER/BOOT through the checked file path.
    "boot-toggle": [
        ("until", "boot-settled", {"autoload.phase": 4}, 120),
        (TO_NLOADER,),
        ("keys", "plugin-settings", ["down", "ok"]),
        ("keys", "app-page", ["ok"]),
        ("keys", "boot-toggled", ["ok"]),
        ("keys", "back-to-plugins", ["left"]),
        ("keys", "app-page-again", ["ok"]),
    ],
    # A card without MANIFEST or STATE.NLS whose old ENABLED names a
    # described extension: migrated by id, loaded at boot.
    "legacy": [
        ("until", "loaded-at-boot", {"autoload.phase": 4, "autoload.enabled.count": 1}, 180),
        (TO_NLOADER,),
        ("keys", "plugin-settings", ["down", "ok"]),
    ],
    # NLOADER/MASTER says "off": with a bundle BOOT
    # and an extension on the card, nothing starts; the root page says Off.
    "master": [
        ("samples", 60),
        (TO_NLOADER,),
        ("samples", 2),
    ],
}
SAMPLED = ("autoload.boot_turns", "autoload.boot_asks", "autoload.boot_done",
           "autoload.boot_bundled", "autoload.boot_decided", "autoload.boot_result",
           "autoload.phase", "autoload.result", "autoload.enabled_result",
           "autoload.enabled.count", "saved_enabled.count", "enabled_save_result",
           "autoload.boot_index", "autoload.store", "load.state", "load.last_result",
           "plat.shell", "directory_result", "directory.count", "native_card",
           "autoload.driver", "autoload.pending", "autoload.next", "autoload.boot_escape")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eg", type=Path, required=True)
    parser.add_argument("--card", type=Path, help="card image; omitted only with --plan nocard")
    parser.add_argument("--plan", choices=sorted(PLANS), required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8876)
    parser.add_argument("--setup-ups", type=int, default=1)
    parser.add_argument("--passive-points", type=Path,
                        help="run.py --passive-points: one-shot read-only instruction "
                             "observations (e.g. the escape check), armed at stream start")
    parser.add_argument("--follow-spec", type=Path,
                        help="run.py --follow-spec: the loader's native-card object, read "
                             "through the observed native_card pointer at every sample")
    parser.add_argument("--read-range", action="append", default=[],
                        help="run.py --read-range LABEL:ADDRESS:LENGTH, read once after "
                             "the owned stop (no live reads: the timing stays the guest's)")
    args = parser.parse_args()
    if not 1 <= args.setup_ups <= 2:
        raise SystemExit("refusing: --setup-ups must be 1 or 2")
    if args.out.exists():
        raise SystemExit(f"refusing: {args.out} exists")
    if args.plan.startswith("nocard") != (args.card is None):
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
               "--snapshot-spec", str(args.spec), "--observe-live",
               "--output", str(args.out), "--port", str(args.port), "--seconds", "1800"]
    if args.follow_spec:
        command += ["--follow-spec", str(args.follow_spec)]
    for declaration in args.read_range:
        command += ["--read-range", declaration]
    if args.passive_points:
        command += ["--passive-points", str(args.passive_points), "--passive-arm", "stream-start"]
    error = None
    session = None
    records = []
    samples = []

    def fields(state=None):
        state = state or session.get("/state")
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

    def followed(state):
        card = state.get("runtime_snapshot", {}).get("followed", {})
        return {"card." + k: v for k, v in card.get("fields", {}).items()} if card else {}

    def sample():
        state = session.get("/state")
        view = fields(state)
        samples.append({"virtual_seconds": state.get("virtual_seconds"),
                        "display_active": state.get("display_active"),
                        **{k: view.get(k) for k in SAMPLED}, **followed(state)})

    def capture(label, keys):
        session.capture(label)
        state = session.get("/state")
        view = fields(state)
        records.append({"label": label, "keys": keys,
                        "virtual_seconds": state.get("virtual_seconds"),
                        "ui_mode": state.get("ui_mode"),
                        "display_active": state.get("display_active"),
                        **{k: view.get(k) for k in SAMPLED}, **followed(state)})
        print(json.dumps(records[-1]), flush=True)

    def until(label, want, seconds):
        deadline = time.monotonic() + seconds * 3 + 60
        start = session.get("/state")["virtual_seconds"]
        while time.monotonic() < deadline:
            state = session.get("/state")
            view = fields(state)
            if all(view.get(k) == v for k, v in want.items()):
                capture(label, [])
                return
            if state["virtual_seconds"] - start > seconds:
                break
            sample()
            time.sleep(1.0)
        capture(label + "-not-reached", [])
        raise RuntimeError(f"{label}: {want} not observed")

    with args.out.with_name(args.out.name + "-runner.log").open("x") as log:
        runner = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 180
            while not (args.out / "session.json").exists():
                if runner.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("owned runner did not start")
                time.sleep(.2)
            session = NativeSession(args.out, 300)
            session.wait(lambda s: s.get("ready"))
            sample()
            capture("first-ready", [])
            for step in PLANS[args.plan]:
                kind = step[0]
                if kind in (TO_NLOADER, TO_APPS):
                    session.wait(lambda s: s.get("ui_mode") == 1)
                    press(["left", "down", "down", "down", "down", "right"]
                          + (["up"] * args.setup_ups if kind == TO_NLOADER else []), 1.5)
                    capture("setup-row", [])
                    press(["ok"], 1.5)
                    capture("nloader-root" if kind == TO_NLOADER else "program-list", ["ok"])
                elif kind == "keys":
                    if step[2]:
                        press(step[2], 1.5)
                    capture(step[1], step[2])
                elif kind == "until":
                    until(step[1], step[2], step[3])
                elif kind == "active":
                    for n in range(step[3]):
                        settle(step[2])
                        if fields().get("load.state") == 0:
                            break
                        press(["half"], 0.5)
                        capture(f"{step[1]}-{n:02d}", ["half"])
                elif kind == "watch":
                    for n in range(step[3]):
                        settle(step[2])
                        capture(f"{step[1]}-{n:02d}", [])
                elif kind == "samples":
                    for _ in range(step[1]):
                        settle(1.0)
                        sample()
                elif kind == "run":
                    press(step[2], .2)
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline and fields().get("load.state") != 2:
                        time.sleep(.2)
                    if fields().get("load.state") != 2:
                        raise RuntimeError(step[1] + ": the program did not start")
                    settle(1.5)
                    capture(step[1] + "-running", step[2])
                    deadline = time.monotonic() + 120
                    while time.monotonic() < deadline and fields().get("load.state") != 0:
                        time.sleep(.2)
                    if fields().get("load.state") != 0:
                        raise RuntimeError(step[1] + ": the program did not end")
                    settle(1.5)
                    capture(step[1], step[2])
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
    for name, path in (("STATE.NLS", "NLOADER/STATE.NLS"), ("SPY.LOG", "NLOADER/APPS/SPY.LOG"),
                       ("LOADER.LOG", "NLOADER/LOADER.LOG"), ("BOOT", "NLOADER/BOOT"),
                       ("BOOTLOG.TXT", "NLOADER/APPS/BOOTLOG.TXT"),
                       ("SVCDEMO.LOG", "NLOADER/APPS/SVCDEMO.LOG")):
        if not card.exists():
            break
        out = args.out.with_name(args.out.name + "-" + name)
        done = subprocess.run([sys.executable, "z8-qemu/tools/extract_card_file.py",
                               "--volume", str(card), "--file", path,
                               "--output", str(out)], capture_output=True, text=True)
        extraction[name] = {"returncode": done.returncode, "stdout": done.stdout[-2000:],
                            "stderr": done.stderr[-2000:]}
    (args.out / "card-cases-observations.json").write_text(
        json.dumps({"plan": args.plan, "error": error, "observations": records,
                    "samples": samples, "extraction": extraction,
                    "runner_exit_code": runner.returncode}, indent=2))
    result = json.loads((args.out / "result.json").read_text())
    print(json.dumps({"error": error,
                      "owned_qemu_stopped": result.get("owned_qemu_stopped")}, indent=1))
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
