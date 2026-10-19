#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Z 8 QEMU fixture for the NLoader switch off (NLOADER/MASTER = "off"):
the loader writes nothing on the card at all -- no STATE.NLS migration, no
pending marker, no boot record, no LOADER.LOG (decision 2026-10-18).

Each leg is one owned cold boot through the repository runner
(tests/qemu/run.py).  It waits for the stock menu, opens the NLoader row
(the Setup page's last row), waits, and stops QEMU.  Every leg after the
first boots the card image the previous, stopped session actually produced
-- never the template again.  After each leg the stopped card is compared
with the card that leg booted, through z8-qemu's inspect_card_volume.py and
extract_card_file.py: every catalogue row under NLOADER/ (path, size,
clusters) and the bytes of every file there must be the same, and neither
NLOADER/STATE.NLS nor NLOADER/LOADER.LOG may exist.  The stock camera
writes its own entries outside NLOADER/ on a card it mounts (DCIM, NIKON,
NIKON001.DSC); those are listed in the verdict, not judged, and whether the
whole image is unchanged is recorded as well.

  run:  tests/qemu/master_off.py --eg <verified EG> --card <card.raw>
            --out <new dir> [--spec runtime-spec.json] [--port N]
            [--legs 2] [--setup-ups 1]

The card is a fresh image made by prepare_card.py from a directory with
NLOADER/MASTER ("off") and at least one program the loader would otherwise
list or migrate (no STATE.NLS).  This records the actual cards and
screenshots; it does not judge pixels and it is not a real-camera result.
The output directory must be new.
"""
import argparse, hashlib, json, subprocess, sys, time, traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "qemu"))
sys.path.insert(0, str(ROOT / "z8-qemu" / "tools"))
from scenario import NativeSession
from inspect_card_volume import catalog
from extract_card_file import extract

FORBIDDEN = ("NLOADER/STATE.NLS", "NLOADER/LOADER.LOG")


def image_digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while True:
            chunk = stream.read(64 << 20)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def rows(card):
    return sorted((json.dumps(row, sort_keys=True)
                   for row in catalog(card, 1048576)["files"]))


def loader_rows(listing):
    return [row for row in listing
            if json.loads(row)["path"] == "NLOADER" or
            json.loads(row)["path"].startswith("NLOADER/")]


def loader_files(card, listing, folder):
    """sha256 of every file under NLOADER/, read out of the stopped image."""
    found = {}
    for row in loader_rows(listing):
        entry = json.loads(row)
        if entry["directory"] or entry["bytes"] == 0:
            continue
        target = folder / entry["path"].replace("/", "_")
        found[entry["path"]] = extract(card, entry["path"], target)["sha256"]
    return found


def leg(args, number, card, digest):
    out = args.out / f"leg-{number}"
    command = [sys.executable, "tests/qemu/run.py",
               "--stock-firmware", "firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi",
               "--firmware", str(args.eg), "--firmware-sha256", digest,
               "--qemu", "build/qemu-platform/qemu-build/qemu-system-aarch64",
               "--raw", "build/qemu-platform/liveview.raw",
               "--card-template", str(card), "--card-interface", "nvme",
               "--output", str(out), "--port", str(args.port), "--seconds", "1800"]
    if args.spec:
        command += ["--snapshot-spec", str(args.spec), "--observe-live"]
    before_rows = rows(card)
    before_image = image_digest(card)
    out.parent.joinpath(f"leg-{number}-before").mkdir()
    before_files = loader_files(card, before_rows, out.parent / f"leg-{number}-before")
    error, session, records = None, None, []

    def fields(state):
        return state.get("runtime_snapshot", {}).get("fields", {})

    def capture(label):
        session.capture(label)
        state = session.get("/state")
        view = fields(state)
        records.append({"label": label, "virtual_seconds": state.get("virtual_seconds"),
                        "ui_mode": state.get("ui_mode"),
                        "autoload.phase": view.get("autoload.phase"),
                        "autoload.result": view.get("autoload.result"),
                        "directory_result": view.get("directory_result")})
        print(json.dumps(records[-1]), flush=True)
        return state

    def settle(seconds):
        end = session.get("/state")["virtual_seconds"] + seconds
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if session.get("/state")["virtual_seconds"] >= end:
                return
            time.sleep(0.5)

    with out.with_name(out.name + "-runner.log").open("x") as log:
        runner = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 180
            while not (out / "session.json").exists():
                if runner.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("owned runner did not start")
                time.sleep(.2)
            session = NativeSession(out, 300)
            session.wait(lambda s: s.get("ready") and s.get("ui_mode") == 1)
            capture("original-menu")
            session.buttons(["left", "down", "down", "down", "down", "right"]
                          + ["up"] * args.setup_ups, .6)
            capture("nloader-row")
            session.buttons(["ok"], .6)
            settle(2)
            capture("nloader-root")
            settle(40)            # later menu checkpoints and page turns
            capture("later")
            session.buttons(["left"], .6)
            settle(2)
            capture("back")
        except BaseException as exc:
            error = repr(exc)
            traceback.print_exc()
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
    result = json.loads((out / "result.json").read_text())
    after = out / "card.raw"
    after_rows = rows(after)
    after_image = image_digest(after)
    out.parent.joinpath(f"leg-{number}-after").mkdir()
    after_files = loader_files(after, after_rows, out.parent / f"leg-{number}-after")
    present = [name for name in FORBIDDEN
               if any(json.loads(row)["path"] == name for row in after_rows)]
    verdict = {
        "leg": number, "booted_card": str(card), "error": error,
        "owned_qemu_stopped": result.get("owned_qemu_stopped"),
        "image_before": before_image, "image_after": after_image,
        "image_identical": before_image == after_image,
        "catalogue_identical": before_rows == after_rows,
        "loader_rows_identical": loader_rows(before_rows) == loader_rows(after_rows),
        "loader_files": after_files,
        "loader_files_identical": before_files == after_files,
        "catalogue_added": sorted(set(after_rows) - set(before_rows)),
        "catalogue_removed": sorted(set(before_rows) - set(after_rows)),
        "forbidden_present": present, "observations": records,
    }
    (out.parent / f"leg-{number}-verdict.json").write_text(json.dumps(verdict, indent=1))
    print(json.dumps({k: verdict[k] for k in ("leg", "error", "owned_qemu_stopped",
                                                "loader_rows_identical", "loader_files_identical",
                                                "forbidden_present", "image_identical",
                                                "catalogue_added")}), flush=True)
    passed = (not error and result.get("owned_qemu_stopped") is True and
              verdict["loader_rows_identical"] and verdict["loader_files_identical"] and
              not present and
              all(not json.loads(row)["path"].startswith("NLOADER")
                  for row in verdict["catalogue_added"] + verdict["catalogue_removed"]))
    return passed, after


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eg", type=Path, required=True)
    parser.add_argument("--card", type=Path, required=True)
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8875)
    parser.add_argument("--legs", type=int, default=2)
    parser.add_argument("--setup-ups", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.setup_ups <= 2:  # one batch holds at most 8 keys
        raise SystemExit("refusing: --setup-ups must be 1 or 2")
    if args.out.exists():
        raise SystemExit(f"refusing: {args.out} exists")
    args.out.mkdir(parents=True)
    args.eg = args.eg.resolve()
    digest = hashlib.sha256(args.eg.read_bytes()).hexdigest()
    card, passed = args.card.resolve(), True
    for number in range(1, args.legs + 1):
        ok, card = leg(args, number, card, digest)
        passed = passed and ok
        if not ok:
            break
    print(json.dumps({"passed": passed}), flush=True)
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
