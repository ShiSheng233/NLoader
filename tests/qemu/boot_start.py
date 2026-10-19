#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Z 8 QEMU fixture for the boot program (NLOADER/BOOT) and its record in
STATE.NLS format 2.

Each leg is one owned cold boot through the repository runner
(tests/qemu/run.py); no key is pressed, the boot program starts on its own
once the autoload pass is done.  After the runner has stopped QEMU, the
stopped card image is read with z8-qemu's extract_card_file.py:
NLOADER/STATE.NLS is decoded slot by slot here (independently of core: CRC,
format, generation, enabled list, pending flag and the boot record) and
NLOADER/APPS/BOOTLOG.TXT, the program's own log, shows whether its entry
ran.  Every leg after the first boots the card image the previous, stopped
session actually produced -- never the template again.

  run:  tests/qemu/boot_start.py --eg <verified EG> --card <card.raw>
            --out <new dir> [--spec runtime-spec.json] [--port N]
            [--with-crash]

The card is a fresh image made by prepare_card.py from the output of
sdk/examples/bootdemo/build.sh: NLOADER/MANIFEST, NLOADER/BOOT ("bootdemo")
and NLOADER/APPS/BOOTDEMO.NLB, no STATE.NLS and no ENABLED.

Legs and what the stopped card must show (G = the newest generation the
previous leg left; a fresh card is migrated to generation 1 first):

  first    STATE.NLS newest = ok(bootdemo) at 3, other slot run(bootdemo)
           at 2; the log has one `start`, `alive` lines and `done`.
  restart  newest ok at G+2, other run at G+1; one more `start` and `done`.
  --with-crash adds (needs --spec with load.state):
  crash    QMP stop 3 guest seconds after load.state reaches 2: newest
           run at G+1; one more `start`, no new `done`.  The stop is a
           process interruption, not a power cut.
  skip     newest skipped(bootdemo) at G+1; the log is byte-identical to
           the previous leg's (the program was not started).
  again    newest ok at G+2; one more `start` and `done`.

This records the actual card, screenshots and runner results; it does not
judge pixels, it is not a real-camera result, and QEMU starts in the menu,
so it says nothing about whether the menu checkpoint runs when a real
camera starts in live view.  The output directory must be new.
"""
import argparse, hashlib, json, re, struct, subprocess, sys, time, traceback, zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "qemu"))
sys.path.insert(0, str(ROOT / "z8-qemu" / "tools"))
from scenario import NativeSession
from extract_card_file import extract
from inspect_card_volume import catalog

BOOT_ID = "bootdemo"
MARKS = {0: "none", 1: "run", 2: "ok", 3: "skipped", 4: "failed"}
ID_BYTES = 33
TOKEN = re.compile(rb"[!-~]{1,32}")


def decode_slot(data):
    """One 4096-byte STATE.NLS record, checked without core's codec."""
    assert len(data) == 4096
    if not any(data):
        return None
    assert data[:8] == b"NLRSTAT1", "magic"
    version, length, generation, pending, count, checksum = struct.unpack_from("<IIQIII", data, 8)
    assert version in (1, 2) and length == 4096, (version, length)
    copy = bytearray(data)
    copy[32:36] = bytes(4)
    assert zlib.crc32(copy) == checksum, "crc"
    assert generation and pending in (0, 1) and count <= 64, (generation, pending, count)
    reserved = data[0x24:0x40] if version == 1 else data[0x2C:0x40]
    assert not any(reserved), "reserved header"
    ids = []
    for index in range(64):
        value = data[64 + index * ID_BYTES:64 + (index + 1) * ID_BYTES]
        if index >= count:
            assert not any(value), "unused id field"
            continue
        name, separator, padding = value.partition(b"\0")
        assert separator and TOKEN.fullmatch(name) and not any(padding), "id field"
        ids.append(name.decode("ascii"))
    assert len({name.lower() for name in ids}) == len(ids), "duplicate id"
    mark, result, boot_id = 0, 0, ""
    tail = 0x880
    if version == 2:
        mark, result = struct.unpack_from("<Ii", data, 0x24)
        field = data[0x880:0x880 + ID_BYTES]
        name, separator, padding = field.partition(b"\0")
        assert separator and not any(padding), "boot id field"
        assert mark in MARKS, mark
        if mark == 0:
            assert not name and result == 0, "empty boot record"
        else:
            assert TOKEN.fullmatch(name), "boot id"
            assert (result != 0) if mark == 4 else (result == 0), "boot result"
        boot_id = name.decode("ascii")
        tail = 0x880 + ID_BYTES
    assert not any(data[tail:]), "tail"
    return {"format": version, "generation": generation, "pending": pending, "ids": ids,
            "boot_mark": MARKS[mark], "boot_result": result, "boot_id": boot_id}


def read_card(card, folder):
    """The stopped card's STATE.NLS records and the program's log."""
    files = {row["path"]: row for row in catalog(card, 1048576)["files"]}
    found = {}
    for name, target in (("NLOADER/STATE.NLS", "STATE.NLS"),
                         ("NLOADER/APPS/BOOTLOG.TXT", "BOOTLOG.TXT")):
        if name not in files:
            found[target] = None
            continue
        out = folder / ("actual-" + target)
        extracted = extract(card, name, out)
        found[target] = {"bytes": out.read_bytes(), "sha256": extracted["sha256"]}
    state = found["STATE.NLS"]
    records = None
    if state is not None:
        data = state["bytes"]
        assert len(data) == 8192, len(data)
        records = [decode_slot(data[0:4096]), decode_slot(data[4096:8192])]
    log = found["BOOTLOG.TXT"]["bytes"] if found["BOOTLOG.TXT"] else b""
    return records, log


def newest(records):
    valid = [r for r in records if r]
    assert valid, "no record"
    best = max(valid, key=lambda r: r["generation"])
    assert sum(1 for r in valid if r["generation"] == best["generation"]) == 1 or \
        records[0] == records[1], "same generation, different records"
    other = [r for r in valid if r is not best]
    return best, (other[0] if other else None)


def count(log, word):
    return sum(1 for line in log.decode("ascii", "replace").splitlines()
               if line.split(" ")[0] == word)


def expect_record(record, mark, generation):
    assert record is not None, f"missing {mark} record"
    assert record["format"] == 2, record
    assert record["boot_mark"] == mark, (record, mark)
    assert record["boot_id"].lower() == BOOT_ID, record
    assert record["generation"] == generation, (record, generation)
    assert record["pending"] == 0 and record["ids"] == [], record


def run_leg(args, leg, card, folder, port, digest):
    """One owned cold boot; returns the observations and the runner result."""
    command = [sys.executable, str(ROOT / "tests/qemu/run.py"),
               "--stock-firmware", str(ROOT / "firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi"),
               "--firmware", str(args.eg.resolve()), "--firmware-sha256", digest,
               "--qemu", str(ROOT / "build/qemu-platform/qemu-build/qemu-system-aarch64"),
               "--raw", str(ROOT / "build/qemu-platform/liveview.raw"),
               "--card-template", str(card), "--card-interface", "nvme",
               "--output", str(folder), "--port", str(port), "--seconds", "900"]
    if args.spec:
        command += ["--snapshot-spec", str(args.spec.resolve()), "--observe-live"]
    error = None
    session = None
    records = []

    def fields(state):
        return state.get("runtime_snapshot", {}).get("fields", {})

    def settle(seconds):
        end = session.get("/state")["virtual_seconds"] + seconds
        deadline = time.monotonic() + 60 + seconds * 6
        while time.monotonic() < deadline:
            state = session.get("/state")
            if state["virtual_seconds"] >= end:
                return state
            time.sleep(0.2)
        raise RuntimeError("guest time did not advance")

    def until(predicate, seconds):
        """Wait up to `seconds` of guest time for a runtime observation."""
        end = session.get("/state")["virtual_seconds"] + seconds
        deadline = time.monotonic() + 60 + seconds * 6
        while time.monotonic() < deadline:
            state = session.get("/state")
            if predicate(fields(state)):
                return state
            if state["virtual_seconds"] >= end:
                break
            time.sleep(0.2)
        raise RuntimeError("runtime observation not reached")

    def capture(label):
        session.capture(label)
        state = session.get("/state")
        view = fields(state)
        # Every field the given spec declares (none without --spec).
        records.append({"label": label, "virtual_seconds": state.get("virtual_seconds"),
                        "ui_mode": state.get("ui_mode"), **view})
        print(json.dumps({"leg": leg, **records[-1]}), flush=True)
        return state

    with folder.with_name(folder.name + "-runner.log").open("x") as log:
        runner = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT)
        try:
            deadline = time.monotonic() + 180
            while not (folder / "session.json").exists():
                if runner.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("owned runner did not start")
                time.sleep(.2)
            session = NativeSession(folder, 300)
            session.wait(lambda s: s.get("ready") and s.get("ui_mode") == 1)
            capture("ready")
            if leg == "crash":
                until(lambda f: f.get("load.state") == 2, 60)
                capture("started")
                settle(3)
                capture("before-stop")
            else:
                settle(8)
                capture("early")
                settle(32)
                if args.spec:
                    until(lambda f: f.get("load.state") == 0, 60)
                capture("late")
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
    result = json.loads((folder / "result.json").read_text())
    return {"error": error, "observations": records, "runner_exit_code": runner.returncode,
            "owned_qemu_stopped": result.get("owned_qemu_stopped"),
            "runner_error": result.get("error")}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--eg", type=Path, required=True, help="independently verified EG")
    parser.add_argument("--card", type=Path, required=True,
                        help="fresh card image (MANIFEST, BOOT, APPS/BOOTDEMO.NLB)")
    parser.add_argument("--spec", type=Path, help="this candidate's runtime-spec")
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    parser.add_argument("--port", type=int, default=8875)
    parser.add_argument("--with-crash", action="store_true",
                        help="add the crash, skip and again legs (needs --spec)")
    args = parser.parse_args()
    if args.with_crash and not args.spec:
        raise SystemExit("--with-crash needs --spec: the stop is timed on load.state")
    args.out = args.out.absolute()
    if args.out.exists():
        raise SystemExit(f"refusing: {args.out} exists")
    digest = hashlib.sha256(args.eg.resolve().read_bytes()).hexdigest()
    args.out.mkdir(parents=True)
    legs = ["first", "restart"] + (["crash", "skip", "again"] if args.with_crash else [])
    card = args.card.resolve()
    summary = {"eg_sha256": digest, "input_card": str(card), "legs": []}
    previous_log = b""
    previous_generation = None
    failure = None
    for number, leg in enumerate(legs, 1):
        folder = args.out / f"{number}-{leg}"
        entry = {"leg": leg, "card_template": str(card),
                 "card_template_sha256": hashlib.sha256(card.read_bytes()).hexdigest()}
        summary["legs"].append(entry)
        try:
            entry.update(run_leg(args, leg, card, folder, args.port + number - 1, digest))
            if entry["error"] or entry["runner_exit_code"] or not entry["owned_qemu_stopped"]:
                raise RuntimeError(f"{leg}: session did not end cleanly")
            stopped = folder / "card.raw"
            records, log = read_card(stopped, folder)
            assert records is not None, "STATE.NLS missing"
            best, other = newest(records)
            entry["records"] = records
            entry["log"] = log.decode("ascii", "replace")
            base = 1 if previous_generation is None else previous_generation
            starts, done = count(log, "start"), count(log, "done")
            before_starts, before_done = count(previous_log, "start"), count(previous_log, "done")
            if leg in ("first", "restart", "again"):
                expect_record(best, "ok", base + 2)
                expect_record(other, "run", base + 1)
                assert starts == before_starts + 1 and done == before_done + 1, (starts, done)
                assert count(log, "alive") > count(previous_log, "alive")
                assert log.startswith(previous_log), "log rewritten"
            elif leg == "crash":
                expect_record(best, "run", base + 1)
                assert other is not None and other["generation"] == base
                assert starts == before_starts + 1 and done == before_done, (starts, done)
                assert log.startswith(previous_log), "log rewritten"
            elif leg == "skip":
                expect_record(best, "skipped", base + 1)
                expect_record(other, "run", base)
                assert log == previous_log, "the program ran"
            entry["verified"] = True
            previous_log = log
            previous_generation = best["generation"]
            card = stopped
        except BaseException as exc:
            failure = f"{leg}: {exc!r}"
            entry["failure"] = failure
            traceback.print_exc()
            break
        finally:
            (args.out / "boot-start-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"failure": failure,
                      "legs": [{k: e.get(k) for k in ("leg", "verified", "owned_qemu_stopped")}
                               for e in summary["legs"]]}, indent=1))
    if failure:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
