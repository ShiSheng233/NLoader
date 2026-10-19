#!/usr/bin/env python3
"""Run a bounded two-attempt M2 data/API diagnostic through native menus."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests/qemu"))
from scenario import NativeSession
from observe_runtime import validate_specification, validate_follow


def fields(state):
    snapshot = state.get("runtime_snapshot", {})
    if snapshot.get("found") is not True:
        raise RuntimeError("No unique actual Runtime: " + repr(snapshot.get("error")))
    return snapshot["fields"]


def clean(f):
    assert f["load.state"] == 0
    for key in ("code_allocation", "data_allocation", "api_active", "api_file_used",
                "permissions_touched", "kept"):
        assert f["load.program." + key] == 0, key
    for n in range(16):
        assert f[f"load.program.api_allocation.{n}"] == 0, n


def fresh_result(f, previous):
    return any(row["sequence"] > previous and row["tag"] == "E"
               for row in f["trace"]["ordered"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True)
    parser.add_argument("--materials", type=Path, required=True)
    parser.add_argument("--delivery", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--follow", type=Path, required=True)
    parser.add_argument("--card", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8782)
    parser.add_argument("--attempts", type=int, choices=(1, 2), default=2)
    parser.add_argument("--passive-points", type=Path)
    args = parser.parse_args()
    materials = json.loads(args.materials.read_text())
    case = materials["cases"][args.case]
    if len(case["programs"]) != 1:
        raise ValueError("This driver accepts one foreground entry only")
    program = materials["programs"][case["programs"][0]]
    delivery = json.loads(args.delivery.read_text())
    if delivery["mode"] not in ("exec", "prepare-only") or not delivery["complete_independent_semantic_verification"]:
        raise ValueError("Explicit independently verified execution/preparation candidate required")
    firmware = Path(delivery["eg"])
    if hashlib.sha256(firmware.read_bytes()).hexdigest() != delivery["eg_sha256"]:
        raise ValueError("Candidate changed")
    evidence = json.loads(Path(delivery["acceptance"]).read_text())
    if evidence["mode"] != delivery["mode"] or evidence["eg_sha256"] != delivery["eg_sha256"]:
        raise ValueError("Independent receipt belongs to a different candidate")
    if evidence.get("patch_manifest_used_as_evidence") is not False:
        raise ValueError("Patch manifest cannot be the independent expectation")
    for key in ("official_stock_identity_verified", "non_eg_modules_unchanged",
                "container_crc_header_verified", "two_builds_identical",
                "profile_against_official_firmware_verified"):
        if evidence.get(key) is not True:
            raise ValueError("Incomplete independent receipt: " + key)
    spec = json.loads(args.spec.read_text())
    validate_specification(spec)
    validate_follow(json.loads(args.follow.read_text()), spec)
    required = {"check_result", "trace", "text", "text.generation", "load.data_bytes", "load.bss_bytes"}
    required.update(f"load.program.api_allocation.{n}" for n in range(16))
    if not required <= spec["layout"]["fields"].keys():
        raise ValueError("Missing independently compiled observation fields")
    if args.out.exists():
        raise FileExistsError(args.out)
    base = ROOT / "build/qemu-platform"
    command = [sys.executable, str(ROOT / "tests/qemu/run.py"),
               "--stock-firmware", str(ROOT / "firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi"),
               "--firmware", str(firmware), "--firmware-sha256", delivery["eg_sha256"],
               "--qemu", str(base / "qemu-build/qemu-system-aarch64"), "--raw", str(base / "liveview.raw"),
               "--card-template", str(args.card.resolve()), "--snapshot-spec", str(args.spec.resolve()),
               "--follow-spec", str(args.follow.resolve()), "--observe-live",
               "--output", str(args.out.resolve()), "--port", str(args.port), "--seconds", "1800"]
    if args.passive_points:
        command += ["--passive-points", str(args.passive_points.resolve())]
    if "expected_text" in case:
        expected_text = case["expected_text"]
    elif case["programs"][0] == "data_app":
        expected_text = "DATA BSS relocation OK"
    else:
        expected_text = {"A": "Allocation slots OK", "F": "File slots OK",
                         "U": "API refusal checks OK"}[case["mode"][0]]
    prepare = delivery["mode"] == "prepare-only"
    hold = case["mode"].endswith("H") and not prepare
    attempts, session, error = [], None, None
    with args.out.with_name(args.out.name + "-driver.log").open("x") as log:
        runner = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            end = time.monotonic() + 180
            while not (args.out / "session.json").exists():
                if runner.poll() is not None or time.monotonic() > end:
                    raise RuntimeError("No owned session")
                time.sleep(.2)
            session = NativeSession(args.out, 300)
            session.wait(lambda s: s["ready"] and s.get("ui_mode") == 1)
            session.capture("original-menu")
            session.buttons(["left", "down", "down", "down", "down", "right", "up", "up"])
            session.capture("setup-nloader")
            session.buttons(["ok"])
            session.capture("program-list")
            assert fields(session.get("/state"))["directory.count"] == 1
            for attempt in range(args.attempts):
                session.buttons(["ok"])
                before = fields(session.get("/state"))
                assert before["check_result"] == 0
                assert before["path"].endswith(program["declaration"]["file"].replace("/", "\\"))
                assert before["load.image_bytes"] == program["image_bytes"]
                assert before["load.data_bytes"] == program["data_bytes"]
                assert before["load.bss_bytes"] == program["bss_bytes"]
                session.capture(f"checked-{attempt + 1}")
                previous = before["trace"]["count"]
                session.buttons(["ok"], settle=3)
                if hold:
                    state = session.wait(lambda s: fields(s)["load.state"] == 2 and
                                         fields(s)["text"] == expected_text and
                                         fields(s)["text.generation"] > before["text.generation"])
                    active = fields(state)
                    assert active["load.program.entry_started"] == 1
                    assert active["load.program.code_allocation"] != 0
                    assert bool(active["load.program.data_allocation"]) == bool(program["data_bytes"] + program["bss_bytes"])
                    if case["mode"] == "AH":
                        owned = [active[f"load.program.api_allocation.{n}"] for n in range(16)]
                        assert all(owned) and len(set(owned)) == 16
                    if case["mode"] == "FH":
                        assert active["load.program.api_file_used"] == 0xFFFF
                    session.capture(f"running-{attempt + 1}")
                    session.buttons(["ok"])
                    session.capture(f"visible-running-{attempt + 1}")
                    session.buttons(["menu-delete"], settle=4)
                    state = session.wait(lambda s: fields(s)["load.state"] == 0 and fields(s)["program_pending"] == 0)
                    completed = fields(state)
                    assert completed["load.last_result"] == completed["load.program.exit_code"] == 0
                    assert completed["load.program.returned"] == completed["load.program.exit_requested"] == 1
                else:
                    state = session.wait(lambda s: fields(s)["load.state"] == 0 and fresh_result(fields(s), previous))
                    active = None
                    completed = fields(state)
                    assert completed["load.last_result"] == 0, completed["load.program.exit_code"]
                    assert completed["load.program.prepared"] == 1
                    assert completed["load.program.entry_started"] == (0 if prepare else 1)
                    if prepare:
                        assert completed["load.program.returned"] == 0 and completed["text.generation"] == before["text.generation"]
                    else:
                        assert completed["load.program.returned"] == 1 and completed["load.program.exit_code"] == 0
                        assert completed["text"] == expected_text
                        assert completed["load.program.exit_requested"] == int(case["mode"].endswith("E"))
                    session.capture(f"returned-{attempt + 1}")
                    session.buttons(["ok"])
                    session.capture(f"visible-result-{attempt + 1}")
                    session.buttons(["left"])
                clean(completed)
                after = fields(session.get("/state"))
                assert after["detail_view"] == 0 and all(not after[f"resident.{n}.used"] for n in range(8))
                session.capture(f"list-after-{attempt + 1}")
                attempts.append({"before": before, "active": active, "completed": completed, "after": after})
            session.buttons(["down", "up"])
            session.capture("list-navigation")
            session.buttons(["left"])
            session.capture("setup-after")
        except BaseException as exception:
            error = repr(exception)
            traceback.print_exc()
        finally:
            if session:
                (args.out / "data-inputs.json").write_text(json.dumps({
                    "case": args.case, "mode": delivery["mode"], "program": program, "attempts": attempts,
                    "inputs": session.records, "error": error, "pixel_review_required": True}, indent=2) + "\n")
                try:
                    session.post("/stop")
                except Exception as exception:
                    error = error or "Owned stop request failed: " + repr(exception)
            try:
                runner.wait(timeout=45)
            except subprocess.TimeoutExpired:
                runner.terminate()
                runner.wait(timeout=30)
    if error or runner.returncode:
        raise RuntimeError(f"{args.case}: {error}, runner {runner.returncode}")
    result = json.loads((args.out / "result.json").read_text())
    assert result["owned_qemu_stopped"] and not result.get("error")
    print(json.dumps({"case": args.case, "attempts_passed": len(attempts), "owned_qemu_stopped": True,
                      "pixel_review_required": True}))


if __name__ == "__main__":
    main()
