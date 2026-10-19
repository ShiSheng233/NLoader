#!/usr/bin/env python3
"""Prepare-only Probe/SAFE/v1 checks through the owned original-menu session."""
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


def observed(state):
    snapshot = state.get("runtime_snapshot", {})
    if snapshot.get("found") is not True:
        raise RuntimeError("No unique actual Runtime: " + repr(snapshot.get("error")))
    return snapshot["fields"]


def unexecuted(fields):
    assert fields["load.state"] == 0
    for subject in ("program", "probe"):
        for name in ("entry_started", "returned", "permissions_touched"):
            assert fields[f"load.{subject}.{name}"] == 0, (subject, name)
    for name in ("code_allocation", "data_allocation", "code_page", "data_page", "api_active", "api_file_used", "kept"):
        assert fields["load.program." + name] == 0, name
    assert fields["load.probe.allocation"] == fields["load.probe.page"] == 0
    assert all(fields[f"resident.{n}.used"] == 0 for n in range(8))
    assert all(fields[f"load.program.api_allocation.{n}"] == 0 for n in range(16))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=("probe", "safe", "v1"), required=True)
    parser.add_argument("--delivery", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--follow", type=Path, required=True)
    parser.add_argument("--card", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8782)
    args = parser.parse_args()
    delivery = json.loads(args.delivery.read_text())
    if delivery.get("mode") != "prepare-only" or not delivery.get("complete_independent_semantic_verification"):
        raise ValueError("Explicit fully verified PrepareOnly candidate required")
    firmware = Path(delivery["eg"])
    if hashlib.sha256(firmware.read_bytes()).hexdigest() != delivery["eg_sha256"]:
        raise ValueError("Candidate changed")
    receipt = json.loads(Path(delivery["acceptance"]).read_text())
    if receipt["mode"] != "prepare-only" or receipt["eg_sha256"] != delivery["eg_sha256"] or receipt.get("patch_manifest_used_as_evidence") is not False:
        raise ValueError("Receipt identity or independent expectation mismatch")
    for key in ("official_stock_identity_verified", "non_eg_modules_unchanged", "container_crc_header_verified", "two_builds_identical", "profile_against_official_firmware_verified"):
        if receipt.get(key) is not True:
            raise ValueError("Incomplete independent receipt: " + key)
    spec = json.loads(args.spec.read_text())
    validate_specification(spec)
    validate_follow(json.loads(args.follow.read_text()), spec)
    required = {"directory_result", "directory.count", "check_result", "load.header_bytes", "trace", "text.generation",
                "load.state", "load.last_result", "load.image_bytes", "path", "detail_view",
                "load.probe.prepared", "load.probe.allocation", "load.probe.page",
                "load.probe.challenge", "load.probe.response", "load.program.prepared"}
    required.update(f"load.{subject}.{name}" for subject in ("program", "probe")
                    for name in ("entry_started", "returned", "permissions_touched"))
    required.update("load.program." + name for name in
                    ("code_allocation", "data_allocation", "code_page", "data_page", "api_active", "api_file_used", "kept"))
    required.update(f"resident.{n}.used" for n in range(8))
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
               "--follow-spec", str(args.follow.resolve()), "--observe-live", "--output", str(args.out.resolve()),
               "--port", str(args.port), "--seconds", "1800"]
    session, error, attempts = None, None, []
    with args.out.with_name(args.out.name + "-driver.log").open("x") as log:
        runner = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            end = time.monotonic() + 180
            while not (args.out / "session.json").exists():
                if runner.poll() is not None or time.monotonic() > end:
                    raise RuntimeError("No owned session")
                time.sleep(.2)
            session = NativeSession(args.out, 300)
            session.wait(lambda state: state["ready"] and state.get("ui_mode") == 1)
            session.capture("original-menu")
            session.buttons(["left", "down", "down", "down", "down", "right", "up", "up"])
            session.capture("setup-nloader")
            session.buttons(["ok"])
            session.capture("program-list")
            initial = observed(session.get("/state"))
            if args.case == "safe":
                assert initial["directory_result"] == -8 and initial["directory.count"] == 0
                unexecuted(initial)
                assert initial["load.program.prepared"] == initial["load.probe.prepared"] == 0
                session.buttons(["ok"])
                session.capture("safe-refuses-action")
                after = observed(session.get("/state"))
                assert after["directory_result"] == -8 and after["directory.count"] == 0
                assert after["path"] == "" and after["text.generation"] == initial["text.generation"]
                unexecuted(after)
                attempts.append({"initial": initial, "after": after})
            else:
                assert initial["directory_result"] == 0 and initial["directory.count"] == 1
                for attempt in range(2):
                    session.buttons(["ok"])
                    session.capture(f"checked-{attempt + 1}")
                    before = observed(session.get("/state"))
                    expected_header = 48 if args.case == "probe" else 32
                    assert before["check_result"] == 0 and before["load.header_bytes"] == expected_header
                    assert before["load.image_bytes"] == 16
                    previous = before["trace"]["count"]
                    session.buttons(["ok"], settle=3)
                    if args.case == "probe":
                        session.wait(lambda state: observed(state)["load.state"] == 0 and any(
                            row["sequence"] > previous and row["tag"] == "E" for row in observed(state)["trace"]["ordered"]))
                    completed = observed(session.get("/state"))
                    assert completed["load.last_result"] == 0
                    if args.case == "probe":
                        assert completed["load.probe.prepared"] == 1
                        assert completed["load.probe.challenge"] != 0 and completed["load.probe.response"] == 0
                    else:
                        assert completed["load.program.prepared"] == completed["load.probe.prepared"] == 0
                        assert completed["trace"]["count"] > previous
                    unexecuted(completed)
                    assert completed["text.generation"] == before["text.generation"]
                    session.capture(f"completed-{attempt + 1}")
                    session.buttons(["ok"])
                    session.capture(f"visible-result-{attempt + 1}")
                    session.buttons(["left"])
                    session.capture(f"list-after-{attempt + 1}")
                    after = observed(session.get("/state"))
                    assert after["detail_view"] == 0
                    unexecuted(after)
                    attempts.append({"before": before, "completed": completed, "after": after})
            session.buttons(["left"])
            session.capture("setup-after")
        except BaseException as exception:
            error = repr(exception)
            traceback.print_exc()
        finally:
            if session:
                (args.out / "prepare-inputs.json").write_text(json.dumps({"case": args.case, "command": command,
                    "attempts": attempts, "inputs": session.records, "error": error, "pixel_review_required": True}, indent=2))
                try:
                    session.post("/stop")
                except Exception as exception:
                    error = error or "Owned stop failed: " + repr(exception)
            try:
                runner.wait(timeout=45)
            except subprocess.TimeoutExpired:
                runner.terminate()
                runner.wait(timeout=30)
    if error or runner.returncode:
        raise RuntimeError(f"{args.case}: {error}, runner {runner.returncode}")
    result = json.loads((args.out / "result.json").read_text())
    assert result["owned_qemu_stopped"] and not result.get("error")
    print(json.dumps({"case": args.case, "state_checks_passed": True, "owned_qemu_stopped": True, "pixel_review_required": True}))


if __name__ == "__main__":
    main()
