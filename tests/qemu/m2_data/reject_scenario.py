#!/usr/bin/env python3
"""Exercise invalid files on an actual Exec card, bracketed by valid runs."""
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


def fields(state):
    observed = state.get("runtime_snapshot", {})
    if not observed.get("found"):
        raise RuntimeError("Expected actual Runtime")
    return observed["fields"]


def no_new_entry(before, after):
    start = before["trace"]["count"]
    trace = after["trace"]
    assert trace["all_retained_sequences_match"]
    assert 0 < trace["count"] - start <= 16, "Fresh interval must be completely retained"
    assert not any(row["sequence"] > start and row["tag"] in ("g", "h", "p", "x")
                   for row in trace["ordered"])
    assert after["text.generation"] == before["text.generation"]
    assert after["load.state"] == 0
    assert after["program_pending"] == 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--delivery", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--follow", type=Path, required=True)
    parser.add_argument("--card", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8782)
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text())
    delivery = json.loads(args.delivery.read_text())
    evidence = json.loads(Path(delivery["acceptance"]).read_text())
    assert delivery["mode"] == evidence["mode"] == "exec"
    assert evidence["patch_manifest_used_as_evidence"] is False
    assert evidence["eg_sha256"] == delivery["eg_sha256"] == hashlib.sha256(Path(delivery["eg"]).read_bytes()).hexdigest()
    assert all(evidence[k] is True for k in ["official_stock_identity_verified", "non_eg_modules_unchanged",
               "container_crc_header_verified", "two_builds_identical", "profile_against_official_firmware_verified"])
    if args.out.exists():
        raise FileExistsError(args.out)
    platform = ROOT / "build/qemu-platform"
    command = [sys.executable, str(ROOT / "tests/qemu/run.py"), "--stock-firmware",
               str(ROOT / "firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi"), "--firmware", delivery["eg"],
               "--firmware-sha256", delivery["eg_sha256"], "--qemu", str(platform / "qemu-build/qemu-system-aarch64"),
               "--raw", str(platform / "liveview.raw"), "--card-template", str(args.card.resolve()),
               "--snapshot-spec", str(args.spec.resolve()), "--follow-spec", str(args.follow.resolve()),
               "--observe-live", "--output", str(args.out.resolve()), "--port", str(args.port), "--seconds", "3600"]
    session, error, checks = None, None, []
    with args.out.with_name(args.out.name + "-driver.log").open("x") as log:
        runner = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 180
            while not (args.out / "session.json").exists():
                if runner.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("No owned runner session")
                time.sleep(.2)
            session = NativeSession(args.out, 300)
            session.wait(lambda s: s["ready"] and s.get("ui_mode") == 1)
            session.buttons(["left", "down", "down", "down", "down", "right", "up", "up"])
            session.capture("setup-before")
            session.buttons(["ok"])
            session.capture("initial-list")
            assert fields(session.get("/state"))["directory.count"] == len(catalog["entries"])
            for entry in [*catalog["entries"], catalog["entries"][0]]:
                before = fields(session.get("/state"))
                session.buttons(["ok"])
                checked = fields(session.get("/state"))
                assert checked["checked"] == entry["index"]
                assert checked["path"].endswith(entry["file"].replace("/", "\\"))
                assert checked["check_result"] == entry["check_result"], (entry, checked["check_result"])
                no_new_entry(before, checked)
                session.capture("check-" + str(entry["index"]))
                session.buttons(["ok"], settle=3)
                expected = entry["execution_result"]
                if expected is None:
                    result = fields(session.get("/state"))
                    no_new_entry(checked, result)
                    assert result["check_result"] == entry["check_result"]
                else:
                    old_count = checked["trace"]["count"]
                    result = fields(session.wait(lambda s: fields(s)["load.state"] == 0 and any(
                        row["sequence"] > old_count and row["tag"] == "E" for row in fields(s)["trace"]["ordered"])))
                    assert result["load.last_result"] == expected, (entry, result["load.last_result"])
                    prefix = "load.probe." if entry["executor"] == "probe" else "load.program."
                    assert result[prefix + "entry_started"] == int(expected == 0)
                    assert result[prefix + "returned"] == int(expected == 0)
                    if entry["executor"] == "probe" and expected == 0:
                        challenge = result["load.probe.challenge"]
                        rotated = ((challenge >> 17) | (challenge << 47)) & ((1 << 64) - 1)
                        response = ((rotated ^ (rotated << 13)) + 0x311) & ((1 << 64) - 1)
                        assert result["load.probe.response"] == response
                    assert result["load.program.code_allocation"] == result["load.program.data_allocation"] == result["load.probe.allocation"] == 0
                    if expected != 0:
                        assert result["text.generation"] == checked["text.generation"]
                    session.buttons(["ok"])
                session.capture("result-" + str(entry["index"]))
                session.buttons(["left"])
                session.capture("list-after-" + str(entry["index"]))
                assert fields(session.get("/state"))["detail_view"] == 0
                checks.append({"entry": entry, "before": before, "checked": checked, "result": result})
                if len(checks) <= len(catalog["entries"]):
                    session.buttons(["down"])
                print(json.dumps({"case": entry["name"], "check": checked["check_result"],
                                  "execution": expected, "passed": True}), flush=True)
            session.buttons(["left"])
            session.capture("setup-after")
        except BaseException as exception:
            error = repr(exception)
            traceback.print_exc()
        finally:
            if session:
                (args.out / "rejection-inputs.json").write_text(json.dumps({"checks": checks,
                    "inputs": session.records, "error": error, "pixel_review_required": True}, indent=2) + "\n")
                try:
                    session.post("/stop")
                except Exception as exception:
                    error = error or repr(exception)
            try:
                runner.wait(timeout=45)
            except subprocess.TimeoutExpired:
                runner.terminate()
                runner.wait(timeout=30)
    if error or runner.returncode:
        raise RuntimeError(f"Rejected matrix failed: {error}, runner {runner.returncode}")
    result = json.loads((args.out / "result.json").read_text())
    assert result["owned_qemu_stopped"] and not result.get("error")
    print(json.dumps({"checks_passed": len(checks), "owned_qemu_stopped": True, "pixel_review_required": True}))


if __name__ == "__main__":
    main()
