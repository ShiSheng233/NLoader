#!/usr/bin/env python3
"""Measure execution-block budget using real resident data extensions."""
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
    snapshot = state.get("runtime_snapshot", {})
    if not snapshot.get("found"):
        return {}
    return snapshot["fields"]


def saved_state(state):
    f = fields(state)
    followed = state["runtime_snapshot"]["followed"]
    assert followed["found"]
    native = followed["fields"]
    assert native["state_valid"] == 1 and native["current.pending"] == 1
    assert 1 <= f["saved_enabled.count"] <= 4
    return {"saved_count": f["saved_enabled.count"],
            "saved_ids": [f[f"saved_enabled.id.{n}"] for n in range(f["saved_enabled.count"])],
            "recovery_armed": f["autoload.recovery_armed"],
            "native_state": native["current.state_bytes"]}


def residents(f, count, data=True):
    kept = {}
    blocks = []
    for n in range(count):
        prefix = "data" if data else "code"
        assert f[f"resident.{n}.id"] == prefix + "_" + ("one", "two", "three")[n]
        assert f[f"resident.{n}.used"] == 1 and f[f"resident.{n}.kind"] == 1
        assert f[f"resident.{n}.failed"] == f[f"resident.{n}.uncertain"] == 0
        for key in (("code_block", "data_block") if data else ("code_block",)):
            block = f[f"resident.{n}.{key}"]
            assert block and block % 0x200000 == 0
            blocks.append(block)
        assert f[f"resident.{n}.code_block"] != f[f"resident.{n}.data_block"]
        assert f[f"resident.{n}.code_bytes"] == 0x200000
        assert f[f"resident.{n}.data_bytes"] == (0x200000 if data else 0)
        if not data:
            assert not f[f"resident.{n}.data_block"]
        for key in ("code_block", "data_block", "id", "used", "failed", "uncertain"):
            kept[f"resident.{n}.{key}"] = f[f"resident.{n}.{key}"]
    assert len(set(blocks)) == (2 if data else 1) * count
    return kept


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=("budget-fit", "budget-full", "resident-limit"), required=True)
    parser.add_argument("--delivery", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--follow", type=Path, required=True)
    parser.add_argument("--card", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8782)
    parser.add_argument("--limits", choices=("6-3", "2-1"), default="6-3")
    args = parser.parse_args()
    reduced = args.limits == "2-1"
    count = 1 if reduced else (2 if args.case == "budget-fit" else 3)
    resident_limit = args.case == "resident-limit"
    data_residents = not resident_limit and (not reduced or args.case == "budget-full")
    enabled_count = count + 1
    delivery = json.loads(args.delivery.read_text())
    evidence = json.loads(Path(delivery["acceptance"]).read_text())
    assert delivery["mode"] == evidence["mode"] == "exec" and delivery["complete_independent_semantic_verification"]
    assert evidence["eg_sha256"] == delivery["eg_sha256"] == hashlib.sha256(Path(delivery["eg"]).read_bytes()).hexdigest()
    assert evidence["two_builds_identical"] and evidence["patch_manifest_used_as_evidence"] is False
    table = evidence["complete_private_text_verification"]["exec_table_proof"]
    expected_limits = (2, 1) if reduced else (6, 3)
    assert (table["budget_blocks"], table["max_resident"], table["region_bytes"]) == (*expected_limits, 0x200000)
    if args.out.exists():
        raise FileExistsError(args.out)
    platform = ROOT / "build/qemu-platform"
    command = [sys.executable, str(ROOT / "tests/qemu/run.py"), "--stock-firmware",
               str(ROOT / "firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi"), "--firmware", delivery["eg"],
               "--firmware-sha256", delivery["eg_sha256"], "--qemu", str(platform / "qemu-build/qemu-system-aarch64"),
               "--raw", str(platform / "liveview.raw"), "--card-template", str(args.card.resolve()),
               "--snapshot-spec", str(args.spec.resolve()), "--follow-spec", str(args.follow.resolve()),
               "--observe-live", "--output", str(args.out.resolve()), "--port", str(args.port), "--seconds", "1800"]
    session, error, baseline, outcomes = None, None, None, []
    with args.out.with_name(args.out.name + "-driver.log").open("x") as log:
        runner = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            end = time.monotonic() + 180
            while not (args.out / "session.json").exists():
                if runner.poll() is not None or time.monotonic() > end:
                    raise RuntimeError("No owned session")
                time.sleep(.2)
            session = NativeSession(args.out, 300)
            state = session.wait(lambda s: s.get("ready") and fields(s).get("autoload.phase") in (4, 5))
            baseline = fields(state)
            assert baseline["autoload.phase"] == (5 if resident_limit else 4), ("Unexpected autoload result", baseline["autoload.result"])
            assert baseline["autoload.result"] == (-6 if resident_limit else 0)
            assert baseline["autoload.next"] == baseline["resource_clone.published_count"] == count
            kept = residents(baseline, count, data_residents)
            if resident_limit:
                assert baseline["load.last_result"] == -6
                assert baseline["checked"] == count
                assert baseline["path"].endswith(f"APPS\\CODE{count + 1}.NLB")
                assert baseline["load.header_bytes"] == 64
                assert baseline["load.data_bytes"] == baseline["load.bss_bytes"] == 0
                assert all(not baseline[f"resident.{n}.used"] for n in range(count, 8))
                saved = saved_state(state)
                assert saved["saved_count"] == enabled_count and saved["recovery_armed"] == 0
                names = ["code_" + n for n in ("one", "two", "three", "four")]
                assert saved["saved_ids"] == names[:enabled_count]
            session.capture("resident-extensions-ready")
            session.buttons(["left", "down", "down", "down", "down", "right", "up", "up"])
            session.buttons(["up"] * count)
            session.capture("setup-nloader")
            session.buttons(["ok"])
            if resident_limit:
                assert fields(session.get("/state"))["recovery_view"] == 1
                session.capture("recovery-before")
                session.buttons(["left"])
                listed = fields(session.get("/state"))
                assert listed["recovery_view"] == listed["detail_view"] == 0
                for n in range(enabled_count):
                    session.capture(f"resource-{n + 1}")
                    session.buttons(["ok"])
                    session.capture(f"resource-detail-{n + 1}")
                    current = session.get("/state")
                    after = fields(current)
                    assert after["checked"] == n and after["detail_view"] == 1 and after["recovery_view"] == 0
                    assert saved_state(current) == saved
                    assert residents(after, count, False) == kept
                    assert all(not after[f"resident.{i}.used"] for i in range(count, 8))
                    assert after["autoload.phase"] == 5 and after["autoload.result"] == -6
                    outcomes.append({"resource": n, "after": after})
                    session.buttons(["left"])
                    session.buttons(["down"])
            else:
                session.buttons(["down"] * count)
            session.capture("foreground-selected")
            for attempt in range(0 if resident_limit else 2):
                session.buttons(["ok"])
                checked = fields(session.get("/state"))
                assert checked["checked"] == count and checked["check_result"] == 0
                assert checked["load.data_bytes"] == (0 if reduced else 24)
                assert checked["load.bss_bytes"] == (0 if reduced else 148)
                before = checked["trace"]["count"]
                session.capture(f"checked-{attempt + 1}")
                session.buttons(["ok"], settle=3)
                if args.case == "budget-fit":
                    result = fields(session.wait(lambda s: fields(s).get("load.state") == 0 and any(
                        row["sequence"] > before and row["tag"] == "E" for row in fields(s)["trace"]["ordered"])))
                    assert result["load.last_result"] == result["load.program.exit_code"] == 0
                    assert result["load.program.entry_started"] == result["load.program.returned"] == 1
                    assert result["text"] == ("API refusal checks OK" if reduced else "DATA BSS relocation OK")
                    session.buttons(["ok"])
                else:
                    result = fields(session.get("/state"))
                    assert result["load.state"] == 0 and result["load.last_result"] == -13
                    trace = result["trace"]
                    assert trace["all_retained_sequences_match"]
                    assert 0 < trace["count"] - before <= 16
                    fresh = [row for row in trace["ordered"] if row["sequence"] > before]
                    # E also marks the synchronous file recheck. The budget
                    # guard follows that successful read and precedes queueing.
                    assert [(row["tag"], row["value"]) for row in fresh if row["tag"] == "E"] == [("E", 0)]
                    assert not any(row["tag"] in ("Q", "g", "h", "p", "x") for row in fresh)
                    assert result["text.generation"] == checked["text.generation"]
                assert not result["load.program.code_allocation"] and not result["load.program.data_allocation"]
                assert residents(result, count, data_residents) == kept
                session.capture(f"outcome-{attempt + 1}")
                session.buttons(["left"])
                after = fields(session.get("/state"))
                assert residents(after, count, data_residents) == kept
                assert all(not after[f"resident.{n}.used"] for n in range(count, 8))
                session.capture(f"list-after-{attempt + 1}")
                outcomes.append({"checked": checked, "result": result, "after": after})
            session.buttons(["left"])
            session.capture("setup-after")
        except BaseException as exception:
            error = repr(exception)
            traceback.print_exc()
        finally:
            if session:
                (args.out / "budget-inputs.json").write_text(json.dumps({"case": args.case, "limits": args.limits, "baseline": baseline,
                    "outcomes": outcomes, "inputs": session.records, "error": error,
                    "pixel_review_required": True}, indent=2) + "\n")
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
        raise RuntimeError(f"{args.case}: {error}, runner {runner.returncode}")
    result = json.loads((args.out / "result.json").read_text())
    assert result["owned_qemu_stopped"] and not result.get("error")
    print(json.dumps({"case": args.case, "observations_passed": len(outcomes), "owned_qemu_stopped": True}))


if __name__ == "__main__":
    main()
