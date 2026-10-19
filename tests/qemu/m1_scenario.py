#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Record native LoadOnly checks and navigation against a prepared card case.

Runtime assertions and pixel review are separate. The catalog contains
independent preboot expectations, not a build patch manifest. This driver
never writes guest memory, changes a backing card, or calls guest functions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from scenario import NativeSession

NO_CHECK = 0xFFFFFFFF


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def firmware_evidence(output, evidence_path, case):
    receipt = json.loads((output / "inputs.json").read_text())
    evidence = json.loads(evidence_path.read_text())
    if evidence.get("mode") != "load-only" or evidence.get("patch_manifest_used_as_evidence") is not False:
        raise ValueError("Independent LoadOnly firmware verification is required")
    expected = evidence.get("eg_sha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Firmware evidence requires the exact EG SHA256")
    if receipt.get("firmware_sha256") != expected:
        raise ValueError("Runner loaded a different firmware from the LoadOnly evidence")
    firmware = Path(receipt["firmware"])
    if not firmware.is_file() or digest(firmware) != expected:
        raise ValueError("Actual source EG no longer matches the verified LoadOnly firmware")
    state = case.get("card_state", "normal")
    if state not in ("normal", "absent", "unpartitioned") or receipt.get("card_state", "normal") != state:
        raise ValueError("Runner card state does not match the explicit catalog case")
    if state == "absent":
        if case.get("image") is not None or case.get("image_sha256") is not None or receipt.get("card_template") is not None or receipt.get("card_template_sha256") is not None:
            raise ValueError("Absent case must have no backing image or template identity")
    else:
        if not receipt.get("card_template") or not case.get("image") or Path(receipt["card_template"]).resolve() != Path(case["image"]).resolve():
            raise ValueError("Runner card template does not match the explicit catalog case")
        expected_image_sha256 = case.get("image_sha256")
        if state == "unpartitioned" and (not isinstance(expected_image_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_image_sha256)):
            raise ValueError("Unpartitioned case requires its independently checked image SHA256")
        if expected_image_sha256 is not None and receipt.get("card_template_sha256") != expected_image_sha256:
            raise ValueError("Runner template SHA256 differs from the independently checked case")
    if state != "normal":
        directory_result = case["expected"].get("directory_result")
        if (receipt.get("card_interface") != "nvme" or
                type(directory_result) is not int or directory_result >= 0):
            raise ValueError("Storage failure diagnostics require NVMe and an explicit negative directory error")
    if evidence.get("storage_root") != case.get("root"):
        raise ValueError("Verified firmware storage root does not match the catalog")
    return {"path": str(evidence_path.resolve()), "sha256": digest(evidence_path),
            "mode": evidence["mode"], "eg_sha256": expected,
            "card_template": receipt["card_template"], "card_state": state}


def fields(state):
    observed = state.get("runtime_snapshot", {})
    if not observed.get("found"):
        raise RuntimeError("Expected one observed NLoader runtime")
    return observed["fields"]


def current(session):
    state = session.get("/state")
    if state.get("session") != session.session["session"]:
        raise RuntimeError("Emulator session changed")
    return fields(state)


def trace(values):
    observed = values["load.trace"]
    if observed.get("all_retained_sequences_match") is not True:
        raise AssertionError("Runtime trace is incomplete or inconsistent")
    count = observed["count"]
    if type(count) is not int or count < 0:
        raise AssertionError("Invalid runtime trace count")
    return count, observed["ordered"]


def trace_since(values, previous):
    count, rows = trace(values)
    if count <= previous or count - previous > len(rows):
        raise AssertionError("No complete fresh trace interval for this check")
    return rows[-(count - previous):]


def check_only(values):
    if values.get("load.state") != 0:
        raise AssertionError("LoadOnly observation is not idle")
    for name in ("load.probe.prepared", "load.probe.entry_started",
                 "load.program.prepared", "load.program.entry_started",
                 "autoload.phase", *(f"resident.{n}.used" for n in range(8))):
        if values.get(name) != 0:
            raise AssertionError(f"LoadOnly must keep {name} zero: {values.get(name)!r}")


def assert_expected(values, expected):
    check_only(values)
    names = {"directory_result": "directory_result",
             "directory_count": "directory.count",
             "directory_bytes": "directory.bytes",
             "error_line": "directory.error_line"}
    for name, field in names.items():
        if name in expected and values.get(field) != expected[name]:
            raise AssertionError(f"{field}: expected {expected[name]}, observed {values.get(field)!r}")
    if expected.get("manifest_must_not_be_read"):
        count, rows = trace(values)
        if count > len(rows) or values.get("directory.count") != 0 or values.get("directory.bytes") != 0:
            raise AssertionError("SAFE_MODE requires an empty directory and complete initial trace")
        if any(row["tag"] in ("F", "P", "L", "O") for row in rows):
            raise AssertionError("SAFE_MODE nevertheless reached MANIFEST or NLB access")


def entry_expectation(case, index):
    expected = case["expected"]
    entries = expected.get("entries")
    if entries is not None:
        wanted = entries[index]
        if wanted.get("index") != index:
            raise ValueError("Catalog entry identity does not match its index")
        return wanted
    if index != 0:
        raise ValueError("A single-case expectation only permits index zero")
    root = case["root"]
    if root not in ("A:\\NLOADER\\", "B:\\NLOADER\\"):
        raise ValueError("Single-case fixtures require an explicit NLOADER root")
    comparisons = [row for row in case["file_comparisons"]
                   if row["path"] == "NLOADER/MANIFEST"]
    if len(comparisons) != 1:
        raise ValueError("Single-case MANIFEST needs one independent preboot identity")
    source = Path(case["files"]).resolve()
    manifest = (source / "NLOADER" / "MANIFEST").resolve()
    if source not in manifest.parents or digest(manifest) != comparisons[0]["sha256"]:
        raise ValueError("Source MANIFEST does not match its independent preboot SHA256")
    lines = [line.strip() for line in manifest.read_text(encoding="ascii").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if len(lines) != 1:
        raise ValueError("Single-case MANIFEST must contain exactly one data row")
    columns = [column.strip() for column in lines[0].split("|")]
    if len(columns) not in (5, 6):
        raise ValueError("Single-case MANIFEST does not match the line schema")
    relative = columns[3].replace("\\", "/")
    parts = relative.split("/")
    if parts[0] != "APPS" or any(part in ("", ".", "..") or ":" in part for part in parts):
        raise ValueError("Expected an explicit relative APPS file in the catalog MANIFEST")
    wanted = {"index": 0, "check_result": expected["check_result"],
              "path": root + relative.replace("/", "\\")}
    if wanted["check_result"] == 0:
        identities = [row for row in case["nlb_identities"]
                      if row["relative_path"] == "NLOADER/" + relative]
        if len(identities) != 1:
            raise ValueError("Successful case needs one independent NLB identity")
        identity = identities[0]
        program = (source / identity["relative_path"]).resolve()
        if source not in program.parents or digest(program) != identity["sha256"]:
            raise ValueError("Source NLB does not match its independent preboot SHA256")
        header = bytes.fromhex(identity["header_hex"])
        if len(header) < 32 or header[:4] != b"NPLD":
            raise ValueError("Successful NLB expectation needs a complete recognized header")
        version, size = struct.unpack_from("<HH", header, 4)
        if (version, size) not in ((1, 32), (2, 64)) or len(header) < size:
            raise ValueError("Successful NLB expectation has an unsupported header layout")
        with program.open("rb") as stream:
            if stream.read(size) != header[:size]:
                raise ValueError("Independent header does not match the preboot NLB")
        image_bytes = struct.unpack_from("<I", header, 12)[0]
        if "image_bytes_if_passed" in expected and expected["image_bytes_if_passed"] != image_bytes:
            raise ValueError("Independent successful image length conflicts with the header")
        wanted["image_bytes"] = image_bytes
    return wanted


def check_entry(session, case, index, label):
    wanted = entry_expectation(case, index)
    before = current(session)
    assert_expected(before, case["expected"])
    if before["detail_view"] != 0:
        raise AssertionError("Expected a list before checking a row")
    previous, _ = trace(before)
    session.buttons(["ok"], settle=3)
    state = session.wait(lambda s: s.get("runtime_snapshot", {}).get("found") and
                         s["runtime_snapshot"]["fields"]["load.state"] == 0 and
                         s["runtime_snapshot"]["fields"]["checked"] == index and
                         s["runtime_snapshot"]["fields"]["detail_view"] == 1 and
                         s["runtime_snapshot"]["fields"]["load.trace"]["count"] > previous)
    actual = fields(state)
    if state.get("session") != session.session["session"]:
        raise RuntimeError("Emulator session changed")
    assert_expected(actual, case["expected"])
    fresh = trace_since(actual, previous)
    if actual["check_result"] != wanted["check_result"]:
        raise AssertionError(f"Check {index}: {actual['check_result']} != {wanted['check_result']}")
    if not case["expected"].get("nlb_must_not_be_opened") and actual["path"] != wanted["path"]:
        raise AssertionError("Checked a different card file")
    if wanted["check_result"] == 0:
        if wanted.get("image_bytes") is not None and actual["load.image_bytes"] != wanted["image_bytes"]:
            raise AssertionError("Unexpected actual image length")
    if case["expected"].get("nlb_must_not_be_opened"):
        if any(row["tag"] in ("L", "O") for row in fresh) or actual["path"]:
            raise AssertionError("Refused entry nevertheless reached file opening")
    elif not any(row["tag"] == "L" and row["value"] == index for row in fresh):
        raise AssertionError("No fresh read attempt for the selected card file")
    session.capture(label)
    session.buttons(["left"], settle=2)
    actual = current(session)
    if actual["detail_view"] != 0 or actual["list_cursor"] != index:
        raise AssertionError("Return did not preserve the checked list cursor")
    check_only(actual)
    session.capture(label + "-returned-list")


def status_only(values, expected):
    assert_expected(values, expected)
    if values.get("checked") != NO_CHECK or values.get("detail_view") != 0 or values.get("path") != "":
        raise AssertionError("Empty or error page unexpectedly checked/opened a program")


def run_case(session, case):
    session.wait(lambda s: s["ready"] and s.get("ui_mode") == 1)
    session.capture("m1-initial-menu")
    session.buttons(["left", "down", "down", "down", "down", "right", "up", "up"])
    session.capture("m1-nloader-selected")
    session.buttons(["ok"], settle=3)
    state = session.wait(lambda s: s.get("runtime_snapshot", {}).get("found") and
                         s["runtime_snapshot"]["fields"]["directory_result"] == case["expected"]["directory_result"])
    actual = fields(state)
    if state.get("session") != session.session["session"]:
        raise RuntimeError("Emulator session changed")
    assert_expected(actual, case["expected"])
    session.capture("m1-first-list-or-error")
    if case["expected"]["directory_result"] == 0 and actual["directory.count"]:
        count = actual["directory.count"]
        if not 1 <= count <= 64:
            raise AssertionError("Unexpected successful list length")
        if count > 6:
            session.buttons(["down"] * 6, settle=2)
            session.capture("m1-seventh-row-viewport")
            check_entry(session, case, 6, "m1-seventh-check")
            last_visible = 6
            if count > 7:
                session.buttons(["down"], settle=2)
                session.capture("m1-eighth-row-viewport")
                check_entry(session, case, 7, "m1-eighth-check")
                last_visible = 7
            session.buttons(["up"] * last_visible, settle=2)
            check_entry(session, case, 0, "m1-return-to-first-check")
        session.buttons(["up"], settle=2)
        session.capture("m1-first-wraps-to-last")
        check_entry(session, case, count - 1, "m1-last-check")
        session.buttons(["down"], settle=2)
        session.capture("m1-last-wraps-to-first")
        check_entry(session, case, 0, "m1-first-check")
    else:
        status_only(actual, case["expected"])
        session.buttons(["up", "down", "ok"], settle=2)
        status_only(current(session), case["expected"])
        session.capture("m1-error-or-empty-after-native-input")
    session.buttons(["left"], settle=2)
    check_only(current(session))
    # ui_mode=1 does not identify the Setup window. This frame needs actual
    # pixel review until the owned observer supplies an independent window ID.
    session.capture("m1-after-left-setup-review-required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--firmware-evidence", type=Path, required=True,
                        help="Independent package verification with mode and exact EG SHA256")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--stop", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 300:
        parser.error("Use a host timeout of 1..300 seconds")
    catalog = json.loads(args.catalog.read_text())
    matches = [case for case in catalog if case["case"] == args.case]
    if len(matches) != 1:
        raise ValueError("Expected one explicit catalog case")
    case = matches[0]
    if case.get("firmware_mode_required") != "load-only" or case.get("image_contents_independently_match") is not True:
        raise ValueError("An independently checked LoadOnly card case is required")
    destination = args.output / "m1-inputs.json"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("M1 input record already exists")
    session = NativeSession(args.output, args.timeout)
    error = None
    proof = None
    try:
        proof = firmware_evidence(args.output, args.firmware_evidence, case)
        run_case(session, case)
    except BaseException as exception:
        error = repr(exception)
        raise
    finally:
        try:
            with destination.open("x") as stream:
                stream.write(json.dumps({"case": args.case, "session": session.session,
                                         "firmware_evidence": proof,
                                         "inputs": session.records, "error": error,
                                         "runtime_expectations_only": True,
                                         "setup_return_confirmed": False,
                                         "pixel_acceptance": "separate actual image review required"}, indent=2) + "\n")
        finally:
            if args.stop:
                try:
                    session.post("/stop")
                except Exception:
                    if error is None:
                        raise


if __name__ == "__main__":
    main()
