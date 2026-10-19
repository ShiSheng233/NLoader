#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Start one owned runner and drive its native menu as soon as it is ready.

Pass runner arguments after --. Results remain separate from acceptance:
this prevents waiting for manual orchestration from consuming the original
firmware's menu idle timeout, without changing any guest timer or result.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--chord-exit", action="store_true")
    parser.add_argument("--chord-order", choices=("simultaneous", "menu-first", "delete-first"),
                        default="simultaneous")
    parser.add_argument("--autoload", action="store_true")
    parser.add_argument("--m1-catalog", type=Path)
    parser.add_argument("--m1-case")
    parser.add_argument("--firmware-evidence", type=Path)
    parser.add_argument("--timeout", type=int, default=180,
                        help="Host control wait in seconds (1..300); guest time is unchanged")
    parser.add_argument("runner", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.runner[1:] if args.runner[:1] == ["--"] else args.runner
    if arguments.count("--output") != 1 or not 1 <= args.repeat <= 3:
        parser.error("One explicit runner --output and repeat 1..3 required")
    if not 1 <= args.timeout <= 300:
        parser.error("Use 1..300 host wait seconds")
    if args.autoload and (args.run or args.chord_exit or args.repeat != 1):
        parser.error("Autoload observation is separate from foreground execution")
    if (args.repeat != 1 or args.chord_exit) and not args.run:
        parser.error("Repeat and chord exit require --run")
    m1_options = (args.m1_catalog, args.m1_case, args.firmware_evidence)
    m1 = any(value is not None for value in m1_options)
    if m1 and not all(value is not None for value in m1_options):
        parser.error("M1 requires catalog, case and independent firmware evidence together")
    if m1 and (args.run or args.autoload or args.chord_exit or args.repeat != 1):
        parser.error("M1 LoadOnly observation is separate from execution and autoload")
    if m1:
        catalog = json.loads(args.m1_catalog.read_text())
        cases = [case for case in catalog if case.get("case") == args.m1_case]
        evidence = json.loads(args.firmware_evidence.read_text())
        if len(cases) != 1 or cases[0].get("firmware_mode_required") != "load-only" or cases[0].get("image_contents_independently_match") is not True:
            parser.error("M1 requires one independently checked LoadOnly card case")
        if evidence.get("mode") != "load-only" or evidence.get("patch_manifest_used_as_evidence") is not False:
            parser.error("M1 requires independent LoadOnly firmware verification")
    at = arguments.index("--output")
    if at + 1 == len(arguments):
        parser.error("Missing runner output path")
    output = Path(arguments[at + 1])
    here = Path(__file__).resolve().parent
    runner = subprocess.Popen([sys.executable, str(here / "run.py"), *arguments])
    try:
        deadline = time.monotonic() + 120
        while not (output / "session.json").is_file():
            if runner.poll() is not None:
                raise RuntimeError(f"Owned runner exited before session creation: {runner.returncode}")
            if time.monotonic() >= deadline:
                raise TimeoutError("Owned runner did not create a session")
            time.sleep(0.1)
        scenario = [sys.executable, str(here / "scenario.py"),
                    "--output", str(output), "--repeat", str(args.repeat),
                    "--timeout", str(args.timeout), "--stop"]
        if args.autoload:
            scenario = [sys.executable, str(here / "autoload_scenario.py"),
                        "--output", str(output), "--timeout", str(args.timeout), "--stop"]
        if m1:
            scenario = [sys.executable, str(here / "m1_scenario.py"),
                        "--output", str(output), "--catalog", str(args.m1_catalog),
                        "--case", args.m1_case,
                        "--firmware-evidence", str(args.firmware_evidence),
                        "--timeout", str(args.timeout), "--stop"]
        if args.run:
            scenario.append("--run")
        if args.chord_exit:
            scenario.extend(["--chord-exit", "--chord-order", args.chord_order])
        result = subprocess.run(scenario, check=False)
        runner.wait(timeout=30)
        if result.returncode or runner.returncode:
            raise RuntimeError(f"Native scenario={result.returncode}; owned runner={runner.returncode}")
    finally:
        if runner.poll() is None:
            runner.terminate()
            runner.wait(timeout=30)


if __name__ == "__main__":
    main()
