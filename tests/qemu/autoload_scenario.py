#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe natural autoload before opening NLoader, then inspect stock Setup."""
import argparse
import json
from pathlib import Path
from scenario import NativeSession


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--published", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--stop", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 300:
        parser.error("Use 1..300 host wait seconds")
    destination = args.output / "autoload-inputs.json"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    session = NativeSession(args.output, args.timeout)
    error = None
    try:
        def done(state):
            observed = state.get("runtime_snapshot", {})
            fields = observed.get("fields", {})
            return state["ready"] and state.get("ui_mode") == 1 and observed.get("found") and \
                fields.get("autoload.phase") == 4 and fields.get("autoload.result") == 0 and \
                fields.get("resource_clone.published_count") == args.published
        session.wait(done)
        session.capture("autoload-done-before-nloader")
        session.buttons(["left", "down", "down", "down", "down", "right"], settle=2)
        session.capture("setup-with-resources")
        session.buttons(["down"], settle=2)
        session.capture("next-setup-item")
        session.buttons(["ok"], settle=2)
        session.capture("inert-item-ok")
        session.buttons(["up"], settle=2)
        session.capture("navigation-after-item")
    except BaseException as exception:
        error = repr(exception)
        raise
    finally:
        destination.write_text(json.dumps({"session": session.session, "inputs": session.records,
                                            "error": error, "acceptance": "separate actual records and pixels"}, indent=2) + "\n")
        if args.stop:
            session.post("/stop")


if __name__ == "__main__":
    main()
