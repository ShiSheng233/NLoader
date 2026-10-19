#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Copy NLOADER files into a fresh macOS exFAT image before QEMU starts."""
import argparse
import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "z8-qemu" / "tools"))


def detach_image(device):
    # macOS metadata services may briefly hold the freshly copied volume.
    # Retry a normal detach; never force unmount or affect unrelated disks.
    for attempt in range(4):
        result = subprocess.run(["hdiutil", "detach", device], capture_output=True)
        if result.returncode == 0:
            return
        if result.returncode != 16 or attempt == 3:
            result.check_returncode()
        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=Path, required=True, help="Card file tree")
    parser.add_argument("--loader-dir", default="NLOADER", help="Profile root without volume, using / separators")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--no-manifest", action="store_true",
                        help="a card whose programs describe themselves (NPLD v3): "
                             "no MANIFEST, at least one "
                             "APPS/*.NLB")
    parser.add_argument("--no-loader", action="store_true",
                        help="a card without the loader directory at all; only "
                             "--extra-dir directories are copied")
    parser.add_argument("--extra-dir", action="append", default=[],
                        help="Another top-level directory of --files to copy too "
                             "(e.g. DCIM for the ABI 9 read-only pictures); repeatable")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("This preparation helper uses macOS image tools")
    components = args.loader_dir.split("/")
    if any(not part or not all(c.isascii() and (c.isalnum() or c in "_-") for c in part)
           for part in components):
        parser.error("Expected relative loader directory components")
    loader_dir = Path(*components)
    extras = []
    for name in args.extra_dir:
        if (not name or "/" in name or name == loader_dir.parts[0] or
                not all(c.isascii() and (c.isalnum() or c in "_-") for c in name)):
            parser.error("Expected a plain top-level directory name for --extra-dir")
        extra = args.files.resolve() / name
        if not extra.is_dir() or extra.is_symlink() or any(
                path.is_symlink() for path in extra.rglob("*")):
            parser.error(f"--extra-dir {name} must be a real directory of --files")
        extras.append(name)
    files = args.files.resolve() / loader_dir
    if args.no_loader:
        if args.no_manifest or files.exists() or not extras:
            parser.error("--no-loader needs no loader directory in --files, "
                         "at least one --extra-dir, and no --no-manifest")
    elif args.no_manifest:
        if not files.is_dir() or (files / "MANIFEST").exists() or \
                not any((files / "APPS").glob("*.NLB")):
            parser.error("--no-manifest needs APPS/*.NLB and no MANIFEST")
    elif not files.is_dir() or not (files / "MANIFEST").is_file():
        parser.error("MANIFEST under the selected loader directory is required")
    if not args.no_loader and (files.is_symlink() or
                               any(path.is_symlink() for path in files.rglob("*"))):
        parser.error("Card inputs must not contain symbolic links")
    output = args.out.absolute()
    reserved = [output, output.with_suffix(".initial.json"),
                output.with_suffix(".files.json"), output.with_suffix(".failed.json"),
                output.with_suffix(".failed.raw"),
                output.with_name(output.stem + "-initial-volume.raw")]
    if any(path.exists() or path.is_symlink() for path in reserved):
        raise FileExistsError("Refusing to overwrite card image or its preparation records")
    output.parent.mkdir(parents=True, exist_ok=True)
    from virtual_recording_card import create
    from inspect_card_volume import catalog

    device = None
    try:
        create(output, "exfat")
        with tempfile.TemporaryDirectory(prefix="nl-card-") as mount:
            attached = plistlib.loads(subprocess.check_output([
                "hdiutil", "attach", "-plist", "-noverify", "-noautofsck",
                "-imagekey", "diskimage-class=CRawDiskImage",
                "-mountpoint", mount, str(output),
            ]))
            entities = attached["system-entities"]
            disks = [row["dev-entry"] for row in entities
                     if re.fullmatch(r"/dev/disk[0-9]+", row.get("dev-entry", ""))]
            if len(disks) != 1:
                raise ValueError("Expected exactly one attached image disk")
            device = disks[0]
            try:
                mounted = [row for row in entities if row.get("mount-point")
                           and Path(row["mount-point"]).resolve() == Path(mount).resolve()]
                if len(mounted) != 1:
                    raise ValueError("Expected exactly one mounted image volume")
                if not args.no_loader:
                    target = Path(mount) / loader_dir
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(files, target, copy_function=shutil.copyfile,
                                    ignore=shutil.ignore_patterns(".DS_Store", "._*"))
                for name in extras:
                    shutil.copytree(args.files.resolve() / name, Path(mount) / name,
                                    copy_function=shutil.copyfile,
                                    ignore=shutil.ignore_patterns(".DS_Store", "._*"))
            finally:
                detach_image(device)
                device = None
        receipt = catalog(output, 1048576)
        receipt["loader_directory"] = None if args.no_loader else args.loader_dir
        receipt["extra_directories"] = extras
        with output.with_suffix(".files.json").open("x") as stream:
            stream.write(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, indent=2))
    except BaseException:
        cleanup_error = None
        if device:
            try:
                detach_image(device)
            except subprocess.CalledProcessError as error:
                cleanup_error = str(error)
        # Preserve failed preparation under an unmistakable diagnostic name.
        if cleanup_error:
            with output.with_suffix(".failed.json").open("x") as stream:
                stream.write(json.dumps({
                    "image": str(output), "attached_device": device,
                    "detach_error": cleanup_error, "preparation_passed": False,
                }, indent=2) + "\n")
        elif output.exists():
            output.rename(output.with_suffix(".failed.raw"))
        raise


if __name__ == "__main__":
    main()
