#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""NLoader menu testing with the pinned Z8 model and a real exFAT/NVMe image."""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "z8-qemu" / "tools"
sys.path.insert(0, str(TOOLS))


def run_owned_session(guest, boot, stream_run, seconds, control, stop_label, final_observation):
    """Keep final reads and owned cleanup on every exit, without resuming a cut."""
    from passive import StopAtPassive

    with guest:
        try:
            boot(guest)
            hit = False
            try:
                stream_run(guest, seconds, control)
            except StopAtPassive as stopped:
                evidence = guest.data.get("passive_stop", {})
                if (stop_label is None or stopped.label != stop_label or
                        evidence.get("requested_label") != stop_label or
                        evidence.get("hit") is not True or
                        evidence.get("intentional") is not True or
                        evidence.get("resume_after_hit") is not False):
                    raise RuntimeError("Unexpected passive stop label") from stopped
                hit = True
            if stop_label is not None and not hit:
                guest.data["passive_stop"] = {
                    "requested_label": stop_label, "hit": False, "intentional": False,
                }
                raise RuntimeError("Requested passive stop was not hit")
            guest.check("no unmodeled MMIO in observed run", "Z8_UNKNOWN" not in guest.log())
        finally:
            final_observation()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def card_geometry(path):
    if not path.is_file() or path.stat().st_size != 8 * 1024**3:
        raise ValueError("Expected an 8 GiB regular card image")
    with path.open("rb") as stream:
        mbr = stream.read(512)
        if mbr[510:] != b"\x55\xaa" or mbr[450] != 7:
            raise ValueError("Expected an MBR exFAT card")
        start, sectors = struct.unpack_from("<II", mbr, 454)
        if start != 2048 or sectors != path.stat().st_size // 512 - start:
            raise ValueError("Unexpected card partition bounds")
        stream.seek(start * 512)
        if stream.read(11)[3:11] != b"EXFAT   ":
            raise ValueError("Expected an exFAT volume")
    return {"partition_offset": start * 512, "sectors": sectors}


def card_input(template, interface, state):
    """Validate the real backing input before any process or copy is created."""
    if state == "absent":
        if template is not None or interface != "nvme":
            raise ValueError("Absent CFexpress requires no card template and the NVMe interface")
        return {"partition_offset": None, "sectors": None}
    if template is None:
        raise ValueError("A present card requires an explicit template")
    if state == "normal":
        return card_geometry(template)
    if state != "unpartitioned" or interface != "nvme":
        raise ValueError("Unpartitioned diagnostics require the NVMe interface")
    if not template.is_file() or template.stat().st_size != 8 * 1024**3:
        raise ValueError("Unpartitioned input requires an 8 GiB regular image")
    with template.open("rb") as stream:
        for offset in (0, 512, template.stat().st_size - 512):
            stream.seek(offset)
            if stream.read(512) != bytes(512):
                raise ValueError("Unpartitioned diagnostic requires zero MBR and both GPT header sectors")
    return {"partition_offset": None, "sectors": template.stat().st_size // 512}


def validate_card_access(interface, state, access):
    if access not in ("read-write", "read-only"):
        raise ValueError("Unknown card access mode")
    if access == "read-only" and (interface != "nvme" or state != "normal"):
        raise ValueError("Read-only diagnostics require a normal NVMe card")


def verify_read_only_backend(blocks, card):
    """Require the actual owned raw device to be read-only, not just its argv."""
    entries = [item for item in blocks if item.get("device") == "card"]
    if len(entries) != 1:
        raise ValueError("Expected exactly one owned card backend")
    inserted = entries[0].get("inserted", {})
    image = inserted.get("image", {})
    if (inserted.get("ro") is not True or inserted.get("drv") != "raw" or
            inserted.get("file") != str(card) or image.get("filename") != str(card) or
            image.get("virtual-size") != 8 * 1024**3):
        raise ValueError("Actual card backend does not match the read-only diagnostic")
    return {"verified": True, "file": str(card), "ro": True,
            "virtual_size": image["virtual-size"], "physical_write_protection_proven": False}


def storage_devices(card, interface, state, access="read-write"):
    validate_card_access(interface, state, access)
    if state == "absent":
        return []
    if card is None:
        raise ValueError("A present device requires its owned copied image")
    device = ("sd-card,drive=card,bus=sd-bus" if interface == "sd" else
              "nvme,drive=card,serial=NLOADER-QEMU,bus=dw-pcie,addr=0")
    drive = f"file={card},if=none,id=card,format=raw"
    if access == "read-only":
        drive += ",readonly=on"
    return ["-drive", drive, "-device", device]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-firmware", type=Path, required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--firmware-sha256", required=True)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--card-template", type=Path)
    parser.add_argument("--card-state", choices=("normal", "absent", "unpartitioned"),
                        default="normal", help="Normal exFAT, no endpoint, or a real unpartitioned disk")
    parser.add_argument("--card-interface", choices=("sd", "nvme"), default="nvme",
                        help="NVMe maps to A:; SD is an unqualified diagnostic")
    parser.add_argument("--card-access", choices=("read-write", "read-only"), default="read-write",
                        help="Read-only uses the NVMe block backend; no full-card or power-loss claim")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8778)
    parser.add_argument("--seconds", type=int, default=1800)
    parser.add_argument("--snapshot-spec", type=Path,
                        help="Bounded read-only runtime observation using this build's layout")
    parser.add_argument("--observe-live", action="store_true",
                        help="Expose read-only runtime fields at the stream's existing paused captures")
    parser.add_argument("--memory-samples", type=Path,
                        help="Candidate-bound fixed RAM samples at idle live screenshot captures")
    parser.add_argument("--follow-spec", type=Path,
                        help="Read one aligned, magic-checked object through an observed runtime pointer")
    parser.add_argument("--passive-points", type=Path,
                        help="One-shot read-only instruction observations after the runtime exists")
    parser.add_argument("--stop-at-passive", metavar="LABEL",
                        help="End this owned session at one verified passive instruction, without resuming")
    parser.add_argument("--passive-arm", choices=("runtime", "stream-start"), default="runtime",
                        help="Arm after Runtime discovery (default), or after boot before the stream starts")
    parser.add_argument("--read-range", action="append", default=[],
                        help="Read verified high-RAM LABEL:ADDRESS:LENGTH before owned shutdown")
    parser.add_argument("--translate", action="append", default=[],
                        help="Record QEMU's own gva2gpa answer for LABEL:ADDRESS on CPU 0 "
                             "after the owned stop; read-only, nothing in the guest changes")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600 or not 1024 <= args.port <= 65535:
        parser.error("Invalid duration or port")
    if args.observe_live and (not args.snapshot_spec or args.smoke):
        parser.error("Live observations require an interactive session and --snapshot-spec")
    if args.memory_samples and not args.observe_live:
        parser.error("Memory samples require --observe-live")
    if args.stop_at_passive is not None and (not args.passive_points or args.smoke):
        parser.error("Stop-at-passive requires passive points and an interactive session")
    if args.passive_arm != "runtime" and (not args.passive_points or args.smoke):
        parser.error("Stream-start arming requires passive points and an interactive session")
    validate_card_access(args.card_interface, args.card_state, args.card_access)
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("Use a fresh run directory")

    from runtime import verify
    from full_guest import Guest
    from copy_card import copy_card
    from boot_z8 import boot
    from rom_inputs import attach
    import stream
    from controls import Control, make_peer
    from control import png_from_ppm

    stock, _ = verify(args.stock_firmware)
    firmware, binary, raw, output = (
        path.resolve() for path in
        (args.firmware, args.qemu, args.raw, args.output)
    )
    template = args.card_template.resolve() if args.card_template is not None else None
    if firmware.stat().st_size != stock.stat().st_size:
        raise ValueError("Candidate must be an EG payload without its CRC trailer")
    actual = digest(firmware)
    if actual != args.firmware_sha256.lower():
        raise ValueError("Candidate firmware SHA256 mismatch")
    for path in (firmware, binary, raw, output, *((template,) if template else ())):
        if "," in str(path):
            raise ValueError("QEMU runtime paths cannot contain commas")
    if output.exists():
        raise FileExistsError("Use a fresh run directory")
    if not binary.is_file() or not raw.is_file():
        raise ValueError("QEMU and sensor input must exist")
    geometry = card_input(template, args.card_interface, args.card_state)
    snapshot_spec = None
    follow_spec = None
    passive_points = None
    memory_samples = None
    read_ranges = []
    for declaration in args.read_range:
        label, address, length = declaration.split(":")
        if not label or not all(c.isascii() and (c.isalnum() or c in "_-") for c in label):
            raise ValueError("Invalid memory observation label")
        address, length = int(address, 0), int(length, 0)
        if not 0 < length <= 65536 or not 0xa00000000 <= address < address + length <= 0xa20000000:
            raise ValueError("Memory observation must be bounded high RAM")
        read_ranges.append((label, address, length))
    if len({label for label, _, _ in read_ranges}) != len(read_ranges):
        raise ValueError("Memory observation labels must be unique")
    translations = []
    for declaration in args.translate:
        label, address = declaration.split(":")
        if not label or not all(c.isascii() and (c.isalnum() or c in "_-") for c in label):
            raise ValueError("Invalid translation label")
        address = int(address, 0)
        if not 0 <= address < 1 << 48 or address % 4096:
            raise ValueError("Translation address must be a page start")
        translations.append((label, address))
    if len({label for label, _ in translations}) != len(translations) or len(translations) > 256:
        raise ValueError("Translation labels must be unique, at most 256")
    if args.snapshot_spec:
        snapshot_spec = json.loads(args.snapshot_spec.read_text())
        from observe_runtime import validate_specification
        validate_specification(snapshot_spec)
    if args.memory_samples:
        memory_samples = json.loads(args.memory_samples.read_text())
        from memory_samples import validate
        validate(memory_samples, actual)
        state_field = snapshot_spec["layout"]["fields"].get("load.state", {})
        if state_field.get("type") not in ("u32", "i32"):
            raise ValueError("Memory samples require an observed integer load.state")
    if args.follow_spec:
        if snapshot_spec is None:
            parser.error("Follow observation requires --snapshot-spec")
        follow_spec = json.loads(args.follow_spec.read_text())
        from observe_runtime import validate_follow
        validate_follow(follow_spec, snapshot_spec)
    if args.passive_points:
        if not args.observe_live:
            parser.error("Passive points require live runtime observation")
        passive_points = json.loads(args.passive_points.read_text())
        from passive import validate, validate_stop_label
        validate(passive_points, firmware)
        validate_stop_label(passive_points, args.stop_at_passive)
    revision = subprocess.check_output(
        ["git", "-C", str(ROOT / "z8-qemu"), "rev-parse", "HEAD"], text=True
    ).strip()
    receipt = {
        "submodule_commit": revision,
        "stock_firmware": str(stock), "stock_firmware_sha256": digest(stock),
        "firmware": str(firmware), "firmware_sha256": actual,
        "qemu": str(binary), "qemu_sha256": digest(binary),
        "raw": str(raw), "raw_sha256": digest(raw),
        "card_template": str(template) if template is not None else None,
        "card_template_sha256": digest(template) if template is not None else None,
        **geometry,
        "card_interface": args.card_interface,
        "card_state": args.card_state,
        "card_access": args.card_access,
        "storage": "guest filesystem via SDHCI or DesignWare PCIe/NVMe; no file-request stand-in",
        "physical_camera_verified": False,
        "read_ranges": read_ranges,
        "translations": [[label, hex(address)] for label, address in translations],
    }
    if args.snapshot_spec:
        receipt["snapshot_spec"] = str(args.snapshot_spec.resolve())
        receipt["snapshot_spec_sha256"] = digest(args.snapshot_spec)
    if args.memory_samples:
        receipt["memory_samples"] = str(args.memory_samples.resolve())
        receipt["memory_samples_sha256"] = digest(args.memory_samples)
    if args.follow_spec:
        receipt["follow_spec"] = str(args.follow_spec.resolve())
        receipt["follow_spec_sha256"] = digest(args.follow_spec)
    if args.passive_points:
        receipt["passive_points"] = str(args.passive_points.resolve())
        receipt["passive_points_sha256"] = digest(args.passive_points)
        receipt["passive_arm"] = args.passive_arm
        if args.stop_at_passive is not None:
            receipt["stop_at_passive"] = args.stop_at_passive
    if args.check_only:
        print(json.dumps(receipt, indent=2))
        return

    # Preserve upstream's stock verification. Only the explicit kernel input is
    # replaced after candidate verification; no global hash checks are disabled.
    guest = Guest(stock, binary, raw, output)
    guest.data.update(receipt)
    control = None
    def stop_owned_session(*_):
        if control:
            control.stop.set()
        else:
            raise KeyboardInterrupt("Session termination requested")
    signal.signal(signal.SIGTERM, stop_owned_session)
    try:
        card = output / "card.raw" if template is not None else None
        if card is not None:
            copy_card(template, card)
        guest.firmware = firmware
        guest.command[guest.command.index("-kernel") + 1] = str(firmware)
        machine_index = guest.command.index("-M") + 1
        guest.command[machine_index] = guest.command[machine_index].replace(
            "nikon-z8-lab,", "nikon-z8-full-lab,"
        )
        if args.card_interface == "nvme":
            guest.command[machine_index] += (
                ",zr-sd-empty-fixture=on,capture-gpio-model=on"
                ",pcie-link-diagnostic-mask=4,pcie-dbi-model=on"
                ",pcie-ram-dma-input=on,pcie-image-ram-dma-input=on,pcie-intx-model=on"
            )
        guest.command += [
            "-device", f"loader,file={firmware},addr=0x40160000,force-raw=on,cpu-num=0",
        ]
        guest.command += storage_devices(card, args.card_interface, args.card_state, args.card_access)
        attach(guest)
        guest.data["command"] = guest.command
        guest.data["card"] = str(card) if card is not None else None
        (output / "inputs.json").write_text(json.dumps(receipt, indent=2) + "\n")
        if not args.smoke:
            control = Control(args.port)
            if args.observe_live:
                from observe_runtime import capture, capture_followed
                def observe_live():
                    observed = capture(guest, snapshot_spec, persist=False)
                    if memory_samples:
                        from memory_samples import capture as capture_memory_samples
                        rows = guest.data.get("pipeline_samples", [])
                        if not rows:
                            raise ValueError("Memory samples require the existing paused pipeline capture")
                        observed["memory_samples"] = capture_memory_samples(
                            guest, observed, memory_samples, actual, rows[-1], len(rows))
                    if follow_spec:
                        observed["followed"] = capture_followed(
                            guest, observed, follow_spec, snapshot_spec, persist=False)
                    return observed
                control.observe = observe_live
        stream.Peer = make_peer(control, passive_points, args.stop_at_passive, args.passive_arm)
        (output / "session.json").write_text(json.dumps({
            "qmp_socket": str(guest.runtime / "qmp.sock"),
            "controller_url": None if control is None else f"http://127.0.0.1:{args.port}/",
            "session": None if control is None else control.session,
        }, indent=2) + "\n")
        def final_observation():
            guest.data["storage_observations"] = {}
            for name, arguments in (
                ("pcie-dbi-state", {"path": "/machine", "property": "pcie-dbi-state"}),
                ("query-block", {}),
            ):
                try:
                    command = "query-block" if name == "query-block" else "qom-get"
                    guest.data["storage_observations"][name] = guest.qmp.command(command, **arguments)
                except Exception as error:
                    guest.data["storage_observations"][name] = {"error": str(error)}
            if args.card_access == "read-only":
                try:
                    guest.data["read_only_backend_final"] = verify_read_only_backend(
                        guest.data["storage_observations"]["query-block"], card)
                except Exception as error:
                    guest.data["read_only_backend_final"] = {"verified": False, "error": str(error)}
            try:
                guest.qmp.command("stop")
                guest.data["cpu_registers"] = {
                    str(cpu): guest.qmp.hmp("info registers", cpu) for cpu in range(4)
                }
                guest.data["memory_observations"] = {}
                for label, address, length in read_ranges:
                    try:
                        observed = guest.read_bytes(address, length)
                        if len(observed) != length:
                            raise RuntimeError("Short physical observation")
                        target = output / f"observation-{label}.bin"
                        with target.open("xb") as stream:
                            stream.write(observed)
                        guest.data["memory_observations"][label] = {
                            "address": hex(address), "bytes": length,
                            "file": str(target), "sha256": digest(target),
                        }
                    except Exception as error:
                        guest.data["memory_observations"][label] = {"error": str(error)}
                # The answer is QEMU's walk of CPU 0's current tables at the
                # stop; the raw monitor text is kept as the evidence.
                guest.data["translations"] = {}
                for label, address in translations:
                    try:
                        guest.data["translations"][label] = {
                            "address": hex(address),
                            "gva2gpa": guest.qmp.hmp(f"gva2gpa {address:#x}", 0).strip(),
                        }
                    except Exception as error:
                        guest.data["translations"][label] = {"address": hex(address),
                                                             "error": str(error)}
                if snapshot_spec:
                    from observe_runtime import capture
                    try:
                        guest.data["runtime_snapshot"] = capture(guest, snapshot_spec)
                        if follow_spec:
                            from observe_runtime import capture_followed
                            guest.data["followed_snapshot"] = capture_followed(
                                guest, guest.data["runtime_snapshot"], follow_spec, snapshot_spec)
                    except Exception as error:
                        guest.data["runtime_snapshot"] = {"found": False, "error": str(error)}
                guest.qmp.command("screendump", filename=str(output / "final.ppm"))
                (output / "final.png").write_bytes(png_from_ppm(output / "final.ppm"))
            except Exception as error:
                guest.data["final_screenshot_error"] = str(error)
            if (args.card_access == "read-only" and
                    guest.data.get("read_only_backend_final", {}).get("verified") is not True):
                raise RuntimeError("Final read-only backend identity was not verified")

        def verified_boot(owned_guest):
            if args.card_access == "read-only":
                actual_blocks = owned_guest.qmp.command("query-block")
                owned_guest.data["read_only_backend_before_boot"] = verify_read_only_backend(actual_blocks, card)
            boot(owned_guest)

        run_owned_session(guest, verified_boot, stream.run, args.seconds, control,
                          args.stop_at_passive, final_observation)
    except BaseException as error:
        if guest.proc is None:
            guest.__exit__(type(error), error, error.__traceback__)
        raise
    finally:
        if control:
            control.close()


if __name__ == "__main__":
    main()
