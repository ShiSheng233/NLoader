#!/usr/bin/env python3
"""Build WADCHECK twice and prepare synthetic, independently described WAD cards."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tests/qemu/m2_data'))
from materials import audit_program


def fnv(data):
    result = 2166136261
    for byte in data:
        result = ((result ^ byte) * 16777619) & 0xffffffff
    return result


def fixtures():
    payload = bytes((n * 29 + n // 251) & 255 for n in range(8192))
    directory = [(12, 600, b'FIRST'), (0, 0, b'MARKER'),
                 (31, 10, b'FIRST'), (INT_MAX, 0, b'EMPTY'),
                 (7100, 67, b'LAST')]
    valid = b'IWAD' + struct.pack('<II', len(directory), 12 + len(payload)) + payload
    valid += b''.join(struct.pack('<II8s', *item) for item in directory)
    expected = {'count': 5, 'file_bytes': len(valid),
                'first': {'index': 0, 'hash': fnv(valid[12:76])},
                'last': {'index': 4, 'hash': fnv(valid[7100:7164])}}
    out_of_bounds = bytearray(valid)
    struct.pack_into('<I', out_of_bounds, 12 + len(payload) + 4, len(valid))
    return {
        'valid': (valid, 0, expected),
        'empty': (b'PWAD' + struct.pack('<II', 0, 12), 0,
                  {'count': 0, 'file_bytes': 12}),
        'directory-truncated': (valid[:-1], 5, None),
        'lump-out-of-bounds': (bytes(out_of_bounds), 5, None),
        'missing': (None, 2, None),
    }


INT_MAX = 0x7fffffff


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--resident', type=Path,
                        help='Optional independently built data extension NLB; matching .MANIFEST required')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'sdk/examples/doom'
    declaration = json.loads((source / 'wad_check.json').read_text())
    copies = []
    for n in (1, 2):
        output = args.out / f'WADCHECK-{n}.NLB'
        command = [str(ROOT / 'tool/nloader/target/debug/nloader'), 'program',
                   '--decl', str(source / 'wad_check.json'), '--source', str(ROOT / 'sdk/crt0.s'),
                   '--source', str(source / 'wad.c'), '--source', str(source / 'wad_check.c'),
                   '--include', str(ROOT / 'sdk'), '--cc', '/opt/homebrew/opt/llvm/bin/clang',
                   '--out', str(output), '--manifest', str(output.with_suffix('.MANIFEST'))]
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        output.with_suffix('.build.json').write_text(completed.stdout)
        copies.append(output.read_bytes())
    if copies[0] != copies[1]:
        raise ValueError('WADCHECK builds differ')
    program = dict(audit_program(copies[0]), declaration=declaration)
    if program['kind'] != 2:
        raise ValueError('Expected a foreground application')
    resident = None
    resident_line = ''
    if args.resident:
        resident = audit_program(args.resident.read_bytes())
        if resident['kind'] != 1 or not resident['data_bytes'] or not resident['bss_bytes']:
            raise ValueError('Coexistence requires a resource extension with data and BSS')
        resident_line = args.resident.with_suffix('.MANIFEST').read_text()
        lines = [line for line in resident_line.splitlines() if line.strip() and not line.lstrip().startswith('#')]
        if len(lines) != 1:
            raise ValueError('Exactly one resident declaration required')
        parts = [v.strip() for v in lines[0].split('|')]
        if len(parts) != 6 or parts[1] != 'resource_extension':
            raise ValueError('One complete resource declaration required')
        resident.update(id=parts[0], file=parts[3], manifest=resident_line)
    cases = {}
    for name, (wad, result, summary) in fixtures().items():
        folder = args.out / 'cards' / name
        apps = folder / 'NLOADER/APPS'
        apps.mkdir(parents=True)
        (apps / Path(declaration['file']).name).write_bytes(copies[0])
        manifest = (args.out / 'WADCHECK-1.MANIFEST').read_text()
        with_resident = name == 'valid' and resident is not None
        if with_resident:
            (apps / Path(resident['file']).name).write_bytes(args.resident.read_bytes())
            manifest += resident_line
            (apps.parent / 'ENABLED').write_text(resident['id'] + '\n')
        (apps.parent / 'MANIFEST').write_text(manifest)
        if wad is not None:
            (apps.parent / 'DOOM.WAD').write_bytes(wad)
        cases[name] = {'folder': str(folder.resolve()), 'result': result, 'summary': summary,
                       'text': 'WAD ready' if result == 0 else 'WAD rejected',
                       'resident': resident if with_resident else None,
                       'files': {str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in folder.rglob('*') if p.is_file()}}
    (args.out / 'materials.json').write_text(json.dumps({
        'program': program, 'two_builds_identical': True, 'cases': cases,
        'synthetic_wad_only': True, 'game_playability_verified': False}, indent=2) + '\n')


if __name__ == '__main__':
    main()
