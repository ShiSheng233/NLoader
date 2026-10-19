#!/usr/bin/env python3
"""Build four independent code-only extensions to isolate the resident limit."""
import argparse
import json
from pathlib import Path
import subprocess

from materials import ROOT, audit_program


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    apps = args.out / 'card-files/NLOADER/APPS'
    apps.mkdir(parents=True)
    records, lines, ids = [], [], []
    for n, name in enumerate(('one', 'two', 'three', 'four')):
        identity = 'code_' + name
        declaration = {'id': identity, 'kind': 'resource_extension',
                       'display_name': 'Code ' + name, 'file': 'APPS/CODE' + str(n + 1) + '.NLB',
                       'min_abi': 2, 'models': 'z8/3.11'}
        decl = args.out / (identity + '.json')
        decl.write_text(json.dumps(declaration) + '\n')
        source = args.out / (identity + '.c')
        source.write_text('#define NLR_TEST_ITEM_ID ' + hex(0x7ffa - n) + 'u\n'
                          '#define NLR_TEST_INIT_RESULT 0\n'
                          '#include "extension_lifecycle.c"\n')
        copies = []
        for attempt in (1, 2):
            output = args.out / (identity + '-' + str(attempt) + '.NLB')
            manifest = output.with_suffix('.MANIFEST')
            completed = subprocess.run([
                str(ROOT / 'tool/nloader/target/debug/nloader'), 'program', '--decl', str(decl),
                '--source', str(ROOT / 'sdk/crt0.s'), '--source', str(source),
                '--include', str(ROOT / 'sdk'), '--include', str(ROOT / 'tests/qemu/extension_lifecycle'),
                '--cc', '/opt/homebrew/opt/llvm/bin/clang', '--out', str(output),
                '--manifest', str(manifest)], check=True, capture_output=True, text=True)
            output.with_suffix('.build.json').write_text(completed.stdout)
            copies.append(output.read_bytes())
        assert copies[0] == copies[1]
        record = audit_program(copies[0])
        assert record['data_bytes'] == record['bss_bytes'] == 0 and record['kind'] == 1
        records.append(dict(record, id=identity, two_builds_identical=True))
        (apps / Path(declaration['file']).name).write_bytes(copies[0])
        lines.append(manifest.read_text())
        ids.append(identity)
    (apps.parent / 'MANIFEST').write_text(''.join(lines))
    (apps.parent / 'ENABLED').write_text('\n'.join(ids) + '\n')
    (args.out / 'materials.json').write_text(json.dumps({'programs': records,
        'expected_resident_limit': 3, 'expected_budget_blocks': 6,
        'actual_qemu_verified': False}, indent=2) + '\n')


if __name__ == '__main__':
    main()
