#!/usr/bin/env python3
"""Prepare bounded cards for a separately verified two-block/one-resident profile."""
import argparse
import json
from pathlib import Path
from materials import audit_program


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-materials', type=Path, required=True)
    parser.add_argument('--resident-materials', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    sources = {
        'code_one': (args.resident_materials / 'code_one-1.NLB', 'CODE1.NLB'),
        'code_two': (args.resident_materials / 'code_two-1.NLB', 'CODE2.NLB'),
        'data_one': (args.data_materials / 'programs/extension_one-1.NLB', 'DATA1.NLB'),
        'api_limits': (args.data_materials / 'programs/api_limits-1.NLB', 'LIMITS.NLB'),
    }
    programs = {}
    for name, (path, filename) in sources.items():
        data = path.read_bytes()
        assert data == path.with_name(path.name.replace('-1.NLB', '-2.NLB')).read_bytes()
        record = audit_program(data)
        assert record['kind'] == (2 if name == 'api_limits' else 1)
        assert bool(record['data_bytes'] + record['bss_bytes']) == (name == 'data_one')
        programs[name] = dict(record, path=str(path.resolve()), two_builds_identical=True)
    cases = {}
    for name, names in (('budget-fit', ['code_one', 'api_limits']),
                        ('budget-full', ['data_one', 'api_limits']),
                        ('resident-limit', ['code_one', 'code_two'])):
        folder = args.out / name
        apps = folder / 'NLOADER/APPS'
        apps.mkdir(parents=True)
        lines, enabled = [], []
        for program in names:
            source, filename = sources[program]
            (apps / filename).write_bytes(source.read_bytes())
            lines.append(source.with_suffix('.MANIFEST').read_text())
            if program != 'api_limits':
                enabled.append(program)
        (apps.parent / 'MANIFEST').write_text(''.join(lines))
        (apps.parent / 'ENABLED').write_text('\n'.join(enabled) + '\n')
        if 'api_limits' in names:
            (apps.parent / 'MODE.TXT').write_text('UR')
        cases[name] = {'folder': str(folder.resolve()), 'programs': names, 'enabled': enabled}
    (args.out / 'materials.json').write_text(json.dumps({'programs': programs, 'cases': cases,
        'required_budget_blocks': 2, 'required_max_resident': 1, 'actual_qemu_verified': False}, indent=2) + '\n')


if __name__ == '__main__':
    main()
