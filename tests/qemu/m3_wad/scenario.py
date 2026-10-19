#!/usr/bin/env python3
"""Verify WAD reads and optional data-extension coexistence through native controls."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tests/qemu'))
from scenario import NativeSession
sys.path.insert(0, str(ROOT / 'z8-qemu/tools'))
from extract_card_file import extract
from inspect_card_volume import catalog


def fields(state):
    snapshot = state.get('runtime_snapshot', {})
    if not snapshot.get('found'):
        raise RuntimeError('No unique observed Runtime')
    return snapshot['fields']


def logs(trace, after):
    rows = [row for row in trace['ordered'] if row['sequence'] > after]
    if any(not row['sequence_matches'] for row in rows):
        raise ValueError('Incomplete trace sequence')
    messages = []
    for n, row in enumerate(rows):
        if row['tag'] != 'T' or not 0 <= row['value'] <= 32:
            continue
        length = row['value']
        chunks = rows[n + 1:n + 1 + (length + 3) // 4]
        if len(chunks) * 4 < length or any(chunk['tag'] != 't' for chunk in chunks):
            continue
        data = b''.join((chunk['value'] & 0xffffffff).to_bytes(4, 'little') for chunk in chunks)
        messages.append(data[:length].decode('ascii'))
    return messages


def resident_fields(f, expected):
    if expected is None:
        assert not any(f[f'resident.{n}.used'] for n in range(8))
        return {}
    assert f['autoload.phase'] == 4 and f['autoload.result'] == 0
    assert f['autoload.next'] == f['resource_clone.published_count'] == 1
    assert f['resident.0.id'] == expected['id']
    names = ('used', 'kind', 'failed', 'uncertain', 'allocation', 'allocation_bytes',
             'code_block', 'data_block', 'code_bytes', 'data_bytes', 'id')
    kept = {name: f['resident.0.' + name] for name in names}
    region = 0x200000
    assert kept['used'] == kept['kind'] == 1
    assert kept['failed'] == kept['uncertain'] == 0
    assert kept['allocation'] and kept['code_block'] and kept['data_block']
    assert kept['allocation_bytes'] in (2 * region + region // 2 - 1, 3 * region - 1)
    assert kept['code_bytes'] == kept['data_bytes'] == region
    assert kept['code_block'] % region == 0
    assert kept['data_block'] == kept['code_block'] + region
    assert kept['allocation'] <= kept['code_block']
    assert kept['data_block'] + region <= kept['allocation'] + kept['allocation_bytes']
    assert not any(f[f'resident.{n}.used'] for n in range(1, 8))
    return kept


def verify_card(card, case, destination):
    """Read actual stopped image contents, independently of its preparation receipt."""
    destination.mkdir(parents=True, exist_ok=False)
    actual = {row['path'] for row in catalog(card, 1048576)['files']
              if not row['directory'] and not Path(row['path']).name.startswith('._')
              and Path(row['path']).name != '.DS_Store'}
    expected = set(case['files'])
    if {name for name in actual if name.startswith('NLOADER/')} != expected:
        raise ValueError('Card files differ from declared case')
    records = []
    for n, (name, digest) in enumerate(case['files'].items()):
        record = extract(card, name, destination / f'file-{n}.bin')
        if record['sha256'] != digest:
            raise ValueError('Actual card bytes differ: ' + name)
        records.append(record)
    (destination / 'verified.json').write_text(json.dumps(records, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    for name in ('materials', 'delivery', 'spec', 'follow', 'card', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--case', required=True)
    parser.add_argument('--port', type=int, default=8782)
    args = parser.parse_args()
    materials = json.loads(args.materials.read_text())
    case = materials['cases'][args.case]
    program = materials['program']
    delivery = json.loads(args.delivery.read_text())
    evidence = json.loads(Path(delivery['acceptance']).read_text())
    assert delivery['mode'] == evidence['mode'] == 'exec'
    assert delivery['complete_independent_semantic_verification']
    assert evidence['patch_manifest_used_as_evidence'] is False
    assert evidence['two_builds_identical']
    assert hashlib.sha256(Path(delivery['eg']).read_bytes()).hexdigest() == delivery['eg_sha256'] == evidence['eg_sha256']
    for name, digest in case['files'].items():
        assert hashlib.sha256((Path(case['folder']) / name).read_bytes()).hexdigest() == digest
    if args.out.exists():
        raise FileExistsError(args.out)
    verify_card(args.card, case, args.out.with_name(args.out.name + '-preflight'))
    platform = ROOT / 'build/qemu-platform'
    command = [sys.executable, str(ROOT / 'tests/qemu/run.py'), '--stock-firmware',
               str(ROOT / 'firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi'),
               '--firmware', delivery['eg'], '--firmware-sha256', delivery['eg_sha256'],
               '--qemu', str(platform / 'qemu-build/qemu-system-aarch64'),
               '--raw', str(platform / 'liveview.raw'), '--card-template', str(args.card.resolve()),
               '--snapshot-spec', str(args.spec.resolve()), '--follow-spec', str(args.follow.resolve()),
               '--observe-live', '--output', str(args.out.resolve()), '--port', str(args.port), '--seconds', '1800']
    session, error, baseline = None, None, None
    attempts = []
    with args.out.with_name(args.out.name + '-driver.log').open('x') as log:
        runner = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 180
            while not (args.out / 'session.json').is_file():
                if runner.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('Owned session did not start')
                time.sleep(.2)
            session = NativeSession(args.out, 300)
            session.wait(lambda s: s.get('ready') and s.get('ui_mode') == 1 and
                         fields(s).get('autoload.phase') == 4)
            baseline = resident_fields(fields(session.get('/state')), case['resident'])
            session.capture('original-menu')
            session.buttons(['left', 'down', 'down', 'down', 'down', 'right', 'up', 'up'])
            if case['resident']:
                session.buttons(['up'])
            session.capture('setup-nloader')
            session.buttons(['ok'])
            session.capture('program-list')
            assert fields(session.get('/state'))['directory.count'] == (2 if case['resident'] else 1)
            for attempt in (1, 2):
                session.buttons(['ok'])
                before = fields(session.get('/state'))
                assert before['check_result'] == 0
                assert before['path'].endswith(program['declaration']['file'].replace('/', '\\'))
                for name in ('image_bytes', 'data_bytes', 'bss_bytes'):
                    assert before['load.' + name] == program[name]
                previous = before['trace']['count']
                session.capture(f'checked-{attempt}')
                session.buttons(['ok'], settle=3)
                state = session.wait(lambda s: fields(s)['load.state'] == 0 and
                                     any(row['tag'] == 'E' and row['sequence'] > previous
                                         for row in fields(s)['trace']['ordered']))
                completed = fields(state)
                assert completed['load.program.prepared'] == completed['load.program.entry_started'] == completed['load.program.returned'] == 1
                assert completed['load.program.exit_code'] == case['result']
                assert completed['load.last_result'] == (0 if case['result'] == 0 else -12)
                assert completed['text'] == case['text']
                assert completed['text.generation'] > before['text.generation']
                fresh = [row for row in completed['trace']['ordered'] if row['sequence'] > previous]
                for tag, value in [('g', ord('R')), ('h', case['result']),
                                   ('E', 0 if case['result'] == 0 else -12)]:
                    assert any(row['tag'] == tag and row['value'] == value for row in fresh), tag
                for name in ('code_allocation', 'data_allocation', 'api_active', 'api_file_used', 'permissions_touched', 'kept'):
                    assert completed['load.program.' + name] == 0, name
                assert all(completed[f'load.program.api_allocation.{n}'] == 0 for n in range(16))
                messages = logs(completed['trace'], previous)
                if case['result'] == 0:
                    summary = case['summary']
                    first = summary.get('first', {}).get('hash', 0)
                    last = summary.get('last', {}).get('hash', 0)
                    assert f'W {summary["count"]} {first:x} {last:x}' in messages, messages
                else:
                    assert f'wad rejected: {case["result"]}' in messages, messages
                session.capture(f'returned-{attempt}')
                session.buttons(['ok'])
                session.capture(f'visible-result-{attempt}')
                session.buttons(['left'])
                after = fields(session.get('/state'))
                assert after['detail_view'] == 0
                assert resident_fields(after, case['resident']) == baseline
                session.capture(f'list-after-{attempt}')
                attempts.append({'before': before, 'completed': completed, 'after': after, 'logs': messages})
            session.buttons(['down', 'up'])
            session.capture('list-navigation')
            session.buttons(['left'])
            session.capture('setup-after')
            if case['resident']:
                session.buttons(['down', 'down'])
                session.capture('resident-menu-item')
                session.buttons(['ok'])
                session.capture('resident-menu-item-after-ok')
                assert resident_fields(fields(session.get('/state')), case['resident']) == baseline
                session.buttons(['down'])
                session.capture('stock-navigation')
        except BaseException as exception:
            error = repr(exception)
            traceback.print_exc()
            if session:
                try:
                    session.capture('failure')
                except Exception:
                    # Preserve the original failure even if display capture
                    # is unavailable; owned-process cleanup still runs.
                    pass
        finally:
            if session:
                try:
                    (args.out / 'wad-acceptance.json').write_text(json.dumps({
                        'case': args.case, 'expected': case, 'attempts': attempts,
                        'baseline_resident': baseline, 'inputs': session.records, 'error': error,
                        'actual_pixel_review_required': True, 'synthetic_wad_only': True,
                        'game_playability_verified': False}, indent=2) + '\n')
                except Exception as exception:
                    error = error or 'Cannot preserve observations: ' + repr(exception)
                try:
                    session.post('/stop')
                except Exception as exception:
                    error = error or 'Owned stop failed: ' + repr(exception)
            try:
                runner.wait(timeout=45)
            except subprocess.TimeoutExpired:
                runner.terminate()
                runner.wait(timeout=30)
    result = json.loads((args.out / 'result.json').read_text())
    assert result['owned_qemu_stopped'], 'Owned QEMU did not stop'
    receipt = args.out / 'wad-acceptance.json'
    if receipt.is_file():
        acceptance = json.loads(receipt.read_text())
        acceptance['owned_qemu_stopped'] = True
        acceptance['runtime_checks_passed'] = not error and not runner.returncode and not result.get('error') and len(attempts) == 2
        acceptance['error'] = error or result.get('error')
        receipt.write_text(json.dumps(acceptance, indent=2) + '\n')
    if error or runner.returncode or result.get('error'):
        raise RuntimeError(f'{args.case}: {error}, runner {runner.returncode}, {result.get("error")}')
    print(json.dumps({'case': args.case, 'attempts': len(attempts), 'owned_qemu_stopped': True}))


if __name__ == '__main__':
    main()
