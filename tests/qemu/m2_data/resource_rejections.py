#!/usr/bin/env python3
"""Verify preboot resource refusals through real storage and native menus."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
import traceback
import zlib

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tests/qemu'))
sys.path.insert(0, str(ROOT / 'z8-qemu/tools'))
from scenario import NativeSession
from extract_card_file import extract
from inspect_card_volume import catalog


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fields(state):
    observed = state.get('runtime_snapshot', {})
    return observed.get('fields', {}) if observed.get('found') else {}


def native(state):
    observed = state['runtime_snapshot']['followed']
    assert observed['found']
    return observed['fields']


def verify(state, expectation, baseline=False):
    f, n = fields(state), native(state)
    for key, value in expectation['runtime'].items():
        if key == 'load.last_result' and not baseline:
            continue  # Later native directory inspection can replace this load result.
        assert f[key] == value, (key, f[key], value)
    for key, value in expectation.get('native_fields', {}).items():
        assert n[key] == value, (key, n[key], value)
    assert f['load.state'] == f['resource_clone.published_count'] == 0
    for key in ('load.program_attempted', 'load.probe_attempted', 'load.program.entry_started',
                'load.program.returned', 'load.probe.entry_started', 'load.probe.returned',
                'load.program.code_allocation', 'load.program.data_allocation', 'load.probe.allocation'):
        assert f[key] == 0, key
    assert all(f[f'resident.{i}.used'] == 0 for i in range(8))
    assert all(f[f'menu_registration.{i}.state'] == 0 for i in range(8))
    assert f['trace']['all_retained_sequences_match']
    assert not any(row['tag'] in ('g', 'h', 'p', 'x') for row in f['trace']['ordered'])


def decode_record(data):
    assert len(data) == 4096 and data[:8] == b'NLRSTAT1'
    version, length, generation, pending, count, checksum = struct.unpack_from('<IIQIII', data, 8)
    # Format 2 (PLAN 6.2, 2026-10-17) adds the boot record; these cases never
    # name a boot program, so it must be empty in either format.
    assert version in (1, 2) and length == 4096 and generation and pending in (0, 1) and count <= 64
    copy = bytearray(data)
    copy[32:36] = bytes(4)
    assert zlib.crc32(copy) == checksum
    assert not any(data[36:64]) and not any(data[64 + 64 * 33:])
    ids = []
    for index in range(64):
        value = data[64 + index * 33:64 + (index + 1) * 33]
        if index >= count:
            assert not any(value)
            continue
        name, separator, padding = value.partition(b'\0')
        assert separator and re.fullmatch(rb'[!-~]{1,32}', name) and not any(padding)
        ids.append(name.decode('ascii'))
    assert len(set(name.lower() for name in ids)) == len(ids)
    return {'generation': generation, 'pending': pending, 'ids': ids}


def main():
    parser = argparse.ArgumentParser()
    for name in ('expectations', 'images', 'case-files', 'delivery', 'spec', 'follow', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--case', required=True)
    parser.add_argument('--port', type=int, default=8782)
    args = parser.parse_args()
    expectations = json.loads(args.expectations.read_text())
    assert digest(args.case_files) == expectations['catalog_sha256']
    assert all(digest(ROOT / name) == sha for name, sha in expectations['source_sha256'].items())
    expectation = next(row for row in expectations['cases'] if row['case'] == args.case)
    input_case = next(row for row in json.loads(args.case_files.read_text()) if row['case'] == args.case)
    card = Path(next(row for row in json.loads(args.images.read_text()) if row['case'] == args.case)['image'])
    delivery = json.loads(args.delivery.read_text())
    evidence = json.loads(Path(delivery['acceptance']).read_text())
    assert delivery['mode'] == evidence['mode'] == 'exec'
    assert digest(delivery['eg']) == delivery['eg_sha256'] == evidence['eg_sha256']
    assert delivery['eg_sha256'] == expectations['candidate_sha256']
    assert delivery['complete_independent_semantic_verification'] and evidence['patch_manifest_used_as_evidence'] is False
    for key in ('official_stock_identity_verified', 'non_eg_modules_unchanged', 'container_crc_header_verified',
                'two_builds_identical', 'profile_against_official_firmware_verified'):
        assert evidence[key] is True
    if args.out.exists():
        raise FileExistsError(args.out)
    audited = args.out.with_name(args.out.name + '-card-inputs')
    audited.mkdir()
    rows = {row['path']: row for row in catalog(card, 1048576)['files']
            if row['path'].startswith('NLOADER/') and not row['directory']
            and not any(part.startswith('._') for part in Path(row['path']).parts)}
    assert set(rows) == set(input_case['files'])
    for name, sha in input_case['files'].items():
        assert digest(Path(input_case['folder']) / name) == sha
        row = rows[name]
        assert row['bytes'] == row['valid_bytes']
        if not row['bytes']:
            assert sha == hashlib.sha256(b'').hexdigest()
        else:
            extracted = audited / name.replace('/', '-')
            assert extract(card, name, extracted)['sha256'] == sha
    platform = ROOT / 'build/qemu-platform'
    command = [sys.executable, str(ROOT / 'tests/qemu/run.py'), '--stock-firmware',
               str(ROOT / 'firmware/unpacked/Z_8_0311/modules/eg2070_0311b0.bi'),
               '--firmware', delivery['eg'], '--firmware-sha256', delivery['eg_sha256'],
               '--qemu', str(platform / 'qemu-build/qemu-system-aarch64'), '--raw', str(platform / 'liveview.raw'),
               '--card-template', str(card), '--snapshot-spec', str(args.spec.resolve()),
               '--follow-spec', str(args.follow.resolve()), '--observe-live', '--output', str(args.out.resolve()),
               '--port', str(args.port), '--seconds', '600']
    session, error, snapshots = None, None, []
    with args.out.with_name(args.out.name + '-driver.log').open('x') as log:
        runner = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 180
            while not (args.out / 'session.json').exists():
                if runner.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('No owned session')
                time.sleep(.2)
            session = NativeSession(args.out, 300)
            state = session.wait(lambda s: s.get('ready') and fields(s).get('autoload.phase') in (4, 5))
            verify(state, expectation, baseline=True)
            saved = native(state)['current.state_bytes']
            snapshots.append(state)
            session.capture('initial-refusal')
            session.buttons(['left', 'down', 'down', 'down', 'down', 'right', 'up', 'up'])
            session.capture('setup-before')
            session.buttons(['ok'])
            session.capture('refusal-page')
            state = session.get('/state')
            verify(state, expectation)
            snapshots.append(state)
            if fields(state)['recovery_view']:
                session.buttons(['left'])
                session.capture('list-without-recovery')
                assert fields(session.get('/state'))['recovery_view'] == 0
            session.buttons(['left'])
            session.capture('setup-after')
            state = session.get('/state')
            verify(state, expectation)
            assert native(state)['current.state_bytes'] == saved
            assert fields(state)['autoload.recovery_armed'] == 0
            snapshots.append(state)
        except BaseException as exception:
            error = repr(exception)
            traceback.print_exc()
        finally:
            if session:
                (args.out / 'refusal-inputs.json').write_text(json.dumps({'case': args.case, 'expectation': expectation,
                    'snapshots': snapshots, 'inputs': session.records, 'error': error,
                    'pixel_review_required': True}, indent=2) + '\n')
                try:
                    session.post('/stop')
                except Exception as exception:
                    error = error or repr(exception)
            try:
                runner.wait(timeout=45)
            except subprocess.TimeoutExpired:
                runner.terminate()
                runner.wait(timeout=30)
    if error or runner.returncode:
        raise RuntimeError(f'{args.case}: {error}; runner {runner.returncode}')
    result = json.loads((args.out / 'result.json').read_text())
    assert result['owned_qemu_stopped'] and not result.get('error')
    actual = [row for row in catalog(args.out / 'card.raw', 1048576)['files'] if row['path'] == 'NLOADER/STATE.NLS']
    journal = expectation['journal']
    if journal['mode'] == 'absent':
        assert not actual
        journal_result = {'absent': True}
    else:
        target = args.out / 'actual-STATE.NLS'
        extracted = extract(args.out / 'card.raw', 'NLOADER/STATE.NLS', target)
        data = target.read_bytes()
        assert len(data) == journal['bytes'] and extracted['sha256'] == journal['sha256']
        if journal['mode'] == 'unchanged':
            assert data == (Path(input_case['folder']) / 'NLOADER/STATE.NLS').read_bytes()
            journal_result = {'unchanged': True, 'sha256': extracted['sha256']}
        else:
            assert journal['mode'] == 'records' and len(data) == 8192
            records = [decode_record(data[n:n + 4096]) for n in (0, 4096) if any(data[n:n + 4096])]
            assert records == journal['records'], (records, journal['records'])
            journal_result = {'records': records, 'sha256': extracted['sha256']}
    (args.out / 'journal-verification.json').write_text(json.dumps(journal_result, indent=2) + '\n')
    print(json.dumps({'case': args.case, 'refused_without_entry': True, 'journal_verified': True,
                      'owned_qemu_stopped': True, 'pixel_review_required': True}))


if __name__ == '__main__':
    main()
