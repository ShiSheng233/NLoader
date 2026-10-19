#!/usr/bin/env python3
"""Verify the real active-service exit branch against a candidate-bound proof."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def registers(record):
    return {key: int(value, 16) for key, value in
            re.findall(r'\b(X\d\d|PC|SP)=([0-9a-fA-F]+)', record['registers'])}


def words(record, label):
    observed = record['reads'][label]
    assert 'error' not in observed
    data = Path(observed['file']).read_bytes()
    assert data.hex() == observed['hex']
    return struct.unpack('<' + 'I' * (len(data) // 4), data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--proof', type=Path, required=True)
    parser.add_argument('--points', type=Path, required=True)
    args = parser.parse_args()
    proof = json.loads(args.proof.read_text())
    result = json.loads((args.session / 'result.json').read_text())
    assert digest(proof['candidate']) == proof['candidate_sha256'] == result['firmware_sha256']
    assert digest(proof['full_receipt']) == proof['receipt_sha256']
    assert digest(args.points) == proof['points_file_sha256'] == result['passive_points_sha256']
    assert digest(proof['layout_source']) == proof['layout_sha256']
    assert digest(result['snapshot_spec']) == result['snapshot_spec_sha256']
    pinned_layout = json.loads(Path(proof['layout_source']).read_text())['layout']
    observed_layout = json.loads(Path(result['snapshot_spec']).read_text())['layout']
    assert observed_layout['size'] == pinned_layout['size']
    assert all(observed_layout['fields'].get(name) == declaration
               for name, declaration in pinned_layout['fields'].items())
    assert result['owned_qemu_stopped'] and not result.get('error')
    runtime = result['runtime_snapshot']
    assert runtime['found']
    address = int(runtime['address'], 16)
    events = result['passive_observations']
    labels = [event['label'] for event in events]
    required = ['api-exit-branch', 'api-resume-call', 'api-resume-return', 'api-service-end-exit']
    assert len(labels) == 4 and set(labels) == set(required)
    assert labels[0:2] == required[0:2]
    assert result['passive_unhit'] == ['forbidden-terminate']
    points = {point['label']: point for point in json.loads(args.points.read_text())}
    indexed = {event['label']: event for event in events}
    for event in events:
        assert event['registers_changed'] is False
        actual = registers(event)
        point = points[event['label']]
        assert actual['PC'] == int(point['address'], 16)
        assert set(event['reads']) == {item['label'] for item in point['reads']}
        for item in point['reads']:
            observed = event['reads'][item['label']]
            assert 'error' not in observed
            expected_address = (int(item['address'], 16) if 'address' in item else
                                actual[item['register']] + item['offset'])
            assert int(observed['address'], 16) == expected_address
            assert len(Path(observed['file']).read_bytes()) == item['length']
    first = indexed[required[0]]
    regs = registers(first)
    assert regs['X19'] == address and regs['X08'] & 0xffffffff > 0
    assert regs['X20'] == int(proof['exit_table']['address'], 16)
    assert words(first, 'load-state') == (2,)
    assert words(first, 'program-kind') == (2,)
    assert words(first, 'jump-armed') == (1,)
    active, stop = words(first, 'api-stop')
    assert active > 0 and stop == 1
    service_words = words(first, 'main-services')
    assert service_words[0] | service_words[1] << 32 == int(proof['exit_table']['main_services'], 16)
    called = registers(indexed[required[1]])
    assert called['X00'] == address and called['X08'] == proof['wrappers']['resume']['address']
    assert registers(indexed[required[2]])['X00'] & 0xffffffff == 0
    ended = indexed[required[3]]
    end_regs = registers(ended)
    # Derive the embedded program's location from the independently compiled layout.
    layout = pinned_layout['fields']
    program = address + layout['load.program.code_allocation']['offset']
    assert end_regs['X08'] == program
    assert end_regs['X00'] == program + 72 and end_regs['X01'] == 1
    assert words(ended, 'api-stop') == (0, 1)
    assert words(ended, 'exit-flags') == (1, 0, 1)
    final = runtime['fields']
    assert final['load.state'] == final['load.last_result'] == final['load.program.exit_code'] == 0
    assert final['load.program.returned'] == final['load.program.exit_requested'] == 1
    for name in ('api_active', 'api_file_used', 'code_allocation', 'data_allocation', 'permissions_touched', 'kept'):
        assert final['load.program.' + name] == 0
    for n in range(16):
        assert final[f'load.program.api_allocation.{n}'] == 0
    receipt = {'active_service_observed': True, 'resume_returned_successfully': True,
               'service_end_drained_then_exited': True, 'terminate_not_taken': True,
               'cleanup_verified': True, 'owned_qemu_stopped': True,
               'actual_exit_attempts_proven': 1, 'pixel_review_required': True,
               'proof_sha256': digest(args.proof), 'result_sha256': digest(args.session / 'result.json')}
    with (args.session / 'api-exit-branch-acceptance.json').open('x') as stream:
        stream.write(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
