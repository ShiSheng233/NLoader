"""Host checks for a real read-only NVMe backend; no guest or device launch."""
from pathlib import Path
import subprocess
import sys
import unittest

from test_passive_stop import runner


class CardAccessTests(unittest.TestCase):
    def test_default_command_is_unchanged(self):
        self.assertEqual(runner.storage_devices(Path('/owned/card.raw'), 'nvme', 'normal'),
                         ['-drive', 'file=/owned/card.raw,if=none,id=card,format=raw',
                          '-device', 'nvme,drive=card,serial=NLOADER-QEMU,bus=dw-pcie,addr=0'])
        self.assertEqual(runner.storage_devices(None, 'nvme', 'absent'), [])

    def test_read_only_uses_normal_backend_option(self):
        command = runner.storage_devices(Path('/owned/card.raw'), 'nvme', 'normal', 'read-only')
        self.assertEqual(command[1], 'file=/owned/card.raw,if=none,id=card,format=raw,readonly=on')
        self.assertEqual(command[3], 'nvme,drive=card,serial=NLOADER-QEMU,bus=dw-pcie,addr=0')

    def test_unsupported_access_is_rejected_before_launch(self):
        for interface, state, access in [('sd', 'normal', 'read-only'),
                                         ('nvme', 'absent', 'read-only'),
                                         ('nvme', 'unpartitioned', 'read-only'),
                                         ('nvme', 'normal', 'unknown')]:
            with self.subTest(interface=interface, state=state, access=access):
                with self.assertRaises(ValueError):
                    runner.storage_devices(None, interface, state, access)
        common = ['--stock-firmware', '/missing-stock', '--firmware', '/missing-eg',
                  '--firmware-sha256', 'invalid', '--qemu', '/missing-qemu', '--raw', '/missing-raw',
                  '--output', '/missing-output', '--card-access', 'read-only']
        result = subprocess.run([sys.executable, str(Path(runner.__file__)), *common,
                                 '--card-state', 'absent'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Read-only diagnostics require a normal NVMe card', result.stderr)
        self.assertNotIn('missing-stock', result.stderr)

    def test_actual_qmp_identity_is_required(self):
        path = Path('/owned/card.raw')
        inserted = {'ro': True, 'drv': 'raw', 'file': str(path),
                    'image': {'filename': str(path), 'virtual-size': 8 * 1024**3}}
        blocks = [{'device': 'card', 'inserted': inserted}]
        self.assertTrue(runner.verify_read_only_backend(blocks, path)['verified'])
        for key, value in [('ro', False), ('ro', None), ('drv', 'qcow2'), ('file', '/other')]:
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    runner.verify_read_only_backend([{'device': 'card', 'inserted': {**inserted, key: value}}], path)
        for invalid in [[], blocks * 2, [{'device': 'other', 'inserted': inserted}],
                        [{'device': 'card', 'inserted': {**inserted, 'image': {}}}]]:
            with self.assertRaises(ValueError):
                runner.verify_read_only_backend(invalid, path)


if __name__ == '__main__':
    unittest.main()
