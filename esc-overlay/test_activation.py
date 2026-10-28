import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('activation', HERE / 'activate.py')
activation = importlib.util.module_from_spec(spec)
if (HERE / 'activate.py').exists():
    spec.loader.exec_module(activation)


class OwnedFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.path = self.root / 'owned'

    def tearDown(self):
        self.tmp.cleanup()

    def test_owned_unchanged_file_can_be_removed(self):
        record = activation.create_owned(self.path, b'owned bytes', 0o555)
        activation.remove_owned(self.path, record, os.getuid())
        self.assertFalse(self.path.exists())

    def test_changed_or_replaced_file_is_never_deleted(self):
        record = activation.create_owned(self.path, b'owned bytes', 0o555)
        self.path.chmod(0o755)
        self.path.write_bytes(b'foreign bytes')
        with self.assertRaises(RuntimeError):
            activation.remove_owned(self.path, record, os.getuid())
        self.assertEqual(self.path.read_bytes(), b'foreign bytes')

    def test_existing_file_or_symlink_is_not_adopted(self):
        self.path.symlink_to(self.root / 'outside')
        with self.assertRaises(FileExistsError):
            activation.create_owned(self.path, b'owned bytes', 0o555)
        self.assertTrue(self.path.is_symlink())

    def test_postgres_backup_requires_explicit_retention_and_hides_credentials(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        backup = self.root / 'snapshot.pgcustom'
        url = 'postgresql://fixture-user:fixture-secret@fixture.invalid:5433/lldap'
        with self.assertRaises(ValueError):
            activation.backup_postgres(url, backup, '')
        self.assertFalse(backup.exists())
        calls = []

        def execute(arguments, **options):
            calls.append((arguments, options))
            if arguments[0] == '/usr/bin/pg_dump':
                self.assertNotIn('fixture-secret', str(arguments))
                self.assertEqual(options['env']['PGPASSWORD'], 'fixture-secret')
                os.write(options['pass_fds'][0], b'fixture pg custom archive')
            return SimpleNamespace(returncode=0, stdout=b'fixture archive table list')

        with patch.object(activation.subprocess, 'run', side_effect=execute):
            receipt = activation.backup_postgres(url, backup, '2026-11-30T14:00:00+00:00')
        self.assertEqual(len(calls), 2)
        self.assertEqual(receipt['format'], 'postgresql-custom')
        self.assertFalse(receipt['automatic_cleanup'])
        self.assertNotIn('fixture-secret', str(receipt))
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)

    def test_interruption_failure_restores_baseline_package_and_availability(self):
        from unittest.mock import patch
        package = self.root / 'package'
        vendor = self.root / 'vendor'
        package.write_bytes(b'original vendor')
        package.chmod(0o555)
        receipt = self.root / 'receipt.json'
        events = []
        active = True

        def control(*arguments):
            nonlocal active
            events.append(arguments)
            if arguments == ('stop',):
                active = False
            if arguments == ('start',):
                active = True
            if arguments == ('is-active',):
                return 'active' if active else 'inactive'
            return ''

        def divert(operation):
            events.append(('diversion', operation))
            if operation == 'add':
                package.rename(vendor)
            else:
                vendor.rename(package)

        with patch.multiple(activation, PACKAGE=package, DIVERTED=vendor), \
             patch.object(activation, 'preflight', return_value=(
                 {Path('usr/bin/lldap'): (b'wrapper', 0o555)}, Path('release'), 'postgresql://fixture')), \
             patch.object(activation, 'ensure_directory'), \
             patch.object(activation, 'systemctl', side_effect=control), \
             patch.object(activation, 'backup_postgres', return_value={'fixture': True}), \
             patch.object(activation, 'change_diversion', side_effect=divert), \
             patch.object(activation, 'diversion_owned', return_value=True), \
             patch.object(activation.contract, 'trusted_ancestors'), \
             patch.object(activation, 'create_owned', side_effect=OSError('injected wrapper write failure')):
            with self.assertRaisesRegex(OSError, 'injected wrapper'):
                activation.activate(self.root, 'a' * 64, self.root / 'config', self.root / 'backup',
                                    '2026-11-30T14:00:00+00:00', receipt_path=receipt)
        self.assertEqual(package.read_bytes(), b'original vendor')
        self.assertFalse(vendor.exists())
        self.assertTrue(active)
        self.assertIn(('unmask', '--runtime'), events)

    def test_rollback_refuses_changed_wrapper_before_interrupting(self):
        from unittest.mock import patch
        package = self.root / 'package'
        vendor = self.root / 'vendor'
        vendor.write_bytes(b'vendor')
        vendor.chmod(0o555)
        record = activation.create_owned(package, b'wrapper', 0o555)
        package.chmod(0o755)
        package.write_bytes(b'foreign')
        receipt = {'format': 'lldap-diversion-owner-v1', 'diversion_added': True,
                   'files': {str(package): record}}
        with patch.multiple(activation, PACKAGE=package, DIVERTED=vendor), \
             patch.object(activation, 'diversion_owned', return_value=True):
            with self.assertRaises(RuntimeError):
                activation.rollback_preflight(receipt, os.getuid())
        self.assertEqual(package.read_bytes(), b'foreign')
