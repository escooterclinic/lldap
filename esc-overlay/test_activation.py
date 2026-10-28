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

    def test_bundle_refuses_special_or_writable_manifest_modes(self):
        import hashlib
        import json
        spec = importlib.util.spec_from_file_location('fixture_prepare', HERE / 'prepare.py')
        preparation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preparation)
        artifact = self.root / 'candidate'
        artifact.write_bytes(b'reviewed fixture')
        artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        bundle = self.root / 'bundle'
        preparation.prepare(bundle, artifact, artifact_digest, '1', 'a' * 64,
                            'b' * 64, {}, package_diversion=True)
        path = bundle / 'manifest.json'
        digest = lambda: hashlib.sha256(path.read_bytes()).hexdigest()
        options = {'owner_uid': os.getuid(), 'trust_root': self.root}
        activation.read_bundle(bundle, digest(), **options)
        manifest = json.loads(path.read_text())
        manifest['files'][0]['mode'] = '4555'
        path.chmod(0o644)
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(RuntimeError, 'Manifest mode'):
            activation.read_bundle(bundle, digest(), **options)

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
            activation.backup_postgres(url, backup, '', journal=lambda entry: None)
        self.assertFalse(backup.exists())
        calls = []

        def execute(arguments, **options):
            calls.append((arguments, options))
            if arguments[0].endswith('/pg_dump'):
                self.assertNotIn('fixture-secret', str(arguments))
                self.assertEqual(options['env']['PGPASSWORD'], 'fixture-secret')
                os.write(options['pass_fds'][0], b'fixture pg custom archive')
            return SimpleNamespace(returncode=0, stdout=b'fixture archive table list')

        with patch.object(activation.subprocess, 'run', side_effect=execute):
            receipt = activation.backup_postgres(url, backup, '2026-11-30T14:00:00+00:00', journal=lambda entry: None)
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

    def test_failure_after_candidate_start_stops_it_before_vendor_restore(self):
        from unittest.mock import patch
        package = self.root / 'package'
        vendor = self.root / 'vendor'
        package.write_bytes(b'vendor')
        package.chmod(0o555)
        state = self.root / 'receipt.json'
        running = 'vendor'
        real_save = activation.save_receipt
        real_remove = activation.remove_owned

        def control(*arguments):
            nonlocal running
            if arguments == ('stop',):
                running = None
            if arguments == ('start',) and running is None:
                running = 'candidate' if package.read_bytes() == b'wrapper' else 'vendor'
            return 'active' if running else 'inactive'

        def divert(operation):
            if operation == 'add':
                package.rename(vendor)
            else:
                vendor.rename(package)

        def save(path, receipt):
            if receipt['state'] == 'active_pending_authenticated_controls':
                raise OSError('injected final receipt failure')
            real_save(path, receipt)

        with patch.multiple(activation, PACKAGE=package, DIVERTED=vendor), \
             patch.object(activation, 'preflight', return_value=(
                 {Path('usr/bin/lldap'): (b'wrapper', 0o555)}, Path('release'), 'postgresql://fixture')), \
             patch.object(activation, 'ensure_directory'), \
             patch.object(activation, 'systemctl', side_effect=control), \
             patch.object(activation, 'backup_postgres', return_value={'fixture': True}), \
             patch.object(activation, 'change_diversion', side_effect=divert), \
             patch.object(activation, 'diversion_owned', return_value=True), \
             patch.object(activation.contract, 'trusted_ancestors'), \
             patch.object(activation, 'remove_owned', side_effect=lambda path, record: real_remove(path, record, os.getuid())), \
             patch.object(activation, 'save_receipt', side_effect=save):
            with self.assertRaisesRegex(OSError, 'injected final receipt'):
                activation.activate(self.root, 'a' * 64, self.root / 'config', self.root / 'backup',
                                    '2026-11-30T14:00:00+00:00', receipt_path=state)
        self.assertEqual(running, 'vendor')

    def test_native_config_uses_declared_service_owner_and_refuses_writable_parent(self):
        config = self.root / 'lldap_config.toml'
        config.write_bytes(b'fixture native configuration')
        config.chmod(0o600)
        self.assertEqual(activation.native_config_bytes(config, os.getuid(), self.root),
                         b'fixture native configuration')
        self.root.chmod(0o777)
        with self.assertRaises(RuntimeError):
            activation.native_config_bytes(config, os.getuid(), self.root)
        self.root.chmod(0o700)
        config.unlink()
        config.symlink_to(self.root / 'other')
        with self.assertRaises(OSError):
            activation.native_config_bytes(config, os.getuid(), self.root)

    def test_failed_dump_and_readback_retain_positive_partial_backup_receipt(self):
        import hashlib
        from types import SimpleNamespace
        from unittest.mock import patch
        for failure in ('pg_dump', 'pg_restore'):
            with self.subTest(failure=failure):
                backup = self.root / (failure + '.pgcustom')
                journal = []

                def execute(arguments, **options):
                    if arguments[0].endswith('/pg_dump'):
                        self.assertTrue(journal, 'Sensitive dump bytes require a prior durable owner receipt')
                        self.assertEqual(journal[-1]['status'], 'incomplete_dump')
                        self.assertEqual(journal[-1]['identity']['inode'], backup.stat().st_ino)
                        os.write(options['pass_fds'][0], b'partial retained archive')
                    failed = arguments[0].endswith('/' + failure)
                    return SimpleNamespace(returncode=int(failed), stdout=b'fixture archive list')

                with patch.object(activation.subprocess, 'run', side_effect=execute):
                    with self.assertRaises(RuntimeError):
                        activation.backup_postgres('postgresql://fixture@host/db', backup,
                                                   '2026-11-30T14:00:00+00:00', journal=journal.append)
                self.assertTrue(backup.exists())
                self.assertEqual(journal[-1]['status'], 'failed_' + ('dump' if failure == 'pg_dump' else 'readback'))
                self.assertEqual(journal[-1]['sha256'], hashlib.sha256(backup.read_bytes()).hexdigest())
                self.assertEqual(journal[-1]['identity']['inode'], backup.stat().st_ino)
                self.assertEqual(journal[-1]['retain_until'], '2026-11-30T14:00:00+00:00')
