import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('expiry', Path(__file__).with_name('expire_backup.py'))
expiry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(expiry)


class ExpirationTests(unittest.TestCase):
    def test_expired_owned_backup_fires_and_refuses_foreign_or_early(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / 'backup.pgcustom'
            receipt = root / 'receipt.json'
            backup.write_bytes(b'isolated sensitive fixture')
            backup.chmod(0o600)
            deadline = '2000-01-01T00:00:00Z'
            entry = {'format': 'lldap-diversion-owner-v1', 'backup': {
                'path': str(backup), 'identity': expiry.identity(backup),
                'retain_until': deadline, 'format': 'postgresql-custom', 'status': 'verified'}}
            receipt.write_text(json.dumps(entry)); receipt.chmod(0o600)
            def invoke():
                return expiry.expire(receipt, backup, deadline, owner_uid=os.getuid(), trust_root=root)
            with patch.object(expiry, 'now_utc', return_value=expiry.parse_time('1999-01-01T00:00:00Z')):
                with self.assertRaises(RuntimeError):
                    invoke()
            self.assertTrue(backup.exists())
            for change in ('inode', 'hash', 'receipt', 'record'):
                saved = backup.read_bytes()
                if change == 'inode':
                    old = root / 'old'; backup.rename(old); backup.write_bytes(saved); backup.chmod(0o600)
                elif change == 'hash':
                    backup.write_bytes(b'foreign change')
                elif change == 'receipt':
                    receipt.chmod(0o666)
                else:
                    foreign = dict(entry); foreign['format'] = 'foreign-receipt'
                    receipt.write_text(json.dumps(foreign))
                with self.assertRaises(RuntimeError):
                    invoke()
                self.assertTrue(backup.exists())
                if change == 'inode':
                    backup.unlink(); old.rename(backup)
                elif change == 'hash':
                    backup.write_bytes(saved)
                elif change == 'receipt':
                    receipt.chmod(0o600)
                else:
                    receipt.write_text(json.dumps(entry))
            result = invoke()
            self.assertFalse(backup.exists())
            self.assertEqual(result['state'], 'expired_owned_backup_deleted')
            self.assertEqual(json.loads(receipt.read_text())['backup']['status'], 'expired_deleted')

    def test_native_verified_and_partial_receipts_expire(self):
        for status in ('verified', 'incomplete_dump', 'incomplete_readback', 'failed_dump', 'failed_readback'):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                backup = root / 'owned.pgcustom'
                backup.write_bytes(b'owned partial or complete fixture')
                backup.chmod(0o600)
                receipt = root / 'receipt.json'
                receipt.write_text(json.dumps({'format': 'lldap-diversion-owner-v1', 'backup': {
                    'path': str(backup), 'identity': expiry.identity(backup),
                    'retain_until': '2000-01-01T00:00:00Z', 'format': 'postgresql-custom', 'status': status}}))
                receipt.chmod(0o600)
                expiry.expire(receipt, backup, '2000-01-01T00:00:00Z', owner_uid=os.getuid(), trust_root=root)
                self.assertFalse(backup.exists())


    def test_post_unlink_save_failure_retains_durable_intent_and_reconciles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / 'owned.pgcustom'
            backup.write_bytes(b'owned archive')
            backup.chmod(0o600)
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps({'format': 'lldap-diversion-owner-v1', 'backup': {
                'path': str(backup), 'identity': expiry.identity(backup),
                'retain_until': '2000-01-01T00:00:00Z', 'format': 'postgresql-custom', 'status': 'verified'}}))
            receipt.chmod(0o600)
            save = expiry.save_receipt
            def fail_final(path, value):
                if value['backup']['status'] == 'expired_deleted':
                    raise OSError('injected final receipt failure')
                save(path, value)
            def invoke():
                return expiry.expire(receipt, backup, '2000-01-01T00:00:00Z', owner_uid=os.getuid(), trust_root=root)
            with patch.object(expiry, 'save_receipt', side_effect=fail_final):
                with self.assertRaises(RuntimeError):
                    invoke()
            self.assertFalse(backup.exists())
            pending = json.loads(receipt.read_text())['backup']
            self.assertEqual(pending['status'], 'expiration_pending')
            self.assertEqual(pending['expiration']['target']['path'], str(backup))
            with patch.object(expiry.os, 'unlink', wraps=os.unlink) as unlink:
                result = invoke()
                self.assertEqual(unlink.call_count, 0)
            self.assertEqual(result['state'], 'expired_owned_backup_deleted')
            self.assertEqual(json.loads(receipt.read_text())['backup']['status'], 'expired_deleted')


    def test_post_unlink_directory_fsync_faults_reconcile_without_second_unlink(self):
        for fail_at in (3, 5):
            with self.subTest(fsync=fail_at), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                backup = root / 'owned.pgcustom'
                backup.write_bytes(b'owned archive')
                backup.chmod(0o600)
                receipt = root / 'receipt.json'
                receipt.write_text(json.dumps({'format': 'lldap-diversion-owner-v1', 'backup': {
                    'path': str(backup), 'identity': expiry.identity(backup),
                    'retain_until': '2000-01-01T00:00:00Z', 'format': 'postgresql-custom', 'status': 'verified'}}))
                receipt.chmod(0o600)
                fsync = os.fsync
                calls = []
                def fault(descriptor):
                    calls.append(descriptor)
                    if len(calls) == fail_at:
                        raise OSError('injected post-unlink directory fsync failure')
                    return fsync(descriptor)
                def invoke():
                    return expiry.expire(receipt, backup, '2000-01-01T00:00:00Z', owner_uid=os.getuid(), trust_root=root)
                with patch.object(expiry.os, 'fsync', side_effect=fault):
                    with self.assertRaisesRegex(RuntimeError, 'operation_id='):
                        invoke()
                self.assertFalse(backup.exists())
                journal = json.loads(receipt.read_text())['backup']
                self.assertIn(journal['status'], ('expiration_pending', 'expired_deleted'))
                self.assertEqual(journal['expiration']['target']['path'], str(backup))
                with patch.object(expiry.os, 'unlink', wraps=os.unlink) as unlink:
                    invoke()
                    self.assertEqual(unlink.call_count, 0)
                self.assertEqual(json.loads(receipt.read_text())['backup']['status'], 'expired_deleted')


class TimerTests(unittest.TestCase):
    def test_single_utc_event_and_no_other_command(self):
        timer_spec = importlib.util.spec_from_file_location('units', Path(__file__).with_name('render_expiration_units.py'))
        units = importlib.util.module_from_spec(timer_spec)
        timer_spec.loader.exec_module(units)
        service, timer = units.render(Path('/opt/owned/expire_backup.py'), Path('/var/lib/owned/receipt.json'),
                                      Path('/root/owned.pgcustom'), '2026-11-03T14:00:00Z')
        self.assertEqual(timer.count('OnCalendar='), 1)
        self.assertIn('OnCalendar=2026-11-03 14:00:00 UTC\n', timer)
        self.assertIn('Persistent=true\n', timer)
        self.assertEqual(service.count('ExecStart='), 1)
        self.assertNotIn('OnUnitActiveSec', timer)
        with self.assertRaises(ValueError):
            units.render(Path('/opt/owned/e.py'), Path('/root/r'), Path('/root/b'), '2026-11-03 14:00:00+00:00')
        with self.assertRaises(ValueError):
            units.render(Path('/opt/evil%name'), Path('/root/r'), Path('/root/b'), '2026-11-03T14:00:00Z')


if __name__ == '__main__':
    unittest.main()
