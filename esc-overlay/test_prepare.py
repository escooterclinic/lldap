import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lldap_esc_prepare', HERE / 'prepare.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.artifact = self.root / 'reviewed-binary'
        self.artifact.write_bytes(b'reviewed binary bytes')
        self.digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.output = self.root / 'new-bundle'

    def tearDown(self):
        self.tmp.cleanup()

    def stage(self, digest=None):
        return prepare.prepare(self.output, self.artifact, digest or self.digest, '0.6.3', 'a' * 64, 'b' * 64, {})

    def test_bundle_has_fixed_owner_paths_and_no_activation(self):
        result = self.stage()
        self.assertTrue(result['staged_only'])
        base = Path('opt/lldap-esc/releases') / self.digest
        self.assertEqual((self.output / base / 'lldap').read_bytes(), self.artifact.read_bytes())
        conf = json.loads((self.output / base / 'deployment.json').read_text())
        self.assertEqual(conf['artifact_sha256'], self.digest)
        unit = self.output / 'etc/systemd/system/lldap.service.d/zz-esc-atomic-service-user.conf'
        self.assertEqual(unit.read_text(), '[Service]\nExecStart=\nExecStart=/usr/bin/python3 /' + str(base / 'runtime.py') + '\n')
        self.assertEqual(len(result['files']), 4)
        for entry in result['files']:
            self.assertEqual(prepare.sha(self.output / entry['path']), entry['sha256'])
        self.assertFalse((self.output / 'root/.ssh/authorized_keys').exists())

    def test_wrong_artifact_hash_writes_nothing(self):
        with self.assertRaises(ValueError):
            self.stage('b' * 64)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_not_adopted_or_overwritten(self):
        self.output.mkdir()
        existing = self.output / 'foreign'
        existing.write_text('preserve')
        with self.assertRaises(ValueError):
            self.stage()
        self.assertEqual(existing.read_text(), 'preserve')
        self.assertEqual(sorted(p.name for p in self.output.iterdir()), ['foreign'])

    def test_output_and_artifact_symlinks_are_refused(self):
        self.output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.stage()
        self.assertTrue(self.output.is_symlink())
        self.output.unlink()
        linked = self.root / 'linked'
        linked.symlink_to(self.artifact)
        self.artifact = linked
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_directory_modes_and_manifest_ignore_permissive_umask(self):
        old = os.umask(0)
        try:
            result = self.stage()
        finally:
            os.umask(old)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        directories = [path for path in self.output.rglob('*') if path.is_dir()]
        self.assertTrue(directories)
        for path in directories:
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        self.assertEqual({row['path'] for row in result['directories']},
                         {str(path.relative_to(self.output)) for path in directories})

    def test_symlink_staging_parent_is_refused(self):
        linked = self.root / 'linked-parent'
        linked.symlink_to(self.root, target_is_directory=True)
        self.output = linked / 'new-bundle'
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_diversion_bundle_keeps_vendor_unit_and_arguments_untouched(self):
        result = prepare.prepare(self.output, self.artifact, self.digest,
                                 '0.6.3', 'a' * 64, 'b' * 64, {}, package_diversion=True)
        self.assertFalse((self.output / 'etc').exists())
        self.assertEqual(len(result['files']), 5)
        wrapper = self.output / 'usr/bin/lldap'
        self.assertTrue(wrapper.read_text().startswith('#!/usr/bin/python3 -I\n'))
        self.assertNotIn('--config-file', wrapper.read_text())
