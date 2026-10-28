import hashlib
import importlib.util
import json
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
        self.root = Path(self.tmp.name)
        self.artifact = self.root / 'reviewed-binary'
        self.artifact.write_bytes(b'reviewed binary bytes')
        self.digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.output = self.root / 'new-bundle'

    def tearDown(self):
        self.tmp.cleanup()

    def stage(self, digest=None):
        return prepare.prepare(self.output, self.artifact, digest or self.digest, '0.6.3', 'a' * 64)

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
