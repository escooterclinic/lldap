import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lldap_esc_runtime', HERE / 'runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class RuntimeSelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.release = self.root / 'release'
        self.release.mkdir()
        self.package = self.root / 'package'
        self.package.write_bytes(b'current vendor package')
        self.package.chmod(0o555)
        self.candidate = self.release / 'lldap'
        self.candidate.write_bytes(b'reviewed fork')
        self.candidate.chmod(0o555)
        self.config = {'format':'lldap-esc-overlay-v1', 'baseline_package_version':'0.6.3',
                       'baseline_sha256':hashlib.sha256(self.package.read_bytes()).hexdigest(),
                       'artifact_sha256':hashlib.sha256(self.candidate.read_bytes()).hexdigest()}
        self.save()

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        (self.release / 'deployment.json').write_text(json.dumps(self.config))
        (self.release / 'deployment.json').chmod(0o644)

    def select(self, version='0.6.3'):
        return runtime.select_binary(self.release, self.package, version, owner_uid=os.getuid())

    def test_reviewed_matching_artifact_is_selected_without_global_readiness_claim(self):
        binary, status = self.select()
        self.assertEqual(binary, self.candidate)
        self.assertEqual(status['atomic_api'], 'PENDING_LIVE_PROOF')

    def test_vendor_upgrade_preserves_new_package_and_marks_atomic_api_pending(self):
        binary, status = self.select('0.6.4')
        self.assertEqual(binary, self.package)
        self.assertEqual(status['atomic_api'], 'PENDING')
        self.package.chmod(0o755)
        self.package.write_bytes(b'new package bytes')
        binary, status = self.select()
        self.assertEqual(binary, self.package)
        self.assertEqual(status['atomic_api'], 'PENDING')

    def test_untrusted_symlink_or_changed_artifact_never_runs(self):
        self.candidate.chmod(0o755)
        self.candidate.write_bytes(b'tampered candidate')
        self.assertEqual(self.select()[0], self.package)
        self.candidate.unlink()
        self.candidate.symlink_to(self.package)
        self.assertEqual(self.select()[0], self.package)

    def test_unknown_config_fields_do_not_select_caller_chosen_executable(self):
        self.config['binary'] = '/untrusted/executable'
        self.save()
        self.assertEqual(self.select()[0], self.package)

    def test_writable_config_or_artifact_is_not_trusted(self):
        (self.release / 'deployment.json').chmod(0o666)
        self.assertEqual(self.select()[0], self.package)
        (self.release / 'deployment.json').chmod(0o644)
        self.candidate.chmod(0o777)
        self.assertEqual(self.select()[0], self.package)

    def test_runtime_argv_preserves_fixed_native_operation(self):
        self.assertEqual(runtime.argv(self.candidate),
                         [str(self.candidate),'run','--config-file','/etc/lldap/lldap_config.toml'])
