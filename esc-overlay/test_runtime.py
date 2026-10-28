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
        self.root = Path(self.tmp.name).resolve()
        self.release = self.root / 'release'
        self.release.mkdir()
        self.release.chmod(0o755)
        self.unit = self.root / 'lldap.service'
        self.unit.write_text('[Service]\nExecStart=/usr/bin/lldap run --config-file /etc/lldap/lldap_config.toml\n')
        self.unit.chmod(0o644)
        self.dropins = self.root / 'dropins'
        self.dropins.mkdir(mode=0o755)
        self.dropins.chmod(0o755)
        self.dropin = self.dropins / 'override.conf'
        self.dropin.write_text('[Service]\nUser=lldap\n')
        self.dropin.chmod(0o644)
        self.package = self.root / 'package'
        self.package.write_bytes(b'current vendor package')
        self.package.chmod(0o555)
        self.candidate = self.release / 'lldap'
        self.candidate.write_bytes(b'reviewed fork')
        self.candidate.chmod(0o555)
        self.config = {'format':'lldap-esc-overlay-v1', 'baseline_package_version':'0.6.3',
                       'baseline_sha256':hashlib.sha256(self.package.read_bytes()).hexdigest(),
                       'baseline_dropins':{str(self.dropin): hashlib.sha256(self.dropin.read_bytes()).hexdigest()},
                       'baseline_unit_sha256':hashlib.sha256(self.unit.read_bytes()).hexdigest(),
                       'artifact_sha256':hashlib.sha256(self.candidate.read_bytes()).hexdigest()}
        self.save()

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        (self.release / 'deployment.json').write_text(json.dumps(self.config))
        (self.release / 'deployment.json').chmod(0o644)

    def select(self, version='0.6.3'):
        return runtime.select_binary(self.release, self.package, version, owner_uid=os.getuid(), vendor_unit=self.unit, trust_root=self.root, dropin_dirs=(self.dropins,))

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
        with self.assertRaises(RuntimeError):
            self.select()
        (self.release / 'deployment.json').chmod(0o644)
        self.candidate.chmod(0o777)
        self.assertEqual(self.select()[0], self.package)

    def test_runtime_argv_preserves_fixed_native_operation(self):
        self.assertEqual(runtime.argv(self.candidate),
                         [str(self.candidate),'run','--config-file','/etc/lldap/lldap_config.toml'])

    def test_unit_drift_refuses_even_package_fallback(self):
        self.unit.write_text('[Service]\nExecStart=/usr/bin/lldap different-command\n')
        with self.assertRaises(RuntimeError):
            self.select('0.6.4')

    def test_writable_or_symlink_ancestor_refuses_execution(self):
        self.root.chmod(0o777)
        with self.assertRaises(RuntimeError):
            self.select()
        self.root.chmod(0o700)
        real = self.root / 'real-release'
        self.release.rename(real)
        self.release.symlink_to(real, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            self.select()

    def test_dropin_addition_removal_and_content_drift_refuse_execution(self):
        addition = self.dropins / 'new.conf'
        addition.write_text('[Service]\nUser=other\n')
        addition.chmod(0o644)
        with self.assertRaises(RuntimeError):
            self.select('0.6.4')
        addition.unlink()
        original = self.dropin.read_bytes()
        self.dropin.write_text('[Service]\nUser=other\n')
        with self.assertRaises(RuntimeError):
            self.select()
        self.dropin.unlink()
        with self.assertRaises(RuntimeError):
            self.select()
        self.dropin.write_bytes(original)
        self.dropin.chmod(0o644)
        self.assertEqual(self.select()[0], self.candidate)
