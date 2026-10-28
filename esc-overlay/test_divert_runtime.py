import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('divert_runtime', HERE / 'divert_runtime.py')
module = importlib.util.module_from_spec(spec)
if spec.loader is not None and (HERE / 'divert_runtime.py').exists():
    spec.loader.exec_module(module)


class DivertRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.vendor = self.root / 'lldap.distrib'
        self.vendor.write_text('trusted vendor')
        self.vendor.chmod(0o555)

    def tearDown(self):
        self.tmp.cleanup()

    def test_unit_contract_drift_preserves_current_package_and_marks_pending(self):
        with patch.object(module.contract, 'select_binary', side_effect=module.contract.ContractDrift('unit drift')):
            binary, status = module.select(self.root, self.vendor, 'new-version',
                                           owner_uid=os.getuid(), trust_root=self.root)
        self.assertEqual(binary, self.vendor)
        self.assertEqual(status['atomic_api'], 'PENDING')

    def test_package_or_ancestor_ownership_failure_is_never_fallback(self):
        self.vendor.chmod(0o777)
        with self.assertRaises(RuntimeError):
            module.select(self.root, self.vendor, 'new-version',
                          owner_uid=os.getuid(), trust_root=self.root)

    def test_argv_is_passed_through_exactly(self):
        supplied = ['run', '--config-file', '/new/package-config.toml', '--verbose']
        self.assertEqual(module.forward_argv(supplied), ['/usr/bin/lldap', *supplied])

    def test_unsafe_contract_failure_cannot_become_vendor_fallback(self):
        with patch.object(module.contract, 'select_binary', side_effect=RuntimeError('untrusted drop-in')):
            with self.assertRaises(RuntimeError):
                module.select(self.root, self.vendor, 'new-version',
                              owner_uid=os.getuid(), trust_root=self.root)

    def test_actual_writable_dropin_refuses_even_when_vendor_unit_changed(self):
        import hashlib
        import json
        unit = self.root / 'lldap.service'
        unit.write_text('[Service]\nExecStart=/usr/bin/lldap old-args\n')
        unit.chmod(0o644)
        candidate = self.root / 'lldap'
        candidate.write_bytes(b'reviewed candidate')
        candidate.chmod(0o555)
        dropins = self.root / 'dropins'
        dropins.mkdir(mode=0o755)
        dropins.chmod(0o755)
        config = {'format': 'lldap-esc-overlay-v1', 'baseline_package_version': '1',
                  'baseline_sha256': hashlib.sha256(self.vendor.read_bytes()).hexdigest(),
                  'artifact_sha256': hashlib.sha256(candidate.read_bytes()).hexdigest(),
                  'baseline_unit_sha256': hashlib.sha256(unit.read_bytes()).hexdigest(),
                  'baseline_dropins': {}}
        (self.root / 'deployment.json').write_text(json.dumps(config))
        (self.root / 'deployment.json').chmod(0o444)
        unit.write_text('[Service]\nExecStart=/usr/bin/lldap new-vendor-args\n')
        unsafe = dropins / 'unsafe.conf'
        unsafe.write_text('[Service]\nUser=foreign\n')
        unsafe.chmod(0o666)
        with self.assertRaises(module.contract.UnsafeContract):
            module.select(self.root, self.vendor, '2', owner_uid=os.getuid(),
                          trust_root=self.root, vendor_unit=unit, dropin_dirs=(dropins,))
