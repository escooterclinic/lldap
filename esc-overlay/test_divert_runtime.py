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
        with patch.object(module.contract, 'select_binary', side_effect=RuntimeError('unit drift')):
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
