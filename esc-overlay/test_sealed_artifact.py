import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('sealed_artifact', HERE / 'preflight_artifact.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class SealedArtifactTests(unittest.TestCase):
    def test_kernel_seals_hold_when_python_does_not_export_constants(self):
        names = ('F_ADD_SEALS', 'F_GET_SEALS', 'F_SEAL_SEAL', 'F_SEAL_SHRINK',
                 'F_SEAL_GROW', 'F_SEAL_WRITE')
        with patch.dict(helper.fcntl.__dict__):
            for name in names:
                helper.fcntl.__dict__.pop(name, None)
            descriptor = helper.sealed_bytes(b'sealed')
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                self.assertEqual(os.read(descriptor, 6), b'sealed')
                os.lseek(descriptor, 0, os.SEEK_SET)
                with self.assertRaises(OSError):
                    os.write(descriptor, b'x')
                with self.assertRaises(OSError):
                    os.ftruncate(descriptor, 1)
                with self.assertRaises(OSError):
                    os.ftruncate(descriptor, 100)
            finally:
                os.close(descriptor)

    def test_wrong_artifact_hash_refuses_before_any_external_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'artifact'
            path.write_bytes(b'wrong bytes')
            with patch.object(helper.subprocess, 'check_output') as command:
                with self.assertRaisesRegex(RuntimeError, 'hash mismatch'):
                    helper.inspect(path, '0' * 64)
                command.assert_not_called()
