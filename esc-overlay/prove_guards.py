#!/usr/bin/env python3
"""Run behavioral guard-removal controls in isolated source copies."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
CASES = (
    ('dropin-contract', 'runtime.py',
     '    if observed != expected:', '    if False:',
     'test_runtime.RuntimeSelectionTests.test_dropin_addition_removal_and_content_drift_refuse_execution'),
    ('unit-drift', 'runtime.py',
     "if digest(vendor_unit) != expected_unit:", "if False:",
     'test_runtime.RuntimeSelectionTests.test_unit_drift_refuses_even_package_fallback'),
    ('ancestor-trust', 'runtime.py',
     '        trusted_ancestors(path, owner_uid, trust_root)', '        pass',
     'test_runtime.RuntimeSelectionTests.test_writable_or_symlink_ancestor_refuses_execution'),
    ('directory-modes', 'prepare.py',
     '        directory.chmod(0o755)', '        pass',
     'test_prepare.PreparationTests.test_directory_modes_and_manifest_ignore_permissive_umask'),
)


def main():
    subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(HERE),
                    '-p', 'test_*.py', '-q'], check=True)
    for name, filename, before, after, test in CASES:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'overlay'
            shutil.copytree(HERE, source, ignore=shutil.ignore_patterns('__pycache__'))
            path = source / filename
            text = path.read_text()
            if text.count(before) != 1:
                raise RuntimeError('Mutation anchor is not unique: ' + name)
            path.write_text(text.replace(before, after))
            result = subprocess.run([sys.executable, '-m', 'unittest', test],
                                    cwd=source, capture_output=True, text=True)
            evidence = result.stdout + result.stderr
            if (result.returncode == 0 or 'FAILED (failures=' not in evidence
                    or 'AssertionError' not in evidence):
                raise RuntimeError('Mutation did not fail behaviorally: ' + name + '\n' + evidence)
            print(name + ': KILLED by behavioral assertion', flush=True)


if __name__ == '__main__':
    main()
