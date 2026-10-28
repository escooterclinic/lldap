#!/usr/bin/env python3
"""Run behavioral guard-removal controls in isolated source copies."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
CASES = (
    ('native-config-ancestor', 'activate.py',
     '            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, service_uid)\n                    or info.st_mode & 0o022):',
     '            if False:',
     'test_activation.OwnedFileTests.test_native_config_uses_declared_service_owner_and_refuses_writable_parent'),
    ('manifest-file-mode', 'activate.py',
     '        if mode != required_mode:', '        if False:',
     'test_activation.OwnedFileTests.test_bundle_refuses_special_or_writable_manifest_modes'),
    ('build-tree-binding', '../scripts/build-activation-release.sh',
     '[ "$source_tree" = "$2" ] ||', 'true ||',
     'test_build_attribution.BuildAttributionTests.test_unreviewed_tree_and_dirty_source_are_refused_before_output'),
    ('build-clean-source', '../scripts/build-activation-release.sh',
     '[ -z "$(git status --porcelain --untracked-files=all)" ] ||', 'true ||',
     'test_build_attribution.BuildAttributionTests.test_unreviewed_tree_and_dirty_source_are_refused_before_output'),
    ('backup-before-sensitive-bytes', 'activate.py',
     "        record('incomplete_dump')  # durable owner journal MUST precede any sensitive dump bytes",
     '        pass',
     'test_activation.OwnedFileTests.test_failed_dump_and_readback_retain_positive_partial_backup_receipt'),
    ('unsafe-contract-refusal', 'divert_runtime.py',
     '    except contract.ContractDrift:', '    except RuntimeError:',
     'test_divert_runtime.DivertRuntimeTests.test_actual_writable_dropin_refuses_even_when_vendor_unit_changed'),
    ('rollback-file-ownership', 'activate.py',
     "    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid\n            or identity(path) != record):", "    if False:",
     'test_activation.OwnedFileTests.test_changed_or_replaced_file_is_never_deleted'),
    ('rollback-before-interruption', 'activate.py',
     "or identity(PACKAGE) != wrapper:", "or False:",
     'test_activation.OwnedFileTests.test_rollback_refuses_changed_wrapper_before_interrupting'),
    ('argv-passthrough', 'divert_runtime.py',
     "    return ['/usr/bin/lldap', *arguments]", "    return ['/usr/bin/lldap', 'run']",
     'test_divert_runtime.DivertRuntimeTests.test_argv_is_passed_through_exactly'),
    ('dropin-contract', 'runtime.py',
     '    if observed != expected:', '    if False:',
     'test_runtime.RuntimeSelectionTests.test_dropin_addition_removal_and_content_drift_refuse_execution'),
    ('unit-drift', 'runtime.py',
     "if digest(vendor_unit) != expected_unit or overridden:", "if False:",
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
            shutil.copytree(HERE.parent / 'scripts', source.parent / 'scripts')
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
