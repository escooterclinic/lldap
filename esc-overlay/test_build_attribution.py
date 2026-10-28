import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class BuildAttributionTests(unittest.TestCase):
    def test_unreviewed_tree_and_dirty_source_are_refused_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            script = root / 'scripts/build-activation-release.sh'
            script.parent.mkdir()
            shutil.copyfile(HERE.parent / 'scripts/build-activation-release.sh', script)
            environment = os.environ | {'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                                        'GIT_COMMITTER_NAME': 'Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, env=environment, text=True).strip()
            git('init', '-q')
            git('add', 'scripts/build-activation-release.sh')
            git('commit', '-qm', 'owned fixture')
            tree = git('rev-parse', 'HEAD^{tree}')
            output = root / 'output'
            def build(expected):
                return subprocess.run(['bash', str(script), str(output), expected], cwd=root,
                                      capture_output=True, text=True)
            mismatch = build('0' * 40)
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn('Reviewed source tree mismatch', mismatch.stderr)
            (root / 'unexpected-source.rs').write_text('unreviewed source')
            dirty = build(tree)
            self.assertNotEqual(dirty.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn('Reviewed source checkout is dirty', dirty.stderr)
