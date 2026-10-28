#!/usr/bin/python3
"""Create a NEW staged bundle only. Does not install, reload or restart anything."""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import shutil


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(output, artifact, artifact_sha, package_version, package_sha, unit_sha, baseline_dropins):
    if any(not re.fullmatch(r'[0-9a-f]{64}', value) for value in (artifact_sha, package_sha, unit_sha)):
        raise ValueError('Explicit artifact and baseline SHA256 values are required')
    if not isinstance(baseline_dropins, dict) or any(
            not isinstance(name, str) or not name.startswith('/')
            or not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)
            for name, value in baseline_dropins.items()):
        raise ValueError('Explicit drop-in filename/hash map is required')
    if not package_version or any(char in package_version for char in '\r\n\0'):
        raise ValueError('Explicit baseline package version is required')
    if artifact.is_symlink() or not artifact.is_file():
        raise ValueError('Reviewed artifact must be a regular file')
    artifact_bytes = artifact.read_bytes()
    if hashlib.sha256(artifact_bytes).hexdigest() != artifact_sha:
        raise ValueError('Reviewed artifact hash does not match')
    if output.exists() or output.is_symlink():
        raise ValueError('Staging output must be new; existing content is never adopted')
    for parent in (output.absolute().parent, *output.absolute().parent.parents):
        info = parent.lstat()
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if not stat.S_ISDIR(info.st_mode) or (info.st_mode & 0o022 and not sticky_root):
            raise ValueError('Unsafe staging ancestor')
        if info.st_uid not in (0, os.getuid()):
            raise ValueError('Untrusted staging ancestor owner')
    output.mkdir(mode=0o700, parents=False)
    output.chmod(0o700)
    relative = Path('opt/lldap-esc/releases') / artifact_sha
    release = output / relative
    release.mkdir(parents=True, mode=0o755)
    (release / 'lldap').write_bytes(artifact_bytes)
    (release / 'lldap').chmod(0o555)
    shutil.copyfile(Path(__file__).with_name('runtime.py'), release / 'runtime.py')
    (release / 'runtime.py').chmod(0o555)
    config = {'format': 'lldap-esc-overlay-v1', 'baseline_package_version': package_version,
              'baseline_sha256': package_sha, 'artifact_sha256': artifact_sha,
              'baseline_unit_sha256': unit_sha, 'baseline_dropins': baseline_dropins}
    (release / 'deployment.json').write_text(json.dumps(config, sort_keys=True) + '\n')
    (release / 'deployment.json').chmod(0o444)
    unit = output / 'etc/systemd/system/lldap.service.d/zz-esc-atomic-service-user.conf'
    unit.parent.mkdir(parents=True)
    unit.write_text('[Service]\nExecStart=\nExecStart=/usr/bin/python3 /' + str(relative / 'runtime.py') + '\n')
    unit.chmod(0o444)
    directories = [path for path in output.rglob('*') if path.is_dir()]
    for directory in directories:
        directory.chmod(0o755)
    files = [path for path in output.rglob('*') if path.is_file()]
    manifest = {'owner': 'escooterclinic/lldap:esc-overlay-v1', 'staged_only': True,
                'directories': [{'path': str(path.relative_to(output)), 'mode': '0755'}
                                for path in sorted(directories)],
                'files': [{'path': str(path.relative_to(output)), 'sha256': sha(path),
                           'mode': format(path.stat().st_mode & 0o777, '04o')} for path in sorted(files)]}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (output / 'manifest.json').chmod(0o444)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--artifact', type=Path, required=True)
    parser.add_argument('--artifact-sha256', required=True)
    parser.add_argument('--baseline-package-version', required=True)
    parser.add_argument('--baseline-sha256', required=True)
    parser.add_argument('--baseline-unit-sha256', required=True)
    parser.add_argument('--baseline-dropins-manifest', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output, args.artifact, args.artifact_sha256,
                             args.baseline_package_version, args.baseline_sha256, args.baseline_unit_sha256,
                             json.loads(args.baseline_dropins_manifest.read_text()))))


if __name__ == '__main__':
    main()
