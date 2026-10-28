#!/usr/bin/python3
"""Business overlay: retain package auth updates; never fake atomic API readiness."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

FIELDS = {'format', 'baseline_package_version', 'baseline_sha256', 'artifact_sha256'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def owned_regular(path, owner_uid):
    info = path.lstat()
    return (stat.S_ISREG(info.st_mode) and info.st_uid == owner_uid
            and info.st_mode & 0o022 == 0)


def argv(binary):
    return [str(binary), 'run', '--config-file', '/etc/lldap/lldap_config.toml']


def select_binary(release, package, package_version, *, owner_uid=0):
    if not owned_regular(package, owner_uid):
        raise RuntimeError('Package executable ownership is not trusted')
    pending = {'atomic_api': 'PENDING', 'selection': 'vendor_package'}
    try:
        config_path = release / 'deployment.json'
        if not owned_regular(config_path, owner_uid):
            return package, pending | {'reason': 'untrusted_owner_configuration'}
        config = json.loads(config_path.read_text())
        valid = (isinstance(config, dict) and config.keys() == FIELDS
                 and config['format'] == 'lldap-esc-overlay-v1'
                 and isinstance(config['baseline_package_version'], str)
                 and bool(config['baseline_package_version']))
        if not valid or any(not isinstance(config[k], str) or not re.fullmatch(r'[0-9a-f]{64}', config[k])
                            for k in ('baseline_sha256', 'artifact_sha256')):
            return package, pending | {'reason': 'invalid_owner_configuration'}
        if package_version != config['baseline_package_version'] or digest(package) != config['baseline_sha256']:
            return package, pending | {'reason': 'vendor_package_changed'}
        artifact = release / 'lldap'
        if not owned_regular(artifact, owner_uid) or digest(artifact) != config['artifact_sha256']:
            return package, pending | {'reason': 'untrusted_overlay_artifact'}
        return artifact, {'atomic_api': 'PENDING_LIVE_PROOF', 'selection': 'reviewed_fork',
                          'artifact_sha256': config['artifact_sha256']}
    except (OSError, ValueError, TypeError, KeyError):
        return package, pending | {'reason': 'owner_configuration_unavailable'}


def main():
    if len(sys.argv) != 1:
        raise SystemExit('The owner runtime accepts no caller arguments')
    query = subprocess.run(['/usr/bin/dpkg-query', '-W', '-f', '${Version}', 'lldap'],
                           capture_output=True, text=True, check=False)
    version = query.stdout.strip() if query.returncode == 0 else None
    binary, status = select_binary(Path(__file__).resolve().parent, Path('/usr/bin/lldap'), version)
    print(json.dumps(status, sort_keys=True), file=sys.stderr, flush=True)
    os.execv(binary, argv(binary))


if __name__ == '__main__':
    main()
