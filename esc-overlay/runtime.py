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

FIELDS = {'format', 'baseline_package_version', 'baseline_sha256', 'artifact_sha256', 'baseline_unit_sha256', 'baseline_dropins'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def owned_regular(path, owner_uid):
    info = path.lstat()
    return (stat.S_ISREG(info.st_mode) and info.st_uid == owner_uid
            and info.st_mode & 0o022 == 0)


def argv(binary):
    return [str(binary), 'run', '--config-file', '/etc/lldap/lldap_config.toml']


def trusted_ancestors(path, owner_uid, trust_root):
    path = path.absolute()
    trust_root = trust_root.absolute()
    if not path.is_relative_to(trust_root):
        raise RuntimeError('Path escapes trusted root')
    current = path.parent
    while True:
        info = current.lstat()
        if not (stat.S_ISDIR(info.st_mode) and info.st_uid == owner_uid
                and info.st_mode & 0o022 == 0):
            raise RuntimeError('Executable ancestor is not trusted')
        if current == trust_root:
            return
        current = current.parent


DROPIN_DIRS = tuple(Path(path) for path in (
    '/etc/systemd/system/lldap.service.d', '/run/systemd/system/lldap.service.d',
    '/usr/local/lib/systemd/system/lldap.service.d', '/usr/lib/systemd/system/lldap.service.d'))
OWN_DROPIN = Path('/etc/systemd/system/lldap.service.d/zz-esc-atomic-service-user.conf')


def verify_dropins(config, directories, owner_uid, trust_root):
    expected = config.get('baseline_dropins')
    if not isinstance(expected, dict):
        raise RuntimeError('Missing drop-in contract')
    for name, value in expected.items():
        path = Path(name)
        if (not path.is_absolute() or path.parent not in directories or path == OWN_DROPIN
                or path.suffix != '.conf' or not isinstance(value, str)
                or not re.fullmatch(r'[0-9a-f]{64}', value)):
            raise RuntimeError('Invalid drop-in contract')
    observed = {}
    for directory in directories:
        if not directory.exists() and not directory.is_symlink():
            ancestor = directory.parent
            while not ancestor.exists() and not ancestor.is_symlink():
                ancestor = ancestor.parent
            trusted_ancestors(ancestor / 'entry', owner_uid, trust_root)
            continue
        trusted_ancestors(directory / 'entry', owner_uid, trust_root)
        for path in directory.iterdir():
            if path == OWN_DROPIN or path.suffix != '.conf':
                continue
            if not owned_regular(path, owner_uid):
                raise RuntimeError('Drop-in file is not trusted')
            observed[str(path)] = digest(path)
    if observed != expected:
        raise RuntimeError('Unit drop-in drift requires owner review; execution refused')


def select_binary(release, package, package_version, *, owner_uid=0,
                  vendor_unit=Path('/usr/lib/systemd/system/lldap.service'),
                  trust_root=Path('/'), dropin_dirs=DROPIN_DIRS):
    for path in (package, vendor_unit, release / 'deployment.json'):
        trusted_ancestors(path, owner_uid, trust_root)
    if not owned_regular(package, owner_uid) or not owned_regular(vendor_unit, owner_uid):
        raise RuntimeError('Package executable or unit is not trusted')
    config_path = release / 'deployment.json'
    if not owned_regular(config_path, owner_uid):
        raise RuntimeError('Owner unit contract configuration is not trusted')
    try:
        config = json.loads(config_path.read_text())
        expected_unit = config.get('baseline_unit_sha256') if isinstance(config, dict) else None
    except (OSError, ValueError):
        raise RuntimeError('Owner unit contract is unavailable') from None
    if not isinstance(expected_unit, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_unit):
        raise RuntimeError('Owner unit contract is invalid')
    if digest(vendor_unit) != expected_unit:
        raise RuntimeError('Vendor unit drift requires owner review; execution refused')
    verify_dropins(config, dropin_dirs, owner_uid, trust_root)
    pending = {'atomic_api': 'PENDING', 'selection': 'vendor_package'}
    try:
        valid = (config.keys() == FIELDS and config['format'] == 'lldap-esc-overlay-v1'
                 and isinstance(config['baseline_package_version'], str)
                 and bool(config['baseline_package_version']))
        if not valid or any(not isinstance(config[k], str) or not re.fullmatch(r'[0-9a-f]{64}', config[k])
                            for k in ('baseline_sha256', 'artifact_sha256')):
            return package, pending | {'reason': 'invalid_owner_configuration'}
        if package_version != config['baseline_package_version'] or digest(package) != config['baseline_sha256']:
            return package, pending | {'reason': 'vendor_package_changed_same_unit_contract'}
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
    for fragment in ('/etc/systemd/system/lldap.service', '/run/systemd/system/lldap.service'):
        if os.path.lexists(fragment):
            raise RuntimeError('Overridden vendor unit requires owner review')
    version = query.stdout.strip() if query.returncode == 0 else None
    binary, status = select_binary(Path(__file__).absolute().parent, Path('/usr/bin/lldap'), version)
    print(json.dumps(status, sort_keys=True), file=sys.stderr, flush=True)
    os.execv(binary, argv(binary))


if __name__ == '__main__':
    main()
