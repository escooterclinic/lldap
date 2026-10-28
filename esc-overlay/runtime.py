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


class ContractDrift(RuntimeError):
    """Trusted native inputs changed; current vendor argv remain authoritative."""


class UnsafeContract(RuntimeError):
    """Ownership or input integrity is not trusted; no executable may be selected."""


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
        raise UnsafeContract('Path escapes trusted root')
    current = path.parent
    while True:
        info = current.lstat()
        if not (stat.S_ISDIR(info.st_mode) and info.st_uid == owner_uid
                and info.st_mode & 0o022 == 0):
            raise UnsafeContract('Executable ancestor is not trusted')
        if current == trust_root:
            return
        current = current.parent


UNIT_DIRS = tuple(Path(path) for path in (
    '/etc/systemd/system.control', '/run/systemd/system.control', '/run/systemd/transient',
    '/run/systemd/generator.early', '/etc/systemd/system', '/run/systemd/system',
    '/run/systemd/generator', '/usr/local/lib/systemd/system', '/usr/lib/systemd/system',
    '/run/systemd/generator.late'))
DROPIN_DIRS = tuple(base / name for base in UNIT_DIRS
                   for name in ('lldap.service.d', 'service.d'))
OWN_DROPIN = Path('/etc/systemd/system/lldap.service.d/zz-esc-atomic-service-user.conf')


def verify_dropins(config, directories, owner_uid, trust_root):
    expected = config.get('baseline_dropins')
    if not isinstance(expected, dict):
        raise UnsafeContract('Missing drop-in contract')
    for name, value in expected.items():
        path = Path(name)
        if (not path.is_absolute() or path.parent not in directories or path == OWN_DROPIN
                or path.suffix != '.conf' or not isinstance(value, str)
                or not re.fullmatch(r'[0-9a-f]{64}', value)):
            raise UnsafeContract('Invalid drop-in contract')
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
                raise UnsafeContract('Drop-in file is not trusted')
            observed[str(path)] = digest(path)
    if observed != expected:
        raise ContractDrift('Unit drop-in drift requires owner review; execution refused')


def select_binary(release, package, package_version, *, owner_uid=0,
                  vendor_unit=Path('/usr/lib/systemd/system/lldap.service'),
                  trust_root=Path('/'), dropin_dirs=DROPIN_DIRS):
    overridden = False
    if trust_root == Path('/') and vendor_unit == Path('/usr/lib/systemd/system/lldap.service'):
        for base in UNIT_DIRS:
            fragment = base / 'lldap.service'
            if fragment != vendor_unit and os.path.lexists(fragment):
                trusted_ancestors(fragment, owner_uid, trust_root)
                if not owned_regular(fragment, owner_uid):
                    raise UnsafeContract('Overriding unit fragment is not trusted')
                overridden = True
    for path in (package, vendor_unit, release / 'deployment.json'):
        trusted_ancestors(path, owner_uid, trust_root)
    if not owned_regular(package, owner_uid) or not owned_regular(vendor_unit, owner_uid):
        raise UnsafeContract('Package executable or unit is not trusted')
    config_path = release / 'deployment.json'
    if not owned_regular(config_path, owner_uid):
        raise UnsafeContract('Owner unit contract configuration is not trusted')
    try:
        config = json.loads(config_path.read_text())
        expected_unit = config.get('baseline_unit_sha256') if isinstance(config, dict) else None
    except (OSError, ValueError):
        raise UnsafeContract('Owner unit contract is unavailable') from None
    if not isinstance(expected_unit, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_unit):
        raise UnsafeContract('Owner unit contract is invalid')
    verify_dropins(config, dropin_dirs, owner_uid, trust_root)
    if digest(vendor_unit) != expected_unit or overridden:
        raise ContractDrift('Vendor unit drift requires owner review; execution refused')
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
            raise UnsafeContract('Overridden vendor unit requires owner review')
    version = query.stdout.strip() if query.returncode == 0 else None
    binary, status = select_binary(Path(__file__).absolute().parent, Path('/usr/bin/lldap'), version)
    print(json.dumps(status, sort_keys=True), file=sys.stderr, flush=True)
    os.execv(binary, argv(binary))


if __name__ == '__main__':
    main()
