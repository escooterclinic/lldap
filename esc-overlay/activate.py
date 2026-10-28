#!/usr/bin/python3 -I
"""Root-owned, explicit package-diversion activation and ownership-checked rollback."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import tomllib
from urllib.parse import urlsplit, unquote

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('contract', HERE / 'runtime.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
PACKAGE = Path('/usr/bin/lldap')
DIVERTED = Path('/usr/lib/lldap-esc/lldap.distrib')
SERVICE = 'lldap.service'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    info = path.lstat()
    return {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
            'mode': stat.S_IMODE(info.st_mode), 'sha256': sha(path.read_bytes())}


def create_owned(path, data, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), mode)
    return identity(path)


def remove_owned(path, record, owner_uid=0):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
            or identity(path) != record):
        raise RuntimeError('Rollback ownership mismatch; refusing deletion')
    path.unlink()


def approved_deadline(retain_until):
    try:
        deadline = datetime.fromisoformat(retain_until)
    except (ValueError, TypeError):
        raise ValueError('Explicit approved retention deadline required') from None
    if deadline.tzinfo is None or deadline <= datetime.now(timezone.utc):
        raise ValueError('Approved retention deadline must be future and timezone-qualified')
    return retain_until


def postgres_environment(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ('postgres', 'postgresql') or not parsed.hostname or not parsed.path.strip('/'):
        raise RuntimeError('Actual PostgreSQL database authority is required')
    if parsed.query:
        raise RuntimeError('Unreviewed PostgreSQL connection options require owner review')
    return ENV | {'PGHOST': parsed.hostname, 'PGPORT': str(parsed.port or 5432),
                  'PGDATABASE': unquote(parsed.path.removeprefix('/')),
                  'PGUSER': unquote(parsed.username or ''), 'PGPASSWORD': unquote(parsed.password or '')}


def backup_postgres(url, output, retain_until):
    approved_deadline(retain_until)
    environment = postgres_environment(url)
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        result = subprocess.run(['/usr/bin/pg_dump', '--format=custom', '--no-password',
                                 '--file=/proc/self/fd/' + str(descriptor)],
                                env=environment, pass_fds=(descriptor,), capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError('PostgreSQL consistent backup failed; no credential-bearing diagnostics emitted')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    result = subprocess.run(['/usr/bin/pg_restore', '--list', str(output)],
                            env=ENV, capture_output=True, check=False)
    if result.returncode or not result.stdout:
        raise RuntimeError('PostgreSQL archive readback failed')
    return {'path': str(output), 'sha256': sha(output.read_bytes()), 'retain_until': retain_until,
            'format': 'postgresql-custom', 'automatic_cleanup': False}


def effective_database_url(config, pid):
    if config != Path('/etc/lldap/lldap_config.toml'):
        raise RuntimeError('Only the verified native config path is supported')
    contract.trusted_ancestors(config, 0, Path('/'))
    if not contract.owned_regular(config, 0):
        raise RuntimeError('Native database configuration must be root-owned and not writable by others')
    arguments = (Path('/proc') / str(pid) / 'cmdline').read_bytes().split(b'\0')
    if b'--config-file' not in arguments or arguments[arguments.index(b'--config-file') + 1] != bytes(config):
        raise RuntimeError('Running subject does not positively name the verified config')
    environment = (Path('/proc') / str(pid) / 'environ').read_bytes().split(b'\0')
    overrides = [entry.split(b'=', 1)[1].decode() for entry in environment
                 if entry.startswith(b'LLDAP_DATABASE_URL=')]
    configured = tomllib.loads(config.read_text()).get('database_url')
    url = overrides[0] if overrides else configured
    postgres_environment(url)  # validate without printing credentials
    return url


def command(*arguments):
    return subprocess.run(arguments, env=ENV, capture_output=True, text=True, check=True).stdout.strip()


def systemctl(*arguments):
    suffix = () if arguments == ('daemon-reload',) else (SERVICE,)
    result = subprocess.run(('/usr/bin/systemctl', *arguments, *suffix), env=ENV,
                            capture_output=True, text=True, check=False)
    if result.returncode and not (arguments == ('is-active',) and result.returncode == 3):
        raise RuntimeError('Exact-service systemctl operation failed: ' + arguments[0])
    return result.stdout.strip()


def ensure_directory(path):
    if not path.exists():
        ensure_directory(path.parent)
        path.mkdir(mode=0o755)
        path.chmod(0o755)
    contract.trusted_ancestors(path / 'entry', 0, Path('/'))


def save_receipt(path, receipt):
    descriptor, temporary = tempfile.mkstemp(prefix='.receipt-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(receipt, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def diversion_owned():
    return (command('/usr/bin/dpkg-divert', '--listpackage', str(PACKAGE)) == 'LOCAL'
            and command('/usr/bin/dpkg-divert', '--truename', str(PACKAGE)) == str(DIVERTED))


def change_diversion(operation):
    command('/usr/bin/dpkg-divert', '--local', '--divert', str(DIVERTED), '--rename',
            '--' + operation, str(PACKAGE))


def read_bundle(bundle, expected):
    manifest_path = bundle / 'manifest.json'
    contract.trusted_ancestors(manifest_path, 0, Path('/'))
    if not contract.owned_regular(manifest_path, 0) or sha(manifest_path.read_bytes()) != expected:
        raise RuntimeError('Reviewed bundle manifest mismatch')
    manifest = json.loads(manifest_path.read_text())
    files = {}
    for row in manifest['files']:
        relative = Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts or relative in files:
            raise RuntimeError('Invalid bundle path')
        source = bundle / relative
        contract.trusted_ancestors(source, 0, Path('/'))
        if not contract.owned_regular(source, 0):
            raise RuntimeError('Untrusted bundle file')
        data = source.read_bytes()
        if sha(data) != row['sha256']:
            raise RuntimeError('Bundle file hash mismatch')
        files[relative] = (data, int(row['mode'], 8))
    releases = {path.parent for path in files if path.name == 'deployment.json'}
    if len(releases) != 1:
        raise RuntimeError('Expected one explicit release')
    release = releases.pop()
    if (release.parts[:3] != ('opt', 'lldap-esc', 'releases') or len(release.parts) != 4
            or len(release.name) != 64):
        raise RuntimeError('Invalid fixed release path')
    expected_files = {release / name for name in ('lldap', 'runtime.py', 'divert_runtime.py', 'deployment.json')}
    if set(files) != expected_files | {Path('usr/bin/lldap')}:
        raise RuntimeError('Only the package-diversion bundle is activatable')
    return files, release


def preflight(bundle, manifest_sha, database, backup, retain_until):
    approved_deadline(retain_until)
    if not all(path.is_absolute() for path in (bundle, database, backup)):
        raise RuntimeError('Explicit absolute source/database/backup paths required')
    files, release = read_bundle(bundle, manifest_sha)
    for relative in files:
        if relative == Path('usr/bin/lldap'):
            continue
        destination = Path('/') / relative
        if os.path.lexists(destination):
            raise RuntimeError('Existing release files are never adopted')
    if command('/usr/bin/dpkg-divert', '--listpackage', str(PACKAGE)) or os.path.lexists(DIVERTED):
        raise RuntimeError('Preexisting diversion or destination is not owned')
    version = command('/usr/bin/dpkg-query', '-W', '-f', '${Version}', 'lldap')
    selected, _ = contract.select_binary(bundle / release, PACKAGE, version)
    if selected != bundle / release / 'lldap':
        raise RuntimeError('Reviewed baseline package/unit contract is not current')
    if systemctl('show', '--property=FragmentPath', '--value') != '/usr/lib/systemd/system/lldap.service':
        raise RuntimeError('Effective package unit fragment is not the verified vendor path')
    if systemctl('is-active') != 'active':
        raise RuntimeError('An independently healthy baseline service is required')
    if 'masked' in systemctl('show', '--property=UnitFileState', '--value'):
        raise RuntimeError('A preexisting intentional-off mask is not owned')
    pid = int(systemctl('show', '--property=MainPID', '--value'))
    database_url = effective_database_url(database, pid)
    for path in (database, backup):
        contract.trusted_ancestors(path, 0, Path('/'))
    if os.path.lexists(backup):
        raise RuntimeError('Unsafe database or preexisting backup')
    return files, release, database_url


def rollback_preflight(receipt, owner_uid=0):
    if receipt.get('format') != 'lldap-diversion-owner-v1' or not receipt.get('diversion_added'):
        raise RuntimeError('No active owned diversion in this receipt')
    if not diversion_owned():
        raise RuntimeError('Exact LOCAL diversion ownership is not current')
    wrapper = receipt.get('files', {}).get(str(PACKAGE))
    if not wrapper or not contract.owned_regular(PACKAGE, owner_uid) or identity(PACKAGE) != wrapper:
        raise RuntimeError('Owned unchanged wrapper required before interruption')
    contract.trusted_ancestors(DIVERTED, owner_uid, Path('/') if owner_uid == 0 else DIVERTED.parent)
    if not contract.owned_regular(DIVERTED, owner_uid):
        raise RuntimeError('Current vendor executable is not trusted')


def restore(receipt, receipt_path):
    wrapper = receipt['files'].get(str(PACKAGE))
    if receipt.get('diversion_added'):
        if not diversion_owned():
            raise RuntimeError('Diversion no longer matches positive ownership receipt')
        contract.trusted_ancestors(PACKAGE, 0, Path('/'))
        if wrapper:
            remove_owned(PACKAGE, wrapper)
        elif os.path.lexists(PACKAGE):
            raise RuntimeError('Unrecorded original-path file; refusing rollback')
        change_diversion('remove')
        receipt['diversion_added'] = False
        save_receipt(receipt_path, receipt)
    systemctl('daemon-reload')
    if receipt.get('mask_owned'):
        systemctl('unmask', '--runtime')
        receipt['mask_owned'] = False
    systemctl('start')
    if systemctl('is-active') != 'active':
        raise RuntimeError('Baseline availability not restored; independent fallback required')
    receipt['state'] = 'baseline_restored'
    save_receipt(receipt_path, receipt)
    # Release files are intentionally retained: no destructive directory sweep.


def activate(bundle, manifest_sha, database, backup, retain_until, *, receipt_path=None):
    files, release, database_url = preflight(bundle, manifest_sha, database, backup, retain_until)
    state = receipt_path or Path('/var/lib/lldap-esc/deployments') / (manifest_sha + '.json')
    ensure_directory(state.parent)
    descriptor = os.open(state, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
    receipt = {'format': 'lldap-diversion-owner-v1', 'manifest_sha256': manifest_sha,
               'files': {}, 'state': 'preparing', 'mask_owned': False, 'diversion_added': False}
    save_receipt(state, receipt)
    try:
        for relative, (data, mode) in files.items():
            if relative == Path('usr/bin/lldap'):
                continue
            destination = Path('/') / relative
            ensure_directory(destination.parent)
            receipt['files'][str(destination)] = create_owned(destination, data, mode)
            save_receipt(state, receipt)
        ensure_directory(DIVERTED.parent)
        systemctl('mask', '--runtime')
        receipt['mask_owned'] = True
        save_receipt(state, receipt)
        systemctl('stop')
        if systemctl('is-active') == 'active':
            raise RuntimeError('Intentional-off guard failed')
        receipt['backup_intent'] = {'path': str(backup), 'retain_until': retain_until}
        save_receipt(state, receipt)
        receipt['backup'] = backup_postgres(database_url, backup, retain_until)
        save_receipt(state, receipt)
        change_diversion('add')
        receipt['diversion_added'] = True
        save_receipt(state, receipt)
        data, mode = files[Path('usr/bin/lldap')]
        receipt['files'][str(PACKAGE)] = create_owned(PACKAGE, data, mode)
        save_receipt(state, receipt)
        systemctl('unmask', '--runtime')
        receipt['mask_owned'] = False
        systemctl('start')
        if systemctl('is-active') != 'active':
            raise RuntimeError('New process is not active')
        receipt['state'] = 'active_pending_authenticated_controls'
        save_receipt(state, receipt)
    except BaseException:
        restore(receipt, state)
        raise
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    create = sub.add_parser('activate')
    for name in ('bundle', 'database', 'backup'):
        create.add_argument('--' + name, type=Path, required=True)
    create.add_argument('--manifest-sha256', required=True)
    create.add_argument('--retain-until', required=True)
    rollback = sub.add_parser('rollback')
    rollback.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Only the root deployment owner may activate or roll back')
    if args.operation == 'activate':
        print(activate(args.bundle, args.manifest_sha256, args.database, args.backup, args.retain_until))
    else:
        contract.trusted_ancestors(args.receipt, 0, Path('/'))
        if not contract.owned_regular(args.receipt, 0):
            raise RuntimeError('Untrusted deployment receipt')
        receipt = json.loads(args.receipt.read_text())
        if receipt.get('format') != 'lldap-diversion-owner-v1':
            raise RuntimeError('Unknown deployment receipt')
        rollback_preflight(receipt)
        if 'masked' in systemctl('show', '--property=UnitFileState', '--value'):
            raise RuntimeError('Preexisting mask is not owned by this rollback')
        systemctl('mask', '--runtime')
        systemctl('stop')
        receipt['mask_owned'] = True
        restore(receipt, args.receipt)


if __name__ == '__main__':
    main()
