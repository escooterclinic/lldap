#!/usr/bin/python3 -I
"""Expire one positively owned retained archive, never a directory or sweep."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile


def parse_time(value):
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise RuntimeError('Timezone-qualified deadline required')
    return result.astimezone(timezone.utc)


def now_utc():
    return datetime.now(timezone.utc)


def trusted_parents(path, owner_uid, trust_root):
    relative = path.absolute().relative_to(trust_root.absolute())
    current = trust_root
    for part in relative.parts[:-1]:
        current /= part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o022:
            raise RuntimeError('Untrusted archive or receipt ancestor')
    info = trust_root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o022:
        raise RuntimeError('Untrusted trust root')


def identity(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError('Expected regular archive')
        digest = hashlib.sha256()
        while data := os.read(descriptor, 1024 * 1024):
            digest.update(data)
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError('Archive changed during readback')
        return {'device': before.st_dev, 'inode': before.st_ino, 'uid': before.st_uid,
                'mode': stat.S_IMODE(before.st_mode), 'sha256': digest.hexdigest()}
    finally:
        os.close(descriptor)


def save_receipt(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix='.expiry-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def expire(receipt_path, backup, deadline, *, owner_uid=0, trust_root=Path('/')):
    if now_utc() < parse_time(deadline):
        raise RuntimeError('Approved retention deadline has not arrived')
    for path in (receipt_path, backup):
        if not path.is_absolute():
            raise RuntimeError('Absolute owned paths required')
        trusted_parents(path, owner_uid, trust_root)
    record = identity(receipt_path)
    if record['uid'] != owner_uid or record['mode'] != 0o600:
        raise RuntimeError('Untrusted deployment receipt')
    descriptor = os.open(receipt_path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        receipt = json.load(stream)
    if identity(receipt_path) != record or receipt.get('format') != 'lldap-diversion-owner-v1':
        raise RuntimeError('Foreign or changing deployment receipt')
    entry = receipt.get('backup', {})
    if (entry.get('path') != str(backup) or entry.get('retain_until') != deadline
            or entry.get('format') != 'postgresql-custom'
            or entry.get('status') not in ('verified', 'failed_dump', 'failed_readback', 'incomplete_dump', 'incomplete_readback')):
        raise RuntimeError('Archive ownership or deadline mismatch')
    actual = identity(backup)
    if actual != entry.get('identity') or actual['uid'] != owner_uid or actual['mode'] != 0o600:
        raise RuntimeError('Foreign or changed archive; refusing deletion')
    parent = os.open(backup.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.stat(backup.name, dir_fd=parent, follow_symlinks=False)
        if (info.st_dev, info.st_ino) != (actual['device'], actual['inode']):
            raise RuntimeError('Archive replaced before deletion')
        os.unlink(backup.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    entry['status'] = 'expired_deleted'
    entry['expired_at'] = now_utc().isoformat()
    save_receipt(receipt_path, receipt)
    return {'state': 'expired_owned_backup_deleted', 'path': str(backup)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--retain-until', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Root-owned expiration only')
    print(json.dumps(expire(args.receipt, args.backup, args.retain_until)))


if __name__ == '__main__':
    main()
