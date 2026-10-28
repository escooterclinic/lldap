#!/usr/bin/python3 -I
"""Inspect final artifact ABI; optional sealed-memory --version only, never run service."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess


def inspect(artifact, expected):
    data = artifact.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('Reviewed artifact hash mismatch')
    descriptor = sealed_bytes(data)
    try:
        path = '/proc/self/fd/' + str(descriptor)
        def readelf(option):
            return subprocess.check_output(['/usr/bin/readelf', option, path],
                                           pass_fds=(descriptor,), text=True)
        versions = readelf('--version-info')
        header = readelf('--file-header')
        dynamic = readelf('--dynamic')
    finally:
        os.close(descriptor)
    required = max((tuple(map(int, value.split('.'))) for value in
                    re.findall(r'GLIBC_([0-9]+\.[0-9]+)', versions)), default=(0, 0))
    current = tuple(map(int, subprocess.check_output(['/usr/bin/getconf', 'GNU_LIBC_VERSION'],
                                                    text=True).strip().split()[1].split('.')))
    needed = sorted(re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic))
    libraries = subprocess.check_output(['/sbin/ldconfig', '-p'], text=True)
    present = {line.strip().split()[0] for line in libraries.splitlines() if '=>' in line}
    if platform.machine() != 'x86_64' or 'Advanced Micro Devices X86-64' not in header:
        raise RuntimeError('Reviewed x86_64 artifact/target architecture mismatch')
    if current < required or set(needed) - present:
        raise RuntimeError('Target ABI/library requirement is not satisfied')
    return data, {'sha256': expected, 'architecture': platform.machine(),
                  'required_glibc': list(required), 'target_glibc': list(current),
                  'needed': needed, 'abi_metadata': 'compatible', 'target_version_executed': False}


def sealed_bytes(data):
    descriptor = os.memfd_create('lldap-reviewed-version', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(descriptor), 'wb') as stream:
            stream.write(data)
            stream.flush()
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def sealed_version(data):
    descriptor = sealed_bytes(data)
    try:
        result = subprocess.run(['/usr/bin/lldap', '--version'], executable='/proc/self/fd/' + str(descriptor),
                                pass_fds=(descriptor,), capture_output=True, text=True, check=True,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        return result.stdout.strip()
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--execute-version', action='store_true')
    args = parser.parse_args()
    data, result = inspect(args.artifact, args.sha256)
    if args.execute_version:
        result['version_output'] = sealed_version(data)
        result['target_version_executed'] = True
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
