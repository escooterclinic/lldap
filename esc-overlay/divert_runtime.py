#!/usr/bin/python3
"""Fixed package diversion wrapper; preserve the caller's complete argument vector."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('lldap_unit_contract', HERE / 'runtime.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
VENDOR = Path('/usr/lib/lldap-esc/lldap.distrib')


def forward_argv(arguments):
    return ['/usr/bin/lldap', *arguments]


def select(release, vendor, version, *, owner_uid=0, trust_root=Path('/'), **contract_options):
    contract.trusted_ancestors(vendor, owner_uid, trust_root)
    if not contract.owned_regular(vendor, owner_uid):
        raise RuntimeError('Current diverted package executable is not trusted')
    try:
        return contract.select_binary(release, vendor, version,
                                      owner_uid=owner_uid, trust_root=trust_root, **contract_options)
    except contract.ContractDrift:
        return vendor, {'atomic_api': 'PENDING', 'selection': 'vendor_package',
                        'reason': 'reviewed_unit_contract_not_current'}


def main():
    query = subprocess.run(['/usr/bin/dpkg-query', '-W', '-f', '${Version}', 'lldap'],
                           capture_output=True, text=True, check=False)
    version = query.stdout.strip() if query.returncode == 0 else None
    binary, status = select(HERE, VENDOR, version)
    print(json.dumps(status, sort_keys=True), file=sys.stderr, flush=True)
    os.execv(binary, forward_argv(sys.argv[1:]))


if __name__ == '__main__':
    main()
