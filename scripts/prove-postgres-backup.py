#!/usr/bin/env python3
"""Native backup control of this gate's disposable DB, never the live directory."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

root = Path(sys.argv[1]).resolve()
url = urlsplit(os.environ['LLDAP_TEST_POSTGRES_URL'])
socket = Path(parse_qs(url.query)['host'][0]).resolve()
if socket != root / 'socket' or not (root / 'data/PG_VERSION').is_file():
    raise RuntimeError('Only this run-owned private cluster is admissible')
source = Path(__file__).resolve().parent.parent / 'esc-overlay/activate.py'
spec = importlib.util.spec_from_file_location('owned_backup', source)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
environment = owner.ENV | {'PGHOST': str(socket), 'PGDATABASE': 'lldap_owned_gate'}
output = root / 'fixture.pgcustom'
# Retention field is fixture data. Entire private cluster is destroyed by its owning test.
with patch.object(owner, 'postgres_environment', return_value=environment):
    receipt = owner.backup_postgres('private-fixture-only', output, '2030-01-01T00:00:00+00:00',
                                    journal=lambda entry: owner.save_receipt(root / 'backup-receipt.json', entry))
result = subprocess.run(['/usr/lib/postgresql/17/bin/pg_restore', '--list', str(output)],
                        env=environment, capture_output=True, text=True, check=True)
if not all('TABLE DATA public ' + table in result.stdout for table in ('users', 'memberships')):
    raise RuntimeError('Native archive did not retain expected private directory tables')
if output.read_bytes()[:5] != b'PGDMP' or receipt['format'] != 'postgresql-custom':
    raise RuntimeError('Native PostgreSQL archive format was not proven')
print('Private PostgreSQL17 consistent backup + archive readback: PASS')
