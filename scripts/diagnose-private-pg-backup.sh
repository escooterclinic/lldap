#!/bin/bash
# Reproducible private-only archive diagnostic; never reads live config/credentials.
set -euo pipefail
bindir=/usr/lib/postgresql/17/bin
lab=$(mktemp -d /tmp/lldap-backup-lab.XXXXXXXX)
cleanup() { "$bindir/pg_ctl" -D "$lab/data" -m immediate stop >/dev/null 2>&1 || true; rm -rf -- "$lab"; }
trap cleanup EXIT
mkdir -m 0700 "$lab/socket"
"$bindir/initdb" -D "$lab/data" --auth=trust --no-locale --encoding=UTF8 >/dev/null
"$bindir/pg_ctl" -D "$lab/data" -l "$lab/server.log" -o "-k $lab/socket -h ''" start >/dev/null
"$bindir/createdb" -h "$lab/socket" lldap_owned_gate
"$bindir/psql" -h "$lab/socket" -d lldap_owned_gate -c 'CREATE TABLE fixture(value TEXT)' >/dev/null
python3 - "$lab" <<'PY'
import importlib.util,json,pathlib,subprocess,sys
from unittest.mock import patch
root=pathlib.Path(sys.argv[1]);source=pathlib.Path('esc-overlay/activate.py').resolve()
spec=importlib.util.spec_from_file_location('owner',source);owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
env=owner.ENV|{'PGHOST':str(root/'socket'),'PGDATABASE':'lldap_owned_gate'}
records=[];output=root/'fixture.pgcustom'
with patch.object(owner,'postgres_environment',return_value=env):
 try:owner.backup_postgres('private-only',output,'2030-01-01T00:00:00+00:00',journal=records.append)
 except RuntimeError as error:print('PRIVATE_FIXTURE_ERROR',str(error))
for tool in ('pg_dump','pg_restore'):
 print(subprocess.check_output(['/usr/lib/postgresql/17/bin/'+tool,'--version'],text=True).strip())
result=subprocess.run(['/usr/lib/postgresql/17/bin/pg_restore','--list',str(output)],env=owner.ENV,capture_output=True,text=True)
print(json.dumps({'size':output.stat().st_size,'magic_hex':output.read_bytes()[:16].hex(),'restore_rc':result.returncode,'private_fixture_restore_stderr':result.stderr,'journal_statuses':[row['status'] for row in records]}))
if result.returncode:raise SystemExit(result.returncode)
PY
