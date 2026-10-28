#!/bin/bash
# A private run-owned PostgreSQL17 cluster, never an existing service/database.
set -euo pipefail
export PATH="${PATH:-/usr/bin:/bin}"
PG_BINDIR=/usr/lib/postgresql/17/bin
[ -x "$PG_BINDIR/initdb" ] || { echo 'Private PostgreSQL17 toolchain required' >&2; exit 1; }
cluster_root=$(mktemp -d /tmp/lldap-pg-gate.XXXXXXXX)
cleanup() {
  "$PG_BINDIR/pg_ctl" -D "$cluster_root/data" -m immediate stop >/dev/null 2>&1 || true
  rm -rf -- "$cluster_root"
}
trap cleanup EXIT
mkdir -m 0700 "$cluster_root/socket"
"$PG_BINDIR/initdb" -D "$cluster_root/data" --auth=trust --no-locale --encoding=UTF8 > "$cluster_root/init.log"
"$PG_BINDIR/pg_ctl" -D "$cluster_root/data" -l "$cluster_root/server.log" -o "-k $cluster_root/socket -h ''" start > "$cluster_root/start.log"
"$PG_BINDIR/createdb" -h "$cluster_root/socket" lldap_owned_gate
export LLDAP_TEST_POSTGRES_URL="postgresql:///lldap_owned_gate?host=$cluster_root/socket"
if ! command -v cargo >/dev/null 2>&1; then
  export CARGO_HOME="$PWD/.gate-cargo"
  export RUSTUP_HOME="$PWD/.gate-rustup"
  export PATH="$CARGO_HOME/bin:$PATH"
fi
cargo test --locked -p lldap_sql_backend_handler test_service_user_postgres_atomicity_and_concurrent_readback -- --ignored --exact sql_user_backend_handler::tests::test_service_user_postgres_atomicity_and_concurrent_readback
