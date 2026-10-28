#!/bin/bash
# Whole source-payload gate; release attribution is a separate exact-Git build.
set -euo pipefail
cd "$(dirname "$0")"
[ "$(uname -s)" = Linux ] || { echo 'Linux native gate required' >&2; exit 1; }
bash scripts/test-atomic-service-user.sh
if [ -x "$PWD/.gate-cargo/bin/cargo" ]; then
  export CARGO_HOME="$PWD/.gate-cargo"
  export RUSTUP_HOME="$PWD/.gate-rustup"
  export PATH="$CARGO_HOME/bin:${PATH:-/usr/bin:/bin}"
fi
rustup component add --toolchain 1.91.0 rustfmt clippy
cargo fmt --all --check
cargo clippy --locked --tests --workspace -- -D warnings
cargo test --locked --workspace
bash scripts/test-service-postgres.sh
bash scripts/mutate-postgres-service.sh
python3 esc-overlay/prove_guards.py
bash scripts/test-atomic-service-user.sh
schema=$(mktemp /tmp/lldap-schema-gate.XXXXXXXX)
trap 'rm -f -- "$schema"' EXIT
cargo run --locked -p lldap -- export_graphql_schema -o "$schema"
cmp schema.graphql "$schema"
