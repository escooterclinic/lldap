#!/bin/bash
# Whole native server/backend/auth/LDAP workspace coverage, private PG, exact release.
set -euo pipefail
[ "$#" -eq 2 ] && [ "${1:0:1}" = / ] && [[ "$2" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'Required: ABSOLUTE-NEW-OUTPUT-DIRECTORY EXPECTED-GIT-TREE' >&2; exit 64;
}
[ "$(uname -s)" = Linux ] || { echo 'Linux-only release gate' >&2; exit 1; }
output=$1
source_tree=$2
bash scripts/test-atomic-service-user.sh
export CARGO_HOME="$PWD/.gate-cargo"
export RUSTUP_HOME="$PWD/.gate-rustup"
export PATH="$CARGO_HOME/bin:${PATH:-/usr/bin:/bin}"
cargo test --locked --workspace --exclude lldap_app
bash scripts/test-service-postgres.sh
python3 esc-overlay/prove_guards.py
bash scripts/test-atomic-service-user.sh --build-artifact "$output"
printf '%s\n' "$source_tree" > "$output/source-git-tree.txt"
sha256sum "$output"/* > "$output/BUILD-SHA256SUMS"
readelf --version-info "$output/lldap" > "$output/elf-version-info.txt"
ldd "$output/lldap" > "$output/linked-libraries.txt"
