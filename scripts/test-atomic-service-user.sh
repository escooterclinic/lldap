#!/bin/bash
# Disposable runner bootstrap. Never changes a system toolchain or shell profile.
set -euo pipefail
export PATH="${PATH:-/usr/bin:/bin}"
if ! command -v cargo >/dev/null 2>&1; then
  export CARGO_HOME="$PWD/.gate-cargo"
  export RUSTUP_HOME="$PWD/.gate-rustup"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$PWD/.gate-rustup-init.sh"
  sh "$PWD/.gate-rustup-init.sh" -y --profile minimal --default-toolchain 1.91.0 --no-modify-path
  export PATH="$CARGO_HOME/bin:$PATH"
fi
if [ "$#" -ne 0 ] && [ "$(uname -s)" != Linux ]; then
  printf '%s\n' 'Linux artifact mode refuses a non-Linux fallback' >&2
  exit 1
fi
rustc --version
cargo test --locked -q -p lldap_sql_backend_handler -p lldap_graphql_server --lib
if [ "$#" -ne 0 ]; then
  [ "$#" -eq 2 ] && [ "$1" = --build-artifact ] && [ "${2:0:1}" = / ] || {
    printf '%s\n' 'Usage: test-atomic-service-user.sh [--build-artifact ABSOLUTE-OUTPUT-DIRECTORY]' >&2
    exit 64
  }
  [ ! -e "$2" ] && [ ! -L "$2" ] || { printf '%s\n' 'Artifact output must be new' >&2; exit 1; }
  cargo build --locked --release -p lldap
  mkdir -m 0700 "$2"
  install -m 0755 target/release/lldap "$2/lldap"
  target/release/lldap export_graphql_schema -o "$2/schema.graphql"
  sha256sum "$2/lldap" "$2/schema.graphql" Cargo.lock > "$2/SHA256SUMS"
  rustc --version > "$2/toolchain.txt"
  uname -sm >> "$2/toolchain.txt"
  printf '%s\n' "Linux build artifacts preserved at $2"
fi
