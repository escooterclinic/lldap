#!/bin/bash
# Whole native server/backend/auth/LDAP coverage, private PG, attributable release.
set -euo pipefail
[ "$#" -eq 2 ] && [ "${1:0:1}" = / ] && [[ "$2" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'Required: ABSOLUTE-NEW-OUTPUT-DIRECTORY EXPECTED-GIT-TREE' >&2; exit 64;
}
[ "$(uname -s)" = Linux ] || { echo 'Linux-only release gate' >&2; exit 1; }
output=$1
source_tree=$(git rev-parse 'HEAD^{tree}')
[ "$source_tree" = "$2" ] || { echo 'Reviewed source tree mismatch' >&2; exit 1; }
[ -z "$(git status --porcelain --untracked-files=all)" ] || { echo 'Reviewed source checkout is dirty' >&2; exit 1; }
source_commit=$(git rev-parse HEAD)
[ ! -e "$output" ] && [ ! -L "$output" ] || { echo 'Output must be new' >&2; exit 1; }
mkdir -m 0700 "$output"
printf '%s\n' "$source_tree" > "$output/source-git-tree.txt"
printf '%s\n' "$source_commit" > "$output/source-git-commit.txt"
python3 - "$output/source-inputs.sha256" <<'PY'
import hashlib, os, pathlib, subprocess, sys
rows = []
for value in subprocess.check_output(['git', 'ls-files', '-z']).split(b'\0'):
    if not value:
        continue
    path = pathlib.Path(os.fsdecode(value))
    data = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
    rows.append((str(path), hashlib.sha256(data).hexdigest()))
pathlib.Path(sys.argv[1]).write_text(''.join(digest + '  ' + path + '\n' for path, digest in sorted(rows)))
PY
{
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
  git diff --exit-code
  git diff --cached --exit-code
  python3 esc-overlay/prove_guards.py
  bash scripts/test-atomic-service-user.sh --build-artifact "$output/artifact"
  cmp schema.graphql "$output/artifact/schema.graphql"
  readelf --version-info "$output/artifact/lldap" > "$output/elf-version-info.txt"
  ldd "$output/artifact/lldap" > "$output/linked-libraries.txt"
} 2>&1 | tee "$output/build.log"
sha256sum "$output/artifact/lldap" "$output/artifact/schema.graphql" \
  "$output/source-git-tree.txt" "$output/source-git-commit.txt" "$output/source-inputs.sha256" "$output/build.log" \
  "$output/elf-version-info.txt" "$output/linked-libraries.txt" > "$output/BUILD-SHA256SUMS"
