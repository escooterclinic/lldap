#!/bin/bash
# Whole native server/backend/auth/LDAP coverage, private PG, attributable release.
set -euo pipefail
[ "$#" -eq 2 ] && [ "${1:0:1}" = / ] && [[ "$2" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'Required: ABSOLUTE-NEW-OUTPUT-DIRECTORY EXPECTED-GIT-TREE' >&2; exit 64;
}
[ "$(uname -s)" = Linux ] || { echo 'Linux-only release gate' >&2; exit 1; }
output=$1
source_tree=$2
[ ! -e "$output" ] && [ ! -L "$output" ] || { echo 'Output must be new' >&2; exit 1; }
mkdir -m 0700 "$output"
printf '%s\n' "$source_tree" > "$output/source-git-tree.txt"
python3 - "$output/source-inputs.sha256" <<'PY'
import hashlib, os, pathlib, sys
excluded = {'.git', 'target', '.gate-cargo', '.gate-rustup', '__pycache__'}
rows = []
for directory, dirs, files in os.walk('.'):
    dirs[:] = sorted(name for name in dirs if name not in excluded)
    for name in sorted(files):
        path = pathlib.Path(directory) / name
        if name in ('.git', '.gate-rustup-init.sh') or name.endswith('.pyc'):
            continue
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
  cargo test --locked --workspace --exclude lldap_app
  bash scripts/test-service-postgres.sh
  python3 esc-overlay/prove_guards.py
  bash scripts/test-atomic-service-user.sh --build-artifact "$output/artifact"
  readelf --version-info "$output/artifact/lldap" > "$output/elf-version-info.txt"
  ldd "$output/artifact/lldap" > "$output/linked-libraries.txt"
} 2>&1 | tee "$output/build.log"
sha256sum "$output/artifact/lldap" "$output/artifact/schema.graphql" \
  "$output/source-git-tree.txt" "$output/source-inputs.sha256" "$output/build.log" \
  "$output/elf-version-info.txt" "$output/linked-libraries.txt" > "$output/BUILD-SHA256SUMS"
