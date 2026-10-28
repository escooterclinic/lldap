#!/bin/bash
# Gate payloads lack .git. Build a fresh fixed-origin exact-commit checkout instead.
set -euo pipefail
[ "$#" -eq 3 ] && [ "${1:0:1}" = / ] && [[ "$2" =~ ^[0-9a-f]{40}$ ]] && [[ "$3" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'Required: ABSOLUTE-NEW-OUTPUT EXPECTED-COMMIT EXPECTED-TREE' >&2; exit 64;
}
output=$1
checkout="$output.source"
[ ! -e "$output" ] && [ ! -L "$output" ] && [ ! -e "$checkout" ] && [ ! -L "$checkout" ] || {
  echo 'Both source checkout and artifact destination must be new' >&2; exit 1;
}
mkdir -m 0700 "$checkout"
git init -q "$checkout"
git -C "$checkout" remote add origin https://github.com/escooterclinic/lldap.git
git -C "$checkout" -c credential.helper= fetch --no-tags --depth=1 origin "$2"
git -C "$checkout" checkout --detach FETCH_HEAD
[ "$(git -C "$checkout" rev-parse HEAD)" = "$2" ] && \
  [ "$(git -C "$checkout" rev-parse 'HEAD^{tree}')" = "$3" ] || {
  echo 'Fetched reviewed commit/tree mismatch' >&2; exit 1;
}
cd "$checkout"
exec bash scripts/build-activation-release.sh "$output" "$3"
