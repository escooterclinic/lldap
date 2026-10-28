#!/bin/bash
# Each invocation owns a separate private PG cluster; reviewed checkout stays intact.
set -euo pipefail
source_root="$PWD"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
scratch=$(mktemp -d /tmp/lldap-pg-mutations.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
for label in bot-marker-policy atomic-user-marker; do
  copied="$scratch/$label"
  mkdir "$copied"
  tar --exclude=./target --exclude=./.gate-cargo --exclude=./.gate-rustup \
      --exclude=./.git -cf - . | tar -xf - -C "$copied"
  (
    cd "$copied"
    git apply --check "$source_root/scripts/mutations/$label.patch"
    git apply "$source_root/scripts/mutations/$label.patch"
    set +e
    bash scripts/test-service-postgres.sh > "$scratch/$label.log" 2>&1
    status=$?
    set -e
    [ "$status" -eq 101 ] && grep -Fq 'test result: FAILED.' "$scratch/$label.log" \
      && grep -Fq 'test_service_user_postgres_atomicity_and_concurrent_readback' "$scratch/$label.log" || {
        cat "$scratch/$label.log"
        echo "PostgreSQL mutation $label did not fail behaviorally" >&2
        exit 1
      }
    echo "POSTGRES_MUTATION_KILLED $label"
  )
done
