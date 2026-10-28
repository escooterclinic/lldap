#!/bin/bash
# Mutate disposable source copies; never edit the reviewed checkout.
set -euo pipefail
bash scripts/test-atomic-service-user.sh
if ! command -v cargo >/dev/null 2>&1; then
  export CARGO_HOME="$PWD/.gate-cargo" RUSTUP_HOME="$PWD/.gate-rustup"
  export PATH="$CARGO_HOME/bin:${PATH:-/usr/bin:/bin}"
fi
source_root="$PWD"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/lldap-service-mutations.XXXXXXXX")
trap 'rm -rf "$scratch"' EXIT
for spec in \
  bot-marker-policy:test_create_service_user_refuses_non_bot_group_without_user \
  atomic-user-marker:test_create_service_user_membership_failure_rolls_back_all_rows; do
  label="${spec%%:*}"; behavior="${spec#*:}"
  copied="$scratch/$label"; mkdir "$copied"
  tar --exclude=./target --exclude=./.gate-cargo --exclude=./.gate-rustup \
      --exclude=./.git -cf - . | tar -xf - -C "$copied"
  (
    cd "$copied"
    export CARGO_TARGET_DIR="$copied/target"
    git apply --check "$source_root/scripts/mutations/$label.patch"
    git apply "$source_root/scripts/mutations/$label.patch"
    set +e
    cargo test --locked -q -p lldap_sql_backend_handler --lib "$behavior" > "$scratch/$label.log" 2>&1
    status=$?
    set -e
    [ "$status" -eq 101 ] && grep -Fq 'test result: FAILED.' "$scratch/$label.log" \
      && grep -Fq "$behavior" "$scratch/$label.log" || {
        cat "$scratch/$label.log"; printf '%s\n' "Mutation $label did not produce the required behavioral failure" >&2; exit 1;
      }
    printf '%s\n' "MUTATION_KILLED $label $behavior"
  )
done
