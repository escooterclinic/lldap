# Business package overlay — staging source only

This single overlay preserves the packaged LLDAP executable and original unit.
`runtime.py` selects a reviewed immutable release only while the installed
package version AND binary digest match the reviewed baseline. If the vendor
package changes, configuration is unknown or the candidate is unsafe, it selects
the current packaged executable and logs atomic-API `PENDING`. It never calls
legacy `createUser` as a fallback for service provisioning. Even selecting the
reviewed fork reports `PENDING_LIVE_PROOF`, not global readiness.

The existing native command remains `run --config-file
/etc/lldap/lldap_config.toml`. This is the inspected deployment's command, not a
promise about uninspected future package-unit arguments. The package manager,
updater script, existing unit properties/drop-ins and auth database are not
modified. A future unit/configuration change requires fresh owner review.
Automatic future convergence of the new atomic API is NOT delivered here.

## What the source does

`prepare.py` accepts an explicit reviewed artifact digest, baseline package
version/digest and a NEW staging output directory. It captures the checked
artifact bytes, writes the versioned desired file tree and named unit drop-in,
and emits a desired-files digest/mode manifest. Existing output and symlinks
are refused. It creates no service, account, key, timer, grant or live file.

The generated drop-in clears only `ExecStart`, then invokes the owner runtime
under the baseline unit's existing user, working directory and other properties.
The runtime accepts no caller arguments. Configuration allows exactly its four
version/hash fields; callers cannot supply an executable path.

Tests: `python3 -m unittest discover -s esc-overlay -p 'test_*.py' -q` — ten
passed on the Linux runner. They exercise package upgrades/content changes,
unsafe or symlinked candidates/configuration, fixed argv, exact staging hashes,
existing-output preservation and no activation. Fixture modes are explicit so
the runner's group-write umask cannot change the intended safety predicate.

## Activation and rollback are NOT implemented by the staging helper

This overlay is pending independent Python/security review and a source-owned
activation/rollback implementation. Do not copy it into production as an ad hoc
fix. The staging manifest describes intended files; it does NOT establish
ownership of existing installed files or authorize their deletion.

The root orchestrator must first merge/gate the reviewed source, rebuild the
exact final source and verify the final artifact/schema hashes, target ABI and
safe target `--version`. Revalidate actual package/unit/updater metadata,
canonical registered node/guest/pmxcfs binding and an independently working
parent-root-to-guest fallback. No guest key grant follows from that fallback.

Only after those proofs may the owner activation path record actual created
file identities/digests, mask/stop the service, install the versioned release
and named drop-in, reload and restore availability as a hard exit condition.
Capture ownership before any later rollback delete; never delete by a directory
prefix or a staging filename alone. Rollback removes only positively owned
unchanged overlay files and returns to the package path, preserving directory
users, credentials, memberships/history and schema. It does not restore the
database over unrelated changes or enable people.

The final native admin/LDAP human controls and isolated atomic-creation
allowed/denied controls remain required. Every credential provisioner must
require the new atomic mutation and committed Bot marker; pending capability
must never trigger nonatomic user creation. No new cadence, timeout, retention
or grant is configured by this overlay.
