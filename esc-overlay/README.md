# Business package overlay — staging source only

This single staging overlay leaves the installed executable and unit untouched.
It is not an availability-preserving activation mechanism.
`runtime.py` selects a reviewed immutable release only while the installed
package version AND binary digest match the reviewed baseline. Only with the same explicitly pinned vendor unit and drop-in filename/hash set,
a changed package binary/version or unsafe candidate selects the current package
binary with atomic-API `PENDING`. Unit/drop-in additions, removal or content drift,
untrusted ancestry, or an unavailable trusted unit contract refuse execution.
There is no availability promise across unit drift. It never calls
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
version/digest, vendor unit SHA256, explicit drop-in filename/hash JSON map
(`--baseline-dropins-manifest`) and a NEW staging output directory. It captures the checked
artifact bytes, writes the versioned desired file tree and named unit drop-in,
and emits a desired-files digest/mode manifest including explicit directory
modes. The staging root is0700; every internal directory is0755 independent of
umask. Symlink or unsafe staging ancestors are refused. Existing output and symlinks
are refused. It creates no service, account, key, timer, grant or live file.

The generated drop-in clears only `ExecStart`, then invokes the owner runtime
under the baseline unit's existing user, working directory and other properties.
The runtime accepts no caller arguments. Runtime executable/config/unit ancestors
must be root-owned directories without group/world write access. Fixed service
drop-in directories are compared against the recorded map, excluding only this
overlay's exact named drop-in. An overriding `/etc` or `/run` unit fragment refuses
startup. Activation must verify that this supported package-unit layout really
represents the effective target command; unsupported systemd search paths or
configuration are not silently adopted. Configuration allows exactly six
version/hash/drop-in contract fields; callers cannot supply an executable path.

Tests: `python3 -m unittest discover -s esc-overlay -p 'test_*.py' -q` — fifteen tests. `python3 esc-overlay/prove_guards.py` additionally
requires four independent guard-removal mutations to fail behaviorally. They exercise package upgrades/content changes,
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
