# Source-owned package diversion activation — pending review and live proof

This supersedes the proposed unit override for production. The older staging
mode remains source-only. Production preparation uses `prepare.py
--package-diversion`: no vendor unit or drop-in is written. It stages the
reviewed binary, both runtime modules, config and an isolated-Python wrapper.

Debian's [dpkg-divert documentation](https://manpages.debian.org/trixie/dpkg/dpkg-divert.1.en.html)
defines LOCAL diversion for all package versions; explicit `--rename` refuses
an existing destination. The owner diverts `/usr/bin/lldap` to
`/usr/lib/lldap-esc/lldap.distrib` and places the wrapper at the original path.
The wrapper forwards every original argument unchanged, including arguments
from a future package unit. An unchanged verified baseline selects the reviewed
fork. New package bytes/version or unit/drop-in contract drift selects the
CURRENT trusted package executable, logging atomic API `PENDING`. No nonatomic
credential provisioning fallback exists. This preserves package availability;
it does not promise automatic future atomic-feature convergence.

`activate.py` is a root-only owner, not a generic arbitrary-file installer. It
requires the explicit reviewed bundle manifest digest, fixed release paths,
new destination files and no preexisting diversion. Runtime and bundle ancestor
ownership/modes are checked. It records created file device/inode/uid/mode/hash
and the exact LOCAL diversion. Rollback verifies the current matching wrapper
before interruption and again before deletion, then restores the CURRENT vendor
binary through the matching diversion. Release files and backups are retained;
there is no directory sweep, database restore or automatic cleanup.

## Target facts and backup decision still required

The deployment uses PostgreSQL, not the SQLite unit-test fixture. Native
config/process observations, exact endpoint/database and version readback are
kept in the private operational record. Native pg_dump/pg_restore must match
the actual server major version. Prior SQLite unit tests establish source behavior only. The mandatory
private PostgreSQL17 test covers marker policy, trigger-induced complete
rollback and concurrent-reader invisibility on the actual backend family.

The supported native config path is `/etc/lldap/lldap_config.toml`; the owner verifies the
running process actually names it and honors its existing `LLDAP_DATABASE_URL`
environment override if present. Native config ancestry is opened with anchored
no-symlink directory descriptors; its declared service UID must match both the
unit and running process. Root/service-owned configuration is preserved without
changing existing permissions. Group/world-writable authority refuses the read.
Preflight requires the reviewed PostgreSQL major17 and schema11; automatic
datastore migration is not authorized. Credential material stays in process memory
and child PG environment, never command arguments, receipts or diagnostics.
The consistent PostgreSQL custom archive is created exclusively0600. Its
incomplete inode/mode/path/retention receipt is fsynced before any sensitive
dump bytes; failed dump/readback states retain positive ownership and hashes.
Explicit versioned PostgreSQL17 tools prevent mixed-client wrapper selection,
and pg_restore list readback must pass. Unsupported DSN options fail closed.

A NEW exact backup path and explicit timezone-qualified future retention
deadline require operator approval. Retention approved for unrelated rollback
material does not authorize this backup. No default, timer or deletion is
introduced. The proposed directory is `/var/lib/lldap-esc/backups`; the final
filename includes the reviewed bundle digest. Its parent must already exist
as an approved root-owned safe directory before activation. No backup has been
created by this source preparation.

## Root orchestration and hard exit conditions

Before interruption, root revalidates the registered node/guest/pmxcfs binding
and existing independent raw-key parent-root→guest fallback in the private
preflight record. No guest key grant follows from the parent fallback.
Verify current native admin and LDAP controls before acting; refresh the actual
package, effective unit, drop-in contract, DB authority and host-key bindings.
Prepare the reviewed bundle and read its digest back. Source-owned `preflight_artifact.py`
checks final hash, x86_64/GLIBC and installed libraries without executing the
artifact. Only explicit `--execute-version` executes hash-checked sealed-memory
bytes with `--version`; it never starts a service or writes config.

Activation journals intent, stages immutable release files, masks only
`lldap.service` at runtime, stops it, verifies intentional-off, creates the
approved consistent backup, registers the exact diversion and creates the
wrapper without clobbering. It unmasks/starts that same service and requires it
active. Any handled failure restores the baseline package path and availability
or fails loudly with the retained owner receipt for the independently verified
fallback. A process kill or host failure can require owner receipt reconciliation;
this is not a claim of cross-process crash-atomicity. Never clear an unknown
mask/diversion or delete an unrecorded path to force recovery.

Service-active is `active_pending_authenticated_controls`. Root must run real
native admin/LDAP and new GraphQL allowed/denied/atomic marker controls before
creating the three approved nonhuman identities or issuing any credentials.
A failed control invokes the owned rollback. The backup is not restored over
later directory changes. All users, memberships/history and existing schema are
preserved. No key, grant, cadence, timeout or unrelated service changes here.

## Reproducible reviewed build

Gate payloads have no Git metadata. `scripts/run-verified-activation-build.sh`
fetches the explicit reviewed commit from the fixed owning repository into a
NEW checkout. The owning build script requires clean index/worktree/untracked
state and exact actual Git-tree equality before output or compilation. It
records commit/tree from Git, hashes every tracked input and retains full native
workspace, private PostgreSQL, backup, Python and mutation logs beside the Linux
artifact/schema/checksums. Caller text alone cannot establish source attribution.
