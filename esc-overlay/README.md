# Business package overlay

The current production direction is the reviewed-source
[package-diversion owner](ACTIVATION.md). It is not deployed. `prepare.py
--package-diversion` stages a fixed isolated-Python wrapper and reviewed release;
`activate.py` owns the exact diversion, created-file receipt and checked rollback.
Vendor units/drop-ins remain untouched and all original argv pass through.
Current package updates remain effective; a changed package/unit contract falls
back to the current vendor binary with atomic API PENDING. No nonatomic service
provisioning fallback exists. Future atomic-feature convergence is not claimed.

The earlier default staging mode generates a unit override with fixed baseline
arguments. It remains source-only and MUST NOT be used for production activation.
Its `runtime.py` refuses unit drift; the package-diversion runtime catches a
changed contract and safely passes the current unit's argv to the trusted current
vendor. Unsupported ownership or an unsafe vendor path still refuses execution.

Every staged directory has explicit modes independent of umask. Runtime/bundle
ancestor ownership, regular files and immutable modes are checked. The manifest
records desired file hashes/modes and directories; it establishes no ownership
of preexisting installed content. Only actual activation receipts can authorize
rollback deletion. Existing output, foreign diversions and unknown files are
never adopted.

Linux tests include a real isolated Debian package install/diversion/update
with changed unit arguments, API PENDING and current-package availability;
owned rollback; injected interruption recovery; PostgreSQL backup secrecy and
explicit retention; parent safety; and artifact/config selection. Run
`python3 esc-overlay/prove_guards.py` on the Linux runner: all tests plus independent
guard-removal mutations must pass. The separate private PostgreSQL17
native gate verifies real service creation/rollback/concurrent readback and a
consistent PostgreSQL custom archive. These are source/lab proofs, not deployed
coverage or credential/grant approval.
