# Production-shaped field validation

`make field-validation` is a network-free regression gate. It records the
capability manifest, environment metadata, pipeline benchmark, thresholds, and
checksums. It is not evidence that an authorized production engagement has
been validated.

## Required authorized validation record

For every release candidate, create a private record that contains no customer
targets, credentials, response bodies, or evidence values. Record only:

- release version, commit, artifact checksum, operating system, and datastore;
- authorized environment class (small, medium, or large), network conditions,
  and enabled profile;
- target count, elapsed time, peak process memory, datastore growth, retries,
  module failures, and verified/heuristic finding counts;
- restart/resume, retention/purge, credential-rotation, and backup/restore
  exercise outcomes; and
- the operator, authorization reference, timestamp, and approval decision.

## Release thresholds

A candidate fails the validation gate when any of the following is true:

- a scan finishes with an unacknowledged module failure;
- restart/resume loses evidence or creates duplicate evidence;
- a recovery drill cannot restore and migrate a separate recovery database;
- the synthetic pipeline gate fails its recorded time, allocation, or memory
  ceiling; or
- an authorized field run exceeds its approved request, concurrency, storage,
  retry, or duration budget without a documented approval.

Keep sanitized summaries and benchmark artifacts with the release evidence.
Do not add live target data to this repository.

## PostgreSQL recovery drill

Use the separate [PostgreSQL recovery runbook](postgres_recovery.md). The
script only acts when the source and target DSNs differ, the target name
contains `recovery`, and `ENUMSCAN_RECOVERY_CONFIRM=RESTORE_ENUMSCAN_RECOVERY`
is set. It never prints either DSN.
