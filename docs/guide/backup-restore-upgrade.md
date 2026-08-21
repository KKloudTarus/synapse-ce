# Backup, restore, and v0.1.8-to-current upgrade runbook

This runbook starts from a deliberately seeded and running v0.1.8 baseline, preserves a paired backup of that baseline, and performs a gated forward upgrade to the current branch. It is an operator procedure for the paired PostgreSQL database and evidence object store. It intentionally does not cover an active-write backup. Synapse reports rely on rows and evidence objects together; a database snapshot taken before or after its matching object state can be incomplete even when each individual command succeeds.

The wrappers in `deploy/operations/recovery/` are deliberately conservative:

- They perform a dry run unless `--execute` is passed.
- They require a literal confirmation token for a quiesced backup, fresh isolated restore, or forward upgrade.
- They accept connection strings only through the *name* of an already exported environment variable. Do not put a DSN, password, access key, account identifier, or other credential on a command line, in shell history, or in a ticket.
- They do not use object deletion, object overwrite, `pg_restore --clean`, or `pg_restore --create`.
- They never run down migrations, destroy a source database, delete a source bucket, or stop services. Quiescing and lifecycle changes remain deliberate operator actions outside the wrappers.

Run commands from the repository root with a Bash implementation that provides `sha256sum`, `pg_dump`, `pg_restore`, `psql`, and the MinIO `mc` client. Use a PostgreSQL client compatible with the server version. `mc` is used because its default mirror behavior does not delete target-only objects; the wrappers also omit `--remove` and `--overwrite`.

## Safety model and supported consistency boundary

The supported backup consistency boundary is **fully quiesced writes**. Before collecting data, stop or drain every writer that can change Synapse state, including API instances, workers, migrations, scheduled jobs, import jobs, and any automation calling the API. Confirm that no writer remains and retain the change record that authorizes the outage. The wrapper requires `BACKUP-QUIESCED`, but the token is an acknowledgement, not a technical proof.

An **active-write backup is unsupported** by this runbook. `pg_dump` creates a transactionally consistent database archive, but it cannot make a separately copied object store point-in-time consistent with that archive. Do not claim that a backup taken while writers are active is recoverable as a paired Synapse state. If an active-write recovery objective is required, design and validate a provider-native coordinated snapshot, write fencing, and an application-specific reconciliation procedure before using it in production.

Keep the backup directory on storage distinct from the system being protected and limit access to approved operators. The wrappers set `umask 077`, but filesystem and object-store retention, encryption, immutability, and access controls are still operator responsibilities.

## 1. Establish the v0.1.8 baseline

Obtain approved v0.1.8 release artifacts and separately approved current-branch artifacts. Independently record and verify the SHA-256 digest of each v0.1.8 and current migrator and service artifact that will run. Do not reuse a digest between releases or artifacts. Create an isolated database with separate owner-level migration and runtime credentials. Run the verified v0.1.8 migrator against the empty database with automatic migration disabled, then start only verified v0.1.8 service artifacts. Confirm readiness and a representative evidence/report path before declaring the environment the baseline.

## 2. Create a quiesced paired baseline backup

1. Select a new, empty, absolute backup directory on protected storage. Its parent must already exist. A failed attempt can leave a partial directory; do not treat it as a backup and do not overwrite it.
2. Export the database DSN in the operator's environment. The following uses a placeholder name only; it does not show a credential.
3. Configure an authenticated `mc` alias outside these commands. Pass the source bucket or prefix as an `mc` source reference.
4. Quiesce all writers and record the authorization and start time.
5. First inspect the dry run, then execute with the exact confirmation token.

```bash
export SYNAPSE_BASELINE_DB_DSN='set-this-outside-command-history'

deploy/operations/recovery/backup.sh \
  --backup-dir /secure/backups/synapse/v0.1.8-baseline-YYYYMMDDTHHMMSSZ \
  --pg-dsn-env SYNAPSE_BASELINE_DB_DSN \
  --object-source baseline-evidence-alias/synapse-evidence

# Only after all v0.1.8 baseline writers are quiesced:
deploy/operations/recovery/backup.sh \
  --backup-dir /secure/backups/synapse/v0.1.8-baseline-YYYYMMDDTHHMMSSZ \
  --pg-dsn-env SYNAPSE_BASELINE_DB_DSN \
  --object-source baseline-evidence-alias/synapse-evidence \
  --quiesced-confirmation BACKUP-QUIESCED \
  --execute
```

The backup contains:

- `database.dump`: a PostgreSQL custom-format archive from `pg_dump`.
- `objects/`: evidence objects copied with `mc mirror`, without deletion or overwrite options.
- `BACKUP-METADATA.txt`: format, timestamp, and client version evidence.
- `MANIFEST.sha256`: SHA-256 hashes for `database.dump` and every copied object.

A manifest matches only the files captured in that backup directory. Record the immutable backup location, manifest, quiesce authorization, source database/object-store identifiers in the protected change record, and the wrapper output. Do not place protected identifiers or credentials in this guide or source control. Resume writers only after the backup operation and its evidence capture have completed.

## 3. Restore to a fresh isolated environment

Restore is a recovery rehearsal or investigation step, not an in-place repair procedure. Create a separate non-production environment with network isolation, distinct credentials, and an application configuration that cannot contact production. Create the destination database and empty destination object-store bucket or prefix before running the wrapper.

The restore wrapper verifies `MANIFEST.sha256` before it writes anything, rejects a database containing user tables, and rejects a non-empty object target. It restores with `pg_restore --single-transaction --exit-on-error --no-owner --no-privileges`; it neither cleans nor creates a database. It mirrors objects without deletion or overwrite options. If an object appears in the target during execution, stop and investigate rather than retrying over it.

```bash
export SYNAPSE_RESTORE_DB_DSN='set-this-outside-command-history'

deploy/operations/recovery/restore.sh \
  --backup-dir /secure/backups/synapse/v0.1.8-baseline-YYYYMMDDTHHMMSSZ \
  --target-pg-dsn-env SYNAPSE_RESTORE_DB_DSN \
  --object-target isolated-baseline-evidence-alias/synapse-evidence-restore

# Only for the new, isolated, empty targets:
deploy/operations/recovery/restore.sh \
  --backup-dir /secure/backups/synapse/v0.1.8-baseline-YYYYMMDDTHHMMSSZ \
  --target-pg-dsn-env SYNAPSE_RESTORE_DB_DSN \
  --object-target isolated-baseline-evidence-alias/synapse-evidence-restore \
  --fresh-target-confirmation RESTORE-TO-FRESH-ISOLATED-TARGET \
  --execute
```

After a successful restore, start Synapse only with isolated non-production configuration. Validate a baseline rehearsal with separately digest-verified v0.1.8 compatibility artifacts, application readiness, and a representative evidence/report path. Capture the manifest-verification output, database restore output, object-copy output, readiness result, and validation results as recovery evidence. Do not point restored services at production endpoints or credentials.

## 4. Forward upgrade from v0.1.8 to current

Use the current branch's verified synapse-migrate binary, not the v0.1.8 migrator. The wrapper verifies the paired baseline backup manifest and separately verifies the v0.1.8 baseline and current migrator digests. The baseline binary is verified as provenance evidence only; the wrapper executes only the current migrator with SYNAPSE_DB_AUTO_MIGRATE=false, applying current embedded forward migrations only.

1. Confirm the seeded, running v0.1.8 baseline and its verified artifacts are recorded.
2. Preserve the quiesced paired baseline backup using the preceding procedure.
3. Quiesce writers again for the upgrade window.
4. Dry-run and compare the baseline backup, both binary paths, matching digests, and environment-variable names with the change plan.
5. Execute with all literal confirmations.
6. Deploy only separately digest-verified current service artifacts with automatic migration disabled, then run readiness checks.

Example dry run and execution use separately verified baseline and current migrators:

```bash
export SYNAPSE_RUNTIME_DB_DSN='set-this-outside-command-history'
export SYNAPSE_MIGRATION_DB_DSN='set-this-outside-command-history'

deploy/operations/recovery/forward-upgrade.sh \
  --backup-dir /secure/backups/synapse/v0.1.8-baseline-YYYYMMDDTHHMMSSZ \
  --baseline-migrator /approved-artifacts/v0.1.8/synapse-migrate \
  --baseline-expected-sha256 APPROVED_V0.1.8_MIGRATOR_64_CHARACTER_SHA256 \
  --current-migrator /approved-artifacts/current/synapse-migrate \
  --current-expected-sha256 APPROVED_CURRENT_MIGRATOR_64_CHARACTER_SHA256 \
  --runtime-pg-dsn-env SYNAPSE_RUNTIME_DB_DSN \
  --migration-pg-dsn-env SYNAPSE_MIGRATION_DB_DSN

# Only after writers are quiesced, the baseline is verified, and the change is approved:
deploy/operations/recovery/forward-upgrade.sh \
  --backup-dir /secure/backups/synapse/v0.1.8-baseline-YYYYMMDDTHHMMSSZ \
  --baseline-migrator /approved-artifacts/v0.1.8/synapse-migrate \
  --baseline-expected-sha256 APPROVED_V0.1.8_MIGRATOR_64_CHARACTER_SHA256 \
  --current-migrator /approved-artifacts/current/synapse-migrate \
  --current-expected-sha256 APPROVED_CURRENT_MIGRATOR_64_CHARACTER_SHA256 \
  --runtime-pg-dsn-env SYNAPSE_RUNTIME_DB_DSN \
  --migration-pg-dsn-env SYNAPSE_MIGRATION_DB_DSN \
  --quiesced-confirmation UPGRADE-QUIESCED \
  --baseline-confirmation BASELINE-V0.1.8-VERIFIED \
  --forward-upgrade-confirmation UPGRADE-FROM-V0.1.8-TO-CURRENT \
  --execute
```

Do not run a down migration. Do not remove migration records, edit migration files, or attempt to make a newer database appear older. The deployed current service configuration must keep SYNAPSE_DB_AUTO_MIGRATE=false; production migration authority belongs to the separate owner-level migration credential.

## 5. Rollback rehearsal and recovery

There is no in-place rollback. Test rollback only by restoring the pre-upgrade paired v0.1.8 baseline backup to a fresh isolated copy. Validate that copy with separately digest-verified v0.1.8 compatibility artifacts or as a pre-upgrade restore under an approved recovery plan. Never restore over the upgraded production database or production evidence bucket, and never use down migrations as a rollback mechanism.

Before any cutover decision, preserve the upgraded state as separate evidence, identify the data-loss window, and obtain incident/change authorization. The restored copy can establish recoverability and support investigation; it is not authorization to destroy, overwrite, or replace a production source.

## Operational evidence checklist

For each baseline seed, backup, restore rehearsal, forward upgrade, or rollback decision, retain access-controlled evidence outside the source tree:

- change/incident authorization and operators involved;
- baseline v0.1.8 seed/readiness record and separately approved baseline artifact digests;
- separately approved current migrator and service-artifact digests;
- writer-quiescence record and start/end times;
- backup directory location and `MANIFEST.sha256` result;
- dry-run and execution output with secrets redacted;
- isolated restore validation and readiness results; and
- explicit confirmation that no down migration, source destruction, or in-place restore occurred.
