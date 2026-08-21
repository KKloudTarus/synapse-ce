# Operations drill evidence

[Documentation home](README.md) · Related: [Deployment](deployment.md) ·
[ADR 0007](https://github.com/KKloudTarus/synapse-ce/blob/main/docs/adr/0007-paired-backup-and-forward-only-upgrades.md)

This guide records a backup, restore, or rollback-on-copy drill without committing operational output,
credentials, topology, or customer data. The committed record is a redacted summary envelope, not the
drill's raw evidence.

## Envelope contract

Use [`operations-drill-evidence-v1.schema.json`](schemas/operations-drill-evidence-v1.schema.json). Its fixed
`schema_version` is `1.0`; a breaking change requires a new schema file and version, not an edit to the
meaning of this one.

Every envelope must include:

- an `OPS-DRILL-` prefixed `drill_id`, unique `run_id`, environment, and the runbook identifier,
  revision, and SHA-256;
- UTC start and completion timestamps plus an explicit execution-complete flag;
- every assertion's stable ID, whether it is required, its status, and a sanitized summary;
- a derived result and its matching deterministic rule; and
- at least one artifact manifest entry containing its stable ID, SHA-256, byte length, media type,
  redacted summary, and named sanitization reviewer.

The envelope contains no raw artifact path, database DSN, bucket name, access token, signed URL, IP
address, hostname, tenant identifier, account number, email address, or unredacted command output.

## Raw artifacts and committed summaries

Keep raw local artifacts in the approved restricted drill location. Examples include database backup
identifiers, object-store inventories, restore logs, command transcripts, and chain-verification output.
They may be retained under the applicable access and retention policy, but must be excluded from Git and
from review attachments unless a separately approved secure channel is used.

Before writing the committed envelope, calculate each raw artifact's SHA-256 and byte length. The hash
identifies the exact reviewed input without publishing its contents. Then replace the raw content with a
short factual `redacted_summary`: describe the check, whether it succeeded, and the relevant count or
version only when that value is safe to publish. A named reviewer records either `redacted` or
`no-sensitive-content-confirmed`. Sanitization is not optional because a hash is safe while surrounding
metadata and prose may not be.

## Deterministic result semantics

Set `result` from the recorded fields, never from a narrative judgement:

1. If `execution.complete` is `false`, the result is `inconclusive` with rule
   `execution-incomplete`.
2. Otherwise, if any required assertion is `failed`, the result is `failed` with rule
   `complete-and-a-required-assertion-failed`.
3. Otherwise, if every required assertion is `passed`, the result is `passed` with rule
   `complete-and-all-required-assertions-passed`.

A required `not-run` assertion therefore makes execution incomplete. Optional assertions may explain
follow-up work but never turn a completed passing required set into a failure. The schema enforces the
allowed result/rule combinations and the required-assertion conditions for passed and failed records.

A drill is successful only when the paired PostgreSQL and object-store copy restores in isolation and
the evidence and audit chains verify. A database-only restore, a raw-artifact hash without the raw
artifact, or a release rollback that uses down migrations is not a successful drill. See
[ADR 0007](https://github.com/KKloudTarus/synapse-ce/blob/main/docs/adr/0007-paired-backup-and-forward-only-upgrades.md).
