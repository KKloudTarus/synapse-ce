# Finding ownership and team routing

[Documentation home](README.md)

Finding ownership routes each canonical finding to one accountable Synapse team,
shows the evidence behind that choice, and preserves human triage decisions across
rescans. It can use ordered policy rules, a trusted CODEOWNERS snapshot, or an
explicit business-asset mapping. It never guesses a team from names, email
addresses, folders, package cache paths, or free-text asset owners.

## Enable ownership

Apply database migrations before deploying the new API and worker binaries. Both
processes need the same PostgreSQL database and ownership mode:

```text
SYNAPSE_DB_DSN=postgres://...
SYNAPSE_OWNERSHIP_MODE=observe
SYNAPSE_WORKER_PROFILE=all
```

`off` is the default and leaves existing finding behavior unchanged. `observe`
evaluates new and changed findings and makes preview available without applying
automatic assignments. After reviewing results, set the mode to `enforce` on both
API and worker to permit automatic assignment, historical reroute, and
release-to-auto. Memory storage cannot provide durable ownership and reports
`postgres_required` through the capability endpoint. The `all` worker profile is
required for source scan capture and notification delivery. The data-only
`lifecycle` profile can dispatch and consume ownership routing jobs without a tool
sandbox, which supports a separate routing worker deployment.

Open **Settings → Finding ownership** to configure teams and policies. The
**Ownership Inbox** in Security operations shows routed, manually owned and
unresolved findings. Team membership groups existing users; it grants no role or
engagement access. Only administrators change teams, mappings, snapshots, policies
and runs. Existing human triage roles can claim, assign, transfer, clear and release
findings they are authorized to see.

## Configure a trusted policy

1. Create active teams and add existing users. A disabled user or archived team
   cannot receive a new assignment.
2. Add exact repository/CODEOWNERS-token mappings, such as
   `github.com/acme/payments + @acme/payments → Payments`. Tokens are case-sensitive
   evidence; there is no SCM directory lookup.
3. Add explicit business asset mappings when non-source findings should fall back
   to an accountable team. The asset's free-text `owner` is never treated as an ID.
4. Review a scan-captured CODEOWNERS snapshot. Verify its repository, immutable
   `git:` or `sha256:` revision, exact content hash, file content and parser
   diagnostics before approval. Approval creates another immutable snapshot.
5. Create a policy version. Ordered rules run first; lower numeric priority wins.
   Conditions are ANDed across fields and ORed within a field. A rule either names
   one active team or explicitly excludes matching findings.
6. Run preview and inspect each result and its path evidence. Activate the reviewed
   version for future or changed findings. Activation advances the policy fence, so
   run a fresh preview afterward and start historical reroute from that exact
   completed preview.

Mapping edits do not rewrite an existing immutable policy version. Saving the next
version freezes the currently listed token and asset mappings. Repository-specific
active policies take precedence over the engagement fallback policy. Activation
uses policy revision and content hash checks, so a stale browser cannot activate
different content.

## Trust and source coverage

Git scans capture head and base CODEOWNERS from exact object IDs before temporary
workspace cleanup. A pull request that changes CODEOWNERS cannot grant itself a new
owner: routing requires the approved base revision. Archive/image input uses its
immutable digest and remains untrusted until an administrator approves the exact
snapshot. The worker never rereads a branch or mutable checkout while routing.

| Canonical finding | Evidence used |
| --- | --- |
| SAST, secret and IaC | Normalized repository-relative paths from the exact scan source |
| SCA | Application manifests and introducing direct-dependency paths from the exact scan; all relevant paths are combined |
| DAST, network, CSPM and manual | Explicit policy rule or business-asset mapping |
| Imported SBOM | Explicitly records that trusted application source is unavailable; asset/rule fallback may apply |
| Standalone project issue/import | No ownership until a verified canonical finding binding exists |

Source publication is two-phase. The scan stores immutable source and finding
bindings first, then marks the source ready only after canonical finding and
vulnerability projections complete. The dispatcher ignores incomplete sources.
Overlapping scans are ordered by capture sequence, so a late older completion
cannot replace a newer binding.

The CODEOWNERS parser uses `.github/CODEOWNERS`, `CODEOWNERS`, then
`docs/CODEOWNERS`, with the first existing file selected and the last matching line
winning. Paths are case-sensitive. Empty-owner lines are explicit exclusions.
Unsupported negation, bracket ranges and escaped leading comments produce visible
diagnostics; they are never silently ignored during approval.

Common unresolved reasons include:

| Reason | Operator action |
| --- | --- |
| `missing_source_binding` | Confirm the producer supports source capture and let its projection finish. |
| `invalid_path` | Fix the producer's repository-root/path mapping; absolute paths and traversal are rejected. |
| `missing_trusted_base_snapshot` | Import or approve the exact base CODEOWNERS revision. Do not approve a PR head as its base. |
| `unmapped_owner` | Map every owner token on the matching CODEOWNERS line. Partial mapping stays unresolved. |
| `ambiguous_owners` | Align mappings or add an explicit rule; Synapse will not choose the first team. |
| `no_matching_owner` | Add an explicit rule, CODEOWNERS mapping, or asset mapping if ownership is known. |
| `unsupported_source` | Use an explicit rule/asset mapping or retain the finding for manual triage. |
| `manual_protected` | The human assignment is authoritative. Use release-to-auto only when that is intended. |

## Triage and notification behavior

Claim assigns the current user and requires membership in the active owning team.
Transfer preserves an eligible assignee; otherwise choose a replacement or
explicitly clear the individual. Clear removes the team/person but keeps manual
protection. Release removes that protection and creates a fresh durable routing
obligation. Rescans and stale workers cannot overwrite a manual assignment.

Bulk updates process at most 200 unique findings independently. Successful rows
remain committed and conflicts stay selected in the UI for review. Retry a network
failure with the same body and idempotency key; use a new key after changing input.

To notify teams, enable the [notification framework](notifications.md), create a
rule for `finding.ownership_changed`, and select explicit team IDs or all teams.
Transfers match both old and new teams. One effective assignment transition creates
one immutable decision and one notification source intent in the same transaction.
Disabled notifications record a suppressed intent that is not replayed later.

## Recovery and operations

The worker freezes at most 100 ownership inputs per durable job, resolves them in
batches of 50, and commits each finding behind current lease, policy, source,
finding, ownership and manual-generation fences. API or worker restart preserves
run progress. Queue retry uses the platform's exponential backoff. A worker paused
in observe mode returns enforce work as retryable rather than marking it complete.

If retries exhaust, the run is `failed` and the queue job is dead-lettered. Fix the
database, policy, or worker cause, open the run in Routing policies and choose
**Replay dead-lettered run**. Replay requires the current run revision and the same
active policy; it reuses the frozen selection. Cancel stops queued/running run work
without deleting its evidence.

Monitor queue age, failed ownership runs, conflicts, unresolved reason counts and
suppressed notification intents. Do not put finding IDs, user email, owner tokens
or raw paths in metric labels. Back up ownership tables with the rest of PostgreSQL;
immutable snapshots, decisions and run results are required to explain history.

## Limits and measured scale

V1 limits CODEOWNERS content to 3,000,000 bytes, 20,000 patterns, 100 owners per
line and 128 relevant paths per finding. A policy accepts at most 200 rules and 200
conditions per rule. Inbox/admin bulk pages are bounded at 200; automatic jobs are
bounded at 100. V1 does not implement SCM organization sync, GitLab sections,
round-robin/on-call assignment, ticketing, workload balancing, or owner prediction.

The opt-in PostgreSQL acceptance fixture is
`TestOwnershipRepresentativeScale` (`SYNAPSE_OWNERSHIP_SCALE_TEST=1`). On
2026-09-12 it routed 10,000 new SAST findings through a worst-case 200-rule policy
on PostgreSQL 18.6/Windows x86-64 in 48.33 seconds using 101 bounded jobs. The Go
heap peaked at 14,311,248 bytes; cumulative allocation was 3,538,800,744 bytes and
the pgx tracer counted 256,565 SQL statements. The statement count includes the
intentional per-finding fenced transaction, audit append and progress commit;
policy and snapshot compilation are cached per job, dispatcher selection/deletion
is batched, and no transaction contains the full dataset. These figures describe
this development host and are a regression reference, not a capacity guarantee.

See the [HTTP API contract](../ownership-api.md) for pagination, optimistic
concurrency, idempotency and endpoint details.
