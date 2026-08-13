# AI false-positive triage evaluation

Synapse evaluates AI false-positive triage on a versioned, human-reviewed, non-production dataset before
an operator enables gate automation. Evaluation uses the same proposer, verifier, typed DTO, confidence
threshold, human-review floors, and deterministic policy as a scan. The only policy difference is forced
shadow mode: `would_gate_exempt` is measured, while `gate_exempt` must remain `false`.

The repository includes three offline AI-triage data/evaluation commands:

| Binary | Role |
| --- | --- |
| `synapse-fptriage-eval` | Run the versioned AI false-positive evaluation harness |
| `synapse-fptriage-curate` | Curate human review outcomes into privacy- and label-reviewed evaluation data |
| `synapse-fptriage-drift` | Compare production input distribution with a human-approved baseline |

## Golden dataset

The seed dataset is stored at
`internal/usecase/sca/testdata/fptriage-golden-v1.json`. Its schema requires:

- dataset schema version, dataset version, provenance, and reviewer;
- a unique case ID and human label (`true_positive`, `false_positive`, or `uncertain`);
- language, finding kind, CWE, severity, and framework dimensions;
- synthetic or explicitly approved source context; and
- adversarial cases that place prompt-injection text inside the untrusted source data.

Dataset validation fails before any model call if review metadata, dimensions, context, or labels are
missing. Do not copy production findings or source into the repository fixture.

## Curate human reviewer feedback

Human Accept/Reject outcomes can seed a separate evaluation dataset, but they never update production
thresholds, prompts, models, or gate policy automatically. The feedback path is offline and pull-based:
the existing review decision remains the source of truth, and an operator explicitly curates selected
outcomes into an evaluation file.

Export the tenant-scoped response from `GET /api/v1/ai-triage/reviews` to a local `reviews.json`. Keep this
file outside the repository: it contains production review metadata. Prepare a local curation manifest
using schema `synapse-ai-triage-feedback-curation-v1`. Each selected case identifies one decided review
and supplies only the source/context intended for evaluation use:

```json
{
  "schema_version": "synapse-ai-triage-feedback-curation-v1",
  "dataset_version": "feedback-2026-08-12",
  "provenance": "privacy-approved reviewer feedback batch",
  "curator": "dataset-curator",
  "cases": [
    {
      "review_id": "<review-id>",
      "label": "false_positive",
      "language": "go",
      "framework": "net/http",
      "kind": "sast",
      "title": "Sanitized reproduction title",
      "description": "Approved minimal reproduction",
      "file": "curated/example.go",
      "line": 7,
      "source": "package curated\n",
      "privacy_review": {
        "reviewer": "privacy-reviewer",
        "approved": true,
        "rationale": "approved redacted context",
        "reviewed_at": "2026-08-12T12:00:00Z",
        "reviewed_sha256": "<digest>"
      },
      "label_quality_review": {
        "reviewer": "label-auditor",
        "approved": true,
        "rationale": "label matches reviewed outcome",
        "reviewed_at": "2026-08-12T12:05:00Z",
        "reviewed_sha256": "<same-digest>"
      }
    }
  ]
}
```

Compute the exact digest reviewers must approve before filling the two `reviewed_sha256` fields:

```bash
go run ./cmd/synapse-fptriage-curate \
  --reviews reviews.json \
  --manifest feedback-curation.json \
  --print-review-digests
```

The approval digest is fail-closed over the complete exported review snapshot, including tenant,
engagement/finding identity, sealed evidence reference, decision actor/timestamps/version, model/provider,
prompt, policy, finding metadata, and the decision rationale via the snapshot hash. It also binds the
manifest header (`schema_version`, `dataset_version`, `provenance`, and `curator`) and the exact curated
label, dimensions, title/description, file/line, adversarial flag, and source hash. Changing any of those
values after approval invalidates both approvals.

Privacy and label-quality approval are both mandatory and must be performed by distinct human reviewers.
The label-quality reviewer must also differ from the original reviewer who made the Accept/Reject decision.
Machine principals (`agent:`, `llm:`, `mcp:`, `system:`, `machine:`, `bot:`, and `service:` identities) are
rejected using the same domain predicate that protects the human review lifecycle, and the original decision
actor is revalidated as neither a machine principal nor the proposer/verifier model identity. The manifest is
deliberately local: approval identities and rationale stay in the curation record and are not copied verbatim
into the evaluation dataset. Reviewer names in this offline manifest are process provenance, not cryptographic
identities; run curation only in a controlled workflow that authenticates and records the humans responsible
for those approvals.

An accepted AI false-positive recommendation may become `false_positive`; a rejected recommendation may
become `true_positive`. A label-quality auditor may conservatively downgrade either outcome to
`uncertain`, but cannot reverse it into the opposite label. Pending reviews, reviews without sealed
evidence, impossible decision lifecycle metadata, contradictory labels, missing approvals, stale approval
digests, changed manifest metadata, changed source, machine approvers, and machine/model decision actors all
fail closed.

After both approvals are recorded, materialize the evaluation dataset explicitly to a **new private file**:

```bash
go run ./cmd/synapse-fptriage-curate \
  --reviews reviews.json \
  --manifest feedback-curation.json \
  --output curated-feedback.json
```

Dataset materialization intentionally refuses stdout because approved source may still be
production-derived and terminal/CI logs are not a privacy boundary. The curator also refuses to replace
an existing file, symlink, review export, or manifest. It writes and syncs a mode-`0600` temporary file in
the destination directory and publishes it with an atomic create-only filesystem link, so an existing
path is never followed or truncated. Once that link succeeds, publication is considered successful;
cleanup of the temporary link is best effort and cannot turn a successfully published dataset into a
reported materialization failure. Choose a fresh output path for each materialized dataset.

The generated dataset uses opaque digest-derived case IDs and does not copy raw tenant IDs, review IDs,
evidence references, decision rationale, or local provenance text into the evaluation file. It does
contain the explicitly approved source/context, so treat it according to the approved data-handling
policy and do not commit a production-derived dataset to the repository fixture by default. The dataset
provenance includes a hash of the complete curation manifest so the evaluated file can be tied back to
the reviewed local curation record.

Use the resulting file only as an explicit evaluation input. Nothing in this workflow changes runtime
behaviour:

```bash
go run ./cmd/synapse-fptriage-eval \
  --dataset curated-feedback.json \
  --output ai-triage-feedback-eval.json
```

## Run an evaluation

Configure the same OpenAI-compatible endpoint used by Synapse and two distinct model IDs:

```bash
export SYNAPSE_LLM_BASE_URL=http://localhost:20128/v1
export SYNAPSE_LLM_API_KEY=...
export SYNAPSE_LLM_PROVIDER=openai
export SYNAPSE_FP_TRIAGE_MODEL=<proposer-model>
export SYNAPSE_FP_TRIAGE_PROVIDER=openai
export SYNAPSE_VERIFIER_BASE_URL=https://verifier.example/v1
export SYNAPSE_VERIFIER_API_KEY=...
export SYNAPSE_VERIFIER_PROVIDER=anthropic
export SYNAPSE_VERIFIER_MODEL=<verifier-model>
export SYNAPSE_FP_TRIAGE_INDEPENDENCE=provider

make ai-triage-eval
```

Use `AI_EVAL_DATASET` and `AI_EVAL_OUTPUT` to override the Make defaults, or invoke the command directly:

```bash
go run ./cmd/synapse-fptriage-eval \
  --dataset internal/usecase/sca/testdata/fptriage-golden-v1.json \
  --output ai-triage-eval.json
```

The verifier must remain distinct after model-family canonicalization. `model_family` policy permits the
same transport/provider with a different family; `provider` policy additionally requires complete and
different explicit provider identities. It runs before the proposer result exists and receives only the
finding plus source context, so the proposer verdict cannot anchor its assessment. Both calls use
temperature zero. A provider failure, invalid response, missing identity, missing verifier, or incomplete
consensus remains covered as a non-exemption; no error path grants gate authority.

## Report contract

The `synapse-ai-triage-evaluation-v2` JSON report identifies the dataset, proposer/verifier providers and model families, independence
policy, prompt version, and gate-policy version. It records every case beside its human label and emits:

- precision and recall of verified false-positive consensus;
- false-negative escape rate (human true positives the deterministic policy would exempt);
- proposer/verifier disagreement rate;
- model-response coverage; and
- breakdowns by language, finding kind, CWE, severity, and framework.

`dataset_sha256` binds the report to the canonical dataset content, and `run_id` is a SHA-256 digest of
that dataset identity, version metadata, and ordered decisions. The report has no wall-clock field, so
the same dataset and deterministic replies produce the same identifier. CI tests load the
versioned fixture without production data, verify the metric calculations, and assert that shadow mode
cannot produce `gate_exempt`.

The report is evidence for PM/Security threshold approval; it does not approve a model automatically.
Keep `SYNAPSE_FP_TRIAGE_MODE=shadow` until the threshold and dataset are approved for canary rollout.

## Detect production distribution drift

The tenant-scoped observability response includes a source-free `distribution` snapshot. It counts the
latest stored scan for each visible project and normalizes language, CWE, and project shares to exactly
10,000 basis points. Language byte percentages are weighted by the number of AI-triaged findings in that
scan; missing language and CWE metadata are explicit as `unknown` and `unclassified` rather than silently
dropped.

Save a current response without committing it to the repository:

```bash
curl -H "Authorization: Bearer $SYNAPSE_TOKEN" \
  "$SYNAPSE_API_URL/api/v1/ai-triage/observability" \
  > ai-triage-observability.json
```

Create a reviewed baseline by copying a trusted snapshot into this versioned envelope. The approver must
be a human identity; reserved machine principals fail validation.

```json
{
  "schema_version": "synapse-ai-triage-drift-baseline-v1",
  "version": "production-2026-08",
  "provenance": "security/review-42",
  "approved_by": "security@example.com",
  "minimum_samples": 50,
  "maximum_total_variation_basis_points": 1000,
  "distribution": {
    "schema_version": "synapse-ai-triage-distribution-v1",
    "sample_size": 100,
    "language_basis_points": {"go": 6000, "typescript": 4000},
    "cwe_basis_points": {"CWE-79": 10000},
    "project_basis_points": {"project-a": 10000}
  }
}
```

Run the deterministic comparison in CI:

```bash
go run ./cmd/synapse-fptriage-drift \
  --baseline ai-triage-drift-baseline.json \
  --observed ai-triage-observability.json \
  --output ai-triage-drift-report.json
```

For each dimension, drift is total-variation distance: half the sum of absolute basis-point changes over
the union of baseline and observed categories. This catches a newly dominant language, CWE, or project as
well as shifts among existing categories. The default CLI behavior writes the complete deterministic
report and then exits non-zero for `drift_detected` or `insufficient_samples`; use
`--fail-on-alert=false` for report-only monitoring. The approved threshold is read only from the baseline,
not from a CLI override. A drift report requests review but has no authority to promote a model, change a
prompt, suppress a finding, or alter a quality gate. `approved_by` is process provenance, not a
cryptographic identity; create and run approved baselines only in a workflow that authenticates and
audits the responsible reviewer.
