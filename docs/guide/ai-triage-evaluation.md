# AI false-positive triage evaluation

Synapse evaluates AI false-positive triage on a versioned, human-reviewed, non-production dataset before
an operator enables gate automation. Evaluation uses the same proposer, verifier, typed DTO, confidence
threshold, human-review floors, and deterministic policy as a scan. The only policy difference is forced
shadow mode: `would_gate_exempt` is measured, while `gate_exempt` must remain `false`.

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
