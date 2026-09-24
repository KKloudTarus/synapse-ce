# SAST post-triage benchmark

The Securibench scorecard measures scanner findings against a pinned answer key. Its post-triage path replays
recorded decisions from an independent verifier over fresh scanner output. A proposal export or a passing
propose-stage scorecard alone does not establish post-triage precision.

## Produce a blinded packet

Build a CGO-enabled `synapse-ast` and check out the Securibench revision pinned in
`sast-benchmark.yml`. Set `SYNAPSE_SECURIBENCH_DIR` and `SYNAPSE_AST_BIN` as for the normal scorecard. Generate a
random 32-byte key encoded as 64 hexadecimal characters, keep it outside the repository and logs, and set
`SYNAPSE_POST_TRIAGE_PACKET_SALT` to that value. Set `SYNAPSE_POST_TRIAGE_PROPOSALS` to an output path, then run
`TestSecuribenchScorecard` in `internal/infrastructure/tools/ast`.

The exported packet contains opaque file tokens, source context with benchmark comments removed, and one ID
per finding. The key must be retained for replay against a fresh scan. The verifier receives only this packet:
it must not inspect the corpus checkout, answer key, scorer, or unmasked filename mapping. Since the source
corpus is public, this is an access rule for the independent review, not a claim that source code cannot be
identified through external search.

## Record and replay decisions

Retain the verifier's actual response and a verdict artifact with the verifier identity, model and role,
prompt/configuration digests, packet digest, response digest, and one `confirmed` or `rejected` decision per
proposal. Set `SYNAPSE_POST_TRIAGE_VERDICTS` and `SYNAPSE_POST_TRIAGE_RESPONSE` to those files, using the same
packet key. Replay rejects changed packets, missing or duplicate decisions, malformed responses, and any
proposed true case lost after triage. Unknown or incomplete source context should remain confirmed.

For a diagnostic measurement without a baseline, set `SYNAPSE_POST_TRIAGE_DIAGNOSTIC_REPORT` to an output path.
The machine-readable report is marked `[diagnostic-unaccepted]`. It cannot establish improvement by itself.

For acceptance, omit the diagnostic output setting and supply `SYNAPSE_POST_TRIAGE_BASELINE` and
`SYNAPSE_POST_TRIAGE_BASELINE_ENGINE`. The baseline must be a separately measured and committed pre-change
post-triage result with its source revision, corpus, verifier policy, response, and report digest recorded.
The acceptance check requires per-CWE recall and precision not to regress, at least one precision gain, the
absolute floors, and no newly lost true cases. Pin the baseline digest and provenance in the workflow before
using the result as a release gate. Until the independent response, baseline, and required workflow gate are
present, this path is diagnostic and the post-triage claim remains unaccepted.
