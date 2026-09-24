# SAST post-triage benchmark

The [Securibench Micro](https://github.com/too4words/securibench-micro) scorecard measures scanner findings against a pinned answer key. Its post-triage path replays
recorded decisions from an independent verifier over fresh scanner output. A proposal export or a passing
propose-stage scorecard alone does not establish post-triage precision.

## Produce a blinded packet

Build a CGO-enabled `synapse-ast` and check out the Securibench revision pinned in
`sast-benchmark.yml`. Set `SYNAPSE_SECURIBENCH_DIR` and `SYNAPSE_AST_BIN` as for the normal scorecard. Generate a
random 32-byte key encoded as 64 hexadecimal characters, keep it outside the repository and logs, and set
`SYNAPSE_POST_TRIAGE_PACKET_SALT` to that value. Set `SYNAPSE_POST_TRIAGE_PROPOSALS` to an output path, then run
`TestSecuribenchScorecard` in `internal/infrastructure/tools/ast`.

The exported packet contains opaque file tokens, source context with benchmark comments removed, an exact
context start-line header, and one ID per finding. Java source line endings are canonicalized to CRLF in the
packet so Windows and Linux checkouts of the same corpus produce identical verifier input. The key must be
retained for replay against a fresh scan.
The verifier receives only this packet:
it must not inspect the corpus checkout, answer key, scorer, or unmasked filename mapping. Since the source
corpus is public, this is an access rule for the independent review, not a claim that source code cannot be
identified through external search.

## Run the independent offline verifier

`scripts/sast_offline_verifier.py` consumes only the blinded packet. Run it from the repository root against a
loopback llama.cpp server with a model file and runtime image pinned by SHA-256. Supply `--gguf-path`,
`--container`, and a repository-relative `--attestation` path along with the model filename and pinned digests.
The runner hashes the actual GGUF bytes and inspects the running Docker container and image before using the
endpoint. It requires exactly one read-only model bind mount, the pinned server command and image environment,
a read-only root filesystem, reduced privileges, and a `127.0.0.1:18080` binding for the model server port.
Requests connect directly to that loopback endpoint without an environment proxy or HTTP redirects. The retained
attestation binds those observations to the verifier config by digest; offline verification checks the attestation
against the source-controlled inspection policy. This records a local observation, not cryptographic proof that
every response in a long run came from that process. The runner fixes the prompt and generation
settings in source, records the raw request and response for every proposal in one transcript, and writes the
model's normalized response plus verdict artifact. It checkpoints each completed response; a resumed
run checks every retained exchange before sending another request. Keep the same runner revision, model,
runtime, endpoint, and settings for historical baseline and candidate. Exact duplicate blinded requests may
reuse the retained provider exchange after request-byte and config validation; the audit must disclose this.
The current local verifier uses
[`qwen2.5-coder-7b-instruct-q4_k_m.gguf`](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF/tree/13fb94bfda8c8cf22497dc57b78f391a9acb426a)
at GGUF SHA-256
`509287f78cb4d4cf6b3843734733b914b2c158e43e22a7f4bf5e963800894d3c` and llama.cpp image digest
`sha256:57e505f69c3a55fa5dd9c15fced47cff7a899f5b5b504ea93d75b2f401b87830`.

Run `python scripts/sast_offline_verifier.py --mode verify` with the same packet, model response, model verdict,
and raw transcript paths to check their provenance without contacting the model. This check recomputes packet and
response digests, requires complete decisions, and parses the retained provider output. Model output that is
truncated or malformed fails. The raw transcript contains public benchmark source excerpts and should be
reviewed before reuse with a private corpus.

## Check rejection proofs

The model's verdict alone is diagnostic. `scripts/sast_composite_verifier.py` reads the verified model evidence
and writes the final response and verdict consumed by Go replay. A model rejection is effective only when
`scripts/sast_proof_gate.py` validates a narrow, syntactic proof that the identified sink is inside a literal
`if (false)` body. Uncertain context, unsupported Java syntax, or an unmatched source line retains the finding.
The proof checker uses only the blinded packet and is calibrated on hand-authored Java cases outside the
benchmark. It does not use the Securibench answer key or the scanner's taint conclusion.

Keep the raw model exchange, model verdict, composite response, composite verdict, and composite audit together.
The audit records the model decision, proof result and reason, and final decision for every proposal; it never
rewrites the model's response. Run `scripts/sast_composite_verifier.py --mode verify` to recompute the complete
audit and final decision set from the retained model evidence and source-controlled proof code. A run with zero
validated rejection proofs is reported as such; a precision gain in that run comes from the scanner change.

## Record and replay decisions

Retain the composite verifier's actual response and a verdict artifact with the verifier identity, model and role,
prompt/configuration digests, packet digest, response digest, and one `confirmed` or `rejected` decision per
proposal. Set `SYNAPSE_POST_TRIAGE_VERDICTS` and `SYNAPSE_POST_TRIAGE_RESPONSE` to those files, using the same
packet key. Replay rejects changed packets, missing or duplicate decisions, malformed responses, and any
proposed true case lost after triage. Unknown or incomplete source context should remain confirmed.

For a diagnostic measurement without a baseline, set `SYNAPSE_POST_TRIAGE_DIAGNOSTIC_REPORT` to an output path.
The machine-readable report is marked `[diagnostic-unaccepted]`. It cannot establish improvement by itself.
The recorded Securibench pre-tuning diagnostic control and its provenance are in `docs/benchmarks/`.
Its verifier confirmed every proposal, and the model invocation is not reproducibly pinned; treat those
files as a comparison aid, not as release acceptance evidence.

For acceptance, omit the diagnostic output setting and supply `SYNAPSE_POST_TRIAGE_BASELINE`,
`SYNAPSE_POST_TRIAGE_BASELINE_ENGINE`, and `SYNAPSE_POST_TRIAGE_BASELINE_SHA256`. The loader checks the
baseline file against that exact digest and rejects diagnostic reports. The baseline must be a separately
measured and committed pre-change post-triage result with its source revision, corpus, verifier policy,
response, and report digest recorded.
Use `SYNAPSE_POST_TRIAGE_BASELINE_REPORT` only while running the pinned historical scanner binary: it records
the pre-change report through the same fresh verdict replay without applying the candidate comparison. The
hosted acceptance job must build that historical revision, reproduce the report with the retained baseline
verdict, and compare its digest to the committed report before testing the candidate. The packet salt belongs
in `SYNAPSE_POST_TRIAGE_PACKET_SALT` as an Actions secret; never commit or log its value.
Same-repository branch writers are trusted with this secret because they can change
the workflow and the Go test that receives it. Fork PRs skip this salt-backed gate;
a green aggregate on a fork is not post-triage acceptance.
The acceptance check requires per-CWE recall and precision not to regress, at least one precision gain, the
absolute floors, and no newly lost true cases. Pin the baseline digest and provenance in the workflow before
using the result as a release gate. Until the independent response, baseline, and required workflow gate are
present, this path is diagnostic and the post-triage claim remains unaccepted.

## Semgrep CE comparison lane

The hosted Securibench scorecard also runs Semgrep CE `1.177.0` from the pinned container manifest in
`sast-benchmark.yml`. It checks out `semgrep/semgrep-rules` at the pinned revision and scans its local `java`
directory. The scan has no network access, produces SARIF, requires at least one result, and stores SARIF plus
metadata for the exact source SHA, tool image/version, rules revision, rules scope, and target scope.

The scorecard passes that report to the Securibench comparator. A missing or malformed report fails the lane;
Semgrep's precision and recall are recorded for comparison only and do not affect the owned scanner's ratchet.
