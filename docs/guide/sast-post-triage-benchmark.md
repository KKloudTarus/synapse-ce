# SAST post-triage benchmark

The required sast-benchmark.yml job measures post-triage precision against the
[Securibench Micro](https://github.com/too4words/securibench-micro) answer key. It builds the historical Synapse scanner at the pinned
BASELINE_SOURCE_SHA and the current scanner at the routed source SHA, then runs
both against the same pinned public corpus. The job requires a real named test pass,
a precision improvement over the historical report, the per-CWE floors, no recall
regression, no newly lost true case, and a nonempty scorecard artifact. It runs on
fork pull requests as well as same-repository changes; the aggregate fails if it
is skipped or has no artifact.

## Fresh deterministic proof triage

Each scanner first exports a fresh blinded proposal packet. The workflow creates
an ephemeral 32-byte packet salt on the runner; it does not need a repository
secret. Only the packet is given to scripts/sast_proof_verifier.py, which checks
every proposal with the narrow scripts/sast_proof_gate.py grammar. It rejects a
finding only when it proves that the identified sink is within a literal
if (false) body. Ambiguous or unsupported syntax stays confirmed. The verifier
does not read the corpus answer key. Its complete decision set, source policy
digests, packet digest, and response digest are replayed by the Go scorecard
against a second fresh scan. The current scan compares against a report measured
from the pinned historical scanner during the same job.

The workflow uploads only the two scorecards and proof counts. Packets, responses,
verdicts, scanner binaries, and the salt remain in runner temporary storage.
Local replay outputs belong under .git/taurus/, outside the tracked source tree.
The proof verifier is identified as syntactic-proof-v1. It does not claim to
reproduce an earlier model-assisted run.

The last local replay measured CWE-79 precision from 0.750 on the historical
scanner to 0.772 on the candidate, with recall 0.629 in both and zero proven
rejections. The gain therefore comes from scanner behavior, not the proof
verifier. A future change must earn its own fresh CI result.

## Optional model audit

scripts/sast_offline_verifier.py remains available for an optional local model
audit. Its model decisions do not satisfy the required deterministic proof gate.
Keep raw model exchanges, transcripts, attestation, verdicts, and reports under
`.git/taurus/`; they are not committed benchmark inputs or required CI artifacts.
The previous model-assisted capture is retained locally at
.git/taurus/sast-post-triage-artifacts. Do not treat it as the result of the
required deterministic proof job.

## Semgrep CE comparison

The separate hosted Securibench scorecard runs Semgrep CE from a pinned image
and a pinned local rules revision without runtime network access. Its SARIF is
required for the comparator and retained with source/tool metadata. Semgrep
scores are comparison data; the owned scanner's ratchet is evaluated against
the independent Securibench answer key.
