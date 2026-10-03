# ADR 0011: JEPA-style predictive models in Synapse

- Status: Accepted (decision: **no detection path; one narrow ranking use, gated behind the columnar
  telemetry tier**)
- Date: 2026-10-03
- Relates to: ADR 0001 (columnar telemetry store), the judgment primitive, `ports.TelemetryStore`

## Context

A Joint-Embedding Predictive Architecture (JEPA) is trained to predict the representation of a masked
or future part of its input from the part it can see, in embedding space, with an EMA teacher
producing the target. Nothing is reconstructed at the input level, so the objective does not spend
capacity on detail that carries no information, and no labels are required. The published variants are
I-JEPA for images, V-JEPA for video, AD-L-JEPA for LiDAR, T-JEPA for tabular data, and MTS-JEPA and
SC-JEPA for multivariate time series.

The property that makes the family interesting for security is the derived signal rather than the
representation: the distance between the predicted future embedding and the observed one is a
per-window **surprise** score, available without any attack labels. That is the quantity every
proposal in this space ends up using.

The question this record answers is whether that signal has a place in Synapse, and if so where.

## What the published evidence supports

Security work with JEPA today is concentrated in three places: autonomous-vehicle safety and security
surveys, 6G network telemetry, and multivariate time-series anomaly prediction. The time-series line is
the closest analogue to fleet telemetry and the only one reporting numbers on standard benchmarks.

MTS-JEPA reports best AUC on all four of MSL, SMAP, SWaT and PSM, with these F1 and precision figures:

| Benchmark | MTS-JEPA F1 | Best prior in the paper | MTS-JEPA precision |
| --- | --- | --- | --- |
| MSL (spacecraft telemetry) | 33.58% | 25.49% (TS-JEPA) | 35.87% |
| SMAP (spacecraft telemetry) | 33.64% | 26.92% (PAD) | reported in Table 1 |
| SWaT (water-treatment ICS) | 72.89% | 69.75% (PAD) | 98.00% |
| PSM (pooled server metrics) | 61.61% | 58.17% (PatchTST) | reported in Table 1 |

Two readings matter here. The improvement over prior self-supervised baselines is real and consistent.
The absolute level on the two telemetry benchmarks is an F1 near 34% with precision near 36%, which
means roughly two of every three positives are wrong at the operating point the paper reports. The
paper also records that removing its soft-codebook bottleneck collapses performance "to near-random
levels", so the result depends on a stabiliser that is specific to the architecture rather than on the
JEPA objective alone.

There is a second gap that the numbers hide. MSL, SMAP, SWaT and PSM are continuous numeric sensor
series. Synapse's fleet telemetry is a stream of typed discrete records: `ProcessEvent` with PID,
PPID, resolved path, bounded argv and UID; `NetworkEvent` with protocol, remote address, port and
direction; plus file and privilege classes. Predicting the embedding of a future window of categorical
event records is closer to sequence modelling over a vocabulary than to forecasting a sensor, and the
published benchmark results do not transfer to it. No host-telemetry benchmark for a JEPA-style model
was found.

## The arithmetic that decides the role

ADR 0001 states the volume: conservatively 2M events per host per day, about 2 billion rows per day at
a 1,000-host fleet. Scoring one-minute windows per host at that fleet size produces 1,440 windows per
host per day, so 1.44M scored windows per day.

| Specificity per window | False positives per day at 1,000 hosts |
| --- | --- |
| 99% | 14,400 |
| 99.9% | 1,440 |
| 99.99% | 144 |

True incidents on such a fleet are counted in single digits per month. A detector at 99.99%
specificity still buries each real one under roughly a thousand false ones. This is the base-rate
problem that has defeated anomaly detection as an alerting primitive in security for twenty years, and
no improvement in representation learning changes the denominator.

The consequence is specific: a surprise score can order work a human has already decided to do, and it
cannot open work on its own.

## Four constraints this codebase imposes

**The judgment primitive admits a proposer only.** Every analysis or AI claim in Synapse is propose,
verify, confirm; a proposer never confirms its own claim, and no model sits in the report path.
A surprise score is admissible as a proposal, and a deterministic rule or a named analyst has to
confirm before anything reaches a finding or a report. Any design where the score itself creates a
detection violates the invariant.

**Tenant isolation forbids the shared model that makes self-supervision attractive.** Tenant-scoped
data is reached through `postgres.WithTenant` under RLS, and cross-tenant access has to be rejected by
the hostile harness. A model trained across tenants is an inference channel over tenant data: its
weights carry one tenant's normal behaviour into another tenant's scoring. Per-tenant models stay
inside the invariant and give up exactly the data efficiency that motivates the approach, because each
tenant then trains on its own fleet alone.

**A learned baseline is attacker-influenced.** An intruder resident before training shapes what the
model accepts as normal, and the model answers "what does this host consider unusual" to anyone who
can observe its scores. A deterministic rule has neither property. This argues for the score being
visible only to the tenant's own operators and never for it being the thing that decides.

**The data the model needs is behind a store that CE does not ship.** Detections plus a bounded
surrounding window reach the system of record; the raw stream lives behind `ports.TelemetryStore`,
whose CE implementation is a Postgres time-partitioned tier that ADR 0001 describes as honest about
its ceiling, with ClickHouse named as the fleet-scale target and not yet implemented. Training a
sequence model on the raw stream needs the columnar tier first. Training on detection windows instead
would learn only from samples a rule already matched, which cannot represent normal and cannot reach
anything no rule flagged.

## Decision

**Rejected: a JEPA model as a detection or alerting source.** Nothing in this family may create a
detection, a finding, an incident or a notification. The base-rate arithmetic and the published
precision both say the same thing, and the judgment primitive forbids it independently.

**Rejected: a JEPA model in reachability, taint or matching.** Those paths are deterministic and
build-aware on purpose, and their correctness is the product's measured advantage over competing
scanners. Substituting a learned embedding for an assembly-metadata or value-flow decision trades a
provable answer for a scored one.

**Accepted, narrowly and in this order: surprise as a ranking signal on retro-hunt queries.** Once the
columnar tier exists, a per-tenant model may order the windows a hunter is already scanning, so the
first page of a time-bounded retro-hunt is the most unusual windows for that asset rather than the
most recent. The output is an ordering, it carries no severity, it produces no record in the evidence
spine, and the surface has to say that it ranks and does not judge.

**Deferred: precursor prediction.** Predicting the staging phase before the payload is the stated
appeal of MTS-JEPA, and it is also exactly where its F1 near 34% sits. Revisit when there is a
measurement on Synapse's own data.

## What would change this decision

A ranking claim is testable without any of the alerting machinery. The bar is a measurement on
Synapse's own event-stream corpus, per tenant, with no cross-tenant training: recall@50 windows
against incidents already confirmed by a rule or an analyst, compared against two baselines that cost
nothing, which are recency ordering and rarity of the executable path or remote address. The model has
to beat both by a margin that survives a different tenant's fleet. Until that number exists, the
ranking use stays unbuilt rather than built on the strength of a benchmark from another modality.

## Consequences

- No work starts in this area before ADR 0001's ClickHouse implementation lands, because the training
  input does not otherwise exist.
- The AI-triage subsystem and its offline eval gate are unaffected. That subsystem is a labelled
  classification problem with a curated corpus and a release gate, and it is the wrong place for a
  self-supervised objective.
- Synapse's detection remains its own deterministic engines. A ranking signal added later orders their
  output and does not become a second, weaker detector beside them.
