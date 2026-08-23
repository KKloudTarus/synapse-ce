# Capacity and service objectives

[Documentation home](README.md) · Related: [Deployment](deployment.md) ·
[Backup, restore, and upgrade](backup-restore-upgrade.md)

Service objectives are activated only after a representative, repeatable benchmark covers the
intended workload. A configured replica or connection limit is not evidence of capacity.

## Reproducible benchmark input

`synapse-bench` reduces a versioned observation set into deterministic JSON. It does not generate
load or invent missing measurements:

```bash
synapse-bench -input benchmark-input.json -output benchmark-report.json
sha256sum benchmark-input.json benchmark-report.json
```

Record the environment, release, image, fixture, and tool digests with each run. Include request,
queue, pool, evidence-growth, migration, failover, and correctness observations when that scenario
actually measures them. Leave an unmeasured observation set empty or zero rather than relabeling a
configured limit as a measurement. A run is invalid if correctness reports a lost or duplicate job,
cross-tenant result, result-digest drift, broken evidence chain, or missing object.

## Generating observations

Generate benchmark observations through the public HTTP contracts rather than by calling internal
services:

- `POST /api/v1/sca/scans` submits one asynchronous scan (`202` with the job).
- `GET /api/v1/sca/scans/{id}` polls that job by its own ID.
- `GET /api/v1/engagements/{id}/evidence` verifies the hash-chained ledger after drain.
- The private Prometheus listener supplies `synapse_job_queue_*` and
  `synapse_postgres_pool_*`.

Use persistent HTTP connections, a bounded request rate/concurrency, and credentials obtained from
the runtime secret store. Never place bearer credentials in process arguments or observation files.
Record raw timestamped observations outside the repository, sanitize them, and reduce the resulting
`synapse-benchmark-input-v1` file with `synapse-bench`. Treat omitted terminal state, evidence growth,
or a requested metric family as an incomplete run rather than inventing a measurement.

## AWS staging topology measured

The production-shaped acceptance environment used:

- two `synapse-api` replicas behind the EKS ingress/load balancer;
- one shared RDS PostgreSQL database;
- four native, non-root `synapse-worker` instances in a private EC2 Auto Scaling Group;
- worker launch template version 9 and AMI `ami-027ebfd75c8c6c9d1`;
- worker RPM SHA-256
  `c2eb38c4c1f02c3e7cac6b6c972d309360410133193334a7bebfa55766162157`;
- AI disabled during capacity measurements.

Each worker passed the exact production-runner startup gate. A replacement-image full conformance
run passed all 12 required controls: filesystem isolation, empty capabilities, default-deny network,
seccomp, timeout/tree termination, cgroup PID and memory limits, executable integrity, bounded
output, secret redaction, and recovery. The worker uses a root-owned typed egress broker; the worker
itself has no effective or ambient capabilities.

The sanitized raw observations, reducer inputs, deterministic reports, remote command identifiers,
and SHA-256 manifest are retained outside the source tree. The repository publishes only the compact
measurements below; runtime credentials, signed grants, local AI configuration, control objects,
scratch executables, and sensitive remote logs are excluded.

## Measured API admission envelope

The admission ladder used persistent HTTP connections through the load balancer. All requests
succeeded. No API failure boundary was reached; the final rung is the driver's configured ceiling,
not proof that higher rates are healthy.

| Concurrency / target rate | Requests | Successes | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 32 / 500 requests/s | 5,000 | 5,000 | 2 ms | 2 ms | 9 ms |
| 64 / 1,000 requests/s | 10,000 | 10,000 | 1 ms | 2 ms | 55 ms |
| 128 / 2,000 requests/s | 20,000 | 20,000 | 1 ms | 3 ms | 98 ms |
| 256 / 5,000 requests/s | 50,000 | 50,000 | 1 ms | 13 ms | 155 ms |
| 256 / 5,000 requests/s, repeat | 50,000 | 50,000 | 1 ms | 20 ms | 215 ms |

The observed API admission envelope is therefore **at least 5,000 requests/s at concurrency 256**
for this fixture and topology, with zero request failures and repeat-run p95 of 20 ms. Retest rather
than extrapolate beyond that harness ceiling.

### API failover

During sustained load, one API pod was deleted:

- 60,000 / 60,000 requests succeeded at approximately 999.883 requests/s;
- p50/p95/p99 were 1/4/11 ms;
- the surviving replica maintained continuity;
- the replacement became ready in 24,184 ms;
- the deployment returned to 2/2 ready.

## Measured worker and database envelope

The repeated four-worker scan ladder found the first reproducible queue-degradation boundary. A
healthy rung requires every accepted job to complete once, intact evidence chains, no admission
conflicts, no unexpected dead letters, no pool errors, and observed post-arrival recovery.

| Rung | Accepted / successful | Throughput | Request p50/p95/p99 | Queue delay p50/p95/p99 | Queue recovery p50/p95/p99 | Pool p50/p95/p99 | Saturation | Correctness failures |
| --- | ---: | ---: | --- | --- | --- | --- | ---: | ---: |
| **Healthy: c16 / 16 scans/s / 15 s, repeat** | 240 / 240 | 8.79 scans/s | 33/43/65 ms | 2,576/4,810/4,810 ms | 5,587/6,697/6,697 ms | 0/0/0 ms | 0 | 0 |
| **Degraded: c32 / 32 scans/s / 15 s, repeat** | 480 / 480 | 9.92 scans/s | 33/51/209 ms | 4,880/9,571/9,571 ms | 18,736/27,076/27,769 ms | 0/0/1 ms | 1 | 0 |

The safe operating envelope is the last repeated healthy rung: **four workers, concurrency 16,
16 arrivals/s for 15 seconds, and 240 jobs**, sustaining about 8.79 completed scans/s. The first
reproducibly degraded rung is concurrency 32 at 32 arrivals/s: correctness remains exact, but queue
recovery rises to p95 27.076 seconds and the first pool saturation interval appears. Queue/database
recovery, not double completion or job loss, is the first unhealthy signal.

Do not publish 9.92 scans/s as a safe steady-state target: it was measured while accepting a bounded
backlog and then draining it. For continuous arrivals, stay below measured completion throughput and
retain headroom for worker loss.

### Active worker termination and replacement

A worker was terminated during the degraded 480-job workload. The corrected drill observed:

- 480 / 480 jobs succeeded with zero correctness failures;
- approximately 8.535 scans/s;
- request p50/p95/p99 34/51/94 ms;
- queue delay p50/p95/p99 5,141/10,208/10,208 ms;
- queue recovery p50/p95/p99 23,587/35,504/36,003 ms;
- pool p50/p95/p99 0/0/0 ms with one saturation event;
- replacement instance ready in 34,066 ms;
- the replacement reran strict production sandbox conformance.

An earlier drill that terminated a worker during evidence sealing exposed a retry/idempotency defect
and produced one failed job. That run remains defect evidence and is not included as a passing
result. The remediation makes parent-delivery cancellation retryable and reserves the durable scan
job ID for exact evidence redelivery. Only the corrected rerun is acceptance evidence.

## Controlled evidence growth

A separate 240-scan rung used the same four-worker topology and verified all six engagement evidence
chains. PostgreSQL measurements were taken with the runtime role and tenant RLS context; S3 bucket
count and bytes were measured with the configured AWS staging account.

| Observation | Before | After | Growth |
| --- | ---: | ---: | ---: |
| Evidence rows | 6,020 | 6,260 | 240 |
| Evidence relation bytes | 8,445,952 | 8,814,592 | 368,640 bytes |
| Evidence content bytes | 3,618,672 | 3,768,912 | 150,240 bytes |
| S3 objects | 33 | 33 | 0 |
| S3 bytes | 1,730,555,162 | 1,730,555,162 | 0 bytes |

The rung completed 240/240 jobs at 8.824 scans/s with request p50/p95/p99 of 33/52/90 ms and zero
correctness failures. The zero S3 delta is expected for this scan path: general evidence content is
stored inline in PostgreSQL. It must not be interpreted as an object-store write failure.

## Signed live-egress acceptance

A live staging drill used the exact production `sandbox.Runner`, worker-to-control-plane grant
authority, and root-owned broker. The helper worker was stopped before creating the authoritative
recon run so another worker owned that run. On the isolated helper host:

- the first signed setup was accepted;
- exact resubmission of the still-valid grant was rejected;
- the public broker response remained the generic `operation failed`;
- the sandboxed tool exited 0;
- the replay journal grew by exactly one record;
- the journal contained two unique IDs and zero duplicates after the drill;
- the worker and broker were restored, with no residual Bubblewrap process or network namespace.

This is a replay/security acceptance drill, not a throughput result.

## Operating objectives for the measured topology

Until a longer endurance run establishes trend-based SLOs, use these measured guardrails:

- Keep ordinary scan admission at or below the repeated healthy rung: concurrency 16 and no more
  than 16 arrivals/s for this fixture, with sustained arrivals below observed completion throughput.
- Warn when queue recovery p95 exceeds 7 seconds for comparable short rungs; treat 27 seconds or a
  pool saturation event as degraded.
- Page on any lost job, duplicate terminal completion, broken evidence chain, unexpected dead letter,
  scope/authorization bypass, or pool acquisition error. Correctness has zero error budget.
- Keep at least two API replicas ready; API pod replacement should return to 2/2 within 60 seconds.
- Keep the worker ASG at four healthy instances for this envelope; a replacement should become
  healthy within 60 seconds and pass the exact startup conformance gate before claiming jobs.
- Do not increase rate in response to low API latency when queue recovery is already degrading.

Prometheus starting points:

```promql
# Five-minute successful-request ratio
sum(rate(synapse_http_requests_total{route!~"/healthz|/readyz",status_class!="5xx"}[5m]))
/
sum(rate(synapse_http_requests_total{route!~"/healthz|/readyz"}[5m]))

# Five-minute p95 request duration
histogram_quantile(
  0.95,
  sum by (le) (rate(synapse_http_request_duration_seconds_bucket{route!~"/healthz|/readyz"}[5m]))
)

# PostgreSQL pool utilization
sum(synapse_postgres_pool_connections{state="acquired"})
/
sum(synapse_postgres_pool_connections{state="max"})

# Pool-empty wait rate
sum(rate(synapse_postgres_pool_empty_acquire_wait_seconds[5m]))
```

Repeat the ladder after any worker or database shape change, API/worker replica-count change,
PostgreSQL pool-budget change, sandbox/tool digest change, queue semantics change, or major release.
Run a longer endurance benchmark before converting these bounded-run guardrails into rolling
production SLOs.