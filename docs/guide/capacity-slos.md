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

## Current measured envelope

The disposable AWS rehearsal used two API replicas on two EKS nodes, two web replicas, and one
lease-locked worker. One hundred sequential, fresh-TLS `/readyz` requests were sent through the
TLS ingress with certificate-chain and hostname verification enabled. The exact input and report
are locally retained and SHA-256 sidecars bind each artifact.

| Observation | Result |
| --- | ---: |
| Successful requests | 100 / 100 |
| Request latency p50 | 732 ms |
| Request latency p95 | 784 ms |
| Request latency p99 | 948 ms |
| Observed maximum | 1,546 ms |
| API pod-deletion drill | 90 / 90 one-second probes succeeded |
| Replacement pod | ready on the other node |

This narrow result proves only low-rate readiness and API-replica failover. Every request opened a
new TLS connection, so it is not an application-handler latency baseline. It did not measure scan
throughput, queue saturation, PostgreSQL acquisition wait, evidence growth, or migration duration
under production-like data. Those objectives therefore remain explicitly unactivated.

## Provisional objectives for the measured path

For the same topology and low-rate `/readyz` probe only:

- **Availability:** 99.9% successful requests over a rolling 30-day window.
- **Latency:** 95% complete within 1 second over five-minute windows.
- **Failover continuity:** deleting one API pod produces no failed one-second service probes.

The 1-second latency threshold is above the measured 784 ms p95 but below the observed 1,546 ms
maximum; it is a starting objective, not a general API promise. The 99.9% objective permits a
30-day error budget of 43 minutes 49 seconds. Alert on fast and slow error-budget burn rather than
on a single failed request.

Prometheus queries (exclude health checks when deriving user-API objectives):

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

## Alert starting points

- Page when the user-API 5xx ratio exceeds 1.4% for one hour or 0.6% for six hours; these are
  approximate 14.4× and 6× burn rates for a 99.9% objective.
- Ticket when p95 user-API latency exceeds the activated route-specific threshold for 30 minutes.
- Warn when pool utilization exceeds 80% for 15 minutes or empty-acquire wait keeps increasing;
  page only when it coincides with errors or latency burn.
- Page when fewer than two API replicas are ready for 10 minutes.

Do not activate scan-completion, queue-delay, migration-duration, or evidence-growth objectives
until a representative fixture and concurrency ladder have measured them. Repeat a scenario after
any node shape, replica count, PostgreSQL pool budget, tool digest, or major release change.
