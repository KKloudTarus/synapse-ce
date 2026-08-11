# ADR 0001 — Columnar telemetry store for retro hunting (#424)

**Status:** Accepted · **Date:** 2026-08-11 · **Deciders:** blue-team pillar (#405)

This is the written spike issue #424 gates its implementation behind: a comparison of candidate stores
for raw blue-team telemetry, naming the decision and the reason, with a cost estimate at a stated fleet
size. The implementation PR references this ADR.

## Context

Milestone one (#422/#423) deliberately shipped **detections only** into Postgres and the hash-chained
evidence spine, precisely so this decision could be made with the real data shape in hand. Raw
telemetry is a different problem:

- **Volume.** Process, connect, file and privilege events run to **millions of rows per host per day**.
  A 1,000-host fleet at a conservative 2M events/host/day is ~**2 billion rows/day**, ~**60B/month**.
- **Access pattern.** Retro hunting is columnar and time-bounded: scan one or a few columns over a time
  window, filter by asset, aggregate. It is not the OLTP row-at-a-time pattern the system of record uses.
- **It must never touch the system of record.** A finding, a judgment, and the evidence chain must never
  wait on, or be coupled to, a telemetry store measured in billions of rows.

So telemetry gets its **own persistence port** and its **own store**, and the store choice is the single
largest cost fork in the platform. Hence this gate.

## Candidates compared

| Store | Ingest (1 node, rough) | Retro-hunt latency (hot window) | Compression | Ops burden | Cost @ 1k-host fleet (self-hosted, 7d hot) |
|---|---|---|---|---|---|
| **ClickHouse** | 500k–1M+ rows/s | sub-second to seconds on a column+time scan over billions | ~10–30× (columnar + codecs) | Moderate: a real distributed system to run, but purpose-built | ~a few TB hot on disk after compression; a handful of nodes |
| **Postgres (time-partitioned, BRIN)** | ~50–150k rows/s per node before it hurts OLTP | seconds–minutes at billions; degrades sharply past the hot window | ~2–4× | Low: already operated | 10s of TB uncompressed; **does not hold at fleet scale** |
| **TimescaleDB** | better than raw PG on time-series; still row-store at heart | good in the hot window, weaker on wide column scans | ~3–7× (with compression) | Low–moderate: a PG extension | between PG and ClickHouse |
| **DuckDB / Parquet on object store** | batch-oriented, not a live-ingest server | excellent for archival scans, poor for interactive live ingest | ~10× (parquet) | Low infra, but you build the ingest/serving layer | cheap storage, but not an interactive hot tier |

## Decision

**Two-part decision, both parts binding:**

1. **ClickHouse is the target store at fleet scale.** It is the reference candidate in #424 and it is the
   right columnar engine for the volume and the three retro-hunt patterns. When a deployment runs a real
   fleet, telemetry is served by ClickHouse behind the `TelemetryStore` port.

2. **The CE milestone ships a Postgres-backed, time-partitioned telemetry tier behind the same port.**
   synapse-ce must be self-contained — it cannot require an operator to stand up and learn ClickHouse to
   run or test the platform. The CE tier proves the *contract* (bounded/backpressured ingest, tiered
   retention with audited expiry, explicit sampling, batch-sequence gap visibility, and the three
   retro-hunt query shapes) on a **seeded volume within a stated latency bound**, at a scale a single
   Postgres node comfortably serves. It is honest about its ceiling: past the hot window / past fleet
   scale, the ClickHouse impl is the answer, and it drops into the identical port with **no domain
   change** because the columnar store never appears in a domain type.

**Reason.** The cost fork is real, but the *risk* is architectural coupling, not the engine choice: if
the columnar store leaked into domain types or into the finding/judgment/evidence path, swapping engines
would be a rewrite. By putting telemetry behind a dedicated port that no domain type references (enforced
by an architecture test) and shipping a correct, bounded, honest CE tier today, we get retro hunting now
and a clean ClickHouse swap later, and the expensive decision is paid for with a proven contract rather
than an assumption.

## Consequences

- A new port `ports.TelemetryStore` (`Ingest`/`Query`/`RetentionSweep`), used by nothing in the system-of-
  record path. An `arch_test.go` asserts the columnar store and its row types never leak into a domain
  package.
- Ingest is one coherent budget across the agent buffer (#410), transport (#409) and store rate; overflow
  at any stage is a **telemetry gap** on the affected host, never a silent drop.
- Retention is tiered: hot (interactive, full resolution) → warm (reduced resolution) → expiry, each
  boundary configurable and **expiry audited**.
- Sampling is explicit: a sampled high-volume class records its rate with the data, and a sampled window
  is never presented as complete.
- Telemetry is **not** hash-chained per event (the #405 decision); batches stay signed + sequence-numbered
  so a hunt sees a complete vs. lossy sequence.
- **Cost is observable:** the store reports its footprint (rows + bytes) per tenant/fleet so an operator
  predicts spend rather than discovers it.

## Config

| Key | Default |
|---|---|
| `SYNAPSE_TELEMETRY_ENABLED` | `false` |
| `SYNAPSE_TELEMETRY_HOT` | `7d` |
| `SYNAPSE_TELEMETRY_WARM` | `30d` |
| `SYNAPSE_TELEMETRY_SAMPLE` | per high-volume class, recorded with the data |

## Out of scope

Response actions (#425); cross-region telemetry federation.
