# Agent telemetry WAL invariants

The host agent's telemetry spool is the durability boundary between observing a security event and a
future transport accepting it. This note records the invariants reviewers and future A3 changes must
preserve. The implementation lives in `internal/infrastructure/spool`; the inward-facing contract is
`ports.TelemetrySpool`.

## Delivery claim

Synapse does not claim exactly-once delivery. The contract is:

> at-least-once delivery + idempotent ingest + a durable agent spool + a monotonic sequence per stream
> incarnation + highest-contiguous ACK + explicit durable gaps.

Once `Enqueue` succeeds, its coordinate must have one of three observable outcomes:

1. it remains readable from the WAL;
2. the exact priority/epoch/sequence was durably ACKed; or
3. durable gap evidence covers the coordinate.

An enqueue which fails is not part of that accepted set. Quota failures still append an
unknown-coordinate gap because the sensor did observe something the WAL could not accept. That gap
makes coverage incomplete without inventing a sequence which was never committed.

## Priority and pressure

The queue is physically segmented and logically ordered per priority. `Peek` always visits P0, P1, P2,
then P3, while preserving epoch/sequence order inside each lane.

- P0: response verification, coverage, and sensor health.
- P1: confirmed detections.
- P2: privilege changes and critical-file events.
- P3: background process and network telemetry.

P0–P2 carry `MustNotShed=true` and use `SyncAlways`. If the quota cannot be recovered by deleting P3,
the append returns `ports.ErrTelemetrySpoolSaturated` after syncing a `quota_backpressure` gap. The
producer retries and therefore applies pressure toward the source.

P3 is the only eviction lane. Before removing a P3 segment, the spool appends and fsyncs exact inclusive
sequence ranges to `gaps.log`. If the gap write or fsync fails, the segment is not deleted. If higher
priorities consume the entire quota, a new P3 observation is refused after an unknown-coordinate
`quota_eviction` gap is committed; the sensor may shed it and marks class coverage degraded.

The quota counts WAL segment bytes, not state/gap journal bytes. This reservation is intentional: a full
data allocation must not make the evidence of loss impossible to write. Operators must still monitor
gap-journal growth.

## Frame format

Each WAL frame has a fixed 48-byte little-endian header followed by JSON metadata and the producer's raw
payload bytes. Payloads are not base64 encoded. Version one contains:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `SYNW` |
| 4 | 2 | format version |
| 6 | 2 | header length |
| 8 | 4 | body length |
| 12 | 4 | CRC32C |
| 16 | 1 | priority |
| 17 | 1 | record kind |
| 18 | 2 | flags (`MustNotShed`) |
| 20 | 8 | epoch |
| 28 | 8 | sequence |
| 36 | 8 | observed-at Unix nanoseconds |
| 44 | 4 | metadata length |

The CRC32C covers the complete header with the checksum slot zeroed plus metadata and payload. Header
coordinates are therefore protected as strongly as the body. Configured record/segment bounds are
checked before allocating recovery buffers, preventing a corrupted length field from becoming an
unbounded allocation.

Metadata contains the event id/class, content type, session id, boot id, enqueue time, and schema
version. It is separately validated after checksum verification. `Peek` rereads payloads by offset
instead of retaining them in memory, so memory usage scales with record count/index size rather than
queued payload bytes.

## State and incarnation recovery

`state.json` and `state.backup.json` are generation-numbered snapshots installed by synced temporary
file plus atomic replace. State records the current session, boot, epoch, assigned-through coordinate per
priority, and ACK watermarks keyed by priority+epoch.

On a normal process restart with the same enrollment identity and Linux kernel boot UUID, recovery keeps
the epoch and continues the sequence. A different session or boot advances the epoch and resets each
lane to sequence one. If both state copies are missing or invalid while WAL data exists, recovery derives
the maximum epoch present, starts at the next epoch, and commits a `state_recovery` gap for every lane.
It never reuses an incarnation observed on disk.

For batched P3 sync, the assigned-through state is forced before `Enqueue` returns. A crash can therefore
lose kernel-buffered WAL tail bytes but cannot erase knowledge of their coordinates. Startup compares
the highest recovered/ACKed/gapped coordinate with assigned-through and commits the missing suffix as an
`unsynced_tail` gap. P0–P2 sync the segment before committing assigned state.

## Corruption and repair

Startup scans segment files in canonical filename order. It validates the fixed header, length bounds,
CRC, metadata, record contract, and filename priority/epoch. A valid header with a bad body produces an
exact `corrupt_frame` gap. Damage before a trustworthy coordinate produces an unknown-coordinate gap.
A partial final header/body produces `torn_write` evidence.

After damage the scanner searches for the next valid magic/header and can retain later frames in the
same segment. Valid unacknowledged frames are rewritten to a synced repair file and atomically installed,
so the next restart does not report the same corruption again. A corrupt gap journal is different: loss
evidence is the authority which permits deletion, so checksum corruption there fails open rather than
silently discarding it. Only an incomplete unsynced tail is safely truncated.

## ACK and deletion order

An ACK always names priority, epoch, and highest contiguous sequence. ACKs ahead of anything assigned are
rejected. Regressive/equal ACKs are idempotent. The state snapshot containing the new ACK is synced before
record references are removed or segment files are deleted. Consequently, a crash can retain an already
ACKed segment (harmless resend/compaction on restart), but cannot delete a segment whose ACK was not
durably committed.

A3 must not reinterpret `Peek` as a destructive dequeue. It should batch returned records, deliver them
with their `StreamPosition`, then call `Ack` only after the control plane returns a durable
highest-contiguous ACK for that exact lane and epoch.

## Retry and metrics

`RetryPolicy` provides capped exponential full jitter. HTTP 429 honors a bounded `Retry-After`; 408 and
5xx retry; other 4xx are permanent; network failures use the same jitter schedule. A3 owns the actual
request loop but should consume this policy so a server outage cannot synchronize a fleet-wide retry
storm.

The Prometheus collector owns no global registry and uses only the bounded `priority` label. It reports
depth/bytes, oldest-unacked age, current sequence/ACK, durable gaps, evictions, corruption recovery, and
fsync count/duration. Collection errors become invalid metrics rather than stale healthy-looking values.

## Test obligations

Changes to the WAL or A3 integration must retain:

- restart membership/order and sequence continuation;
- epoch advance on boot/session change;
- ACK-before-delete ordering and idempotent ACK behavior;
- P3-only eviction with gap-before-delete;
- never-shed saturation/backpressure evidence;
- middle-frame corruption resynchronization and stable repair;
- torn/unsynced tail gap coverage;
- exclusive directory locking;
- concurrent unique sequence assignment and `go test -race` cleanliness;
- the property invariant that every successful enqueue remains readable or gap-covered unless ACKed.
