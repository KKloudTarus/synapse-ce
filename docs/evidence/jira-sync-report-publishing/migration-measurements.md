# Migration lock measurements

These are focused local PostgreSQL 17.11 measurements, not a production capacity
claim or a complete replay benchmark. Each measured table had one million
synthetic rows. The isolated container had two CPUs and a 1 GiB memory limit,
with fsync and synchronous commit enabled. Each migration was measured once with
a warm local cache and a concurrent one-row reader and writer.

| Migration | Transaction | Reader wait | Writer wait | Observed blocking lock |
| --- | ---: | ---: | ---: | --- |
| Inbound ticket backfill | 64.693 s | 64.677 s | 64.682 s | Access exclusive |
| Inbound ticket read index | 2.178 s | 0.001 s | 2.174 s | Share |
| Engagement lookup index | 1.897 s | 0.003 s | 1.885 s | Share |
| Source-job purpose constraint and index | 2.828 s | 2.821 s | 2.825 s | Access exclusive |

The inbound backfill alters forced RLS inside the same transaction as its full
qualifying-row insert. Its access-exclusive lock therefore blocks readers as well
as writers until commit. The source-job migration validates a check constraint and
builds an ordinary index while holding its table lock.

Use a maintenance window and drain all database clients before migration. Rehearse
on a restored database to estimate the actual window. Keep the existing coordinated
worker rollout and retained-history rollback requirements. Do not infer an online
upgrade from schema compatibility alone.

The [measurement proof](migration-measurement-proof.json) records exact SQL hashes,
row counts, settings, lock samples, durations, and fixture limitations. The
[inventory](migration-inventory.json) distinguishes existing growing tables from
tables that are new and empty during a single stopped-application upgrade. New
foreign keys can also briefly lock referenced existing tables. These fixtures omit
production table bloat, replicas, traffic, and some historical schema details;
their timings do not predict another installation. The disposable measurement
container and its volume were removed after the run.
