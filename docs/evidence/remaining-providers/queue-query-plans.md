# Document command queue plan excerpts

All measurements used a warm isolated PostgreSQL 17 fixture with 100,005
commands, 100,002 terminal rows, and three eligible rows. They are diagnostic
measurements, not a production SLO.

## Existing query

The exact current `ListDocumentCommands` candidate query used this plan shape:

```text
Seq Scan on document_intents
  Filter: tenant and eligible-state predicate
  Rows Removed by Filter: 100002
  Buffers: shared hit=5556
  actual time: 0.007..38.579; rows=3
Nested Loop to document_commands primary key
Sort eligible candidates; LockRows; Limit 16
Execution Time: 149.939 ms for the measured CTE update
```

Setting every terminal row's `checked_at` to year 2000 still selected only the
two due rows. Terminal history therefore does not alter queue fairness, but it
does make the candidate read O(N tenant intents).

## Exact partial index with unchanged OR query

The additive partial index requested for the review did contain three rows, but
the planner estimated 25,009 rows under the unchanged OR predicate:

```text
Bitmap Index Scan on eligible_intents_idx: actual rows=3
Hash Join
Seq Scan on document_commands: actual rows=100004
Execution Time: 44.682 ms; Buffers: 7550
```

It does not solve the query alone.

## Partial index plus split eligible predicate

Splitting the eligible state predicate into three disjoint `UNION ALL` branches
and using a partial `(tenant_id,state,lease_until,id)` index produced:

```text
Index Only Scan: pending/uncertain branch, actual rows=2
Bitmap scan: retryable failed branch, actual rows=0
Index Only Scan: due in-flight branch, actual rows=1
Nested Loop to document_commands primary key
Execution Time: 0.265 ms; Buffers: 30
```

This plan did not read terminal history.

## Final candidate query and residual write cost

The final candidate used the same partial index and split predicate as the
working pair. Under a temporary non-superuser, non-BYPASSRLS role with FORCE
RLS and `app.current_tenant` set, its selected CTE read three eligible intents
and chose two rows in 0.163 ms with 28 shared buffers; terminal history was not
scanned. The plan includes the tenant-policy one-time filter.

The complete `UPDATE document_commands SET checked_at=..., check_version=...`
still took 121.887 ms and 5,502 buffers for the two selected rows because one
row carries a valid maximum PDF artifact. A rolled-back diagnostic showed the
cause: with `document_commands_artifact_check` active, a direct metadata update
took 177.917 ms and 5,403 buffers; without that CHECK inside the same rolled-
back transaction it took 0.564 ms and 19 buffers. Both emitted five WAL records
and 413 bytes, so this measurement identifies JSONB detoasting/check evaluation,
not a large TOAST rewrite. The repository constraint was restored unchanged.
