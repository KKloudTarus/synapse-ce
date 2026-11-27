package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAuditAppendPathsNormalizeInvalidUTF8 (#1723) drives each audit append path directly, as a non-owner
// role so row-level security is active: the tenant chain and its first-observation variant. The two global
// paths run only where row-level security is off; TestAuditRowWithInvalidUTF8RecomputesToItsHash covers them. Each stored row must recompute to its hash, and an idempotent retry with the same raw bytes must
// match the stored row instead of conflicting.
func TestAuditAppendPathsNormalizeInvalidUTF8(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	entry := func(target string) ports.AuditEntry {
		return ports.AuditEntry{Actor: "op\xff", Action: "scan.archive", Target: target, At: at,
			Metadata: map[string]string{"path": "a\xffb", "head": "\x00", "idempotency_key": target + "\xfe"}}
	}
	cases := []struct {
		name   string
		append func(tx pgx.Tx, e ports.AuditEntry) error
	}{
		{"tenant chain", func(tx pgx.Tx, e ports.AuditEntry) error { return appendTenantAudit(ctx, tx, "default", e) }},
		{"tenant first observation", func(tx pgx.Tx, e ports.AuditEntry) error {
			return appendTenantAuditWithFirstObservation(ctx, tx, "default", e, true)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := "utf8-paths-" + tc.name
			for i := 0; i < 2; i++ {
				if err := WithTenant(ctx, pool, "default", func(tx pgx.Tx) error { return tc.append(tx, entry(target)) }); err != nil {
					t.Fatalf("attempt %d: %v", i, err)
				}
			}
			var rows []struct {
				actor, action, hash, prev string
				meta                      []byte
				at                        time.Time
				scheme                    int
			}
			if err := WithTenant(ctx, pool, "default", func(tx pgx.Tx) error {
				r, err := tx.Query(ctx, `SELECT actor, action, metadata, created_at, hash, COALESCE(previous_hash,''), hash_scheme FROM audit_log WHERE target = $1`, target)
				if err != nil {
					return err
				}
				defer r.Close()
				for r.Next() {
					var row struct {
						actor, action, hash, prev string
						meta                      []byte
						at                        time.Time
						scheme                    int
					}
					if err := r.Scan(&row.actor, &row.action, &row.meta, &row.at, &row.hash, &row.prev, &row.scheme); err != nil {
						return err
					}
					rows = append(rows, row)
				}
				return r.Err()
			}); err != nil {
				t.Fatalf("read back: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("rows = %d, want 1: a retry with the same raw bytes must match the stored entry", len(rows))
			}
			var metadata map[string]string
			if err := json.Unmarshal(rows[0].meta, &metadata); err != nil {
				t.Fatalf("decode metadata: %v", err)
			}
			if want := audit.ComputeHash(rows[0].scheme, rows[0].prev, rows[0].actor, rows[0].action, target, metadata, rows[0].at); want != rows[0].hash {
				t.Fatalf("stored row does not recompute to its hash: the row reads as tampered")
			}
		})
	}
}
