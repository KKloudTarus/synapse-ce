package postgres_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAuditRowWithInvalidUTF8RecomputesToItsHash (#1723): JSON encoding stores an invalid metadata byte as
// U+FFFD, so the writer must hash the normalized metadata. The stored row, read back, recomputes to its
// stored hash, on the global path and on the tenant-bound transaction path.
func TestAuditRowWithInvalidUTF8RecomputesToItsHash(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("audit-utf8-tenant")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	stamp := time.Now().UTC().Format("150405.000000000")
	log := postgres.NewAuditLog(pool)
	runner := postgres.NewTenantTransactionRunner(pool)

	cases := []struct {
		name   string
		record func(target string) error
	}{
		{"global", func(target string) error {
			return log.Record(ctx, ports.AuditEntry{Actor: "op\xff", Action: "scan.archive", Target: target, At: time.Now().UTC(),
				Metadata: map[string]string{"path": "a\xffb", "evidence_head": "\x00"}})
		}},
		{"tenant transaction", func(target string) error {
			return runner.Run(ctx, tenant, func(txCtx context.Context) error {
				return log.Record(txCtx, ports.AuditEntry{Actor: "op", Action: "scan.archive", Target: target, At: time.Now().UTC(),
					Metadata: map[string]string{"path": "a\xffb", "k\xfe": "v"}})
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := "audit-utf8-" + tc.name + "-" + stamp
			cleanupAuditRows(t, pool, target)
			if err := tc.record(target); err != nil {
				t.Fatalf("record: %v", err)
			}
			var actor, action, hash, prev string
			var scheme int
			var meta []byte
			var at time.Time
			if err := pool.QueryRow(ctx, `SELECT actor, action, metadata, created_at, hash, previous_hash, hash_scheme FROM audit_log WHERE target = $1`, target).
				Scan(&actor, &action, &meta, &at, &hash, &prev, &scheme); err != nil {
				t.Fatalf("read back: %v", err)
			}
			var metadata map[string]string
			if err := json.Unmarshal(meta, &metadata); err != nil {
				t.Fatalf("decode metadata: %v", err)
			}
			if metadata["path"] != "a\uFFFDb" {
				t.Fatalf("stored path = %q, want the U+FFFD form", metadata["path"])
			}
			if tc.name == "global" && metadata["evidence_head"] != "\uFFFD" {
				t.Fatalf("stored evidence_head = %q, want a NUL stored as U+FFFD", metadata["evidence_head"])
			}
			if want := audit.ComputeHash(scheme, prev, actor, action, target, metadata, at); want != hash {
				t.Fatalf("stored row recomputes to %s, stored hash is %s: the row reads as tampered", want, hash)
			}
		})
	}
}
