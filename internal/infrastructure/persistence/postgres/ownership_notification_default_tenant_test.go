package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestOwnershipNotificationNamesDefaultTenantAssignees: users of the default tenant are stored with
// tenant_id '' while ownership rows carry 'default', so the assignee names must be resolved through
// users.ownership_tenant_id. Before #1724 the subqueries compared tenant_id and returned empty names.
func TestOwnershipNotificationNamesDefaultTenantAssignees(t *testing.T) {
	pool, _ := ownershipTestDatabase(t, 163, nil)
	ctx := shared.WithTenant(context.Background(), "default")
	at := time.Now().UTC().Truncate(time.Microsecond)

	for _, u := range []struct{ id, name, hash string }{{"carol", "Carol", "dt-carol"}, {"dave", "Dave", "dt-dave"}} {
		if err := WithTenant(ctx, pool, "default", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES($1,$2,'consultant',$3,'')`, u.id, u.name, u.hash)
			return err
		}); err != nil {
			t.Fatalf("seed user %s: %v", u.id, err)
		}
	}
	payload, err := json.Marshal(map[string]any{
		"actor":  "carol",
		"result": map[string]string{"reason": "manual_assign"},
		"before": map[string]string{"assignee_id": "carol"},
		"after":  map[string]string{"assignee_id": "dave"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, "default", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES('dt-eng','default','Default tenant')`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO findings(id,tenant_id,engagement_id,title,assignee) VALUES('dt-finding','default','dt-eng','Default finding','')`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ownership_decisions(tenant_id,engagement_id,finding_id,id,transition_key,request_hash,payload,created_at)
			VALUES('default','dt-eng','dt-finding','dt-decision','dt-key',repeat('a',64),$1,$2)`, payload, at); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO ownership_intents(tenant_id,engagement_id,finding_id,id,kind,source_key,decision_id,payload,state,created_at)
			VALUES('default','dt-eng','dt-finding','dt-intent','notification','dt-decision','dt-decision','{}','pending',$1)`, at)
		return err
	}); err != nil {
		t.Fatalf("seed ownership decision: %v", err)
	}

	source := NewNotificationSource(pool, NewNotificationRepository(pool), time.Minute)
	var raw []byte
	if err := WithTenant(ctx, pool, "default", func(tx pgx.Tx) error {
		n, err := source.pollOwnership(ctx, tx, "default", 10)
		if err != nil {
			return err
		}
		if n != 1 {
			t.Fatalf("pollOwnership published %d events, want 1", n)
		}
		return tx.QueryRow(ctx, `SELECT context FROM notification_events WHERE tenant_id='default' AND source_id='dt-decision'`).Scan(&raw)
	}); err != nil {
		t.Fatalf("poll: %v", err)
	}
	var decoded struct {
		Vars map[string]string `json:"vars"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode context %s: %v", raw, err)
	}
	got := decoded.Vars
	if got["old_assignee"] != "Carol" || got["new_assignee"] != "Dave" {
		t.Fatalf("assignee names = %q -> %q, want Carol -> Dave (context %s)", got["old_assignee"], got["new_assignee"], raw)
	}
}
