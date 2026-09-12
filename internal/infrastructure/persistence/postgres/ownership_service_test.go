package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	ownershipuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

type ownershipServiceClock struct{ at time.Time }

func (c ownershipServiceClock) Now() time.Time { return c.at }

func TestOwnershipServiceAuditFailureRollsBack(t *testing.T) {
	f := newOwnershipFixture(t)
	svc, err := ownershipuc.NewService(f.repo, f.repo, NewFindingRepository(f.pool), NewTenantTransactionRunner(f.pool), NewAuditLog(f.pool), ownershipServiceClock{f.at}, &ownershipTestIDs{}, "observe", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ddl.Exec(`CREATE FUNCTION ownership_api_audit_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END; $$; CREATE TRIGGER ownership_api_audit_failure BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION ownership_api_audit_fail()`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SaveTeam(f.ctx, "alice", "pay", ownershipuc.TeamInput{Slug: "pay", Name: "Changed", Revision: 1}); err == nil {
		t.Fatal("admin audit failure ignored")
	}
	team, err := f.repo.GetTeam(f.ctx, "pay")
	if err != nil || team.Revision != 1 || team.Name != "pay" {
		t.Fatalf("partial team update: %+v %v", team, err)
	}
	if err := svc.Member(f.ctx, "alice", "ops", "alice", 1, false); err == nil {
		t.Fatal("membership audit failure ignored")
	}
	team, err = f.repo.GetTeam(f.ctx, "ops")
	members, membersErr := f.repo.ListMembers(f.ctx, "ops", "", 200)
	if err != nil || membersErr != nil || team.Revision != 1 || len(members) != 1 || members[0].UserID != "bob" {
		t.Fatalf("partial membership: %+v %+v %v %v", team, members, err, membersErr)
	}
	if _, err := svc.SetLegacyAssignee(f.ctx, "own-a-eng", "own-a-legacy", "", "alice", 1); err == nil {
		t.Fatal("legacy clear audit failure ignored")
	}
	cur, err := f.repo.GetAssignment(f.ctx, "own-a-eng", "own-a-legacy")
	if err != nil || cur.FindingVersion != 1 || cur.FindingAssignee != "Old owner" || cur.Assignment.Revision != 0 {
		t.Fatalf("partial legacy clear: %+v %v", cur, err)
	}
	for _, table := range []string{"ownership_decisions", "ownership_intents", "audit_log"} {
		if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
			var n int
			if err := tx.QueryRow(f.ctx, `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Errorf("partial %s: %d", table, n)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.ddl.Exec(`DROP TRIGGER ownership_api_audit_failure ON audit_log; DROP FUNCTION ownership_api_audit_fail()`); err != nil {
		t.Fatal(err)
	}
	updated, err := svc.SetLegacyAssignee(f.ctx, "own-a-eng", "own-a-legacy", "", "alice", 1)
	if err != nil || updated.Version != 2 || updated.Assignee != "" {
		t.Fatalf("retry clear: %+v %v", updated, err)
	}
	if _, err := svc.SetLegacyAssignee(f.ctx, "own-a-eng", "own-a-legacy", "ignored", "alice", 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale clear retry: %v", err)
	}
	history, err := f.repo.ListDecisions(f.ctx, "own-a-eng", "own-a-legacy", ports.OwnershipHistoryCursor{Limit: 200})
	if err != nil || len(history) != 1 || history[0].After.Mode != "manual" || history[0].After.ManualGeneration != 1 {
		t.Fatalf("retry history: %+v %v", history, err)
	}
}
