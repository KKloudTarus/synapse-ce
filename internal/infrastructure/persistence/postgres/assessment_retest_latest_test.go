package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestPostgresAssessmentRetestLatestRead(t *testing.T) {
	ctx, pool := setupTestDB(t)
	ensureTestTenantAndEngagement(t, ctx, pool, "latest", "assessment", "", "")
	ctx = shared.WithTenant(ctx, "latest")
	now := time.Now().UTC().Truncate(time.Microsecond)
	item := finding.Finding{ID: "finding", EngagementID: "assessment", Title: "Verification", Kind: finding.KindManual, Severity: shared.SeverityHigh, Status: finding.StatusConfirmed, DedupKey: "manual", Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
	if err := NewFindingRepository(pool).Upsert(ctx, []finding.Finding{item}); err != nil {
		t.Fatal(err)
	}
	repo := NewRetestRepository(pool)
	for _, id := range []shared.ID{"a", "z"} {
		decision, err := finding.NewRetest(id, item.EngagementID, item.ID, finding.RetestRemediated, "not part of comparison projection", "tester", now)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Add(ctx, decision); err != nil {
			t.Fatal(err)
		}
	}
	history, err := repo.RetestHistories(ctx, item.EngagementID, []shared.ID{item.ID, "missing"})
	if err != nil || len(history) != 1 || len(history[item.ID]) != 2 || history[item.ID][0].ID != "a" || history[item.ID][1].Note == "" {
		t.Fatalf("retained batch history=%+v err=%v", history, err)
	}
	foreign, err := repo.RetestHistories(shared.WithTenant(ctx, "other"), item.EngagementID, []shared.ID{item.ID})
	if err != nil || len(foreign) != 0 {
		t.Fatalf("foreign retained history=%+v err=%v", foreign, err)
	}
	if _, err := repo.RetestHistories(context.Background(), item.EngagementID, []shared.ID{item.ID}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unscoped history=%v", err)
	}
	if _, err := repo.RetestHistories(ctx, item.EngagementID, make([]shared.ID, 1001)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unbounded history=%v", err)
	}
	got, err := repo.LatestByEngagementFindings(ctx, item.EngagementID, []shared.ID{item.ID, "missing"})
	if err != nil || len(got) != 1 || got[item.ID].ID != "z" || got[item.ID].Outcome != finding.RetestRemediated || got[item.ID].Note != "" {
		t.Fatalf("latest=%+v err=%v", got, err)
	}
	got, err = repo.LatestByEngagementFindings(shared.WithTenant(ctx, "other"), item.EngagementID, []shared.ID{item.ID})
	if err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant read=%+v err=%v", got, err)
	}
	if _, err := repo.LatestByEngagementFindings(context.Background(), item.EngagementID, []shared.ID{item.ID}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unscoped read accepted: %v", err)
	}
}
