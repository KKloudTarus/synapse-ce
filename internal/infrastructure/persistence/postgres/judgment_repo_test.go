package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Integration test – runs only when SYNAPSE_TEST_DB_DSN points at a Postgres.
func TestJudgmentRepository(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	eid := shared.ID("jt-" + randHex(t))
	e, err := engagement.New(eid, "", "judgment-test", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, e); err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM judgments WHERE engagement_id=$1", eid.String())
		_, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", eid.String())
	})

	repo := NewJudgmentRepository(pool)
	now := time.Now().UTC().Truncate(time.Second)
	jid := shared.ID("jid-" + randHex(t))
	j, err := judgment.New(jid, eid, judgment.CapReachability, judgment.SubjectFinding, "f1",
		judgment.ReachabilityClaim{Reachable: "not_reachable", Tier: "tier-1.5", Confidence: 90}, "agent:s1", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Save(ctx, j); err != nil {
		t.Fatalf("save: %v", err)
	}

	// round-trip: claim decodes fail-closed back to the typed value
	list, err := repo.ListByEngagement(ctx, eid)
	if err != nil || len(list) != 1 || list[0].ID != jid {
		t.Fatalf("ListByEngagement: %+v err=%v", list, err)
	}
	if list[0].State != judgment.StateProposed || list[0].EvidenceScore != 0 {
		t.Fatalf("want proposed/0, got %s/%d", list[0].State, list[0].EvidenceScore)
	}
	if rc, ok := list[0].Claim.(judgment.ReachabilityClaim); !ok || rc.Tier != "tier-1.5" {
		t.Fatalf("claim did not round-trip typed: %#v", list[0].Claim)
	}
	if bySub, _ := repo.ListBySubject(ctx, eid, "f1"); len(bySub) != 1 {
		t.Fatalf("ListBySubject: %+v", bySub)
	}

	// score/state move under optimistic concurrency
	upd, err := repo.SetScoreState(ctx, eid, jid, 80, judgment.StateConfirmed, 1)
	if err != nil {
		t.Fatalf("SetScoreState: %v", err)
	}
	if upd.EvidenceScore != 80 || upd.State != judgment.StateConfirmed || upd.Version != 2 {
		t.Fatalf("SetScoreState result: %+v", upd)
	}
	// stale version → conflict (lost-update guard)
	if _, err := repo.SetScoreState(ctx, eid, jid, 90, judgment.StateRefuted, 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version: want ErrConflict, got %v", err)
	}
	// unknown id → not found
	if _, err := repo.SetScoreState(ctx, eid, shared.ID("nope"), 1, judgment.StateConfirmed, 1); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}

	// fail-closed on a corrupted enum row (defense-in-depth): a hand-edited row with a junk state
	// must be rejected on read, never hydrated. (Last assertion – it poisons ListByEngagement.)
	if _, err := pool.Exec(ctx,
		`INSERT INTO judgments (id, tenant_id, engagement_id, capability, subject_kind, subject_id, claim, state, version, created_at, updated_at)
		 VALUES ($1,'',$2,'reachability','finding','f1','{"capability":"reachability","claim":{"reachable":"unknown","tier":"tier-0","confidence":0}}','GARBAGE',1,now(),now())`,
		"jbad-"+randHex(t), eid.String()); err != nil {
		t.Fatalf("insert corrupted row: %v", err)
	}
	if _, err := repo.ListByEngagement(ctx, eid); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("corrupted enum row should fail-closed on read, got %v", err)
	}
}
