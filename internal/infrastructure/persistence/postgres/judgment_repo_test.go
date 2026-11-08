package postgres

import (
	"context"
	"errors"
	"os"
	"reflect"
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
	ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)
	if err := MigrateLocked(ctx, dsn); err != nil {
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
	if list[0].State != judgment.StateProposed || list[0].EvidenceScore != 0 || list[0].VerifiedBy != "" || list[0].VerdictRationale != "" {
		t.Fatalf("want proposed/0/empty provenance, got %#v", list[0])
	}
	if rc, ok := list[0].Claim.(judgment.ReachabilityClaim); !ok || rc.Tier != "tier-1.5" {
		t.Fatalf("claim did not round-trip typed: %#v", list[0].Claim)
	}
	if bySub, _ := repo.ListBySubject(ctx, eid, "f1"); len(bySub) != 1 {
		t.Fatalf("ListBySubject: %+v", bySub)
	}

	// Score/state updates for acceptance must not invent or clear verdict provenance.
	upd, err := repo.SetScoreState(ctx, eid, jid, 80, judgment.StateConfirmed, 1)
	if err != nil {
		t.Fatalf("SetScoreState: %v", err)
	}
	if upd.EvidenceScore != 80 || upd.State != judgment.StateConfirmed || upd.Version != 2 || upd.VerifiedBy != "" || upd.VerdictRationale != "" {
		t.Fatalf("SetScoreState result: %+v", upd)
	}

	// A verdict transition round-trips its sealed provenance through storage.
	verdictState, err := repo.SetVerdictState(ctx, eid, jid, 90, judgment.StateConfirmed, "human:verifier", "reproduced", 2)
	if err != nil {
		t.Fatalf("SetVerdictState: %v", err)
	}
	if verdictState.EvidenceScore != 90 || verdictState.Version != 3 || verdictState.VerifiedBy != "human:verifier" || verdictState.VerdictRationale != "reproduced" {
		t.Fatalf("SetVerdictState result: %+v", verdictState)
	}
	list, err = repo.ListByEngagement(ctx, eid)
	if err != nil || len(list) != 1 || list[0].VerifiedBy != "human:verifier" || list[0].VerdictRationale != "reproduced" {
		t.Fatalf("verdict provenance did not round-trip: %+v err=%v", list, err)
	}

	// stale version → conflict (lost-update guard)
	if _, err := repo.SetScoreState(ctx, eid, jid, 90, judgment.StateRefuted, 2); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version: want ErrConflict, got %v", err)
	}
	// unknown id → not found
	if _, err := repo.SetScoreState(ctx, eid, shared.ID("nope"), 1, judgment.StateConfirmed, 3); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}

	// fail-closed on a corrupted enum row (defense-in-depth): a hand-edited row with a junk state
	// must be rejected on read, never hydrated. (Last assertion – it poisons ListByEngagement.)
	if _, err := pool.Exec(ctx,
		`INSERT INTO judgments (id, tenant_id, engagement_id, capability, subject_kind, subject_id, claim, state, version, created_at, updated_at)
		 VALUES ($1,'default',$2,'reachability','finding','f1','{"capability":"reachability","claim":{"reachable":"unknown","tier":"tier-0","confidence":0}}','GARBAGE',1,now(),now())`,
		"jbad-"+randHex(t), eid.String()); err != nil {
		t.Fatalf("insert corrupted row: %v", err)
	}
	if _, err := repo.ListByEngagement(ctx, eid); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("corrupted enum row should fail-closed on read, got %v", err)
	}
}

func TestJudgmentRepositoryGetByIDScoped(t *testing.T) {
	f := newTenantRLSFixtureWithDSN(t, isolatedMigrationDSN(t, testDSN(t), "judgment_get_by_id"))
	root := context.Background()
	suffix := randHex(t)
	tenant := shared.ID("judgment-tenant-" + suffix)
	foreignTenant := shared.ID("judgment-foreign-" + suffix)
	engagementID := shared.ID("judgment-engagement-" + suffix)
	otherEngagementID := shared.ID("judgment-other-engagement-" + suffix)
	id := shared.ID("judgment-id-" + suffix)
	corruptID := shared.ID("judgment-corrupt-" + suffix)

	t.Cleanup(func() {
		if _, err := f.owner.Exec(root, `DELETE FROM judgments WHERE id = ANY($1)`, []string{id.String(), corruptID.String()}); err != nil {
			t.Errorf("delete judgments: %v", err)
		}
		if _, err := f.owner.Exec(root, `DELETE FROM engagements WHERE id = ANY($1)`, []string{engagementID.String(), otherEngagementID.String()}); err != nil {
			t.Errorf("delete engagements: %v", err)
		}
		if _, err := f.owner.Exec(root, `DELETE FROM tenants WHERE id = ANY($1)`, []string{tenant.String(), foreignTenant.String()}); err != nil {
			t.Errorf("delete tenants: %v", err)
		}
	})
	for _, tenantID := range []shared.ID{tenant, foreignTenant} {
		if _, err := f.owner.Exec(root, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	for _, eng := range []shared.ID{engagementID, otherEngagementID} {
		if _, err := f.owner.Exec(root, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, eng, tenant); err != nil {
			t.Fatalf("seed engagement: %v", err)
		}
	}

	ctx := shared.WithTenant(root, tenant)
	repo := NewJudgmentRepository(f.runtime)
	claim := judgment.ReachabilityClaim{
		Reachable: "reachable", Tier: "tier-1.5", Confidence: 90,
		Path: []string{"entry", "vulnerable"}, EntrypointsPresent: true,
	}
	j, err := judgment.New(id, engagementID, judgment.CapReachability, judgment.SubjectFinding,
		"finding-1", claim, "agent:proposer", time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Save(ctx, j); err != nil {
		t.Fatalf("save judgment: %v", err)
	}
	if _, err := repo.SetVerdictState(ctx, engagementID, id, 90, judgment.StateConfirmed, "human:verifier", "reproduced path", 1); err != nil {
		t.Fatalf("set verdict: %v", err)
	}

	got, err := repo.GetByID(ctx, engagementID, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != id || got.EngagementID != engagementID || got.Capability != judgment.CapReachability ||
		got.SubjectKind != judgment.SubjectFinding || got.SubjectID != "finding-1" ||
		got.State != judgment.StateConfirmed || got.EvidenceScore != 90 || got.Version != 2 ||
		got.ProposedBy != "agent:proposer" || got.VerifiedBy != "human:verifier" || got.VerdictRationale != "reproduced path" {
		t.Fatalf("GetByID returned wrong judgment or provenance: %+v", got)
	}
	if actual, ok := got.Claim.(judgment.ReachabilityClaim); !ok || !reflect.DeepEqual(actual, claim) {
		t.Fatalf("GetByID claim = %#v, want typed %#v", got.Claim, claim)
	}

	for _, tc := range []struct {
		name string
		ctx  context.Context
		eng  shared.ID
		id   shared.ID
	}{
		{"wrong engagement", ctx, otherEngagementID, id},
		{"foreign tenant", shared.WithTenant(root, foreignTenant), engagementID, id},
		{"missing id", ctx, engagementID, shared.ID("missing-" + suffix)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := repo.GetByID(tc.ctx, tc.eng, tc.id); !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("GetByID: want ErrNotFound, got %v", err)
			}
		})
	}

	if _, err := f.owner.Exec(root,
		`INSERT INTO judgments (id, tenant_id, engagement_id, capability, subject_kind, subject_id, claim, state, version, created_at, updated_at)
		 VALUES ($1,$2,$3,'reachability','finding','f1','{"capability":"reachability","claim":{"reachable":"unknown","tier":"tier-0","confidence":0}}','GARBAGE',1,now(),now())`,
		corruptID, tenant, engagementID); err != nil {
		t.Fatalf("insert corrupt judgment: %v", err)
	}
	if _, err := repo.GetByID(ctx, engagementID, corruptID); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("corrupt enum: want ErrValidation, got %v", err)
	}
}
