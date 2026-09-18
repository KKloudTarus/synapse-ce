package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestJudgmentStore(t *testing.T) {
	st := NewJudgmentStore()
	ctx := context.Background()
	j := judgment.Judgment{
		ID: "j1", EngagementID: "e1", Capability: judgment.CapReachability,
		SubjectKind: judgment.SubjectFinding, SubjectID: "f1", State: judgment.StateProposed, Version: 1,
	}
	if err := st.Save(ctx, j); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.ListByEngagement(ctx, "e1"); len(got) != 1 || got[0].ID != "j1" {
		t.Fatalf("ListByEngagement: %+v", got)
	}
	if got, _ := st.ListBySubject(ctx, "e1", "f1"); len(got) != 1 {
		t.Fatalf("ListBySubject: %+v", got)
	}
	if got, _ := st.ListBySubject(ctx, "e1", "other"); len(got) != 0 {
		t.Fatalf("ListBySubject other: %+v", got)
	}

	upd, err := st.SetScoreState(ctx, "e1", "j1", 80, judgment.StateConfirmed, 1)
	if err != nil {
		t.Fatal(err)
	}
	if upd.EvidenceScore != 80 || upd.State != judgment.StateConfirmed || upd.Version != 2 || upd.VerifiedBy != "" || upd.VerdictRationale != "" {
		t.Fatalf("SetScoreState: %+v", upd)
	}
	provenance, err := st.SetVerdictState(ctx, "e1", "j1", 91, judgment.StateConfirmed, "human:verifier", "reproduced", 2)
	if err != nil {
		t.Fatal(err)
	}
	if provenance.VerifiedBy != "human:verifier" || provenance.VerdictRationale != "reproduced" || provenance.EvidenceScore != 91 || provenance.Version != 3 {
		t.Fatalf("SetVerdictState lost provenance: %#v", provenance)
	}
	accepted, err := st.SetScoreState(ctx, "e1", "j1", 91, judgment.StateConfirmed, 3)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.VerifiedBy != "human:verifier" || accepted.VerdictRationale != "reproduced" || accepted.Version != 4 {
		t.Fatalf("SetScoreState cleared sealed provenance: %#v", accepted)
	}
	// stale expectedVersion → conflict (lost-update guard)
	if _, err := st.SetScoreState(ctx, "e1", "j1", 90, judgment.StateRefuted, 3); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version: want ErrConflict, got %v", err)
	}
	// unknown id → not found
	if _, err := st.SetScoreState(ctx, "e1", "nope", 1, judgment.StateConfirmed, 4); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}

	// Save is insert-only: a re-Save of an existing id must NOT clobber score/state (mirror
	// postgres ON CONFLICT DO NOTHING). The row is currently confirmed/80/v2 from SetScoreState.
	clobber := j
	clobber.State = judgment.StateProposed
	clobber.EvidenceScore = 0
	clobber.Version = 99
	if err := st.Save(ctx, clobber); err != nil {
		t.Fatal(err)
	}
	again, _ := st.ListByEngagement(ctx, "e1")
	if again[0].EvidenceScore != 91 || again[0].State != judgment.StateConfirmed || again[0].Version != 4 || again[0].VerifiedBy != "human:verifier" || again[0].VerdictRationale != "reproduced" {
		t.Fatalf("re-Save clobbered an existing row: %+v", again[0])
	}
}
