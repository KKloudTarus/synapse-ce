package findings

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestRecordConfirmedDAST(t *testing.T) {
	repo := &fakeRepo{}
	audit := &fakeAudit{}
	svc := newSvc(repo, &fakeComments{}, audit)
	if err := svc.RecordConfirmedDAST(context.Background(), "human:bob", confirmedSAST()); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(repo.upserted) != 1 {
		t.Fatalf("want 1 dast finding persisted, got %d", len(repo.upserted))
	}
	f := repo.upserted[0]
	if f.Kind != finding.KindDAST || f.Class != finding.ClassFirstParty || f.DedupKey != "dast:ai:j-9" {
		t.Fatalf("dast finding wrong kind/class/dedup: %+v", f)
	}
	if f.Reachability != "reachable" {
		t.Errorf("a runtime probe proves reachability, want Reachability=reachable, got %q", f.Reachability)
	}
	if f.CWE != "CWE-89" || f.ProposedBy != "" {
		t.Errorf("CWE must carry through + ProposedBy empty (the gate ran at the judgment layer): %+v", f)
	}
	// The DAST dedup key differs from the SAST projection's so a static + a runtime confirmation of the
	// SAME judgment never collide into one row.
	if f.DedupKey == "sast:ai:j-9" {
		t.Errorf("DAST dedup key must not collide with the SAST projection")
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "finding.dast_promoted" {
		t.Errorf("promotion must be audited, got %+v", audit.entries)
	}
	if audit.entries[0].Actor != "human:bob" {
		t.Errorf("promotion must be attributed to the verifier (the trigger), not the system proposer; got %q", audit.entries[0].Actor)
	}
}

func TestRecordConfirmedDASTRejectsWrongInput(t *testing.T) {
	svc := newSvc(&fakeRepo{}, &fakeComments{}, &fakeAudit{})
	// not a sast capability
	j := confirmedSAST()
	j.Capability = judgment.CapReachability
	if err := svc.RecordConfirmedDAST(context.Background(), "human:bob", j); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("non-sast capability must be rejected, got %v", err)
	}
	// sast capability but the claim isn't a SASTClaim (defense-in-depth)
	j2 := confirmedSAST()
	j2.Claim = judgment.ReachabilityClaim{Reachable: "unknown", Tier: "tier-0"}
	if err := svc.RecordConfirmedDAST(context.Background(), "human:bob", j2); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a sast judgment without a SASTClaim must be rejected, got %v", err)
	}
}
