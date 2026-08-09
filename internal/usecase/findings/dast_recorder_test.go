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

func TestRecordConfirmedNativeDAST(t *testing.T) {
	repo := &fakeRepo{}
	svc := newSvc(repo, &fakeComments{}, &fakeAudit{})
	j := judgment.Judgment{
		ID: "j-native", EngagementID: "eng-1", Capability: judgment.CapDAST,
		Claim: judgment.DASTClaim{CWE: "CWE-79", Location: "/search", Rule: "reflected-xss", Source: "first_party", Fingerprint: "search_reflection", ProofEvidenceID: "proof-1"},
	}
	if err := svc.RecordConfirmedDAST(context.Background(), "human:bob", j); err != nil {
		t.Fatalf("record: %v", err)
	}
	if got := repo.upserted[0].DedupKey; got != "dast:first_party:search_reflection" {
		t.Fatalf("DedupKey = %q", got)
	}
}

func TestRecordConfirmedDASTRejectsWrongInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		j    judgment.Judgment
	}{
		{"wrong capability", func() judgment.Judgment { j := confirmedSAST(); j.Capability = judgment.CapReachability; return j }()},
		{"wrong claim", func() judgment.Judgment {
			j := confirmedSAST()
			j.Claim = judgment.ReachabilityClaim{Reachable: "unknown", Tier: "tier-0"}
			return j
		}()},
		{"proposed", func() judgment.Judgment { j := confirmedSAST(); j.State = judgment.StateProposed; return j }()},
		{"confirmed below evidence bar", func() judgment.Judgment { j := confirmedSAST(); j.EvidenceScore = 74; return j }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepo{}
			if err := newSvc(repo, &fakeComments{}, &fakeAudit{}).RecordConfirmedDAST(context.Background(), "human:bob", tc.j); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
			if len(repo.upserted) != 0 {
				t.Fatal("non-publishable judgment must not persist a finding")
			}
		})
	}
}
