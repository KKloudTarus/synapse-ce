package findings

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func confirmedSAST() judgment.Judgment {
	return judgment.Judgment{
		ID: "j-9", EngagementID: "eng-1", Capability: judgment.CapSAST,
		SubjectKind: judgment.SubjectDataFlow, SubjectID: "flow-9",
		Claim: judgment.SASTClaim{CWE: "CWE-89", Location: "app/dao.Find", Rule: "taint-sqli"},
		State: judgment.StateConfirmed, EvidenceScore: finding.EvidenceThreshold,
	}
}

func TestRecordConfirmedSAST(t *testing.T) {
	repo := &fakeRepo{}
	audit := &fakeAudit{}
	svc := newSvc(repo, &fakeComments{}, audit)
	if err := svc.RecordConfirmedSAST(context.Background(), "human:bob", confirmedSAST()); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(repo.upserted) != 1 {
		t.Fatalf("want 1 sast finding persisted, got %d", len(repo.upserted))
	}
	f := repo.upserted[0]
	if f.Kind != finding.KindSAST || f.Class != finding.ClassFirstParty || f.DedupKey != "sast:ai:j-9" {
		t.Fatalf("sast finding wrong kind/class/dedup: %+v", f)
	}
	if f.CWE != "CWE-89" || f.ProposedBy != "" {
		t.Errorf("CWE must carry through + ProposedBy empty (the gate ran at the judgment layer): %+v", f)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "finding.sast_promoted" {
		t.Errorf("promotion must be audited, got %+v", audit.entries)
	}
	if audit.entries[0].Actor != "human:bob" {
		t.Errorf("promotion must be attributed to the verifier (the trigger), not the system proposer; got %q", audit.entries[0].Actor)
	}
}

func TestRecordConfirmedSASTRejectsWrongInput(t *testing.T) {
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
			if err := newSvc(repo, &fakeComments{}, &fakeAudit{}).RecordConfirmedSAST(context.Background(), "human:bob", tc.j); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
			if len(repo.upserted) != 0 {
				t.Fatal("non-publishable judgment must not persist a finding")
			}
		})
	}
}
