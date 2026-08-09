package findings

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func confirmedThreat() judgment.Judgment {
	return judgment.Judgment{
		ID: "j-1", EngagementID: "eng-1", Capability: judgment.CapThreat,
		SubjectKind: judgment.SubjectDataFlow, SubjectID: "flow-1",
		Claim: judgment.ThreatClaim{Category: judgment.InfoDisclosure, Asset: "pii"},
		State: judgment.StateConfirmed, EvidenceScore: finding.EvidenceThreshold,
	}
}

func TestRecordConfirmedThreat(t *testing.T) {
	repo := &fakeRepo{}
	audit := &fakeAudit{}
	svc := newSvc(repo, &fakeComments{}, audit)
	if err := svc.RecordConfirmedThreat(context.Background(), "human:bob", confirmedThreat()); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(repo.upserted) != 1 {
		t.Fatalf("want 1 threat finding persisted, got %d", len(repo.upserted))
	}
	f := repo.upserted[0]
	if f.Kind != finding.KindThreat || f.Class != finding.ClassFirstParty || f.DedupKey != "threat:j-1" {
		t.Fatalf("threat finding wrong kind/class/dedup: %+v", f)
	}
	if f.Title != "STRIDE info_disclosure threat on flow-1" {
		t.Errorf("title not templated from the claim: %q", f.Title)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "finding.threat_promoted" {
		t.Errorf("promotion must be audited, got %+v", audit.entries)
	}
	if audit.entries[0].Actor != "human:bob" {
		t.Errorf("promotion must be attributed to the human verifier (the trigger), not the agent proposer; got %q", audit.entries[0].Actor)
	}
}

func TestRecordConfirmedThreatRejectsWrongInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		j    judgment.Judgment
	}{
		{"wrong capability", func() judgment.Judgment { j := confirmedThreat(); j.Capability = judgment.CapReachability; return j }()},
		{"wrong claim", func() judgment.Judgment {
			j := confirmedThreat()
			j.Claim = judgment.ReachabilityClaim{Reachable: "unknown", Tier: "tier-0"}
			return j
		}()},
		{"proposed", func() judgment.Judgment { j := confirmedThreat(); j.State = judgment.StateProposed; return j }()},
		{"confirmed below evidence bar", func() judgment.Judgment { j := confirmedThreat(); j.EvidenceScore = 74; return j }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepo{}
			if err := newSvc(repo, &fakeComments{}, &fakeAudit{}).RecordConfirmedThreat(context.Background(), "human:bob", tc.j); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
			if len(repo.upserted) != 0 {
				t.Fatal("non-publishable judgment must not persist a finding")
			}
		})
	}
}
