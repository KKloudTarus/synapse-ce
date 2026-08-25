package pyreach

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	exportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/export"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTier2RecorderMintsSemanticClaimsAndFiltersIncompleteNegative(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		t.Run(fmt.Sprintf("incomplete=%v", incomplete), func(t *testing.T) {
			store := memory.NewJudgmentStore()
			service, err := analysis.NewService(store, tier2Sealer{}, tier2Auditor{}, tier2Clock{}, &tier2IDs{})
			if err != nil {
				t.Fatal(err)
			}
			recorder, err := NewTier2Recorder(
				&fakePythonFactsProvider{document: pythonTier2Fixture(incomplete), available: true},
				service, tier2Auditor{}, tier2Clock{},
			)
			if err != nil {
				t.Fatal(err)
			}
			positive := mustPythonSubject(t, "requests.sessions.Session.request")
			negative := mustPythonSubject(t, "requests.sessions.safe")
			minted, err := recorder.Record(context.Background(), "eng", "/workspace", []ports.ReachabilitySubject{
				{FindingID: "positive", Symbols: []string{positive}},
				{FindingID: "negative", Symbols: []string{negative}},
			})
			if err != nil {
				t.Fatal(err)
			}
			want := 2
			if incomplete {
				want = 1
			}
			if minted != want {
				t.Fatalf("minted = %d, want %d", minted, want)
			}
			judgments, err := store.ListByEngagement(context.Background(), "eng")
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range judgments {
				claim, ok := item.Claim.(judgment.ReachabilityClaim)
				if !ok || claim.Tier != judgment.Tier2 || !item.Publishable() {
					t.Fatalf("semantic judgment = %+v", item)
				}
				if item.SubjectID == "negative" && claim.Reachable != judgment.NotReachable {
					t.Fatalf("negative claim = %+v", claim)
				}
			}
			if !incomplete {
				findings := memory.NewFindingRepository()
				if err := findings.Upsert(context.Background(), []finding.Finding{{
					ID: "negative", EngagementID: "eng", Kind: finding.KindSCA, Status: finding.StatusFalsePos,
					Title: "Python affected symbol", Severity: shared.SeverityHigh, DedupKey: "vuln:CVE-1:requests:2.31.0",
				}}); err != nil {
					t.Fatal(err)
				}
				exporter := exportuc.NewService(findings, tier2Clock{}, "test")
				exporter.SetJudgments(store)
				document, err := exporter.OpenVEX(context.Background(), "eng")
				if err != nil || len(document.Statements) != 1 || document.Statements[0].Status != "not_affected" ||
					document.Statements[0].Justification != "vulnerable_code_not_in_execute_path" {
					t.Fatalf("Tier-2 OpenVEX = %+v err=%v", document, err)
				}
			}
		})
	}
}

type tier2Sealer struct{}

func (tier2Sealer) Seal(context.Context, shared.ID, string, []byte, string) (evidence.Evidence, error) {
	return evidence.Evidence{}, nil
}

type tier2Auditor struct{}

func (tier2Auditor) Record(context.Context, ports.AuditEntry) error     { return nil }
func (tier2Auditor) RecordOnce(context.Context, ports.AuditEntry) error { return nil }

type tier2Clock struct{}

func (tier2Clock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

type tier2IDs struct{ next int }

func (ids *tier2IDs) NewID() shared.ID {
	ids.next++
	return shared.ID(fmt.Sprintf("tier2-%d", ids.next))
}
