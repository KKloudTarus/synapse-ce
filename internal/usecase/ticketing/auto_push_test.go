package ticketing_test

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usecase "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

func TestAutoPushEligibilityAndActivation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		status           finding.Status
		kind             finding.Kind
		severity         shared.Severity
		score            int
		beforeActivation bool
		want             int
	}{
		{name: "confirmed native", status: finding.StatusConfirmed, kind: finding.KindManual, severity: shared.SeverityCritical, want: 1},
		{name: "unconfirmed", status: finding.StatusOpen, kind: finding.KindManual, severity: shared.SeverityCritical},
		{name: "low severity", status: finding.StatusConfirmed, kind: finding.KindManual, severity: shared.SeverityLow},
		{name: "external even with evidence", status: finding.StatusConfirmed, kind: finding.KindExternal, severity: shared.SeverityCritical, score: 100},
		{name: "unverified exploitation", status: finding.StatusConfirmed, kind: finding.KindExploitation, severity: shared.SeverityCritical},
		{name: "historical confirmation", status: finding.StatusConfirmed, kind: finding.KindManual, severity: shared.SeverityCritical, beforeActivation: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWorkflowFixture(t)
			f.workflow.SetAutoPushSourceAvailable(true)
			ctx := shared.WithTenant(context.Background(), "tenant-a")
			_, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "security-1", AutoPushEnabled: true, AutoPushMinSeverity: shared.SeverityHigh, Actor: "admin", AllowAdmin: true})
			if err != nil {
				t.Fatal(err)
			}
			candidate := finding.Finding{ID: "auto-candidate", EngagementID: "eng-a", Title: "Confirmed test finding", Severity: tc.severity, Status: tc.status, Kind: tc.kind, EvidenceScore: tc.score, DedupKey: "manual:auto-candidate", Version: 1, Audit: shared.Audit{CreatedAt: f.clock.Now(), UpdatedAt: f.clock.Now()}}
			err = f.findings.Upsert(ctx, []finding.Finding{candidate})
			if tc.kind == finding.KindExternal {
				if err == nil || f.provider.posts != 0 {
					t.Fatal("external import acquired native finding authority")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			at := f.clock.Now().Add(time.Nanosecond)
			if tc.beforeActivation {
				at = f.clock.Now().Add(-time.Second)
			}
			event := ports.TicketAutoPushEvent{ID: "candidate-confirmation", OccurredAt: at, EngagementID: "eng-a", FindingID: candidate.ID, ToStatus: "confirmed"}
			if err = f.store.AppendAutoPushEvent("tenant-a", event); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
					t.Fatal(err)
				}
			}
			intents, err := f.store.ListFindingIntents(ctx, "tenant-a", candidate.ID, 10)
			if err != nil || len(intents) != tc.want || f.provider.posts != tc.want {
				t.Fatalf("intents=%d posts=%d want=%d err=%v", len(intents), f.provider.posts, tc.want, err)
			}
		})
	}
}
