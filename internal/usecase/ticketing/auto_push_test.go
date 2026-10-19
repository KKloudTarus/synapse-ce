package ticketing_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
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

func TestAutoPushReconfirmationKeepsExistingTicket(t *testing.T) {
	f := newWorkflowFixture(t)
	f.workflow.SetAutoPushSourceAvailable(true)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	_, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "security-1", AutoPushEnabled: true, AutoPushMinSeverity: shared.SeverityHigh, Actor: "admin", AllowAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.findings.GetByEngagementAndID(ctx, "eng-a", "finding-a")
	if err != nil {
		t.Fatal(err)
	}
	current, err = f.findings.UpdateStatus(ctx, "eng-a", current.ID, finding.StatusConfirmed, current.Version)
	if err != nil {
		t.Fatal(err)
	}
	for _, eventID := range []shared.ID{"first-confirmation", "replayed-confirmation", "reconfirmation"} {
		if err = f.store.AppendAutoPushEvent("tenant-a", ports.TicketAutoPushEvent{ID: eventID, OccurredAt: f.clock.Now().Add(time.Nanosecond), EngagementID: "eng-a", FindingID: current.ID, ToStatus: "confirmed"}); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
		}
	}
	links, err := f.store.ListLinks(ctx, "tenant-a", current.ID)
	if err != nil || len(links) != 1 || f.provider.posts != 1 {
		t.Fatalf("distinct confirmation events duplicated ticket: links=%d posts=%d err=%v", len(links), f.provider.posts, err)
	}
}

func TestAutoPushPreservesEarlierInitialCommand(t *testing.T) {
	for _, tc := range []struct {
		name          string
		providerError *ports.TicketProviderError
		wantState     writeintent.State
	}{
		{name: "pending", wantState: writeintent.Done},
		{name: "refused", providerError: &ports.TicketProviderError{Status: 400}, wantState: writeintent.Failed},
		{name: "uncertain", providerError: &ports.TicketProviderError{Ambiguous: true}, wantState: writeintent.Uncertain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWorkflowFixture(t)
			f.workflow.SetAutoPushSourceAvailable(true)
			ctx := shared.WithTenant(context.Background(), "tenant-a")
			m, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "security-1", AutoPushEnabled: true, AutoPushMinSeverity: shared.SeverityHigh, Actor: "admin", AllowAdmin: true})
			if err != nil {
				t.Fatal(err)
			}
			current, err := f.findings.GetByEngagementAndID(ctx, "eng-a", "finding-a")
			if err != nil {
				t.Fatal(err)
			}
			current, err = f.findings.UpdateStatus(ctx, "eng-a", current.ID, finding.StatusConfirmed, current.Version)
			if err != nil {
				t.Fatal(err)
			}
			preview, err := f.workflow.Preview(ctx, usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: current.ID, EngagementID: "eng-a"})
			if err != nil {
				t.Fatal(err)
			}
			initial, _, err := f.workflow.Submit(ctx, usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: current.ID, EngagementID: "eng-a", RequestKey: "earlier-automatic-command", PreviewDigest: preview.Digest, Actor: "system:auto_push"})
			if err != nil {
				t.Fatal(err)
			}
			if tc.providerError != nil {
				f.provider.createErr = tc.providerError
				if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
					t.Fatal(err)
				}
				f.provider.createErr = nil
			}
			for _, id := range []shared.ID{"later-confirmation", "concurrent-confirmation"} {
				if err = f.store.AppendAutoPushEvent("tenant-a", ports.TicketAutoPushEvent{ID: id, OccurredAt: f.clock.Now().Add(time.Nanosecond), EngagementID: "eng-a", FindingID: current.ID, ToStatus: "confirmed"}); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
					t.Fatal(err)
				}
			}
			intents, err := f.store.ListFindingIntents(ctx, "tenant-a", current.ID, 10)
			if err != nil || len(intents) != 1 || intents[0].ID != initial.ID || f.provider.posts != 1 {
				t.Fatalf("initial command bypassed: intents=%+v posts=%d err=%v", intents, f.provider.posts, err)
			}
			if intents[0].State != tc.wantState {
				t.Fatalf("initial command state=%s want=%s", intents[0].State, tc.wantState)
			}
		})
	}
}

func TestAutoPushConcurrentTicksCreateOneTicket(t *testing.T) {
	f, ctx, _ := configuredAutoPushWorkflow(t)
	appendConfirmedAutoPushEvents(t, f, 20)

	start := make(chan struct{})
	errs := make(chan error, 20)
	var workers sync.WaitGroup
	for range 20 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := f.workflow.Tick(ctx, "tenant-a", 100)
			errs <- err
		}()
	}
	close(start)
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	intents, err := f.store.ListFindingIntents(ctx, "tenant-a", "finding-a", 200)
	if err != nil || len(intents) != 1 || f.provider.posts != 1 {
		t.Fatalf("concurrent automatic admission intents=%d posts=%d err=%v", len(intents), f.provider.posts, err)
	}
}

func TestAutoPushFullHistoryDefersEventsUntilRetryInterval(t *testing.T) {
	f, ctx, _ := configuredAutoPushWorkflow(t)
	store := fullHistoryTicketStore{TicketStore: f.store, intents: unrelatedCreateIntents(t, f.clock.Now())}
	workflow, err := usecase.NewWorkflow(store, f.integrations, workflowProviders{f.provider}, f.findings, f.engagements, f.policy, f.audit, &ticketIDs{}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	workflow.SetAutoPushSourceAvailable(true)
	appendConfirmedAutoPushEvents(t, f, 20)

	if _, err = workflow.Tick(ctx, "tenant-a", 100); err != nil {
		t.Fatal(err)
	}
	intents, err := f.store.ListFindingIntents(ctx, "tenant-a", "finding-a", 200)
	if err != nil || len(intents) != 0 || f.provider.posts != 0 {
		t.Fatalf("full history made a remote write: intents=%d posts=%d err=%v", len(intents), f.provider.posts, err)
	}
	now, err := f.store.ListAutoPushEvents(ctx, "tenant-a", f.clock.Now(), 100)
	if err != nil || len(now) != 0 {
		t.Fatalf("full history events were not deferred: count=%d err=%v", len(now), err)
	}
	afterRetry, err := f.store.ListAutoPushEvents(ctx, "tenant-a", f.clock.Now().Add(time.Minute), 100)
	if err != nil || len(afterRetry) != 20 {
		t.Fatalf("full history events were not available after retry interval: count=%d err=%v", len(afterRetry), err)
	}
}

func configuredAutoPushWorkflow(t *testing.T) (workflowFixture, context.Context, domain.Mapping) {
	t.Helper()
	f := newWorkflowFixture(t)
	f.workflow.SetAutoPushSourceAvailable(true)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	mapping, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "security-1", AutoPushEnabled: true, AutoPushMinSeverity: shared.SeverityHigh, Actor: "admin", AllowAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.findings.GetByEngagementAndID(ctx, "eng-a", "finding-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.findings.UpdateStatus(ctx, "eng-a", current.ID, finding.StatusConfirmed, current.Version); err != nil {
		t.Fatal(err)
	}
	return f, ctx, mapping
}

func appendConfirmedAutoPushEvents(t *testing.T, f workflowFixture, count int) {
	t.Helper()
	for index := range count {
		event := ports.TicketAutoPushEvent{
			ID:           shared.ID(fmt.Sprintf("confirmed-auto-push-%d", index)),
			OccurredAt:   f.clock.Now().Add(time.Nanosecond),
			EngagementID: "eng-a",
			FindingID:    "finding-a",
			ToStatus:     "confirmed",
		}
		if err := f.store.AppendAutoPushEvent("tenant-a", event); err != nil {
			t.Fatal(err)
		}
	}
}

type fullHistoryTicketStore struct {
	*memory.TicketStore
	intents []domain.Intent
}

func (s fullHistoryTicketStore) ListFindingIntents(_ context.Context, _ shared.ID, _ shared.ID, _ int) ([]domain.Intent, error) {
	items := make([]domain.Intent, len(s.intents))
	for index, intent := range s.intents {
		items[index] = intent.Clone()
	}
	return items, nil
}

func unrelatedCreateIntents(t *testing.T, at time.Time) []domain.Intent {
	t.Helper()
	snapshot := json.RawMessage(`{"fields":{"project":{"key":"SEC"},"issuetype":{"id":"10001"}}}`)
	intents := make([]domain.Intent, 0, 200)
	for index := range 200 {
		id := shared.ID(fmt.Sprintf("history-intent-%03d", index))
		intent := domain.Intent{
			ID:                 id,
			TenantID:           "tenant-a",
			IntegrationID:      "jira",
			MappingID:          shared.ID(fmt.Sprintf("unrelated-mapping-%03d", index)),
			FindingID:          "finding-a",
			EngagementID:       "eng-a",
			Action:             domain.Create,
			RequestKey:         fmt.Sprintf("unrelated-history-%03d", index),
			PayloadDigest:      fmt.Sprintf("%064x", index+1),
			Marker:             "synapse-intent-" + id.String(),
			State:              writeintent.Pending,
			Version:            1,
			Snapshot:           append(json.RawMessage(nil), snapshot...),
			MappingVersion:     1,
			ConnectionRevision: 1,
			CredentialRevision: 1,
			SecurityLevel:      "security-1",
			CreatedAt:          at,
			UpdatedAt:          at,
		}
		if err := intent.Validate(); err != nil {
			t.Fatalf("invalid unrelated history fixture: %v", err)
		}
		intents = append(intents, intent)
	}
	return intents
}
