package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing/storetest"
)

type ticketAuditRecorder struct{}

func (ticketAuditRecorder) Record(context.Context, ports.AuditEntry) error { return nil }

type failingTicketAudit struct{}

func (failingTicketAudit) Record(context.Context, ports.AuditEntry) error {
	return errors.New("audit unavailable")
}

func TestTicketStoreConformance(t *testing.T) {
	f := storetest.Fixture{Tenant: "ticket-a", Other: "ticket-b", Integration: "ticket-integration-a",
		Project: "ticket-project-a", Engagement: "ticket-engagement-a", Finding: "ticket-finding-a"}
	engagements := NewEngagementRepository()
	findings := NewFindingRepository()
	seedTicketParents(t, engagements, findings, f)
	store, err := NewTicketStore(engagements, findings)
	if err != nil {
		t.Fatal(err)
	}
	store.SetAudit(ticketAuditRecorder{})
	storetest.Run(t, store, f)
	storetest.ConcurrentReplay(t, store, f)
	storetest.ConcurrentClaim(t, store, f)
	storetest.ConcurrentCompletionConflict(t, store, f)
	storetest.CanceledContext(t, store, f)
	storetest.Dispatch(t, store, f)
	storetest.StatusRefusalDoesNotGateTuple(t, store, f)
	storetest.InboundTombstone(t, store, f)
	storetest.InboundPollingClaims(t, store, f)
}

func TestNewTicketStoreRequiresParents(t *testing.T) {
	engagements := NewEngagementRepository()
	findings := NewFindingRepository()
	for _, parents := range []struct {
		name        string
		engagements *EngagementRepository
		findings    *FindingRepository
	}{
		{name: "engagements", findings: findings},
		{name: "findings", engagements: engagements},
	} {
		t.Run(parents.name, func(t *testing.T) {
			if store, err := NewTicketStore(parents.engagements, parents.findings); store != nil || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("store=%v err=%v", store, err)
			}
		})
	}
}

func TestTicketStoreRetryAuditFailureDoesNotPublish(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	f := storetest.Fixture{Tenant: "ticket-retry-a", Integration: "ticket-retry-integration", Project: "ticket-retry-project", Engagement: "ticket-retry-engagement", Finding: "ticket-retry-finding"}
	engagements, findings := NewEngagementRepository(), NewFindingRepository()
	seedTicketParents(t, engagements, findings, f)
	store, err := NewTicketStore(engagements, findings)
	if err != nil {
		t.Fatal(err)
	}
	mapping := ticketing.Mapping{ID: "ticket-retry-map", TenantID: f.Tenant, IntegrationID: f.Integration, Scope: ticketing.Engagement, ScopeID: f.Engagement, ProjectKey: "SEC", IssueType: "Bug", Version: 1, CreatedAt: now, UpdatedAt: now}
	if err = store.CreateMapping(ctx, f.Tenant, mapping); err != nil {
		t.Fatal(err)
	}
	intent := ticketing.Intent{ID: "ticket-retry-intent", TenantID: f.Tenant, IntegrationID: f.Integration, MappingID: mapping.ID, FindingID: f.Finding, EngagementID: f.Engagement, Action: ticketing.Create, RequestKey: "retry-audit", PayloadDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Marker: "synapse-intent-ticket-retry-intent", State: writeintent.Pending, Version: 1, MappingVersion: 1, ConnectionRevision: 1, Snapshot: []byte(`{"fields":{"project":{"key":"SEC"},"issuetype":{"id":"Bug"}}}`), CreatedAt: now, UpdatedAt: now}
	if _, created, e := store.CreateOrGetIntent(ctx, f.Tenant, intent); e != nil || !created {
		t.Fatalf("create intent: %t %v", created, e)
	}
	claimed, ok, err := store.AcquireDispatch(ctx, f.Tenant, intent.ID, 1, now, now.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("claim: %t %v", ok, err)
	}
	failed, err := store.FinishDispatch(ctx, f.Tenant, intent.ID, claimed.Version, ticketing.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_rejected"}, now.Add(time.Second), nil, "")
	if err != nil || failed.State != writeintent.Failed {
		t.Fatalf("reject: %+v %v", failed, err)
	}
	store.SetAudit(failingTicketAudit{})
	_, err = store.RetryIntentAudited(ctx, f.Tenant, intent.ID, failed.Version, now.Add(2*time.Second), ports.AuditEntry{Actor: "admin", Action: "ticket.intent.retry_duplicate_risk", Target: intent.ID.String(), At: now.Add(2 * time.Second)})
	if err == nil {
		t.Fatal("retry accepted failed audit")
	}
	got, err := store.GetIntent(ctx, f.Tenant, intent.ID)
	if err != nil || got.State != writeintent.Failed || got.Version != failed.Version {
		t.Fatalf("audit failure published retry: %+v %v", got, err)
	}
}

func TestTicketStoreAuditedCreateFence(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 2, 4, 0, 0, 0, 0, time.UTC)
	f := storetest.Fixture{Tenant: "ticket-fence-a", Integration: "ticket-fence-integration", Project: "ticket-fence-project", Engagement: "ticket-fence-engagement", Finding: "ticket-fence-finding"}
	engagements, findings := NewEngagementRepository(), NewFindingRepository()
	seedTicketParents(t, engagements, findings, f)
	store, err := NewTicketStore(engagements, findings)
	if err != nil {
		t.Fatal(err)
	}
	store.SetAudit(ticketAuditRecorder{})
	mapping := ticketing.Mapping{ID: "ticket-fence-map", TenantID: f.Tenant, IntegrationID: f.Integration, Scope: ticketing.Engagement, ScopeID: f.Engagement, ProjectKey: "SEC", IssueType: "Bug", Version: 1, CreatedAt: now, UpdatedAt: now}
	if err = store.CreateMapping(ctx, f.Tenant, mapping); err != nil {
		t.Fatal(err)
	}
	makeIntent := func(id string, findingID shared.ID, key string) ticketing.Intent {
		return ticketing.Intent{ID: shared.ID(id), TenantID: f.Tenant, IntegrationID: f.Integration, MappingID: mapping.ID, FindingID: findingID, EngagementID: f.Engagement, Action: ticketing.Create, RequestKey: key, PayloadDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Marker: "synapse-intent-" + id, State: writeintent.Pending, Version: 1, MappingVersion: 1, ConnectionRevision: 1, Snapshot: []byte(`{"fields":{"project":{"key":"SEC"},"issuetype":{"id":"Bug"}}}`), CreatedAt: now, UpdatedAt: now}
	}
	audit := func(id string, at time.Time) ports.AuditEntry {
		return ports.AuditEntry{Actor: "admin", Action: "ticket.intent.created", Target: id, At: at}
	}
	first := makeIntent("ticket-fence-first", f.Finding, "first")
	if _, created, e := store.CreateOrGetIntentAudited(ctx, f.Tenant, first, audit(first.ID.String(), now)); e != nil || !created {
		t.Fatalf("first audited create: %t %v", created, e)
	}
	replay := first
	replay.ID, replay.Marker = "ticket-fence-replay", "synapse-intent-ticket-fence-replay"
	if got, created, e := store.CreateOrGetIntentAudited(ctx, f.Tenant, replay, audit(replay.ID.String(), now)); e != nil || created || got.ID != first.ID {
		t.Fatalf("audited replay: %+v created=%t err=%v", got, created, e)
	}
	blocked := makeIntent("ticket-fence-blocked", f.Finding, "blocked")
	if _, _, e := store.CreateOrGetIntentAudited(ctx, f.Tenant, blocked, audit(blocked.ID.String(), now)); !errors.Is(e, shared.ErrConflict) {
		t.Fatalf("new request bypassed pending fence: %v", e)
	}
	lease := now.Add(time.Minute)
	claimed, e := store.TransitionIntent(ctx, f.Tenant, first.ID, 1, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = store.TransitionIntent(ctx, f.Tenant, first.ID, claimed.Version, ticketing.IntentTransition{Event: writeintent.Acknowledge, Remote: &ticketing.RemoteTicket{ID: "SEC-1", URL: "https://jira.example/browse/SEC-1"}}, now.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	afterDone := makeIntent("ticket-fence-after-done", f.Finding, "after-done")
	if _, created, e := store.CreateOrGetIntentAudited(ctx, f.Tenant, afterDone, audit(afterDone.ID.String(), now.Add(3*time.Second))); e != nil || !created {
		t.Fatalf("create after done: %t %v", created, e)
	}
	lateReplay := first
	lateReplay.ID, lateReplay.Marker = "ticket-fence-late-replay", "synapse-intent-ticket-fence-late-replay"
	if got, created, e := store.CreateOrGetIntentAudited(ctx, f.Tenant, lateReplay, audit(lateReplay.ID.String(), now.Add(3*time.Second))); e != nil || created || got.ID != first.ID {
		t.Fatalf("late audited replay: %+v created=%t err=%v", got, created, e)
	}
	alteredReplay := lateReplay
	alteredReplay.PayloadDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, _, e := store.CreateOrGetIntentAudited(ctx, f.Tenant, alteredReplay, audit(alteredReplay.ID.String(), now.Add(3*time.Second))); !errors.Is(e, shared.ErrConflict) {
		t.Fatalf("altered late replay accepted: %v", e)
	}
	claimed, e = store.TransitionIntent(ctx, f.Tenant, afterDone.ID, 1, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(3*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = store.TransitionIntent(ctx, f.Tenant, afterDone.ID, claimed.Version, ticketing.IntentTransition{Event: writeintent.LeaseExpired}, lease); e != nil {
		t.Fatal(e)
	}
	uncertain := makeIntent("ticket-fence-uncertain", f.Finding, "uncertain")
	if _, _, e := store.CreateOrGetIntentAudited(ctx, f.Tenant, uncertain, audit(uncertain.ID.String(), lease)); !errors.Is(e, shared.ErrConflict) {
		t.Fatalf("new request bypassed uncertain fence: %v", e)
	}
	secondFinding, e := finding.NewManual("ticket-fence-finding-two", f.Engagement, finding.ManualInput{Title: "Second", Severity: shared.SeverityHigh}, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = findings.Upsert(shared.WithTenant(ctx, f.Tenant), []finding.Finding{secondFinding}); e != nil {
		t.Fatal(e)
	}
	left, right := makeIntent("ticket-fence-race-left", secondFinding.ID, "race-left"), makeIntent("ticket-fence-race-right", secondFinding.ID, "race-right")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, candidate := range []ticketing.Intent{left, right} {
		wg.Add(1)
		go func(i ticketing.Intent) {
			defer wg.Done()
			_, _, e := store.CreateOrGetIntentAudited(ctx, f.Tenant, i, audit(i.ID.String(), now))
			results <- e
		}(candidate)
	}
	wg.Wait()
	close(results)
	wins := 0
	for e := range results {
		if e == nil {
			wins++
		} else if !errors.Is(e, shared.ErrConflict) {
			t.Fatalf("concurrent audited create: %v", e)
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent audited creates admitted=%d", wins)
	}
	thirdFinding, e := finding.NewManual("ticket-fence-finding-three", f.Engagement, finding.ManualInput{Title: "Third", Severity: shared.SeverityHigh}, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = findings.Upsert(shared.WithTenant(ctx, f.Tenant), []finding.Finding{thirdFinding}); e != nil {
		t.Fatal(e)
	}
	store.SetAudit(failingTicketAudit{})
	failedAudit := makeIntent("ticket-fence-audit-failure", thirdFinding.ID, "audit-failure")
	if _, _, e = store.CreateOrGetIntentAudited(ctx, f.Tenant, failedAudit, audit(failedAudit.ID.String(), now)); e == nil {
		t.Fatal("audited create accepted failed audit")
	}
	if _, e = store.GetIntent(ctx, f.Tenant, failedAudit.ID); !errors.Is(e, shared.ErrNotFound) {
		t.Fatalf("audit failure published intent: %v", e)
	}
}

func TestTicketStoreChecksProjectContextAndFindingReference(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	engagements := NewEngagementRepository()
	findings := NewFindingRepository()
	standard := storetest.Fixture{Tenant: "ticket-a", Integration: "ticket-integration-a", Project: "ticket-project-a", Engagement: "ticket-engagement-a", Finding: "ticket-finding-a"}
	seedTicketParents(t, engagements, findings, standard)
	projectContext, err := engagement.New("ticket-project-context-a", standard.Tenant, "Project ticketing", "Synapse", now)
	if err != nil {
		t.Fatal(err)
	}
	projectContext.ProjectID = standard.Project
	if err = engagements.Create(shared.WithTenant(ctx, standard.Tenant), projectContext); err != nil {
		t.Fatal(err)
	}
	projectFinding, err := finding.NewManual("ticket-project-finding-a", projectContext.ID, finding.ManualInput{Title: "Project ticket finding", Severity: shared.SeverityHigh}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = findings.Upsert(shared.WithTenant(ctx, standard.Tenant), []finding.Finding{projectFinding}); err != nil {
		t.Fatal(err)
	}
	store, err := NewTicketStore(engagements, findings)
	if err != nil {
		t.Fatal(err)
	}
	mapping := ticketing.Mapping{ID: "ticket-project-map-a", TenantID: standard.Tenant, IntegrationID: standard.Integration,
		Scope: ticketing.Project, ScopeID: standard.Project, ProjectKey: "SEC", IssueType: "Bug", Version: 1, CreatedAt: now, UpdatedAt: now}
	if err = store.CreateMapping(ctx, standard.Tenant, mapping); err != nil {
		t.Fatal(err)
	}
	intent := ticketing.Intent{ID: "ticket-project-intent-a", TenantID: standard.Tenant, IntegrationID: standard.Integration,
		MappingID: mapping.ID, FindingID: projectFinding.ID, EngagementID: projectContext.ID, Action: ticketing.Create,
		RequestKey: "project-context", PayloadDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Marker: "synapse-intent-ticket-project-intent-a", State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	if _, created, createErr := store.CreateOrGetIntent(ctx, standard.Tenant, intent); createErr != nil || !created {
		t.Fatalf("project intent: created=%t err=%v", created, createErr)
	}
	if _, created, createErr := store.CreateLink(ctx, standard.Tenant, ticketing.Link{ID: "ticket-project-link-a", TenantID: standard.Tenant, FindingID: projectFinding.ID, EngagementID: projectContext.ID, ExternalURL: "https://jira.example/browse/PROJECT-1", CreatedAt: now}); createErr != nil || !created {
		t.Fatalf("project context link: created=%t err=%v", created, createErr)
	}
	engagementMapping := mapping
	engagementMapping.ID = "ticket-project-engagement-map-a"
	engagementMapping.Scope = ticketing.Engagement
	engagementMapping.ScopeID = projectContext.ID
	if err = store.CreateMapping(ctx, standard.Tenant, engagementMapping); err != nil {
		t.Fatal(err)
	}
	engagementIntent := intent
	engagementIntent.ID = "ticket-project-engagement-intent-a"
	engagementIntent.MappingID = engagementMapping.ID
	engagementIntent.RequestKey = "project-engagement-context"
	engagementIntent.Marker = "synapse-intent-" + engagementIntent.ID.String()
	if _, created, createErr := store.CreateOrGetIntent(ctx, standard.Tenant, engagementIntent); createErr != nil || !created {
		t.Fatalf("engagement-scoped project context intent: created=%t err=%v", created, createErr)
	}
	wrongContext := intent
	wrongContext.ID = "ticket-project-intent-wrong-a"
	wrongContext.Marker = "synapse-intent-" + wrongContext.ID.String()
	wrongContext.RequestKey = "wrong-project-context"
	wrongContext.EngagementID = standard.Engagement
	wrongContext.FindingID = standard.Finding
	if _, _, createErr := store.CreateOrGetIntent(ctx, standard.Tenant, wrongContext); !errors.Is(createErr, shared.ErrValidation) {
		t.Fatalf("accepted project intent for unrelated engagement: %v", createErr)
	}
	missingFinding := intent
	missingFinding.ID = "ticket-project-intent-missing-a"
	missingFinding.Marker = "synapse-intent-" + missingFinding.ID.String()
	missingFinding.RequestKey = "missing-project-finding"
	missingFinding.FindingID = "ticket-finding-missing-a"
	if _, _, createErr := store.CreateOrGetIntent(ctx, standard.Tenant, missingFinding); !errors.Is(createErr, shared.ErrNotFound) {
		t.Fatalf("accepted missing project finding: %v", createErr)
	}
}

func seedTicketParents(t *testing.T, engagements *EngagementRepository, findings *FindingRepository, f storetest.Fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	item, err := engagement.New(f.Engagement, f.Tenant, "Ticketing", "Synapse", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = engagements.Create(shared.WithTenant(ctx, f.Tenant), item); err != nil {
		t.Fatal(err)
	}
	issue, err := finding.NewManual(f.Finding, f.Engagement, finding.ManualInput{Title: "Ticketing finding", Severity: shared.SeverityHigh}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = findings.Upsert(shared.WithTenant(ctx, f.Tenant), []finding.Finding{issue}); err != nil {
		t.Fatal(err)
	}
}
