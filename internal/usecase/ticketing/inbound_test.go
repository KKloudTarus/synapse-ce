package ticketing_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usecase "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type inboundDeduper struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (d *inboundDeduper) ProcessInboundWebhookEvent(ctx context.Context, _ ports.InboundWebhookIdentity, event ports.InboundWebhookEvent, reduce func(context.Context) error) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = map[string]bool{}
	}
	if d.seen[event.EventID] {
		return false, nil
	}
	if err := reduce(ctx); err != nil {
		return false, err
	}
	d.seen[event.EventID] = true
	return true, nil
}

func setupInboundTicket(t *testing.T) workflowFixture {
	t.Helper()
	f := newWorkflowFixture(t)
	mapping := f.mapping(t, "security-1")
	preview, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: mapping.ID, EngagementID: "eng-a", FindingID: "finding-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: mapping.ID, EngagementID: "eng-a", FindingID: "finding-a", RequestKey: "inbound-create", PreviewDigest: preview.Digest, Actor: "admin"}); err != nil || !created {
		t.Fatalf("submit create: created=%t err=%v", created, err)
	}
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	configs := any(f.store).(ports.TicketInboundConfigurationStore)
	if _, err = configs.SaveTicketInboundConfiguration(context.Background(), "tenant-a", ports.TicketInboundConfiguration{TenantID: "tenant-a", IntegrationID: "jira", Enabled: true, IntegrationAuthor: "jira-integration", ConnectionRevision: 1, CredentialRevision: 1, UpdatedAt: f.clock.Now()}, 0); err != nil {
		t.Fatal(err)
	}
	f.workflow.SetInboundWebhookDeduper(&inboundDeduper{})
	return f
}

func inboundStatusEvent(id, author, category string, at time.Time) ports.InboundWebhookEvent {
	body := `{"issue":{"key":"SEC-1","fields":{"updated":"` + at.UTC().Format(time.RFC3339) + `","status":{"statusCategory":{"key":"` + category + `"}}}},"user":{"accountId":"` + author + `"},"changelog":{"created":"` + at.UTC().Format(time.RFC3339) + `","items":[{"field":"status"}]}}`
	return ports.InboundWebhookEvent{Provider: "jira-cloud", EventType: "jira:issue_updated", EventID: id, Body: []byte(body)}
}

func TestReceiveInboundWebhookDoneCreatesOneProposalAndDoesNotMutateFinding(t *testing.T) {
	f := setupInboundTicket(t)
	ctx := context.Background()
	identity := ports.InboundWebhookIdentity{PublicID: "hook", TenantID: "tenant-a", OwnerKind: "integration", OwnerID: "jira"}
	event := inboundStatusEvent("one", "human", "done", f.clock.Now().Add(time.Minute))
	if err := f.workflow.ReceiveInboundWebhook(ctx, identity, event); err != nil {
		t.Fatal(err)
	}
	if err := f.workflow.ReceiveInboundWebhook(ctx, identity, event); err != nil {
		t.Fatal(err)
	}
	view, err := f.workflow.ListTicketObservations(ctx, "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Observations) != 1 || len(view.Proposals) != 1 {
		t.Fatalf("view=%+v err=%v", view, err)
	}
	candidate, err := f.findings.GetByEngagementAndID(shared.WithTenant(ctx, "tenant-a"), "eng-a", "finding-a")
	if err != nil || candidate.Status != "open" {
		t.Fatalf("inbound altered finding: %+v err=%v", candidate, err)
	}
}

func TestReceiveInboundWebhookOwnAndUnknownDoneDoNotPropose(t *testing.T) {
	f := setupInboundTicket(t)
	identity := ports.InboundWebhookIdentity{PublicID: "hook", TenantID: "tenant-a", OwnerKind: "integration", OwnerID: "jira"}
	at := f.clock.Now().Add(time.Minute)
	// A generic comment snapshot has no status author and deliberately defers.
	unknown := ports.InboundWebhookEvent{Provider: "jira-cloud", EventType: "comment_created", EventID: "unknown", Body: []byte(`{"issue":{"key":"SEC-1","fields":{"updated":"` + at.Format(time.RFC3339) + `","status":{"statusCategory":{"key":"done"}}}},"user":{"accountId":"human"}}`)}
	if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, unknown); err != nil {
		t.Fatal(err)
	}
	// The later proven integration transition consumes the pending state without a proposal.
	if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, inboundStatusEvent("own", "jira-integration", "done", at.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Proposals) != 0 || !view.Observations[0].StatusAuthorKnown || view.Observations[0].PendingDone {
		t.Fatalf("view=%+v err=%v", view, err)
	}
}

func TestReceiveInboundWebhookRefusesRetargetedIntegration(t *testing.T) {
	f := setupInboundTicket(t)
	f.integrations.item.Endpoint = "https://other.atlassian.net"
	identity := ports.InboundWebhookIdentity{PublicID: "hook", TenantID: "tenant-a", OwnerKind: "integration", OwnerID: "jira"}
	if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, inboundStatusEvent("retargeted", "human", "done", f.clock.Now().Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Observations) != 0 || len(view.Proposals) != 0 {
		t.Fatalf("retargeted integration accepted inbound state: %+v err=%v", view, err)
	}
}

func TestReceiveInboundWebhookRejectsStaleStatusAndRedactsADFComment(t *testing.T) {
	f := setupInboundTicket(t)
	identity := ports.InboundWebhookIdentity{PublicID: "hook", TenantID: "tenant-a", OwnerKind: "integration", OwnerID: "jira"}
	at := f.clock.Now().Add(time.Minute)
	if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, inboundStatusEvent("new", "human", "done", at)); err != nil {
		t.Fatal(err)
	}
	stale := inboundStatusEvent("stale", "human", "new", at.Add(-time.Second))
	if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, stale); err != nil {
		t.Fatal(err)
	}
	comment := ports.InboundWebhookEvent{Provider: "jira-cloud", EventType: "comment_created", EventID: "comment", Body: []byte(`{"issue":{"key":"SEC-1","fields":{"updated":"` + at.Format(time.RFC3339) + `","status":{"statusCategory":{"key":"done"}}}},"user":{"accountId":"human"},"comment":{"created":"` + at.Format(time.RFC3339) + `","body":{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"Fixed https://token@example.test/secret"},{"type":"mention","attrs":{"id":"person"}}]}]}}}`)}
	if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, comment); err != nil {
		t.Fatal(err)
	}
	view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || view.Observations[0].StatusCategory != "done" || len(view.Comments) != 1 || view.Comments[0].Body != "Fixed [REDACTED]" {
		t.Fatalf("view=%+v err=%v", view, err)
	}
}

func TestWorkflowTickReconcilesProviderStateAndMarksUnreadable(t *testing.T) {
	f := setupInboundTicket(t)
	f.provider.observation = ports.TicketObservation{ExternalID: "SEC-1", StatusCategory: "done", UpdatedAt: f.clock.Now().Add(time.Minute), StatusChangedAt: f.clock.Now().Add(time.Minute), AuthorID: "human", ResolutionName: "Fixed"}
	if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Proposals) != 1 || view.Proposals[0].ResolutionName != "Fixed" || view.Observations[0].StatusCategory != "done" {
		t.Fatalf("reconciled view=%+v err=%v", view, err)
	}
	f.provider.observation = ports.TicketObservation{ExternalID: "SEC-1", Deleted: true}
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	view, err = f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || !view.Observations[0].DeletedOrUnreadable || view.Observations[0].StatusCategory != "done" {
		t.Fatalf("unreadable view=%+v err=%v", view, err)
	}
}

func TestWorkflowTickFreshUnreadableTicketDefersUntilReadableStatus(t *testing.T) {
	f := setupInboundTicket(t)
	f.provider.observation = ports.TicketObservation{ExternalID: "SEC-1", Deleted: true}
	if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Proposals) != 0 || len(view.Observations) != 1 || !view.Observations[0].DeletedOrUnreadable || view.Observations[0].StatusCategory != "" {
		t.Fatalf("fresh unreadable view=%+v err=%v", view, err)
	}
	f.provider.observation = ports.TicketObservation{ExternalID: "SEC-1", StatusCategory: "done", UpdatedAt: f.clock.Now().Add(time.Minute), StatusChangedAt: f.clock.Now().Add(time.Minute), AuthorID: "human"}
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	view, err = f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Proposals) != 1 || view.Observations[0].DeletedOrUnreadable || view.Observations[0].StatusCategory != "done" {
		t.Fatalf("repaired view=%+v err=%v", view, err)
	}
}
