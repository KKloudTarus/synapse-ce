package ticketing_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usecase "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type inboundThrottleProvider struct {
	*workflowProvider
	reads, identities int
	readErr           error
	identityErr       error
}

func (p *inboundThrottleProvider) GetTicket(_ context.Context, remoteID string) (ports.TicketObservation, error) {
	p.reads++
	if p.readErr != nil {
		return ports.TicketObservation{}, p.readErr
	}
	return ports.TicketObservation{ExternalID: remoteID, StatusCategory: "done", UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), StatusChangedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), AuthorID: "external-human"}, nil
}

func (p *inboundThrottleProvider) TicketIdentity(context.Context) (string, error) {
	p.identities++
	if p.identityErr != nil {
		return "", p.identityErr
	}
	return "jira-integration", nil
}

func newInboundThrottleWorkflow(t *testing.T, f workflowFixture, provider ports.TicketProvider) *usecase.Workflow {
	t.Helper()
	w, err := usecase.NewWorkflow(f.store, f.integrations, workflowProviders{provider}, f.findings, f.engagements, f.policy, f.audit, &ticketIDs{}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	w.SetPublicBaseURL("https://console.example")
	return w
}

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
	// Submit's completion tick reserves the first durable poll slot. Advance to
	// its due boundary before an inbound-specific assertion begins.
	f.clock.Advance(time.Minute)
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
	comment := ports.InboundWebhookEvent{Provider: "jira-cloud", EventType: "comment_created", EventID: "comment", Body: []byte(`{"issue":{"key":"SEC-1","fields":{"updated":"` + at.Format(time.RFC3339) + `","status":{"statusCategory":{"key":"done"}}}},"user":{"accountId":"human"},"comment":{"author":{"accountId":"commenter"},"created":"` + at.Format(time.RFC3339) + `","body":{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"Fixed https://token@example.test/secret"},{"type":"mention","attrs":{"id":"person"}}]}]}}}`)}
	if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, comment); err != nil {
		t.Fatal(err)
	}
	view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || view.Observations[0].StatusCategory != "done" || len(view.Comments) != 1 || view.Comments[0].Body != "Fixed [REDACTED]" {
		t.Fatalf("view=%+v err=%v", view, err)
	}
}

func TestReceiveInboundWebhookCloudCommentOnlyUsesCommentAuthorAndNeverObservesStatus(t *testing.T) {
	f := setupInboundTicket(t)
	identity := ports.InboundWebhookIdentity{PublicID: "hook", TenantID: "tenant-a", OwnerKind: "integration", OwnerID: "jira"}
	at := f.clock.Now().Add(time.Minute).UTC()
	event := ports.InboundWebhookEvent{Provider: "jira-cloud", EventType: "comment_created", EventID: "cloud-comment", Body: []byte(`{
		"timestamp":1735689600000,
		"webhookEvent":"comment_created",
		"eventType":"comment_created",
		"issue":{"key":"SEC-1","fields":{"status":{"statusCategory":{"key":"done"}}}},
		"comment":{"author":{"accountId":"cloud-comment-author"},"updateAuthor":{"accountId":"cloud-comment-editor"},"created":"` + at.Format(time.RFC3339) + `","updated":"` + at.Add(time.Second).Format(time.RFC3339) + `","body":"Xin chào <script>alert(1)</script> [~not-a-real-user]"}
	}`)}
	if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, event); err != nil {
		t.Fatal(err)
	}
	view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Observations) != 0 || len(view.Proposals) != 0 || len(view.Comments) != 1 {
		t.Fatalf("comment-only delivery must not observe status: view=%+v err=%v", view, err)
	}
	if got := view.Comments[0]; got.AuthorID != "cloud-comment-author" || !got.ProviderAt.Equal(at) || got.Body != "Xin chào <script>alert(1)</script> [~not-a-real-user]" {
		t.Fatalf("comment attribution or literal changed: %+v", got)
	}
}

func TestReceiveInboundWebhookCloudOwnDoneCommentIsSuppressedWithoutProposal(t *testing.T) {
	f := setupInboundTicket(t)
	identity := ports.InboundWebhookIdentity{PublicID: "hook", TenantID: "tenant-a", OwnerKind: "integration", OwnerID: "jira"}
	at := f.clock.Now().Add(time.Minute).UTC()
	event := ports.InboundWebhookEvent{Provider: "jira-cloud", EventType: "comment_updated", EventID: "cloud-own-comment", Body: []byte(`{
		"webhookEvent":"comment_updated",
		"issue":{"key":"SEC-1","fields":{"status":{"statusCategory":{"key":"done"}}}},
		"comment":{"author":{"accountId":"human"},"updateAuthor":{"accountId":"jira-integration"},"created":"` + at.Format(time.RFC3339) + `","updated":"` + at.Add(time.Second).Format(time.RFC3339) + `","body":"own status explanation"}
	}`)}
	if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, event); err != nil {
		t.Fatal(err)
	}
	view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Observations) != 0 || len(view.Proposals) != 0 || len(view.Comments) != 0 {
		t.Fatalf("own comment-only delivery must be suppressed: view=%+v err=%v", view, err)
	}
}

func TestReceiveInboundWebhookIssueUpdateKeepsDistinctCommentAndStatusAuthors(t *testing.T) {
	f := setupInboundTicket(t)
	identity := ports.InboundWebhookIdentity{PublicID: "hook", TenantID: "tenant-a", OwnerKind: "integration", OwnerID: "jira"}
	at := f.clock.Now().Add(time.Minute).UTC()
	event := ports.InboundWebhookEvent{Provider: "jira-cloud", EventType: "jira:issue_updated", EventID: "issue-update-with-comment", Body: []byte(`{
		"issue":{"key":"SEC-1","fields":{"updated":"` + at.Format(time.RFC3339) + `","status":{"statusCategory":{"key":"done"}}}},
		"user":{"accountId":"status-author"},
		"changelog":{"created":"` + at.Format(time.RFC3339) + `","items":[{"field":"status"}]},
		"comment":{"author":{"accountId":"comment-author"},"created":"` + at.Add(time.Second).Format(time.RFC3339) + `","body":"Comment separately attributed"}
	}`)}
	if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, event); err != nil {
		t.Fatal(err)
	}
	view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Observations) != 1 || len(view.Proposals) != 1 || len(view.Comments) != 1 {
		t.Fatalf("issue update was not reduced: view=%+v err=%v", view, err)
	}
	if view.Observations[0].AuthorID != "status-author" || view.Comments[0].AuthorID != "comment-author" {
		t.Fatalf("status and comment authors were conflated: observations=%+v comments=%+v", view.Observations, view.Comments)
	}
}

func TestReceiveInboundWebhookDeduplicatesProviderCommentAcrossJiraWebhookShapes(t *testing.T) {
	for _, provider := range []string{"jira-cloud", "jira-dc"} {
		t.Run(provider, func(t *testing.T) {
			f := setupInboundTicket(t)
			identity := ports.InboundWebhookIdentity{PublicID: "hook", TenantID: "tenant-a", OwnerKind: "integration", OwnerID: "jira"}
			at := f.clock.Now().Add(time.Minute).UTC()
			issueUpdated := ports.InboundWebhookEvent{Provider: provider, EventType: "jira:issue_updated", EventID: "issue-update-delivery", Body: []byte(`{"issue":{"key":"SEC-1","fields":{"updated":"` + at.Format(time.RFC3339) + `"}},"comment":{"id":"10008","author":{"accountId":"human"},"created":"` + at.Format(time.RFC3339) + `","body":"same provider comment"}}`)}
			commentCreated := ports.InboundWebhookEvent{Provider: provider, EventType: "comment_created", EventID: "comment-created-delivery", Body: []byte(`{"issue":{"key":"SEC-1"},"comment":{"id":"10008","author":{"accountId":"human"},"created":"` + at.Format(time.RFC3339) + `","body":"same provider comment"}}`)}
			for _, event := range []ports.InboundWebhookEvent{issueUpdated, commentCreated} {
				if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, event); err != nil {
					t.Fatal(err)
				}
			}
			view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
			if err != nil || len(view.Comments) != 1 {
				t.Fatalf("same provider comment delivered in two webhook shapes must create one snapshot: view=%+v err=%v", view, err)
			}
		})
	}
}

func TestReceiveInboundWebhookCommentSnapshotsKeepProviderIdentityAndEdits(t *testing.T) {
	f := setupInboundTicket(t)
	identity := ports.InboundWebhookIdentity{PublicID: "hook", TenantID: "tenant-a", OwnerKind: "integration", OwnerID: "jira"}
	at := f.clock.Now().Add(time.Minute).UTC()
	comment := func(eventID, eventType, commentID, stamp, body string) ports.InboundWebhookEvent {
		return ports.InboundWebhookEvent{Provider: "jira-cloud", EventType: eventType, EventID: eventID, Body: []byte(`{"issue":{"key":"SEC-1"},"comment":{"id":"` + commentID + `","author":{"accountId":"human"},"updateAuthor":{"accountId":"editor"},"created":"` + at.Format(time.RFC3339) + `","updated":"` + stamp + `","body":"` + body + `"}}`)}
	}
	created := comment("delivery-one", "comment_created", "10008", at.Format(time.RFC3339), "same text")
	replay := created
	replay.EventID = "delivery-two"
	differentComment := comment("delivery-three", "comment_created", "10009", at.Format(time.RFC3339), "same text")
	updatedAt := at.Add(time.Minute).Format(time.RFC3339)
	updated := comment("delivery-four", "comment_updated", "10008", updatedAt, "edited text")
	for _, event := range []ports.InboundWebhookEvent{created, replay, differentComment, updated} {
		if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, event); err != nil {
			t.Fatal(err)
		}
	}
	view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Comments) != 3 {
		t.Fatalf("replay must collapse while distinct provider IDs and edits remain append-only: view=%+v err=%v", view, err)
	}
	seen := map[string]bool{}
	for _, item := range view.Comments {
		seen[item.Body] = true
	}
	if !seen["same text"] || !seen["edited text"] {
		t.Fatalf("comment snapshots missing expected literal bodies: %+v", view.Comments)
	}
}

func TestReceiveInboundWebhookNormalizesEmbeddedAndDedicatedCommentEdits(t *testing.T) {
	f := setupInboundTicket(t)
	identity := ports.InboundWebhookIdentity{PublicID: "hook", TenantID: "tenant-a", OwnerKind: "integration", OwnerID: "jira"}
	createdAt := f.clock.Now().Add(time.Minute).UTC()
	updatedAt := createdAt.Add(time.Minute).UTC()
	created := ports.InboundWebhookEvent{Provider: "jira-dc", EventType: "comment_created", EventID: "create-delivery", Body: []byte(`{"issue":{"key":"SEC-1"},"comment":{"id":"10008","author":{"name":"creator"},"created":"` + createdAt.Format(time.RFC3339) + `","updated":"` + updatedAt.Format(time.RFC3339) + `","body":"before edit"}}`)}
	embeddedEdit := ports.InboundWebhookEvent{Provider: "jira-dc", EventType: "jira:issue_updated", EventID: "issue-update-delivery", Body: []byte(`{"issue":{"key":"SEC-1","fields":{"updated":"` + updatedAt.Format(time.RFC3339) + `"}},"comment":{"id":"10008","author":{"name":"creator"},"updateAuthor":{"name":"editor"},"created":"` + createdAt.Format(time.RFC3339) + `","updated":"` + updatedAt.Format(time.RFC3339) + `","body":"after edit"}}`)}
	dedicatedEdit := ports.InboundWebhookEvent{Provider: "jira-dc", EventType: "comment_updated", EventID: "comment-update-delivery", Body: []byte(`{"issue":{"key":"SEC-1"},"comment":{"id":"10008","author":{"name":"creator"},"updateAuthor":{"name":"editor"},"created":"` + createdAt.Format(time.RFC3339) + `","updated":"` + updatedAt.Format(time.RFC3339) + `","body":"after edit"}}`)}
	for _, event := range []ports.InboundWebhookEvent{created, embeddedEdit, dedicatedEdit} {
		if err := f.workflow.ReceiveInboundWebhook(context.Background(), identity, event); err != nil {
			t.Fatal(err)
		}
	}
	view, err := f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Comments) != 2 {
		t.Fatalf("creation must remain while equivalent edit webhook shapes collapse: view=%+v err=%v", view, err)
	}
	byBody := map[string]ticketing.ExternalTicketComment{}
	for _, item := range view.Comments {
		byBody[item.Body] = item
	}
	if byBody["before edit"].AuthorID != "creator" || byBody["after edit"].AuthorID != "editor" || !byBody["after edit"].ProviderAt.Equal(updatedAt) {
		t.Fatalf("edit normalization used the wrong snapshot identity or actor: %+v", view.Comments)
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
	f.clock.Advance(time.Minute)
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
	f.clock.Advance(time.Minute)
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	view, err = f.workflow.ListTicketObservations(context.Background(), "tenant-a", "eng-a", "finding-a")
	if err != nil || len(view.Proposals) != 1 || view.Observations[0].DeletedOrUnreadable || view.Observations[0].StatusCategory != "done" {
		t.Fatalf("repaired view=%+v err=%v", view, err)
	}
}

func TestWorkflowTickPersistsInboundReadThrottleAcrossRestart(t *testing.T) {
	for _, status := range []int{429, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := setupInboundTicket(t)
			provider := &inboundThrottleProvider{
				workflowProvider: f.provider,
				readErr:          &ports.TicketProviderError{Code: "rate_limited", Status: status, RetryAfter: 9 * time.Minute},
			}
			first := newInboundThrottleWorkflow(t, f, provider)
			if _, err := first.Tick(context.Background(), "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
			if provider.reads != 1 {
				t.Fatalf("throttled read calls=%d, want 1", provider.reads)
			}

			// A new worker must obtain its target from the persisted due queue; it must
			// not retry the provider read before the provider's longer Retry-After.
			f.clock.Advance(8 * time.Minute)
			restarted := newInboundThrottleWorkflow(t, f, provider)
			if _, err := restarted.Tick(context.Background(), "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
			if provider.reads != 1 {
				t.Fatalf("restarted worker retried before durable retry-after: reads=%d", provider.reads)
			}

			provider.readErr = nil
			f.clock.Advance(time.Minute)
			if _, err := restarted.Tick(context.Background(), "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
			if provider.reads != 2 {
				t.Fatalf("worker did not resume at durable retry-after boundary: reads=%d", provider.reads)
			}

		})
	}
}

func TestWorkflowTickIdentityThrottleStopsRemainingIntegrationTargetsWithoutProposal(t *testing.T) {
	for _, status := range []int{429, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := setupInboundTicket(t)
			mappings, err := f.store.ListMappings(context.Background(), "tenant-a", 10, "")
			if err != nil || len(mappings) != 1 {
				t.Fatalf("mappings=%+v err=%v", mappings, err)
			}
			second, err := finding.NewManual("finding-inbound-throttle", "eng-a", finding.ManualInput{Title: "Second inbound target", Severity: shared.SeverityHigh}, f.clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err = f.findings.Upsert(shared.WithTenant(context.Background(), "tenant-a"), []finding.Finding{second}); err != nil {
				t.Fatal(err)
			}
			preview, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: mappings[0].ID, EngagementID: "eng-a", FindingID: second.ID})
			if err != nil {
				t.Fatal(err)
			}
			if _, created, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: mappings[0].ID, EngagementID: "eng-a", FindingID: second.ID, RequestKey: "inbound-throttle-second", PreviewDigest: preview.Digest, Actor: "admin"}); err != nil || !created {
				t.Fatalf("second submission created=%t err=%v", created, err)
			}
			if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
			f.clock.Advance(time.Minute)
			targets, err := f.store.ListInboundTicketTargets(context.Background(), "tenant-a", 10)
			if err != nil || len(targets) != 2 {
				t.Fatalf("inbound targets=%+v err=%v", targets, err)
			}
			configs := any(f.store).(ports.TicketInboundConfigurationStore)
			config, err := configs.GetTicketInboundConfiguration(context.Background(), "tenant-a", "jira")
			if err != nil {
				t.Fatal(err)
			}
			config.Enabled = false // Exercise the authenticated fallback identity read.
			config.UpdatedAt = f.clock.Now()
			if _, err = configs.SaveTicketInboundConfiguration(context.Background(), "tenant-a", config, config.Version); err != nil {
				t.Fatal(err)
			}

			provider := &inboundThrottleProvider{
				workflowProvider: f.provider,
				identityErr:      &ports.TicketProviderError{Code: "rate_limited", Status: status, RetryAfter: 9 * time.Minute},
			}
			w := newInboundThrottleWorkflow(t, f, provider)
			if _, err = w.Tick(context.Background(), "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
			if provider.reads != 1 || provider.identities != 1 {
				t.Fatalf("identity throttle did not stop later same-integration target: reads=%d identities=%d", provider.reads, provider.identities)
			}
			for _, findingID := range []shared.ID{"finding-a", second.ID} {
				view, viewErr := w.ListTicketObservations(context.Background(), "tenant-a", "eng-a", findingID)
				if viewErr != nil || len(view.Proposals) != 0 {
					t.Fatalf("identity-unproven target %s proposed a retest: view=%+v err=%v", findingID, view, viewErr)
				}
			}

		})
	}
}
