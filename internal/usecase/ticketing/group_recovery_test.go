package ticketing_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usecase "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

func groupedFixture(t *testing.T) (workflowFixture, domain.Mapping) {
	t.Helper()
	f := newWorkflowFixture(t)
	seedTicketParent(t, f.engagements, f.findings, "tenant-a", "group-engagement", "group-first", "group-project", f.clock.Now())
	for _, id := range []shared.ID{"group-first", "group-second", "group-third"} {
		item, err := finding.NewManual(id, "group-engagement", finding.ManualInput{Title: id.String(), Severity: shared.SeverityHigh}, f.clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		item.AdvisoryID = "CVE-2026-12345"
		if err = f.findings.Upsert(shared.WithTenant(context.Background(), "tenant-a"), []finding.Finding{item}); err != nil {
			t.Fatal(err)
		}
	}
	f.policy.setting.EngagementID = "group-engagement"
	m, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Project, ScopeID: "group-project", ProjectKey: "SEC", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: "security-1", DataClass: notification.DataClassDetail, GroupingMode: domain.GroupingVulnerabilityProject, Actor: "admin", AllowAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	return f, m
}

func groupSubmitRequest(t *testing.T, f workflowFixture, m domain.Mapping, id shared.ID, key string) usecase.SubmitRequest {
	t.Helper()
	p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, EngagementID: "group-engagement", FindingID: id})
	if err != nil {
		t.Fatal(err)
	}
	return usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, EngagementID: "group-engagement", FindingID: id, RequestKey: key, PreviewDigest: p.Digest, Actor: "admin"}
}

func TestWorkflowGroupBusyDoesNotLoseMembersAndRequestReplayRecovers(t *testing.T) {
	f, m := groupedFixture(t)
	ctx := context.Background()
	firstRequest := groupSubmitRequest(t, f, m, "group-first", "first")
	first, fresh, err := f.workflow.Submit(ctx, firstRequest)
	if err != nil || !fresh {
		t.Fatalf("first: %+v %v", first, err)
	}
	replayed, fresh, err := f.workflow.Submit(ctx, firstRequest)
	if err != nil || fresh || replayed.ID != first.ID {
		t.Fatalf("replay after reservation: %+v %v", replayed, err)
	}
	if _, _, err = f.workflow.Submit(ctx, groupSubmitRequest(t, f, m, "group-second", "second")); !errors.Is(err, domain.ErrGroupBusy) {
		t.Fatalf("pending group admitted member: %v", err)
	}
	facts, err := f.store.GroupTicketFacts(ctx, "tenant-a", m.ID, "group-project", "CVE-2026-12345", ports.TicketGroupMember{EngagementID: "group-engagement", FindingID: "group-first"})
	if err != nil || len(facts) != 1 {
		t.Fatalf("refused member persisted: %+v %v", facts, err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	second, fresh, err := f.workflow.Submit(ctx, groupSubmitRequest(t, f, m, "group-second", "second"))
	if err != nil || !fresh || second.Action != domain.Update {
		t.Fatalf("second: %+v %v", second, err)
	}
	if _, _, err = f.workflow.Submit(ctx, groupSubmitRequest(t, f, m, "group-third", "third")); !errors.Is(err, domain.ErrGroupBusy) {
		t.Fatalf("active update admitted another member: %v", err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	var sent struct {
		Fields map[string]json.RawMessage `json:"fields"`
	}
	if json.Unmarshal(f.provider.createdPayload, &sent) != nil {
		t.Fatal("invalid update payload")
	}
	var labels []string
	if json.Unmarshal(sent.Fields["labels"], &labels) != nil {
		t.Fatal("missing update labels")
	}
	marked := false
	for _, label := range labels {
		marked = marked || label == second.Marker
	}
	if !marked || sent.Fields["project"] != nil || sent.Fields["issuetype"] != nil {
		t.Fatalf("update lost correlation or changed destination: %s", f.provider.createdPayload)
	}
	third, fresh, err := f.workflow.Submit(ctx, groupSubmitRequest(t, f, m, "group-third", "third"))
	if err != nil || !fresh || third.Action != domain.Update {
		t.Fatalf("third: %+v %v", third, err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	facts, err = f.store.GroupTicketFacts(ctx, "tenant-a", m.ID, "group-project", "CVE-2026-12345", ports.TicketGroupMember{EngagementID: "group-engagement", FindingID: "group-first"})
	if err != nil || len(facts) != 3 {
		t.Fatalf("lost accepted member: %+v %v", facts, err)
	}
	if f.provider.posts != 1 || f.provider.updates != 2 {
		t.Fatalf("create=%d update=%d", f.provider.posts, f.provider.updates)
	}
	for _, id := range []shared.ID{"group-first", "group-second", "group-third"} {
		links, err := f.store.ListLinks(ctx, "tenant-a", id)
		if err != nil || len(links) != 1 || links[0].ExternalID != "SEC-1" {
			t.Fatalf("finding %s links=%+v %v", id, links, err)
		}
	}
	firstRequest.PreviewDigest = "different"
	if _, _, err = f.workflow.Submit(ctx, firstRequest); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("request content changed: %v", err)
	}
}

type groupPolicyStore struct {
	*memory.TicketStore
	blocked shared.ID
}

func (s *groupPolicyStore) GroupTicketFacts(ctx context.Context, tenant, mapping, project shared.ID, vulnerability string, candidate ports.TicketGroupMember) ([]ports.TicketGroupFact, error) {
	facts, err := s.TicketStore.GroupTicketFacts(ctx, tenant, mapping, project, vulnerability, candidate)
	for i := range facts {
		if facts[i].FindingID == s.blocked {
			facts[i].ExternalNotifications = notification.EngagementNotificationsNone
		}
	}
	return facts, err
}

func TestWorkflowGroupRechecksEveryMembersPrivacyBeforeDispatch(t *testing.T) {
	f, m := groupedFixture(t)
	ctx := context.Background()
	store := &groupPolicyStore{TicketStore: f.store}
	w, err := usecase.NewWorkflow(store, f.integrations, workflowProviders{f.provider}, f.findings, f.engagements, f.policy, f.audit, &ticketIDs{n: 100}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	w.SetPublicBaseURL("https://console.example")
	f.workflow = w
	if _, _, err = w.Submit(ctx, groupSubmitRequest(t, f, m, "group-first", "first")); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	second, _, err := w.Submit(ctx, groupSubmitRequest(t, f, m, "group-second", "second"))
	if err != nil {
		t.Fatal(err)
	}
	store.blocked = "group-first"
	if _, err = w.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	saved, err := store.GetIntent(ctx, "tenant-a", second.ID)
	if err != nil || saved.State != writeintent.Failed || f.provider.updates != 0 {
		t.Fatalf("privacy revoked: %+v updates=%d %v", saved, f.provider.updates, err)
	}
	store.blocked = ""
	if _, _, err = w.Submit(ctx, groupSubmitRequest(t, f, m, "group-second", "privacy-restored")); err != nil {
		t.Fatalf("definite refusal wedged group: %v", err)
	}
	if _, err = w.Tick(ctx, "tenant-a", 10); err != nil || f.provider.updates != 1 {
		t.Fatalf("restored privacy updates=%d err=%v", f.provider.updates, err)
	}
}

func TestWorkflowGroupUncertainCreateCannotAdmitAnotherCommand(t *testing.T) {
	f, m := groupedFixture(t)
	ctx := context.Background()
	f.provider.createErr = &ports.TicketProviderError{Code: "network", Ambiguous: true}
	if _, _, err := f.workflow.Submit(ctx, groupSubmitRequest(t, f, m, "group-first", "first")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.workflow.Submit(ctx, groupSubmitRequest(t, f, m, "group-second", "second")); !errors.Is(err, domain.ErrGroupBusy) {
		t.Fatalf("uncertain group admitted command: %v", err)
	}
	if f.provider.posts != 1 || f.provider.updates != 0 {
		t.Fatalf("create=%d update=%d", f.provider.posts, f.provider.updates)
	}
}
