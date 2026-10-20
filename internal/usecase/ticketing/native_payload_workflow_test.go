package ticketing_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/integration/ticketproviders"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usecase "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type nativeWorkflowProvider struct {
	*workflowProvider
	built int
}

func (p *nativeWorkflowProvider) BuildTicketPayload(_ context.Context, input ports.TicketPayloadInput) (ports.TicketPayload, error) {
	p.built++
	var description string
	_ = json.Unmarshal(input.Description, &description)
	wire, err := json.Marshal(map[string]any{"title": input.Summary, "body": description, "labels": []string{"security"}, "visibility": input.SecurityPolicy})
	return ports.TicketPayload{Wire: wire, Marker: ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerJSONArray, Path: []string{"labels"}}}, err
}

func newNativeWorkflow(t *testing.T) (workflowFixture, *nativeWorkflowProvider) {
	t.Helper()
	f := newWorkflowFixture(t)
	provider := &nativeWorkflowProvider{workflowProvider: f.provider}
	f.integrations.item.Provider = "github-issues"
	f.integrations.item.Name = "GitHub Issues"
	f.integrations.item.Endpoint = "https://github.example.test"
	f.provider.created = domain.RemoteTicket{ID: "42", URL: "https://github.example.test/browse/42"}
	f.provider.metadata = ports.TicketMetadata{Projects: []ports.TicketChoice{{ID: "SEC", Name: "security/repo"}}, IssueTypes: []ports.TicketChoice{{ID: "10001", Name: "issue"}}, SecurityPolicy: "private_repository"}
	w, err := usecase.NewWorkflow(f.store, f.integrations, workflowProviders{provider}, f.findings, f.engagements, f.policy, f.audit, &ticketIDs{}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	w.SetPublicBaseURL("https://console.example")
	f.workflow = w
	return f, provider
}

func newNativeWorkflowForProvider(t *testing.T, provider integration.Provider, endpoint string) (workflowFixture, *nativeWorkflowProvider) {
	t.Helper()
	f, native := newNativeWorkflow(t)
	f.integrations.item.Provider = provider
	f.integrations.item.Endpoint = endpoint
	f.integrations.item.Name = string(provider)
	native.metadata = ports.TicketMetadata{
		Projects:       []ports.TicketChoice{{ID: "SEC", Name: "SEC"}},
		IssueTypes:     []ports.TicketChoice{{ID: "issue", Name: "issue"}},
		SecurityPolicy: "provider_access",
	}
	return f, native
}

func submitNativeURLTicket(t *testing.T, f workflowFixture, requestKey string) domain.Intent {
	t.Helper()
	mapping, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{
		IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "issue",
		SummaryTemplate: "Title: {{.title}}", DescriptionTemplate: "Description: {{.title}}", Actor: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: mapping.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	intent, created, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: mapping.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: requestKey, PreviewDigest: preview.Digest, Actor: "admin"})
	if err != nil || !created {
		t.Fatalf("submit native URL ticket=%+v created=%t err=%v", intent, created, err)
	}
	return intent
}

func TestNativeTicketPreviewSubmitAndDispatchFreezeWire(t *testing.T) {
	f, provider := newNativeWorkflow(t)
	ctx := context.Background()
	mapping, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SummaryTemplate: "Title: {{.title}}", DescriptionTemplate: "Description: {{.title}}", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if mapping.SecurityLevel != "private_repository" {
		t.Fatalf("stored native policy = %q", mapping.SecurityLevel)
	}
	preview, err := f.workflow.Preview(ctx, usecase.PreviewRequest{TenantID: "tenant-a", MappingID: mapping.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Wire json.RawMessage `json:"wire"`
	}
	if json.Unmarshal(preview.Payload, &envelope) != nil || !json.Valid(envelope.Wire) || string(envelope.Wire) == "" {
		t.Fatalf("preview does not contain native wire: %s", preview.Payload)
	}
	if string(envelope.Wire) == "" || string(envelope.Wire) == string(preview.Payload) {
		t.Fatalf("native wire was not isolated: %s", preview.Payload)
	}
	intent, created, err := f.workflow.Submit(ctx, usecase.SubmitRequest{TenantID: "tenant-a", MappingID: mapping.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "native-once", PreviewDigest: preview.Digest, Actor: "admin"})
	if err != nil || !created {
		t.Fatalf("submit created=%v err=%v", created, err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if provider.built != 2 { // explicit preview and Submit's stale-preview fence only
		t.Fatalf("builder calls = %d, want 2", provider.built)
	}
	var sent map[string]any
	if json.Unmarshal(provider.createdPayload, &sent) != nil {
		t.Fatalf("sent wire invalid: %s", provider.createdPayload)
	}
	if _, found := sent["_synapse"]; found {
		t.Fatalf("dispatch leaked envelope: %s", provider.createdPayload)
	}
	labels, ok := sent["labels"].([]any)
	if !ok || len(labels) != 2 || labels[1] != intent.Marker {
		t.Fatalf("sent marker labels = %#v", sent["labels"])
	}
}

func TestNativeTicketPolicyRejectsWaiverAndUnsupportedControls(t *testing.T) {
	f, _ := newNativeWorkflow(t)
	ctx := context.Background()
	if _, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "private_repository", WaiverReason: "legacy waiver", Actor: "admin"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("native waiver err=%v", err)
	}
	if _, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "confidential_issue", Actor: "admin"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("mismatched native policy err=%v", err)
	}
	seedTicketParent(t, f.engagements, f.findings, "tenant-a", "group-engagement", "group-finding", "group-project", f.clock.Now())
	f.policy.setting = notification.EngagementNotificationSetting{TenantID: "tenant-a", EngagementID: "group-engagement", ExternalNotifications: notification.EngagementNotificationsInherit}
	if _, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Project, ScopeID: "group-project", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "private_repository", DataClass: notification.DataClassDetail, GroupingMode: domain.GroupingVulnerabilityProject, Actor: "admin", AllowAdmin: true}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsupported native grouping err=%v", err)
	}
}

func TestNativeTicketWorkflowAcknowledgesAndReconcilesCanonicalProviderURLs(t *testing.T) {
	const serviceNowID = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name, endpoint, remoteURL, remoteID string
		provider                            integration.Provider
	}{
		{"linear", "https://api.linear.app/graphql", "https://linear.app/team/issue/SEC-42/title", "linear-42", "linear"},
		{"servicenow", "https://instance.service-now.com", "https://instance.service-now.com/now/nav/ui/classic/params/target/incident.do%3Fsys_id%3D" + serviceNowID, serviceNowID, "servicenow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, provider := newNativeWorkflowForProvider(t, tc.provider, tc.endpoint)
			provider.created = domain.RemoteTicket{ID: tc.remoteID, URL: tc.remoteURL}
			intent := submitNativeURLTicket(t, f, "canonical-ack-"+tc.name)
			if completed, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil || completed != 1 {
				t.Fatalf("acknowledge completed=%d err=%v", completed, err)
			}
			acknowledged, err := f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
			if err != nil || acknowledged.State != writeintent.Done || acknowledged.RemoteURL != tc.remoteURL {
				t.Fatalf("acknowledged=%+v err=%v", acknowledged, err)
			}

			f, provider = newNativeWorkflowForProvider(t, tc.provider, tc.endpoint)
			provider.createErr = &ports.TicketProviderError{Code: "network", Ambiguous: true}
			intent = submitNativeURLTicket(t, f, "canonical-reconcile-"+tc.name)
			if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
			uncertain, err := f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
			if err != nil || uncertain.State != writeintent.Uncertain {
				t.Fatalf("uncertain=%+v err=%v", uncertain, err)
			}
			provider.hits = []domain.RemoteTicket{{ID: tc.remoteID, URL: tc.remoteURL}}
			reconciled, err := f.workflow.Reconcile(context.Background(), "tenant-a", intent.ID, uncertain.Version)
			if err != nil || reconciled.State != writeintent.Done || reconciled.RemoteURL != tc.remoteURL {
				t.Fatalf("reconciled=%+v err=%v", reconciled, err)
			}
		})
	}
}

func TestNativeTicketWorkflowRejectsUnsafeProviderBrowserURLs(t *testing.T) {
	const serviceNowID = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name, endpoint, remoteURL, remoteID string
		provider                            integration.Provider
	}{
		{"linear wrong origin", "https://api.linear.app/graphql", "https://other.linear.app/team/issue/SEC-42/title", "linear-42", "linear"},
		{"linear extra query", "https://api.linear.app/graphql", "https://linear.app/team/issue/SEC-42/title?view=board", "linear-42", "linear"},
		{"linear credential URI", "https://api.linear.app/graphql", "https://user:secret@linear.app/team/issue/SEC-42/title", "linear-42", "linear"},
		{"servicenow wrong origin", "https://instance.service-now.com", "https://other.service-now.com/now/nav/ui/classic/params/target/incident.do%3Fsys_id%3D" + serviceNowID, serviceNowID, "servicenow"},
		{"servicenow extra query", "https://instance.service-now.com", "https://instance.service-now.com/now/nav/ui/classic/params/target/incident.do%3Fsys_id%3D" + serviceNowID + "?view=default", serviceNowID, "servicenow"},
		{"servicenow wrong table", "https://instance.service-now.com", "https://instance.service-now.com/now/nav/ui/classic/params/target/problem.do%3Fsys_id%3D" + serviceNowID, serviceNowID, "servicenow"},
		{"servicenow classic query", "https://instance.service-now.com", "https://instance.service-now.com/nav_to.do?uri=incident.do%3Fsys_id%3D" + serviceNowID, serviceNowID, "servicenow"},
		{"servicenow credential URI", "https://instance.service-now.com", "https://user:secret@instance.service-now.com/now/nav/ui/classic/params/target/incident.do%3Fsys_id%3D" + serviceNowID, serviceNowID, "servicenow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, provider := newNativeWorkflowForProvider(t, tc.provider, tc.endpoint)
			provider.created = domain.RemoteTicket{ID: tc.remoteID, URL: tc.remoteURL}
			intent := submitNativeURLTicket(t, f, "unsafe-ack")
			if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
			stored, err := f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
			if err != nil || stored.State != writeintent.Uncertain || stored.RemoteURL != "" {
				t.Fatalf("unsafe acknowledgement=%+v err=%v", stored, err)
			}

			f, provider = newNativeWorkflowForProvider(t, tc.provider, tc.endpoint)
			provider.createErr = &ports.TicketProviderError{Code: "network", Ambiguous: true}
			intent = submitNativeURLTicket(t, f, "unsafe-reconcile")
			if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
			stored, err = f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
			if err != nil || stored.State != writeintent.Uncertain {
				t.Fatalf("reconcile setup=%+v err=%v", stored, err)
			}
			provider.hits = []domain.RemoteTicket{{ID: tc.remoteID, URL: tc.remoteURL}}
			if _, err := f.workflow.Reconcile(context.Background(), "tenant-a", intent.ID, stored.Version); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("unsafe reconciliation err=%v", err)
			}
		})
	}
}

func TestJiraMetadataRetainsLegacyCapabilityDefaults(t *testing.T) {
	f := newWorkflowFixture(t)
	meta, err := f.workflow.Metadata(context.Background(), "tenant-a", "jira", "SEC", "10001", "")
	if err != nil {
		t.Fatal(err)
	}
	if !meta.SupportsGrouping || !meta.SupportsStatusSync || !meta.SupportsStatusTransitions {
		t.Fatalf("Jira capability defaults = %#v", meta)
	}
}

var _ ports.TicketPayloadBuilder = (*nativeWorkflowProvider)(nil)
var _ integration.Provider = "github-issues"

// Keep the real native serializer inside the workflow while replacing only I/O.
type azureWorkflowProvider struct {
	*workflowProvider
	native *ticketproviders.Adapter
	built  int
}

func (p *azureWorkflowProvider) FormatTicketDescription(body string, links []ports.RenderedLink) (json.RawMessage, error) {
	return p.native.FormatTicketDescription(body, links)
}
func (p *azureWorkflowProvider) BuildTicketPayload(ctx context.Context, in ports.TicketPayloadInput) (ports.TicketPayload, error) {
	p.built++
	return p.native.BuildTicketPayload(ctx, in)
}
func TestAzureWorkflowFreezesRenderedHTMLBeforeDispatch(t *testing.T) {
	f, _ := newNativeWorkflowForProvider(t, "azure-boards", "https://dev.azure.com/org/project")
	native, err := ticketproviders.New(f.integrations.item, integration.CredentialBundle{"pat": "synthetic-pat"}, selfhosted.Rules{}, nil, "azure-boards")
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	provider := &azureWorkflowProvider{workflowProvider: f.provider, native: native}
	provider.metadata = ports.TicketMetadata{Projects: []ports.TicketChoice{{ID: "SEC", Name: "SEC"}}, IssueTypes: []ports.TicketChoice{{ID: "issue", Name: "issue"}}, SecurityPolicy: "provider_access"}
	provider.created = domain.RemoteTicket{ID: "42", URL: "https://dev.azure.com/org/project/_workitems/edit/42"}
	w, err := usecase.NewWorkflow(f.store, f.integrations, workflowProviders{provider}, f.findings, f.engagements, f.policy, f.audit, &ticketIDs{}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	w.SetPublicBaseURL("https://console.example")
	f.workflow = w
	intent := submitNativeURLTicket(t, f, "azure-html-once")
	var envelope struct {
		Wire json.RawMessage `json:"wire"`
	}
	if err = json.Unmarshal(intent.Snapshot, &envelope); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(envelope.Wire), `fields/System.Description`) || !strings.Contains(string(envelope.Wire), `noopener noreferrer`) {
		t.Fatalf("HTML/typed link missing: %s", envelope.Wire)
	}
	// Dispatch must reuse queued wire without invoking the serializer.
	before := provider.built
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if provider.built != before {
		t.Fatal("dispatch rerendered the description")
	}
	var want, got any
	if json.Unmarshal(envelope.Wire, &want) != nil || json.Unmarshal(provider.createdPayload, &got) != nil {
		t.Fatal("invalid frozen wire")
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("dispatch changed frozen HTML: %s", provider.createdPayload)
	}
}
