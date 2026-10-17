package ticketing_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usecase "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type workflowIntegrations struct {
	ports.IntegrationStore
	item integration.Integration
}

type mutableWorkflowClock struct{ now time.Time }

func (c *mutableWorkflowClock) Now() time.Time { return c.now }

func (s workflowIntegrations) GetIntegration(ctx context.Context, id shared.ID) (integration.Integration, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || id != s.item.ID || tenant != s.item.TenantID {
		return integration.Integration{}, shared.ErrNotFound
	}
	return s.item, nil
}

type workflowPolicy struct {
	setting notification.EngagementNotificationSetting
}

func (p workflowPolicy) GetEngagementNotificationSetting(_ context.Context, tenant, engagement shared.ID) (notification.EngagementNotificationSetting, error) {
	if tenant != p.setting.TenantID || engagement != p.setting.EngagementID {
		return notification.EngagementNotificationSetting{}, shared.ErrNotFound
	}
	return p.setting, nil
}

type workflowAudit struct {
	mu      sync.Mutex
	entries []ports.AuditEntry
	err     error
}

func (a *workflowAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.entries = append(a.entries, entry)
	return nil
}

type workflowProvider struct {
	mu             sync.Mutex
	posts          int
	updates        int
	transitions    int
	created        domain.RemoteTicket
	createErr      error
	hits           []domain.RemoteTicket
	metadata       ports.TicketMetadata
	metadataErr    error
	validationErr  error
	validationFn   func(json.RawMessage) error
	observation    ports.TicketObservation
	observationErr error
	createdPayload json.RawMessage
	discoverStart  chan struct{}
	discoverWait   <-chan struct{}
	discoveries    int
}

func (p *workflowProvider) DiscoverTickets(ctx context.Context, _ string, _ string, _ string) (ports.TicketMetadata, error) {
	p.mu.Lock()
	p.discoveries++
	started, wait, metadata, err := p.discoverStart, p.discoverWait, p.metadata, p.metadataErr
	p.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			return ports.TicketMetadata{}, ctx.Err()
		}
	}
	return metadata, err
}
func (p *workflowProvider) FormatTicketDescription(body string, _ []ports.RenderedLink) (json.RawMessage, error) {
	return json.Marshal(body)
}
func (p *workflowProvider) FormatTicketGroupDescription(body string, _ []ports.RenderedLink, _ []string, _ [][]string) (json.RawMessage, error) {
	return json.Marshal(body)
}
func (p *workflowProvider) ValidateTicketPayload(raw json.RawMessage) error {
	p.mu.Lock()
	validationFn, validationErr := p.validationFn, p.validationErr
	p.mu.Unlock()
	if validationFn != nil {
		return validationFn(raw)
	}
	return validationErr
}
func (p *workflowProvider) CreateTicket(_ context.Context, raw json.RawMessage) (domain.RemoteTicket, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.posts++
	p.createdPayload = append(json.RawMessage(nil), raw...)
	return p.created, p.createErr
}
func (p *workflowProvider) UpdateTicket(_ context.Context, _ string, raw json.RawMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updates++
	p.createdPayload = append(json.RawMessage(nil), raw...)
	return nil
}
func (p *workflowProvider) TransitionTicket(_ context.Context, _ string, _ string, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.transitions++
	return nil
}
func (p *workflowProvider) TicketIdentity(context.Context) (string, error) {
	return "jira-integration", nil
}
func (p *workflowProvider) GetTicket(context.Context, string) (ports.TicketObservation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.observation, p.observationErr
}
func (p *workflowProvider) RedactExternalTicketText(value string) (string, error) {
	return value, nil
}
func (p *workflowProvider) SearchTicketMarker(context.Context, string, string, string) ([]domain.RemoteTicket, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]domain.RemoteTicket(nil), p.hits...), nil
}

type workflowProviders struct{ provider ports.TicketProvider }

func (r workflowProviders) TicketProvider(context.Context, integration.Integration) (ports.TicketProvider, error) {
	return r.provider, nil
}

type workflowFixture struct {
	ticketFixture
	workflow     *usecase.Workflow
	provider     *workflowProvider
	audit        *workflowAudit
	integrations *workflowIntegrations
	policy       *workflowPolicy
}

func newWorkflowFixture(t *testing.T) workflowFixture {
	t.Helper()
	base := newTicketFixture(t)
	item := integration.Integration{ID: "jira", TenantID: "tenant-a", Provider: "jira-cloud", Name: "Jira", Endpoint: "https://tenant.atlassian.net", Config: json.RawMessage(`{}`), Enabled: true, Version: 1, ConnectionRevision: 1, CredentialRevision: 1}
	provider := &workflowProvider{created: domain.RemoteTicket{ID: "SEC-1", URL: "https://tenant.atlassian.net/browse/SEC-1"}, metadata: ports.TicketMetadata{
		Projects: []ports.TicketChoice{{ID: "SEC", Name: "Security"}}, IssueTypes: []ports.TicketChoice{{ID: "10001", Name: "Bug"}},
		SecurityLevels: []ports.TicketChoice{{ID: "security-1", Name: "Internal"}}, Priorities: []ports.TicketChoice{{ID: "priority-1", Name: "High"}},
		Components: []ports.TicketChoice{{ID: "component-1", Name: "Platform"}}, Fields: []ports.TicketField{{ID: "summary", Name: "Summary"}, {ID: "description", Name: "Description"}, {ID: "labels", Name: "Labels"}, {ID: "security", Name: "Security level"}, {ID: "priority", Name: "Priority"}, {ID: "components", Name: "Components"}},
	}}
	audit := &workflowAudit{}
	setter, ok := any(base.store).(interface{ SetAudit(ports.AuditLogger) })
	if !ok {
		t.Fatal("memory ticket store must expose SetAudit for atomic ticket audit tests")
	}
	setter.SetAudit(audit)
	policy := &workflowPolicy{setting: notification.EngagementNotificationSetting{TenantID: "tenant-a", EngagementID: "eng-a", ExternalNotifications: notification.EngagementNotificationsInherit}}
	integrations := &workflowIntegrations{item: item}
	w, err := usecase.NewWorkflow(base.store, integrations, workflowProviders{provider}, base.findings, base.engagements, policy, audit, &ticketIDs{}, base.clock)
	if err != nil {
		t.Fatal(err)
	}
	w.SetPublicBaseURL("https://console.example")
	return workflowFixture{ticketFixture: base, workflow: w, provider: provider, audit: audit, integrations: integrations, policy: policy}
}

func (f workflowFixture) mapping(t *testing.T, security string) domain.Mapping {
	t.Helper()
	m, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: security, SummaryTemplate: "Title: {{.title}}", DescriptionTemplate: "Description: {{.title}}", Version: 1, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestWorkflowGroupedSubmissionRetainsRemoteTicket(t *testing.T) {
	f := newWorkflowFixture(t)
	ctx := context.Background()
	seedTicketParent(t, f.engagements, f.findings, "tenant-a", "group-engagement", "group-finding-a", "group-project", f.clock.Now())
	first, err := f.findings.GetByEngagementAndID(shared.WithTenant(ctx, "tenant-a"), "group-engagement", "group-finding-a")
	if err != nil {
		t.Fatal(err)
	}
	first.AdvisoryID = "CVE-2026-12345"
	if err = f.findings.Upsert(shared.WithTenant(ctx, "tenant-a"), []finding.Finding{first}); err != nil {
		t.Fatal(err)
	}
	f.policy.setting.EngagementID = "group-engagement"
	mapping, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Project, ScopeID: "group-project", ProjectKey: "SEC", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: "security-1", DataClass: notification.DataClassDetail, GroupingMode: domain.GroupingVulnerabilityProject, SummaryTemplate: "Title: {{.title}}", DescriptionTemplate: "Description: {{.title}}", Version: 1, Actor: "admin", AllowAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := f.workflow.Preview(ctx, usecase.PreviewRequest{TenantID: "tenant-a", MappingID: mapping.ID, FindingID: "group-finding-a", EngagementID: "group-engagement"})
	if err != nil {
		t.Fatal(err)
	}
	created, fresh, err := f.workflow.Submit(ctx, usecase.SubmitRequest{TenantID: "tenant-a", MappingID: mapping.ID, FindingID: "group-finding-a", EngagementID: "group-engagement", RequestKey: "group-create", PreviewDigest: preview.Digest, Actor: "admin"})
	if err != nil || !fresh || created.Action != domain.Create {
		t.Fatalf("create grouped intent: %#v fresh=%t err=%v", created, fresh, err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	groups := any(f.store).(ports.TicketGroupStore)
	group, found, err := groups.GetTicketGroup(ctx, "tenant-a", mapping.ID, "group-project", "CVE-2026-12345")
	if err != nil || !found || group.Remote.ID != "SEC-1" {
		t.Fatalf("group completion: %#v found=%t err=%v", group, found, err)
	}

	second, err := finding.NewManual("group-finding-b", "group-engagement", finding.ManualInput{Title: "Rescanned group finding", Severity: shared.SeverityHigh}, f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	second.AdvisoryID = "CVE-2026-12345"
	if err = f.findings.Upsert(shared.WithTenant(ctx, "tenant-a"), []finding.Finding{second}); err != nil {
		t.Fatal(err)
	}
	preview, err = f.workflow.Preview(ctx, usecase.PreviewRequest{TenantID: "tenant-a", MappingID: mapping.ID, FindingID: "group-finding-b", EngagementID: "group-engagement"})
	if err != nil {
		t.Fatal(err)
	}
	updated, fresh, err := f.workflow.Submit(ctx, usecase.SubmitRequest{TenantID: "tenant-a", MappingID: mapping.ID, FindingID: "group-finding-b", EngagementID: "group-engagement", RequestKey: "group-update", PreviewDigest: preview.Digest, Actor: "admin"})
	if err != nil || !fresh || updated.Action != domain.Update {
		t.Fatalf("update grouped intent: %#v fresh=%t err=%v", updated, fresh, err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if f.provider.posts != 1 || f.provider.updates != 1 {
		t.Fatalf("group update dispatched as a create: posts=%d updates=%d", f.provider.posts, f.provider.updates)
	}
	if _, err = f.workflow.SaveMapping(ctx, "tenant-a", mapping.ID, usecase.MappingInput{IntegrationID: "jira", Scope: domain.Project, ScopeID: "group-project", ProjectKey: "OTHER", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: "security-1", DataClass: notification.DataClassDetail, GroupingMode: domain.GroupingVulnerabilityProject, SummaryTemplate: "Title: {{.title}}", DescriptionTemplate: "Description: {{.title}}", Version: mapping.Version, Actor: "admin", AllowAdmin: true}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("mapping destination change accepted: %v", err)
	}
}

func TestWorkflowBreakerRecoveryAfterCredentialRotationAndReplacement(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	ctx := context.Background()
	submit := func(key string) domain.Intent {
		t.Helper()
		p, err := f.workflow.Preview(ctx, usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
		if err != nil {
			t.Fatal(err)
		}
		i, created, err := f.workflow.Submit(ctx, usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: key, PreviewDigest: p.Digest, Actor: "admin"})
		if err != nil || !created {
			t.Fatalf("submit: created=%t err=%v", created, err)
		}
		return i
	}
	first := submit("before-rotation")
	f.provider.createErr = &ports.TicketProviderError{Status: 401}
	if _, err := f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	failed, err := f.store.GetIntent(ctx, "tenant-a", first.ID)
	if err != nil || failed.State != writeintent.Failed {
		t.Fatalf("first=%+v err=%v", failed, err)
	}
	f.integrations.item.CredentialRevision++
	f.provider.createErr = nil
	replacement := submit("after-rotation")
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if f.provider.posts != 1 {
		t.Fatal("breaker admitted replacement before recovery")
	}
	if _, err = f.workflow.RetryUncertain(ctx, "tenant-a", failed.ID, failed.Version, true, "credential repaired", "admin"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("retry should preserve active replacement: %v", err)
	}
	recovery, ok := any(f.workflow).(interface {
		ResetBreaker(context.Context, shared.ID, shared.ID, string, string, string) error
	})
	if !ok {
		t.Fatal("no workflow recovery for the blocked replacement")
	}
	for _, input := range [][3]string{{"", "10001", "admin"}, {"SEC", "", "admin"}, {"SEC", "10001", ""}, {strings.Repeat("a", 256), "10001", "admin"}} {
		if err = recovery.ResetBreaker(ctx, "tenant-a", "jira", input[0], input[1], input[2]); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("invalid reset: %v", err)
		}
	}
	beforeAudit := len(f.audit.entries)
	f.provider.validationErr = shared.ErrValidation
	if err = recovery.ResetBreaker(ctx, "tenant-a", "jira", "SEC", "10001", "admin"); err == nil || len(f.audit.entries) != beforeAudit {
		t.Fatal("refused tuple literal reached audit")
	}
	f.provider.validationErr = nil
	if err = recovery.ResetBreaker(ctx, "foreign", "jira", "SEC", "10001", "admin"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign reset: %v", err)
	}
	f.audit.err = errors.New("audit unavailable")
	if err = recovery.ResetBreaker(ctx, "tenant-a", "jira", "SEC", "10001", "admin"); err == nil {
		t.Fatal("reset survived failed audit")
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if f.provider.posts != 1 {
		t.Fatal("failed audit opened breaker")
	}
	f.audit.err = nil
	if err = recovery.ResetBreaker(ctx, "tenant-a", "jira", "SEC", "10001", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	done, err := f.store.GetIntent(ctx, "tenant-a", replacement.ID)
	if err != nil || done.State != writeintent.Done || f.provider.posts != 2 {
		t.Fatalf("replacement=%+v posts=%d err=%v", done, f.provider.posts, err)
	}
	unchanged, err := f.store.GetIntent(ctx, "tenant-a", failed.ID)
	if err != nil || unchanged.State != failed.State || unchanged.Version != failed.Version {
		t.Fatalf("failed intent changed: %+v %v", unchanged, err)
	}
	last := f.audit.entries[len(f.audit.entries)-1]
	if last.Action != "ticket.breaker.reset" || last.Actor != "admin" || last.Target != "jira" || last.Metadata["project_key"] != "SEC" || last.Metadata["issue_type"] != "10001" {
		t.Fatalf("reset audit=%+v", last)
	}
}

func TestWorkflowPreviewSubmitSnapshotsAndPostsOnlyFromTick(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", Locale: "en"})
	if err != nil || f.provider.posts != 0 || p.MarkerRequired != true {
		t.Fatalf("preview=%+v posts=%d err=%v", p, f.provider.posts, err)
	}
	intent, created, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "request-1", PreviewDigest: p.Digest, Actor: "admin"})
	if err != nil || !created || f.provider.posts != 0 {
		t.Fatalf("submit=%+v created=%t posts=%d err=%v", intent, created, f.provider.posts, err)
	}
	var preview, snapshot map[string]any
	_ = json.Unmarshal(p.Payload, &preview)
	_ = json.Unmarshal(intent.Snapshot, &snapshot)
	snapshotLabels := snapshot["fields"].(map[string]any)["labels"].([]any)
	if len(snapshotLabels) != 2 || snapshotLabels[0] != "synapse" || snapshotLabels[1] != intent.Marker {
		t.Fatalf("snapshot marker labels = %#v", snapshotLabels)
	}
	delete(snapshot["fields"].(map[string]any), "labels")
	facts := snapshot["_synapse"].(map[string]any)
	if facts["request_preview_digest"] != p.Digest {
		t.Fatal("submit lost original request preview identity")
	}
	delete(facts, "request_preview_digest")
	previewFields := preview["fields"].(map[string]any)
	delete(previewFields, "labels")
	if !reflect.DeepEqual(preview, snapshot) {
		t.Fatalf("snapshot differs beyond marker and request identity\npreview=%s\nsnapshot=%s", p.Payload, intent.Snapshot)
	}
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if f.provider.posts != 1 {
		t.Fatalf("POST count = %d", f.provider.posts)
	}
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil || f.provider.posts != 1 {
		t.Fatalf("duplicate tick posted: %d %v", f.provider.posts, err)
	}
	stored, err := f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
	if err != nil || stored.State != writeintent.Done {
		t.Fatalf("intent=%+v err=%v", stored, err)
	}
}

func TestWorkflowRequiredReporterUsesResolvedDCIdentityInImmutablePayload(t *testing.T) {
	f := newWorkflowFixture(t)
	f.integrations.item.Provider = "jira-dc"
	f.integrations.item.Endpoint = "https://jira.example.test/jira"
	f.provider.metadata.Fields = append(f.provider.metadata.Fields, ports.TicketField{ID: "reporter", Name: "Reporter", Required: true, Type: "user"})
	f.provider.metadata.ResolvedReporter = "sandbox-admin"
	m := f.mapping(t, "security-1")
	p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	var preview map[string]any
	if err := json.Unmarshal(p.Payload, &preview); err != nil {
		t.Fatal(err)
	}
	fields := preview["fields"].(map[string]any)
	reporter, ok := fields["reporter"].(map[string]any)
	if !ok || reporter["name"] != "sandbox-admin" {
		t.Fatalf("preview reporter=%#v", fields["reporter"])
	}
	intent, created, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "resolved-reporter", PreviewDigest: p.Digest, Actor: "admin"})
	if err != nil || !created {
		t.Fatalf("submit=%+v created=%t err=%v", intent, created, err)
	}
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	if err := json.Unmarshal(f.provider.createdPayload, &sent); err != nil {
		t.Fatal(err)
	}
	sentFields, ok := sent["fields"].(map[string]any)
	if !ok {
		t.Fatalf("posted fields=%#v", sent["fields"])
	}
	sentReporter, ok := sentFields["reporter"].(map[string]any)
	if !ok || sentReporter["name"] != "sandbox-admin" {
		t.Fatalf("posted payload=%s", f.provider.createdPayload)
	}
}

func TestWorkflowRefusesRequiredReporterWithoutResolvedIdentity(t *testing.T) {
	f := newWorkflowFixture(t)
	f.provider.metadata.Fields = append(f.provider.metadata.Fields, ports.TicketField{ID: "reporter", Name: "Reporter", Required: true, Type: "user"})
	if _, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "security-1", Version: 1, Actor: "admin"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing reporter identity error=%v", err)
	}
	if f.provider.posts != 0 {
		t.Fatalf("missing reporter identity posted=%d", f.provider.posts)
	}
}

func TestWorkflowRefusesOtherRequiredUserField(t *testing.T) {
	f := newWorkflowFixture(t)
	f.provider.metadata.Fields = append(f.provider.metadata.Fields, ports.TicketField{ID: "assignee", Name: "Assignee", Required: true, Type: "user"})
	if _, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "security-1", Version: 1, Actor: "admin"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("required arbitrary user field error=%v", err)
	}
}

func TestWorkflowRequiredReporterCredentialRevisionChangeRefusesDispatch(t *testing.T) {
	f := newWorkflowFixture(t)
	f.integrations.item.Provider = "jira-dc"
	f.integrations.item.Endpoint = "https://jira.example.test/jira"
	f.provider.metadata.Fields = append(f.provider.metadata.Fields, ports.TicketField{ID: "reporter", Name: "Reporter", Required: true, Type: "user"})
	f.provider.metadata.ResolvedReporter = "sandbox-admin"
	m := f.mapping(t, "security-1")
	intent := f.submit(t, m, "reporter-credential-revision")
	f.integrations.item.CredentialRevision++
	f.provider.metadata.ResolvedReporter = "different-identity"
	if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
	if err != nil || stored.State != writeintent.Failed || stored.ErrorCode != "preflight_refused" || f.provider.posts != 0 {
		t.Fatalf("credential revision intent=%+v posts=%d err=%v", stored, f.provider.posts, err)
	}
}

func TestWorkflowSubmitIsIdempotentAndRejectsStaleDigest(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "same", PreviewDigest: "stale", Actor: "admin"}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale digest = %v", err)
	}
	first, created, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "same", PreviewDigest: p.Digest, Actor: "admin"})
	if err != nil || !created {
		t.Fatalf("first=%+v %t %v", first, created, err)
	}
	replay, created, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "same", PreviewDigest: p.Digest, Actor: "admin"})
	if err != nil || created || replay.ID != first.ID {
		t.Fatalf("replay=%+v %t %v", replay, created, err)
	}
}

func TestWorkflowSubmitRejectsConfiguredCredentialRequestKeyBeforePersistence(t *testing.T) {
	credential := "short-dc-pat"
	for _, test := range []struct {
		name       string
		requestKey string
	}{
		{name: "raw", requestKey: credential},
		{name: "base64url", requestKey: base64.RawURLEncoding.EncodeToString([]byte(credential))},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newWorkflowFixture(t)
			m := f.mapping(t, "security-1")
			p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
			if err != nil {
				t.Fatal(err)
			}
			f.provider.validationFn = func(raw json.RawMessage) error {
				if strings.Contains(string(raw), test.requestKey) {
					return &ports.TicketProviderError{Code: "unsafe_payload"}
				}
				return nil
			}
			f.audit.mu.Lock()
			auditCount := len(f.audit.entries)
			f.audit.mu.Unlock()

			if _, _, err = f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: test.requestKey, PreviewDigest: p.Digest, Actor: "admin"}); err == nil {
				t.Fatal("configured credential request key was accepted")
			}
			if strings.Contains(err.Error(), credential) || strings.Contains(err.Error(), test.requestKey) {
				t.Fatalf("credential refusal exposed request key: %v", err)
			}
			intents, listErr := f.store.ListFindingIntents(context.Background(), "tenant-a", "finding-a", 100)
			if listErr != nil || len(intents) != 0 || f.provider.posts != 0 {
				t.Fatalf("credential request key changed durable state intents=%d posts=%d err=%v", len(intents), f.provider.posts, listErr)
			}
			f.audit.mu.Lock()
			defer f.audit.mu.Unlock()
			if len(f.audit.entries) != auditCount {
				t.Fatalf("credential request key appended audit entries: %#v", f.audit.entries)
			}
		})
	}
}

func TestWorkflowSubmitAllowsOrdinaryRequestKeyReplay(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	req := usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "ordinary-request-key", PreviewDigest: p.Digest, Actor: "admin"}
	first, created, err := f.workflow.Submit(context.Background(), req)
	if err != nil || !created {
		t.Fatalf("first=%+v created=%t err=%v", first, created, err)
	}
	replay, created, err := f.workflow.Submit(context.Background(), req)
	if err != nil || created || replay.ID != first.ID {
		t.Fatalf("replay=%+v created=%t err=%v", replay, created, err)
	}
}

func TestWorkflowConcurrentTicksIssueOneProviderWrite(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "concurrent", PreviewDigest: p.Digest, Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() { defer wait.Done(); _, _ = f.workflow.Tick(context.Background(), "tenant-a", 10) }()
	}
	wait.Wait()
	f.provider.mu.Lock()
	posts := f.provider.posts
	f.provider.mu.Unlock()
	if posts != 1 {
		t.Fatalf("concurrent ticks issued %d provider POSTs", posts)
	}
}

func TestWorkflowUncertainRecoveryNeverRetriesWrite(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	f.provider.createErr = &ports.TicketProviderError{Code: "network", Ambiguous: true}
	p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	intent, _, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "uncertain", PreviewDigest: p.Digest, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
	if err != nil || stored.State != writeintent.Uncertain || f.provider.posts != 1 {
		t.Fatalf("uncertain=%+v posts=%d err=%v", stored, f.provider.posts, err)
	}
	if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil || f.provider.posts != 1 {
		t.Fatalf("uncertain was retried: posts=%d err=%v", f.provider.posts, err)
	}
	zero, err := f.workflow.Reconcile(context.Background(), "tenant-a", intent.ID, stored.Version)
	if err != nil || zero.State != writeintent.Uncertain {
		t.Fatalf("zero reconciliation=%+v %v", zero, err)
	}
	f.provider.hits = []domain.RemoteTicket{{ID: "SEC-1", URL: "https://tenant.atlassian.net/browse/SEC-1"}}
	found, err := f.workflow.Reconcile(context.Background(), "tenant-a", intent.ID, zero.Version)
	if err != nil || found.State != writeintent.Done {
		t.Fatalf("one reconciliation=%+v %v", found, err)
	}
}

func TestWorkflowRequiresSecurityOrAuditedAdminWaiver(t *testing.T) {
	f := newWorkflowFixture(t)
	_, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", Version: 1, Actor: "admin"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing security = %v", err)
	}
	m, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", Version: 1, Actor: "admin", AllowAdmin: true, WaiverReason: "approved incident exception"})
	if err != nil || m.WaiverReason == "" {
		t.Fatalf("waiver mapping=%+v err=%v", m, err)
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	if len(f.audit.entries) == 0 {
		t.Fatal("waiver save was not audited")
	}
}

func TestWorkflowRetryUncertainRequiresAcknowledgementAndRecordsReason(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	f.provider.createErr = &ports.TicketProviderError{Code: "network", Ambiguous: true}
	p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	intent, _, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "retry", PreviewDigest: p.Digest, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := f.workflow.RetryUncertain(context.Background(), "tenant-a", intent.ID, 3, false, "operator checked Jira", "admin"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("retry without acknowledgement = %v", err)
	}
	updated, err := f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.workflow.RetryUncertain(context.Background(), "tenant-a", intent.ID, updated.Version, true, "operator checked Jira", "admin"); err != nil {
		t.Fatal(err)
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	found := false
	for _, entry := range f.audit.entries {
		if entry.Action == "ticket.intent.retry_duplicate_risk" && entry.Metadata["reason"] == "operator checked Jira" {
			found = true
		}
	}
	if !found {
		t.Fatalf("retry reason missing from audit: %#v", f.audit.entries)
	}
}

func TestWorkflowRetryAuditReasonScrubsGenericSecretsAndURLs(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	f.provider.createErr = &ports.TicketProviderError{Code: "network", Ambiguous: true}
	intent := f.submit(t, m, "redacted-retry")
	if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	current, err := f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	secret := "token" + "Value_123456"
	reason := "Bearer " + secret + " observed at https://jira.example.test/browse/SEC-1?token=" + secret
	if _, err = f.workflow.RetryUncertain(context.Background(), "tenant-a", intent.ID, current.Version, true, reason, "admin"); err != nil {
		t.Fatal(err)
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	for _, entry := range f.audit.entries {
		if entry.Action != "ticket.intent.retry_duplicate_risk" {
			continue
		}
		got := entry.Metadata["reason"]
		if strings.Contains(got, secret) || strings.Contains(got, "https://") || !strings.Contains(got, "[REDACTED]") {
			t.Fatalf("unsafe retry audit reason %q", got)
		}
		return
	}
	t.Fatal("retry audit entry missing")
}

func TestWorkflowConfiguredCredentialInReasonRefusesBeforeAuditOrStateChange(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	f.provider.createErr = &ports.TicketProviderError{Code: "network", Ambiguous: true}
	intent := f.submit(t, m, "credential-retry")
	if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	before, err := f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.audit.mu.Lock()
	auditCount := len(f.audit.entries)
	f.audit.mu.Unlock()
	secret := "bare-configured-credential"
	f.provider.validationFn = func(raw json.RawMessage) error {
		if strings.Contains(string(raw), secret) {
			return &ports.TicketProviderError{Code: "unsafe_payload"}
		}
		return nil
	}
	if _, err = f.workflow.RetryUncertain(context.Background(), "tenant-a", intent.ID, before.Version, true, "checked "+secret, "admin"); err == nil {
		t.Fatal("configured credential in retry reason was accepted")
	}
	after, err := f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("credential refusal changed intent before=%+v after=%+v err=%v", before, after, err)
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	if len(f.audit.entries) != auditCount {
		t.Fatalf("credential refusal appended audit entries: %#v", f.audit.entries)
	}
}

func TestWorkflowConfiguredCredentialInWaiverRefusesBeforePersistence(t *testing.T) {
	f := newWorkflowFixture(t)
	before, err := f.store.ListMappings(context.Background(), "tenant-a", 200, "")
	if err != nil {
		t.Fatal(err)
	}
	f.audit.mu.Lock()
	auditCount := len(f.audit.entries)
	f.audit.mu.Unlock()
	secret := "bare-configured-credential"
	f.provider.validationFn = func(raw json.RawMessage) error {
		if strings.Contains(string(raw), secret) {
			return &ports.TicketProviderError{Code: "unsafe_payload"}
		}
		return nil
	}
	_, err = f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{
		IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001",
		AllowAdmin: true, WaiverReason: "approved " + secret, Version: 1, Actor: "admin",
	})
	if err == nil {
		t.Fatal("configured credential in waiver was accepted")
	}
	after, listErr := f.store.ListMappings(context.Background(), "tenant-a", 200, "")
	if listErr != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("credential refusal changed mappings before=%+v after=%+v err=%v", before, after, listErr)
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	if len(f.audit.entries) != auditCount {
		t.Fatalf("credential refusal appended audit entries: %#v", f.audit.entries)
	}
}

func TestWorkflowRejectsMappingSelectionMissingFromProviderMetadataBeforeSend(t *testing.T) {
	f := newWorkflowFixture(t)
	f.provider.metadata = ports.TicketMetadata{}
	_, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "security-1", Version: 1, Actor: "admin"})
	if !errors.Is(err, shared.ErrValidation) || f.provider.posts != 0 {
		t.Fatalf("invalid metadata mapping err=%v posts=%d", err, f.provider.posts)
	}
}

func TestWorkflowRejectsMappingWhenCreateMetadataOmitsEmittedCoreField(t *testing.T) {
	for _, omitted := range []string{"summary", "description", "labels"} {
		t.Run(omitted, func(t *testing.T) {
			f := newWorkflowFixture(t)
			fields := make([]ports.TicketField, 0, len(f.provider.metadata.Fields))
			for _, field := range f.provider.metadata.Fields {
				if field.ID != omitted {
					fields = append(fields, field)
				}
			}
			f.provider.metadata.Fields = fields
			if _, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "security-1", Version: 1, Actor: "admin"}); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("missing %s error=%v, want validation", omitted, err)
			}
			intents, err := f.store.ListFindingIntents(context.Background(), "tenant-a", "finding-a", 100)
			if err != nil || len(intents) != 0 || f.provider.posts != 0 {
				t.Fatalf("missing %s admitted intent=%d posts=%d err=%v", omitted, len(intents), f.provider.posts, err)
			}
		})
	}
}

func TestWorkflowPreviewAndPreflightRefuseWhenCreateMetadataOmitsEmittedCoreField(t *testing.T) {
	for _, omitted := range []string{"summary", "description", "labels"} {
		t.Run(omitted, func(t *testing.T) {
			f := newWorkflowFixture(t)
			m := f.mapping(t, "security-1")
			intent := f.submit(t, m, "missing-core-"+omitted)
			f.provider.metadata.Fields = ticketMetadataWithoutField(f.provider.metadata.Fields, omitted)
			fresh, err := usecase.NewWorkflow(f.store, f.integrations, workflowProviders{f.provider}, f.findings, f.engagements, f.policy, f.audit, &ticketIDs{}, f.clock)
			if err != nil {
				t.Fatal(err)
			}
			fresh.SetPublicBaseURL("https://console.example")
			if _, err = fresh.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"}); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("preview missing %s error=%v, want validation", omitted, err)
			}
			if _, err = fresh.Tick(context.Background(), "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
			stored, err := f.store.GetIntent(context.Background(), "tenant-a", intent.ID)
			if err != nil || stored.State != writeintent.Failed || stored.ErrorCode != "preflight_refused" || f.provider.posts != 0 {
				t.Fatalf("missing %s preflight=%+v posts=%d err=%v", omitted, stored, f.provider.posts, err)
			}
		})
	}
}

func ticketMetadataWithoutField(fields []ports.TicketField, omitted string) []ports.TicketField {
	result := make([]ports.TicketField, 0, len(fields))
	for _, field := range fields {
		if field.ID != omitted {
			result = append(result, field)
		}
	}
	return result
}

func (f workflowFixture) submit(t *testing.T, m domain.Mapping, key string) domain.Intent {
	t.Helper()
	p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	i, _, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: key, PreviewDigest: p.Digest, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestWorkflowLeaseExpiryRequiresReconciliationWithoutSending(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	i := f.submit(t, m, "crashed-worker")
	now := f.clock.Now()
	lease := now.Add(time.Minute)
	if _, ok, err := f.store.AcquireDispatch(context.Background(), "tenant-a", i.ID, i.Version, now, lease); err != nil || !ok {
		t.Fatalf("claim %t %v", ok, err)
	}
	restarted, err := usecase.NewWorkflow(f.store, f.integrations, workflowProviders{f.provider}, f.findings, f.engagements, f.policy, f.audit, &ticketIDs{}, ticketClock{now.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	restarted.SetPublicBaseURL("https://console.example")
	for range 2 {
		if _, err := restarted.Tick(context.Background(), "tenant-a", 10); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := f.store.GetIntent(context.Background(), "tenant-a", i.ID)
	if err != nil || stored.State != writeintent.Uncertain || f.provider.posts != 0 {
		t.Fatalf("expired %+v posts=%d %v", stored, f.provider.posts, err)
	}
}

func TestWorkflowMultipleMarkerMatchesKeepHumanDecision(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	i := f.submit(t, m, "multiple")
	f.provider.createErr = &ports.TicketProviderError{Code: "network", Ambiguous: true}
	if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	f.provider.hits = []domain.RemoteTicket{{ID: "SEC-1", URL: "https://tenant.atlassian.net/browse/SEC-1"}, {ID: "SEC-2", URL: "https://tenant.atlassian.net/browse/SEC-2"}}
	stored, err := f.store.GetIntent(context.Background(), "tenant-a", i.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.workflow.Reconcile(context.Background(), "tenant-a", i.ID, stored.Version)
	if err != nil || got.State != writeintent.Uncertain || got.ErrorCode != "multiple_matches" {
		t.Fatalf("reconcile %+v %v", got, err)
	}
	if _, err = f.workflow.RetryUncertain(context.Background(), "tenant-a", i.ID, got.Version, true, "operator checked", "admin"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("ambiguous retry %v", err)
	}
	links, _ := f.store.ListLinks(context.Background(), "tenant-a", "finding-a")
	if len(links) != 0 || f.provider.posts != 1 {
		t.Fatalf("ambiguity produced links=%d posts=%d", len(links), f.provider.posts)
	}
}

func TestWorkflowPreflightRefusesChangedAuthorityBeforeProviderWrite(t *testing.T) {
	for _, kind := range []string{"origin", "credentials", "mapping", "disabled", "policy"} {
		t.Run(kind, func(t *testing.T) {
			f := newWorkflowFixture(t)
			m := f.mapping(t, "security-1")
			i := f.submit(t, m, "authority-change")
			switch kind {
			case "origin":
				f.integrations.item.Endpoint = "https://other.atlassian.net"
			case "credentials":
				f.integrations.item.CredentialRevision++
			case "disabled":
				f.integrations.item.Enabled = false
			case "mapping":
				m.Labels = []string{"changed"}
				if _, err := f.store.UpdateMapping(context.Background(), "tenant-a", m, m.Version); err != nil {
					t.Fatal(err)
				}
			case "policy":
				f.policy.setting.ExternalNotifications = notification.EngagementNotificationsNone
			}
			if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
			got, err := f.store.GetIntent(context.Background(), "tenant-a", i.ID)
			if err != nil || got.State != writeintent.Failed || got.ErrorCode != "preflight_refused" || f.provider.posts != 0 {
				t.Fatalf("authority %+v posts=%d %v", got, f.provider.posts, err)
			}
		})
	}
}

func TestWorkflowAuditFailureCannotAdmitExternalCommand(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	f.audit.err = errors.New("audit unavailable")
	if _, _, err = f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "audit-failure", PreviewDigest: p.Digest, Actor: "admin"}); err == nil {
		t.Fatal("audit failure admitted command")
	}
	intents, _ := f.store.ListFindingIntents(context.Background(), "tenant-a", "finding-a", 100)
	if len(intents) != 0 {
		t.Fatalf("unaudited intents=%d", len(intents))
	}
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil || f.provider.posts != 0 {
		t.Fatalf("unaudited write posts=%d %v", f.provider.posts, err)
	}
}

func TestWorkflowConfiguredCredentialRefusalPrecedesPreviewAndPersistence(t *testing.T) {
	f := newWorkflowFixture(t)
	m := f.mapping(t, "security-1")
	f.provider.validationErr = &ports.TicketProviderError{Code: "unsafe_payload"}
	if _, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"}); err == nil {
		t.Fatal("unsafe preview exposed")
	}
	before, _ := f.store.ListMappings(context.Background(), "tenant-a", 200, "")
	if _, err := f.workflow.SaveMapping(context.Background(), "tenant-a", m.ID, usecase.MappingInput{IntegrationID: m.IntegrationID, Scope: m.Scope, ScopeID: m.ScopeID, ProjectKey: m.ProjectKey, IssueType: m.IssueType, SecurityLevel: m.SecurityLevel, SummaryTemplate: "opaque credential literal", Version: m.Version, Actor: "admin"}); err == nil {
		t.Fatal("unsafe literal stored")
	}
	after, _ := f.store.ListMappings(context.Background(), "tenant-a", 200, "")
	if !reflect.DeepEqual(before, after) || f.provider.posts != 0 {
		t.Fatal("credential refusal changed durable state")
	}
}

func TestWorkflowFreshRequestCannotBypassUnresolvedCreate(t *testing.T) {
	for _, state := range []string{"pending", "uncertain"} {
		t.Run(state, func(t *testing.T) {
			f := newWorkflowFixture(t)
			m := f.mapping(t, "security-1")
			original := f.submit(t, m, "original-command")
			if state == "uncertain" {
				f.provider.createErr = &ports.TicketProviderError{Code: "network", Ambiguous: true}
				if _, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
					t.Fatal(err)
				}
			}
			p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "fresh-command", PreviewDigest: p.Digest, Actor: "consultant"}); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("new key bypassed %s: %v", state, err)
			}
			replay, created, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "original-command", PreviewDigest: p.Digest, Actor: "consultant"})
			if err != nil || created || replay.ID != original.ID {
				t.Fatalf("idempotent replay %+v %t %v", replay, created, err)
			}
			all, err := f.store.ListFindingIntents(context.Background(), "tenant-a", "finding-a", 100)
			if err != nil || len(all) != 1 {
				t.Fatalf("unresolved commands %d %v", len(all), err)
			}
		})
	}
}

func TestWorkflowMetadataAdmissionBoundsDistinctDiscoveriesAndReleasesCapacity(t *testing.T) {
	f := newWorkflowFixture(t)
	release := make(chan struct{})
	f.provider.discoverStart = make(chan struct{}, 8)
	f.provider.discoverWait = release
	done := make(chan error, 4)
	for index := range 4 {
		go func(index int) {
			_, err := f.workflow.Metadata(context.Background(), "tenant-a", "jira", "project-"+string(rune('a'+index)), "10001", "")
			done <- err
		}(index)
	}
	for range 4 {
		select {
		case <-f.provider.discoverStart:
		case <-time.After(time.Second):
			t.Fatal("metadata discovery did not start")
		}
	}
	if _, err := f.workflow.Metadata(context.Background(), "tenant-a", "jira", "capacity-refused", "10001", ""); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("fifth active metadata discovery error=%v, want capacity conflict", err)
	}
	close(release)
	for range 4 {
		if err := <-done; err != nil {
			t.Fatalf("admitted metadata discovery error=%v", err)
		}
	}
	if _, err := f.workflow.Metadata(context.Background(), "tenant-a", "jira", "capacity-released", "10001", ""); err != nil {
		t.Fatalf("metadata capacity did not release after completed discovery: %v", err)
	}
}

type metadataWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *metadataWaitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestWorkflowMetadataSameKeySharesOneDiscovery(t *testing.T) {
	f := newWorkflowFixture(t)
	release := make(chan struct{})
	f.provider.discoverStart = make(chan struct{}, 1)
	f.provider.discoverWait = release
	done := make(chan error, 2)
	go func() {
		_, err := f.workflow.Metadata(context.Background(), "tenant-a", "jira", "shared", "10001", "")
		done <- err
	}()
	select {
	case <-f.provider.discoverStart:
	case <-time.After(time.Second):
		t.Fatal("primary metadata discovery did not start")
	}
	joined := &metadataWaitingContext{Context: context.Background(), waiting: make(chan struct{})}
	go func() {
		_, err := f.workflow.Metadata(joined, "tenant-a", "jira", "shared", "10001", "")
		done <- err
	}()
	// The second caller reaches its context wait only after joining the still
	// blocked discovery. No scheduler or sleep assumption permits release early.
	select {
	case <-joined.waiting:
	case <-time.After(time.Second):
		t.Fatal("second caller did not join metadata discovery")
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("shared metadata discovery error=%v", err)
		}
	}
	f.provider.mu.Lock()
	discoveries := f.provider.discoveries
	f.provider.mu.Unlock()
	if discoveries != 1 {
		t.Fatalf("same metadata key issued %d discoveries, want one", discoveries)
	}
}

func TestWorkflowMetadataCanceledDiscoveryReleasesCapacity(t *testing.T) {
	f := newWorkflowFixture(t)
	f.provider.discoverStart = make(chan struct{}, 1)
	f.provider.discoverWait = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := f.workflow.Metadata(ctx, "tenant-a", "jira", "canceled", "10001", "")
		done <- err
	}()
	select {
	case <-f.provider.discoverStart:
	case <-time.After(time.Second):
		t.Fatal("metadata discovery did not start")
	}
	joined := &metadataWaitingContext{Context: context.Background(), waiting: make(chan struct{})}
	flightDone := make(chan error, 1)
	go func() {
		_, err := f.workflow.Metadata(joined, "tenant-a", "jira", "canceled", "10001", "")
		flightDone <- err
	}()
	select {
	case <-joined.waiting:
	case <-time.After(time.Second):
		t.Fatal("observer did not join canceled metadata discovery")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled metadata discovery error=%v, want context canceled", err)
	}
	// The uncanceled observer receives the flight result after its deferred
	// admission release, whereas the canceled caller may return before cleanup.
	if err := <-flightDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("shared flight error=%v, want context canceled", err)
	}
	f.provider.mu.Lock()
	release := make(chan struct{})
	f.provider.discoverStart = make(chan struct{}, 4)
	f.provider.discoverWait = release
	f.provider.mu.Unlock()
	remaining := make(chan error, 4)
	for index := range 4 {
		go func(index int) {
			_, err := f.workflow.Metadata(context.Background(), "tenant-a", "jira", "after-cancel-"+string(rune('a'+index)), "10001", "")
			remaining <- err
		}(index)
	}
	for range 4 {
		select {
		case <-f.provider.discoverStart:
		case <-time.After(time.Second):
			t.Fatal("canceled discovery did not restore all four admission slots")
		}
	}
	close(release)
	for range 4 {
		if err := <-remaining; err != nil {
			t.Fatalf("discovery after cancellation failed: %v", err)
		}
	}
}

func TestWorkflowPreflightRereadsAuthorityAfterMetadataDiscovery(t *testing.T) {
	for _, kind := range []string{"disabled", "mapping", "policy"} {
		t.Run(kind, func(t *testing.T) {
			f := newWorkflowFixture(t)
			m := f.mapping(t, "security-1")
			i := f.submit(t, m, "mid-discovery-"+kind)
			fresh, err := usecase.NewWorkflow(f.store, f.integrations, workflowProviders{f.provider}, f.findings, f.engagements, f.policy, f.audit, &ticketIDs{}, f.clock)
			if err != nil {
				t.Fatal(err)
			}
			fresh.SetPublicBaseURL("https://console.example")
			release := make(chan struct{})
			f.provider.discoverStart = make(chan struct{}, 1)
			f.provider.discoverWait = release
			done := make(chan error, 1)
			go func() { _, err := fresh.Tick(context.Background(), "tenant-a", 10); done <- err }()
			select {
			case <-f.provider.discoverStart:
			case <-time.After(time.Second):
				t.Fatal("preflight metadata discovery did not start")
			}
			switch kind {
			case "disabled":
				// Disabling changes only the optimistic-lock version; it must still
				// fence a dispatch that was admitted before metadata started.
				f.integrations.item.Enabled = false
				f.integrations.item.Version++
			case "mapping":
				m.Labels = []string{"changed"}
				if _, err := f.store.UpdateMapping(context.Background(), "tenant-a", m, m.Version); err != nil {
					t.Fatal(err)
				}
			case "policy":
				f.policy.setting.ExternalNotifications = notification.EngagementNotificationsNone
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			got, err := f.store.GetIntent(context.Background(), "tenant-a", i.ID)
			if err != nil || got.State != writeintent.Failed || got.ErrorCode != "preflight_refused" || f.provider.posts != 0 {
				t.Fatalf("mid-discovery %s authority=%+v posts=%d err=%v", kind, got, f.provider.posts, err)
			}
		})
	}
}

func TestWorkflowAutoPushIsOptInConfirmedAndIdempotent(t *testing.T) {
	f := newWorkflowFixture(t)
	input := usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: "security-1", SummaryTemplate: "{{.title}}", DescriptionTemplate: "{{.title}}", AutoPushEnabled: true, AutoPushMinSeverity: shared.SeverityHigh, Version: 1, Actor: "admin"}
	if _, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", input); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("non-admin auto-push enable: %v", err)
	}
	input.AllowAdmin = true
	if _, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", input); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("auto-push without durable event source: %v", err)
	}
	f.workflow.SetAutoPushSourceAvailable(true)
	m, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", input)
	if err != nil || m.AutoPushEnabledAt == nil {
		t.Fatalf("save auto policy: %#v %v", m, err)
	}
	current, err := f.findings.GetByEngagementAndID(shared.WithTenant(context.Background(), "tenant-a"), "eng-a", "finding-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.findings.UpdateStatus(shared.WithTenant(context.Background(), "tenant-a"), "eng-a", "finding-a", finding.StatusConfirmed, current.Version); err != nil {
		t.Fatal(err)
	}
	event := ports.TicketAutoPushEvent{ID: "status-confirmed", OccurredAt: f.clock.Now().Add(time.Nanosecond), EngagementID: "eng-a", FindingID: "finding-a", ToStatus: string(finding.StatusConfirmed)}
	if err = f.store.AppendAutoPushEvent("tenant-a", event); err != nil {
		t.Fatal(err)
	}
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	intents, err := f.store.ListFindingIntents(context.Background(), "tenant-a", "finding-a", 10)
	if err != nil || len(intents) != 1 || f.provider.posts != 1 {
		t.Fatalf("first auto push intents=%+v posts=%d err=%v", intents, f.provider.posts, err)
	}
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	intents, _ = f.store.ListFindingIntents(context.Background(), "tenant-a", "finding-a", 10)
	if len(intents) != 1 || f.provider.posts != 1 {
		t.Fatalf("replay created duplicate: intents=%d posts=%d", len(intents), f.provider.posts)
	}
}

func TestWorkflowAutoPushDispatchRechecksCurrentFindingAndPolicy(t *testing.T) {
	f := newWorkflowFixture(t)
	f.workflow.SetAutoPushSourceAvailable(true)
	m, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: "security-1", SummaryTemplate: "{{.title}}", DescriptionTemplate: "{{.title}}", AutoPushEnabled: true, AutoPushMinSeverity: shared.SeverityHigh, Version: 1, Actor: "admin", AllowAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	current, _ := f.findings.GetByEngagementAndID(shared.WithTenant(context.Background(), "tenant-a"), "eng-a", "finding-a")
	confirmed, err := f.findings.UpdateStatus(shared.WithTenant(context.Background(), "tenant-a"), "eng-a", "finding-a", finding.StatusConfirmed, current.Version)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.workflow.Preview(context.Background(), usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	i, created, err := f.workflow.Submit(context.Background(), usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "auto:current-state", PreviewDigest: p.Digest, Actor: "system:auto_push"})
	if err != nil || !created {
		t.Fatalf("create auto intent: %#v %t %v", i, created, err)
	}
	if _, err = f.findings.UpdateStatus(shared.WithTenant(context.Background(), "tenant-a"), "eng-a", "finding-a", finding.StatusOpen, confirmed.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	got, err := f.store.GetIntent(context.Background(), "tenant-a", i.ID)
	if err != nil || got.State != writeintent.Failed || got.ErrorCode != "preflight_refused" || f.provider.posts != 0 {
		t.Fatalf("stale auto intent=%+v posts=%d err=%v", got, f.provider.posts, err)
	}
}

func TestWorkflowAutoPushDefaultsMinimumSeverityToHigh(t *testing.T) {
	f := newWorkflowFixture(t)
	f.workflow.SetAutoPushSourceAvailable(true)
	m, err := f.workflow.SaveMapping(context.Background(), "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", SecurityLevel: "security-1", SummaryTemplate: "{{.title}}", DescriptionTemplate: "{{.title}}", AutoPushEnabled: true, Actor: "admin", AllowAdmin: true})
	if err != nil || m.AutoPushMinSeverity != shared.SeverityHigh {
		t.Fatalf("default threshold mapping=%+v err=%v", m, err)
	}
}

func TestWorkflowStatusTransitionIsIdempotent(t *testing.T) {
	f := newWorkflowFixture(t)
	f.workflow.SetSLAStore(memory.NewSLAStore())
	ctx := context.Background()
	m, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: "security-1", SummaryTemplate: "Title: {{.title}}", DescriptionTemplate: "Description: {{.title}}", StatusTransitions: map[domain.SyncState]string{domain.SyncRemediated: "123"}, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.workflow.Preview(ctx, usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := f.workflow.Submit(ctx, usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "status-origin", PreviewDigest: p.Digest, Actor: "admin"}); err != nil || !created {
		t.Fatalf("origin created=%t err=%v", created, err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	item, err := f.findings.GetByEngagementAndID(shared.WithTenant(ctx, "tenant-a"), "eng-a", "finding-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.findings.UpdateStatus(shared.WithTenant(ctx, "tenant-a"), "eng-a", "finding-a", finding.StatusRemediated, item.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	// A rescanned title update changes the finding revision but not its status
	// episode, so it must not repeat the remote transition.
	item, err = f.findings.GetByEngagementAndID(shared.WithTenant(ctx, "tenant-a"), "eng-a", "finding-a")
	if err != nil {
		t.Fatal(err)
	}
	item.Title = "Ticket finding, rescanned"
	if err = f.findings.Upsert(shared.WithTenant(ctx, "tenant-a"), []finding.Finding{item}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if f.provider.transitions != 1 {
		items, _ := f.store.ListFindingIntents(ctx, "tenant-a", "finding-a", 10)
		targets, targetErr := f.store.ListTicketStatusTargets(ctx, "tenant-a", 10)
		t.Fatalf("transitions=%d intents=%+v targets=%+v targetErr=%v", f.provider.transitions, items, targets, targetErr)
	}
	if f.provider.updates != 1 {
		items, _ := f.store.ListFindingIntents(ctx, "tenant-a", "finding-a", 10)
		t.Fatalf("field refreshes=%d, want one after the transition; intents=%+v", f.provider.updates, items)
	}
	progresses := any(f.store).(ports.TicketStatusProgressStore)
	progress, err := progresses.GetTicketStatusProgress(ctx, "tenant-a", m.ID, "eng-a", "finding-a")
	if err != nil || progress.AppliedState != domain.SyncRemediated || progress.UpdateIntentID.IsZero() || progress.IntegrationAuthor != "jira-integration" {
		t.Fatalf("status progress=%+v err=%v", progress, err)
	}
}

func TestWorkflowStatusSyncUsesDistinctEpisodesForReopen(t *testing.T) {
	f := newWorkflowFixture(t)
	f.workflow.SetSLAStore(memory.NewSLAStore())
	ctx := context.Background()
	m, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: "security-1", SummaryTemplate: "Title: {{.title}}", DescriptionTemplate: "Description: {{.title}}", StatusTransitions: map[domain.SyncState]string{domain.SyncRemediated: "123", domain.SyncReopen: "124"}, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.workflow.Preview(ctx, usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := f.workflow.Submit(ctx, usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "episode-origin", PreviewDigest: p.Digest, Actor: "admin"}); err != nil || !created {
		t.Fatalf("origin created=%t err=%v", created, err)
	}
	tick := func(n int) {
		for range n {
			if _, err := f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
		}
	}
	set := func(status finding.Status) {
		item, getErr := f.findings.GetByEngagementAndID(shared.WithTenant(ctx, "tenant-a"), "eng-a", "finding-a")
		if getErr != nil {
			t.Fatal(getErr)
		}
		if _, updateErr := f.findings.UpdateStatus(shared.WithTenant(ctx, "tenant-a"), "eng-a", "finding-a", status, item.Version); updateErr != nil {
			t.Fatal(updateErr)
		}
	}
	// Initial open, close, reopen, and close again are four distinct state
	// episodes. Repeating a tick after each completion must not add a fifth.
	tick(4)
	set(finding.StatusRemediated)
	tick(3)
	set(finding.StatusConfirmed)
	tick(3)
	set(finding.StatusRemediated)
	tick(4)
	if f.provider.transitions != 4 || f.provider.updates != 4 {
		t.Fatalf("transitions=%d updates=%d", f.provider.transitions, f.provider.updates)
	}
	progresses := any(f.store).(ports.TicketStatusProgressStore)
	progress, err := progresses.GetTicketStatusProgress(ctx, "tenant-a", m.ID, "eng-a", "finding-a")
	if err != nil || progress.Episode != 4 || progress.AppliedState != domain.SyncRemediated {
		t.Fatalf("progress=%+v err=%v", progress, err)
	}
}

func TestWorkflowStatusSyncReopensOnAcceptedRiskExpiry(t *testing.T) {
	base := newWorkflowFixture(t)
	ctx := context.Background()
	clock := &mutableWorkflowClock{now: base.clock.Now()}
	workflow, err := usecase.NewWorkflow(base.store, base.integrations, workflowProviders{base.provider}, base.findings, base.engagements, base.policy, base.audit, &ticketIDs{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	workflow.SetPublicBaseURL("https://console.example")
	slaStore := memory.NewSLAStore()
	workflow.SetSLAStore(slaStore)
	m, err := workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: "security-1", SummaryTemplate: "Title: {{.title}}", DescriptionTemplate: "Description: {{.title}}", StatusTransitions: map[domain.SyncState]string{domain.SyncAccepted: "125", domain.SyncReopen: "124"}, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := workflow.Preview(ctx, usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := workflow.Submit(ctx, usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "accepted-expiry-origin", PreviewDigest: p.Digest, Actor: "admin"}); err != nil || !created {
		t.Fatalf("origin created=%t err=%v", created, err)
	}
	tick := func(n int) {
		for range n {
			if _, err := workflow.Tick(ctx, "tenant-a", 10); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The initial open episode uses reopen. This proves a later expiry cannot
	// reuse its completed request key.
	tick(4)
	assessment, err := sla.Evaluate(sla.AssessmentInput{TenantID: "tenant-a", EngagementID: "eng-a", FindingID: "finding-a", Risk: sla.Inputs{Severity: shared.SeverityHigh}}, sla.DefaultConfig(), clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = slaStore.UpsertAssessment(shared.WithTenant(ctx, "tenant-a"), assessment); err != nil {
		t.Fatal(err)
	}
	current, err := slaStore.Current(shared.WithTenant(ctx, "tenant-a"), "tenant-a", "eng-a", "finding-a")
	if err != nil {
		t.Fatal(err)
	}
	expires := clock.now.Add(time.Hour)
	next, event, err := sla.ApplyTransition(current.Lifecycle, "accepted-event", sla.TransitionCommand{To: sla.RemediationAcceptedRisk, Reason: "approved exception", CompensatingControl: "network isolation", AcceptanceExpiresAt: &expires, Actor: "alice", ExpectedVersion: current.Lifecycle.Version}, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if err = slaStore.SaveTransition(shared.WithTenant(ctx, "tenant-a"), next, event); err != nil {
		t.Fatal(err)
	}
	tick(3)
	clock.now = expires
	tick(4)
	if base.provider.transitions != 3 || base.provider.updates != 3 {
		t.Fatalf("transitions=%d updates=%d", base.provider.transitions, base.provider.updates)
	}
	progresses := any(base.store).(ports.TicketStatusProgressStore)
	progress, err := progresses.GetTicketStatusProgress(ctx, "tenant-a", m.ID, "eng-a", "finding-a")
	if err != nil || progress.Episode != 3 || progress.AppliedState != domain.SyncReopen {
		t.Fatalf("progress=%+v err=%v", progress, err)
	}
}

func TestWorkflowStatusSyncFairlyAdvancesPastUnconfiguredTargetsAtFrozenClock(t *testing.T) {
	f := newWorkflowFixture(t)
	f.workflow.SetSLAStore(memory.NewSLAStore())
	ctx := context.Background()
	m, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: "security-1", SummaryTemplate: "Title: {{.title}}", DescriptionTemplate: "Description: {{.title}}", StatusTransitions: map[domain.SyncState]string{domain.SyncRemediated: "123"}, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 11; n++ {
		id := shared.ID(fmt.Sprintf("fairness-finding-%02d", n))
		item, e := finding.NewManual(id, "eng-a", finding.ManualInput{Title: id.String(), Severity: shared.SeverityHigh}, f.clock.Now())
		if e != nil {
			t.Fatal(e)
		}
		if e = f.findings.Upsert(shared.WithTenant(ctx, "tenant-a"), []finding.Finding{item}); e != nil {
			t.Fatal(e)
		}
		preview, e := f.workflow.Preview(ctx, usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, EngagementID: "eng-a", FindingID: id})
		if e != nil {
			t.Fatal(e)
		}
		if _, created, e := f.workflow.Submit(ctx, usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, EngagementID: "eng-a", FindingID: id, RequestKey: "fairness-" + id.String(), PreviewDigest: preview.Digest, Actor: "admin"}); e != nil || !created {
			t.Fatalf("submit %s created=%t err=%v", id, created, e)
		}
	}
	for n := 0; n < 3; n++ {
		if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
			t.Fatal(err)
		}
	}
	progresses := any(f.store).(ports.TicketStatusProgressStore)
	if _, err = progresses.GetTicketStatusProgress(ctx, "tenant-a", m.ID, "eng-a", "fairness-finding-10"); err != nil {
		t.Fatalf("unvisited target starved behind frozen-clock targets: %v", err)
	}
}

func TestWorkflowStatusSyncRefusesRetargetedMapping(t *testing.T) {
	f := newWorkflowFixture(t)
	f.workflow.SetSLAStore(memory.NewSLAStore())
	ctx := context.Background()
	m, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: "security-1", SummaryTemplate: "Title: {{.title}}", DescriptionTemplate: "Description: {{.title}}", StatusTransitions: map[domain.SyncState]string{domain.SyncRemediated: "123"}, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.workflow.Preview(ctx, usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := f.workflow.Submit(ctx, usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "retarget-origin", PreviewDigest: p.Digest, Actor: "admin"}); err != nil || !created {
		t.Fatalf("origin created=%t err=%v", created, err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	m.ProjectKey = "OPS"
	if _, err = f.store.UpdateMapping(ctx, "tenant-a", m, m.Version); err != nil {
		t.Fatal(err)
	}
	item, err := f.findings.GetByEngagementAndID(shared.WithTenant(ctx, "tenant-a"), "eng-a", "finding-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.findings.UpdateStatus(shared.WithTenant(ctx, "tenant-a"), "eng-a", "finding-a", finding.StatusRemediated, item.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	if f.provider.transitions != 0 {
		t.Fatalf("retargeted mapping sent %d transitions", f.provider.transitions)
	}
}

func TestWorkflowStatusSyncUsesCurrentCredentialRevision(t *testing.T) {
	f := newWorkflowFixture(t)
	f.workflow.SetSLAStore(memory.NewSLAStore())
	ctx := context.Background()
	m, err := f.workflow.SaveMapping(ctx, "tenant-a", "", usecase.MappingInput{IntegrationID: "jira", Scope: domain.Engagement, ScopeID: "eng-a", ProjectKey: "SEC", IssueType: "10001", Labels: []string{"synapse"}, SecurityLevel: "security-1", SummaryTemplate: "Title: {{.title}}", DescriptionTemplate: "Description: {{.title}}", StatusTransitions: map[domain.SyncState]string{domain.SyncRemediated: "123"}, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.workflow.Preview(ctx, usecase.PreviewRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := f.workflow.Submit(ctx, usecase.SubmitRequest{TenantID: "tenant-a", MappingID: m.ID, FindingID: "finding-a", EngagementID: "eng-a", RequestKey: "credential-origin", PreviewDigest: p.Digest, Actor: "admin"}); err != nil || !created {
		t.Fatalf("origin created=%t err=%v", created, err)
	}
	if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
		t.Fatal(err)
	}
	f.integrations.item.ConnectionRevision++
	f.integrations.item.CredentialRevision++
	item, err := f.findings.GetByEngagementAndID(shared.WithTenant(ctx, "tenant-a"), "eng-a", "finding-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.findings.UpdateStatus(shared.WithTenant(ctx, "tenant-a"), "eng-a", "finding-a", finding.StatusRemediated, item.Version); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err = f.workflow.Tick(ctx, "tenant-a", 10); err != nil {
			t.Fatal(err)
		}
	}
	if f.provider.transitions != 1 || f.provider.updates != 1 {
		t.Fatalf("transitions=%d updates=%d", f.provider.transitions, f.provider.updates)
	}
}
