package scmwebhook

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type fakeIntegrations struct {
	item     integration.Integration
	bindings []integration.Binding
	err      error
}

func (f *fakeIntegrations) Get(context.Context, shared.ID, shared.ID) (integration.Integration, error) {
	return f.item, f.err
}
func (f *fakeIntegrations) ListBindings(context.Context, shared.ID, shared.ID) ([]integration.Binding, error) {
	return append([]integration.Binding(nil), f.bindings...), f.err
}

type capturedWebhookScan struct {
	tenant  shared.ID
	project shared.ID
	input   projectuc.WebhookAnalysisInput
}
type fakeProjectScans struct {
	calls []capturedWebhookScan
	err   error
}

func (f *fakeProjectScans) StartWebhookAnalysis(_ context.Context, _ string, tenant, project shared.ID, in projectuc.WebhookAnalysisInput) (ports.ScanJob, error) {
	f.calls = append(f.calls, capturedWebhookScan{tenant: tenant, project: project, input: in})
	return ports.ScanJob{ID: "job"}, f.err
}

func webhookFixture() (*Service, *fakeProjectScans, ports.InboundWebhookIdentity) {
	integrations := &fakeIntegrations{
		item:     integration.Integration{ID: "integration-1", TenantID: "tenant-1", Provider: "github", Enabled: true},
		bindings: []integration.Binding{{ID: "binding-1", TenantID: "tenant-1", IntegrationID: "integration-1", ProjectID: "project-1"}},
	}
	scans := &fakeProjectScans{}
	return NewService(integrations, scans), scans, ports.InboundWebhookIdentity{
		PublicID: "hook", TenantID: "tenant-1", OwnerKind: "integration", OwnerID: "integration-1",
	}
}

func TestGitHubPushUsesOnlyStoredProjectBindingAndPinsCommit(t *testing.T) {
	svc, scans, identity := webhookFixture()
	sha := "0123456789abcdef0123456789abcdef01234567"
	body := []byte(`{"repository":{"clone_url":"https://evil.invalid/attacker/repo.git"}}`)
	err := svc.ReceiveInboundWebhook(context.Background(), identity, ports.InboundWebhookEvent{Provider: "github", EventType: "push", EventID: "d1", Ref: "main", SHA: sha, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 1 {
		t.Fatalf("scan calls=%d, want 1", len(scans.calls))
	}
	got := scans.calls[0]
	if got.tenant != "tenant-1" || got.project != "project-1" || got.input.Ref != "main" || got.input.Commit != sha {
		t.Fatalf("scan target=%+v", got)
	}
	if got.input.PullRequest || got.input.DisableGitCredentials || got.input.NoBuildExecution {
		t.Fatal("ordinary push unexpectedly used pull-request/fork restrictions")
	}
}

func TestGitHubForkPullRequestDisablesCredentialsAndBuildExecution(t *testing.T) {
	svc, scans, identity := webhookFixture()
	sha := "abcdef0123456789abcdef0123456789abcdef01"
	body := []byte(`{"repository":{"clone_url":"https://evil.invalid/fork.git"}}`)
	err := svc.ReceiveInboundWebhook(context.Background(), identity, ports.InboundWebhookEvent{Provider: "github", EventType: "pull_request", EventID: "d2", Ref: "contrib/fix", SHA: sha, Fork: true, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 1 {
		t.Fatalf("scan calls=%d, want 1", len(scans.calls))
	}
	got := scans.calls[0].input
	if got.Ref != "contrib/fix" || got.Commit != sha || !got.PullRequest || !got.DisableGitCredentials || !got.NoBuildExecution {
		t.Fatalf("fork scan=%+v", got)
	}
}

func TestGitHubWebhookRejectsInvalidSHAAndAmbiguousBinding(t *testing.T) {
	svc, scans, identity := webhookFixture()
	err := svc.ReceiveInboundWebhook(context.Background(), identity, ports.InboundWebhookEvent{
		Provider: "github", EventType: "push", EventID: "d3", Ref: "main", SHA: "ABCDEF",
	})
	if !errors.Is(err, shared.ErrValidation) || len(scans.calls) != 0 {
		t.Fatalf("invalid sha err=%v calls=%d", err, len(scans.calls))
	}
	upperSHA := strings.Repeat("A", 40)
	err = svc.ReceiveInboundWebhook(context.Background(), identity, ports.InboundWebhookEvent{
		Provider: "github", EventType: "push", EventID: "d3-upper", Ref: "main", SHA: upperSHA,
	})
	if !errors.Is(err, shared.ErrValidation) || len(scans.calls) != 0 {
		t.Fatalf("uppercase sha err=%v calls=%d", err, len(scans.calls))
	}
	f := svc.integrations.(*fakeIntegrations)
	f.bindings = append(f.bindings, integration.Binding{ID: "binding-2", TenantID: "tenant-1", IntegrationID: "integration-1", ProjectID: "project-2"})
	err = svc.ReceiveInboundWebhook(context.Background(), identity, ports.InboundWebhookEvent{
		Provider: "github", EventType: "push", EventID: "d4", Ref: "main", SHA: "0123456789abcdef0123456789abcdef01234567",
	})
	if !errors.Is(err, shared.ErrValidation) || len(scans.calls) != 0 {
		t.Fatalf("ambiguous binding err=%v calls=%d", err, len(scans.calls))
	}
}

func TestGitHubWebhookIgnoresNonScanningEvents(t *testing.T) {
	svc, scans, identity := webhookFixture()
	if err := svc.ReceiveInboundWebhook(context.Background(), identity, ports.InboundWebhookEvent{Provider: "github", EventType: "issues", EventID: "d5", Body: []byte(`{"action":"opened"}`)}); err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 0 {
		t.Fatalf("unexpected scans=%d", len(scans.calls))
	}
}

type fakeWebhookAdmin struct {
	endpoint *ports.InboundWebhookEndpoint
}

func (f *fakeWebhookAdmin) GetInboundWebhookForOwner(_ context.Context, tenant shared.ID, ownerKind, ownerID string) (ports.InboundWebhookEndpoint, bool, error) {
	if f.endpoint == nil || f.endpoint.TenantID != tenant || f.endpoint.OwnerKind != ownerKind || f.endpoint.OwnerID != ownerID {
		return ports.InboundWebhookEndpoint{}, false, nil
	}
	return *f.endpoint, true, nil
}
func (f *fakeWebhookAdmin) ProvisionInboundWebhook(_ context.Context, endpoint ports.InboundWebhookEndpoint) (bool, error) {
	if f.endpoint != nil {
		return false, nil
	}
	copy := endpoint
	f.endpoint = &copy
	return true, nil
}
func (f *fakeWebhookAdmin) RotateInboundWebhook(_ context.Context, id ports.InboundWebhookIdentity, expected int, sealed string, expires time.Time) (bool, error) {
	if f.endpoint == nil || f.endpoint.PublicID != id.PublicID || f.endpoint.CurrentVersion != expected {
		return false, nil
	}
	f.endpoint.PreviousSealed = f.endpoint.CurrentSealed
	f.endpoint.PreviousExpiresAt = expires
	f.endpoint.CurrentSealed = sealed
	f.endpoint.CurrentVersion++
	return true, nil
}

type fakeWebhookSealer struct {
	plaintext []byte
	aad       []byte
}

func (f *fakeWebhookSealer) Seal(plaintext, aad []byte) (string, error) {
	f.plaintext = append([]byte(nil), plaintext...)
	f.aad = append([]byte(nil), aad...)
	return "sealed-" + string(plaintext), nil
}

type fakeWebhookAudit struct{ entries []ports.AuditEntry }

func (f *fakeWebhookAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	f.entries = append(f.entries, entry)
	return nil
}

type fakeWebhookClock struct{ now time.Time }

func (f fakeWebhookClock) Now() time.Time { return f.now }

type fakeWebhookTx struct{}

func (fakeWebhookTx) Run(ctx context.Context, tenant shared.ID, fn func(context.Context) error) error {
	return fn(shared.WithTenant(ctx, tenant))
}

func TestConfigureGitHubWebhookProvisionsThenRotatesCallerSuppliedSecret(t *testing.T) {
	svc, _, _ := webhookFixture()
	admin := &fakeWebhookAdmin{}
	sealer := &fakeWebhookSealer{}
	audit := &fakeWebhookAudit{}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	if err := svc.SetAdmin(admin, sealer, audit, fakeWebhookClock{now: now}, fakeWebhookTx{}); err != nil {
		t.Fatal(err)
	}

	firstSecret := "github-webhook-secret-000000000001"
	first, err := svc.ConfigureInboundWebhook(context.Background(), "tenant-1", "integration-1", "admin-1", firstSecret)
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 || first.Rotated || !strings.HasPrefix(first.Path, "/api/v1/hooks/") {
		t.Fatalf("first configuration=%+v", first)
	}
	if admin.endpoint == nil || admin.endpoint.PublicID != strings.TrimPrefix(first.Path, "/api/v1/hooks/") ||
		admin.endpoint.CurrentVersion != 1 || admin.endpoint.Provider != "github" {
		t.Fatalf("provisioned endpoint=%+v", admin.endpoint)
	}
	if string(sealer.plaintext) != firstSecret {
		t.Fatal("sealer did not receive the caller-supplied secret")
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "integration.github_webhook_provisioned" {
		t.Fatalf("provision audit=%+v", audit.entries)
	}
	for _, value := range audit.entries[0].Metadata {
		if strings.Contains(value, firstSecret) || strings.Contains(value, admin.endpoint.PublicID) {
			t.Fatal("audit metadata contains webhook credential material")
		}
	}

	secondSecret := "github-webhook-secret-000000000002"
	second, err := svc.ConfigureInboundWebhook(context.Background(), "tenant-1", "integration-1", "admin-1", secondSecret)
	if err != nil {
		t.Fatal(err)
	}
	if second.Version != 2 || !second.Rotated || second.Path != first.Path ||
		second.PreviousSecretExpiresAt == nil || !second.PreviousSecretExpiresAt.After(now) {
		t.Fatalf("rotated configuration=%+v", second)
	}
	if string(sealer.plaintext) != secondSecret {
		t.Fatal("sealer did not receive the rotated caller-supplied secret")
	}
	if admin.endpoint.CurrentVersion != 2 || len(audit.entries) != 2 ||
		audit.entries[1].Action != "integration.github_webhook_rotated" {
		t.Fatalf("rotation endpoint=%+v audit=%+v", admin.endpoint, audit.entries)
	}
}

func TestConfigureGitHubWebhookRejectsInvalidSecretWithoutPersisting(t *testing.T) {
	svc, _, _ := webhookFixture()
	admin := &fakeWebhookAdmin{}
	if err := svc.SetAdmin(admin, &fakeWebhookSealer{}, &fakeWebhookAudit{}, fakeWebhookClock{now: time.Now()}, fakeWebhookTx{}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.ConfigureInboundWebhook(context.Background(), "tenant-1", "integration-1", "admin-1", "too-short")
	if !errors.Is(err, shared.ErrValidation) || admin.endpoint != nil {
		t.Fatalf("invalid secret err=%v endpoint=%+v", err, admin.endpoint)
	}
}

func TestConfigureGitHubWebhookRequiresSingleBoundGitHubProject(t *testing.T) {
	svc, _, _ := webhookFixture()
	fi := svc.integrations.(*fakeIntegrations)
	fi.bindings = nil
	admin := &fakeWebhookAdmin{}
	if err := svc.SetAdmin(admin, &fakeWebhookSealer{}, &fakeWebhookAudit{}, fakeWebhookClock{now: time.Now()}, fakeWebhookTx{}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.ConfigureInboundWebhook(context.Background(), "tenant-1", "integration-1", "admin-1", "github-webhook-secret-000000000001")
	if !errors.Is(err, shared.ErrConflict) || admin.endpoint != nil {
		t.Fatalf("unbound configure err=%v endpoint=%+v", err, admin.endpoint)
	}

	fi.bindings = []integration.Binding{{ProjectID: "project-1"}}
	fi.item.Provider = "jenkins"
	_, err = svc.ConfigureInboundWebhook(context.Background(), "tenant-1", "integration-1", "admin-1", "github-webhook-secret-000000000001")
	if !errors.Is(err, shared.ErrValidation) || admin.endpoint != nil {
		t.Fatalf("wrong-provider configure err=%v endpoint=%+v", err, admin.endpoint)
	}
}
