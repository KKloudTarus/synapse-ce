package ticketing_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usecase "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type jiraAdminTransaction struct {
	inside bool
	calls  int
}

func (r *jiraAdminTransaction) Run(ctx context.Context, _ shared.ID, fn func(context.Context) error) error {
	r.inside = true
	r.calls++
	defer func() { r.inside = false }()
	return fn(ctx)
}

type jiraAdminProvider struct {
	*workflowProvider
	runner *jiraAdminTransaction
	err    error
	t      *testing.T
}

func (p *jiraAdminProvider) TicketWebhookPrincipal(context.Context) (string, error) {
	if p.runner.inside {
		p.t.Fatal("remote identity lookup inside database transaction")
	}
	return "verified-principal", p.err
}

type jiraAdminHookStore struct {
	endpoint             ports.InboundWebhookEndpoint
	provisioned, rotated int
}

func (s *jiraAdminHookStore) GetInboundWebhookForOwner(_ context.Context, tenant shared.ID, kind, owner string) (ports.InboundWebhookEndpoint, bool, error) {
	return s.endpoint, s.endpoint.TenantID == tenant && s.endpoint.OwnerKind == kind && s.endpoint.OwnerID == owner, nil
}
func (s *jiraAdminHookStore) ProvisionInboundWebhook(_ context.Context, e ports.InboundWebhookEndpoint) (bool, error) {
	s.endpoint = e
	s.provisioned++
	return true, nil
}
func (s *jiraAdminHookStore) RotateInboundWebhook(_ context.Context, id ports.InboundWebhookIdentity, version int, sealed string, expires time.Time) (bool, error) {
	if s.endpoint.PublicID != id.PublicID || s.endpoint.CurrentVersion != version {
		return false, nil
	}
	s.endpoint.PreviousSealed = s.endpoint.CurrentSealed
	s.endpoint.CurrentSealed = sealed
	s.endpoint.CurrentVersion++
	s.endpoint.PreviousExpiresAt = expires
	s.rotated++
	return true, nil
}

func TestJiraWebhookAdminCapturesPrincipalAndSealsRotatingSecrets(t *testing.T) {
	f := newWorkflowFixture(t)
	ctx := context.Background()
	runner := &jiraAdminTransaction{}
	provider := &jiraAdminProvider{workflowProvider: f.provider, runner: runner, t: t}
	w, err := usecase.NewWorkflow(f.store, f.integrations, workflowProviders{provider}, f.findings, f.engagements, f.policy, f.audit, &ticketIDs{}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := vault.NewCipher([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	hooks := &jiraAdminHookStore{}
	admin, err := usecase.NewWebhookAdmin(w, hooks, f.store, cipher, runner)
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("first-secret-", 3)
	out, err := admin.ConfigureInboundWebhook(ctx, "tenant-a", "jira", "human-admin", secret)
	if err != nil || out.Rotated || out.Version != 1 || hooks.provisioned != 1 {
		t.Fatalf("configuration=%+v err=%v", out, err)
	}
	config, err := f.store.GetTicketInboundConfiguration(ctx, "tenant-a", "jira")
	if err != nil || config.IntegrationAuthor != "verified-principal" || config.ConnectionRevision != 1 || config.CredentialRevision != 1 || !config.Enabled {
		t.Fatalf("config=%+v err=%v", config, err)
	}
	plain, err := cipher.Open(hooks.endpoint.CurrentSealed, ports.InboundWebhookAAD("tenant-a", hooks.endpoint.PublicID, "integration", "jira", 1))
	if err != nil || string(plain) != secret {
		t.Fatal("secret not bound to endpoint authority")
	}
	if _, err = cipher.Open(hooks.endpoint.CurrentSealed, ports.InboundWebhookAAD("tenant-b", hooks.endpoint.PublicID, "integration", "jira", 1)); err == nil {
		t.Fatal("sealed secret moved to another tenant")
	}
	second := strings.Repeat("second-secret-", 3)
	rotated, err := admin.ConfigureInboundWebhook(ctx, "tenant-a", "jira", "human-admin", second)
	if err != nil || !rotated.Rotated || rotated.Version != 2 || hooks.rotated != 1 || rotated.Path != out.Path || rotated.PreviousSecretExpiresAt == nil {
		t.Fatalf("rotation=%+v err=%v", rotated, err)
	}
	raw, _ := json.Marshal(f.audit.entries)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), second) || strings.Contains(string(raw), hooks.endpoint.CurrentSealed) {
		t.Fatal("credential leaked to audit")
	}
	provider.err = errors.New("capability unavailable")
	if _, err = admin.ConfigureInboundWebhook(ctx, "tenant-a", "jira", "human-admin", second); err == nil || runner.calls != 2 {
		t.Fatal("unsupported provider admitted local credential mutation")
	}
}
