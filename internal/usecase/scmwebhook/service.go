package scmwebhook

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

const githubWebhookActor = "system:github-webhook"

var (
	githubCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	githubRefPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
)

type integrationReader interface {
	Get(context.Context, shared.ID, shared.ID) (integration.Integration, error)
	ListBindings(context.Context, shared.ID, shared.ID) ([]integration.Binding, error)
}

type projectScanStarter interface {
	StartWebhookAnalysis(context.Context, string, shared.ID, shared.ID, projectuc.WebhookAnalysisInput) (ports.ScanJob, error)
}

type webhookSealer interface {
	Seal([]byte, []byte) (string, error)
}

// Service turns an authenticated provider event into a scan of one already
// configured Project. Repository identity never comes from provider JSON.
type Service struct {
	integrations integrationReader
	projects     projectScanStarter
	admin        ports.InboundWebhookAdminStore
	sealer       webhookSealer
	audit        ports.AuditLogger
	clock        ports.Clock
	transactions ports.TenantTransactionRunner
}

func NewService(integrations integrationReader, projects projectScanStarter) *Service {
	return &Service{integrations: integrations, projects: projects}
}

// SetAdmin wires the tenant-authorized endpoint lifecycle. It is kept separate
// from NewService so receiver-only unit tests stay small, while production
// requires every dependency before exposing the management route.
func (s *Service) SetAdmin(store ports.InboundWebhookAdminStore, sealer webhookSealer, audit ports.AuditLogger, clock ports.Clock, transactions ports.TenantTransactionRunner) error {
	if s == nil || store == nil || sealer == nil || audit == nil || clock == nil || transactions == nil {
		return fmt.Errorf("%w: inbound webhook admin dependencies are required", shared.ErrValidation)
	}
	s.admin, s.sealer, s.audit, s.clock, s.transactions = store, sealer, audit, clock, transactions
	return nil
}

type GitHubWebhookConfiguration struct {
	Path                    string     `json:"path"`
	Version                 int        `json:"version"`
	Rotated                 bool       `json:"rotated"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at,omitempty"`
}

func randomWebhookPublicID(bytes int) (string, error) {
	if bytes < 32 {
		return "", fmt.Errorf("%w: webhook public ID random size is too small", shared.ErrValidation)
	}
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate webhook public ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ConfigureInboundWebhook configures only registered inbound SCM providers.
func (s *Service) ConfigureInboundWebhook(ctx context.Context, tenantID, integrationID shared.ID, actor, secret string) (GitHubWebhookConfiguration, error) {
	if s == nil || s.integrations == nil {
		return GitHubWebhookConfiguration{}, fmt.Errorf("%w: webhook administration is not configured", shared.ErrValidation)
	}
	item, err := s.integrations.Get(ctx, tenantID, integrationID)
	if err != nil {
		return GitHubWebhookConfiguration{}, err
	}
	if item.Provider != "github" && item.Provider != "bitbucket" {
		return GitHubWebhookConfiguration{}, fmt.Errorf("%w: integration does not support inbound webhook administration", shared.ErrValidation)
	}
	return s.configureWebhook(ctx, tenantID, integrationID, actor, secret, string(item.Provider))
}

func (s *Service) configureWebhook(ctx context.Context, tenantID, integrationID shared.ID, actor, secret, provider string) (GitHubWebhookConfiguration, error) {
	if s == nil || s.admin == nil || s.sealer == nil || s.audit == nil || s.clock == nil || s.transactions == nil {
		return GitHubWebhookConfiguration{}, fmt.Errorf("%w: inbound webhook administration is not configured", shared.ErrValidation)
	}
	if tenantID.IsZero() || integrationID.IsZero() || strings.TrimSpace(actor) == "" {
		return GitHubWebhookConfiguration{}, fmt.Errorf("%w: webhook administration identity is required", shared.ErrValidation)
	}
	if len(secret) < 32 || len(secret) > 128 || strings.TrimSpace(secret) != secret {
		return GitHubWebhookConfiguration{}, fmt.Errorf("%w: SCM webhook secret must be 32-128 non-whitespace-trimmed bytes", shared.ErrValidation)
	}
	item, err := s.integrations.Get(ctx, tenantID, integrationID)
	if err != nil {
		return GitHubWebhookConfiguration{}, err
	}
	if item.Provider != integration.Provider(provider) || item.Archived {
		return GitHubWebhookConfiguration{}, fmt.Errorf("%w: integration is not an eligible SCM integration", shared.ErrValidation)
	}
	bindings, err := s.integrations.ListBindings(ctx, tenantID, integrationID)
	if err != nil {
		return GitHubWebhookConfiguration{}, err
	}
	if len(bindings) != 1 || bindings[0].ProjectID.IsZero() {
		return GitHubWebhookConfiguration{}, fmt.Errorf("%w: bind exactly one Project before configuring the SCM webhook", shared.ErrConflict)
	}

	var result GitHubWebhookConfiguration
	err = s.transactions.Run(ctx, tenantID, func(txCtx context.Context) error {
		existing, found, err := s.admin.GetInboundWebhookForOwner(txCtx, tenantID, "integration", integrationID.String())
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		action := "integration." + provider + "_webhook_provisioned"
		if !found {
			publicID, err := randomWebhookPublicID(32)
			if err != nil {
				return err
			}
			sealed, err := s.sealer.Seal([]byte(secret), ports.InboundWebhookAAD(tenantID, publicID, "integration", integrationID.String(), 1))
			if err != nil {
				return fmt.Errorf("seal SCM webhook secret: %w", err)
			}
			created, err := s.admin.ProvisionInboundWebhook(txCtx, ports.InboundWebhookEndpoint{
				PublicID: publicID, TenantID: tenantID, OwnerKind: "integration", OwnerID: integrationID.String(),
				Provider: provider, CurrentVersion: 1, CurrentSealed: sealed, Enabled: true, RatePerMinute: 60,
			})
			if err != nil {
				return err
			}
			if !created {
				return fmt.Errorf("%w: SCM webhook endpoint already exists", shared.ErrConflict)
			}
			result = GitHubWebhookConfiguration{Path: "/api/v1/hooks/" + publicID, Version: 1}
		} else {
			if existing.Provider != provider || existing.RevokedAt != nil || existing.CurrentVersion < 1 {
				return fmt.Errorf("%w: SCM webhook endpoint cannot be rotated", shared.ErrConflict)
			}
			nextVersion := existing.CurrentVersion + 1
			sealed, err := s.sealer.Seal([]byte(secret), ports.InboundWebhookAAD(tenantID, existing.PublicID, "integration", integrationID.String(), nextVersion))
			if err != nil {
				return fmt.Errorf("seal rotated SCM webhook secret: %w", err)
			}
			// Leave a small clock-skew margin below the hard 24-hour database cap.
			expires := now.Add(23*time.Hour + 59*time.Minute)
			rotated, err := s.admin.RotateInboundWebhook(txCtx, ports.InboundWebhookIdentity{
				PublicID: existing.PublicID, TenantID: tenantID, OwnerKind: "integration", OwnerID: integrationID.String(),
			}, existing.CurrentVersion, sealed, expires)
			if err != nil {
				return err
			}
			if !rotated {
				return fmt.Errorf("%w: SCM webhook endpoint changed concurrently", shared.ErrConflict)
			}
			action = "integration." + provider + "_webhook_rotated"
			result = GitHubWebhookConfiguration{
				Path:    "/api/v1/hooks/" + existing.PublicID,
				Version: nextVersion, Rotated: true, PreviousSecretExpiresAt: &expires,
			}
		}
		return s.audit.Record(txCtx, ports.AuditEntry{
			Actor: strings.TrimSpace(actor), Action: action, Target: integrationID.String(), At: now,
			Metadata: map[string]string{"provider": provider, "webhook_version": fmt.Sprintf("%d", result.Version)},
		})
	})
	if err != nil {
		return GitHubWebhookConfiguration{}, err
	}
	return result, nil
}

func (s *Service) ReceiveInboundWebhook(ctx context.Context, identity ports.InboundWebhookIdentity, event ports.InboundWebhookEvent) error {
	if s == nil || s.integrations == nil || s.projects == nil {
		return fmt.Errorf("%w: SCM webhook receiver is not configured", shared.ErrValidation)
	}
	if identity.OwnerKind != "integration" || identity.OwnerID == "" || identity.TenantID.IsZero() {
		return fmt.Errorf("%w: invalid webhook owner", shared.ErrValidation)
	}
	if event.Provider != "github" {
		return fmt.Errorf("%w: unsupported SCM webhook provider", shared.ErrValidation)
	}
	item, err := s.integrations.Get(ctx, identity.TenantID, shared.ID(identity.OwnerID))
	if err != nil {
		return err
	}
	if item.Provider != integration.Provider("github") || !item.Enabled || item.Archived {
		return fmt.Errorf("%w: GitHub integration is not active", shared.ErrValidation)
	}
	bindings, err := s.integrations.ListBindings(ctx, identity.TenantID, item.ID)
	if err != nil {
		return err
	}
	if len(bindings) != 1 || bindings[0].ProjectID.IsZero() {
		return fmt.Errorf("%w: GitHub inbound integration must bind exactly one project", shared.ErrValidation)
	}

	ref, commit, fork, scan, err := githubScanTarget(event)
	if err != nil {
		return err
	}
	if !scan {
		return nil
	}
	_, err = s.projects.StartWebhookAnalysis(ctx, githubWebhookActor, identity.TenantID, bindings[0].ProjectID, projectuc.WebhookAnalysisInput{
		Ref: ref, Commit: commit, PullRequest: event.EventType == "pull_request",
		DisableGitCredentials: fork,
		NoBuildExecution:      fork,
	})
	return err
}

func githubScanTarget(event ports.InboundWebhookEvent) (ref, commit string, fork, scan bool, err error) {
	if event.Provider != "github" {
		return "", "", false, false, fmt.Errorf("%w: unsupported SCM webhook provider", shared.ErrValidation)
	}
	switch event.EventType {
	case "push", "pull_request":
		ref = strings.TrimSpace(event.Ref)
		commit = strings.TrimSpace(event.SHA)
		fork = event.EventType == "pull_request" && event.Fork
	default:
		return "", "", false, false, nil
	}
	if !githubRefPattern.MatchString(ref) || !githubCommitPattern.MatchString(commit) {
		return "", "", false, false, fmt.Errorf("%w: invalid GitHub webhook ref or commit", shared.ErrValidation)
	}
	return ref, commit, fork, true, nil
}
