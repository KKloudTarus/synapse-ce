package ticketing

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type webhookSealer interface {
	Seal([]byte, []byte) (string, error)
}

// WebhookAdmin enables signed delivery only after current Jira capabilities and
// the integration principal have been verified outside the local transaction.
type WebhookAdmin struct {
	workflow      *Workflow
	store         ports.InboundWebhookAdminStore
	configuration ports.TicketInboundConfigurationStore
	sealer        webhookSealer
	transactions  ports.TenantTransactionRunner
}

type WebhookConfiguration struct {
	Path                    string     `json:"path"`
	Version                 int        `json:"version"`
	Rotated                 bool       `json:"rotated"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at,omitempty"`
}

func NewWebhookAdmin(w *Workflow, store ports.InboundWebhookAdminStore, configuration ports.TicketInboundConfigurationStore, sealer webhookSealer, transactions ports.TenantTransactionRunner) (*WebhookAdmin, error) {
	if w == nil || store == nil || configuration == nil || sealer == nil || transactions == nil {
		return nil, fmt.Errorf("%w: Jira webhook dependencies required", shared.ErrValidation)
	}
	return &WebhookAdmin{w, store, configuration, sealer, transactions}, nil
}

func (s *WebhookAdmin) ConfigureInboundWebhook(ctx context.Context, tenant, integrationID shared.ID, actor, secret string) (out WebhookConfiguration, err error) {
	if tenant.IsZero() || integrationID.IsZero() || strings.TrimSpace(actor) == "" || len(secret) < 32 || len(secret) > 128 || strings.TrimSpace(secret) != secret {
		return out, fmt.Errorf("%w: Jira webhook identity and 32-128 byte secret required", shared.ErrValidation)
	}
	item, err := s.workflow.integration(ctx, tenant, integrationID)
	if err != nil {
		return out, err
	}
	if !item.Enabled {
		return out, shared.ErrConflict
	}
	provider, err := s.workflow.providers.TicketProvider(ctx, item)
	if err != nil {
		return out, safeTicketError(err)
	}
	defer closeTicketProvider(provider)
	capability, ok := provider.(ports.TicketWebhookCapability)
	if !ok {
		return out, fmt.Errorf("%w: signed Jira webhooks unsupported", shared.ErrConflict)
	}
	principal, err := capability.TicketWebhookPrincipal(ctx)
	if err != nil {
		return out, safeTicketError(err)
	}
	if strings.TrimSpace(principal) == "" || len(principal) > 255 {
		return out, shared.ErrValidation
	}
	err = s.transactions.Run(ctx, tenant, func(txCtx context.Context) error {
		current, e := s.workflow.integration(txCtx, tenant, integrationID)
		if e != nil {
			return e
		}
		if current.ConnectionRevision != item.ConnectionRevision || current.CredentialRevision != item.CredentialRevision {
			return shared.ErrConflict
		}
		config, e := s.configuration.GetTicketInboundConfiguration(txCtx, tenant, integrationID)
		if e != nil && !errors.Is(e, shared.ErrNotFound) {
			return e
		}
		version := config.Version
		now := s.workflow.clock.Now().UTC()
		_, e = s.configuration.SaveTicketInboundConfiguration(txCtx, tenant, ports.TicketInboundConfiguration{TenantID: tenant, IntegrationID: integrationID, Enabled: true, IntegrationAuthor: principal, ConnectionRevision: item.ConnectionRevision, CredentialRevision: item.CredentialRevision, UpdatedAt: now}, version)
		if e != nil {
			return e
		}
		existing, found, e := s.store.GetInboundWebhookForOwner(txCtx, tenant, "integration", integrationID.String())
		if e != nil {
			return e
		}
		action := "ticket.webhook.provisioned"
		if !found {
			raw := make([]byte, 32)
			if _, e = rand.Read(raw); e != nil {
				return fmt.Errorf("generate webhook ID: %w", e)
			}
			publicID := base64.RawURLEncoding.EncodeToString(raw)
			sealed, e := s.sealer.Seal([]byte(secret), ports.InboundWebhookAAD(tenant, publicID, "integration", integrationID.String(), 1))
			if e != nil {
				return fmt.Errorf("seal Jira webhook secret: %w", e)
			}
			created, e := s.store.ProvisionInboundWebhook(txCtx, ports.InboundWebhookEndpoint{PublicID: publicID, TenantID: tenant, OwnerKind: "integration", OwnerID: integrationID.String(), Provider: string(item.Provider), CurrentVersion: 1, CurrentSealed: sealed, Enabled: true, RatePerMinute: 60})
			if e != nil {
				return e
			}
			if !created {
				return shared.ErrConflict
			}
			out = WebhookConfiguration{Path: "/api/v1/hooks/" + publicID, Version: 1}
		} else {
			if existing.Provider != string(item.Provider) || existing.RevokedAt != nil || existing.CurrentVersion < 1 {
				return shared.ErrConflict
			}
			next := existing.CurrentVersion + 1
			expires := now.Add(2 * time.Hour)
			sealed, e := s.sealer.Seal([]byte(secret), ports.InboundWebhookAAD(tenant, existing.PublicID, "integration", integrationID.String(), next))
			if e != nil {
				return fmt.Errorf("seal Jira webhook secret: %w", e)
			}
			rotated, e := s.store.RotateInboundWebhook(txCtx, ports.InboundWebhookIdentity{PublicID: existing.PublicID, TenantID: tenant, OwnerKind: "integration", OwnerID: integrationID.String()}, existing.CurrentVersion, sealed, expires)
			if e != nil {
				return e
			}
			if !rotated {
				return shared.ErrConflict
			}
			out = WebhookConfiguration{Path: "/api/v1/hooks/" + existing.PublicID, Version: next, Rotated: true, PreviousSecretExpiresAt: &expires}
			action = "ticket.webhook.rotated"
		}
		return s.workflow.audit.Record(txCtx, ports.AuditEntry{Actor: actor, Action: action, Target: integrationID.String(), At: now, Metadata: map[string]string{"version": fmt.Sprint(out.Version)}})
	})
	if err != nil {
		return WebhookConfiguration{}, err
	}
	return out, nil
}
