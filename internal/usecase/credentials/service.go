// Package credentials is the management use case over the credential vault
// (secrets never enter logs): an operator stores per-engagement secrets (write-only) and lists
// or deletes them by NAME. The secret value is never returned, logged, or audited – only
// the SandboxRunner resolves plaintext, at execution time. Every mutation is recorded to
// the append-only audit log WITHOUT the value.
package credentials

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service manages vault credentials (set/list/delete), audited.
type Service struct {
	vault ports.CredentialVault
	audit ports.AuditLogger
	clock ports.Clock
}

// NewService validates its dependencies and returns the service.
func NewService(vault ports.CredentialVault, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if vault == nil {
		return nil, fmt.Errorf("%w: credentials service requires a vault", shared.ErrValidation)
	}
	if audit == nil {
		return nil, fmt.Errorf("%w: credentials service requires an audit logger", shared.ErrValidation)
	}
	if clock == nil {
		return nil, fmt.Errorf("%w: credentials service requires a clock", shared.ErrValidation)
	}
	return &Service{vault: vault, audit: audit, clock: clock}, nil
}

// Set stores (or replaces) a secret under name for an engagement. The value is
// write-only: it is encrypted by the vault and never echoed, logged, or audited.
func (s *Service) Set(ctx context.Context, actor string, engagementID shared.ID, name string, secret []byte) error {
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	if len(secret) == 0 {
		return fmt.Errorf("%w: secret value is required", shared.ErrValidation)
	}
	if err := s.vault.Put(ctx, engagementID, name, secret); err != nil {
		return fmt.Errorf("put credential: %w", err)
	}
	// Audit the fact + the name only – NEVER the value.
	return s.record(ctx, actor, "credential.set", engagementID, name)
}

// List returns the credential names + timestamps for an engagement (no values).
func (s *Service) List(ctx context.Context, engagementID shared.ID) ([]ports.CredentialMeta, error) {
	return s.vault.List(ctx, engagementID)
}

// Delete removes a credential by name. ErrNotFound if it does not exist.
func (s *Service) Delete(ctx context.Context, actor string, engagementID shared.ID, name string) error {
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	if err := s.vault.Delete(ctx, engagementID, name); err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	return s.record(ctx, actor, "credential.deleted", engagementID, name)
}

func (s *Service) record(ctx context.Context, actor, action string, engagementID shared.ID, name string) error {
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    actor,
		Action:   action,
		Target:   engagementID.String(),
		Metadata: map[string]string{"engagement": engagementID.String(), "name": name},
		At:       s.clock.Now(),
	}); err != nil {
		return fmt.Errorf("audit %s: %w", action, err)
	}
	return nil
}
