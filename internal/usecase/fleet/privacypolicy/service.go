// Package privacypolicy manages immutable tenant source-redaction policy history
// and the independently mutable active assignment delivered to fleet agents.
package privacypolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service is the application boundary for tenant privacy-policy governance.
type Service struct {
	store ports.PrivacyPolicyAuditStore
	audit ports.IdempotentAuditLogger
	clock ports.Clock
}

// NewService constructs the tenant privacy-policy service.
func NewService(store ports.PrivacyPolicyAuditStore, audit ports.IdempotentAuditLogger, clock ports.Clock) (*Service, error) {
	if store == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: privacy policy service needs a store, audit log and clock", shared.ErrValidation)
	}
	return &Service{store: store, audit: audit, clock: clock}, nil
}

// Admit appends an immutable policy assignment without changing the active pointer.
func (s *Service) Admit(ctx context.Context, actor string, policy privacy.Policy) (privacy.Assignment, bool, error) {
	tenantID, err := tenantFrom(ctx)
	if err != nil {
		return privacy.Assignment{}, false, err
	}
	actor = strings.TrimSpace(actor)
	assignment, err := privacy.NewAssignment(tenantID, policy, actor, s.clock.Now().UTC())
	if err != nil {
		return privacy.Assignment{}, false, err
	}
	created, err := s.store.PutPrivacyPolicy(ctx, assignment)
	if err != nil {
		return privacy.Assignment{}, false, fmt.Errorf("put privacy policy: %w", err)
	}
	if err := s.audit.RecordOnce(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "fleet.privacy_policy.admit",
		Target: assignment.Policy.Version,
		At:     assignment.CreatedAt,
		Metadata: map[string]string{
			"idempotency_key": "fleet.privacy_policy.admit:" + tenantID.String() + ":" + assignment.Digest,
			"digest":          assignment.Digest,
			"created":         fmt.Sprintf("%t", created),
		},
	}); err != nil {
		return privacy.Assignment{}, false, fmt.Errorf("audit privacy policy admission: %w", err)
	}
	stored, err := s.store.PrivacyPolicyByDigest(ctx, tenantID, assignment.Digest)
	if err != nil {
		return privacy.Assignment{}, false, fmt.Errorf("reload privacy policy: %w", err)
	}
	return stored, created, nil
}

// Activate changes only the active pointer to an existing immutable policy digest.
func (s *Service) Activate(ctx context.Context, actor, digest string, operationID shared.ID) (privacy.Assignment, error) {
	tenantID, err := tenantFrom(ctx)
	if err != nil {
		return privacy.Assignment{}, err
	}
	actor = strings.TrimSpace(actor)
	digest = strings.TrimSpace(digest)
	if actor == "" || digest == "" || operationID.IsZero() {
		return privacy.Assignment{}, fmt.Errorf("%w: privacy policy actor, digest and activation operation id are required", shared.ErrValidation)
	}
	assignment, err := s.store.PrivacyPolicyByDigest(ctx, tenantID, digest)
	if err != nil {
		return privacy.Assignment{}, fmt.Errorf("resolve privacy policy for activation: %w", err)
	}
	activatedAt := s.clock.Now().UTC()
	intentID := "fleet.privacy_policy.activate:" + tenantID.String() + ":" + operationID.String()
	intent := ports.FleetAuditIntent{
		ID: intentID,
		Entry: ports.AuditEntry{
			Actor:  actor,
			Action: "fleet.privacy_policy.activate",
			Target: assignment.Policy.Version,
			At:     activatedAt,
			Metadata: map[string]string{
				"idempotency_key": intentID,
				"operation_id":    operationID.String(),
				"digest":          assignment.Digest,
			},
		},
	}
	_, committed, err := s.store.ActivatePrivacyPolicyWithAudit(ctx, privacy.Activation{
		TenantID: tenantID, OperationID: operationID, PolicyDigest: assignment.Digest,
		PolicyVersion: assignment.Policy.Version, ActivatedBy: actor, ActivatedAt: activatedAt,
	}, intent)
	if err != nil {
		return privacy.Assignment{}, fmt.Errorf("activate privacy policy: %w", err)
	}
	// Deliver the payload that actually became durable, never a locally re-derived one:
	// a restart-time reconciler reads the committed row, so re-deriving here would risk
	// two different chain entries for one obligation.
	if err := s.audit.RecordOnce(ctx, committed.Entry); err != nil {
		return privacy.Assignment{}, fmt.Errorf("audit privacy policy activation: %w", err)
	}
	if err := s.store.AcknowledgeFleetAudit(ctx, committed.ID); err != nil {
		return privacy.Assignment{}, fmt.Errorf("acknowledge privacy policy activation audit: %w", err)
	}
	return assignment, nil
}

// Active returns the tenant's active assignment.
func (s *Service) Active(ctx context.Context) (privacy.Assignment, error) {
	tenantID, err := tenantFrom(ctx)
	if err != nil {
		return privacy.Assignment{}, err
	}
	assignment, err := s.store.ActivePrivacyPolicy(ctx, tenantID)
	if err != nil {
		return privacy.Assignment{}, fmt.Errorf("read active privacy policy: %w", err)
	}
	return assignment, nil
}

// History returns immutable assignments newest-first.
func (s *Service) History(ctx context.Context) ([]privacy.Assignment, error) {
	tenantID, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	assignments, err := s.store.PrivacyPolicyHistory(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read privacy policy history: %w", err)
	}
	return assignments, nil
}

func tenantFrom(ctx context.Context) (shared.ID, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return "", fmt.Errorf("%w: privacy policy operation requires tenant context", shared.ErrForbidden)
	}
	return tenantID, nil
}
