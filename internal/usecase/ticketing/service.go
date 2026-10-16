// Package ticketing composes the ticket domain with tenant-scoped stores.
// Service provides the provider-independent foundation; Workflow adds Jira delivery.
package ticketing

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Service struct {
	store       ports.TicketStore
	findings    ports.FindingRepository
	engagements ports.EngagementRepository
	ids         ports.IDGenerator
	clock       ports.Clock
}

func NewService(store ports.TicketStore, findings ports.FindingRepository, engagements ports.EngagementRepository, ids ports.IDGenerator, clock ports.Clock) (*Service, error) {
	if store == nil || findings == nil || engagements == nil || ids == nil || clock == nil {
		return nil, fmt.Errorf("%w: ticketing service dependencies are required", shared.ErrValidation)
	}
	return &Service{store: store, findings: findings, engagements: engagements, ids: ids, clock: clock}, nil
}
func (s *Service) CreateMapping(ctx context.Context, tenant, integration, scopeID shared.ID, scope domain.Scope, projectKey, issueType string) (domain.Mapping, error) {
	if tenant.IsZero() {
		return domain.Mapping{}, shared.ErrValidation
	}
	now := s.clock.Now().UTC()
	m := domain.Mapping{ID: s.ids.NewID(), TenantID: tenant, IntegrationID: integration,
		Scope: scope, ScopeID: scopeID, ProjectKey: projectKey, IssueType: issueType,
		Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateMapping(ctx, tenant, m); err != nil {
		return domain.Mapping{}, err
	}
	return m, nil
}

// LinkManual never fetches a caller-supplied URL and needs no integration.
func (s *Service) LinkManual(ctx context.Context, tenant, engagement, finding shared.ID, rawURL string) (domain.Link, bool, error) {
	if tenant.IsZero() {
		return domain.Link{}, false, shared.ErrValidation
	}
	url, err := domain.CanonicalURL(rawURL)
	if err != nil {
		return domain.Link{}, false, err
	}
	link := domain.Link{ID: s.ids.NewID(), TenantID: tenant, EngagementID: engagement,
		FindingID: finding, ExternalURL: url, CreatedAt: s.clock.Now().UTC()}
	return s.store.CreateLink(ctx, tenant, link)
}

// OpenIntent creates a durable command BEFORE any caller sends an external request.
// The marker derives only from a server-issued ID; request-key retries return the original.
// It verifies the finding's engagement and, for a project mapping, the hidden project context.
func (s *Service) OpenIntent(ctx context.Context, tenant, mappingID, findingID, engagementID shared.ID,
	action domain.Action, requestKey, payloadDigest string) (domain.Intent, bool, error) {
	if tenant.IsZero() {
		return domain.Intent{}, false, shared.ErrValidation
	}
	m, err := s.store.GetMapping(ctx, tenant, mappingID)
	if err != nil {
		return domain.Intent{}, false, err
	}
	tenantCtx := shared.WithTenant(ctx, tenant)
	if _, err = s.findings.GetByEngagementAndID(tenantCtx, engagementID, findingID); err != nil {
		return domain.Intent{}, false, err
	}
	switch m.Scope {
	case domain.Engagement:
		if m.ScopeID != engagementID {
			return domain.Intent{}, false, fmt.Errorf("%w: ticket mapping does not belong to finding engagement", shared.ErrValidation)
		}
	case domain.Project:
		projectContext, projectErr := s.engagements.GetByProjectID(tenantCtx, tenant, m.ScopeID)
		if projectErr != nil {
			return domain.Intent{}, false, projectErr
		}
		if projectContext.ID != engagementID {
			return domain.Intent{}, false, fmt.Errorf("%w: ticket project does not own finding engagement", shared.ErrValidation)
		}
	default:
		return domain.Intent{}, false, shared.ErrValidation
	}
	now := s.clock.Now().UTC()
	id := s.ids.NewID()
	i := domain.Intent{ID: id, TenantID: tenant, IntegrationID: m.IntegrationID,
		MappingID: m.ID, FindingID: findingID, EngagementID: engagementID, Action: action,
		RequestKey: requestKey, PayloadDigest: payloadDigest, Marker: "synapse-intent-" + id.String(),
		State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	return s.store.CreateOrGetIntent(ctx, tenant, i)
}

// MoveIntent is an internal-only seam. Callers must prove the relevant provider outcome
// before it invokes ReconcileAbsent/ReconcileFound; the domain never retries uncertain.
func (s *Service) MoveIntent(ctx context.Context, tenant, intent shared.ID, version int,
	change domain.IntentTransition) (domain.Intent, error) {
	return s.store.TransitionIntent(ctx, tenant, intent, version, change, s.clock.Now().UTC())
}
