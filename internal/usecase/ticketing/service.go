// Package ticketing composes the ticket domain with tenant-scoped stores.
// ticketing intentionally adds no API, provider calls, or background job.
package ticketing

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Service struct {
	store ports.TicketStore
	ids   ports.IDGenerator
	clock ports.Clock
}

func NewService(store ports.TicketStore, ids ports.IDGenerator, clock ports.Clock) (*Service, error) {
	if store == nil || ids == nil || clock == nil {
		return nil, fmt.Errorf("%w: ticketing service dependencies are required", shared.ErrValidation)
	}
	return &Service{store: store, ids: ids, clock: clock}, nil
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
// Callers authorize the command and verify project association before using a project mapping.
func (s *Service) OpenIntent(ctx context.Context, tenant, mappingID, findingID, engagementID shared.ID,
	action domain.Action, requestKey, payloadDigest string) (domain.Intent, bool, error) {
	if tenant.IsZero() {
		return domain.Intent{}, false, shared.ErrValidation
	}
	m, err := s.store.GetMapping(ctx, tenant, mappingID)
	if err != nil {
		return domain.Intent{}, false, err
	}
	if m.Scope == domain.Engagement && m.ScopeID != engagementID {
		return domain.Intent{}, false, fmt.Errorf("%w: ticket mapping does not belong to finding engagement", shared.ErrValidation)
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
	event writeintent.Event, lease *time.Time) (domain.Intent, error) {
	return s.store.TransitionIntent(ctx, tenant, intent, version, event, lease, s.clock.Now().UTC())
}
