package memory

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func (s *DocumentStore) ClaimDocumentRestrictionChecks(ctx context.Context, tenant shared.ID, limit int, at time.Time) ([]docpublish.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if bound, ok := shared.TenantFrom(ctx); ok && bound != tenant {
		return nil, shared.ErrForbidden
	}
	if tenant.IsZero() || limit < 1 || limit > docpublish.MaxListLimit || at.IsZero() {
		return nil, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var due []docpublish.Link
	for _, link := range s.links[tenant] {
		if link.RetiredAt == nil && !link.RestrictionNextAt.After(at) {
			due = append(due, link.Clone())
		}
	}
	slices.SortFunc(due, func(a, b docpublish.Link) int {
		if order := a.RestrictionNextAt.Compare(b.RestrictionNextAt); order != 0 {
			return order
		}
		return strings.Compare(a.ID.String(), b.ID.String())
	})
	due = due[:min(limit, len(due))]
	for index := range due {
		due[index].RestrictionNextAt = at.UTC().Add(5 * time.Minute)
		due[index].RestrictionCheckVersion++
		s.links[tenant][due[index].ID] = due[index].Clone()
	}
	return due, nil
}

func (s *DocumentStore) SaveDocumentRestrictionCheck(ctx context.Context, tenant shared.ID, link docpublish.Link, status string, at, next time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if bound, ok := shared.TenantFrom(ctx); ok && bound != tenant {
		return shared.ErrForbidden
	}
	if tenant.IsZero() || link.TenantID != tenant || link.ID.IsZero() || link.Revision < 1 || link.RestrictionCheckVersion < 1 || at.IsZero() || !next.After(at) || (status != "verified" && status != "restriction_lost" && status != "unverifiable" && status != "destination_managed") {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, found := s.links[tenant][link.ID]
	if !found || current.Revision != link.Revision || current.RestrictionCheckVersion != link.RestrictionCheckVersion || current.RetiredAt != nil {
		return shared.ErrConflict
	}
	current.RestrictionStatus, current.RestrictionCheckedAt, current.RestrictionNextAt = status, &at, next.UTC()
	s.links[tenant][link.ID] = current.Clone()
	return nil
}
