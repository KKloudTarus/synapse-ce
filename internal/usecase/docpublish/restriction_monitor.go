package docpublish

import (
	"context"
	"errors"
	"fmt"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	restrictionMonitorPassBudget        = 12 * time.Second
	restrictionMonitorObservationBudget = 10 * time.Second
	restrictionMonitorClaimLimit        = 1
)

// checkRestrictions observes existing pages only. A lost restriction is reported,
// never silently repaired: changing remote access requires a new human release.
// Each tenant pass claims one due link from the indexed, bounded restriction queue.
func (s *Service) checkRestrictions(ctx context.Context, tenant shared.ID, limit int) error {
	return s.checkRestrictionsWithBudget(ctx, tenant, limit, restrictionMonitorPassBudget, restrictionMonitorObservationBudget)
}

func (s *Service) checkRestrictionsWithBudget(ctx context.Context, tenant shared.ID, limit int, passBudget, observationBudget time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, passBudget)
	defer cancel()
	links, err := s.store.ClaimDocumentRestrictionChecks(ctx, tenant, min(limit, restrictionMonitorClaimLimit), s.clock.Now().UTC())
	if err != nil {
		return err
	}
	var failures []error
	for _, link := range links {
		if ctx.Err() != nil {
			break
		}
		deadline, _ := ctx.Deadline()
		remaining := time.Until(deadline) - (passBudget - observationBudget)
		if remaining <= 0 {
			break
		}
		checkCtx, stop := context.WithTimeout(ctx, min(observationBudget, remaining))
		status := s.observeRestriction(checkCtx, tenant, link)
		stop()
		at := s.clock.Now().UTC()
		if status != link.RestrictionStatus && (status == "restriction_lost" || status == "unverifiable") {
			action := "document.restriction_lost"
			if status == "unverifiable" {
				action = "document.restriction_unverifiable"
			}
			// This append-only event describes the observed revision. A concurrent
			// republish may supersede it; the subsequent CAS cannot mark that new
			// revision with this old observation. Never record provider error text.
			err = s.audit.Record(ctx, ports.AuditEntry{Actor: "system", Action: action, Target: link.ID.String(), At: at,
				Metadata: map[string]string{"page_id": link.RemotePageID, "link_revision": fmt.Sprint(link.Revision),
					"idempotency_key": fmt.Sprintf("%s:restriction:%d:%d", link.ID, link.Revision, link.RestrictionCheckVersion)}})
			if err != nil {
				failures = append(failures, errors.New("document sharing audit failed"))
				continue
			}
		}
		interval := 15 * time.Minute
		if status != "verified" {
			interval = 5 * time.Minute
		}
		if err = s.store.SaveDocumentRestrictionCheck(ctx, tenant, link, status, at, at.Add(interval)); err != nil && !errors.Is(err, shared.ErrConflict) {
			failures = append(failures, errors.New("document sharing checkpoint failed"))
		}
	}
	return errors.Join(failures...)
}

func (s *Service) observeRestriction(ctx context.Context, tenant shared.ID, link domain.Link) string {
	in, err := s.integration(ctx, tenant, link.IntegrationID)
	if err != nil {
		return "unverifiable"
	}
	space, group, err := destination(in)
	if err != nil || space != link.Container {
		return "unverifiable"
	}
	provider, err := s.providers.DocumentProvider(ctx, in)
	if err != nil {
		return "unverifiable"
	}
	defer closeProvider(provider)
	// The provider verifies both remote identity/container and complete current
	// sharing. Fetching the document separately duplicates that bounded proof.
	err = provider.VerifyDocumentRestriction(ctx, link.RemotePageID, link.Container, group)
	// Re-read configuration after the remote observation, so a rotated credential
	// or changed destination cannot make an old proof look current.
	current, readErr := s.integration(ctx, tenant, link.IntegrationID)
	if readErr != nil || current.ConnectionRevision != in.ConnectionRevision || current.CredentialRevision != in.CredentialRevision {
		return "unverifiable"
	}
	if err == nil {
		return "verified"
	}
	var refusal *ports.DocumentProviderError
	if errors.As(err, &refusal) && (refusal.Code == "restriction_unverified" || refusal.Code == "public_sharing_unverifiable") {
		return "restriction_lost"
	}
	return "unverifiable"
}
