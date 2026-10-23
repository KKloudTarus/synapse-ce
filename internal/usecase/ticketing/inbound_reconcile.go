package ticketing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	inboundPollFloor          = time.Minute
	inboundPollFailureBackoff = 5 * time.Minute
)

// tickInboundTicketObservations reads existing provider tickets into the same
// reducer used by signed webhooks. It has no create path and cannot mutate a
// finding; an external done state can only create a retest proposal.
func (w *Workflow) tickInboundTicketObservations(ctx context.Context, tenant shared.ID, store ports.TicketInboundStore, limit int) error {
	return w.tickInboundTicketObservationsWithProgress(ctx, ctx, tenant, store, limit)
}

// tickInboundTicketObservationsWithProgress keeps provider I/O bounded without
// losing the fair polling checkpoint for a target that was actually attempted.
// progressCtx remains the worker context; it still honors caller cancellation.
func (w *Workflow) tickInboundTicketObservationsWithProgress(providerCtx, progressCtx context.Context, tenant shared.ID, store ports.TicketInboundStore, limit int) error {
	type queuedTarget struct {
		target ports.TicketStatusTarget
		claim  *ports.TicketInboundPollClaim
	}
	queued := make([]queuedTarget, 0, limit)
	if claims, ok := store.(ports.TicketInboundClaimStore); ok {
		claimed, err := claims.ClaimInboundTicketTargets(providerCtx, tenant, limit, w.clock.Now().UTC(), inboundPollFloor)
		if err != nil {
			return err
		}
		for i := range claimed {
			queued = append(queued, queuedTarget{target: claimed[i].Target, claim: &claimed[i]})
		}
	} else {
		targets, err := store.ListInboundTicketTargets(providerCtx, tenant, limit)
		if err != nil {
			return err
		}
		for _, target := range targets {
			queued = append(queued, queuedTarget{target: target})
		}
	}
	principals := map[shared.ID]string{}
	principalChecked := map[shared.ID]bool{}
	throttled := map[shared.ID]time.Duration{}
	remainingRequests := 250
	for _, queuedTarget := range queued {
		target := queuedTarget.target
		if err := providerCtx.Err(); err != nil {
			return err
		}
		if remainingRequests == 0 {
			break
		}
		now := w.clock.Now().UTC()
		delay := inboundPollFloor
		observed := false
		record := func() error {
			if queuedTarget.claim != nil {
				checkedAt := time.Time{}
				if observed {
					checkedAt = now
				}
				return store.(ports.TicketInboundClaimStore).CompleteInboundTicketPoll(progressCtx, tenant, *queuedTarget.claim, checkedAt, now.Add(delay))
			}
			return store.RecordInboundTicketPoll(progressCtx, tenant, target, now)
		}
		if blockedDelay, blocked := throttled[target.Mapping.IntegrationID]; blocked {
			delay = blockedDelay
			if err := record(); err != nil {
				return err
			}
			continue
		}
		if err := w.validateStatusTarget(providerCtx, tenant, target); err != nil {
			delay = inboundPollFailureBackoff
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			continue
		}
		in, err := w.integration(providerCtx, tenant, target.Mapping.IntegrationID)
		if err != nil || !in.Enabled {
			delay = inboundPollFailureBackoff
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			continue
		}
		provider, err := w.providers.TicketProvider(providerCtx, in)
		if err != nil {
			delay = inboundPollFailureBackoff
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			continue
		}
		reader, ok := provider.(ports.TicketReader)
		if !ok {
			closeTicketProvider(provider)
			delay = inboundPollFailureBackoff
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			continue
		}
		remainingRequests--
		observed = true
		remote, readErr := reader.GetTicket(providerCtx, target.Intent.RemoteID)
		closeTicketProvider(provider)
		if readErr != nil {
			if providerCtx.Err() != nil {
				if recordErr := record(); recordErr != nil {
					return recordErr
				}
				return providerCtx.Err()
			}
			var providerErr *ports.TicketProviderError
			if !errors.As(readErr, &providerErr) || inboundProviderThrottle(providerErr) || (providerErr.Status != 403 && providerErr.Status != 404) {
				delay = inboundPollFailureBackoff
				if errors.As(readErr, &providerErr) && inboundProviderThrottle(providerErr) {
					delay = inboundRateLimitDelay(providerErr.RetryAfter)
					throttled[in.ID] = delay
				}
				if recordErr := record(); recordErr != nil {
					return recordErr
				}
				continue
			}
			remote = ports.TicketObservation{ExternalID: target.Intent.RemoteID, Deleted: true}
		}
		if remote.ExternalID != target.Intent.RemoteID {
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			continue
		}
		if !remote.Deleted && remote.StatusCategory != "new" && remote.StatusCategory != "indeterminate" && remote.StatusCategory != "done" {
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			continue
		}
		principal := principals[in.ID]
		if remote.AuthorID != "" && !principalChecked[in.ID] {
			configStore, hasConfig := w.store.(ports.TicketInboundConfigurationStore)
			if hasConfig {
				if config, configErr := configStore.GetTicketInboundConfiguration(providerCtx, tenant, in.ID); configErr == nil && config.Enabled && config.ConnectionRevision == in.ConnectionRevision && config.CredentialRevision == in.CredentialRevision {
					principal = config.IntegrationAuthor
				}
			}
			if principal == "" && remainingRequests > 0 {
				identityProvider, identityErr := w.providers.TicketProvider(providerCtx, in)
				if identityErr == nil {
					if identity, ok := identityProvider.(ports.TicketIdentityReader); ok {
						remainingRequests--
						principal, identityErr = identity.TicketIdentity(providerCtx)
					} else {
						identityErr = fmt.Errorf("%w: ticket integration identity unavailable", shared.ErrConflict)
					}
					closeTicketProvider(identityProvider)
				}
				if identityErr != nil {
					var providerErr *ports.TicketProviderError
					if errors.As(identityErr, &providerErr) && inboundProviderThrottle(providerErr) {
						delay = inboundRateLimitDelay(providerErr.RetryAfter)
						throttled[in.ID] = delay
					}
					principal = ""
				}
			}
			principal = strings.TrimSpace(principal)
			principals[in.ID] = principal
			principalChecked[in.ID] = true
		}
		if err := providerCtx.Err(); err != nil {
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			return err
		}
		if remote.AuthorID != "" && strings.TrimSpace(principal) == "" {
			// Current status remains useful when identity is unavailable or the
			// read budget is exhausted. Defer a proposal until its author can be
			// compared with the authenticated integration principal.
			remote.AuthorID = ""
		}
		linked, err := store.ResolveInboundTicket(providerCtx, tenant, in.ID, target.Intent.RemoteID)
		if err != nil {
			delay = inboundPollFailureBackoff
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			continue
		}
		observations := make([]domain.ExternalTicketObservation, 0, len(linked))
		for _, member := range linked {
			if err := w.validateStatusTarget(providerCtx, tenant, member); err != nil {
				continue
			}
			observations = append(observations, domain.ExternalTicketObservation{
				TenantID: tenant, IntegrationID: in.ID, MappingID: member.Mapping.ID,
				EngagementID: member.Intent.EngagementID, FindingID: member.Intent.FindingID,
				RemoteID: target.Intent.RemoteID, StatusCategory: remote.StatusCategory, ProviderUpdatedAt: remote.UpdatedAt,
				StatusChangedAt: remote.StatusChangedAt, AuthorID: remote.AuthorID, ResolutionName: remote.ResolutionName,
				StatusAuthorKnown: remote.AuthorID != "", OwnWrite: remote.AuthorID != "" && remote.AuthorID == principal,
				DeletedOrUnreadable: remote.Deleted, CheckedAt: now, Version: 1,
			})
		}
		if len(observations) > 0 {
			if err := store.ReduceInboundTicket(providerCtx, tenant, observations, nil, now); err != nil {
				delay = inboundPollFailureBackoff
				if recordErr := record(); recordErr != nil {
					return recordErr
				}
				continue
			}
		}
		if err := record(); err != nil {
			return err
		}
	}
	return nil
}

func inboundRateLimitDelay(retryAfter time.Duration) time.Duration {
	if retryAfter < inboundPollFailureBackoff {
		return inboundPollFailureBackoff
	}
	return retryAfter
}

func inboundProviderThrottle(refusal *ports.TicketProviderError) bool {
	return refusal.Status == 429 || refusal.Code == "rate_limited"
}
