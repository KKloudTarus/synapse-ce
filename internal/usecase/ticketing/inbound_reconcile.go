package ticketing

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
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
	targets, err := store.ListInboundTicketTargets(providerCtx, tenant, limit)
	if err != nil {
		return err
	}
	principals := map[shared.ID]string{}
	principalChecked := map[shared.ID]bool{}
	remainingRequests := 250
	for _, target := range targets {
		if err := providerCtx.Err(); err != nil {
			return err
		}
		if remainingRequests == 0 {
			break
		}
		now := w.clock.Now().UTC()
		record := func() error { return store.RecordInboundTicketPoll(progressCtx, tenant, target, now) }
		if err := w.validateStatusTarget(providerCtx, tenant, target); err != nil {
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			continue
		}
		in, err := w.integration(providerCtx, tenant, target.Mapping.IntegrationID)
		if err != nil || !in.Enabled {
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			continue
		}
		provider, err := w.providers.TicketProvider(providerCtx, in)
		if err != nil {
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			continue
		}
		reader, ok := provider.(ports.TicketReader)
		if !ok {
			closeTicketProvider(provider)
			if recordErr := record(); recordErr != nil {
				return recordErr
			}
			continue
		}
		remainingRequests--
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
			if !errors.As(readErr, &providerErr) || (providerErr.Status != 403 && providerErr.Status != 404) {
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
						identityErr = fmt.Errorf("%w: Jira integration identity unavailable", shared.ErrConflict)
					}
					closeTicketProvider(identityProvider)
				}
				if identityErr != nil {
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
