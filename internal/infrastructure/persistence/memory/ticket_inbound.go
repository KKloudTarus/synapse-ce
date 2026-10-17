package memory

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TicketInboundStore = (*TicketStore)(nil)

func inboundObservationKey(mappingID, engagementID, findingID shared.ID, remote string) string {
	return mappingID.String() + "\x00" + engagementID.String() + "\x00" + findingID.String() + "\x00" + remote
}

func inboundPollKey(target ports.TicketStatusTarget) string {
	return inboundObservationKey(target.Mapping.ID, target.Intent.EngagementID, target.Intent.FindingID, target.Intent.RemoteID)
}

func (s *TicketStore) ListInboundTicketTargets(ctx context.Context, tenant shared.ID, limit int) ([]ports.TicketStatusTarget, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || limit < 1 || limit > 250 {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ports.TicketStatusTarget, 0, limit)
	for _, intent := range s.intents[tenant] {
		if intent.State != writeintent.Done || intent.Action != ticketing.Create || intent.RemoteID == "" {
			continue
		}
		mapping, ok := s.mappings[tenant][intent.MappingID]
		if !ok {
			continue
		}
		out = append(out, ports.TicketStatusTarget{Mapping: mapping.Clone(), Intent: intent.Clone()})
	}
	slices.SortFunc(out, func(a, b ports.TicketStatusTarget) int {
		left := s.inboundPollProgress[tenant][inboundPollKey(a)]
		right := s.inboundPollProgress[tenant][inboundPollKey(b)]
		if cmp := left.checkedAt.Compare(right.checkedAt); cmp != 0 {
			return cmp
		}
		if left.version != right.version {
			return left.version - right.version
		}
		return strings.Compare(a.Intent.ID.String(), b.Intent.ID.String())
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *TicketStore) RecordInboundTicketPoll(ctx context.Context, tenant shared.ID, target ports.TicketStatusTarget, checkedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || target.Mapping.ID.IsZero() || target.Intent.EngagementID.IsZero() || target.Intent.FindingID.IsZero() || strings.TrimSpace(target.Intent.RemoteID) == "" || checkedAt.IsZero() {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inboundPollProgress[tenant] == nil {
		s.inboundPollProgress[tenant] = map[string]memoryInboundPollProgress{}
	}
	key := inboundPollKey(target)
	item := s.inboundPollProgress[tenant][key]
	item.checkedAt, item.version = checkedAt.UTC(), item.version+1
	s.inboundPollProgress[tenant][key] = item
	return nil
}

func (s *TicketStore) ResolveInboundTicket(ctx context.Context, tenant, integrationID shared.ID, remoteID string) ([]ports.TicketStatusTarget, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || integrationID.IsZero() || strings.TrimSpace(remoteID) == "" {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ports.TicketStatusTarget
	for _, intent := range s.intents[tenant] {
		if intent.State != writeintent.Done || intent.Action != ticketing.Create || intent.IntegrationID != integrationID || intent.RemoteID != remoteID {
			continue
		}
		mapping, ok := s.mappings[tenant][intent.MappingID]
		if !ok {
			continue
		}
		matchedGroup := false
		for _, group := range s.groups[tenant] {
			if group.MappingID != intent.MappingID || group.Remote.ID != remoteID {
				continue
			}
			for _, member := range s.groupMembers[tenant][group.ID] {
				memberIntent := intent.Clone()
				memberIntent.EngagementID, memberIntent.FindingID = member.EngagementID, member.FindingID
				out = append(out, ports.TicketStatusTarget{Mapping: mapping.Clone(), Intent: memberIntent})
			}
			matchedGroup = true
		}
		if !matchedGroup {
			out = append(out, ports.TicketStatusTarget{Mapping: mapping.Clone(), Intent: intent.Clone()})
		}
	}
	return out, nil
}

func (s *TicketStore) ReduceInboundTicket(ctx context.Context, tenant shared.ID, observations []ticketing.ExternalTicketObservation, comments []ticketing.ExternalTicketComment, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || now.IsZero() {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inboundObservations[tenant] == nil {
		s.inboundObservations[tenant] = map[string]ticketing.ExternalTicketObservation{}
	}
	for _, item := range observations {
		if item.TenantID != tenant || !item.Valid() {
			return shared.ErrValidation
		}
		mapping, ok := s.mappings[tenant][item.MappingID]
		if !ok || mapping.IntegrationID != item.IntegrationID {
			return shared.ErrForbidden
		}
	}
	for _, comment := range comments {
		if comment.ID.IsZero() || comment.TenantID != tenant || len(comment.Body) > 16<<10 || comment.Body == "" {
			return shared.ErrValidation
		}
	}
	for _, item := range observations {
		key := inboundObservationKey(item.MappingID, item.EngagementID, item.FindingID, item.RemoteID)
		previous, found := s.inboundObservations[tenant][key]
		if item.DeletedOrUnreadable && item.StatusCategory == "" && found {
			item.StatusCategory = previous.StatusCategory
		}
		if item.DeletedOrUnreadable && item.ProviderUpdatedAt.IsZero() && found {
			item.ProviderUpdatedAt = previous.ProviderUpdatedAt
		}
		if found && !previous.ProviderUpdatedAt.IsZero() && !item.ProviderUpdatedAt.IsZero() {
			if item.ProviderUpdatedAt.Before(previous.ProviderUpdatedAt) || (item.ProviderUpdatedAt.Equal(previous.ProviderUpdatedAt) && item.StatusCategory != previous.StatusCategory) {
				continue
			}
		}
		if found && !item.StatusAuthorKnown && previous.StatusAuthorKnown && item.StatusCategory == previous.StatusCategory {
			item.AuthorID, item.StatusAuthorKnown, item.StatusChangedAt = previous.AuthorID, true, previous.StatusChangedAt
		}
		item.Version = previous.Version + 1
		if !found {
			item.Version = 1
		}
		enteredDone := item.StatusCategory == "done" && (!found || previous.StatusCategory != "done")
		if item.StatusCategory != "done" || item.DeletedOrUnreadable {
			item.PendingDone = false
		} else if enteredDone {
			item.PendingDone = true
		} else if found {
			item.PendingDone = previous.PendingDone
		}
		if item.PendingDone && item.StatusAuthorKnown {
			item.PendingDone = false
			if !item.OwnWrite {
				eligible := true
				for _, proposal := range s.inboundProposals[tenant] {
					if proposal.EngagementID == item.EngagementID && proposal.FindingID == item.FindingID && now.Sub(proposal.ObservedAt) < time.Hour {
						eligible = false
						break
					}
				}
				if eligible {
					s.inboundProposals[tenant] = append(s.inboundProposals[tenant], ticketing.RetestProposal{ID: shared.ID("inbound-proposal-" + item.MappingID.String() + "-" + item.FindingID.String() + "-" + now.UTC().Format("20060102150405.000000000")), TenantID: tenant, IntegrationID: item.IntegrationID, EngagementID: item.EngagementID, FindingID: item.FindingID, RemoteID: item.RemoteID, ResolutionName: item.ResolutionName, ObservedAt: now.UTC(), State: "pending"})
				}
			}
		}
		item.OwnWrite = false
		s.inboundObservations[tenant][key] = item
	}
	for _, comment := range comments {
		duplicate := false
		for _, existing := range s.inboundComments[tenant] {
			if existing.ID == comment.ID {
				duplicate = true
				break
			}
		}
		if !duplicate {
			s.inboundComments[tenant] = append(s.inboundComments[tenant], comment)
		}
	}
	return nil
}

func (s *TicketStore) ListInboundTicketView(ctx context.Context, tenant, engagementID, findingID shared.ID) (ports.TicketInboundView, error) {
	if err := ctx.Err(); err != nil {
		return ports.TicketInboundView{}, err
	}
	if tenant.IsZero() || engagementID.IsZero() || findingID.IsZero() {
		return ports.TicketInboundView{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := ports.TicketInboundView{}
	for _, item := range s.inboundObservations[tenant] {
		if item.EngagementID == engagementID && item.FindingID == findingID {
			out.Observations = append(out.Observations, item)
		}
	}
	for _, item := range s.inboundProposals[tenant] {
		if item.EngagementID == engagementID && item.FindingID == findingID {
			out.Proposals = append(out.Proposals, item)
		}
	}
	for _, item := range s.inboundComments[tenant] {
		if item.EngagementID == engagementID && item.FindingID == findingID {
			out.Comments = append(out.Comments, item)
		}
	}
	slices.SortFunc(out.Observations, func(a, b ticketing.ExternalTicketObservation) int { return b.CheckedAt.Compare(a.CheckedAt) })
	slices.SortFunc(out.Proposals, func(a, b ticketing.RetestProposal) int { return b.ObservedAt.Compare(a.ObservedAt) })
	slices.SortFunc(out.Comments, func(a, b ticketing.ExternalTicketComment) int { return b.CreatedAt.Compare(a.CreatedAt) })
	if len(out.Observations) > 100 {
		out.Observations = out.Observations[:100]
	}
	if len(out.Proposals) > 100 {
		out.Proposals = out.Proposals[:100]
	}
	if len(out.Comments) > 100 {
		out.Comments = out.Comments[:100]
	}
	return out, nil
}
