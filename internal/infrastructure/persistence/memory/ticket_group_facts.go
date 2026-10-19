package memory

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TicketGroupFactsReader = (*TicketStore)(nil)

// SetGroupAssetSources binds the existing attribution stores at composition time.
func (s *TicketStore) SetGroupAssetSources(assets ports.AssetRepository, bindings ports.AttackPathStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groupAssets = assets
	s.groupBindings = bindings
}

func (s *TicketStore) GroupTicketFacts(ctx context.Context, tenant, mappingID, projectID shared.ID, vulnerability string, candidate ports.TicketGroupMember) ([]ports.TicketGroupFact, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || mappingID.IsZero() || projectID.IsZero() || strings.TrimSpace(vulnerability) == "" || len(vulnerability) > 255 || candidate.EngagementID.IsZero() || candidate.FindingID.IsZero() {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	mapping, found := s.mappings[tenant][mappingID]
	members := map[string]ports.TicketGroupMember{ticketGroupMemberKey(candidate): candidate}
	group, hasGroup := s.groups[tenant][mappingID.String()+"\x00"+projectID.String()+"\x00"+vulnerability]
	if hasGroup {
		for key, member := range s.groupMembers[tenant][group.ID] {
			members[key] = member
		}
	}
	assets, bindings := s.groupAssets, s.groupBindings
	s.mu.RUnlock()
	if !found || mapping.ScopeID != projectID || mapping.GroupingMode != "vulnerability_project" || mapping.Scope != "project" || mapping.DataClass != "detail" {
		return nil, shared.ErrNotFound
	}
	if len(members) > 100 {
		return nil, shared.ErrValidation
	}
	var attribution []attackpath.Binding
	if bindings != nil {
		var err error
		attribution, err = bindings.ListBindings(ctx, tenant)
		if err != nil {
			return nil, err
		}
	}
	out := []ports.TicketGroupFact{}
	for _, member := range members {
		isCandidate := member == candidate
		// Human engagement readers intentionally hide internal Project contexts.
		// Read only ownership here, including sibling contexts of one Project.
		s.engagements.mu.RLock()
		eng, exists := s.engagements.data[member.EngagementID]
		owned := exists && eng.TenantID == tenant && eng.ProjectID == projectID
		s.engagements.mu.RUnlock()
		if !owned {
			if isCandidate {
				return nil, shared.ErrNotFound
			}
			continue
		}
		f, err := s.findings.GetByEngagementAndID(shared.WithTenant(ctx, tenant), member.EngagementID, member.FindingID)
		if err != nil {
			if !isCandidate && errors.Is(err, shared.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if !f.CanPromote() || strings.TrimSpace(f.AdvisoryID) != vulnerability {
			if isCandidate {
				return nil, shared.ErrForbidden
			}
			continue
		}
		base := ports.TicketGroupFact{EngagementID: member.EngagementID, FindingID: member.FindingID, Title: f.Title, Severity: f.Severity, Status: f.Status, FindingVersion: f.Version, GroupRevision: group.Revision, ExternalNotifications: notification.EngagementNotificationsInherit}
		seen := map[shared.ID]bool{}
		if assets != nil {
			for _, binding := range attribution {
				if binding.TenantID != tenant || binding.EngagementID != member.EngagementID || binding.FindingID != member.FindingID || binding.TargetKind != attackpath.TargetCanonical || binding.Confidence != asset.EdgeObserved || seen[binding.AssetID] {
					continue
				}
				a, err := assets.GetAssetByID(ctx, tenant, binding.AssetID)
				if err != nil {
					return nil, err
				}
				fact := base
				fact.AssetID = a.ID
				fact.AssetName = a.Name
				out = append(out, fact)
				seen[a.ID] = true
			}
		}
		if len(seen) == 0 {
			out = append(out, base)
		}
		if len(out) > 100 {
			return nil, shared.ErrValidation
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.EngagementID != b.EngagementID {
			return a.EngagementID < b.EngagementID
		}
		if a.FindingID != b.FindingID {
			return a.FindingID < b.FindingID
		}
		return a.AssetID < b.AssetID
	})
	return out, nil
}
