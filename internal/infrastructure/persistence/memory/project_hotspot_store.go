package memory

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ProjectHotspotStore = (*ProjectAnalysisStore)(nil)
var _ ports.ProjectAnalysisProjectionStore = (*ProjectAnalysisStore)(nil)

func (s *ProjectAnalysisStore) ListHotspots(ctx context.Context, tenantID, projectID shared.ID, filter hotspot.ListFilter) (hotspot.Page, error) {
	if err := ctx.Err(); err != nil {
		return hotspot.Page{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]hotspot.Hotspot, 0)
	for _, item := range s.hotspots {
		if item.TenantID != tenantID || item.ProjectID != projectID || !matches(item, filter) {
			continue
		}
		items = append(items, cloneHotspot(item))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeenAt.Equal(items[j].LastSeenAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].LastSeenAt.After(items[j].LastSeenAt)
	})
	page := hotspot.Page{Facets: facets(items)}
	if !filter.BeforeLastSeenAt.IsZero() {
		items = afterCursor(items, filter.BeforeLastSeenAt, filter.BeforeID)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 25
	}
	page.Items = items
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &hotspot.Cursor{BeforeLastSeenAt: last.LastSeenAt, BeforeID: last.ID}
	}
	return page, nil
}

func (s *ProjectAnalysisStore) GetHotspot(ctx context.Context, tenantID, projectID, hotspotID shared.ID) (hotspot.Hotspot, error) {
	if err := ctx.Err(); err != nil {
		return hotspot.Hotspot{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.hotspots {
		if item.TenantID == tenantID && item.ProjectID == projectID && item.ID == hotspotID {
			return cloneHotspot(item), nil
		}
	}
	return hotspot.Hotspot{}, shared.ErrNotFound
}

func matches(item hotspot.Hotspot, filter hotspot.ListFilter) bool {
	if filter.Status != nil && item.Status != *filter.Status {
		return false
	}
	if strings.TrimSpace(filter.RuleKey) != "" && item.RuleKey != strings.TrimSpace(filter.RuleKey) {
		return false
	}
	if filter.Severity != nil && item.Severity != *filter.Severity {
		return false
	}
	query := strings.ToLower(strings.TrimSpace(filter.Search))
	if query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{item.Key, item.RuleKey, item.Title, item.Description, item.Location}, "\x00")), query) {
		return false
	}
	return true
}

func afterCursor(items []hotspot.Hotspot, beforeAt time.Time, beforeID shared.ID) []hotspot.Hotspot {
	for i, item := range items {
		if item.LastSeenAt.Before(beforeAt) || (item.LastSeenAt.Equal(beforeAt) && item.ID < beforeID) {
			return items[i:]
		}
	}
	return nil
}

func facets(items []hotspot.Hotspot) hotspot.Facets {
	out := hotspot.Facets{Statuses: map[string]int{}, RuleKeys: map[string]int{}, Severities: map[string]int{}}
	for _, item := range items {
		out.Statuses[string(item.Status)]++
		out.RuleKeys[item.RuleKey]++
		out.Severities[string(item.Severity)]++
	}
	return out
}

func cloneHotspot(in hotspot.Hotspot) hotspot.Hotspot {
	out := in
	return out
}

func (s *ProjectAnalysisStore) TransitionHotspot(ctx context.Context, cmd hotspot.TransitionCommand) (hotspot.Hotspot, hotspot.ReviewEvent, error) {
	if err := ctx.Err(); err != nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.hotspots {
		if s.hotspots[i].TenantID == cmd.TenantID && s.hotspots[i].ProjectID == cmd.ProjectID && s.hotspots[i].ID == cmd.HotspotID {
			updated, event, err := s.hotspots[i].Transition(cmd.To, cmd.Actor, cmd.Rationale, cmd.ExpectedVersion, cmd.EventID, time.Now())
			if err != nil {
				return hotspot.Hotspot{}, hotspot.ReviewEvent{}, err
			}
			s.hotspots[i] = updated
			s.reviewEvents = append(s.reviewEvents, event)
			return cloneHotspot(updated), event, nil
		}
	}
	return hotspot.Hotspot{}, hotspot.ReviewEvent{}, shared.ErrNotFound
}

func (s *ProjectAnalysisStore) HotspotHistory(ctx context.Context, tenantID, projectID, hotspotID shared.ID) ([]hotspot.ReviewEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []hotspot.ReviewEvent
	for _, e := range s.reviewEvents {
		if e.TenantID == tenantID && e.ProjectID == projectID && e.HotspotID == hotspotID {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Version == out[j].Version {
			return out[i].ID > out[j].ID
		}
		return out[i].Version > out[j].Version
	})
	return out, nil
}

func (s *ProjectAnalysisStore) ListAnalysisHotspots(ctx context.Context, tenantID, projectID, analysisID shared.ID, lens hotspot.Lens, filter hotspot.ListFilter) (hotspot.Page, hotspot.Summary, error) {
	if err := ctx.Err(); err != nil {
		return hotspot.Page{}, hotspot.Summary{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	summary, err := s.currentAnalysisHotspotSummaryLocked(tenantID, projectID, analysisID, lens)
	if err != nil {
		return hotspot.Page{}, hotspot.Summary{}, err
	}
	
	var items []hotspot.Hotspot
	for _, ah := range s.analysisHotspots {
		if ah.AnalysisID != analysisID {
			continue
		}
		if lens == hotspot.LensNewCode && !ah.IsNew {
			continue
		}
		for _, h := range s.hotspots {
			if h.ID == ah.HotspotID && h.TenantID == tenantID && h.ProjectID == projectID {
				if matches(h, filter) {
					items = append(items, cloneHotspot(h))
				}
				break
			}
		}
	}
	
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeenAt.Equal(items[j].LastSeenAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].LastSeenAt.After(items[j].LastSeenAt)
	})
	
	page := hotspot.Page{Facets: facets(items)}
	if !filter.BeforeLastSeenAt.IsZero() {
		items = afterCursor(items, filter.BeforeLastSeenAt, filter.BeforeID)
	}
	limit := filter.Limit
	if limit <= 0 { limit = 25 }
	
	page.Items = items
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &hotspot.Cursor{BeforeLastSeenAt: last.LastSeenAt, BeforeID: last.ID}
	}
	return page, summary, nil
}

func (s *ProjectAnalysisStore) CurrentAnalysisHotspotSummary(ctx context.Context, tenantID, projectID, analysisID shared.ID, lens hotspot.Lens) (hotspot.Summary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentAnalysisHotspotSummaryLocked(tenantID, projectID, analysisID, lens)
}

func (s *ProjectAnalysisStore) currentAnalysisHotspotSummaryLocked(tenantID, projectID, analysisID shared.ID, lens hotspot.Lens) (hotspot.Summary, error) {
	total := 0
	reviewed := 0
	for _, ah := range s.analysisHotspots {
		if ah.AnalysisID != analysisID {
			continue
		}
		if lens == hotspot.LensNewCode && !ah.IsNew {
			continue
		}
		for _, h := range s.hotspots {
			if h.ID == ah.HotspotID && h.TenantID == tenantID && h.ProjectID == projectID {
				total++
				if h.Status.Reviewed() {
					reviewed++
				}
				break
			}
		}
	}
	return hotspot.NewSummary(total, reviewed)
}
