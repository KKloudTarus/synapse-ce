package memory

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/issue"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ProjectIssueStore = (*ProjectAnalysisStore)(nil)
var _ ports.ProjectIssueProjectionStore = (*ProjectAnalysisStore)(nil)
var _ ports.ProjectFindingStatusStore = (*ProjectAnalysisStore)(nil)

func (s *ProjectAnalysisStore) ListIssues(ctx context.Context, tenantID, projectID shared.ID, filter issue.ListFilter) (issue.Page, error) {
	if err := ctx.Err(); err != nil {
		return issue.Page{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]issue.Issue, 0)
	for _, item := range s.issues {
		if item.TenantID != tenantID || item.ProjectID != projectID || !issueMatches(item, filter) {
			continue
		}
		items = append(items, cloneIssue(item))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeenAt.Equal(items[j].LastSeenAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].LastSeenAt.After(items[j].LastSeenAt)
	})
	page := issue.Page{Facets: issueFacets(items), Summary: issueSummary(items)}
	if !filter.BeforeLastSeenAt.IsZero() {
		items = issueAfterCursor(items, filter.BeforeLastSeenAt, filter.BeforeID)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 25
	}
	page.Items = items
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &issue.Cursor{BeforeLastSeenAt: last.LastSeenAt, BeforeID: last.ID}
	}
	return page, nil
}

func (s *ProjectAnalysisStore) GetIssue(ctx context.Context, tenantID, projectID, issueID shared.ID) (issue.Issue, error) {
	if err := ctx.Err(); err != nil {
		return issue.Issue{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.issues {
		if item.TenantID == tenantID && item.ProjectID == projectID && item.ID == issueID {
			return cloneIssue(item), nil
		}
	}
	return issue.Issue{}, shared.ErrNotFound
}

func (s *ProjectAnalysisStore) TransitionIssue(ctx context.Context, cmd issue.TransitionCommand) (issue.Issue, issue.ReviewEvent, error) {
	if err := ctx.Err(); err != nil {
		return issue.Issue{}, issue.ReviewEvent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.issues {
		if s.issues[i].TenantID == cmd.TenantID && s.issues[i].ProjectID == cmd.ProjectID && s.issues[i].ID == cmd.IssueID {
			updated, event, err := s.issues[i].Transition(cmd.To, cmd.Actor, cmd.Rationale, cmd.ExpectedVersion, cmd.EventID, time.Now())
			if err != nil {
				return issue.Issue{}, issue.ReviewEvent{}, err
			}
			s.issues[i] = updated
			s.issueEvents = append(s.issueEvents, event)
			return updated, event, nil
		}
	}
	return issue.Issue{}, issue.ReviewEvent{}, shared.ErrNotFound
}

func (s *ProjectAnalysisStore) IssueHistory(ctx context.Context, tenantID, projectID, issueID shared.ID) ([]issue.ReviewEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []issue.ReviewEvent
	for _, e := range s.issueEvents {
		if e.TenantID == tenantID && e.ProjectID == projectID && e.IssueID == issueID {
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

func (s *ProjectAnalysisStore) CurrentFindingStatuses(ctx context.Context, tenantID, projectID shared.ID, keys []string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	wanted := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		wanted[key] = struct{}{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(wanted))
	for _, item := range s.issues {
		if item.TenantID == tenantID && item.ProjectID == projectID {
			if _, ok := wanted[item.Key]; ok {
				out[item.Key] = string(item.Status)
			}
		}
	}
	for _, item := range s.hotspots {
		if item.TenantID == tenantID && item.ProjectID == projectID {
			if _, ok := wanted[item.Key]; ok {
				out[item.Key] = string(item.Status)
			}
		}
	}
	return out, nil
}

func (s *ProjectAnalysisStore) ResolvedIssueKeys(ctx context.Context, tenantID, projectID shared.ID) (map[string]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]bool{}
	for _, item := range s.issues {
		if item.TenantID == tenantID && item.ProjectID == projectID && item.Status.Resolved() {
			out[item.Key] = true
		}
	}
	return out, nil
}

func cloneIssue(in issue.Issue) issue.Issue {
	out := in
	out.SourceLocation = cloneSourceLocation(in.SourceLocation)
	return out
}

func issueMatches(item issue.Issue, filter issue.ListFilter) bool {
	if filter.Status != nil && item.Status != *filter.Status {
		return false
	}
	if filter.Type != nil && item.Type != *filter.Type {
		return false
	}
	if filter.Severity != nil && item.Severity != *filter.Severity {
		return false
	}
	if rk := strings.TrimSpace(filter.RuleKey); rk != "" && item.RuleKey != rk {
		return false
	}
	if lang := strings.TrimSpace(filter.Language); lang != "" && !strings.EqualFold(item.Language, lang) {
		return false
	}
	if p := strings.TrimSpace(filter.PathPrefix); p != "" && !strings.HasPrefix(item.File, p) {
		return false
	}
	if (filter.NewCodeOnly || filter.Lens == issue.LensNewCode) && !item.IsNew {
		return false
	}
	if q := strings.ToLower(strings.TrimSpace(filter.Search)); q != "" {
		hay := strings.ToLower(strings.Join([]string{item.Key, item.RuleKey, item.Title, item.Description, item.Location}, "\x00"))
		if !strings.Contains(hay, q) {
			return false
		}
	}
	return true
}

func issueAfterCursor(items []issue.Issue, beforeAt time.Time, beforeID shared.ID) []issue.Issue {
	for i, item := range items {
		if item.LastSeenAt.Before(beforeAt) || (item.LastSeenAt.Equal(beforeAt) && item.ID < beforeID) {
			return items[i:]
		}
	}
	return nil
}

func issueFacets(items []issue.Issue) issue.Facets {
	out := issue.Facets{Types: map[string]int{}, Statuses: map[string]int{}, Severities: map[string]int{}, RuleKeys: map[string]int{}, Languages: map[string]int{}}
	for _, item := range items {
		out.Types[string(item.Type)]++
		out.Statuses[string(item.Status)]++
		out.Severities[string(item.Severity)]++
		out.RuleKeys[item.RuleKey]++
		if item.Language != "" {
			out.Languages[item.Language]++
		}
	}
	return out
}

func issueSummary(items []issue.Issue) issue.Summary {
	out := issue.Summary{Total: len(items)}
	for _, item := range items {
		if item.Status.Resolved() {
			out.Resolved++
		} else {
			out.Open++
		}
	}
	return out
}
