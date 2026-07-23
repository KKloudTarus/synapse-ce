package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/issue"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ProjectIssueStore = (*ProjectAnalysisStore)(nil)
var _ ports.ProjectIssueProjectionStore = (*ProjectAnalysisStore)(nil)
var _ ports.ProjectFindingStatusStore = (*ProjectAnalysisStore)(nil)

// SaveWithResultAndProjections commits the immutable analysis, its Security Hotspot
// projection, and its code-quality issue projection in a single PostgreSQL
// transaction. A projection write failure rolls the analysis back, so the scan
// worker cannot publish a successful analysis without both projections.
func (r *ProjectAnalysisStore) SaveWithResultAndProjections(ctx context.Context, analysis projectanalysis.Analysis, result []byte, hotspots []hotspot.Candidate, issues []issue.Candidate) error {
	hotspotItems := make([]hotspot.Hotspot, len(hotspots))
	for i, candidate := range hotspots {
		item, err := hotspot.Project(shared.ID(analysis.TenantID), shared.ID(analysis.ProjectID), analysis.ID, analysis.CreatedAt, candidate)
		if err != nil {
			return err
		}
		hotspotItems[i] = item
	}
	issueItems := make([]issue.Issue, len(issues))
	for i, candidate := range issues {
		item, err := issue.Project(shared.ID(analysis.TenantID), shared.ID(analysis.ProjectID), analysis.ID, analysis.CreatedAt, candidate)
		if err != nil {
			return err
		}
		issueItems[i] = item
	}
	payload, err := json.Marshal(analysis)
	if err != nil {
		return fmt.Errorf("marshal project analysis: %w", err)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin project analysis transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `INSERT INTO project_analyses (id, tenant_id, project_id, created_at, payload, result)
		VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING`,
		analysis.ID, analysis.TenantID, analysis.ProjectID, analysis.CreatedAt, payload, result); err != nil {
		return fmt.Errorf("insert project analysis: %w", err)
	}

	if err := upsertHotspotsTx(ctx, tx, analysis, hotspotItems); err != nil {
		return err
	}
	if err := upsertIssuesTx(ctx, tx, issueItems); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit project analysis transaction: %w", err)
	}
	return nil
}

// upsertIssuesTx projects each issue candidate, preserving the triage lifecycle
// (status/version/review metadata) across rescans; only the descriptive fields and
// seen metadata move forward, and IsNew is recomputed from the merged seen analyses.
// It mirrors the memory store's upsertIssueLocked exactly.
func upsertIssuesTx(ctx context.Context, tx pgx.Tx, items []issue.Issue) error {
	for _, item := range items {
		sourceFile, startLine, endLine, startColumn, endColumn := sourceLocationFields(item.SourceLocation)
		if _, err := tx.Exec(ctx, `INSERT INTO project_issues
			(id, tenant_id, project_id, issue_key, finding_identity, rule_key, issue_type, title, description, severity, finding_kind, cwe, language, file, location, source_file, start_line, end_line, start_column, end_column,
			 status, version, is_new, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$26,$27)
			ON CONFLICT (tenant_id, project_id, issue_key) DO UPDATE SET
				first_seen_analysis_id = CASE WHEN (EXCLUDED.first_seen_at, EXCLUDED.first_seen_analysis_id) < (project_issues.first_seen_at, project_issues.first_seen_analysis_id) THEN EXCLUDED.first_seen_analysis_id ELSE project_issues.first_seen_analysis_id END,
				first_seen_at = CASE WHEN (EXCLUDED.first_seen_at, EXCLUDED.first_seen_analysis_id) < (project_issues.first_seen_at, project_issues.first_seen_analysis_id) THEN EXCLUDED.first_seen_at ELSE project_issues.first_seen_at END,
				created_at = CASE WHEN (EXCLUDED.first_seen_at, EXCLUDED.first_seen_analysis_id) < (project_issues.first_seen_at, project_issues.first_seen_analysis_id) THEN EXCLUDED.created_at ELSE project_issues.created_at END,
				finding_identity = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.finding_identity ELSE project_issues.finding_identity END,
				rule_key = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.rule_key ELSE project_issues.rule_key END,
				issue_type = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.issue_type ELSE project_issues.issue_type END,
				title = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.title ELSE project_issues.title END,
				description = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.description ELSE project_issues.description END,
				severity = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.severity ELSE project_issues.severity END,
				finding_kind = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.finding_kind ELSE project_issues.finding_kind END,
				cwe = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.cwe ELSE project_issues.cwe END,
				language = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.language ELSE project_issues.language END,
				file = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.file ELSE project_issues.file END,
				location = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.location ELSE project_issues.location END,
				source_file = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.source_file ELSE project_issues.source_file END,
				start_line = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.start_line ELSE project_issues.start_line END,
				end_line = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.end_line ELSE project_issues.end_line END,
				start_column = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.start_column ELSE project_issues.start_column END,
				end_column = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.end_column ELSE project_issues.end_column END,
				last_seen_analysis_id = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.last_seen_analysis_id ELSE project_issues.last_seen_analysis_id END,
				last_seen_at = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.last_seen_at ELSE project_issues.last_seen_at END,
				updated_at = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.updated_at ELSE project_issues.updated_at END,
				-- Triage is sticky: status/version/review metadata are never reset by a rescan.
				-- IsNew is recomputed from the merged first/last seen analyses.
				is_new = (
					CASE WHEN (EXCLUDED.first_seen_at, EXCLUDED.first_seen_analysis_id) < (project_issues.first_seen_at, project_issues.first_seen_analysis_id) THEN EXCLUDED.first_seen_analysis_id ELSE project_issues.first_seen_analysis_id END
				) = (
					CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_issues.last_seen_at, project_issues.last_seen_analysis_id) THEN EXCLUDED.last_seen_analysis_id ELSE project_issues.last_seen_analysis_id END
				)`,
			item.ID, item.TenantID, item.ProjectID, item.Key, item.FindingIdentity, item.RuleKey, string(item.Type), item.Title, item.Description,
			string(item.Severity), string(item.Kind), item.CWE, item.Language, item.File, item.Location,
			sourceFile, startLine, endLine, startColumn, endColumn,
			string(item.Status), item.Version, item.IsNew, item.FirstSeenAnalysisID, item.LastSeenAnalysisID, item.FirstSeenAt, item.LastSeenAt); err != nil {
			return fmt.Errorf("upsert project issue: %w", err)
		}
	}
	return nil
}

func (r *ProjectAnalysisStore) ListIssues(ctx context.Context, tenantID, projectID shared.ID, filter issue.ListFilter) (issue.Page, error) {
	where, args := issueWhere(tenantID, projectID, filter, true)
	limit := filter.Limit
	if limit <= 0 {
		limit = 25
	}
	args = append(args, limit+1)
	query := `SELECT id, tenant_id, project_id, issue_key, finding_identity, rule_key, issue_type, title, description, severity, finding_kind, cwe, language, file, location, source_file, start_line, end_line, start_column, end_column,
		status, version, is_new, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at, last_reviewed_by, last_reviewed_at
		FROM project_issues WHERE ` + where + ` ORDER BY last_seen_at DESC, id COLLATE "C" DESC LIMIT $` + fmt.Sprint(len(args))
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return issue.Page{}, fmt.Errorf("list project issues: %w", err)
	}
	defer rows.Close()
	items := make([]issue.Issue, 0, limit+1)
	for rows.Next() {
		item, err := scanIssue(rows)
		if err != nil {
			return issue.Page{}, fmt.Errorf("scan project issue: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return issue.Page{}, err
	}
	page := issue.Page{}
	if len(items) > limit {
		last := items[limit-1]
		page.Next = &issue.Cursor{BeforeLastSeenAt: last.LastSeenAt, BeforeID: last.ID}
		items = items[:limit]
	}
	page.Items = items

	// Facets and summary are computed over the filtered (but unpaginated) set: the
	// cursor is deliberately excluded so paging never shrinks the counts.
	facetWhere, facetArgs := issueWhere(tenantID, projectID, filter, false)

	var total, open, resolved int
	if err := r.pool.QueryRow(ctx, `SELECT count(*),
		count(*) FILTER (WHERE status = 'open'),
		count(*) FILTER (WHERE status IN ('accepted','false_positive','wont_fix'))
		FROM project_issues WHERE `+facetWhere, facetArgs...).Scan(&total, &open, &resolved); err != nil {
		return issue.Page{}, fmt.Errorf("summary project issues: %w", err)
	}
	page.Summary = issue.Summary{Total: total, Open: open, Resolved: resolved}

	facetRows, err := r.pool.Query(ctx, `SELECT 'type' AS kind, issue_type AS value, count(*) FROM project_issues WHERE `+facetWhere+` GROUP BY issue_type
		UNION ALL SELECT 'status', status, count(*) FROM project_issues WHERE `+facetWhere+` GROUP BY status
		UNION ALL SELECT 'severity', severity, count(*) FROM project_issues WHERE `+facetWhere+` GROUP BY severity
		UNION ALL SELECT 'rule', rule_key, count(*) FROM project_issues WHERE `+facetWhere+` GROUP BY rule_key
		UNION ALL SELECT 'language', language, count(*) FROM project_issues WHERE `+facetWhere+` AND language <> '' GROUP BY language`, facetArgs...)
	if err != nil {
		return issue.Page{}, fmt.Errorf("facet project issues: %w", err)
	}
	defer facetRows.Close()
	page.Facets = issue.Facets{Types: map[string]int{}, Statuses: map[string]int{}, Severities: map[string]int{}, RuleKeys: map[string]int{}, Languages: map[string]int{}}
	for facetRows.Next() {
		var kind, value string
		var count int
		if err := facetRows.Scan(&kind, &value, &count); err != nil {
			return issue.Page{}, fmt.Errorf("scan project issue facet: %w", err)
		}
		switch kind {
		case "type":
			page.Facets.Types[value] = count
		case "status":
			page.Facets.Statuses[value] = count
		case "severity":
			page.Facets.Severities[value] = count
		case "rule":
			page.Facets.RuleKeys[value] = count
		case "language":
			page.Facets.Languages[value] = count
		}
	}
	return page, facetRows.Err()
}

func issueLikeEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	value = strings.ReplaceAll(value, `_`, `\_`)
	return value
}

func issueWhere(tenantID, projectID shared.ID, filter issue.ListFilter, cursor bool) (string, []any) {
	args := []any{tenantID.String(), projectID.String()}
	parts := []string{"tenant_id = $1", "project_id = $2"}
	add := func(part string, value any) {
		args = append(args, value)
		parts = append(parts, fmt.Sprintf(part, len(args)))
	}
	if filter.Status != nil {
		add("status = $%d", string(*filter.Status))
	}
	if filter.Type != nil {
		add("issue_type = $%d", string(*filter.Type))
	}
	if filter.Severity != nil {
		add("severity = $%d", string(*filter.Severity))
	}
	if rk := strings.TrimSpace(filter.RuleKey); rk != "" {
		add("rule_key = $%d", rk)
	}
	if lang := strings.TrimSpace(filter.Language); lang != "" {
		add("LOWER(language) = LOWER($%d)", lang)
	}
	if p := strings.TrimSpace(filter.PathPrefix); p != "" {
		add(`file LIKE $%d`, issueLikeEscape(p)+"%")
	}
	if filter.NewCodeOnly || filter.Lens == issue.LensNewCode {
		parts = append(parts, "is_new = true")
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		searchArg := len(args) + 1
		pattern := "%" + issueLikeEscape(search) + "%"
		args = append(args, pattern, pattern, pattern, pattern, pattern)
		parts = append(parts, fmt.Sprintf("(issue_key ILIKE $%d OR rule_key ILIKE $%d OR title ILIKE $%d OR description ILIKE $%d OR location ILIKE $%d)", searchArg, searchArg+1, searchArg+2, searchArg+3, searchArg+4))
	}
	if cursor && !filter.BeforeLastSeenAt.IsZero() {
		args = append(args, filter.BeforeLastSeenAt, filter.BeforeID.String())
		at, id := len(args)-1, len(args)
		parts = append(parts, fmt.Sprintf(`(last_seen_at < $%d OR (last_seen_at = $%d AND id COLLATE "C" < $%d))`, at, at, id))
	}
	return strings.Join(parts, " AND "), args
}

func (r *ProjectAnalysisStore) GetIssue(ctx context.Context, tenantID, projectID, issueID shared.ID) (issue.Issue, error) {
	row := r.pool.QueryRow(ctx, `SELECT id, tenant_id, project_id, issue_key, finding_identity, rule_key, issue_type, title, description, severity, finding_kind, cwe, language, file, location, source_file, start_line, end_line, start_column, end_column,
		status, version, is_new, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at, last_reviewed_by, last_reviewed_at
		FROM project_issues WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, tenantID.String(), projectID.String(), issueID.String())
	item, err := scanIssue(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return issue.Issue{}, shared.ErrNotFound
	}
	if err != nil {
		return issue.Issue{}, fmt.Errorf("get project issue: %w", err)
	}
	return item, nil
}

func scanIssue(row rowScanner) (issue.Issue, error) {
	var item issue.Issue
	var tenantID, projectID, issueType, severity, kind, status string
	var sourceFile *string
	var startLine, endLine, startColumn, endColumn *int
	var createdAt, updatedAt time.Time
	var lastReviewedBy *string
	var lastReviewedAt *time.Time
	if err := row.Scan(&item.ID, &tenantID, &projectID, &item.Key, &item.FindingIdentity, &item.RuleKey, &issueType, &item.Title, &item.Description,
		&severity, &kind, &item.CWE, &item.Language, &item.File, &item.Location, &sourceFile, &startLine, &endLine, &startColumn, &endColumn, &status, &item.Version, &item.IsNew,
		&item.FirstSeenAnalysisID, &item.LastSeenAnalysisID, &item.FirstSeenAt, &item.LastSeenAt, &createdAt, &updatedAt, &lastReviewedBy, &lastReviewedAt); err != nil {
		return issue.Issue{}, err
	}
	if lastReviewedBy != nil {
		item.LastReviewedBy = *lastReviewedBy
	}
	item.SourceLocation = sourceLocationFromFields(sourceFile, startLine, endLine, startColumn, endColumn)
	item.LastReviewedAt = lastReviewedAt
	item.TenantID, item.ProjectID = shared.ID(tenantID), shared.ID(projectID)
	item.Type = rule.Type(issueType)
	item.Severity, item.Kind, item.Status = shared.Severity(severity), finding.Kind(kind), issue.Status(status)
	item.Audit = shared.Audit{CreatedAt: createdAt, UpdatedAt: updatedAt}
	return item, nil
}

func (r *ProjectAnalysisStore) TransitionIssue(ctx context.Context, cmd issue.TransitionCommand) (issue.Issue, issue.ReviewEvent, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return issue.Issue{}, issue.ReviewEvent{}, fmt.Errorf("begin issue transition tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `SELECT id, tenant_id, project_id, issue_key, finding_identity, rule_key, issue_type, title, description, severity, finding_kind, cwe, language, file, location, source_file, start_line, end_line, start_column, end_column,
		status, version, is_new, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at, last_reviewed_by, last_reviewed_at
		FROM project_issues WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, cmd.TenantID.String(), cmd.ProjectID.String(), cmd.IssueID.String())
	item, err := scanIssue(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return issue.Issue{}, issue.ReviewEvent{}, shared.ErrNotFound
	}
	if err != nil {
		return issue.Issue{}, issue.ReviewEvent{}, fmt.Errorf("get issue for update: %w", err)
	}

	updated, event, err := item.Transition(cmd.To, cmd.Actor, cmd.Rationale, cmd.ExpectedVersion, cmd.EventID, time.Now())
	if err != nil {
		return issue.Issue{}, issue.ReviewEvent{}, err
	}

	if _, err := tx.Exec(ctx, `UPDATE project_issues SET status=$1, version=$2, updated_at=$3, last_reviewed_by=$4, last_reviewed_at=$5 WHERE id=$6`,
		string(updated.Status), updated.Version, updated.Audit.UpdatedAt, updated.LastReviewedBy, updated.LastReviewedAt, updated.ID.String()); err != nil {
		return issue.Issue{}, issue.ReviewEvent{}, fmt.Errorf("update issue status: %w", err)
	}

	if _, err := tx.Exec(ctx, `INSERT INTO project_issue_review_events
		(id, tenant_id, project_id, issue_id, from_status, to_status, actor, rationale, previous_version, version, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		event.ID.String(), event.TenantID.String(), event.ProjectID.String(), event.IssueID.String(),
		string(event.From), string(event.To), event.Actor, event.Rationale, event.PreviousVersion, event.Version, event.CreatedAt); err != nil {
		return issue.Issue{}, issue.ReviewEvent{}, fmt.Errorf("insert issue review event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return issue.Issue{}, issue.ReviewEvent{}, fmt.Errorf("commit issue transition tx: %w", err)
	}
	return updated, event, nil
}

func (r *ProjectAnalysisStore) IssueHistory(ctx context.Context, tenantID, projectID, issueID shared.ID) ([]issue.ReviewEvent, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, tenant_id, project_id, issue_id, from_status, to_status, actor, rationale, previous_version, version, created_at
		FROM project_issue_review_events
		WHERE tenant_id=$1 AND project_id=$2 AND issue_id=$3
		ORDER BY version DESC, id COLLATE "C" DESC`, tenantID.String(), projectID.String(), issueID.String())
	if err != nil {
		return nil, fmt.Errorf("query issue review events: %w", err)
	}
	defer rows.Close()

	var events []issue.ReviewEvent
	for rows.Next() {
		var e issue.ReviewEvent
		var id, tID, pID, iID, from, to string
		if err := rows.Scan(&id, &tID, &pID, &iID, &from, &to, &e.Actor, &e.Rationale, &e.PreviousVersion, &e.Version, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan issue review event: %w", err)
		}
		e.ID, e.TenantID, e.ProjectID, e.IssueID = shared.ID(id), shared.ID(tID), shared.ID(pID), shared.ID(iID)
		e.From, e.To = issue.Status(from), issue.Status(to)
		events = append(events, e)
	}
	return events, rows.Err()
}

func sourceLocationFields(location *finding.SourceLocation) (any, any, any, any, any) {
	if location == nil {
		return nil, nil, nil, nil, nil
	}
	var startColumn, endColumn any
	if location.StartColumn != nil {
		startColumn = *location.StartColumn
		endColumn = *location.EndColumn
	}
	return location.File, location.StartLine, location.EndLine, startColumn, endColumn
}

func sourceLocationFromFields(file *string, startLine, endLine, startColumn, endColumn *int) *finding.SourceLocation {
	if file == nil || startLine == nil || endLine == nil {
		return nil
	}
	location := &finding.SourceLocation{File: *file, StartLine: *startLine, EndLine: *endLine, StartColumn: startColumn, EndColumn: endColumn}
	if location.Validate() != nil {
		return nil
	}
	return location
}

func (r *ProjectAnalysisStore) CurrentFindingStatuses(ctx context.Context, tenantID, projectID shared.ID, keys []string) (map[string]string, error) {
	if len(keys) == 0 {
		return map[string]string{}, nil
	}
	rows, err := r.pool.Query(ctx, `SELECT issue_key, status FROM project_issues WHERE tenant_id=$1 AND project_id=$2 AND issue_key = ANY($3)
		UNION ALL SELECT hotspot_key, status FROM project_hotspots WHERE tenant_id=$1 AND project_id=$2 AND hotspot_key = ANY($3)`, tenantID.String(), projectID.String(), keys)
	if err != nil {
		return nil, fmt.Errorf("query current finding statuses: %w", err)
	}
	defer rows.Close()
	out := make(map[string]string, len(keys))
	for rows.Next() {
		var key, status string
		if err := rows.Scan(&key, &status); err != nil {
			return nil, fmt.Errorf("scan current finding status: %w", err)
		}
		out[key] = status
	}
	return out, rows.Err()
}

func (r *ProjectAnalysisStore) ResolvedIssueKeys(ctx context.Context, tenantID, projectID shared.ID) (map[string]bool, error) {
	rows, err := r.pool.Query(ctx, `SELECT issue_key FROM project_issues
		WHERE tenant_id=$1 AND project_id=$2 AND status IN ('accepted','false_positive','wont_fix')`, tenantID.String(), projectID.String())
	if err != nil {
		return nil, fmt.Errorf("query resolved issue keys: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("scan resolved issue key: %w", err)
		}
		out[key] = true
	}
	return out, rows.Err()
}
