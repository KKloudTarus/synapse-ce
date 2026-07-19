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
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ProjectAnalysisProjectionStore = (*ProjectAnalysisStore)(nil)
var _ ports.ProjectHotspotStore = (*ProjectAnalysisStore)(nil)

// SaveWithResultAndHotspots commits the immutable analysis and its projection in
// one PostgreSQL transaction. A projection write failure rolls the analysis back,
// so the scan worker cannot publish a successful analysis without its hotspots.
func (r *ProjectAnalysisStore) SaveWithResultAndHotspots(ctx context.Context, analysis projectanalysis.Analysis, result []byte, candidates []hotspot.Candidate) error {
	items := make([]hotspot.Hotspot, len(candidates))
	for i, candidate := range candidates {
		item, err := hotspot.Project(
			shared.ID(analysis.TenantID),
			shared.ID(analysis.ProjectID),
			analysis.ID,
			analysis.CreatedAt,
			candidate,
		)
		if err != nil {
			return err
		}
		items[i] = item
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
	keys := make([]string, len(items))
	for i, it := range items {
		keys[i] = it.Key
	}

	// Fetch existing hotspots to detect reappearance of fixed hotspots
	existingRows, err := tx.Query(ctx, `SELECT hotspot_key, status, version, last_seen_at FROM project_hotspots WHERE tenant_id=$1 AND project_id=$2 AND hotspot_key = ANY($3) FOR UPDATE`, analysis.TenantID, analysis.ProjectID, keys)
	if err != nil {
		return fmt.Errorf("query existing hotspots: %w", err)
	}
	existingMap := make(map[string]struct {
		Status     hotspot.Status
		Version    int
		LastSeenAt time.Time
	})
	for existingRows.Next() {
		var key, status string
		var version int
		var lastSeenAt time.Time
		if err := existingRows.Scan(&key, &status, &version, &lastSeenAt); err != nil {
			existingRows.Close()
			return fmt.Errorf("scan existing hotspot: %w", err)
		}
		existingMap[key] = struct {
			Status     hotspot.Status
			Version    int
			LastSeenAt time.Time
		}{hotspot.Status(status), version, lastSeenAt}
	}
	existingRows.Close()

	for _, item := range items {
		var reviewEvent *hotspot.ReviewEvent

		if ex, found := existingMap[item.Key]; found {
			// If it's strictly a later analysis (we check LastSeenAt conceptually, but the query uses EXCLUDED > project_hotspots)
			// Wait, if it reappears and the existing status is fixed, AND this analysis is strictly later (which we assume if it's the current one being saved).
			// We only reopen if analysis.CreatedAt is > existing.LastSeenAt.
			if ex.Status == hotspot.StatusFixed && analysis.CreatedAt.After(ex.LastSeenAt) {
				// Reopen
				// generating a deterministic/random ID is tricky here without idGen, let's use analysis.ID + key hash, or just simple uuid?
				// Wait, the interface for SaveWithResultAndHotspots doesn't pass IDGenerator. We can use shared.ID(...) from a random uuid, but since we don't have idGen, we can just use sha256 or uuid string.
				// Wait, the analysis ID is unique, so event ID can be DeterministicID(analysis.ID, item.ID, "reopen").
				eID := hotspot.DeterministicID(shared.ID(analysis.ID), item.ID, "reopen")

				// Simulate transition
				prevVersion := ex.Version
				newVersion := ex.Version + 1
				newStatus := hotspot.StatusToReview

				item.Status = newStatus
				item.Version = newVersion

				reviewEvent = &hotspot.ReviewEvent{
					ID:              eID,
					TenantID:        item.TenantID,
					ProjectID:       item.ProjectID,
					HotspotID:       item.ID,
					From:            hotspot.StatusFixed,
					To:              hotspot.StatusToReview,
					Actor:           "system:project-analysis",
					Rationale:       "Automatically reopened: hotspot detected in later analysis.",
					PreviousVersion: prevVersion,
					Version:         newVersion,
					CreatedAt:       analysis.CreatedAt,
				}
			}
		}

		if err := tx.QueryRow(ctx, `INSERT INTO project_hotspots
			(id, tenant_id, project_id, hotspot_key, finding_identity, rule_key, title, description, severity, finding_kind, cwe, location,
			 status, version, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$17,$18)
			ON CONFLICT (tenant_id, project_id, hotspot_key) DO UPDATE SET
				finding_identity = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.finding_identity ELSE project_hotspots.finding_identity END,
				first_seen_analysis_id = CASE WHEN (EXCLUDED.first_seen_at, EXCLUDED.first_seen_analysis_id) < (project_hotspots.first_seen_at, project_hotspots.first_seen_analysis_id) THEN EXCLUDED.first_seen_analysis_id ELSE project_hotspots.first_seen_analysis_id END,
				first_seen_at = CASE WHEN (EXCLUDED.first_seen_at, EXCLUDED.first_seen_analysis_id) < (project_hotspots.first_seen_at, project_hotspots.first_seen_analysis_id) THEN EXCLUDED.first_seen_at ELSE project_hotspots.first_seen_at END,
				created_at = CASE WHEN (EXCLUDED.first_seen_at, EXCLUDED.first_seen_analysis_id) < (project_hotspots.first_seen_at, project_hotspots.first_seen_analysis_id) THEN EXCLUDED.created_at ELSE project_hotspots.created_at END,
				rule_key = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.rule_key ELSE project_hotspots.rule_key END,
				title = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.title ELSE project_hotspots.title END,
				description = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.description ELSE project_hotspots.description END,
				severity = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.severity ELSE project_hotspots.severity END,
				finding_kind = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.finding_kind ELSE project_hotspots.finding_kind END,
				cwe = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.cwe ELSE project_hotspots.cwe END,
				location = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.location ELSE project_hotspots.location END,
				last_seen_analysis_id = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.last_seen_analysis_id ELSE project_hotspots.last_seen_analysis_id END,
				last_seen_at = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.last_seen_at ELSE project_hotspots.last_seen_at END,
				updated_at = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.updated_at ELSE project_hotspots.updated_at END,
				status = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) AND EXCLUDED.version > project_hotspots.version THEN EXCLUDED.status ELSE project_hotspots.status END,
				version = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) AND EXCLUDED.version > project_hotspots.version THEN EXCLUDED.version ELSE project_hotspots.version END
			RETURNING status, version, first_seen_analysis_id, last_seen_analysis_id`,
			item.ID, item.TenantID, item.ProjectID, item.Key, item.FindingIdentity, item.RuleKey, item.Title, item.Description,
			item.Severity, item.Kind, item.CWE, item.Location, item.Status, item.Version, item.FirstSeenAnalysisID,
			item.LastSeenAnalysisID, item.FirstSeenAt, item.LastSeenAt).Scan(&item.Status, &item.Version, &item.FirstSeenAnalysisID, &item.LastSeenAnalysisID); err != nil {
			return fmt.Errorf("upsert project hotspot: %w", err)
		}

		if reviewEvent != nil {
			if _, err := tx.Exec(ctx, `INSERT INTO project_hotspot_review_events 
				(id, tenant_id, project_id, hotspot_id, from_status, to_status, actor, rationale, previous_version, version, created_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT DO NOTHING`,
				reviewEvent.ID.String(), reviewEvent.TenantID.String(), reviewEvent.ProjectID.String(), reviewEvent.HotspotID.String(),
				reviewEvent.From, reviewEvent.To, reviewEvent.Actor, reviewEvent.Rationale, reviewEvent.PreviousVersion, reviewEvent.Version, reviewEvent.CreatedAt); err != nil {
				return fmt.Errorf("insert review event: %w", err)
			}
		}

		actualIsNew := item.FirstSeenAnalysisID == analysis.ID && item.LastSeenAnalysisID == analysis.ID
		if reviewEvent != nil {
			actualIsNew = true
		}

		if _, err := tx.Exec(ctx, `INSERT INTO project_analysis_hotspots
			(tenant_id, project_id, analysis_id, hotspot_id, is_new, status_at_analysis, version_at_analysis)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
			item.TenantID, item.ProjectID, analysis.ID, item.ID, actualIsNew, item.Status, item.Version); err != nil {
			return fmt.Errorf("insert project analysis hotspot: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit project analysis transaction: %w", err)
	}
	return nil
}

func (r *ProjectAnalysisStore) ListHotspots(ctx context.Context, tenantID, projectID shared.ID, filter hotspot.ListFilter) (hotspot.Page, error) {
	where, args, joins := hotspotWhere(tenantID, projectID, filter, true)
	limit := filter.Limit
	if limit <= 0 {
		limit = 25
	}
	args = append(args, limit+1)
	query := `SELECT ph.id, ph.tenant_id, ph.project_id, ph.hotspot_key, ph.finding_identity, ph.rule_key, ph.title, ph.description, ph.severity, ph.finding_kind, ph.cwe, ph.location,
		ph.status, ph.version, ph.first_seen_analysis_id, ph.last_seen_analysis_id, ph.first_seen_at, ph.last_seen_at, ph.created_at, ph.updated_at, ph.last_reviewed_by, ph.last_reviewed_at
		FROM project_hotspots ph ` + joins + ` WHERE ` + where + ` ORDER BY ph.last_seen_at DESC, ph.id COLLATE "C" DESC LIMIT $` + fmt.Sprint(len(args))
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return hotspot.Page{}, fmt.Errorf("list project hotspots: %w", err)
	}
	defer rows.Close()
	items := make([]hotspot.Hotspot, 0, limit+1)
	for rows.Next() {
		item, err := scanHotspot(rows)
		if err != nil {
			return hotspot.Page{}, fmt.Errorf("scan project hotspot: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return hotspot.Page{}, err
	}
	page := hotspot.Page{}
	if len(items) > limit {
		last := items[limit-1]
		page.Next = &hotspot.Cursor{BeforeLastSeenAt: last.LastSeenAt, BeforeID: last.ID}
		items = items[:limit]
	}
	page.Items = items

	facetWhere, facetArgs, facetJoins := hotspotWhere(tenantID, projectID, filter, false)

	// Query Summary
	var total, reviewed int
	err = r.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE ph.status IN ('acknowledged', 'fixed', 'safe')) FROM project_hotspots ph `+facetJoins+` WHERE `+facetWhere, facetArgs...).Scan(&total, &reviewed)
	if err != nil {
		return hotspot.Page{}, fmt.Errorf("summary project hotspots: %w", err)
	}

	summary, _ := hotspot.NewSummary(total, reviewed)
	page.Summary = summary

	facetRows, err := r.pool.Query(ctx, `SELECT 'status' as kind, ph.status as value, count(*) FROM project_hotspots ph `+facetJoins+` WHERE `+facetWhere+` GROUP BY ph.status
		UNION ALL SELECT 'rule', ph.rule_key, count(*) FROM project_hotspots ph `+facetJoins+` WHERE `+facetWhere+` GROUP BY ph.rule_key
		UNION ALL SELECT 'severity', ph.severity, count(*) FROM project_hotspots ph `+facetJoins+` WHERE `+facetWhere+` GROUP BY ph.severity`, facetArgs...)
	if err != nil {
		return hotspot.Page{}, fmt.Errorf("facet project hotspots: %w", err)
	}
	defer facetRows.Close()
	page.Facets = hotspot.Facets{Statuses: map[string]int{}, RuleKeys: map[string]int{}, Severities: map[string]int{}}
	for facetRows.Next() {
		var kind, value string
		var count int
		if err := facetRows.Scan(&kind, &value, &count); err != nil {
			return hotspot.Page{}, fmt.Errorf("scan project hotspot facet: %w", err)
		}
		switch kind {
		case "status":
			page.Facets.Statuses[value] = count
		case "rule":
			page.Facets.RuleKeys[value] = count
		case "severity":
			page.Facets.Severities[value] = count
		}
	}
	return page, facetRows.Err()
}

func hotspotSearchPattern(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	value = strings.ReplaceAll(value, `_`, `\_`)
	return "%" + value + "%"
}

func hotspotWhere(tenantID, projectID shared.ID, filter hotspot.ListFilter, cursor bool) (string, []any, string) {
	args := []any{tenantID.String(), projectID.String()}
	parts := []string{"ph.tenant_id = $1", "ph.project_id = $2"}
	add := func(part string, value any) {
		args = append(args, value)
		parts = append(parts, fmt.Sprintf(part, len(args)))
	}
	if filter.Status != nil {
		add("ph.status = $%d", string(*filter.Status))
	}
	if strings.TrimSpace(filter.RuleKey) != "" {
		add("ph.rule_key = $%d", strings.TrimSpace(filter.RuleKey))
	}
	if filter.Severity != nil {
		add("ph.severity = $%d", string(*filter.Severity))
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		searchArg := len(args) + 1
		pattern := hotspotSearchPattern(search)

		args = append(args, pattern, pattern, pattern, pattern, pattern)
		parts = append(parts, fmt.Sprintf("(ph.hotspot_key ILIKE $%d OR ph.rule_key ILIKE $%d OR ph.title ILIKE $%d OR ph.description ILIKE $%d OR ph.location ILIKE $%d)", searchArg, searchArg+1, searchArg+2, searchArg+3, searchArg+4))
	}

	joins := ""

	if cursor && !filter.BeforeLastSeenAt.IsZero() {
		args = append(args, filter.BeforeLastSeenAt, filter.BeforeID.String())
		at, id := len(args)-1, len(args)
		parts = append(parts, fmt.Sprintf(`(ph.last_seen_at < $%d OR (ph.last_seen_at = $%d AND ph.id COLLATE "C" < $%d))`, at, at, id))
	}
	return strings.Join(parts, " AND "), args, joins
}
func (r *ProjectAnalysisStore) GetHotspot(ctx context.Context, tenantID, projectID, hotspotID shared.ID) (hotspot.Hotspot, error) {
	row := r.pool.QueryRow(ctx, `SELECT id, tenant_id, project_id, hotspot_key, finding_identity, rule_key, title, description, severity, finding_kind, cwe, location,
		status, version, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at, last_reviewed_by, last_reviewed_at
		FROM project_hotspots WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, tenantID.String(), projectID.String(), hotspotID.String())
	item, err := scanHotspot(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return hotspot.Hotspot{}, shared.ErrNotFound
	}
	if err != nil {
		return hotspot.Hotspot{}, fmt.Errorf("get project hotspot: %w", err)
	}
	return item, nil
}

func scanHotspot(row rowScanner) (hotspot.Hotspot, error) {
	var item hotspot.Hotspot
	var tenantID, projectID, status, kind, severity string
	var createdAt, updatedAt time.Time
	var lastReviewedBy *string
	var lastReviewedAt *time.Time
	if err := row.Scan(&item.ID, &tenantID, &projectID, &item.Key, &item.FindingIdentity, &item.RuleKey, &item.Title, &item.Description,
		&severity, &kind, &item.CWE, &item.Location, &status, &item.Version, &item.FirstSeenAnalysisID, &item.LastSeenAnalysisID,
		&item.FirstSeenAt, &item.LastSeenAt, &createdAt, &updatedAt, &lastReviewedBy, &lastReviewedAt); err != nil {
		return hotspot.Hotspot{}, err
	}
	if lastReviewedBy != nil {
		item.LastReviewedBy = *lastReviewedBy
	}
	item.LastReviewedAt = lastReviewedAt
	item.TenantID, item.ProjectID = shared.ID(tenantID), shared.ID(projectID)
	item.Severity, item.Kind, item.Status = shared.Severity(severity), finding.Kind(kind), hotspot.Status(status)
	item.Audit = shared.Audit{CreatedAt: createdAt, UpdatedAt: updatedAt}
	return item, nil
}

func (r *ProjectAnalysisStore) TransitionHotspot(ctx context.Context, cmd hotspot.TransitionCommand) (hotspot.Hotspot, hotspot.ReviewEvent, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, fmt.Errorf("begin transition tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the row
	row := tx.QueryRow(ctx, `SELECT id, tenant_id, project_id, hotspot_key, finding_identity, rule_key, title, description, severity, finding_kind, cwe, location,
		status, version, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at, last_reviewed_by, last_reviewed_at
		FROM project_hotspots WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, cmd.TenantID.String(), cmd.ProjectID.String(), cmd.HotspotID.String())
	item, err := scanHotspot(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, shared.ErrNotFound
	}
	if err != nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, fmt.Errorf("get hotspot for update: %w", err)
	}

	updated, event, err := item.Transition(cmd.To, cmd.Actor, cmd.Rationale, cmd.ExpectedVersion, cmd.EventID, time.Now())
	if err != nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, err
	}

	// Update hotspot
	if _, err := tx.Exec(ctx, `UPDATE project_hotspots SET status=$1, version=$2, updated_at=$3, last_reviewed_by=$4, last_reviewed_at=$5 WHERE id=$6`,
		updated.Status, updated.Version, updated.Audit.UpdatedAt, updated.LastReviewedBy, updated.LastReviewedAt, updated.ID.String()); err != nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, fmt.Errorf("update hotspot status: %w", err)
	}

	// Insert event
	if _, err := tx.Exec(ctx, `INSERT INTO project_hotspot_review_events 
		(id, tenant_id, project_id, hotspot_id, from_status, to_status, actor, rationale, previous_version, version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		event.ID.String(), event.TenantID.String(), event.ProjectID.String(), event.HotspotID.String(),
		event.From, event.To, event.Actor, event.Rationale, event.PreviousVersion, event.Version, event.CreatedAt); err != nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, fmt.Errorf("insert review event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return hotspot.Hotspot{}, hotspot.ReviewEvent{}, fmt.Errorf("commit transition tx: %w", err)
	}

	return updated, event, nil
}

func (r *ProjectAnalysisStore) HotspotHistory(ctx context.Context, tenantID, projectID, hotspotID shared.ID) ([]hotspot.ReviewEvent, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, tenant_id, project_id, hotspot_id, from_status, to_status, actor, rationale, previous_version, version, created_at
		FROM project_hotspot_review_events 
		WHERE tenant_id=$1 AND project_id=$2 AND hotspot_id=$3 
		ORDER BY version DESC, id COLLATE "C" DESC`, tenantID.String(), projectID.String(), hotspotID.String())
	if err != nil {
		return nil, fmt.Errorf("query review events: %w", err)
	}
	defer rows.Close()

	var events []hotspot.ReviewEvent
	for rows.Next() {
		var e hotspot.ReviewEvent
		var id, tID, pID, hID, from, to string
		if err := rows.Scan(&id, &tID, &pID, &hID, &from, &to, &e.Actor, &e.Rationale, &e.PreviousVersion, &e.Version, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan review event: %w", err)
		}
		e.ID = shared.ID(id)
		e.TenantID = shared.ID(tID)
		e.ProjectID = shared.ID(pID)
		e.HotspotID = shared.ID(hID)
		e.From = hotspot.Status(from)
		e.To = hotspot.Status(to)
		events = append(events, e)
	}
	return events, rows.Err()
}

func (r *ProjectAnalysisStore) ListAnalysisHotspots(ctx context.Context, tenantID, projectID, analysisID shared.ID, lens hotspot.Lens, filter hotspot.ListFilter) (hotspot.Page, hotspot.Summary, error) {
	// First compute summary
	summary, err := r.CurrentAnalysisHotspotSummary(ctx, tenantID, projectID, analysisID, lens)
	if err != nil {
		return hotspot.Page{}, hotspot.Summary{}, err
	}

	// We join project_hotspots with project_analysis_hotspots.
	// Since we need to use the mutable status for ListHotspots (as required by "Overview updates immediately after a review"),
	// the list returns the CURRENT state of hotspots that were present in that analysis.
	// We filter by `is_new` if lens == NewCode.

	args := []any{tenantID.String(), projectID.String(), analysisID.String()}
	parts := []string{"h.tenant_id = $1", "h.project_id = $2", "ah.analysis_id = $3"}
	add := func(part string, value any) {
		args = append(args, value)
		parts = append(parts, fmt.Sprintf(part, len(args)))
	}

	if lens == hotspot.LensNewCode {
		parts = append(parts, "ah.is_new = true")
	}

	if filter.Status != nil {
		add("h.status = $%d", string(*filter.Status))
	}
	if filter.Severity != nil {
		add("h.severity = $%d", string(*filter.Severity))
	}
	if filter.RuleKey != "" {
		add("h.rule_key = $%d", filter.RuleKey)
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		searchArg := len(args) + 1
		pattern := hotspotSearchPattern(search)

		args = append(args, pattern, pattern, pattern, pattern, pattern)
		parts = append(parts, fmt.Sprintf(
			`(h.hotspot_key ILIKE $%d OR
			  h.rule_key ILIKE $%d OR
			  h.title ILIKE $%d OR
			  h.description ILIKE $%d OR
			  h.location ILIKE $%d)`,
			searchArg,
			searchArg+1,
			searchArg+2,
			searchArg+3,
			searchArg+4,
		))
	}

	facetWhere := strings.Join(parts, " AND ")
	facetArgs := append([]any(nil), args...)

	if !filter.BeforeLastSeenAt.IsZero() {
		args = append(
			args,
			filter.BeforeLastSeenAt,
			filter.BeforeID.String(),
		)
		atArg := len(args) - 1
		idArg := len(args)

		parts = append(parts, fmt.Sprintf(
			`(h.last_seen_at < $%d OR
			  (h.last_seen_at = $%d AND h.id COLLATE "C" < $%d))`,
			atArg,
			atArg,
			idArg,
		))
	}

	listWhere := strings.Join(parts, " AND ")
	limit := filter.Limit
	if limit <= 0 {
		limit = 25
	}

	query := `SELECT h.id, h.tenant_id, h.project_id, h.hotspot_key, h.finding_identity, h.rule_key, h.title, h.description, h.severity, h.finding_kind, h.cwe, h.location,
		h.status, h.version, h.first_seen_analysis_id, h.last_seen_analysis_id, h.first_seen_at, h.last_seen_at, h.created_at, h.updated_at, h.last_reviewed_by, h.last_reviewed_at
		FROM project_hotspots h
		JOIN project_analysis_hotspots ah ON h.id = ah.hotspot_id
		WHERE ` + listWhere + ` ORDER BY h.last_seen_at DESC, h.id COLLATE "C" DESC LIMIT $` + fmt.Sprint(len(args)+1)

	args = append(args, limit+1)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return hotspot.Page{}, hotspot.Summary{}, fmt.Errorf("list analysis hotspots: %w", err)
	}
	defer rows.Close()

	var items []hotspot.Hotspot
	for rows.Next() {
		item, err := scanHotspot(rows)
		if err != nil {
			return hotspot.Page{}, hotspot.Summary{}, fmt.Errorf("scan analysis hotspot: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return hotspot.Page{}, hotspot.Summary{}, err
	}

	page := hotspot.Page{}
	if len(items) > limit {
		last := items[limit-1]
		page.Next = &hotspot.Cursor{BeforeLastSeenAt: last.LastSeenAt, BeforeID: last.ID}
		items = items[:limit]
	}
	page.Items = items

	// Facets (current statuses, etc)
	facetRows, err := r.pool.Query(ctx, `SELECT 'status', h.status, count(*) FROM project_hotspots h JOIN project_analysis_hotspots ah ON h.id = ah.hotspot_id WHERE `+facetWhere+` GROUP BY h.status
		UNION ALL SELECT 'rule', h.rule_key, count(*) FROM project_hotspots h JOIN project_analysis_hotspots ah ON h.id = ah.hotspot_id WHERE `+facetWhere+` GROUP BY h.rule_key
		UNION ALL SELECT 'severity', h.severity, count(*) FROM project_hotspots h JOIN project_analysis_hotspots ah ON h.id = ah.hotspot_id WHERE `+facetWhere+` GROUP BY h.severity`, facetArgs...)
	if err != nil {
		return hotspot.Page{}, hotspot.Summary{}, fmt.Errorf("facet analysis hotspots: %w", err)
	}
	defer facetRows.Close()
	page.Facets = hotspot.Facets{Statuses: map[string]int{}, RuleKeys: map[string]int{}, Severities: map[string]int{}}
	for facetRows.Next() {
		var kind, value string
		var count int
		if err := facetRows.Scan(&kind, &value, &count); err != nil {
			return hotspot.Page{}, hotspot.Summary{}, fmt.Errorf("scan analysis hotspot facet: %w", err)
		}
		switch kind {
		case "status":
			page.Facets.Statuses[value] = count
		case "rule":
			page.Facets.RuleKeys[value] = count
		case "severity":
			page.Facets.Severities[value] = count
		}
	}

	return page, summary, nil
}

func (r *ProjectAnalysisStore) CurrentAnalysisHotspotSummary(ctx context.Context, tenantID, projectID, analysisID shared.ID, lens hotspot.Lens) (hotspot.Summary, error) {
	// Query current statuses of hotspots that were in the analysis
	q := `SELECT h.status FROM project_hotspots h JOIN project_analysis_hotspots ah ON h.id = ah.hotspot_id WHERE h.tenant_id=$1 AND h.project_id=$2 AND ah.analysis_id=$3`
	if lens == hotspot.LensNewCode {
		q += ` AND ah.is_new = true`
	}

	rows, err := r.pool.Query(ctx, q, tenantID.String(), projectID.String(), analysisID.String())
	if err != nil {
		return hotspot.Summary{}, fmt.Errorf("query analysis hotspot summary: %w", err)
	}
	defer rows.Close()

	total := 0
	reviewed := 0

	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			return hotspot.Summary{}, err
		}
		total++
		if hotspot.Status(status).Reviewed() {
			reviewed++
		}
	}

	if err := rows.Err(); err != nil {
		return hotspot.Summary{}, err
	}

	return hotspot.NewSummary(total, reviewed)
}
