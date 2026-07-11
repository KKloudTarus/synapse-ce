package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// findingCols is the SELECT/RETURNING projection scanned by scanFinding.
const findingCols = `id, engagement_id, title, description, severity, cvss_vector, cwe, status, evidence_score, ` +
	`COALESCE(dedup_key, ''), kev, risk_score, created_at, updated_at, sources, confidence, class, scope, ` +
	`reachability, impact, priority, kind, assignee, version, proposed_by, class_reachability`

// FindingRepository persists findings to PostgreSQL, deduped per engagement.
type FindingRepository struct{ pool *pgxpool.Pool }

// NewFindingRepository returns a repository backed by the given pool.
func NewFindingRepository(pool *pgxpool.Pool) *FindingRepository {
	return &FindingRepository{pool: pool}
}

var _ ports.FindingRepository = (*FindingRepository)(nil)

// Upsert inserts or updates findings, deduped on (engagement_id, dedup_key). On
// conflict it updates the data fields but preserves id, status (triage), assignee,
// and created_at – and bumps version (a re-scan IS a concurrent change) – so human
// triage state is never clobbered.
func (r *FindingRepository) Upsert(ctx context.Context, findings []finding.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, f := range findings {
		// tenant_id '' = the seeded default tenant. Finding READS are tenant-isolated via the
		// tenant-scoped engagement gate; deriving this row's tenant_id from the engagement
		// is a remaining row-level follow-up and does not affect read isolation today.
		if _, err := tx.Exec(ctx,
			`INSERT INTO findings (id, tenant_id, engagement_id, title, description, severity, cvss_vector, cwe, status, evidence_score, dedup_key, kev, risk_score, created_at, updated_at, sources, confidence, class, scope, reachability, impact, priority, kind, assignee, version, proposed_by, class_reachability)
			 VALUES ($1, '', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
			 ON CONFLICT (engagement_id, dedup_key) WHERE dedup_key IS NOT NULL
			 DO UPDATE SET title = EXCLUDED.title, description = EXCLUDED.description,
			               severity = EXCLUDED.severity, cvss_vector = EXCLUDED.cvss_vector, kev = EXCLUDED.kev, risk_score = EXCLUDED.risk_score,
			               sources = EXCLUDED.sources, confidence = EXCLUDED.confidence, class = EXCLUDED.class,
			               scope = EXCLUDED.scope, reachability = EXCLUDED.reachability, impact = EXCLUDED.impact, priority = EXCLUDED.priority,
			               kind = EXCLUDED.kind, class_reachability = EXCLUDED.class_reachability,
			               updated_at = EXCLUDED.updated_at`,
			f.ID.String(), f.EngagementID.String(), f.Title, f.Description, string(f.Severity),
			f.CVSSVector, f.CWE, string(f.Status), f.EvidenceScore, f.DedupKey,
			f.KEV, f.RiskScore, f.Audit.CreatedAt, f.Audit.UpdatedAt, strings.Join(f.Sources, ","), f.Confidence, classOrDefault(f.Class),
			scopeOrDefault(f.Scope), reachOrDefault(f.Reachability), f.Impact, priorityOrDefault(f.Priority), kindOrDefault(string(f.Kind)),
			f.Assignee, versionOrDefault(f.Version), f.ProposedBy, f.ClassReachability); err != nil {
			return fmt.Errorf("upsert finding: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// UpdateStatus sets the triage status with optimistic concurrency: the row is
// updated only if version matches expectedVersion, then version is bumped. On a
// miss it distinguishes ErrConflict (exists, version moved) from ErrNotFound.
func (r *FindingRepository) UpdateStatus(ctx context.Context, engagementID, findingID shared.ID, status finding.Status, expectedVersion int) (finding.Finding, error) {
	f, err := scanFinding(r.pool.QueryRow(ctx,
		`UPDATE findings SET status=$1, version=version+1, updated_at=now()
		 WHERE id=$2 AND engagement_id=$3 AND version=$4
		 RETURNING `+findingCols,
		string(status), findingID.String(), engagementID.String(), expectedVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return finding.Finding{}, r.classifyUpdateMiss(ctx, engagementID, findingID)
	}
	if err != nil {
		return finding.Finding{}, fmt.Errorf("update finding status: %w", err)
	}
	return f, nil
}

// SetAssignee sets the assignee with the same optimistic-concurrency guard.
func (r *FindingRepository) SetAssignee(ctx context.Context, engagementID, findingID shared.ID, assignee string, expectedVersion int) (finding.Finding, error) {
	f, err := scanFinding(r.pool.QueryRow(ctx,
		`UPDATE findings SET assignee=$1, version=version+1, updated_at=now()
		 WHERE id=$2 AND engagement_id=$3 AND version=$4
		 RETURNING `+findingCols,
		assignee, findingID.String(), engagementID.String(), expectedVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return finding.Finding{}, r.classifyUpdateMiss(ctx, engagementID, findingID)
	}
	if err != nil {
		return finding.Finding{}, fmt.Errorf("set finding assignee: %w", err)
	}
	return f, nil
}

// SetEvidenceScore sets a finding's evidence score with the same optimistic-concurrency
// guard as UpdateStatus (the adversarial-verdict path): the row is
// updated only if version matches, then version is bumped. Note the Upsert ON CONFLICT set
// deliberately omits evidence_score, so this is the only path that moves it for an
// already-stored finding.
func (r *FindingRepository) SetEvidenceScore(ctx context.Context, engagementID, findingID shared.ID, score, expectedVersion int) (finding.Finding, error) {
	f, err := scanFinding(r.pool.QueryRow(ctx,
		`UPDATE findings SET evidence_score=$1, version=version+1, updated_at=now()
		 WHERE id=$2 AND engagement_id=$3 AND version=$4
		 RETURNING `+findingCols,
		score, findingID.String(), engagementID.String(), expectedVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return finding.Finding{}, r.classifyUpdateMiss(ctx, engagementID, findingID)
	}
	if err != nil {
		return finding.Finding{}, fmt.Errorf("set finding evidence score: %w", err)
	}
	return f, nil
}

// classifyUpdateMiss maps a no-row optimistic UPDATE to ErrConflict (the finding
// exists but its version moved – lost-update guard) or ErrNotFound.
func (r *FindingRepository) classifyUpdateMiss(ctx context.Context, engagementID, findingID shared.ID) error {
	var exists bool
	if err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM findings WHERE id=$1 AND engagement_id=$2)`,
		findingID.String(), engagementID.String()).Scan(&exists); err != nil {
		return fmt.Errorf("classify update miss: %w", err)
	}
	if exists {
		return fmt.Errorf("finding %s changed since you loaded it: %w", findingID, shared.ErrConflict)
	}
	return fmt.Errorf("finding %s: %w", findingID, shared.ErrNotFound)
}

// ListByEngagement returns the engagement's findings, highest risk first
// (CISA KEV, then EPSS x CVSS, then severity).
func (r *FindingRepository) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+findingCols+`
		 FROM findings WHERE engagement_id=$1
		 ORDER BY priority ASC, kev DESC, risk_score DESC,
		          CASE severity
		            WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		            WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END DESC,
		          title COLLATE "C" ASC, COALESCE(dedup_key,'') COLLATE "C" ASC, id COLLATE "C" ASC`,
		engagementID.String())
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	out := make([]finding.Finding, 0)
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListPublishableByEngagement returns only the engagement's findings that clear the
// evidence gate. It reuses ListByEngagement and the single domain rule
// finding.Publishable, so the publishability policy lives in exactly one place (the
// domain) rather than being re-encoded in SQL.
func (r *FindingRepository) ListPublishableByEngagement(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error) {
	all, err := r.ListByEngagement(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	return finding.Publishable(all), nil
}

// scanFinding scans a findingCols row (pgx.Row or pgx.Rows) into a Finding.
func scanFinding(row rowScanner) (finding.Finding, error) {
	var (
		f                                          finding.Finding
		id, eid, sev, status, dedup, sources, kind string
	)
	if err := row.Scan(&id, &eid, &f.Title, &f.Description, &sev, &f.CVSSVector, &f.CWE,
		&status, &f.EvidenceScore, &dedup, &f.KEV, &f.RiskScore, &f.Audit.CreatedAt, &f.Audit.UpdatedAt,
		&sources, &f.Confidence, &f.Class, &f.Scope, &f.Reachability, &f.Impact, &f.Priority, &kind,
		&f.Assignee, &f.Version, &f.ProposedBy, &f.ClassReachability); err != nil {
		return finding.Finding{}, err
	}
	f.ID = shared.ID(id)
	f.EngagementID = shared.ID(eid)
	f.Severity = shared.Severity(sev)
	f.Status = finding.Status(status)
	f.Kind = finding.Kind(kindOrDefault(kind))
	f.DedupKey = dedup
	f.Sources = splitSources(sources)
	return f, nil
}

// kindOrDefault defaults a legacy/empty kind to sca (older rows predate Kind).
func kindOrDefault(k string) string {
	if k == "" {
		return string(finding.KindSCA)
	}
	return k
}

// classOrDefault defaults a legacy/empty class to third_party.
func classOrDefault(c string) string {
	if c == "" {
		return finding.ClassThirdParty
	}
	return c
}

func scopeOrDefault(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func reachOrDefault(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func priorityOrDefault(p int) int {
	if p <= 0 {
		return 3
	}
	return p
}

func versionOrDefault(v int) int {
	if v <= 0 {
		return 1
	}
	return v
}

// splitSources turns the stored CSV back into a slice (empty -> nil).
func splitSources(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
