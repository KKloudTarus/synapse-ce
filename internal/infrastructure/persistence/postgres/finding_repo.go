package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	`reachability, impact, priority, kind, assignee, version, proposed_by, class_reachability, rule_key, ` +
	`COALESCE(advisory_id, ''), COALESCE(occurrence_id, ''), COALESCE(component_fingerprint, ''), ` +
	`COALESCE(fixed_version, ''), COALESCE(detection_state, ''), COALESCE(risk_assessment_id, ''), evaluated_at, data_flow`

// FindingRepository persists findings to PostgreSQL, deduped per engagement.
type FindingRepository struct{ pool *pgxpool.Pool }

// NewFindingRepository returns a repository backed by the given pool.
func NewFindingRepository(pool *pgxpool.Pool) *FindingRepository {
	return &FindingRepository{pool: pool}
}

// ClaimFindingProjection atomically reserves the SAST or legacy runtime DAST projection mode for a judgment.
func (r *FindingRepository) ClaimFindingProjection(ctx context.Context, tenantID, engagementID, judgmentID shared.ID, mode ports.FindingProjectionMode) error {
	if tenantID == "" || engagementID == "" || judgmentID == "" || mode != ports.FindingProjectionSAST && mode != ports.FindingProjectionDAST {
		return fmt.Errorf("%w: invalid finding projection claim", shared.ErrValidation)
	}
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var claimed ports.FindingProjectionMode
		err := tx.QueryRow(ctx, `
			INSERT INTO finding_projection_claims (tenant_id, engagement_id, judgment_id, mode)
			SELECT $1, $2, $3, $4
			WHERE EXISTS (
				SELECT 1 FROM engagements
				WHERE id = $2 AND COALESCE(NULLIF(tenant_id, ''), 'default') = $1
			)
			ON CONFLICT (tenant_id, engagement_id, judgment_id)
			DO UPDATE SET mode = finding_projection_claims.mode
			RETURNING mode`, tenantID.String(), engagementID.String(), judgmentID.String(), string(mode)).Scan(&claimed)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("claim finding projection: %w", err)
		}
		if claimed != mode {
			return fmt.Errorf("%w: judgment already projected as %s", shared.ErrConflict, claimed)
		}
		return nil
	})
}

var _ ports.FindingRepository = (*FindingRepository)(nil)

// Upsert inserts or updates findings, deduped on (engagement_id, dedup_key). On
// conflict it updates machine-owned data, preserves id, status (triage), assignee,
// and created_at, and bumps version only when machine-owned data changes.
func (r *FindingRepository) Upsert(ctx context.Context, findings []finding.Finding) error {
	if err := validateFindingBatch(findings); err != nil {
		return err
	}
	if len(findings) == 0 {
		return nil
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		for _, f := range findings {
			dataFlow, err := findingDataFlowJSON(f.DataFlow)
			if err != nil {
				return fmt.Errorf("encode finding data flow: %w", err)
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO findings (id, tenant_id, engagement_id, title, description, severity, cvss_vector, cwe, status, evidence_score, dedup_key, kev, risk_score, created_at, updated_at, sources, confidence, class, scope, reachability, impact, priority, kind, assignee, version, proposed_by, class_reachability, rule_key, advisory_id, occurrence_id, component_fingerprint, fixed_version, detection_state, risk_assessment_id, evaluated_at, data_flow)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36)
			 ON CONFLICT (engagement_id, dedup_key) WHERE dedup_key IS NOT NULL
			 DO UPDATE SET title = EXCLUDED.title, description = EXCLUDED.description,
				               severity = EXCLUDED.severity, cvss_vector = EXCLUDED.cvss_vector, kev = EXCLUDED.kev, risk_score = EXCLUDED.risk_score,
				               sources = EXCLUDED.sources, confidence = EXCLUDED.confidence, class = EXCLUDED.class,
				               scope = EXCLUDED.scope, reachability = EXCLUDED.reachability, impact = EXCLUDED.impact,
				               kind = EXCLUDED.kind, class_reachability = EXCLUDED.class_reachability,
				               rule_key = EXCLUDED.rule_key, advisory_id = EXCLUDED.advisory_id, occurrence_id = EXCLUDED.occurrence_id,
				               component_fingerprint = EXCLUDED.component_fingerprint, fixed_version = EXCLUDED.fixed_version,
				               detection_state = EXCLUDED.detection_state, risk_assessment_id = EXCLUDED.risk_assessment_id,
			               evaluated_at = EXCLUDED.evaluated_at, data_flow = EXCLUDED.data_flow, version = findings.version + 1, updated_at = EXCLUDED.updated_at
			 WHERE findings.title IS DISTINCT FROM EXCLUDED.title
			    OR findings.description IS DISTINCT FROM EXCLUDED.description
			    OR findings.severity IS DISTINCT FROM EXCLUDED.severity
			    OR findings.cvss_vector IS DISTINCT FROM EXCLUDED.cvss_vector
			    OR findings.kev IS DISTINCT FROM EXCLUDED.kev
			    OR findings.risk_score IS DISTINCT FROM EXCLUDED.risk_score
			    OR findings.sources IS DISTINCT FROM EXCLUDED.sources
			    OR findings.confidence IS DISTINCT FROM EXCLUDED.confidence
				    OR findings.class IS DISTINCT FROM EXCLUDED.class
				    OR findings.scope IS DISTINCT FROM EXCLUDED.scope
				    OR findings.reachability IS DISTINCT FROM EXCLUDED.reachability
				    OR findings.impact IS DISTINCT FROM EXCLUDED.impact
				    OR findings.kind IS DISTINCT FROM EXCLUDED.kind
			    OR findings.class_reachability IS DISTINCT FROM EXCLUDED.class_reachability
				OR findings.rule_key IS DISTINCT FROM EXCLUDED.rule_key
				OR findings.advisory_id IS DISTINCT FROM EXCLUDED.advisory_id
				OR findings.occurrence_id IS DISTINCT FROM EXCLUDED.occurrence_id
				OR findings.component_fingerprint IS DISTINCT FROM EXCLUDED.component_fingerprint
				OR findings.fixed_version IS DISTINCT FROM EXCLUDED.fixed_version
				    OR findings.detection_state IS DISTINCT FROM EXCLUDED.detection_state
				    OR findings.risk_assessment_id IS DISTINCT FROM EXCLUDED.risk_assessment_id
				    OR findings.evaluated_at IS DISTINCT FROM EXCLUDED.evaluated_at
				    OR findings.data_flow IS DISTINCT FROM EXCLUDED.data_flow`,
				f.ID.String(), tenantID.String(), f.EngagementID.String(), f.Title, f.Description, string(f.Severity),
				f.CVSSVector, f.CWE, string(f.Status), f.EvidenceScore, f.DedupKey,
				f.KEV, f.RiskScore, f.Audit.CreatedAt, f.Audit.UpdatedAt, strings.Join(f.Sources, ","), f.Confidence, classOrDefault(f.Class),
				scopeOrDefault(f.Scope), reachOrDefault(f.Reachability), f.Impact, priorityOrDefault(f.Priority), kindOrDefault(string(f.Kind)),
				f.Assignee, versionOrDefault(f.Version), f.ProposedBy, f.ClassReachability, f.RuleKey,
				f.AdvisoryID, nullableFindingID(f.OccurrenceID), f.ComponentFingerprint, f.FixedVersion, f.DetectionState,
				nullableFindingID(f.RiskAssessmentID), f.EvaluatedAt, dataFlow); err != nil {
				return fmt.Errorf("upsert finding: %w", err)
			}
		}
		return nil
	})
}

// UpdateStatus sets the triage status with optimistic concurrency: the row is
// updated only if version matches expectedVersion, then version is bumped. On a
// miss it distinguishes ErrConflict (exists, version moved) from ErrNotFound.
func (r *FindingRepository) UpdateStatus(ctx context.Context, engagementID, findingID shared.ID, status finding.Status, expectedVersion int) (out finding.Finding, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		out, err = scanFinding(tx.QueryRow(ctx, `UPDATE findings SET status=$1, version=version+1, updated_at=now() WHERE id=$2 AND engagement_id=$3 AND version=$4 RETURNING `+findingCols, string(status), findingID.String(), engagementID.String(), expectedVersion))
		if errors.Is(err, pgx.ErrNoRows) {
			return classifyFindingUpdateMiss(ctx, tx, engagementID, findingID)
		}
		if err != nil {
			return fmt.Errorf("update finding status: %w", err)
		}
		return nil
	})
	return out, err
}

// SetAssignee sets the assignee with the same optimistic-concurrency guard.
func (r *FindingRepository) SetAssignee(ctx context.Context, engagementID, findingID shared.ID, assignee string, expectedVersion int) (out finding.Finding, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		out, err = scanFinding(tx.QueryRow(ctx, `UPDATE findings SET assignee=$1, version=version+1, updated_at=now() WHERE id=$2 AND engagement_id=$3 AND version=$4 RETURNING `+findingCols, assignee, findingID.String(), engagementID.String(), expectedVersion))
		if errors.Is(err, pgx.ErrNoRows) {
			return classifyFindingUpdateMiss(ctx, tx, engagementID, findingID)
		}
		if err != nil {
			return fmt.Errorf("set finding assignee: %w", err)
		}
		return nil
	})
	return out, err
}

// SetEvidenceScore sets a finding's evidence score with the same optimistic-concurrency
// guard as UpdateStatus (the adversarial-verdict path): the row is
// updated only if version matches, then version is bumped. Note the Upsert ON CONFLICT set
// deliberately omits evidence_score, so this is the only path that moves it for an
// already-stored finding.
func (r *FindingRepository) SetEvidenceScore(ctx context.Context, engagementID, findingID shared.ID, score, expectedVersion int) (out finding.Finding, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		out, err = scanFinding(tx.QueryRow(ctx, `UPDATE findings SET evidence_score=$1, version=version+1, updated_at=now() WHERE id=$2 AND engagement_id=$3 AND version=$4 RETURNING `+findingCols, score, findingID.String(), engagementID.String(), expectedVersion))
		if errors.Is(err, pgx.ErrNoRows) {
			return classifyFindingUpdateMiss(ctx, tx, engagementID, findingID)
		}
		if err != nil {
			return fmt.Errorf("set finding evidence score: %w", err)
		}
		return nil
	})
	return out, err
}

// classifyUpdateMiss maps a no-row optimistic UPDATE to ErrConflict (the finding
// exists but its version moved – lost-update guard) or ErrNotFound.
func classifyFindingUpdateMiss(ctx context.Context, tx pgx.Tx, engagementID, findingID shared.ID) error {
	var exists bool
	if err := tx.QueryRow(ctx,
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
// SummarizeVulnerabilitiesByEngagements aggregates SCA vulnerability findings per engagement in one
// GROUP BY, so a list over thousands of contexts never loads their finding rows.
func (r *FindingRepository) SummarizeVulnerabilitiesByEngagements(ctx context.Context, engagementIDs []shared.ID) (map[shared.ID]ports.VulnerabilitySummary, error) {
	out := make(map[shared.ID]ports.VulnerabilitySummary, len(engagementIDs))
	if len(engagementIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(engagementIDs))
	for i, id := range engagementIDs {
		ids[i] = id.String()
		out[id] = ports.VulnerabilitySummary{}
	}
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
		SELECT engagement_id, severity, count(*),
		       count(*) FILTER (WHERE COALESCE(fixed_version,'') <> ''),
		       count(*) FILTER (WHERE kev)
		FROM findings
		WHERE engagement_id = ANY($1)
		  AND (kind = '' OR kind = 'sca' OR kind IS NULL)
		  AND (dedup_key IS NULL OR dedup_key NOT LIKE 'license:%')
		GROUP BY engagement_id, severity`, ids)
		if err != nil {
			return fmt.Errorf("summarize findings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var eng, severity string
			var total, fixable, kev int
			if err := rows.Scan(&eng, &severity, &total, &fixable, &kev); err != nil {
				return fmt.Errorf("scan finding summary: %w", err)
			}
			sum := out[shared.ID(eng)]
			for i := 0; i < total; i++ {
				sum.Add(shared.Severity(severity), i < fixable, i < kev)
			}
			out[shared.ID(eng)] = sum
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *FindingRepository) ListByEngagement(ctx context.Context, engagementID shared.ID) (out []finding.Finding, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+findingCols+`
		 FROM findings f WHERE f.engagement_id=$1
			 AND (f.kind <> 'cloud_posture' OR EXISTS (
			   SELECT 1 FROM cspm_observations o
			   WHERE o.tenant_id=f.tenant_id AND o.engagement_id=f.engagement_id
			     AND o.observation_kind='finding' AND o.object_id=f.id AND o.active
			 ))
		 ORDER BY priority ASC, kev DESC, risk_score DESC,
		          CASE severity
		            WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		            WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END DESC,
		          title COLLATE "C" ASC, COALESCE(dedup_key,'') COLLATE "C" ASC, id COLLATE "C" ASC`,
			engagementID.String())
		if err != nil {
			return fmt.Errorf("list findings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			f, err := scanFinding(rows)
			if err != nil {
				return fmt.Errorf("scan finding: %w", err)
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
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

// GetByEngagementAndID loads a single finding by engagement and finding ID.
// Returns shared.ErrNotFound if no such finding exists in the engagement.
func (r *FindingRepository) GetByEngagementAndID(ctx context.Context, engagementID, findingID shared.ID) (finding.Finding, error) {
	var f finding.Finding
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT `+findingCols+` FROM findings WHERE engagement_id=$1 AND id=$2`,
			engagementID.String(), findingID.String(),
		)
		var scanErr error
		f, scanErr = scanFinding(row)
		return scanErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return finding.Finding{}, fmt.Errorf("finding %s in engagement %s: %w", findingID, engagementID, shared.ErrNotFound)
	}
	if err != nil {
		return finding.Finding{}, fmt.Errorf("get finding: %w", err)
	}
	return f, nil
}

// scanFinding scans a findingCols row (pgx.Row or pgx.Rows) into a Finding.
func scanFinding(row rowScanner) (finding.Finding, error) {
	var (
		f                                                                                              finding.Finding
		id, eid, sev, status, dedup, sources, kind                                                     string
		advisoryID, occurrenceID, componentFingerprint, fixedVersion, detectionState, riskAssessmentID string
		dataFlowJSON                                                                                   []byte
	)
	if err := row.Scan(&id, &eid, &f.Title, &f.Description, &sev, &f.CVSSVector, &f.CWE,
		&status, &f.EvidenceScore, &dedup, &f.KEV, &f.RiskScore, &f.Audit.CreatedAt, &f.Audit.UpdatedAt,
		&sources, &f.Confidence, &f.Class, &f.Scope, &f.Reachability, &f.Impact, &f.Priority, &kind,
		&f.Assignee, &f.Version, &f.ProposedBy, &f.ClassReachability, &f.RuleKey,
		&advisoryID, &occurrenceID, &componentFingerprint, &fixedVersion, &detectionState, &riskAssessmentID, &f.EvaluatedAt, &dataFlowJSON); err != nil {
		return finding.Finding{}, err
	}
	f.ID = shared.ID(id)
	f.EngagementID = shared.ID(eid)
	f.Severity = shared.Severity(sev)
	f.Status = finding.Status(status)
	f.Kind = finding.Kind(kindOrDefault(kind))
	f.DedupKey = dedup
	f.Sources = splitSources(sources)
	f.AdvisoryID = advisoryID
	f.OccurrenceID = shared.ID(occurrenceID)
	f.ComponentFingerprint = componentFingerprint
	f.FixedVersion = fixedVersion
	f.DetectionState = detectionState
	f.RiskAssessmentID = shared.ID(riskAssessmentID)
	if len(dataFlowJSON) > 0 {
		var trace finding.DataFlowTrace
		decoder := json.NewDecoder(bytes.NewReader(dataFlowJSON))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&trace); err != nil {
			return finding.Finding{}, fmt.Errorf("decode finding data flow: %w", err)
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return finding.Finding{}, errors.New("decode finding data flow: trailing JSON")
		}
		if err := trace.Validate(); err != nil {
			return finding.Finding{}, fmt.Errorf("validate finding data flow: %w", err)
		}
		f.DataFlow = &trace
		sink := trace.Sink
		f.SourceLocation = &sink
	}
	return f, nil
}

func findingDataFlowJSON(trace *finding.DataFlowTrace) (any, error) {
	if trace == nil {
		return nil, nil
	}
	if err := trace.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(trace)
}

func nullableFindingID(value shared.ID) any {
	if value.IsZero() {
		return nil
	}
	return value.String()
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

// validateFindingBatch asserts domain invariants (like RuleKey constraints) for a
// batch before writing to the database. An atomic failure prevents partial writes.
func validateFindingBatch(findings []finding.Finding) error {
	for _, f := range findings {
		if err := f.ValidateRuleKey(); err != nil {
			return fmt.Errorf("finding %s (kind %s): %w", f.DedupKey, f.Kind, err)
		}
		if f.DataFlow != nil {
			if err := f.DataFlow.Validate(); err != nil {
				return fmt.Errorf("finding %s data flow: %w", f.DedupKey, err)
			}
		}
	}
	return nil
}
