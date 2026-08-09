package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// importedFindingCols is the column list shared by the insert and the read projection.
const importedFindingCols = `id, tenant_id, engagement_id, finding_id, severity, title, message, path, ` +
	`start_line, start_column, logical_name, suppressed, fingerprint, tool_name, tool_version, rule_id, ` +
	`source_digest, ingested_by, ingested_at, created_at, updated_at`

// ImportedFindingRepository persists third-party findings (migration 0064) to PostgreSQL.
//
// Durability is not incidental here: the ingest writes an append-only audit entry claiming that N
// external results entered an engagement, and that claim is only true if the rows survive a restart.
// Every method runs through WithTenant so Row Level Security isolates by tenant.
type ImportedFindingRepository struct{ pool *pgxpool.Pool }

// NewImportedFindingRepository constructs the Postgres imported-finding repository.
func NewImportedFindingRepository(pool *pgxpool.Pool) *ImportedFindingRepository {
	return &ImportedFindingRepository{pool: pool}
}

var _ ports.ImportedFindingStore = (*ImportedFindingRepository)(nil)

// Save persists a batch ATOMICALLY: one transaction, so a failure anywhere leaves no partially ingested
// report and no recorded digest that would make a retry look like a clean deduplicated ingest.
//
// Each row is inserted with ON CONFLICT DO NOTHING against the idempotency index, so re-posting the same
// document is a no-op rather than a duplicate, and the accepted/deduplicated split the caller reports is
// the database's own answer rather than a guess.
func (r *ImportedFindingRepository) Save(ctx context.Context, tenantID shared.ID, findings []importedfinding.ImportedFinding) (int, int, error) {
	if len(findings) == 0 {
		return 0, 0, nil
	}
	stored, existing := 0, 0
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		stored, existing = 0, 0
		for _, f := range findings {
			// Validate inside the transaction: an invalid finding aborts the whole batch rather than
			// leaving the valid prefix behind.
			if err := f.Validate(); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `
				INSERT INTO imported_findings (`+importedFindingCols+`)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
				ON CONFLICT (tenant_id, engagement_id, source_digest, rule_id, path, logical_name, start_line)
				DO NOTHING`,
				f.ID.String(), tenantID.String(), f.EngagementID.String(), f.FindingID.String(),
				string(f.Severity), f.Title, f.Message, f.Location.Path,
				f.Location.StartLine, f.Location.StartColumn, f.Location.LogicalName,
				f.Suppressed, f.Fingerprint, f.Provenance.ToolName, f.Provenance.ToolVersion,
				f.Provenance.RuleID, f.Provenance.SourceDigest, f.Provenance.IngestedBy.String(),
				f.Provenance.IngestedAt, f.Audit.CreatedAt, f.Audit.UpdatedAt)
			if err != nil {
				return fmt.Errorf("insert imported finding: %w", err)
			}
			if tag.RowsAffected() == 0 {
				existing++
				continue
			}
			stored++
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return stored, existing, nil
}

// ListByEngagement returns the engagement's imported findings in a deterministic order.
func (r *ImportedFindingRepository) ListByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]importedfinding.ImportedFinding, error) {
	out := make([]importedfinding.ImportedFinding, 0)
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+importedFindingCols+` FROM imported_findings
			 WHERE tenant_id=$1 AND engagement_id=$2
			 ORDER BY rule_id COLLATE "C" ASC, path COLLATE "C" ASC, start_line ASC, id COLLATE "C" ASC`,
			tenantID.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list imported findings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			f, scanErr := scanImportedFinding(rows)
			if scanErr != nil {
				return fmt.Errorf("scan imported finding: %w", scanErr)
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ExistsDigest reports whether this tenant's engagement already ingested a document with this digest.
func (r *ImportedFindingRepository) ExistsDigest(ctx context.Context, tenantID, engagementID shared.ID, digest string) (bool, error) {
	found := false
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM imported_findings
			   WHERE tenant_id=$1 AND engagement_id=$2 AND source_digest=$3)`,
			tenantID.String(), engagementID.String(), digest).Scan(&found)
	})
	if err != nil {
		return false, fmt.Errorf("check imported finding digest: %w", err)
	}
	return found, nil
}

func scanImportedFinding(row rowScanner) (importedfinding.ImportedFinding, error) {
	var (
		f                            importedfinding.ImportedFinding
		id, tenant, engagement, link string
		severity, ingestedBy         string
	)
	if err := row.Scan(&id, &tenant, &engagement, &link, &severity, &f.Title, &f.Message,
		&f.Location.Path, &f.Location.StartLine, &f.Location.StartColumn, &f.Location.LogicalName,
		&f.Suppressed, &f.Fingerprint, &f.Provenance.ToolName, &f.Provenance.ToolVersion,
		&f.Provenance.RuleID, &f.Provenance.SourceDigest, &ingestedBy, &f.Provenance.IngestedAt,
		&f.Audit.CreatedAt, &f.Audit.UpdatedAt); err != nil {
		return importedfinding.ImportedFinding{}, err
	}
	f.ID = shared.ID(id)
	f.TenantID = shared.ID(tenant)
	f.EngagementID = shared.ID(engagement)
	f.FindingID = shared.ID(link)
	f.Severity = shared.Severity(severity)
	f.Provenance.IngestedBy = shared.ID(ingestedBy)
	return f, nil
}
