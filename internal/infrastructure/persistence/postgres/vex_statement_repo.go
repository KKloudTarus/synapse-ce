package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// VEXStatementRepository persists ingested VEX statements (migration 0173) to PostgreSQL so they can be
// re-applied after a rescan. Every method runs through WithTenant, so Row Level Security isolates by tenant.
type VEXStatementRepository struct{ pool *pgxpool.Pool }

// NewVEXStatementRepository constructs the Postgres VEX-statement repository.
func NewVEXStatementRepository(pool *pgxpool.Pool) *VEXStatementRepository {
	return &VEXStatementRepository{pool: pool}
}

var _ ports.VEXStatementRepository = (*VEXStatementRepository)(nil)

// Save persists a batch ATOMICALLY: one transaction, so a partial failure leaves no half-persisted policy.
// Each row is inserted ON CONFLICT DO NOTHING against the (tenant, engagement, digest) primary key, so
// re-importing an identical assertion is a no-op rather than a duplicate.
func (r *VEXStatementRepository) Save(ctx context.Context, tenantID, engagementID shared.ID, statements []vex.StoredStatement) error {
	if len(statements) == 0 {
		return nil
	}
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		for _, s := range statements {
			if s.Digest == "" {
				return fmt.Errorf("%w: vex statement is missing its content digest", shared.ErrValidation)
			}
			payload, err := json.Marshal(s.Statement)
			if err != nil {
				return fmt.Errorf("marshal vex statement: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO vex_statements (tenant_id, engagement_id, digest, advisory, statement, actor, ingested_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7)
				ON CONFLICT (tenant_id, engagement_id, digest) DO NOTHING`,
				tenantID.String(), engagementID.String(), s.Digest, s.Advisory, payload, s.Actor, s.IngestedAt.UTC()); err != nil {
				return fmt.Errorf("insert vex statement: %w", err)
			}
		}
		return nil
	})
}

// ListByEngagement returns the engagement's persisted statements in insertion order (the seq identity), so a
// re-apply walking them applies the most-recent assertion last.
func (r *VEXStatementRepository) ListByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]vex.StoredStatement, error) {
	out := make([]vex.StoredStatement, 0)
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT advisory, digest, statement, actor, ingested_at FROM vex_statements
			 WHERE tenant_id=$1 AND engagement_id=$2
			 ORDER BY seq ASC`,
			tenantID.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list vex statements: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var s vex.StoredStatement
			var payload []byte
			if err := rows.Scan(&s.Advisory, &s.Digest, &payload, &s.Actor, &s.IngestedAt); err != nil {
				return fmt.Errorf("scan vex statement: %w", err)
			}
			if err := json.Unmarshal(payload, &s.Statement); err != nil {
				return fmt.Errorf("decode vex statement: %w", err)
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
