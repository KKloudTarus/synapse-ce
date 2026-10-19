package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func (s *DocumentStore) ClaimDocumentRestrictionChecks(ctx context.Context, tenant shared.ID, limit int, at time.Time) (out []docpublish.Link, err error) {
	if tenant.IsZero() || limit < 1 || limit > docpublish.MaxListLimit || at.IsZero() {
		return nil, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `WITH due AS (
            SELECT id FROM document_links WHERE tenant_id=$1 AND retired_at IS NULL AND restriction_next_at<=$2
            ORDER BY restriction_next_at,id LIMIT $3 FOR UPDATE SKIP LOCKED
        ) UPDATE document_links SET restriction_next_at=$4,restriction_check_version=restriction_check_version+1
          WHERE tenant_id=$1 AND id IN (SELECT id FROM due) RETURNING `+documentLinkCols,
			tenant.String(), at.UTC(), limit, at.UTC().Add(5*time.Minute))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			link, e := scanDocumentLink(rows)
			if e != nil {
				return e
			}
			out = append(out, link)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("claim document sharing checks: %w", err)
	}
	return out, nil
}

func (s *DocumentStore) SaveDocumentRestrictionCheck(ctx context.Context, tenant shared.ID, link docpublish.Link, status string, at, next time.Time) error {
	if tenant.IsZero() || link.TenantID != tenant || link.ID.IsZero() || link.Revision < 1 || link.RestrictionCheckVersion < 1 || at.IsZero() || !next.After(at) || (status != "verified" && status != "restriction_lost" && status != "unverifiable") {
		return shared.ErrValidation
	}
	return requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE document_links SET restriction_status=$5,restriction_checked_at=$6,restriction_next_at=$7
            WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND restriction_check_version=$4 AND retired_at IS NULL`,
			tenant.String(), link.ID.String(), link.Revision, link.RestrictionCheckVersion, status, at.UTC(), next.UTC())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return shared.ErrConflict
		}
		return nil
	})
}
