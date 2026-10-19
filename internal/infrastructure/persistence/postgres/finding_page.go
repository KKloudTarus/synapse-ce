package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.FindingPageReader = (*FindingRepository)(nil)

// ListFindingPage uses an ID keyset and one extra row to determine whether a
// next page exists. It never loads an engagement's whole finding set.
func (r *FindingRepository) ListFindingPage(ctx context.Context, engagementID, afterID shared.ID, limit int) (out ports.FindingPage, err error) {
	if engagementID.IsZero() || limit < 1 {
		return ports.FindingPage{}, fmt.Errorf("%w: finding page arguments are invalid", shared.ErrValidation)
	}
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, queryErr := tx.Query(ctx, `SELECT `+findingCols+`
			FROM findings f WHERE f.engagement_id=$1 AND f.id > $2::text
			AND (f.kind <> 'cloud_posture' OR EXISTS (
				SELECT 1 FROM cspm_observations o
				WHERE o.tenant_id=f.tenant_id AND o.engagement_id=f.engagement_id
					AND o.observation_kind='finding' AND o.object_id=f.id AND o.active
			))
			ORDER BY f.id ASC LIMIT $3`, engagementID.String(), afterID.String(), limit+1)
		if queryErr != nil {
			return fmt.Errorf("list finding page: %w", queryErr)
		}
		defer rows.Close()
		for rows.Next() {
			item, scanErr := scanFinding(rows)
			if scanErr != nil {
				return fmt.Errorf("scan finding page: %w", scanErr)
			}
			if len(out.Items) == limit {
				out.NextAfter = out.Items[len(out.Items)-1].ID
				break
			}
			out.Items = append(out.Items, item)
		}
		return rows.Err()
	})
	return out, err
}
