package postgres

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

// Bound work per query without dropping an artifact from the immutable manifest.
const closureHistoryBatchRowLimit = 100_000

func closureHistoryIDs(engagementID shared.ID, findingIDs []shared.ID) ([]string, error) {
	if engagementID.IsZero() || len(findingIDs) > 1000 {
		return nil, shared.ErrValidation
	}
	ids := make([]string, len(findingIDs))
	for index, id := range findingIDs {
		if id.IsZero() {
			return nil, shared.ErrValidation
		}
		ids[index] = id.String()
	}
	return ids, nil
}

func (r *RetestRepository) RetestHistories(ctx context.Context, engagementID shared.ID, findingIDs []shared.ID) (map[shared.ID][]finding.Retest, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return nil, shared.ErrValidation
	}
	ids, err := closureHistoryIDs(engagementID, findingIDs)
	if err != nil {
		return nil, err
	}
	out := map[shared.ID][]finding.Retest{}
	if len(ids) == 0 {
		return out, nil
	}
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,engagement_id,finding_id,outcome,note,tester,created_at
			FROM finding_retests WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=ANY($3::text[])
			ORDER BY finding_id,created_at,id LIMIT $4`, tenantID.String(), engagementID.String(), ids, closureHistoryBatchRowLimit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			count++
			if count > closureHistoryBatchRowLimit {
				return fmt.Errorf("%w: closure verification history batch exceeds safe limit", shared.ErrValidation)
			}
			var item finding.Retest
			if err := rows.Scan(&item.ID, &item.EngagementID, &item.FindingID, &item.Outcome, &item.Note, &item.Tester, &item.At); err != nil {
				return err
			}
			out[item.FindingID] = append(out[item.FindingID], item)
		}
		return rows.Err()
	})
	return out, err
}

func (s *SLAStore) SLAHistories(ctx context.Context, tenantID, engagementID shared.ID, findingIDs []shared.ID) (ports.SLAHistoryBatch, error) {
	out := ports.SLAHistoryBatch{Assessments: map[shared.ID][]sla.Assessment{}, Events: map[shared.ID][]sla.LifecycleEvent{}}
	tenantID, err := slaPostgresTenant(ctx, tenantID)
	if err != nil {
		return out, err
	}
	ids, err := closureHistoryIDs(engagementID, findingIDs)
	if err != nil || len(ids) == 0 {
		return out, err
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+slaAssessmentColumns+` FROM sla_assessments
			WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=ANY($3::text[])
			ORDER BY finding_id,assessed_at DESC,id DESC LIMIT $4`, tenantID.String(), engagementID.String(), ids, closureHistoryBatchRowLimit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			count++
			if count > closureHistoryBatchRowLimit {
				return fmt.Errorf("%w: closure SLA assessment history batch exceeds safe limit", shared.ErrValidation)
			}
			var item sla.Assessment
			if err := scanSLAAssessment(rows, &item); err != nil {
				return err
			}
			out.Assessments[item.FindingID] = append(out.Assessments[item.FindingID], item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		rows, err = tx.Query(ctx, `SELECT tenant_id,id,engagement_id,finding_id,assessment_id,from_status,to_status,
			reason,compensating_control,acceptance_expires_at,actor,before_version,after_version,occurred_at
			FROM sla_lifecycle_events WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=ANY($3::text[])
			ORDER BY finding_id,occurred_at,id LIMIT $4`, tenantID.String(), engagementID.String(), ids, closureHistoryBatchRowLimit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		count = 0
		for rows.Next() {
			count++
			if count > closureHistoryBatchRowLimit {
				return fmt.Errorf("%w: closure SLA event history batch exceeds safe limit", shared.ErrValidation)
			}
			var item sla.LifecycleEvent
			if err := rows.Scan(&item.TenantID, &item.ID, &item.EngagementID, &item.FindingID, &item.AssessmentID,
				&item.From, &item.To, &item.Reason, &item.CompensatingControl, &item.AcceptanceExpiresAt,
				&item.Actor, &item.BeforeVersion, &item.AfterVersion, &item.At); err != nil {
				return err
			}
			out.Events[item.FindingID] = append(out.Events[item.FindingID], item)
		}
		return rows.Err()
	})
	return out, err
}

var _ ports.RetestHistoryBatchReader = (*RetestRepository)(nil)
var _ ports.SLAHistoryBatchReader = (*SLAStore)(nil)
