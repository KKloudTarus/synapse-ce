package postgres

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func ownershipJSONObject(data json.RawMessage, max int) bool {
	var object map[string]json.RawMessage
	return len(data) <= max && json.Unmarshal(data, &object) == nil && object != nil
}
func ownershipInsertIntent(ctx context.Context, tx pgx.Tx, tenant shared.ID, i ports.OwnershipIntent) error {
	if i.ID.IsZero() || i.EngagementID.IsZero() || i.FindingID.IsZero() || i.SourceKey == "" || len(i.SourceKey) > 256 || i.CreatedAt.IsZero() || i.Kind != "route" && i.Kind != "notification" || i.State != "pending" && i.State != "suppressed" || !ownershipJSONObject(i.Payload, 16384) {
		return shared.ErrValidation
	}
	tag, err := tx.Exec(ctx, `INSERT INTO ownership_intents(tenant_id,engagement_id,finding_id,id,kind,source_key,decision_id,payload,state,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (tenant_id,kind,source_key) DO NOTHING`, tenant, i.EngagementID, i.FindingID, i.ID, i.Kind, i.SourceKey, nullableID(i.DecisionID), i.Payload, i.State, i.CreatedAt)
	if err != nil || tag.RowsAffected() == 1 {
		return err
	}
	var same bool
	err = tx.QueryRow(ctx, `SELECT engagement_id=$4 AND finding_id=$5 AND decision_id IS NOT DISTINCT FROM $6::text AND payload=$7::jsonb FROM ownership_intents WHERE tenant_id=$1 AND kind=$2 AND source_key=$3`, tenant, i.Kind, i.SourceKey, i.EngagementID, i.FindingID, nullableID(i.DecisionID), i.Payload).Scan(&same)
	if err != nil {
		return err
	}
	if !same {
		return shared.ErrConflict
	}
	return nil
}
func (r *OwnershipRepository) AppendIntent(ctx context.Context, i ports.OwnershipIntent) error {
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error { return ownershipInsertIntent(ctx, tx, tenant, i) })
}
func (r *OwnershipRepository) ListPendingIntents(ctx context.Context, kind string, limit int) (out []ports.OwnershipIntent, err error) {
	if kind != "route" && kind != "notification" {
		return nil, shared.ErrValidation
	}
	out = []ports.OwnershipIntent{}
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		rows, e := tx.Query(ctx, `SELECT id,engagement_id,finding_id,kind,source_key,COALESCE(decision_id,''),payload,state,created_at FROM ownership_intents WHERE tenant_id=$1 AND kind=$2 AND state='pending' ORDER BY created_at,id LIMIT $3`, tenant, kind, ownershipLimit(limit))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var i ports.OwnershipIntent
			if e := rows.Scan(&i.ID, &i.EngagementID, &i.FindingID, &i.Kind, &i.SourceKey, &i.DecisionID, &i.Payload, &i.State, &i.CreatedAt); e != nil {
				return e
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return
}
func (r *OwnershipRepository) CompleteIntent(ctx context.Context, id shared.ID) error {
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		tag, err := tx.Exec(ctx, `UPDATE ownership_intents SET state='processed' WHERE tenant_id=$1 AND id=$2 AND state='pending'`, tenant, id)
		if err != nil || tag.RowsAffected() == 1 {
			return err
		}
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM ownership_intents WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&state); err != nil {
			return err
		}
		if state != "processed" {
			return shared.ErrConflict
		}
		return nil
	})
}

func (r *OwnershipRepository) CreateRun(ctx context.Context, run ports.OwnershipRun) error {
	if run.ID.IsZero() || run.EngagementID.IsZero() || run.PolicyID.IsZero() || run.PolicyVersion < 1 || run.PolicyRevision < 1 || len(run.PolicyHash) != 64 || run.Mode != "preview" && run.Mode != "reroute" || run.State != "queued" || run.Revision != 1 || run.Total < 0 || run.Processed != 0 || run.Cutoff.IsZero() || run.CreatedAt.IsZero() || !ownershipJSONObject(run.Filter, 16384) {
		return shared.ErrValidation
	}
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		p, err := ownershipVersion(ctx, tx, tenant, run.PolicyID, run.PolicyVersion)
		if err != nil {
			return err
		}
		if p.Hash() != run.PolicyHash || p.EngagementID != run.EngagementID {
			return shared.ErrConflict
		}
		var revision int
		if err := tx.QueryRow(ctx, `SELECT revision FROM ownership_policies WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, run.PolicyID).Scan(&revision); err != nil {
			return err
		}
		if revision != run.PolicyRevision {
			return shared.ErrConflict
		}
		_, err = tx.Exec(ctx, `INSERT INTO ownership_runs(tenant_id,engagement_id,id,policy_id,policy_version,mode,state,revision,policy_revision,policy_hash,cutoff,total,processed,filter,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,0,$13,$14)`, tenant, run.EngagementID, run.ID, run.PolicyID, run.PolicyVersion, run.Mode, run.State, run.Revision, run.PolicyRevision, run.PolicyHash, run.Cutoff, run.Total, run.Filter, run.CreatedAt)
		return err
	})
}
func ownershipRun(ctx context.Context, tx pgx.Tx, tenant, id shared.ID, lock bool) (run ports.OwnershipRun, err error) {
	q := `SELECT id,engagement_id,policy_id,policy_version,mode,state,revision,policy_revision,policy_hash,cutoff,total,processed,filter,created_at FROM ownership_runs WHERE tenant_id=$1 AND id=$2`
	if lock {
		q += ` FOR UPDATE`
	}
	err = tx.QueryRow(ctx, q, tenant, id).Scan(&run.ID, &run.EngagementID, &run.PolicyID, &run.PolicyVersion, &run.Mode, &run.State, &run.Revision, &run.PolicyRevision, &run.PolicyHash, &run.Cutoff, &run.Total, &run.Processed, &run.Filter, &run.CreatedAt)
	return
}
func (r *OwnershipRepository) GetRun(ctx context.Context, id shared.ID) (run ports.OwnershipRun, err error) {
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		var e error
		run, e = ownershipRun(ctx, tx, tenant, id, false)
		return e
	})
	return
}
func (r *OwnershipRepository) SaveRunItems(ctx context.Context, id shared.ID, revision int, items []ports.OwnershipRunItem) error {
	if id.IsZero() || revision < 1 || len(items) == 0 || len(items) > 100 {
		return shared.ErrValidation
	}
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		run, err := ownershipRun(ctx, tx, tenant, id, true)
		if err != nil {
			return err
		}
		if run.Revision != revision || run.State != "queued" && run.State != "running" {
			return shared.ErrConflict
		}
		added := 0
		for _, item := range items {
			if item.RunID != id || item.EngagementID != run.EngagementID || item.FindingID.IsZero() || item.FindingVersion < 1 || item.OwnershipRevision < 0 || item.ManualGeneration < 0 || !item.Result.Resolution.Valid() || item.Result.PolicyHash != run.PolicyHash {
				return shared.ErrValidation
			}
			data, err := json.Marshal(item.Result)
			if err != nil {
				return err
			}
			if len(data) > 4*1024*1024 {
				return shared.ErrValidation
			}
			tag, err := tx.Exec(ctx, `INSERT INTO ownership_run_items(tenant_id,run_id,engagement_id,finding_id,finding_version,ownership_revision,manual_generation,result) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tenant_id,run_id,finding_id) DO NOTHING`, tenant, id, item.EngagementID, item.FindingID, item.FindingVersion, item.OwnershipRevision, item.ManualGeneration, data)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				added++
				continue
			}
			var same bool
			err = tx.QueryRow(ctx, `SELECT finding_version=$4 AND ownership_revision=$5 AND manual_generation=$6 AND result=$7::jsonb FROM ownership_run_items WHERE tenant_id=$1 AND run_id=$2 AND finding_id=$3`, tenant, id, item.FindingID, item.FindingVersion, item.OwnershipRevision, item.ManualGeneration, data).Scan(&same)
			if err != nil {
				return err
			}
			if !same {
				return shared.ErrConflict
			}
		}
		if run.Processed+added > run.Total {
			return shared.ErrValidation
		}
		if added == 0 {
			return nil
		}
		return ownershipCAS(tx.Exec(ctx, `UPDATE ownership_runs SET processed=processed+$3,revision=revision+1,state='running' WHERE tenant_id=$1 AND id=$2 AND revision=$4`, tenant, id, added, revision))
	})
}
func (r *OwnershipRepository) ListRunItems(ctx context.Context, id, after shared.ID, limit int) (out []ports.OwnershipRunItem, err error) {
	out = []ports.OwnershipRunItem{}
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		rows, e := tx.Query(ctx, `SELECT run_id,engagement_id,finding_id,finding_version,ownership_revision,manual_generation,result FROM ownership_run_items WHERE tenant_id=$1 AND run_id=$2 AND finding_id>$3 ORDER BY finding_id LIMIT $4`, tenant, id, after, ownershipLimit(limit))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var item ports.OwnershipRunItem
			var data []byte
			if e := rows.Scan(&item.RunID, &item.EngagementID, &item.FindingID, &item.FindingVersion, &item.OwnershipRevision, &item.ManualGeneration, &data); e != nil {
				return e
			}
			if e := json.Unmarshal(data, &item.Result); e != nil {
				return e
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return
}
func (r *OwnershipRepository) SetRunState(ctx context.Context, id shared.ID, revision int, state string) error {
	if revision < 1 || !slices.Contains([]string{"running", "completed", "cancelled", "failed"}, state) {
		return shared.ErrValidation
	}
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		run, err := ownershipRun(ctx, tx, tenant, id, true)
		if err != nil {
			return err
		}
		if run.Revision != revision || run.State != "queued" && run.State != "running" {
			return shared.ErrConflict
		}
		if state == "completed" && run.Processed != run.Total {
			return shared.ErrConflict
		}
		if state == run.State {
			return nil
		}
		return ownershipCAS(tx.Exec(ctx, `UPDATE ownership_runs SET state=$3,revision=revision+1 WHERE tenant_id=$1 AND id=$2 AND revision=$4`, tenant, id, state, revision))
	})
}
