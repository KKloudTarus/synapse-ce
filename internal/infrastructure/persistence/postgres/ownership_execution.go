package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

type OwnershipExecution struct {
	repo  *OwnershipRepository
	ids   ports.IDGenerator
	clock ports.Clock
}

func NewOwnershipExecution(repo *OwnershipRepository, ids ports.IDGenerator, clock ports.Clock) (*OwnershipExecution, error) {
	if repo == nil || ids == nil || clock == nil {
		return nil, shared.ErrValidation
	}
	return &OwnershipExecution{repo: repo, ids: ids, clock: clock}, nil
}

var _ ports.OwnershipWorkerStore = (*OwnershipExecution)(nil)

const ownershipSourceJoins = ` LEFT JOIN ownership_finding_sources b ON b.tenant_id=f.tenant_id AND b.engagement_id=f.engagement_id AND b.finding_id=f.id
 LEFT JOIN ownership_sources s ON s.tenant_id=b.tenant_id AND s.engagement_id=b.engagement_id AND s.id=b.source_id
 LEFT JOIN ownership_source_readiness sr ON sr.tenant_id=s.tenant_id AND sr.engagement_id=s.engagement_id AND sr.source_id=s.id`

// A concurrency fingerprint, not a trust signature. It covers associations that
// can change without advancing the canonical finding's optimistic version.
const ownershipBindingFingerprint = `md5(jsonb_build_array(COALESCE(b.binding_hash,''),COALESCE(e.business_asset_id,''),COALESCE(e.assessment_project_id,''),COALESCE(b.origin_hash,''),f.kind,COALESCE(f.occurrence_id,''),COALESCE(f.component_fingerprint,''),sr.source_id IS NOT NULL)::text)`

const ownershipFrozenInput = `jsonb_build_object(
 'tenant_id',f.tenant_id,'engagement_id',f.engagement_id,'finding_id',f.id,
 'repository',COALESCE(s.repository,''),'kind',f.kind,'severity',f.severity,
 'project_ids',CASE WHEN e.assessment_project_id IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(e.assessment_project_id) END,
 'asset_ids',CASE WHEN e.business_asset_id IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(e.business_asset_id) END,
 'paths',COALESCE(b.paths,'[]'::jsonb),'source_revision',COALESCE(s.source_revision,''),
 'source_bound',sr.source_id IS NOT NULL AND s.source_revision<>'','invalid_source',COALESCE(b.invalid,false),
 'base_revision',COALESCE(s.base_revision,''),'base_required',COALESCE(s.base_required,false) OR COALESCE(s.base_revision<>'',false) OR COALESCE(s.reason='missing_base_snapshot',false),
 'supported',true,
 'current',jsonb_build_object('team_id',COALESCE(a.team_id,''),'assignee_id',COALESCE(a.assignee_id,''),
 'legacy_assignee',f.assignee,'mode',COALESCE(a.mode,CASE WHEN f.assignee='' THEN 'auto' ELSE 'manual' END),
 'revision',COALESCE(a.revision,0),'manual_generation',COALESCE(a.manual_generation,0)),
 'active_teams',COALESCE((SELECT jsonb_agg(t.id ORDER BY t.id) FROM ownership_teams t WHERE t.tenant_id=f.tenant_id AND NOT t.archived AND EXISTS(SELECT 1 FROM ownership_policy_team_refs tr WHERE tr.tenant_id=t.tenant_id AND tr.team_id=t.id AND tr.policy_id=p.id AND tr.version=p.selected_version)),'[]'::jsonb))`

const ownershipWorkColumns = `(tenant_id,job_id,engagement_id,finding_id,run_id,policy_id,policy_version,policy_revision,mode,finding_version,input,binding_hash,origin,binding_origin)`

func ownershipInsertJob(ctx context.Context, tx pgx.Tx, tenant shared.ID, id string, run shared.ID) error {
	data, _ := json.Marshal(map[string]shared.ID{"run_id": run})
	_, err := tx.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status,available_at) VALUES($1,$2,'ownership.route',$3,'queued',now())`, id, tenant, data)
	return err
}

func (r *OwnershipExecution) StartOwnershipRun(ctx context.Context, req ports.OwnershipRunRequest) (run ports.OwnershipRun, err error) {
	if req.Actor.IsZero() || len(req.Key) < 1 || len(req.Key) > 200 || req.Mode != "preview" && req.Mode != "reroute" || !ownershipJSONObject(req.Filter, 16384) {
		return run, shared.ErrValidation
	}
	if req.Mode == "reroute" && req.PreviewID.IsZero() || req.Mode == "preview" && !req.PreviewID.IsZero() {
		return run, fmt.Errorf("%w: reroute requires a completed preview", shared.ErrValidation)
	}
	data, _ := json.Marshal(req)
	hash := ownership.ContentHash(string(data))
	err = r.repo.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		ctx = bindTenantTransaction(ctx, tenant, tx)
		if err := r.repo.AuthorizeOwnership(ctx, req.Actor, user.PermAdminister); err != nil {
			return err
		}
		if err := r.repo.VisibleOwnershipEngagement(ctx, req.Policy.EngagementID); err != nil {
			return err
		}
		// Serialize exact-key admission before checking the previous run. No job
		// or selection exists outside the transaction that reserves this key.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "ownership-run:"+tenant.String()+":"+req.Actor.String()+":"+req.Key); err != nil {
			return err
		}
		var stored string
		var prior shared.ID
		e := tx.QueryRow(ctx, `SELECT request_hash,run_id FROM ownership_run_requests WHERE tenant_id=$1 AND actor_id=$2 AND request_key=$3`, tenant, req.Actor, req.Key).Scan(&stored, &prior)
		if e == nil {
			if stored != hash {
				return shared.ErrConflict
			}
			run, e = ownershipRun(ctx, tx, tenant, prior, false)
			return e
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		run = ports.OwnershipRun{ID: r.ids.NewID(), EngagementID: req.Policy.EngagementID, PolicyID: req.Policy.ID, PolicyVersion: req.Version.Version, PolicyRevision: req.Policy.Revision, PolicyHash: req.Version.Hash(), Mode: req.Mode, State: "queued", Revision: 1, Cutoff: r.clock.Now().UTC(), Filter: req.Filter, CreatedAt: r.clock.Now().UTC()}
		if req.Mode == "reroute" {
			preview, e := ownershipRun(ctx, tx, tenant, req.PreviewID, false)
			if e != nil {
				return e
			}
			var sameFilter bool
			if e := tx.QueryRow(ctx, `SELECT filter=$3::jsonb FROM ownership_runs WHERE tenant_id=$1 AND id=$2`, tenant, req.PreviewID, req.Filter).Scan(&sameFilter); e != nil {
				return e
			}
			if preview.Mode != "preview" || preview.State != "completed" || preview.PolicyID != run.PolicyID || preview.PolicyVersion != run.PolicyVersion || preview.PolicyHash != run.PolicyHash || preview.PolicyRevision != run.PolicyRevision || !sameFilter || req.Policy.ActiveVersion != run.PolicyVersion {
				return shared.ErrConflict
			}
			run.Cutoff = preview.Cutoff
		}
		if err := r.repo.CreateRun(ctx, run); err != nil {
			return err
		}
		job := r.ids.NewID().String()
		if err := ownershipInsertJob(ctx, tx, tenant, job, run.ID); err != nil {
			return err
		}
		var total int64
		if req.Mode == "reroute" {
			tag, e := tx.Exec(ctx, `INSERT INTO ownership_work_items `+ownershipWorkColumns+` SELECT tenant_id,$3,engagement_id,finding_id,$4,policy_id,policy_version,policy_revision,'reroute',finding_version,input,binding_hash,origin,binding_origin FROM ownership_work_items WHERE tenant_id=$1 AND run_id=$2`, tenant, req.PreviewID, job, run.ID)
			if e != nil {
				return e
			}
			total = tag.RowsAffected()
		} else {
			var filter ports.OwnershipInboxFilter
			if err := json.Unmarshal(req.Filter, &filter); err != nil {
				return shared.ErrValidation
			}
			filter.EngagementID = run.EngagementID
			filter.MemberID = req.Actor
			where, args, e := ownershipInboxPredicate(tenant, filter)
			if e != nil {
				return e
			}
			add := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }
			jobParam, runParam, policyParam, versionParam, cutoffParam := add(job), add(run.ID), add(run.PolicyID), add(run.PolicyVersion), add(run.Cutoff)
			query := `INSERT INTO ownership_work_items ` + ownershipWorkColumns + ` SELECT f.tenant_id,` + jobParam + `,f.engagement_id,f.id,` + runParam + `,p.id,p.selected_version,p.revision,'preview',f.version,` + ownershipFrozenInput + `,` + ownershipBindingFingerprint + `,jsonb_build_array(f.kind,COALESCE(f.occurrence_id,''),COALESCE(f.component_fingerprint,'')),COALESCE(b.origin_hash,'')` + ownershipInboxFrom + ownershipSourceJoins + ` JOIN (SELECT *,` + versionParam + `::integer AS selected_version FROM ownership_policies WHERE tenant_id=$1 AND id=` + policyParam + `) p ON p.engagement_id=f.engagement_id` + where + ` AND f.created_at<=` + cutoffParam + ` AND (p.repository='' OR p.repository=s.repository)`
			tag, e := tx.Exec(ctx, query, args...)
			if e != nil {
				return e
			}
			total = tag.RowsAffected()
		}
		run.Total = int(total)
		if total == 0 {
			run.State = "completed"
		}
		if _, e := tx.Exec(ctx, `UPDATE ownership_runs SET total=$3,state=$4 WHERE tenant_id=$1 AND id=$2`, tenant, run.ID, run.Total, run.State); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO ownership_run_requests(tenant_id,actor_id,request_key,request_hash,run_id) VALUES($1,$2,$3,$4,$5)`, tenant, req.Actor, req.Key, hash, run.ID)
		return e
	})
	return
}

func (r *OwnershipExecution) LoadOwnershipWork(ctx context.Context, job ports.QueuedJob, limit int) (out []ports.OwnershipWork, err error) {
	out = []ports.OwnershipWork{}
	err = r.repo.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		if tenant != job.TenantID {
			return shared.ErrValidation
		}
		if err := ownershipFence(ctx, tx, tenant, ports.OwnershipMutation{JobID: job.ID, Fence: job.Fence}); err != nil {
			return err
		}
		rows, e := tx.Query(ctx, `SELECT w.input,w.finding_version,w.policy_id,w.policy_version,w.policy_revision,w.binding_hash,COALESCE(w.run_id,''),w.mode,w.origin,w.binding_origin FROM ownership_work_items w LEFT JOIN ownership_runs r ON r.tenant_id=w.tenant_id AND r.id=w.run_id WHERE w.tenant_id=$1 AND w.job_id=$2 AND w.outcome='pending' AND (w.run_id IS NULL OR r.state IN ('queued','running')) ORDER BY w.finding_id COLLATE "C" LIMIT $3`, tenant, job.ID, ownershipLimit(limit))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var work ports.OwnershipWork
			var input, origin []byte
			var bindingOrigin string
			if e := rows.Scan(&input, &work.FindingVersion, &work.PolicyID, &work.PolicyVersion, &work.PolicyRevision, &work.BindingHash, &work.RunID, &work.Mode, &origin, &bindingOrigin); e != nil {
				return e
			}
			if e := json.Unmarshal(input, &work.Input); e != nil {
				return e
			}
			if work.Input.TenantID != tenant {
				return shared.ErrValidation
			}
			var tuple []string
			if e := json.Unmarshal(origin, &tuple); e != nil {
				return e
			}
			if len(tuple) != 3 {
				return shared.ErrValidation
			}
			if bindingOrigin != ownershipOriginHash(tuple[0], tuple[1], tuple[2]) {
				work.Input.SourceBound = false
			}
			out = append(out, work)
		}
		return rows.Err()
	})
	return
}

func (r *OwnershipExecution) CommitOwnershipWork(ctx context.Context, job ports.QueuedJob, work ports.OwnershipWork, result ownership.Result, outcome string, notify bool) error {
	if outcome != "evaluated" && outcome != "manual_protected" && outcome != "conflict" {
		return shared.ErrValidation
	}
	return r.repo.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		ctx = bindTenantTransaction(ctx, tenant, tx)
		if tenant != job.TenantID || work.Input.TenantID != tenant {
			return shared.ErrValidation
		}
		if err := ownershipFence(ctx, tx, tenant, ports.OwnershipMutation{JobID: job.ID, Fence: job.Fence}); err != nil {
			return err
		}
		if !work.RunID.IsZero() {
			run, e := ownershipRun(ctx, tx, tenant, work.RunID, true)
			if e != nil {
				return e
			}
			if run.State == "cancelled" {
				return nil
			}
			if run.State == "failed" {
				return ports.ErrRetryable
			}
		}
		var state string
		if e := tx.QueryRow(ctx, `SELECT outcome FROM ownership_work_items WHERE tenant_id=$1 AND job_id=$2 AND finding_id=$3 FOR UPDATE`, tenant, job.ID, work.Input.FindingID).Scan(&state); e != nil {
			return e
		}
		if state != "pending" {
			return nil
		}
		data, e := json.Marshal(result)
		if e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE ownership_work_items SET outcome=$4,result=$5 WHERE tenant_id=$1 AND job_id=$2 AND finding_id=$3`, tenant, job.ID, work.Input.FindingID, outcome, data); e != nil {
			return e
		}
		if !work.RunID.IsZero() {
			if _, e := tx.Exec(ctx, `INSERT INTO ownership_run_items(tenant_id,run_id,engagement_id,finding_id,finding_version,ownership_revision,manual_generation,result) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, tenant, work.RunID, work.Input.EngagementID, work.Input.FindingID, work.FindingVersion, work.Input.Current.Revision, work.Input.Current.ManualGeneration, data); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `UPDATE ownership_runs SET processed=processed+1,revision=revision+1,state=CASE WHEN processed+1=total THEN 'completed' ELSE 'running' END WHERE tenant_id=$1 AND id=$2`, tenant, work.RunID); e != nil {
				return e
			}
		}
		if outcome == "conflict" && work.RunID.IsZero() {
			_, e = tx.Exec(ctx, `INSERT INTO ownership_dirty_findings(tenant_id,engagement_id,finding_id) VALUES($1,$2,$3) ON CONFLICT(tenant_id,engagement_id,finding_id) DO UPDATE SET generation=ownership_dirty_findings.generation+1`, tenant, work.Input.EngagementID, work.Input.FindingID)
			return e
		}
		if work.Mode == "preview" || work.Mode == "observe" || outcome != "evaluated" {
			return ownershipFence(ctx, tx, tenant, ports.OwnershipMutation{JobID: job.ID, Fence: job.Fence})
		}
		// ApplyAssignment appends audit last; all progress/result writes above
		// roll back with it. There must be no SQL after this call.
		_, e = r.repo.ApplyAssignment(ctx, ports.OwnershipMutation{EngagementID: work.Input.EngagementID, FindingID: work.Input.FindingID, Repository: work.Input.Repository, DecisionID: r.ids.NewID(), Key: "work:" + job.ID + ":" + work.Input.FindingID.String(), Actor: "ownership-worker", Kind: "route", TeamID: result.TeamID, ExpectedFindingVersion: work.FindingVersion, ExpectedRevision: work.Input.Current.Revision, ExpectedManualGeneration: work.Input.Current.ManualGeneration, ExpectedBindingHash: work.BindingHash, PolicyID: work.PolicyID, PolicyVersion: work.PolicyVersion, ExpectedPolicyRevision: work.PolicyRevision, JobID: job.ID, Fence: job.Fence, Result: result, Notify: notify, At: r.clock.Now().UTC()})
		return e
	})
}

func (r *OwnershipExecution) FailOwnershipWork(ctx context.Context, job ports.QueuedJob) error {
	return r.repo.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		if err := ownershipFence(ctx, tx, tenant, ports.OwnershipMutation{JobID: job.ID, Fence: job.Fence}); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE ownership_runs SET state='failed',revision=revision+1 WHERE tenant_id=$1 AND state IN ('queued','running') AND id IN (SELECT run_id FROM ownership_work_items WHERE tenant_id=$1 AND job_id=$2)`, tenant, job.ID)
		return err
	})
}

func (r *OwnershipExecution) ReplayOwnershipRun(ctx context.Context, actor, id shared.ID, revision int) error {
	if actor.IsZero() || id.IsZero() || revision < 1 {
		return shared.ErrValidation
	}
	return r.repo.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		ctx = bindTenantTransaction(ctx, tenant, tx)
		if err := r.repo.AuthorizeOwnership(ctx, actor, user.PermAdminister); err != nil {
			return err
		}
		run, err := ownershipRun(ctx, tx, tenant, id, false)
		if err != nil {
			return err
		}
		if err := r.repo.VisibleOwnershipEngagement(ctx, run.EngagementID); err != nil {
			return err
		}
		var job string
		if err := tx.QueryRow(ctx, `SELECT j.id FROM jobs j WHERE j.tenant_id=$1 AND j.kind='ownership.route' AND j.status='failed' AND EXISTS(SELECT 1 FROM ownership_work_items w WHERE w.tenant_id=j.tenant_id AND w.job_id=j.id AND w.run_id=$2) FOR UPDATE OF j`, tenant, id).Scan(&job); err != nil {
			return err
		}
		run, err = ownershipRun(ctx, tx, tenant, id, true)
		if err != nil {
			return err
		}
		if run.State != "failed" || run.Revision != revision {
			return shared.ErrConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status='queued',attempts=0,claimed_until=NULL,available_at=now(),updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, job); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ownership_runs SET state='queued',revision=revision+1 WHERE tenant_id=$1 AND id=$2`, tenant, id); err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, tenant.String(), ports.AuditEntry{Actor: actor.String(), Action: "ownership.run.retried", Target: id.String(), At: r.clock.Now().UTC(), Metadata: map[string]string{"job_id": job, "engagement_id": run.EngagementID.String()}})
	})
}

// DispatchOwnership enumerates tenant identities only outside RLS, then enters a
// separate tenant transaction. One job contains at most limit frozen inputs.
func (r *OwnershipExecution) DispatchOwnership(ctx context.Context, mode string, limit int) (int, error) {
	if mode != "observe" && mode != "enforce" {
		return 0, shared.ErrValidation
	}
	rows, err := r.repo.pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return 0, err
	}
	var tenants []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		tenants = append(tenants, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	total := 0
	for _, tenant := range tenants {
		n, err := r.dispatchTenant(shared.WithTenant(ctx, tenant), mode, ownershipLimit(limit))
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (r *OwnershipExecution) dispatchTenant(ctx context.Context, mode string, limit int) (count int, err error) {
	err = r.repo.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		// Serialize dispatchers without taking dirty-row locks before finding FK
		// locks. Producers remain independent; generation CAS closes their race.
		var acquired bool
		if e := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, "ownership-dispatch:"+tenant.String()).Scan(&acquired); e != nil {
			return e
		}
		if !acquired {
			return nil
		}
		if e := ownershipExpandScope(ctx, tx, tenant, limit); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT d.engagement_id,d.finding_id,d.generation FROM ownership_dirty_findings d JOIN findings f ON f.tenant_id=d.tenant_id AND f.engagement_id=d.engagement_id AND f.id=d.finding_id JOIN engagements e ON e.tenant_id=f.tenant_id AND e.id=f.engagement_id`+ownershipSourceJoins+` WHERE d.tenant_id=$1 AND (b.source_id IS NULL OR sr.source_id IS NOT NULL) ORDER BY d.finding_id LIMIT $2`, tenant, limit)
		if e != nil {
			return e
		}
		type dirty struct {
			eng, id shared.ID
			gen     int64
		}
		var picked []dirty
		var ids []string
		var engagementIDs []string
		var generations []int64
		for rows.Next() {
			var d dirty
			if e := rows.Scan(&d.eng, &d.id, &d.gen); e != nil {
				rows.Close()
				return e
			}
			picked = append(picked, d)
			ids = append(ids, d.id.String())
			engagementIDs = append(engagementIDs, d.eng.String())
			generations = append(generations, d.gen)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if len(picked) == 0 {
			return nil
		}
		job := r.ids.NewID().String()
		if e := ownershipInsertJob(ctx, tx, tenant, job, ""); e != nil {
			return e
		}
		query := `INSERT INTO ownership_work_items ` + ownershipWorkColumns + ` SELECT f.tenant_id,$2,f.engagement_id,f.id,NULL,p.id,p.selected_version,p.revision,$4,f.version,` + ownershipFrozenInput + `,` + ownershipBindingFingerprint + `,jsonb_build_array(f.kind,COALESCE(f.occurrence_id,''),COALESCE(f.component_fingerprint,'')),COALESCE(b.origin_hash,'')` + ownershipInboxFrom + ownershipSourceJoins + ` JOIN LATERAL (SELECT op.*,op.active_version AS selected_version FROM ownership_policies op WHERE op.tenant_id=f.tenant_id AND op.engagement_id=f.engagement_id AND op.active_version IS NOT NULL AND op.repository IN ('',COALESCE(s.repository,'')) ORDER BY (op.repository=COALESCE(s.repository,'')) DESC LIMIT 1) p ON true WHERE f.tenant_id=$1 AND f.id=ANY($3::text[]) AND (f.created_at>=p.activated_at OR a.finding_id IS NOT NULL OR EXISTS(SELECT 1 FROM ownership_intents oi WHERE oi.tenant_id=f.tenant_id AND oi.finding_id=f.id AND oi.kind='route' AND oi.state='pending'))`
		tag, e := tx.Exec(ctx, query, tenant, job, ids, mode)
		if e != nil {
			return e
		}
		count = int(tag.RowsAffected())
		if _, e := tx.Exec(ctx, `DELETE FROM ownership_dirty_findings d USING unnest($2::text[],$3::text[],$4::bigint[]) AS picked(engagement_id,finding_id,generation) WHERE d.tenant_id=$1 AND d.engagement_id=picked.engagement_id AND d.finding_id=picked.finding_id AND d.generation=picked.generation`, tenant, engagementIDs, ids, generations); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE ownership_intents SET state='processed' WHERE tenant_id=$1 AND kind='route' AND state='pending' AND finding_id=ANY($2::text[])`, tenant, ids); e != nil {
			return e
		}
		if count == 0 {
			_, e = tx.Exec(ctx, `UPDATE jobs SET status='done' WHERE tenant_id=$1 AND id=$2`, tenant, job)
		}
		return e
	})
	return
}

func ownershipExpandScope(ctx context.Context, tx pgx.Tx, tenant shared.ID, limit int) error {
	var eng, after shared.ID
	var generation int64
	err := tx.QueryRow(ctx, `SELECT engagement_id,after_id,generation FROM ownership_dirty_scopes WHERE tenant_id=$1 ORDER BY engagement_id LIMIT 1`, tenant).Scan(&eng, &after, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id FROM findings WHERE tenant_id=$1 AND engagement_id=$2 AND id COLLATE "C">$3 ORDER BY id COLLATE "C" LIMIT $4`, tenant, eng, after, limit)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO ownership_dirty_findings(tenant_id,engagement_id,finding_id) SELECT $1,$2,unnest($3::text[]) ON CONFLICT(tenant_id,engagement_id,finding_id) DO UPDATE SET generation=ownership_dirty_findings.generation+1`, tenant, eng, ids); err != nil {
			return err
		}
	}
	if len(ids) < limit {
		_, err = tx.Exec(ctx, `DELETE FROM ownership_dirty_scopes WHERE tenant_id=$1 AND engagement_id=$2 AND generation=$3`, tenant, eng, generation)
	} else {
		_, err = tx.Exec(ctx, `UPDATE ownership_dirty_scopes SET after_id=$4 WHERE tenant_id=$1 AND engagement_id=$2 AND generation=$3`, tenant, eng, generation, ids[len(ids)-1])
	}
	return err
}
