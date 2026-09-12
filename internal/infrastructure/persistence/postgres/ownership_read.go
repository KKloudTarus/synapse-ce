package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.OwnershipReader = (*OwnershipRepository)(nil)

func (r *OwnershipRepository) AuthorizeOwnership(ctx context.Context, actor shared.ID, permission user.Permission) error {
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		var role user.Role
		var disabled bool
		if err := tx.QueryRow(ctx, `SELECT role,disabled FROM users WHERE ownership_tenant_id=$1 AND id=$2 FOR SHARE`, tenant, actor).Scan(&role, &disabled); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrForbidden
			}
			return err
		}
		if disabled || !role.Can(permission) {
			return shared.ErrForbidden
		}
		return nil
	})
}
func (r *OwnershipRepository) VisibleOwnershipEngagement(ctx context.Context, id shared.ID) error {
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		var found shared.ID
		return tx.QueryRow(ctx, `SELECT id FROM engagements WHERE tenant_id=$1 AND id=$2 AND project_id IS NULL AND host_asset_id IS NULL`, tenant, id).Scan(&found)
	})
}
func (r *OwnershipRepository) ListOwnershipSnapshots(ctx context.Context, eng, after shared.ID, limit int) (out []ownership.Snapshot, err error) {
	out = []ownership.Snapshot{}
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		rows, e := tx.Query(ctx, `SELECT id,engagement_id,repository,source_revision,file_path,content_hash,parser_version,trust,approved_by,accept_diagnostics,created_at FROM ownership_snapshots WHERE tenant_id=$1 AND engagement_id=$2 AND id>$3 ORDER BY id LIMIT $4`, tenant, eng, after, ownershipLimit(limit))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var s ownership.Snapshot
			s.TenantID = tenant
			if e := rows.Scan(&s.ID, &s.EngagementID, &s.Repository, &s.Revision, &s.FilePath, &s.Hash, &s.ParserVersion, &s.Trust, &s.ApprovedBy, &s.AcceptDiagnostics, &s.CreatedAt); e != nil {
				return e
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return
}

const ownershipPolicyHeaderSelect = `SELECT p.id,p.engagement_id,p.repository,p.revision,COALESCE(p.active_version,0),COALESCE((SELECT max(version) FROM ownership_policy_versions v WHERE v.tenant_id=p.tenant_id AND v.policy_id=p.id),0) FROM ownership_policies p`

func scanOwnershipPolicyHeader(row scanner) (p ports.OwnershipPolicyHeader, err error) {
	err = row.Scan(&p.ID, &p.EngagementID, &p.Repository, &p.Revision, &p.ActiveVersion, &p.LatestVersion)
	return
}
func (r *OwnershipRepository) GetOwnershipPolicy(ctx context.Context, id shared.ID) (out ports.OwnershipPolicyHeader, err error) {
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		var e error
		out, e = scanOwnershipPolicyHeader(tx.QueryRow(ctx, ownershipPolicyHeaderSelect+` WHERE p.tenant_id=$1 AND p.id=$2`, tenant, id))
		return e
	})
	return
}
func (r *OwnershipRepository) ListOwnershipPolicies(ctx context.Context, eng, after shared.ID, limit int) (out []ports.OwnershipPolicyHeader, err error) {
	out = []ports.OwnershipPolicyHeader{}
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		rows, e := tx.Query(ctx, ownershipPolicyHeaderSelect+` WHERE p.tenant_id=$1 AND p.engagement_id=$2 AND p.id>$3 ORDER BY p.id LIMIT $4`, tenant, eng, after, ownershipLimit(limit))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			p, e := scanOwnershipPolicyHeader(rows)
			if e != nil {
				return e
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return
}

func (r *OwnershipRepository) ReserveOwnershipBulk(ctx context.Context, actor shared.ID, key, hash string, at time.Time) error {
	if actor.IsZero() || len(key) < 1 || len(key) > 200 || len(hash) != 64 || at.IsZero() {
		return shared.ErrValidation
	}
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ownership_bulk_requests(tenant_id,actor_id,request_key,request_hash,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, tenant, actor, key, hash, at); err != nil {
			return err
		}
		var stored string
		if err := tx.QueryRow(ctx, `SELECT request_hash FROM ownership_bulk_requests WHERE tenant_id=$1 AND actor_id=$2 AND request_key=$3`, tenant, actor, key).Scan(&stored); err != nil {
			return err
		}
		if stored != hash {
			return shared.ErrConflict
		}
		return nil
	})
}

const ownershipInboxFrom = ` FROM findings f JOIN engagements e ON e.tenant_id=f.tenant_id AND e.id=f.engagement_id
 LEFT JOIN ownership_assignments a ON a.tenant_id=f.tenant_id AND a.engagement_id=f.engagement_id AND a.finding_id=f.id
 LEFT JOIN sla_current_assessments sc ON sc.tenant_id=f.tenant_id AND sc.engagement_id=f.engagement_id AND sc.finding_id=f.id
 LEFT JOIN sla_assessments sa ON sa.tenant_id=sc.tenant_id AND sa.id=sc.assessment_id
 LEFT JOIN sla_lifecycles sl ON sl.tenant_id=sc.tenant_id AND sl.engagement_id=sc.engagement_id AND sl.finding_id=sc.finding_id AND sl.assessment_id=sc.assessment_id`

func ownershipInboxPredicate(tenant shared.ID, f ports.OwnershipInboxFilter) (string, []any, error) {
	args := []any{tenant}
	where := ` WHERE f.tenant_id=$1 AND e.project_id IS NULL AND e.host_asset_id IS NULL`
	add := func(clause string, value any) { args = append(args, value); where += fmt.Sprintf(clause, len(args)) }
	if !f.EngagementID.IsZero() {
		add(` AND f.engagement_id=$%d`, f.EngagementID)
	}
	if !f.TeamID.IsZero() {
		add(` AND a.team_id=$%d`, f.TeamID)
	}
	if !f.AssigneeID.IsZero() {
		add(` AND a.assignee_id=$%d`, f.AssigneeID)
	}
	if f.MyTeams {
		if f.MemberID.IsZero() {
			return "", nil, shared.ErrValidation
		}
		add(` AND EXISTS(SELECT 1 FROM ownership_memberships m WHERE m.tenant_id=f.tenant_id AND m.team_id=a.team_id AND m.user_id=$%d)`, f.MemberID)
	}
	if f.Unresolved {
		where += ` AND COALESCE(a.resolution,'unresolved')='unresolved'`
	}
	if f.Severity != "" {
		add(` AND f.severity=$%d`, f.Severity)
	}
	if f.Status != "" {
		add(` AND f.status=$%d`, f.Status)
	}
	if f.Kind != "" {
		add(` AND f.kind=$%d`, f.Kind)
	}
	if f.SLAStatus != "" {
		add(` AND sl.status=$%d`, f.SLAStatus)
	}
	if f.DueBefore != nil {
		add(` AND sa.remediate_by <= $%d`, *f.DueBefore)
	}
	return where, args, nil
}

func (r *OwnershipRepository) OwnershipInbox(ctx context.Context, f ports.OwnershipInboxFilter) (out ports.OwnershipInboxPage, err error) {
	out.Items = []ports.OwnershipInboxItem{}
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		where, args, err := ownershipInboxPredicate(tenant, f)
		if err != nil {
			return err
		}
		add := func(clause string, value any) { args = append(args, value); where += fmt.Sprintf(clause, len(args)) }
		if err := tx.QueryRow(ctx, `SELECT count(*)`+ownershipInboxFrom+where, args...).Scan(&out.Total); err != nil {
			return err
		}
		if !f.After.IsZero() {
			add(` AND f.id COLLATE "C">$%d`, f.After)
		}
		args = append(args, ownershipLimit(f.Limit)+1)
		rows, e := tx.Query(ctx, `SELECT f.id,f.engagement_id,f.title,f.severity,f.status,f.kind,f.version,COALESCE(a.team_id,''),COALESCE(a.assignee_id,''),COALESCE(a.legacy_assignee,f.assignee),COALESCE(a.mode,CASE WHEN f.assignee='' THEN 'auto' ELSE 'manual' END),COALESCE(a.revision,0),COALESCE(a.manual_generation,0),COALESCE(a.resolution,'unresolved'),COALESCE(a.reason,'not_evaluated'),COALESCE(sl.status,''),sa.remediate_by`+ownershipInboxFrom+where+fmt.Sprintf(` ORDER BY f.id COLLATE "C" LIMIT $%d`, len(args)), args...)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v ports.OwnershipInboxItem
			if e := rows.Scan(&v.ID, &v.EngagementID, &v.Title, &v.Severity, &v.Status, &v.Kind, &v.Version, &v.Assignment.TeamID, &v.Assignment.AssigneeID, &v.Assignment.LegacyAssignee, &v.Assignment.Mode, &v.Assignment.Revision, &v.Assignment.ManualGeneration, &v.Resolution, &v.Reason, &v.SLAStatus, &v.RemediateBy); e != nil {
				return e
			}
			out.Items = append(out.Items, v)
		}
		if e := rows.Err(); e != nil {
			return e
		}
		if len(out.Items) > ownershipLimit(f.Limit) {
			out.Items = out.Items[:ownershipLimit(f.Limit)]
			out.Next = out.Items[len(out.Items)-1].ID.String()
		}
		return nil
	})
	return
}
