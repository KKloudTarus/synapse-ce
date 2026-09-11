package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func ownershipCurrent(ctx context.Context, tx pgx.Tx, tenant, eng, finding shared.ID, lock bool) (out ports.OwnershipCurrent, err error) {
	query := `SELECT f.version,f.assignee,COALESCE(a.team_id,''),COALESCE(a.assignee_id,''),COALESCE(a.legacy_assignee,f.assignee),COALESCE(a.mode,CASE WHEN f.assignee='' THEN 'auto' ELSE 'manual' END),COALESCE(a.revision,0),COALESCE(a.manual_generation,0),COALESCE(a.resolution,'unresolved'),COALESCE(a.reason,'not_evaluated'),COALESCE(a.updated_at,f.updated_at) FROM findings f LEFT JOIN ownership_assignments a ON a.tenant_id=f.tenant_id AND a.engagement_id=f.engagement_id AND a.finding_id=f.id WHERE f.tenant_id=$1 AND f.engagement_id=$2 AND f.id=$3`
	if lock {
		query += ` FOR UPDATE OF f`
	}
	err = tx.QueryRow(ctx, query, tenant, eng, finding).Scan(&out.FindingVersion, &out.FindingAssignee, &out.Assignment.TeamID, &out.Assignment.AssigneeID, &out.Assignment.LegacyAssignee, &out.Assignment.Mode, &out.Assignment.Revision, &out.Assignment.ManualGeneration, &out.Resolution, &out.Reason, &out.UpdatedAt)
	return
}
func (r *OwnershipRepository) GetAssignment(ctx context.Context, eng, finding shared.ID) (out ports.OwnershipCurrent, err error) {
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		var e error
		out, e = ownershipCurrent(ctx, tx, tenant, eng, finding, false)
		return e
	})
	return
}

func validateOwnershipMutation(m ports.OwnershipMutation) error {
	if m.ClearAssignee && (m.Kind != "transfer" || !m.AssigneeID.IsZero() || m.LegacyAssignee != "") {
		return shared.ErrValidation
	}
	if m.Kind == "transfer" && m.TeamID.IsZero() {
		return shared.ErrValidation
	}
	if m.LegacyEndpoint && m.Kind != "assign" {
		return shared.ErrValidation
	}
	if m.EngagementID.IsZero() || m.FindingID.IsZero() || m.DecisionID.IsZero() || strings.TrimSpace(m.Actor) == "" || len(m.Actor) > 200 || m.Key == "" || len(m.Key) > 256 || m.ExpectedFindingVersion < 1 || m.ExpectedRevision < 0 || m.ExpectedManualGeneration < 0 || m.At.IsZero() {
		return shared.ErrValidation
	}
	if m.Kind != "assign" && m.Kind != "transfer" && m.Kind != "claim" && m.Kind != "clear" && m.Kind != "release" && m.Kind != "route" {
		return shared.ErrValidation
	}
	if m.Kind == "route" {
		if m.JobID == "" || m.Fence < 1 || m.PolicyID.IsZero() || m.PolicyVersion < 1 || m.ExpectedPolicyRevision < 1 || !m.Result.Resolution.Valid() || len(m.Result.PolicyHash) != 64 || len(m.Result.InputHash) != 64 || m.Result.Reason == "" || m.TeamID != m.Result.TeamID || !m.AssigneeID.IsZero() || m.LegacyAssignee != "" {
			return shared.ErrValidation
		}
		if (m.Result.Resolution == ownership.Resolved) != !m.TeamID.IsZero() {
			return shared.ErrValidation
		}
	} else if !m.PolicyID.IsZero() || m.PolicyVersion != 0 || m.JobID != "" || m.Fence != 0 {
		return shared.ErrValidation
	}
	if m.Kind == "claim" && (m.TeamID.IsZero() || m.AssigneeID.String() != m.Actor || m.LegacyAssignee != m.Actor) {
		return shared.ErrValidation
	}
	if (m.Kind == "clear" || m.Kind == "release") && (!m.TeamID.IsZero() || !m.AssigneeID.IsZero() || m.LegacyAssignee != "") {
		return shared.ErrValidation
	}
	return (ownership.Assignment{Mode: "manual", TeamID: m.TeamID, AssigneeID: m.AssigneeID, LegacyAssignee: m.LegacyAssignee}).Validate()
}

func ownershipRequestHash(m ports.OwnershipMutation) string {
	// A redelivery has a new fence/time/decision ID, but must recover the exact
	// original transition. Changed actor, target or routing evidence conflicts.
	m.DecisionID = ""
	m.At = time.Time{}
	m.JobID = ""
	m.Fence = 0
	m.ExpectedFindingVersion = 0
	m.ExpectedRevision = 0
	m.ExpectedManualGeneration = 0
	m.ExpectedPolicyRevision = 0
	m.Notify = false
	b, _ := json.Marshal(m)
	return ownership.ContentHash(string(b))
}

func ownershipFence(ctx context.Context, tx pgx.Tx, tenant shared.ID, m ports.OwnershipMutation) error {
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM jobs WHERE tenant_id=$1 AND id=$2 AND kind='ownership.route' AND status='claimed' AND claim_fence=$3 AND claimed_until>clock_timestamp() FOR UPDATE`, tenant, m.JobID, m.Fence).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.ErrStaleLease
	}
	return err
}

func (r *OwnershipRepository) ApplyAssignment(ctx context.Context, m ports.OwnershipMutation) (out ownership.Decision, err error) {
	if err = validateOwnershipMutation(m); err != nil {
		return out, err
	}
	m.At = m.At.UTC().Truncate(time.Microsecond)
	requestHash := ownershipRequestHash(m)
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		// Lock order: job, finding, policy scope, policy, teams/users, audit LAST.
		if m.Kind == "route" {
			if err := ownershipFence(ctx, tx, tenant, m); err != nil {
				return err
			}
		}
		current, err := ownershipCurrent(ctx, tx, tenant, m.EngagementID, m.FindingID, true)
		if err != nil {
			return err
		}
		var storedHash string
		var stored []byte
		err = tx.QueryRow(ctx, `SELECT request_hash,payload FROM ownership_decisions WHERE tenant_id=$1 AND transition_key=$2`, tenant, m.Key).Scan(&storedHash, &stored)
		if err == nil {
			if storedHash != requestHash {
				return shared.ErrConflict
			}
			if err := json.Unmarshal(stored, &out); err != nil {
				return err
			}
			out.TenantID = tenant
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if current.FindingVersion != m.ExpectedFindingVersion || current.Assignment.Revision != m.ExpectedRevision || current.Assignment.ManualGeneration != m.ExpectedManualGeneration {
			return shared.ErrConflict
		}
		before := current.Assignment
		after := ownership.Assignment{TeamID: m.TeamID, AssigneeID: m.AssigneeID, LegacyAssignee: m.LegacyAssignee, Mode: "manual", Revision: before.Revision, ManualGeneration: before.ManualGeneration + 1}
		preserveAssignee := m.Kind == "transfer" && !m.ClearAssignee && m.AssigneeID.IsZero()
		if preserveAssignee {
			if before.AssigneeID.IsZero() && current.FindingAssignee != "" {
				return fmt.Errorf("%w: choose an eligible assignee or clear_assignee for a legacy owner", shared.ErrConflict)
			}
			after.AssigneeID, after.LegacyAssignee = before.AssigneeID, before.LegacyAssignee
		}
		if m.Kind == "route" {
			if before.Mode == "manual" || current.FindingAssignee != "" || before.LegacyAssignee != current.FindingAssignee {
				return fmt.Errorf("%w: manual ownership is protected", shared.ErrConflict)
			}
			if err := ownershipCheckPolicy(ctx, tx, tenant, m); err != nil {
				return err
			}
			after.Mode = "auto"
			after.ManualGeneration = before.ManualGeneration
		} else {
			if err := ownershipEligibleUser(ctx, tx, tenant, shared.ID(m.Actor), "", true); err != nil {
				return err
			}
			if m.Kind == "claim" && before.TeamID != m.TeamID {
				return shared.ErrConflict
			}
			m.Result = ownership.Result{Resolution: ownership.Unresolved, Reason: "manual_" + m.Kind, Candidates: []shared.ID{}, Evidence: []ownership.PathEvidence{}}
			if m.Kind == "release" {
				after.Mode = "auto"
				after.TeamID = before.TeamID
			}
			if !after.TeamID.IsZero() {
				m.Result.Resolution = ownership.Resolved
				m.Result.TeamID = after.TeamID
				m.Result.Candidates = []shared.ID{after.TeamID}
			}
		}
		if !after.TeamID.IsZero() {
			if err := ownershipActiveTeam(ctx, tx, tenant, after.TeamID); err != nil {
				return err
			}
		}
		if !after.AssigneeID.IsZero() {
			if err := ownershipEligibleUser(ctx, tx, tenant, after.AssigneeID, after.TeamID, true); err != nil {
				if preserveAssignee && (errors.Is(err, shared.ErrForbidden) || errors.Is(err, pgx.ErrNoRows) || errors.Is(err, shared.ErrValidation)) {
					return fmt.Errorf("%w: choose an eligible assignee or clear_assignee for the destination team", shared.ErrConflict)
				}
				return err
			}
		}
		effectiveChanged := before.TeamID != after.TeamID || before.AssigneeID != after.AssigneeID || current.FindingAssignee != after.LegacyAssignee
		stateChanged := effectiveChanged || before.Mode != after.Mode || before.ManualGeneration != after.ManualGeneration || before.Revision == 0
		if stateChanged {
			after.Revision++
		}
		if effectiveChanged || m.LegacyEndpoint {
			if err := ownershipCAS(tx.Exec(ctx, `UPDATE findings SET assignee=$4,version=version+1,updated_at=$5 WHERE tenant_id=$1 AND engagement_id=$2 AND id=$3 AND version=$6`, tenant, m.EngagementID, m.FindingID, after.LegacyAssignee, m.At, m.ExpectedFindingVersion)); err != nil {
				return err
			}
		}
		if stateChanged || current.Resolution != m.Result.Resolution || current.Reason != m.Result.Reason {
			_, err = tx.Exec(ctx, `INSERT INTO ownership_assignments(tenant_id,engagement_id,finding_id,team_id,assignee_id,legacy_assignee,mode,revision,manual_generation,resolution,reason,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (tenant_id,engagement_id,finding_id) DO UPDATE SET team_id=EXCLUDED.team_id,assignee_id=EXCLUDED.assignee_id,legacy_assignee=EXCLUDED.legacy_assignee,mode=EXCLUDED.mode,revision=EXCLUDED.revision,manual_generation=EXCLUDED.manual_generation,resolution=EXCLUDED.resolution,reason=EXCLUDED.reason,updated_at=EXCLUDED.updated_at`, tenant, m.EngagementID, m.FindingID, nullableID(after.TeamID), nullableID(after.AssigneeID), after.LegacyAssignee, after.Mode, after.Revision, after.ManualGeneration, m.Result.Resolution, m.Result.Reason, m.At)
			if err != nil {
				return err
			}
		}
		out = ownership.Decision{TenantID: tenant, ID: m.DecisionID, EngagementID: m.EngagementID, FindingID: m.FindingID, Key: m.Key, Actor: m.Actor, Before: before, After: after, Result: m.Result, CreatedAt: m.At}
		payload, err := json.Marshal(out)
		if err != nil {
			return err
		}
		if len(payload) > 4*1024*1024 {
			return shared.ErrValidation
		}
		var policyVersion any
		if m.PolicyVersion > 0 {
			policyVersion = m.PolicyVersion
		}
		_, err = tx.Exec(ctx, `INSERT INTO ownership_decisions(tenant_id,engagement_id,finding_id,id,transition_key,request_hash,policy_id,policy_version,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, tenant, m.EngagementID, m.FindingID, out.ID, m.Key, requestHash, nullableID(m.PolicyID), policyVersion, payload, m.At)
		if err != nil {
			return err
		}
		if effectiveChanged {
			data, _ := json.Marshal(map[string]any{"decision_id": out.ID, "finding_id": m.FindingID, "engagement_id": m.EngagementID, "old_team_id": before.TeamID, "new_team_id": after.TeamID})
			state := "suppressed"
			if m.Notify {
				state = "pending"
			}
			if err := ownershipInsertIntent(ctx, tx, tenant, ports.OwnershipIntent{ID: shared.ID("notification:" + out.ID.String()), EngagementID: m.EngagementID, FindingID: m.FindingID, Kind: "notification", SourceKey: m.Key, DecisionID: out.ID, Payload: data, State: state, CreatedAt: m.At}); err != nil {
				return err
			}
		}
		if m.Kind == "release" {
			data, _ := json.Marshal(map[string]any{"decision_id": out.ID, "manual_generation": after.ManualGeneration})
			if err := ownershipInsertIntent(ctx, tx, tenant, ports.OwnershipIntent{ID: shared.ID("route:" + out.ID.String()), EngagementID: m.EngagementID, FindingID: m.FindingID, Kind: "route", SourceKey: m.Key, DecisionID: out.ID, Payload: data, State: "pending", CreatedAt: m.At}); err != nil {
				return err
			}
		}
		if m.Kind == "route" {
			if err := ownershipFence(ctx, tx, tenant, m); err != nil {
				return err
			}
		}
		auditAction := "finding.ownership_changed"
		if !stateChanged {
			auditAction = "finding.ownership_evaluated"
		}
		// No SQL after this append: audit takes the deployment chain lock.
		return appendTenantAudit(ctx, tx, tenant.String(), ports.AuditEntry{Actor: m.Actor, Action: auditAction, Target: m.FindingID.String(), At: m.At, Metadata: map[string]string{"engagement_id": m.EngagementID.String(), "decision_id": out.ID.String(), "reason": m.Result.Reason, "old_team_id": before.TeamID.String(), "new_team_id": after.TeamID.String(), "idempotency_key": "ownership:" + m.Key}})
	})
	return
}

func (r *OwnershipRepository) ListDecisions(ctx context.Context, eng, finding shared.ID, cursor ports.OwnershipHistoryCursor) (out []ownership.Decision, err error) {
	out = []ownership.Decision{}
	err = r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		rows, e := tx.Query(ctx, `SELECT payload FROM ownership_decisions WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=$3 AND ($4::timestamptz IS NULL OR (created_at,id)<($4,$5)) ORDER BY created_at DESC,id DESC LIMIT $6`, tenant, eng, finding, ownershipTimeOrNil(cursor.Before), cursor.BeforeID, ownershipLimit(cursor.Limit))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var data []byte
			var d ownership.Decision
			if e := rows.Scan(&data); e != nil {
				return e
			}
			if e := json.Unmarshal(data, &d); e != nil {
				return e
			}
			d.TenantID = tenant
			out = append(out, d)
		}
		return rows.Err()
	})
	return
}
func ownershipTimeOrNil(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return at
}
