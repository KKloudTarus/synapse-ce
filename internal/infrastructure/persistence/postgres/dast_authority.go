package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.DASTRunAuthority = (*DASTRunStore)(nil)

func (s *DASTRunStore) GetDASTRunAuthorization(ctx context.Context, tenant, runID shared.ID) (out ports.DASTRunAuthorization, err error) {
	if tenant.IsZero() || runID.IsZero() {
		return out, fmt.Errorf("%w: tenant and run required", shared.ErrValidation)
	}
	if current, ok := shared.TenantFrom(ctx); ok && current != tenant {
		return out, fmt.Errorf("%w: tenant mismatch", shared.ErrForbidden)
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error { var e error; out, e = s.readDASTAuthority(ctx, tx, tenant, runID); return e })
	if err != nil {
		return ports.DASTRunAuthorization{}, fmt.Errorf("read DAST authority: %w", err)
	}
	return out, nil
}

func (s *DASTRunStore) readDASTAuthority(ctx context.Context, tx pgx.Tx, tenant, runID shared.ID) (out ports.DASTRunAuthorization, err error) {
	var status, evidenceID string
	var issued *time.Time
	err = tx.QueryRow(ctx, `SELECT id,tenant_id,engagement_id,action_id,actor,status,verdict,http_status,evidence_id,error_code,started_at,finished_at,egress_grant_issued_at FROM dast_runs WHERE tenant_id=$1 AND id=$2`, tenant.String(), runID.String()).Scan(&out.Run.ID, &out.Run.TenantID, &out.Run.EngagementID, &out.Run.ActionID, &out.Run.Actor, &status, &out.Run.Verdict, &out.Run.HTTPStatus, &evidenceID, &out.Run.ErrorCode, &out.Run.StartedAt, &out.Run.FinishedAt, &issued)
	if err != nil {
		return out, dastAuthorityError(err, "run")
	}
	out.Run.Status = dastrun.RunStatus(status)
	out.Run.EvidenceID = shared.ID(evidenceID)
	out.GrantIssued = issued != nil
	var kind string
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT kind,payload FROM jobs WHERE tenant_id=$1 AND id=$2`, tenant.String(), runID.String()+"-job").Scan(&kind, &payload)
	if err != nil {
		return out, dastAuthorityError(err, "job")
	}
	if kind != "dast_run" {
		return out, fmt.Errorf("%w: invalid DAST job kind", shared.ErrForbidden)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&out.Job); err != nil {
		return out, fmt.Errorf("%w: malformed DAST job", shared.ErrForbidden)
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return out, fmt.Errorf("%w: malformed DAST job", shared.ErrForbidden)
	}
	if out.Job.TenantID != tenant || out.Job.RunID != runID {
		return out, fmt.Errorf("%w: DAST job identity", shared.ErrForbidden)
	}
	bound := bindTenantTransaction(ctx, tenant, tx)
	out.Action, out.Decision, err = NewApprovalStore(s.pool).Get(bound, out.Run.ActionID)
	if err != nil {
		return out, dastAuthorityError(err, "approval")
	}
	var owner *string
	var argv, egress []byte
	err = tx.QueryRow(ctx, `SELECT consumed_by_dast_run_id,argv,egress_preview FROM agent_approvals WHERE tenant_id=$1 AND action_id=$2`, tenant.String(), out.Run.ActionID.String()).Scan(&owner, &argv, &egress)
	if err != nil {
		return out, dastAuthorityError(err, "approval owner")
	}
	if err := json.Unmarshal(argv, &out.Action.Argv); err != nil {
		return out, fmt.Errorf("%w: malformed approval argv", shared.ErrForbidden)
	}
	if err := json.Unmarshal(egress, &out.Action.EgressPreview); err != nil {
		return out, fmt.Errorf("%w: malformed approval egress", shared.ErrForbidden)
	}
	if owner != nil {
		out.ConsumedBy = shared.ID(*owner)
	}
	out.Consumption, err = readDASTEvidence(ctx, tx, tenant, out.Run.EngagementID, ports.DASTConsumptionEvidenceID(runID))
	if err != nil {
		return out, err
	}
	var consumed ports.DASTApprovalConsumption
	if err = json.Unmarshal(out.Consumption.Content, &consumed); err != nil || consumed.AdmissionID.IsZero() {
		return out, fmt.Errorf("%w: malformed DAST custody", shared.ErrForbidden)
	}
	out.Admission, err = readDASTEvidence(ctx, tx, tenant, out.Run.EngagementID, consumed.AdmissionID)
	if err != nil {
		return out, err
	}
	return out, nil
}

func readDASTEvidence(ctx context.Context, tx pgx.Tx, tenant, engagementID, id shared.ID) (e evidence.Evidence, err error) {
	err = tx.QueryRow(ctx, `SELECT id,COALESCE(finding_id,''),engagement_id,kind,sha256,COALESCE(previous_hash,''),COALESCE(storage_ref,''),content,COALESCE(created_by,''),created_at FROM evidence WHERE tenant_id=$1 AND engagement_id=$2 AND id=$3`, tenant.String(), engagementID.String(), id.String()).Scan(&e.ID, &e.FindingID, &e.EngagementID, &e.Kind, &e.Hash, &e.PreviousHash, &e.StorageRef, &e.Content, &e.CreatedBy, &e.CreatedAt)
	if err != nil {
		return e, dastAuthorityError(err, "custody evidence")
	}
	return e, nil
}

func dastAuthorityError(err error, part string) error {
	if err == pgx.ErrNoRows {
		return fmt.Errorf("%w: DAST %s missing", shared.ErrForbidden, part)
	}
	return fmt.Errorf("DAST %s: %w", part, err)
}

func (s *DASTRunStore) ClaimDASTRunGrant(ctx context.Context, expected ports.DASTRunAuthorization, at time.Time) error {
	tenant, runID := expected.Run.TenantID, expected.Run.ID
	if tenant.IsZero() || runID.IsZero() || expected.Run.ActionID.IsZero() || at.IsZero() {
		return fmt.Errorf("%w: grant identity required", shared.ErrValidation)
	}
	if current, ok := shared.TenantFrom(ctx); ok && current != tenant {
		return fmt.Errorf("%w: tenant mismatch", shared.ErrForbidden)
	}
	if bound, ok := ctx.Value(tenantTransactionKey{}).(tenantTransaction); ok && bound.tenantID != tenant.String() {
		return fmt.Errorf("%w: transaction tenant mismatch", shared.ErrForbidden)
	}
	independent := context.WithValue(ctx, tenantTransactionKey{}, nil)
	err := requireTenant(independent, s.pool, tenant, func(tx pgx.Tx) error {
		var state string
		var owner *string
		e := tx.QueryRow(independent, `SELECT decision_state,consumed_by_dast_run_id FROM agent_approvals WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE`, tenant.String(), expected.Run.ActionID.String()).Scan(&state, &owner)
		if e != nil {
			return dastAuthorityError(e, "approval")
		}
		var status string
		var issued *time.Time
		e = tx.QueryRow(independent, `SELECT status,egress_grant_issued_at FROM dast_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant.String(), runID.String()).Scan(&status, &issued)
		if e != nil {
			return dastAuthorityError(e, "run")
		}
		if state != "consumed" || owner == nil || *owner != runID.String() || status != "running" || issued != nil {
			return fmt.Errorf("%w: DAST grant unavailable", shared.ErrForbidden)
		}
		// Hold the queued payload and both immutable custody links stable until the
		// one-shot marker commits, even if another database writer races issuance.
		var locked string
		if e = tx.QueryRow(independent, `SELECT id FROM jobs WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant.String(), runID.String()+"-job").Scan(&locked); e != nil {
			return dastAuthorityError(e, "job")
		}
		for _, id := range []shared.ID{expected.Consumption.ID, expected.Admission.ID} {
			if id.IsZero() {
				return fmt.Errorf("%w: missing custody evidence", shared.ErrForbidden)
			}
			if e = tx.QueryRow(independent, `SELECT id FROM evidence WHERE tenant_id=$1 AND engagement_id=$2 AND id=$3 FOR SHARE`, tenant.String(), expected.Run.EngagementID.String(), id.String()).Scan(&locked); e != nil {
				return dastAuthorityError(e, "custody evidence")
			}
		}
		actual, e := s.readDASTAuthority(independent, tx, tenant, runID)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(actual, expected) {
			return fmt.Errorf("%w: DAST authority changed", shared.ErrForbidden)
		}
		tag, e := tx.Exec(independent, `UPDATE dast_runs SET egress_grant_issued_at=$3 WHERE tenant_id=$1 AND id=$2 AND status='running' AND egress_grant_issued_at IS NULL`, tenant.String(), runID.String(), at)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: DAST grant unavailable", shared.ErrForbidden)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("claim DAST grant: %w", err)
	}
	return nil
}
