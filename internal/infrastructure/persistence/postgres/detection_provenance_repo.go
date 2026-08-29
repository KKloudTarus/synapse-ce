package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DetectionProvenanceRepository retains the current read projection and append-only transition facts.
type DetectionProvenanceRepository struct{ pool *pgxpool.Pool }

var _ ports.DetectionProvenanceStore = (*DetectionProvenanceRepository)(nil)

func NewDetectionProvenanceRepository(pool *pgxpool.Pool) (*DetectionProvenanceRepository, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: detection provenance repository requires a database pool", shared.ErrValidation)
	}
	return &DetectionProvenanceRepository{pool: pool}, nil
}

func requireProvenanceTenant(ctx context.Context) (shared.ID, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return "", fmt.Errorf("%w: detection provenance requires a tenant in context", shared.ErrValidation)
	}
	return tenant, nil
}

func (r *DetectionProvenanceRepository) AdmitPending(ctx context.Context, current detectionprovenance.Current, received detectionprovenance.Transition) error {
	tenant, err := requireProvenanceTenant(ctx)
	if err != nil {
		return err
	}
	if err := current.Validate(); err != nil {
		return err
	}
	if err := received.Validate(); err != nil {
		return err
	}
	if current.TenantID != tenant || received.TenantID != tenant || current.EngagementID != received.EngagementID ||
		current.DetectionID != received.DetectionID || current.Status != detectionprovenance.StatusPending || !current.EvidenceID.IsZero() ||
		received.Sequence != 1 || received.Kind != detectionprovenance.Received || received.Status != detectionprovenance.StatusPending {
		return fmt.Errorf("%w: invalid pending detection provenance admission", shared.ErrValidation)
	}
	received = detectionprovenance.SealTransition(received, "")
	telemetryRefs, err := json.Marshal(received.TelemetryRefs)
	if err != nil {
		return fmt.Errorf("marshal admitted provenance telemetry references: %w", err)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO detection_provenance_current
			(tenant_id,engagement_id,detection_id,status,evidence_id,pending_input,updated_at)
			VALUES ($1,$2,$3,$4,NULL,$5,$6)
			ON CONFLICT (tenant_id,engagement_id,detection_id) DO NOTHING`,
			tenant.String(), current.EngagementID.String(), current.DetectionID.String(), string(current.Status), current.PendingInput, current.UpdatedAt.UTC())
		if err != nil {
			return fmt.Errorf("insert pending provenance current state: %w", err)
		}
		if tag.RowsAffected() == 1 {
			if _, err := tx.Exec(ctx, `INSERT INTO detection_provenance_transitions
				(tenant_id,engagement_id,detection_id,sequence,kind,status,evidence_id,agent_id,asset_id,telemetry_refs,reason,previous_hash,entry_hash,occurred_at)
				VALUES ($1,$2,$3,1,$4,$5,NULL,NULLIF($6,''),NULLIF($7,''),$8::jsonb,$9,$10,$11,$12)`,
				tenant.String(), received.EngagementID.String(), received.DetectionID.String(), string(received.Kind), string(received.Status), received.AgentID.String(), received.AssetID.String(), telemetryRefs, received.Reason, received.PreviousHash, received.Hash, received.OccurredAt.UTC()); err != nil {
				return fmt.Errorf("insert received provenance transition: %w", err)
			}
			return nil
		}

		var existing detectionprovenance.Current
		err = tx.QueryRow(ctx, `SELECT status,COALESCE(evidence_id,''),pending_input,updated_at
			FROM detection_provenance_current
			WHERE tenant_id=$1 AND engagement_id=$2 AND detection_id=$3
			FOR UPDATE`, tenant.String(), current.EngagementID.String(), current.DetectionID.String()).
			Scan(&existing.Status, &existing.EvidenceID, &existing.PendingInput, &existing.UpdatedAt)
		if err == pgx.ErrNoRows {
			return fmt.Errorf("%w: conflicting provenance admission is not visible", shared.ErrConflict)
		}
		if err != nil {
			return fmt.Errorf("read existing provenance admission: %w", err)
		}
		if string(existing.PendingInput) != string(current.PendingInput) {
			return fmt.Errorf("%w: detection provenance identity is already admitted with different content", shared.ErrConflict)
		}
		var first detectionprovenance.Transition
		var refs []byte
		err = tx.QueryRow(ctx, `SELECT kind,status,COALESCE(evidence_id,''),COALESCE(agent_id,''),COALESCE(asset_id,''),telemetry_refs,reason,previous_hash,entry_hash,occurred_at
			FROM detection_provenance_transitions
			WHERE tenant_id=$1 AND engagement_id=$2 AND detection_id=$3 AND sequence=1`,
			tenant.String(), current.EngagementID.String(), current.DetectionID.String()).
			Scan(&first.Kind, &first.Status, &first.EvidenceID, &first.AgentID, &first.AssetID, &refs, &first.Reason, &first.PreviousHash, &first.Hash, &first.OccurredAt)
		if err != nil {
			return fmt.Errorf("read admitted provenance transition: %w", err)
		}
		if err := json.Unmarshal(refs, &first.TelemetryRefs); err != nil {
			return fmt.Errorf("decode admitted provenance telemetry references: %w", err)
		}
		first.TenantID, first.EngagementID, first.DetectionID, first.Sequence = tenant, current.EngagementID, current.DetectionID, 1
		if err := detectionprovenance.VerifyChain([]detectionprovenance.Transition{first}); err != nil {
			return fmt.Errorf("verify admitted detection provenance chain: %w", err)
		}
		candidate := received
		candidate.OccurredAt = first.OccurredAt
		if detectionprovenance.EquivalentTransition(first, candidate) {
			return nil
		}
		return fmt.Errorf("%w: detection provenance identity is already admitted with different attribution", shared.ErrConflict)
	})
}

func (r *DetectionProvenanceRepository) AppendTransition(ctx context.Context, transition detectionprovenance.Transition) error {
	tenant, err := requireProvenanceTenant(ctx)
	if err != nil {
		return err
	}
	if err := transition.Validate(); err != nil {
		return err
	}
	if transition.TenantID != tenant {
		return fmt.Errorf("%w: detection provenance transition tenant differs from context", shared.ErrForbidden)
	}
	telemetryRefs, err := json.Marshal(transition.TelemetryRefs)
	if err != nil {
		return fmt.Errorf("marshal provenance telemetry references: %w", err)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var current detectionprovenance.Current
		err := tx.QueryRow(ctx, `SELECT status,COALESCE(evidence_id,''),pending_input,updated_at
			FROM detection_provenance_current
			WHERE tenant_id=$1 AND engagement_id=$2 AND detection_id=$3
			FOR UPDATE`, tenant.String(), transition.EngagementID.String(), transition.DetectionID.String()).
			Scan(&current.Status, &current.EvidenceID, &current.PendingInput, &current.UpdatedAt)
		if err == pgx.ErrNoRows {
			return fmt.Errorf("%w: detection provenance must be admitted before advancing", shared.ErrConflict)
		}
		if err != nil {
			return fmt.Errorf("lock provenance current state: %w", err)
		}
		current.TenantID, current.EngagementID, current.DetectionID = tenant, transition.EngagementID, transition.DetectionID

		rows, err := tx.Query(ctx, `SELECT sequence,kind,status,COALESCE(evidence_id,''),COALESCE(agent_id,''),COALESCE(asset_id,''),telemetry_refs,reason,previous_hash,entry_hash,occurred_at
			FROM detection_provenance_transitions
			WHERE tenant_id=$1 AND engagement_id=$2 AND detection_id=$3 ORDER BY sequence`,
			tenant.String(), transition.EngagementID.String(), transition.DetectionID.String())
		if err != nil {
			return fmt.Errorf("list existing provenance transitions: %w", err)
		}
		var history []detectionprovenance.Transition
		for rows.Next() {
			var existing detectionprovenance.Transition
			var refs []byte
			if err := rows.Scan(&existing.Sequence, &existing.Kind, &existing.Status, &existing.EvidenceID, &existing.AgentID, &existing.AssetID, &refs, &existing.Reason, &existing.PreviousHash, &existing.Hash, &existing.OccurredAt); err != nil {
				rows.Close()
				return fmt.Errorf("scan existing provenance transition: %w", err)
			}
			if err := json.Unmarshal(refs, &existing.TelemetryRefs); err != nil {
				rows.Close()
				return fmt.Errorf("decode existing provenance telemetry references: %w", err)
			}
			existing.TenantID, existing.EngagementID, existing.DetectionID = tenant, transition.EngagementID, transition.DetectionID
			history = append(history, existing)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate existing provenance transitions: %w", err)
		}
		rows.Close()
		if len(history) == 0 {
			return fmt.Errorf("%w: detection provenance current state has no transition history", shared.ErrConflict)
		}
		if err := detectionprovenance.VerifyChain(history); err != nil {
			return fmt.Errorf("verify detection provenance chain: %w", err)
		}
		transition.Sequence = uint64(len(history) + 1)
		for _, existing := range history {
			candidate := transition
			candidate.Sequence = existing.Sequence
			candidate.OccurredAt = existing.OccurredAt
			if detectionprovenance.EquivalentTransition(existing, candidate) {
				return nil
			}
		}
		previous := history[len(history)-1]
		previousKind := previous.Kind
		transition = detectionprovenance.SealTransition(transition, previous.Hash)
		next, err := detectionprovenance.Apply(&current, previousKind, transition)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO detection_provenance_transitions
			(tenant_id,engagement_id,detection_id,sequence,kind,status,evidence_id,agent_id,asset_id,telemetry_refs,reason,previous_hash,entry_hash,occurred_at)
			VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),$10::jsonb,$11,$12,$13,$14)`,
			tenant.String(), transition.EngagementID.String(), transition.DetectionID.String(), int64(transition.Sequence), string(transition.Kind), string(transition.Status), transition.EvidenceID.String(), transition.AgentID.String(), transition.AssetID.String(), telemetryRefs, transition.Reason, transition.PreviousHash, transition.Hash, transition.OccurredAt.UTC()); err != nil {
			return fmt.Errorf("insert provenance transition: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE detection_provenance_current
			SET status=$4,evidence_id=NULLIF($5,''),updated_at=$6
			WHERE tenant_id=$1 AND engagement_id=$2 AND detection_id=$3`,
			tenant.String(), next.EngagementID.String(), next.DetectionID.String(), string(next.Status), next.EvidenceID.String(), next.UpdatedAt.UTC()); err != nil {
			return fmt.Errorf("update provenance current state: %w", err)
		}
		return nil
	})
}

func (r *DetectionProvenanceRepository) Current(ctx context.Context, engagementID, detectionID shared.ID) (detectionprovenance.Current, bool, error) {
	tenant, err := requireProvenanceTenant(ctx)
	if err != nil {
		return detectionprovenance.Current{}, false, err
	}
	var current detectionprovenance.Current
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status,COALESCE(evidence_id,''),pending_input,updated_at FROM detection_provenance_current
			WHERE tenant_id=$1 AND engagement_id=$2 AND detection_id=$3`, tenant.String(), engagementID.String(), detectionID.String()).
			Scan(&current.Status, &current.EvidenceID, &current.PendingInput, &current.UpdatedAt)
	})
	if err == pgx.ErrNoRows {
		return detectionprovenance.Current{}, false, nil
	}
	if err != nil {
		return detectionprovenance.Current{}, false, fmt.Errorf("read provenance current state: %w", err)
	}
	current.TenantID, current.EngagementID, current.DetectionID = tenant, engagementID, detectionID
	return current, true, nil
}

func (r *DetectionProvenanceRepository) ListCurrent(ctx context.Context, engagementID shared.ID) ([]detectionprovenance.Current, error) {
	tenant, err := requireProvenanceTenant(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]detectionprovenance.Current, 0)
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT detection_id,status,COALESCE(evidence_id,''),pending_input,updated_at FROM detection_provenance_current
			WHERE tenant_id=$1 AND engagement_id=$2 ORDER BY detection_id`, tenant.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list provenance current states: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var current detectionprovenance.Current
			if err := rows.Scan(&current.DetectionID, &current.Status, &current.EvidenceID, &current.PendingInput, &current.UpdatedAt); err != nil {
				return fmt.Errorf("scan provenance current state: %w", err)
			}
			current.TenantID, current.EngagementID = tenant, engagementID
			out = append(out, current)
		}
		return rows.Err()
	})
	return out, err
}

func (r *DetectionProvenanceRepository) ListPending(ctx context.Context) ([]detectionprovenance.Current, error) {
	tenant, err := requireProvenanceTenant(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]detectionprovenance.Current, 0)
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT engagement_id,detection_id,status,COALESCE(evidence_id,''),pending_input,updated_at
			FROM detection_provenance_current
			WHERE tenant_id=$1 AND status=$2
			ORDER BY engagement_id,detection_id`, tenant.String(), string(detectionprovenance.StatusPending))
		if err != nil {
			return fmt.Errorf("list pending provenance states: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var current detectionprovenance.Current
			if err := rows.Scan(&current.EngagementID, &current.DetectionID, &current.Status, &current.EvidenceID, &current.PendingInput, &current.UpdatedAt); err != nil {
				return fmt.Errorf("scan pending provenance state: %w", err)
			}
			current.TenantID = tenant
			out = append(out, current)
		}
		return rows.Err()
	})
	return out, err
}

func (r *DetectionProvenanceRepository) ListTransitions(ctx context.Context, engagementID, detectionID shared.ID) ([]detectionprovenance.Transition, error) {
	tenant, err := requireProvenanceTenant(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]detectionprovenance.Transition, 0)
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT sequence,kind,status,COALESCE(evidence_id,''),COALESCE(agent_id,''),COALESCE(asset_id,''),telemetry_refs,reason,previous_hash,entry_hash,occurred_at FROM detection_provenance_transitions
			WHERE tenant_id=$1 AND engagement_id=$2 AND detection_id=$3 ORDER BY sequence`, tenant.String(), engagementID.String(), detectionID.String())
		if err != nil {
			return fmt.Errorf("list provenance transitions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var transition detectionprovenance.Transition
			var telemetryRefs []byte
			if err := rows.Scan(&transition.Sequence, &transition.Kind, &transition.Status, &transition.EvidenceID, &transition.AgentID, &transition.AssetID, &telemetryRefs, &transition.Reason, &transition.PreviousHash, &transition.Hash, &transition.OccurredAt); err != nil {
				return fmt.Errorf("scan provenance transition: %w", err)
			}
			if err := json.Unmarshal(telemetryRefs, &transition.TelemetryRefs); err != nil {
				return fmt.Errorf("decode provenance telemetry references: %w", err)
			}
			transition.TenantID, transition.EngagementID, transition.DetectionID = tenant, engagementID, detectionID
			out = append(out, transition)
		}
		return rows.Err()
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	if err == nil {
		if verifyErr := detectionprovenance.VerifyChain(out); verifyErr != nil {
			return nil, fmt.Errorf("verify detection provenance chain: %w", verifyErr)
		}
	}
	return out, err
}
