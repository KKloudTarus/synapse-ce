package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AttackPathStore persists derived asset-to-finding links behind PostgreSQL RLS.
type AttackPathStore struct{ pool *pgxpool.Pool }

func NewAttackPathStore(pool *pgxpool.Pool) *AttackPathStore { return &AttackPathStore{pool: pool} }

func lockAttackPathBindings(ctx context.Context, tx pgx.Tx, tenantID, engagementID, producer shared.ID) error {
	sum := sha256.Sum256([]byte(tenantID.String() + "\x00" + engagementID.String() + "\x00" + producer.String()))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(binary.BigEndian.Uint64(sum[:8]))); err != nil {
		return fmt.Errorf("lock attack path bindings: %w", err)
	}
	return nil
}

var _ ports.AttackPathStore = (*AttackPathStore)(nil)

func (s *AttackPathStore) ReplaceBindings(ctx context.Context, tenantID, engagementID, producer shared.ID, bindings []attackpath.Binding) error {
	bindings, err := validBindings(tenantID, engagementID, producer, bindings)
	if err != nil {
		return err
	}
	return WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		if err := lockAttackPathBindings(ctx, tx, tenantID, engagementID, producer); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM attack_path_edges WHERE tenant_id=$1 AND engagement_id=$2 AND producer=$3`, tenantID.String(), engagementID.String(), producer.String()); err != nil {
			return fmt.Errorf("delete attack path bindings: %w", err)
		}
		for _, b := range bindings {
			if _, err := tx.Exec(ctx, `
				INSERT INTO attack_path_edges
				(tenant_id, engagement_id, from_kind, from_id, to_kind, to_id, target_kind, canonical_finding_id, imported_finding_id, kind, producer, provenance, confidence)
				VALUES ($1,$2,'asset',$3,'finding',$4,$5,
					CASE WHEN $5 = 'canonical' THEN $4 END,
					CASE WHEN $5 = 'imported' THEN $4 END,
					'affected_by',$6,$7,$8)`,
				tenantID.String(), engagementID.String(), b.AssetID.String(), b.FindingID.String(), string(b.TargetKind), producer.String(), b.Provenance.String(), string(b.Confidence)); err != nil {
				return fmt.Errorf("insert attack path binding: %w", err)
			}
		}
		return nil
	})
}

func validBindings(tenantID, engagementID, producer shared.ID, bindings []attackpath.Binding) ([]attackpath.Binding, error) {
	if tenantID.IsZero() || engagementID.IsZero() || producer.IsZero() {
		return nil, fmt.Errorf("%w: attack path tenant, engagement, and producer are required", shared.ErrValidation)
	}
	out := append([]attackpath.Binding(nil), bindings...)
	for i := range out {
		b := &out[i]
		if b.TargetKind == "" {
			b.TargetKind = attackpath.TargetCanonical
		}
		if b.TenantID != tenantID || b.EngagementID != engagementID || b.Producer != producer || b.AssetID.IsZero() || b.FindingID.IsZero() || !b.TargetKind.Valid() || b.Provenance.IsZero() || !b.Confidence.Valid() {
			return nil, fmt.Errorf("%w: invalid attack path binding", shared.ErrValidation)
		}
	}
	return out, nil
}

func (s *AttackPathStore) ListBindings(ctx context.Context, tenantID shared.ID) ([]attackpath.Binding, error) {
	var out []attackpath.Binding
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, engagement_id, from_id, to_id, target_kind, producer, provenance, confidence
			FROM attack_path_edges WHERE tenant_id=$1
			ORDER BY engagement_id, from_id, to_id, producer, provenance`, tenantID.String())
		if err != nil {
			return fmt.Errorf("list attack path bindings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var tenant, engagement, from, to, targetKind, producer, provenance, confidence string
			if err := rows.Scan(&tenant, &engagement, &from, &to, &targetKind, &producer, &provenance, &confidence); err != nil {
				return err
			}
			b := attackpath.Binding{TenantID: shared.ID(tenant), EngagementID: shared.ID(engagement), AssetID: shared.ID(from), FindingID: shared.ID(to), TargetKind: attackpath.TargetKind(targetKind), Producer: shared.ID(producer), Provenance: shared.ID(provenance), Confidence: asset.EdgeConfidence(confidence)}
			if b.TenantID.IsZero() || b.EngagementID.IsZero() || b.AssetID.IsZero() || b.FindingID.IsZero() || !b.TargetKind.Valid() || b.Producer.IsZero() || b.Provenance.IsZero() || !b.Confidence.Valid() {
				return fmt.Errorf("%w: invalid stored attack path binding", shared.ErrValidation)
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}
