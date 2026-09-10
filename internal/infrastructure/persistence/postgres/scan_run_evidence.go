package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.ScanRunEvidenceStore = (*ScanRunStore)(nil)

func (r *ScanRunStore) SaveScanRunEvidence(ctx context.Context, item ports.ScanRunEvidence) error {
	if err := item.Validate(); err != nil {
		return err
	}
	return WithTenant(ctx, r.pool, item.TenantID.String(), func(tx pgx.Tx) error {
		var sealed bool
		if err := tx.QueryRow(ctx, "SELECT sealed_at IS NOT NULL FROM scan_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE", item.TenantID.String(), item.RunID).Scan(&sealed); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return err
		}
		var hash string
		var payload []byte
		err := tx.QueryRow(ctx, "SELECT content_hash,payload FROM scan_run_comparison_evidence WHERE tenant_id=$1 AND run_id=$2", item.TenantID.String(), item.RunID).Scan(&hash, &payload)
		if err == nil {
			if hash != item.ContentHash || !bytes.Equal(payload, item.Payload) {
				return fmt.Errorf("%w: scan evidence replay differs", shared.ErrConflict)
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if sealed {
			return fmt.Errorf("%w: cannot append evidence to a sealed run", shared.ErrConflict)
		}
		_, err = tx.Exec(ctx, "INSERT INTO scan_run_comparison_evidence(tenant_id,run_id,content_hash,payload) VALUES ($1,$2,$3,$4)", item.TenantID.String(), item.RunID, item.ContentHash, item.Payload)
		return err
	})
}

func (r *ScanRunStore) GetScanRunEvidence(ctx context.Context, tenantID shared.ID, runID string) (ports.ScanRunEvidence, error) {
	item := ports.ScanRunEvidence{TenantID: tenantID, RunID: runID}
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "SELECT content_hash,payload FROM scan_run_comparison_evidence WHERE tenant_id=$1 AND run_id=$2", tenantID.String(), runID).Scan(&item.ContentHash, &item.Payload)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		return err
	})
	if err == nil {
		err = item.Validate()
	}
	return item, err
}
