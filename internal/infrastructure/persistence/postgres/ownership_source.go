package postgres

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.OwnershipSourceStore = (*OwnershipRepository)(nil)

func (r *OwnershipRepository) MarkOwnershipSourceReady(ctx context.Context, eng, id shared.ID) error {
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		_, err := tx.Exec(ctx, `INSERT INTO ownership_source_readiness(tenant_id,engagement_id,source_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, tenant, eng, id)
		return err
	})
}

func (r *OwnershipRepository) SaveOwnershipSource(ctx context.Context, source ports.OwnershipSourceRecord) error {
	if source.ID.IsZero() || source.EngagementID.IsZero() || source.Repository == "" || len(source.Repository) > 2048 || strings.TrimSpace(source.CreatedBy) == "" || source.CreatedAt.IsZero() || len(source.Snapshots) > 2 || source.Revision != "" && !ownership.PinnedRevision(source.Revision) || source.BaseRevision != "" && !ownership.PinnedRevision(source.BaseRevision) {
		return shared.ErrValidation
	}
	return r.within(ctx, func(tx pgx.Tx, tenant shared.ID) error {
		txCtx := context.WithValue(ctx, tenantTransactionKey{}, tenantTransaction{tenantID: tenant.String(), tx: tx})
		_, err := tx.Exec(ctx, `INSERT INTO ownership_sources(tenant_id,engagement_id,id,repository,source_revision,base_revision,reason,created_by,created_at,base_required) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, tenant, source.EngagementID, source.ID, source.Repository, source.Revision, source.BaseRevision, source.Reason, source.CreatedBy, source.CreatedAt, source.BaseRequired)
		if err != nil {
			return err
		}
		for _, snapshot := range source.Snapshots {
			if snapshot.TenantID != tenant || snapshot.EngagementID != source.EngagementID || snapshot.Repository != source.Repository || snapshot.Trust != "untrusted" || snapshot.ApprovedBy != "" || snapshot.Revision != source.Revision && snapshot.Revision != source.BaseRevision {
				return shared.ErrValidation
			}
			if err := r.CreateSnapshot(txCtx, snapshot); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO ownership_source_snapshots(tenant_id,engagement_id,source_id,snapshot_id) VALUES($1,$2,$3,$4)`, tenant, source.EngagementID, source.ID, snapshot.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

func ownershipOriginHash(kind, occurrence, component string) string {
	data, _ := json.Marshal([]string{kind, occurrence, component})
	return ownership.ContentHash(string(data))
}

func ownershipBindFinding(ctx context.Context, tx pgx.Tx, tenant shared.ID, f finding.Finding, batch ports.OwnershipSourceBatch) error {
	if batch.Source.EngagementID != f.EngagementID || batch.Source.ID.IsZero() {
		return shared.ErrValidation
	}
	evidence, ok := batch.Findings[finding.Identity(f)]
	if !ok {
		// A later advisory projection may add a canonical finding that was not in
		// the original scanner output. Preserve the exact scan association, but
		// do not invent manifest paths for an unmatched component/advisory.
		evidence = ports.OwnershipFindingSource{Paths: []string{}}
	}
	if len(evidence.Paths) > 128 {
		return shared.ErrValidation
	}
	paths := slices.Clone(evidence.Paths)
	for _, path := range paths {
		canonical, err := ownership.NormalizePath(path)
		if err != nil || canonical != path {
			return shared.ErrValidation
		}
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	if paths == nil {
		paths = []string{}
	}
	var id, kind, occurrence, component string
	if err := tx.QueryRow(ctx, `SELECT id,kind,COALESCE(occurrence_id,''),COALESCE(component_fingerprint,'') FROM findings WHERE tenant_id=$1 AND engagement_id=$2 AND (($3<>'' AND dedup_key=$3) OR ($3='' AND id=$4)) FOR UPDATE`, tenant, f.EngagementID, f.DedupKey, f.ID).Scan(&id, &kind, &occurrence, &component); err != nil {
		return err
	}
	origin := ownershipOriginHash(kind, occurrence, component)
	// Repeat scans with identical source evidence have the same semantic hash.
	data, _ := json.Marshal(struct {
		Origin, Repository, Revision, BaseRevision string
		BaseRequired                               bool
		Paths                                      []string
		Invalid                                    bool
	}{origin, batch.Source.Repository, batch.Source.Revision, batch.Source.BaseRevision, batch.Source.BaseRequired, paths, evidence.Invalid})
	hash := ownership.ContentHash(string(data))
	encoded, _ := json.Marshal(paths)
	tag, err := tx.Exec(ctx, `INSERT INTO ownership_finding_sources(tenant_id,engagement_id,finding_id,source_id,origin_hash,binding_hash,paths,invalid) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tenant_id,engagement_id,finding_id) DO UPDATE SET source_id=EXCLUDED.source_id,origin_hash=EXCLUDED.origin_hash,binding_hash=EXCLUDED.binding_hash,paths=EXCLUDED.paths,invalid=EXCLUDED.invalid
 WHERE (SELECT capture_sequence FROM ownership_sources WHERE tenant_id=$1 AND engagement_id=$2 AND id=EXCLUDED.source_id)>=(SELECT capture_sequence FROM ownership_sources WHERE tenant_id=$1 AND engagement_id=$2 AND id=ownership_finding_sources.source_id)
 AND (ownership_finding_sources.binding_hash<>EXCLUDED.binding_hash OR (ownership_finding_sources.source_id<>EXCLUDED.source_id AND NOT EXISTS(SELECT 1 FROM ownership_source_readiness WHERE tenant_id=$1 AND engagement_id=$2 AND source_id=ownership_finding_sources.source_id)))`, tenant, f.EngagementID, id, batch.Source.ID, origin, hash, encoded, evidence.Invalid)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO ownership_dirty_findings(tenant_id,engagement_id,finding_id) VALUES($1,$2,$3) ON CONFLICT (tenant_id,engagement_id,finding_id) DO UPDATE SET generation=ownership_dirty_findings.generation+1`, tenant, f.EngagementID, id)
	return err
}
