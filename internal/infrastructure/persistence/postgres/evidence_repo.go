package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// EvidenceStore persists the per-engagement hash-chained evidence ledger.
type EvidenceStore struct{ pool *pgxpool.Pool }

// RestoreEvidenceStore enumerates a restored evidence ledger. It has no write
// methods and is constructed only after the database identity is proven able to
// bypass tenant RLS for recovery verification.
type RestoreEvidenceStore struct{ pool *pgxpool.Pool }

// RestoreEvidenceChain is one engagement's restored evidence ledger in chain order.
type RestoreEvidenceChain = ports.RestoreEvidenceChain

// NewEvidenceStore returns a store backed by the given pool.
func NewEvidenceStore(pool *pgxpool.Pool) *EvidenceStore { return &EvidenceStore{pool: pool} }

// NewReadOnlyEvidenceStore constructs a recovery-only reader. The connection
// identity must be able to read past row-level security: a BYPASSRLS role or a
// superuser. The database owner is not enough: evidence and audit_log force their
// policies on the owner too, so it reads a filtered set that verifies as intact.
// The returned reader opens every enumeration transaction READ ONLY.
func NewReadOnlyEvidenceStore(ctx context.Context, pool *pgxpool.Pool) (*RestoreEvidenceStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: restore evidence store requires database pool", shared.ErrValidation)
	}
	var bypassRLS, superuser bool
	if err := pool.QueryRow(ctx, `SELECT r.rolbypassrls, r.rolsuper
		FROM pg_roles r
		WHERE r.rolname = current_user`).Scan(&bypassRLS, &superuser); err != nil {
		return nil, fmt.Errorf("restore evidence: inspect database identity: %w", err)
	}
	if !restoreRoleEligible(bypassRLS, superuser) {
		return nil, fmt.Errorf("restore evidence: database identity must have BYPASSRLS or be a superuser")
	}
	return &RestoreEvidenceStore{pool: pool}, nil
}

// storedHashScheme is the scheme column value for a link. Zero is how a link built before schemes
// existed (a transfer bundle exported by an older release, say) names the legacy scheme, and the
// column admits only the explicit value.
func storedHashScheme(e evidence.Evidence) int {
	if e.HashScheme == 0 {
		return evidence.HashSchemeLegacy
	}
	return e.HashScheme
}

func restoreRoleEligible(bypassRLS, superuser bool) bool {
	return bypassRLS || superuser
}

var _ ports.EvidenceStore = (*EvidenceStore)(nil)
var _ ports.EvidenceLookup = (*EvidenceStore)(nil)
var _ ports.RestoreEvidenceReader = (*RestoreEvidenceStore)(nil)

// Append inserts sealed evidence items in order, in one transaction (append-only).
func (r *EvidenceStore) Append(ctx context.Context, items []evidence.Evidence) error {
	if len(items) == 0 {
		return nil
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	for _, e := range items {
		// Only an import marker carries a sealed finding id. A native link that claimed one would hash over
		// it in memory and over its FindingID once read back, so it is refused rather than stored broken.
		if !e.Imported && !e.SealedFindingID.IsZero() {
			return fmt.Errorf("%w: evidence %s carries a sealed finding id but is not imported", shared.ErrValidation, e.ID)
		}
	}
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		for _, e := range items {
			var findingID any
			if !e.FindingID.IsZero() {
				findingID = e.FindingID.String()
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO evidence (id, tenant_id, finding_id, engagement_id, kind, sha256, previous_hash, storage_ref, content, created_by, created_at, hash_scheme)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
				e.ID.String(), tenantID.String(), findingID, e.EngagementID.String(), e.Kind, e.Hash, e.PreviousHash, e.StorageRef, e.Content, e.CreatedBy, e.CreatedAt, storedHashScheme(e)); err != nil {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == "23505" {
					return fmt.Errorf("evidence chain: parent already linked: %w", shared.ErrConflict)
				}
				return fmt.Errorf("insert evidence: %w", err)
			}
			if e.Imported {
				var sealedFinding any
				if !e.SealedFindingID.IsZero() {
					sealedFinding = e.SealedFindingID.String()
				}
				if _, err := tx.Exec(ctx,
					`INSERT INTO evidence_imports (tenant_id, engagement_id, evidence_id, sealed_finding_id) VALUES ($1, $2, $3, $4)`,
					tenantID.String(), e.EngagementID.String(), e.ID.String(), sealedFinding); err != nil {
					return fmt.Errorf("mark imported evidence: %w", err)
				}
			}
		}
		return nil
	})
}

// ListByEngagement returns the engagement's evidence in chain order (oldest first).
func (r *EvidenceStore) ListByEngagement(ctx context.Context, engagementID shared.ID) (out []evidence.Evidence, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT e.id, COALESCE(e.finding_id,''), e.engagement_id, e.kind, e.sha256, COALESCE(e.previous_hash,''), COALESCE(e.storage_ref,''), e.content, COALESCE(e.created_by,''), e.created_at, e.hash_scheme,
		        i.evidence_id IS NOT NULL, COALESCE(i.sealed_finding_id,'')
		 FROM evidence e
		 LEFT JOIN evidence_imports i ON i.tenant_id = e.tenant_id AND i.evidence_id = e.id
		 WHERE e.engagement_id=$1 ORDER BY e.seq ASC`, engagementID.String())
		if err != nil {
			return fmt.Errorf("list evidence: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				e            evidence.Evidence
				id, fid, eid string
			)
			var sealedFinding string
			if err := rows.Scan(&id, &fid, &eid, &e.Kind, &e.Hash, &e.PreviousHash, &e.StorageRef, &e.Content, &e.CreatedBy, &e.CreatedAt, &e.HashScheme, &e.Imported, &sealedFinding); err != nil {
				return fmt.Errorf("scan evidence: %w", err)
			}
			e.SealedFindingID = shared.ID(sealedFinding)
			e.ID = shared.ID(id)
			e.FindingID = shared.ID(fid)
			e.EngagementID = shared.ID(eid)
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// LookupSealedByID does not read the imported mark (evidence_imports). Nothing it returns may authorize
// an artifact read; ArtifactForEngagement goes through ListByEngagement for that reason.
func (r *EvidenceStore) LookupSealedByID(ctx context.Context, engagementID, evidenceID shared.ID) (out evidence.Evidence, found bool, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id,COALESCE(finding_id,''),engagement_id,kind,sha256,COALESCE(previous_hash,''),COALESCE(storage_ref,''),content,COALESCE(created_by,''),created_at,hash_scheme FROM evidence WHERE engagement_id=$1 AND id=$2`, engagementID.String(), evidenceID.String()).Scan(&out.ID, &out.FindingID, &out.EngagementID, &out.Kind, &out.Hash, &out.PreviousHash, &out.StorageRef, &out.Content, &out.CreatedBy, &out.CreatedAt, &out.HashScheme)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return evidence.Evidence{}, false, nil
	}
	if err != nil {
		return evidence.Evidence{}, false, fmt.Errorf("lookup sealed evidence: %w", err)
	}
	return out, true, nil
}

// ListEvidenceChains enumerates every restored chain only inside a READ ONLY
// transaction. Construction has already required the recovery identity, but the database owner is
// still subject to a policy on a table that forces row-level security, and a filtered read would
// return no chains, which verifies as intact. row_security off turns any policy that would apply
// into an error, so the enumeration is either complete or refused.
func (r *RestoreEvidenceStore) ListEvidenceChains(ctx context.Context) ([]RestoreEvidenceChain, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("restore evidence: begin read-only transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('row_security', 'off', true)"); err != nil {
		return nil, fmt.Errorf("restore evidence: require unfiltered read: %w", err)
	}

	// The import marker carries the finding id an imported link was sealed with, which its hash binds, so
	// a chain-verifying read joins it. evidence_imports also forces row-level security, so this read is
	// complete or refused for the marker as for the links.
	rows, err := tx.Query(ctx, `SELECT e.id, COALESCE(e.finding_id,''), e.engagement_id, e.kind, e.sha256,
		COALESCE(e.previous_hash,''), COALESCE(e.storage_ref,''), e.content, COALESCE(e.created_by,''), e.created_at, e.hash_scheme,
		i.evidence_id IS NOT NULL, COALESCE(i.sealed_finding_id,'')
		FROM evidence e
		LEFT JOIN evidence_imports i ON i.tenant_id = e.tenant_id AND i.evidence_id = e.id
		ORDER BY e.engagement_id ASC, e.seq ASC`)
	if err != nil {
		return nil, fmt.Errorf("restore evidence: list chains: %w", err)
	}
	defer rows.Close()

	chains := make([]RestoreEvidenceChain, 0)
	byEngagement := make(map[shared.ID]int)
	for rows.Next() {
		var (
			e            evidence.Evidence
			id, fid, eid string
		)
		var sealedFinding string
		if err := rows.Scan(&id, &fid, &eid, &e.Kind, &e.Hash, &e.PreviousHash, &e.StorageRef, &e.Content, &e.CreatedBy, &e.CreatedAt, &e.HashScheme, &e.Imported, &sealedFinding); err != nil {
			return nil, fmt.Errorf("restore evidence: scan chain: %w", err)
		}
		e.SealedFindingID = shared.ID(sealedFinding)
		e.ID = shared.ID(id)
		e.FindingID = shared.ID(fid)
		e.EngagementID = shared.ID(eid)
		index, ok := byEngagement[e.EngagementID]
		if !ok {
			index = len(chains)
			byEngagement[e.EngagementID] = index
			chains = append(chains, RestoreEvidenceChain{ID: e.EngagementID})
		}
		chains[index].Items = append(chains[index].Items, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("restore evidence: iterate chains: %w", err)
	}
	return chains, nil
}

// Head returns the most recent sealed hash for an engagement ("" if the chain is
// empty). A real query error is returned (NOT swallowed as "empty") so the caller
// never forks the append-only chain on a transient DB failure.
func (r *EvidenceStore) Head(ctx context.Context, engagementID shared.ID) (string, error) {
	var head string
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sha256 FROM evidence WHERE engagement_id=$1 ORDER BY seq DESC LIMIT 1`, engagementID.String()).Scan(&head)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil // genuinely empty chain
	}
	if err != nil {
		return "", fmt.Errorf("head evidence: %w", err)
	}
	return head, nil
}

// LookupSealedForFinding returns the most recent sealed evidence link of the
// given kind for the specified finding, or (zero, false, nil) if none exists.
func (r *EvidenceStore) LookupSealedForFinding(ctx context.Context, engagementID, findingID shared.ID, kind string) (evidence.Evidence, bool, error) {
	var out evidence.Evidence
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, engagement_id, finding_id, kind, storage_ref, sha256, previous_hash, created_by, created_at, hash_scheme
			 FROM evidence
			 WHERE engagement_id=$1 AND finding_id=$2 AND kind=$3
			 ORDER BY seq DESC LIMIT 1`,
			engagementID.String(), findingID.String(), kind,
		).Scan(&out.ID, &out.EngagementID, &out.FindingID, &out.Kind, &out.StorageRef, &out.Hash, &out.PreviousHash, &out.CreatedBy, &out.CreatedAt, &out.HashScheme)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return evidence.Evidence{}, false, nil
	}
	if err != nil {
		return evidence.Evidence{}, false, fmt.Errorf("lookup sealed evidence: %w", err)
	}
	return out, true, nil
}
