package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AdvisoryRepository persists the OWNED normalized-advisory store to PostgreSQL. It is
// GLOBAL reference data (NOT tenant-scoped): the full advisory is a JSONB blob in `advisories`, with one
// `advisory_affects` row per affected (ecosystem, package) for the indexed ByPackage lookup.
type AdvisoryRepository struct{ pool *pgxpool.Pool }

// NewAdvisoryRepository returns a repository backed by the given pool.
func NewAdvisoryRepository(pool *pgxpool.Pool) *AdvisoryRepository {
	return &AdvisoryRepository{pool: pool}
}

var (
	_ ports.AdvisoryStore  = (*AdvisoryRepository)(nil)
	_ ports.AdvisoryWriter = (*AdvisoryRepository)(nil) // the ingester loads via the narrow writer port
)

// Upsert inserts or replaces an advisory by id and rebuilds its (ecosystem, package) index rows, in one
// transaction. Idempotent – advisories are re-syncable reference data (a re-ingest REPLACES in place), not
// an append-only ledger. The affected (ecosystem, package) keys must be ingester-normalized per the
// ports.AdvisoryStore KEY CONTRACT. The full domain advisory round-trips through the JSONB `data` blob.
func (r *AdvisoryRepository) Upsert(ctx context.Context, a advisory.Advisory) error {
	if a.ID == "" {
		return fmt.Errorf("%w: advisory id is empty", shared.ErrValidation)
	}
	blob, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshal advisory: %w", err)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin advisory upsert: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit succeeds; matches the package norm
	if _, err := tx.Exec(ctx,
		`INSERT INTO advisories (id, data, created_at, updated_at) VALUES ($1, $2, now(), now())
		 ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
		a.ID, blob); err != nil {
		return fmt.Errorf("upsert advisory: %w", err)
	}
	// Rebuild the affect index for this advisory (the affected set may change across re-syncs). CASCADE on
	// the FK is not enough – we only want THIS advisory's rows cleared, then re-inserted from the new blob.
	if _, err := tx.Exec(ctx, `DELETE FROM advisory_affects WHERE advisory_id = $1`, a.ID); err != nil {
		return fmt.Errorf("clear advisory affects: %w", err)
	}
	seen := map[string]bool{}
	for _, ap := range a.Affected {
		if ap.Ecosystem == "" || ap.Package == "" {
			continue
		}
		k := ap.Ecosystem + "\x00" + ap.Package
		if seen[k] {
			continue // one advisory, multiple blocks for the same package -> index once
		}
		seen[k] = true
		if _, err := tx.Exec(ctx,
			`INSERT INTO advisory_affects (advisory_id, ecosystem, package) VALUES ($1, $2, $3)`,
			a.ID, ap.Ecosystem, ap.Package); err != nil {
			return fmt.Errorf("insert advisory affect: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit advisory upsert: %w", err)
	}
	return nil
}

// ByPackage returns the advisories that affect (ecosystem, name), decoded from their JSONB blobs. The caller
// runs advisory.Match to decide which actually hit the component's version. Deterministic id order.
func (r *AdvisoryRepository) ByPackage(ctx context.Context, ecosystem, name string) ([]advisory.Advisory, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT a.data FROM advisories a
		 JOIN advisory_affects aff ON aff.advisory_id = a.id
		 WHERE aff.ecosystem = $1 AND aff.package = $2
		 ORDER BY a.id COLLATE "C" ASC`,
		ecosystem, name)
	if err != nil {
		return nil, fmt.Errorf("query advisories by package: %w", err)
	}
	defer rows.Close()
	out := make([]advisory.Advisory, 0)
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return nil, fmt.Errorf("scan advisory: %w", err)
		}
		var a advisory.Advisory
		if err := json.Unmarshal(blob, &a); err != nil {
			return nil, fmt.Errorf("decode advisory: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
