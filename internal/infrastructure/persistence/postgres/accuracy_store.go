package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/accuracy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AccuracyRunRepository persists detection-accuracy regression runs. Runs are deployment-global
// engine data (the golden corpus is fixed), so there is no tenant scoping or RLS, matching the
// advisories repository.
type AccuracyRunRepository struct{ pool *pgxpool.Pool }

// NewAccuracyRunRepository returns a repository backed by the given pool.
func NewAccuracyRunRepository(pool *pgxpool.Pool) *AccuracyRunRepository {
	return &AccuracyRunRepository{pool: pool}
}

var _ ports.AccuracyRunStore = (*AccuracyRunRepository)(nil)

const accuracyRunColumns = `id,ran_at,corpus_version,schema_version,cases,overall_tp,overall_fp,overall_fn,overall_precision,overall_recall,overall_f1,overall_fdr,overall_fnr,groups`

// Save inserts a run. A duplicate id is ignored (runs are immutable snapshots).
func (r *AccuracyRunRepository) Save(ctx context.Context, run accuracy.Run) error {
	groups, err := json.Marshal(run.Groups)
	if err != nil {
		return fmt.Errorf("marshal accuracy groups: %w", err)
	}
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO accuracy_runs(`+accuracyRunColumns+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (id) DO NOTHING`,
		run.ID, run.RanAt, run.CorpusVersion, run.SchemaVersion, run.Cases,
		run.Overall.TruePositives, run.Overall.FalsePositives, run.Overall.FalseNegatives,
		run.Overall.Precision, run.Overall.Recall, run.Overall.F1, run.Overall.FalseDiscoveryRate, run.Overall.FalseNegativeRate,
		groups,
	); err != nil {
		return fmt.Errorf("insert accuracy run: %w", err)
	}
	return nil
}

// Recent returns the most recent runs, newest first, capped at limit (a non-positive limit defaults
// to 100).
func (r *AccuracyRunRepository) Recent(ctx context.Context, limit int) ([]accuracy.Run, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx,
		`SELECT `+accuracyRunColumns+` FROM accuracy_runs ORDER BY ran_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("query accuracy runs: %w", err)
	}
	defer rows.Close()
	var out []accuracy.Run
	for rows.Next() {
		var run accuracy.Run
		var groups []byte
		if err := rows.Scan(
			&run.ID, &run.RanAt, &run.CorpusVersion, &run.SchemaVersion, &run.Cases,
			&run.Overall.TruePositives, &run.Overall.FalsePositives, &run.Overall.FalseNegatives,
			&run.Overall.Precision, &run.Overall.Recall, &run.Overall.F1, &run.Overall.FalseDiscoveryRate, &run.Overall.FalseNegativeRate,
			&groups,
		); err != nil {
			return nil, fmt.Errorf("scan accuracy run: %w", err)
		}
		if len(groups) > 0 {
			if err := json.Unmarshal(groups, &run.Groups); err != nil {
				return nil, fmt.Errorf("unmarshal accuracy groups: %w", err)
			}
		}
		out = append(out, run)
	}
	return out, rows.Err()
}
