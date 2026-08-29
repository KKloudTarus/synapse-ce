package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type CoverageWindowRepository struct{ pool *pgxpool.Pool }

var _ ports.CoverageWindowStore = (*CoverageWindowRepository)(nil)

func NewCoverageWindowRepository(pool *pgxpool.Pool) (*CoverageWindowRepository, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: coverage-window repository requires a database pool", shared.ErrValidation)
	}
	return &CoverageWindowRepository{pool: pool}, nil
}

func (r *CoverageWindowRepository) AppendCoverageWindow(ctx context.Context, window sensorstate.CoverageWindow) (sensorstate.CoverageWindow, error) {
	window = normalizePostgresCoverageWindow(window)
	if err := window.Validate(); err != nil {
		return sensorstate.CoverageWindow{}, err
	}
	if err := requireTransportTenant(ctx); err != nil {
		return sensorstate.CoverageWindow{}, err
	}
	states, err := json.Marshal(window.States)
	if err != nil {
		return sensorstate.CoverageWindow{}, fmt.Errorf("marshal coverage window states: %w", err)
	}
	vector, err := json.Marshal(window.Vector)
	if err != nil {
		return sensorstate.CoverageWindow{}, fmt.Errorf("marshal coverage window vector: %w", err)
	}
	var stored sensorstate.CoverageWindow
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		tag, err := tx.Exec(ctx, `INSERT INTO coverage_windows
			(tenant_id,revision,asset_id,agent_id,host_id,since_at,until_at,input_digest,created_at,states,
			 sampled_count,truncated_count,dropped_count,gap_count,batch_count,coverage_vector)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
			ON CONFLICT (tenant_id,revision) DO NOTHING`,
			tenant.String(), window.Revision, window.AssetID.String(), window.AgentID.String(), window.HostID.String(),
			window.Since.UTC(), window.Until.UTC(), window.InputDigest, window.CreatedAt.UTC(), states,
			window.SampledCount, window.TruncatedCount, window.DroppedCount, window.GapCount, window.BatchCount, vector)
		if err != nil {
			return fmt.Errorf("insert coverage window: %w", err)
		}
		stored, err = scanCoverageWindow(tx.QueryRow(ctx, `SELECT revision,asset_id,agent_id,host_id,since_at,until_at,
			input_digest,created_at,states,sampled_count,truncated_count,dropped_count,gap_count,batch_count,coverage_vector
			FROM coverage_windows WHERE tenant_id=$1 AND revision=$2`, tenant.String(), window.Revision))
		if err != nil {
			return fmt.Errorf("read coverage window collision: %w", err)
		}
		if tag.RowsAffected() == 0 && !samePostgresCoverageWindowFacts(stored, window) {
			return fmt.Errorf("%w: coverage revision is already committed to different facts", shared.ErrConflict)
		}
		return nil
	})
	if err != nil {
		return sensorstate.CoverageWindow{}, err
	}
	return stored, nil
}

func (r *CoverageWindowRepository) ListCoverageWindows(ctx context.Context, q ports.CoverageWindowQuery) ([]sensorstate.CoverageWindow, error) {
	if !q.Valid() {
		return nil, fmt.Errorf("%w: coverage window query has invalid interval or limit", shared.ErrValidation)
	}
	if err := requireTransportTenant(ctx); err != nil {
		return nil, err
	}
	out := make([]sensorstate.CoverageWindow, 0)
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		args := []any{tenant.String()}
		conditions := []string{"tenant_id=$1"}
		add := func(format string, value any) {
			args = append(args, value)
			conditions = append(conditions, fmt.Sprintf(format, len(args)))
		}
		if !q.AgentID.IsZero() {
			add("agent_id=$%d", q.AgentID.String())
		}
		if !q.AssetID.IsZero() {
			add("asset_id=$%d", q.AssetID.String())
		}
		if !q.HostID.IsZero() {
			add("host_id=$%d", q.HostID.String())
		}
		if !q.Since.IsZero() {
			add("until_at > $%d", q.Since.UTC())
		}
		if !q.Until.IsZero() {
			add("since_at < $%d", q.Until.UTC())
		}
		limit := q.EffectiveLimit()
		args = append(args, limit)
		rows, err := tx.Query(ctx, `SELECT revision,asset_id,agent_id,host_id,since_at,until_at,
			input_digest,created_at,states,sampled_count,truncated_count,dropped_count,gap_count,batch_count,coverage_vector
			FROM coverage_windows WHERE `+strings.Join(conditions, " AND ")+
			fmt.Sprintf(" ORDER BY since_at DESC,until_at DESC,revision DESC LIMIT $%d", len(args)), args...)
		if err != nil {
			return fmt.Errorf("query coverage windows: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			window, err := scanCoverageWindow(rows)
			if err != nil {
				return fmt.Errorf("scan coverage window: %w", err)
			}
			out = append(out, window)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type coverageWindowScanner interface {
	Scan(dest ...any) error
}

func scanCoverageWindow(row coverageWindowScanner) (sensorstate.CoverageWindow, error) {
	var window sensorstate.CoverageWindow
	var states, vector []byte
	if err := row.Scan(
		&window.Revision, &window.AssetID, &window.AgentID, &window.HostID, &window.Since, &window.Until,
		&window.InputDigest, &window.CreatedAt, &states, &window.SampledCount, &window.TruncatedCount,
		&window.DroppedCount, &window.GapCount, &window.BatchCount, &vector,
	); err != nil {
		return sensorstate.CoverageWindow{}, err
	}
	if err := json.Unmarshal(states, &window.States); err != nil {
		return sensorstate.CoverageWindow{}, fmt.Errorf("decode coverage window states: %w", err)
	}
	if err := json.Unmarshal(vector, &window.Vector); err != nil {
		return sensorstate.CoverageWindow{}, fmt.Errorf("decode coverage window vector: %w", err)
	}
	window.Since = window.Since.UTC()
	window.Until = window.Until.UTC()
	window.CreatedAt = window.CreatedAt.UTC()
	if err := window.Validate(); err != nil {
		return sensorstate.CoverageWindow{}, fmt.Errorf("validate stored coverage window: %w", err)
	}
	return window, nil
}

func samePostgresCoverageWindowFacts(a, b sensorstate.CoverageWindow) bool {
	a = normalizePostgresCoverageWindow(a)
	b = normalizePostgresCoverageWindow(b)
	a.CreatedAt = b.CreatedAt
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func normalizePostgresCoverageWindow(window sensorstate.CoverageWindow) sensorstate.CoverageWindow {
	window.Since = window.Since.UTC()
	window.Until = window.Until.UTC()
	window.CreatedAt = window.CreatedAt.UTC().Truncate(time.Microsecond)
	window.States = append([]detection.ClassCoverage(nil), window.States...)
	sort.Slice(window.States, func(i, j int) bool {
		if window.States[i].Class != window.States[j].Class {
			return window.States[i].Class < window.States[j].Class
		}
		if !window.States[i].Since.Equal(window.States[j].Since) {
			return window.States[i].Since.Before(window.States[j].Since)
		}
		if window.States[i].State != window.States[j].State {
			return window.States[i].State < window.States[j].State
		}
		return window.States[i].Reason < window.States[j].Reason
	})
	window.Vector.Reasons = append([]string(nil), window.Vector.Reasons...)
	sort.Strings(window.Vector.Reasons)
	return window
}
