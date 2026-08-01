package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// QualityGateStore persists tenant-scoped custom quality gates.
type QualityGateStore struct{ pool *pgxpool.Pool }

func NewQualityGateStore(pool *pgxpool.Pool) *QualityGateStore { return &QualityGateStore{pool: pool} }

var _ ports.QualityGateStore = (*QualityGateStore)(nil)

func (s *QualityGateStore) Create(ctx context.Context, tenantID shared.ID, gate qualitygate.Gate) error {
	conditions, err := json.Marshal(gate.Conditions)
	if err != nil {
		return fmt.Errorf("marshal quality gate conditions: %w", err)
	}
	err = WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO quality_gates (tenant_id, key, name, conditions) VALUES ($1,$2,$3,$4)`, tenantID.String(), gate.Key, gate.Name, conditions)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return shared.ErrConflict
			}
			return fmt.Errorf("insert quality gate: %w", err)
		}
		return nil
	})
	return err
}

func (s *QualityGateStore) List(ctx context.Context, tenantID shared.ID) (out []qualitygate.Gate, err error) {
	err = WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT key, name, conditions FROM quality_gates WHERE tenant_id=$1 ORDER BY key`, tenantID.String())
		if err != nil {
			return fmt.Errorf("list quality gates: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			gate, err := scanQualityGate(rows)
			if err != nil {
				return err
			}
			out = append(out, gate)
		}
		return rows.Err()
	})
	return out, err
}

func (s *QualityGateStore) Get(ctx context.Context, tenantID shared.ID, key string) (out qualitygate.Gate, err error) {
	err = WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		gate, err := scanQualityGate(tx.QueryRow(ctx, `SELECT key, name, conditions FROM quality_gates WHERE tenant_id=$1 AND key=$2`, tenantID.String(), key))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select quality gate: %w", err)
		}
		out = gate
		return nil
	})
	return out, err
}

func (s *QualityGateStore) Update(ctx context.Context, tenantID shared.ID, gate qualitygate.Gate) error {
	conditions, err := json.Marshal(gate.Conditions)
	if err != nil {
		return fmt.Errorf("marshal quality gate conditions: %w", err)
	}
	err = WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE quality_gates SET name=$3, conditions=$4, updated_at=now() WHERE tenant_id=$1 AND key=$2`, tenantID.String(), gate.Key, gate.Name, conditions)
		if err != nil {
			return fmt.Errorf("update quality gate: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return nil
	})
	return err
}

func (s *QualityGateStore) Delete(ctx context.Context, tenantID shared.ID, key string) error {
	return WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM quality_gates WHERE tenant_id=$1 AND key=$2`, tenantID.String(), key)
		if err != nil {
			return fmt.Errorf("delete quality gate: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return nil
	})
}

func (s *QualityGateStore) DeleteIfUnassigned(ctx context.Context, tenantID shared.ID, key string) error {
	return WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM quality_gates WHERE tenant_id=$1 AND key=$2 FOR UPDATE)`, tenantID.String(), key).Scan(&exists); err != nil {
			return fmt.Errorf("lock quality gate: %w", err)
		}
		if !exists {
			return shared.ErrNotFound
		}
		var assigned bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE tenant_id=$1 AND gate_id=$2)`, tenantID.String(), key).Scan(&assigned); err != nil {
			return fmt.Errorf("check quality gate assignments: %w", err)
		}
		if assigned {
			return shared.ErrConflict
		}
		if _, err := tx.Exec(ctx, `DELETE FROM quality_gates WHERE tenant_id=$1 AND key=$2`, tenantID.String(), key); err != nil {
			return fmt.Errorf("delete quality gate: %w", err)
		}
		return nil
	})
}

type qualityGateScanner interface{ Scan(...any) error }

func scanQualityGate(row qualityGateScanner) (qualitygate.Gate, error) {
	var gate qualitygate.Gate
	var conditions []byte
	if err := row.Scan(&gate.Key, &gate.Name, &conditions); err != nil {
		return qualitygate.Gate{}, err
	}
	if err := json.Unmarshal(conditions, &gate.Conditions); err != nil {
		return qualitygate.Gate{}, fmt.Errorf("unmarshal quality gate conditions: %w", err)
	}
	return gate, nil
}
