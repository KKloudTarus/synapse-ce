package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// QualityGateMutator commits managed-gate writes and their audit records together.
type QualityGateMutator struct{ pool *pgxpool.Pool }

func NewQualityGateMutator(pool *pgxpool.Pool) *QualityGateMutator {
	return &QualityGateMutator{pool: pool}
}

var _ ports.QualityGateMutator = (*QualityGateMutator)(nil)

func (m *QualityGateMutator) CreateGate(ctx context.Context, tenantID shared.ID, gate qualitygate.Gate, audit ports.AuditEntry) error {
	return m.inTx(ctx, tenantID, func(tx pgx.Tx) error {
		if err := lockGate(ctx, tx, tenantID, gate.Key); err != nil {
			return err
		}
		conditions, err := json.Marshal(gate.Conditions)
		if err != nil {
			return fmt.Errorf("marshal quality gate conditions: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO quality_gates (tenant_id, key, name, conditions) VALUES ($1,$2,$3,$4)`, tenantID.String(), gate.Key, gate.Name, conditions); err != nil {
			return gateWriteError("insert quality gate", err)
		}
		return appendAudit(ctx, tx, audit)
	})
}

func (m *QualityGateMutator) UpdateGate(ctx context.Context, tenantID shared.ID, gate qualitygate.Gate, audit ports.AuditEntry) error {
	return m.inTx(ctx, tenantID, func(tx pgx.Tx) error {
		if err := lockGate(ctx, tx, tenantID, gate.Key); err != nil {
			return err
		}
		conditions, err := json.Marshal(gate.Conditions)
		if err != nil {
			return fmt.Errorf("marshal quality gate conditions: %w", err)
		}
		ct, err := tx.Exec(ctx, `UPDATE quality_gates SET name=$3, conditions=$4, updated_at=now() WHERE tenant_id=$1 AND key=$2`, tenantID.String(), gate.Key, gate.Name, conditions)
		if err != nil {
			return fmt.Errorf("update quality gate: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return appendAudit(ctx, tx, audit)
	})
}

func (m *QualityGateMutator) DeleteGate(ctx context.Context, tenantID shared.ID, key string, audit ports.AuditEntry) error {
	return m.inTx(ctx, tenantID, func(tx pgx.Tx) error {
		if err := lockGate(ctx, tx, tenantID, key); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM quality_gates WHERE tenant_id=$1 AND key=$2)`, tenantID.String(), key).Scan(&exists); err != nil {
			return fmt.Errorf("select quality gate: %w", err)
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
		return appendAudit(ctx, tx, audit)
	})
}

func (m *QualityGateMutator) AssignProjectGate(ctx context.Context, tenantID shared.ID, projectKey, gateID string, audit ports.AuditEntry) error {
	return m.inTx(ctx, tenantID, func(tx pgx.Tx) error {
		gateID = strings.TrimSpace(gateID)
		if err := requireCustomGate(ctx, tx, tenantID, gateID); err != nil {
			return err
		}
		ct, err := tx.Exec(ctx, `UPDATE projects SET gate_id=$3, updated_at=now() WHERE tenant_id=$1 AND key=$2`, tenantID.String(), projectKey, gateID)
		if err != nil {
			return fmt.Errorf("update project gate: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return appendAudit(ctx, tx, audit)
	})
}

func (m *QualityGateMutator) CreateProjectWithGate(ctx context.Context, p *project.Project) error {
	return m.inTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if err := requireCustomGate(ctx, tx, p.TenantID, p.GateID); err != nil {
			return err
		}
		return insertProject(ctx, tx, p)
	})
}

func requireCustomGate(ctx context.Context, tx pgx.Tx, tenantID shared.ID, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	if _, builtIn := qualitygate.Resolve(key); builtIn {
		return nil
	}
	if err := lockGate(ctx, tx, tenantID, key); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM quality_gates WHERE tenant_id=$1 AND key=$2)`, tenantID.String(), key).Scan(&exists); err != nil {
		return fmt.Errorf("select quality gate: %w", err)
	}
	if !exists {
		return shared.ErrNotFound
	}
	return nil
}

func (m *QualityGateMutator) inTx(ctx context.Context, tenantID shared.ID, fn func(pgx.Tx) error) error {
	const maxAttempts = 8
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := m.inTxOnce(ctx, tenantID, fn)
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue
		}
		return err
	}
	return fmt.Errorf("quality gate mutation: %w after %d attempts", shared.ErrConflict, maxAttempts)
}

func (m *QualityGateMutator) inTxOnce(ctx context.Context, tenantID shared.ID, fn func(pgx.Tx) error) error {
	return WithTenantTx(ctx, m.pool, tenantID, fn)
}

func lockGate(ctx context.Context, tx pgx.Tx, tenantID shared.ID, key string) error {
	h := fnv.New64a()
	_, _ = h.Write([]byte(tenantID.String() + "\x00" + key))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(h.Sum64())); err != nil {
		return fmt.Errorf("lock quality gate: %w", err)
	}
	return nil
}

func gateWriteError(op string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return shared.ErrConflict
	}
	return fmt.Errorf("%s: %w", op, err)
}
