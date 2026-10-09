package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// SetNotificationCaptureMode is an operator-only command using the migration credential.
// The exclusive advisory lock waits for every capture that observed the previous mode.
// Runtime roles can read the mode but cannot change it.
func SetNotificationCaptureMode(ctx context.Context, migrationDSN, mode string) (int64, error) {
	if mode != "legacy" && mode != "identity" {
		return 0, fmt.Errorf("notification capture mode must be legacy or identity")
	}
	db, err := sql.Open("pgx", dsnForMigrate(migrationDSN))
	if err != nil {
		return 0, fmt.Errorf("open notification capture control database: %w", err)
	}
	defer func() { _ = db.Close() }()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin notification capture control: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(78146)"); err != nil {
		return 0, fmt.Errorf("lock notification capture mode: %w", err)
	}
	result, err := tx.ExecContext(ctx, "UPDATE notification_capture_policy SET mode=$1,changed_at=now() WHERE singleton", mode)
	if err != nil {
		return 0, fmt.Errorf("set notification capture mode: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return 0, fmt.Errorf("notification capture policy row is unavailable")
	}
	// FORCE RLS also applies to a non-bypass migration role. Count within each
	// explicit tenant context rather than trusting an unscoped zero-row result.
	rows, err := tx.QueryContext(ctx, "SELECT id FROM tenants WHERE id<>'' ORDER BY id")
	if err != nil {
		return 0, fmt.Errorf("list notification capture tenants: %w", err)
	}
	var tenants []string
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			_ = rows.Close()
			return 0, err
		}
		tenants = append(tenants, tenant)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, err
	}
	var pending int64
	for _, tenant := range tenants {
		if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_tenant',$1,true)", tenant); err != nil {
			return 0, err
		}
		var count int64
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND capture_version=2 AND processed_at IS NULL", tenant).Scan(&count); err != nil {
			return 0, err
		}
		pending += count
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit notification capture mode: %w", err)
	}
	return pending, nil
}
