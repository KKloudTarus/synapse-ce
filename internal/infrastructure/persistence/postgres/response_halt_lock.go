package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// lockResponseHalt orders attempt admission against halt commit even before a
// tenant's fence exists. Acquire this before any fence or attempt row lock and
// keep it through transaction commit. Admission shares the lock; halt is exclusive.
// The subsequent fence read must use a fresh snapshot after any lock wait.
func lockResponseHalt(ctx context.Context, tx pgx.Tx, exclusive bool) error {
	var isolation string
	if err := tx.QueryRow(ctx, "SHOW transaction_isolation").Scan(&isolation); err != nil {
		return fmt.Errorf("read response halt transaction isolation: %w", err)
	}
	if isolation != "read committed" {
		return fmt.Errorf("response halt locking requires read committed isolation, got %q", isolation)
	}
	query := `SELECT pg_advisory_xact_lock_shared(hashtextextended('response-halt:' || current_setting('app.current_tenant', true), 0))`
	if exclusive {
		query = `SELECT pg_advisory_xact_lock(hashtextextended('response-halt:' || current_setting('app.current_tenant', true), 0))`
	}
	if _, err := tx.Exec(ctx, query); err != nil {
		return fmt.Errorf("lock response halt transaction: %w", err)
	}
	return nil
}
