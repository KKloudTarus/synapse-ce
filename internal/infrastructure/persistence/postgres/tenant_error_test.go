package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNormalizePersistenceErrorTelemetryAssetBindingConflict(t *testing.T) {
	dbErr := &pgconn.PgError{
		Code:           "23505",
		ConstraintName: "uq_telemetry_asset_bindings_asset",
	}

	got := normalizePersistenceError(dbErr)
	if !errors.Is(got, shared.ErrConflict) {
		t.Fatalf("normalizePersistenceError() = %v, want ErrConflict", got)
	}
}

func TestNormalizePersistenceErrorLeavesOtherUniqueViolationsUntouched(t *testing.T) {
	dbErr := &pgconn.PgError{
		Code:           "23505",
		ConstraintName: "some_other_unique_constraint",
	}

	got := normalizePersistenceError(dbErr)
	if got != dbErr {
		t.Fatalf("normalizePersistenceError() = %v, want original error", got)
	}
	if errors.Is(got, shared.ErrConflict) {
		t.Fatalf("normalizePersistenceError() unexpectedly mapped unrelated unique violation to ErrConflict")
	}
}
