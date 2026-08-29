package postgres

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5/pgxpool"
)

func mustNewDetectionProvenanceRepository(t *testing.T, pool *pgxpool.Pool) *DetectionProvenanceRepository {
	t.Helper()
	repo, err := NewDetectionProvenanceRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func mustNewTelemetryTransportRepository(t *testing.T, pool *pgxpool.Pool) *TelemetryTransportRepository {
	t.Helper()
	repo, err := NewTelemetryTransportRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func mustNewSensorStateRepository(t *testing.T, pool *pgxpool.Pool) *SensorStateRepository {
	t.Helper()
	repo, err := NewSensorStateRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func mustNewCoverageWindowRepository(t *testing.T, pool *pgxpool.Pool) *CoverageWindowRepository {
	t.Helper()
	repo, err := NewCoverageWindowRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func mustNewPrivacyPolicyRepository(t *testing.T, pool *pgxpool.Pool) *PrivacyPolicyRepository {
	t.Helper()
	repo, err := NewPrivacyPolicyRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestIssueRepositoriesRejectNilPool(t *testing.T) {
	constructors := map[string]func() error{
		"detection provenance": func() error {
			_, err := NewDetectionProvenanceRepository(nil)
			return err
		},
		"telemetry transport": func() error {
			_, err := NewTelemetryTransportRepository(nil)
			return err
		},
		"sensor state": func() error {
			_, err := NewSensorStateRepository(nil)
			return err
		},
		"coverage window": func() error {
			_, err := NewCoverageWindowRepository(nil)
			return err
		},
		"privacy policy": func() error {
			_, err := NewPrivacyPolicyRepository(nil)
			return err
		},
	}

	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			if err := construct(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("constructor error = %v, want validation", err)
			}
		})
	}
}
