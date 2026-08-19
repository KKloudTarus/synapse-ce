package telemetry

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestLossDisposition(t *testing.T) {
	for _, d := range []LossDisposition{Complete, Sampled, Truncated, Dropped} {
		if !d.Valid() {
			t.Errorf("%q must be valid", d)
		}
	}
	if LossDisposition("nope").Valid() {
		t.Error("an unknown disposition must be invalid")
	}
	// Only Complete is non-lossy.
	if Complete.Lossy() {
		t.Error("Complete must not be lossy")
	}
	for _, d := range []LossDisposition{Sampled, Truncated, Dropped} {
		if !d.Lossy() {
			t.Errorf("%q must be lossy", d)
		}
	}
}

func TestMustNotShed(t *testing.T) {
	// Privilege + sensitive-file are never-shed; process/network are sheddable background.
	if !MustNotShed(detection.ClassPrivilege) || !MustNotShed(detection.ClassFile) {
		t.Error("privilege and file classes must be never-shed")
	}
	if MustNotShed(detection.ClassProcess) || MustNotShed(detection.ClassNetwork) {
		t.Error("process and network are sheddable background telemetry")
	}
}

func TestValidateLossCounts(t *testing.T) {
	ok := []struct {
		d                       LossDisposition
		observed, kept, dropped int
	}{
		{Complete, 5, 5, 0},
		{Sampled, 10, 1, 9},
		{Truncated, 10, 4, 6},
		{Dropped, 7, 0, 7},
	}
	for _, c := range ok {
		if err := ValidateLossCounts(c.d, c.observed, c.kept, c.dropped); err != nil {
			t.Errorf("%+v must validate, got %v", c, err)
		}
	}
	bad := []struct {
		name                    string
		d                       LossDisposition
		observed, kept, dropped int
	}{
		{"bad disposition", "nope", 5, 5, 0},
		{"negative", Truncated, 5, -1, 6},
		{"counts do not add up", Truncated, 10, 4, 5},
		{"complete with a drop", Complete, 5, 4, 1},
		{"truncated with no drop", Truncated, 5, 5, 0},
		{"dropped with no drop", Dropped, 5, 5, 0},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateLossCounts(c.d, c.observed, c.kept, c.dropped); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}
