package telemetryschema

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestRangeIsCoherent(t *testing.T) {
	if MinSupported > MaxSupported {
		t.Fatalf("MinSupported (%d) must be <= MaxSupported (%d)", MinSupported, MaxSupported)
	}
	if !Supported(Current) {
		t.Fatalf("Current (%d) must be within the supported range [%d,%d]", Current, MinSupported, MaxSupported)
	}
}

func TestSupported(t *testing.T) {
	cases := []struct {
		v    int
		want bool
	}{
		{MinSupported - 1, false}, // unset/old
		{0, false},
		{-1, false},
		{MinSupported, true},
		{Current, true},
		{MaxSupported, true},
		{MaxSupported + 1, false}, // newer than the reader
	}
	for _, c := range cases {
		if got := Supported(c.v); got != c.want {
			t.Errorf("Supported(%d) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	// Accepted: every version inside the range.
	for v := MinSupported; v <= MaxSupported; v++ {
		if err := Validate(v); err != nil {
			t.Errorf("Validate(%d) = %v, want nil (in range)", v, err)
		}
	}
	// Rejected, fail-closed with ErrValidation: unset (0), impossible (< 0), and newer-than-reader.
	for _, v := range []int{0, -1, MinSupported - 1, MaxSupported + 1} {
		err := Validate(v)
		if err == nil {
			t.Errorf("Validate(%d) = nil, want rejection", v)
			continue
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("Validate(%d) error = %v, want wrapped shared.ErrValidation", v, err)
		}
	}
}
