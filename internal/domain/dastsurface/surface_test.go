package dastsurface

import (
	"errors"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNewSurfaceNormalizesPaginationAndSessionDedup(t *testing.T) {
	surface, err := NewSurface([]Request{
		{Method: "get", URL: "https://APP.example.test/orders?page=1&sid=abc&sort=date"},
		{Method: "GET", URL: "https://app.example.test/orders?page=2&sid=def&sort=date"},
		{Method: "GET", URL: "https://app.example.test/orders?sort=date#section"},
	})
	if err != nil {
		t.Fatalf("NewSurface: %v", err)
	}
	want := []Request{{Method: "GET", URL: "https://app.example.test/orders?sort=date"}}
	if !reflect.DeepEqual(surface.Requests, want) {
		t.Fatalf("surface = %#v, want %#v", surface.Requests, want)
	}
}

func TestNewCoverageDeterministicAndConflictSafe(t *testing.T) {
	entry := CoverageEntry{Request: Request{Method: "GET", URL: "https://app.test/a?page=1"}, Status: CoverageLimited, Reason: "page limit"}
	coverage, err := NewCoverage([]CoverageEntry{entry, entry})
	if err != nil || len(coverage.Entries) != 1 {
		t.Fatalf("deduplicated coverage = %#v, %v", coverage, err)
	}
	conflict := entry
	conflict.Status, conflict.Reason = CoverageSkipped, "deny path"
	if _, err := NewCoverage([]CoverageEntry{entry, conflict}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("conflict = %v, want ErrValidation", err)
	}
}
