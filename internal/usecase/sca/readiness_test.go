package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// provenancedSource is a detection source that also reports provenance, so a test can control whether it
// looks like it had a usable DB (non-empty marker) or an empty one.
type provenancedSource struct {
	fakeSource
	ver, db string
}

func (p provenancedSource) Provenance() (string, string) { return p.ver, p.db }

var _ ports.SourceProvenance = provenancedSource{}

func TestDetectionReadiness(t *testing.T) {
	empty := provenancedSource{fakeSource: fakeSource{name: "advisory-store"}} // empty corpus
	populated := provenancedSource{fakeSource: fakeSource{name: "advisory-store"}, db: "50000 advisories@2026-09-12"}
	grypeMissing := provenancedSource{fakeSource: fakeSource{name: "grype"}} // missing DB
	opaque := fakeSource{name: "osv"}                                        // no SourceProvenance

	t.Run("all empty, non-strict: warn + incomplete, no error", func(t *testing.T) {
		s := &Service{sources: []ports.DetectionSource{empty, grypeMissing}}
		w, incomplete, err := s.detectionReadiness(true)
		if err != nil || !incomplete || w == "" {
			t.Fatalf("want warn+incomplete+no-error, got w=%q incomplete=%v err=%v", w, incomplete, err)
		}
	})
	t.Run("all empty, strict: error", func(t *testing.T) {
		s := &Service{sources: []ports.DetectionSource{empty}, strictSources: true}
		if _, incomplete, err := s.detectionReadiness(true); err == nil || !incomplete {
			t.Fatalf("strict must fail closed on an empty corpus, got incomplete=%v err=%v", incomplete, err)
		}
	})
	t.Run("one populated source: ready", func(t *testing.T) {
		s := &Service{sources: []ports.DetectionSource{empty, populated}}
		if w, incomplete, err := s.detectionReadiness(true); incomplete || err != nil || w != "" {
			t.Fatalf("a populated source means ready, got w=%q incomplete=%v err=%v", w, incomplete, err)
		}
	})
	t.Run("opaque source assumed to carry coverage: ready", func(t *testing.T) {
		s := &Service{sources: []ports.DetectionSource{empty, opaque}}
		if _, incomplete, err := s.detectionReadiness(true); incomplete || err != nil {
			t.Fatalf("an opaque (no-provenance) source cannot be judged unready, got incomplete=%v err=%v", incomplete, err)
		}
	})
	t.Run("no components: not applicable", func(t *testing.T) {
		s := &Service{sources: []ports.DetectionSource{empty}, strictSources: true}
		if _, incomplete, err := s.detectionReadiness(false); incomplete || err != nil {
			t.Fatalf("no components means nothing to scan, got incomplete=%v err=%v", incomplete, err)
		}
	})
	t.Run("no sources configured with components: unready", func(t *testing.T) {
		s := &Service{sources: nil}
		if w, incomplete, err := s.detectionReadiness(true); !incomplete || w == "" || err != nil {
			t.Fatalf("an empty source list with components must be unready, got w=%q incomplete=%v err=%v", w, incomplete, err)
		}
	})
	t.Run("strict returns the warning alongside the error", func(t *testing.T) {
		s := &Service{sources: []ports.DetectionSource{empty}, strictSources: true}
		if w, _, err := s.detectionReadiness(true); err == nil || w == "" {
			t.Fatalf("strict must return both a warning and an error, got w=%q err=%v", w, err)
		}
	})
}

// TestApplyDetectionReadiness verifies the snapshotted non-strict result mutation: an unready verdict flips
// Completeness to not-confident and records the warning; a ready verdict leaves the result untouched.
func TestApplyDetectionReadiness(t *testing.T) {
	result := &ScanResult{Completeness: ports.Completeness{Confident: true}}
	applyDetectionReadiness(result, "no usable DB", true)
	if result.Completeness.Confident {
		t.Error("an unready verdict must force Completeness not-confident")
	}
	if result.Completeness.Warning == "" || len(result.SourceWarnings) == 0 {
		t.Errorf("the readiness warning must be surfaced, got completeness=%q sourceWarnings=%v", result.Completeness.Warning, result.SourceWarnings)
	}

	ready := &ScanResult{Completeness: ports.Completeness{Confident: true}}
	applyDetectionReadiness(ready, "", false)
	if !ready.Completeness.Confident || len(ready.SourceWarnings) != 0 {
		t.Error("a ready verdict must leave the result untouched")
	}
}
