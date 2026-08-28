package exposureuc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type fakeReader struct {
	comps []AssetVulnerableComponent
	err   error
}

func (f *fakeReader) ListAssetVulnerableComponents(_ context.Context, _ shared.ID) ([]AssetVulnerableComponent, error) {
	return f.comps, f.err
}

func mustService(t *testing.T, r AssetVulnerabilityReader) *Service {
	t.Helper()
	s, err := NewService(r)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return s
}

func comp(id string, priority int, kev, running bool) AssetVulnerableComponent {
	return AssetVulnerableComponent{
		ComponentID: shared.ID("comp-" + id),
		AdvisoryID:  shared.ID("adv-" + id),
		Severity:    shared.SeverityHigh,
		Priority:    priority,
		KEV:         kev,
		Running:     running,
	}
}

func TestAbstainWhenNoData(t *testing.T) {
	s := mustService(t, &fakeReader{err: shared.ErrNotFound})
	a, err := s.Assess(context.Background(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Scoreable || a.Exposure != 0 || len(a.Reasons) == 0 {
		t.Fatalf("no data must abstain (Scoreable=false, Exposure=0, with a reason), got %+v", a)
	}
}

func TestScoredCleanWhenNoOpenVulns(t *testing.T) {
	s := mustService(t, &fakeReader{comps: nil})
	a, err := s.Assess(context.Background(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Scoreable || a.Exposure != 0 {
		t.Fatalf("inventory-present-but-clean must be a trustworthy 0 (Scoreable=true), got %+v", a)
	}
}

func TestFusesOpenExposures(t *testing.T) {
	// A running priority-1 dominates; result is the worst weighted exposure (100).
	s := mustService(t, &fakeReader{comps: []AssetVulnerableComponent{
		comp("a", 3, false, false), // installed P3 -> 27
		comp("b", 1, false, true),  // running P1 -> 100
	}})
	a, err := s.Assess(context.Background(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Scoreable || a.Exposure != 100 {
		t.Fatalf("expected Scoreable exposure=100, got %+v", a)
	}
	// One component was running, so the running-precision-limited note must be ABSENT.
	for _, r := range a.Reasons {
		if containsRunningLimited(r) {
			t.Fatalf("must not flag running-precision-limited when a component is running: %q", r)
		}
	}
}

func TestInstalledOnlyNotesLimitedPrecision(t *testing.T) {
	s := mustService(t, &fakeReader{comps: []AssetVulnerableComponent{
		comp("a", 1, false, false), // installed P1 -> 50
	}})
	a, err := s.Assess(context.Background(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Scoreable || a.Exposure != 50 {
		t.Fatalf("installed P1 must score 50, got %+v", a)
	}
	found := false
	for _, r := range a.Reasons {
		if containsRunningLimited(r) {
			found = true
		}
	}
	if !found {
		t.Fatal("all-installed must record the running-vs-installed precision-limited reason")
	}
}

func TestValidationAndErrorPropagation(t *testing.T) {
	if _, err := NewService(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("nil reader must be rejected")
	}
	s := mustService(t, &fakeReader{})
	if _, err := s.Assess(context.Background(), ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("empty asset id must be rejected")
	}
	// A non-NotFound reader error propagates (not swallowed as abstain).
	boom := errors.New("db down")
	s2 := mustService(t, &fakeReader{err: boom})
	if _, err := s2.Assess(context.Background(), "a"); !errors.Is(err, boom) {
		t.Fatalf("reader error must propagate, got %v", err)
	}
	// A bad component (invalid priority) fails closed through Fuse.
	s3 := mustService(t, &fakeReader{comps: []AssetVulnerableComponent{comp("x", 9, false, true)}})
	if _, err := s3.Assess(context.Background(), "a"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid component must fail closed, got %v", err)
	}
}

func containsRunningLimited(s string) bool {
	return strings.Contains(s, "running-vs-installed precision limited")
}
