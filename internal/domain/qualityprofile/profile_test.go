package qualityprofile

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func catalog() []rule.Rule {
	return []rule.Rule{
		{Key: "go-a", Language: "Go", DefaultSeverity: shared.SeverityHigh},
		{Key: "go-b", Language: "Go", DefaultSeverity: shared.SeverityMedium},
		{Key: "py-a", Language: "Python", DefaultSeverity: shared.SeverityLow},
	}
}

func TestBuiltInPerLanguage(t *testing.T) {
	p, ok := BuiltIn("Go", catalog())
	if !ok {
		t.Fatal("expected a built-in Go profile")
	}
	if p.Key != "synapse-way-go" || p.Language != "Go" || !p.BuiltIn || p.Name != "Synapse way (Go)" {
		t.Fatalf("built-in profile = %+v", p)
	}
	if len(p.ActivatedRules) != 2 || !p.Active("go-a") || !p.Active("go-b") || p.Active("py-a") {
		t.Fatalf("built-in Go profile must activate exactly the Go rules: %+v", p.ActivatedRules)
	}
	// A language with no catalog rules yields ok=false.
	if _, ok := BuiltIn("Rust", catalog()); ok {
		t.Error("a language with no rules must not produce a built-in profile")
	}
	if _, ok := BuiltIn("", catalog()); ok {
		t.Error("an empty language must not produce a built-in profile")
	}
}

func TestBuiltInIsImmutable(t *testing.T) {
	p, _ := BuiltIn("Go", catalog())
	if _, err := p.Activate("go-a", shared.SeverityLow); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("activate on built-in must be rejected, got %v", err)
	}
	if _, err := p.Deactivate("go-a"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("deactivate on built-in must be rejected, got %v", err)
	}
	if _, err := p.SetSeverity("go-a", shared.SeverityLow); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("set-severity on built-in must be rejected, got %v", err)
	}
}

func TestCopyThenToggle(t *testing.T) {
	base, _ := BuiltIn("Go", catalog())
	custom, err := base.Copy("team-go", "Team Go")
	if err != nil {
		t.Fatal(err)
	}
	if custom.BuiltIn || custom.Parent != "synapse-way-go" || custom.Language != "Go" || len(custom.ActivatedRules) != 2 {
		t.Fatalf("copy = %+v", custom)
	}
	// Copy is independent of the parent.
	custom.ActivatedRules["go-a"] = RuleActivation{Severity: shared.SeverityLow}
	if base.ActivatedRules["go-a"].Severity != "" {
		t.Error("mutating a copy must not affect the built-in")
	}

	custom, _ = base.Copy("team-go", "Team Go")
	off, err := custom.Deactivate("go-b")
	if err != nil || off.Active("go-b") {
		t.Fatalf("deactivate go-b failed: err=%v active=%v", err, off.Active("go-b"))
	}
	// Deactivating an already-inactive rule is a not-found error.
	if _, err := off.Deactivate("go-b"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("deactivating an inactive rule should be ErrNotFound, got %v", err)
	}
	sev, err := off.SetSeverity("go-a", shared.SeverityCritical)
	if err != nil || sev.ActivatedRules["go-a"].Severity != shared.SeverityCritical {
		t.Fatalf("set-severity failed: err=%v got=%+v", err, sev.ActivatedRules["go-a"])
	}
	// Set-severity on an inactive rule fails.
	if _, err := sev.SetSeverity("go-b", shared.SeverityLow); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("set-severity on inactive rule should be ErrNotFound, got %v", err)
	}
	if _, err := sev.Activate("go-x", shared.Severity("bogus")); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("invalid severity must be rejected, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	good, _ := BuiltIn("Go", catalog())
	custom, _ := good.Copy("team-go", "Team Go")
	if err := custom.Validate(); err != nil {
		t.Fatalf("valid custom profile: %v", err)
	}
	bad := custom
	bad.Key = "Bad Key"
	if err := bad.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bad key must be rejected, got %v", err)
	}
	bad = custom
	bad.Name = ""
	if err := bad.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty name must be rejected, got %v", err)
	}
}

func TestToOverlay(t *testing.T) {
	base, _ := BuiltIn("Go", catalog())
	custom, _ := base.Copy("team-go", "Team Go")
	custom, _ = custom.Deactivate("go-b")                           // go-b disabled
	custom, _ = custom.SetSeverity("go-a", shared.SeverityCritical) // go-a severity override

	overlay := custom.ToOverlay([]rule.Key{"go-a", "go-b"})
	// go-b is disabled → Enabled:false; go-a carries the severity override.
	b, ok := overlay.Rules["go-b"]
	if !ok || b.Enabled == nil || *b.Enabled {
		t.Fatalf("go-b must be disabled in the overlay: %+v", b)
	}
	a, ok := overlay.Rules["go-a"]
	if !ok || a.Severity != string(shared.SeverityCritical) {
		t.Fatalf("go-a must carry the severity override: %+v", a)
	}
	// The built-in overlay (all active, no overrides) disables nothing and overrides nothing.
	baseOverlay := base.ToOverlay([]rule.Key{"go-a", "go-b"})
	for k, cfg := range baseOverlay.Rules {
		if cfg.Enabled != nil && !*cfg.Enabled {
			t.Errorf("built-in overlay must not disable rule %q", k)
		}
		if cfg.Severity != "" {
			t.Errorf("built-in overlay must not override severity for %q", k)
		}
	}
}
