package importedfinding

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func completeProvenance() Provenance {
	return Provenance{
		ToolName: "semgrep", ToolVersion: "1.2.3", RuleID: "rule.a", SourceDigest: "abc",
		IngestedBy: "human:alice", IngestedAt: time.Unix(1700000000, 0).UTC(),
	}
}

func completeFinding() ImportedFinding {
	return ImportedFinding{
		ID: "if-1", TenantID: "t1", EngagementID: "eng-1", Severity: shared.SeverityHigh,
		Location: Location{Path: "src/app.go", StartLine: 42}, Provenance: completeProvenance(),
	}
}

// TestProvenanceIsMandatory locks the type's central promise: an unattributable finding is refused, and
// the error names every missing field so the refusal can be acted on.
func TestProvenanceIsMandatory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Provenance)
		missing string
	}{
		{"tool name", func(p *Provenance) { p.ToolName = " " }, "tool name"},
		{"tool version", func(p *Provenance) { p.ToolVersion = "" }, "tool version"},
		{"rule id", func(p *Provenance) { p.RuleID = "" }, "rule id"},
		{"source digest", func(p *Provenance) { p.SourceDigest = "" }, "source digest"},
		{"ingesting actor", func(p *Provenance) { p.IngestedBy = "" }, "ingested by"},
		{"ingest time", func(p *Provenance) { p.IngestedAt = time.Time{} }, "ingested at"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			provenance := completeProvenance()
			test.mutate(&provenance)
			err := provenance.Validate()
			if err == nil {
				t.Fatalf("provenance without a %s must be refused", test.name)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("error %v must wrap ErrValidation", err)
			}
			if !strings.Contains(err.Error(), test.missing) {
				t.Fatalf("error %q must name the missing field %q", err, test.missing)
			}
		})
	}

	if err := completeProvenance().Validate(); err != nil {
		t.Fatalf("complete provenance must validate: %v", err)
	}
}

// The message must be deterministic: two identical failures cannot produce two different error strings,
// or a caller comparing them (or a golden test) breaks at random.
func TestProvenanceErrorIsDeterministic(t *testing.T) {
	t.Parallel()

	provenance := Provenance{IngestedAt: time.Unix(1, 0)}
	first := provenance.Validate().Error()
	for i := 0; i < 50; i++ {
		if got := provenance.Validate().Error(); got != first {
			t.Fatalf("validation message varies between calls:\n%q\n%q", first, got)
		}
	}
}

// TestLocationRejectsPathsOutsideTheScannedTree is the invariant moved INTO the domain. The SARIF
// ingester normalizes its own input, but it is one producer; a second one must not be able to persist a
// path that escapes the tree through a store that only calls Validate.
func TestLocationRejectsPathsOutsideTheScannedTree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
	}{
		{"absolute", "/etc/passwd"},
		{"parent traversal", "../../etc/passwd"},
		{"traversal in the middle", "src/../../etc/passwd"},
		{"traversal at the end", "src/.."},
		{"bare parent", ".."},
		{"windows separators", `src\app.go`},
		{"windows volume", "C:/Windows"},
		{"nul byte", "src/app\x00.go"},
		{"escape sequence", "src/\x1b[31mapp.go"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := Location{Path: test.path}.Validate()
			if err == nil {
				t.Fatalf("a %s path must be refused by the domain, not only by the ingester", test.name)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("error %v must wrap ErrValidation", err)
			}
			// A finding carrying the same path must be refused too — the store calls only this.
			f := completeFinding()
			f.Location = Location{Path: test.path}
			if err := f.Validate(); err == nil {
				t.Fatalf("a finding with a %s path must not be storable", test.name)
			}
		})
	}

	for _, ok := range []string{"", "src/app.go", "a/b/c.ts", "file.with..dots.go", "..hidden/x.go"} {
		if err := (Location{Path: ok}).Validate(); err != nil {
			t.Fatalf("legitimate path %q must be accepted: %v", ok, err)
		}
	}
	if err := (Location{Path: "a.go", StartLine: -1}).Validate(); err == nil {
		t.Fatal("a negative position must be refused")
	}
}

// TestIdempotencyKeyDistinguishesEveryComponent locks that no two DIFFERENT findings collapse onto one
// key. A collision would silently drop a real finding as a duplicate.
func TestIdempotencyKeyDistinguishesEveryComponent(t *testing.T) {
	t.Parallel()

	base := completeFinding()
	mutations := map[string]func(*ImportedFinding){
		"tenant":       func(f *ImportedFinding) { f.TenantID = "other" },
		"engagement":   func(f *ImportedFinding) { f.EngagementID = "eng-2" },
		"digest":       func(f *ImportedFinding) { f.Provenance.SourceDigest = "def" },
		"rule":         func(f *ImportedFinding) { f.Provenance.RuleID = "rule.b" },
		"path":         func(f *ImportedFinding) { f.Location.Path = "src/other.go" },
		"logical name": func(f *ImportedFinding) { f.Location.LogicalName = "Pkg.Method" },
		"start line":   func(f *ImportedFinding) { f.Location.StartLine = 43 },
	}
	seen := map[string]string{IdempotencyKey(base): "base"}
	for name, mutate := range mutations {
		variant := base
		mutate(&variant)
		key := IdempotencyKey(variant)
		if other, taken := seen[key]; taken {
			t.Fatalf("changing the %s must change the idempotency key (collides with %s)", name, other)
		}
		seen[key] = name
	}

	// The identity is stable: the same finding always yields the same key, and fields OUTSIDE the key
	// (the id, the severity, the tool's own text) do not move it.
	same := base
	same.ID = "if-999"
	same.Severity = shared.SeverityLow
	same.Message = "different wording"
	if IdempotencyKey(same) != IdempotencyKey(base) {
		t.Fatal("the idempotency key must not depend on fields outside the documented identity")
	}
}

// An embedded NUL must not be able to shift a field boundary and forge another finding's key.
func TestIdempotencyKeySeparatorCannotBeForged(t *testing.T) {
	t.Parallel()

	forged := completeFinding()
	forged.Provenance.RuleID = "rule.a\x00src/app.go\x00\x0042"
	forged.Location = Location{}
	if IdempotencyKey(forged) == IdempotencyKey(completeFinding()) {
		t.Fatal("an embedded NUL must not forge another finding's idempotency key")
	}
}

// The two governance predicates are unconditional. They are asserted here, in the domain, because every
// surface branches on them.
func TestImportedFindingIsAlwaysExternalAndNeverSelfPromoting(t *testing.T) {
	t.Parallel()

	for _, f := range []ImportedFinding{{}, completeFinding()} {
		if !f.External() {
			t.Fatal("an imported finding is always external")
		}
		if f.CanSelfPromote() {
			t.Fatal("an imported finding can never promote itself: an external tool's confidence is not a distinct verifier's sealed verdict")
		}
	}
}

func TestFindingValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ImportedFinding)
		ok     bool
	}{
		{"complete", func(*ImportedFinding) {}, true},
		{"unknown severity is legitimate", func(f *ImportedFinding) { f.Severity = shared.SeverityUnknown }, true},
		{"no engagement", func(f *ImportedFinding) { f.EngagementID = "" }, false},
		{"no tenant", func(f *ImportedFinding) { f.TenantID = "" }, false},
		{"invented severity", func(f *ImportedFinding) { f.Severity = "spicy" }, false},
		{"incomplete provenance", func(f *ImportedFinding) { f.Provenance.ToolVersion = "" }, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := completeFinding()
			test.mutate(&f)
			err := f.Validate()
			if test.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !test.ok && err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestRefusalCodeValid(t *testing.T) {
	t.Parallel()

	for _, code := range []RefusalCode{
		RefusalNoProvenance, RefusalInvalidLocation, RefusalUnsupportedURI, RefusalUnsupportedURIBase,
		RefusalPathTraversal, RefusalAbsolutePath, RefusalMalformedResult, RefusalTooManyElements,
	} {
		if !code.Valid() {
			t.Fatalf("%q must be a known refusal code", code)
		}
	}
	for _, code := range []RefusalCode{"", "guess", "path-traversal "} {
		if code.Valid() {
			t.Fatalf("%q must not be accepted as a refusal code", code)
		}
	}
}
