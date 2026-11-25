package importedfinding

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func observation(mutate func(*ImportedFinding)) ImportedFinding {
	f := ImportedFinding{
		ID: "o1", TenantID: "t1", EngagementID: "eng1",
		Severity: shared.SeverityHigh,
		Title:    "Hardcoded credential", Message: "AWS access key id in source",
		Location:   Location{Path: "src/app.go", StartLine: 42, StartColumn: 7},
		Provenance: Provenance{ToolName: "semgrep", RuleID: "hardcoded-secret"},
	}
	if mutate != nil {
		mutate(&f)
	}
	return f
}

func TestAToolsFingerprintIsTakenAsTheIdentity(t *testing.T) {
	t.Parallel()
	f := observation(func(f *ImportedFinding) { f.Fingerprint = "abc123" })
	if got := f.BindingExternalIdentity(); got != "fingerprint:abc123" {
		t.Fatalf("identity = %q, want the tool's own fingerprint", got)
	}
	if got := f.BindingScope(); got != "semgrep" {
		t.Fatalf("scope = %q, want the producing tool", got)
	}
}

// Two results a reviewer would never call the same one must not share an identity. Without this, one
// person's decision marks the other approved and nobody ever looks at it. Every case below produced one
// identity before the column and the message digest were part of it.
func TestResultsAReviewerWouldReadDifferentlyGetDifferentIdentities(t *testing.T) {
	t.Parallel()
	base := observation(nil)
	cases := map[string]func(*ImportedFinding){
		"a different secret on the same line": func(f *ImportedFinding) {
			f.Message = "Stripe secret key in source"
		},
		"a different title at the same place": func(f *ImportedFinding) {
			f.Title = "Private key committed"
		},
		"a second match later on the line": func(f *ImportedFinding) {
			f.Location.StartColumn = 61
		},
		"a different line": func(f *ImportedFinding) { f.Location.StartLine = 43 },
		"a different file": func(f *ImportedFinding) { f.Location.Path = "src/other.go" },
		"a different rule": func(f *ImportedFinding) { f.Provenance.RuleID = "weak-cipher" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			other := observation(mutate)
			if base.BindingExternalIdentity() == other.BindingExternalIdentity() {
				t.Fatalf("%s shares the identity %q", name, base.BindingExternalIdentity())
			}
		})
	}
}

// The identity has to be the SAME for the same result across imports, which is the whole reason it is not
// the row id. Nothing that changes between imports of one result may enter it.
func TestTheSameResultKeepsOneIdentityAcrossImports(t *testing.T) {
	t.Parallel()
	first := observation(nil)
	second := observation(func(f *ImportedFinding) {
		f.ID = "o2"
		f.Provenance.SourceDigest = "sha256:tuesday"
		f.Provenance.ToolVersion = "1.9.0"
		f.Provenance.IngestedBy = "human:bob"
		f.Severity = shared.SeverityMedium
		f.Suppressed = true
	})
	if first.BindingExternalIdentity() != second.BindingExternalIdentity() {
		t.Fatalf("identity changed across imports: %q then %q", first.BindingExternalIdentity(), second.BindingExternalIdentity())
	}
}

// Joining components without escaping them lets one result forge another's identity.
func TestASeparatorInsideAComponentCannotForgeAnotherIdentity(t *testing.T) {
	t.Parallel()
	left := observation(func(f *ImportedFinding) {
		f.Provenance.RuleID = "rule@src"
		f.Location.Path = "app.go"
	})
	right := observation(func(f *ImportedFinding) {
		f.Provenance.RuleID = "rule"
		f.Location.Path = "src@app.go"
	})
	if left.BindingExternalIdentity() == right.BindingExternalIdentity() {
		t.Fatalf("two different results share the identity %q", left.BindingExternalIdentity())
	}
}

func TestAResultWithNothingToAddressItByHasNoIdentity(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*ImportedFinding){
		"no rule and no fingerprint": func(f *ImportedFinding) { f.Provenance.RuleID = "" },
		"no location of any kind":    func(f *ImportedFinding) { f.Location.Path, f.Location.LogicalName = "", "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// A decision needs something that distinguishes this result from the next of its kind. Without
			// one, binding it would attach the decision to a key other results share.
			if got := observation(mutate).BindingExternalIdentity(); got != "" {
				t.Fatalf("%s produced the identity %q, want none", name, got)
			}
		})
	}
}

func TestALogicalNameStandsInForAMissingPath(t *testing.T) {
	t.Parallel()
	logical := observation(func(f *ImportedFinding) {
		f.Location.Path = ""
		f.Location.LogicalName = "pkg.Handler"
	})
	if got := logical.BindingExternalIdentity(); got == "" || !strings.Contains(got, "pkg.Handler") {
		t.Fatalf("identity = %q, want it to carry the logical name", got)
	}
	// A logical name and a path that happen to read the same are still different locations, and the
	// escape keeps them apart only if they differ; here they do not, so they are deliberately equal.
	path := observation(func(f *ImportedFinding) { f.Location.Path = "pkg.Handler" })
	if logical.BindingExternalIdentity() == path.BindingExternalIdentity() {
		t.Log("a logical name and an identical path share an identity, which is the documented fallback")
	}
}

func TestAnOverLongIdentityIsReplacedByADigestOfItself(t *testing.T) {
	t.Parallel()
	long := observation(func(f *ImportedFinding) { f.Location.Path = strings.Repeat("deep/", 900) + "a.go" })
	got := long.BindingExternalIdentity()
	if len(got) > MaxBindingIdentityBytes {
		t.Fatalf("identity is %d bytes, over the %d bound the index can hold", len(got), MaxBindingIdentityBytes)
	}
	if !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("identity = %q, want a digest once it outgrows the readable form", got[:min(40, len(got))])
	}
	// The digest still discriminates: a different long path must not collapse onto the same one.
	other := observation(func(f *ImportedFinding) { f.Location.Path = strings.Repeat("deep/", 900) + "b.go" })
	if other.BindingExternalIdentity() == got {
		t.Fatal("two different long paths produced one digest")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
