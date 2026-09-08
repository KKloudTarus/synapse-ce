package response

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestCatalogueEveryKindHasAReversal is the CI/drift check the #425 "an action with no reversal fails a
// CI check, not a runtime check" requirement rests on: every catalogued Kind must carry a valid reversal.
func TestCatalogueEveryKindHasAReversal(t *testing.T) {
	specs := Catalogue()
	if len(specs) == 0 {
		t.Fatal("empty catalogue; the drift test would pass vacuously")
	}
	for _, s := range specs {
		if !s.Reversal.valid() {
			t.Errorf("response kind %s has no valid reversal — reversibility is mandatory", s.Kind)
		}
		if !s.Radius.Valid() {
			t.Errorf("response kind %s has an invalid blast radius %q", s.Kind, s.Radius)
		}
		if !s.Reversibility.Valid() || s.Reversibility == responsesaga.ReversibilityIrreversible {
			t.Errorf("response kind %s has invalid reversibility %q", s.Kind, s.Reversibility)
		}
	}
}

func validAction() Action {
	sp := catalogue[KindIsolateHost]
	return Action{ID: "act-1", Kind: KindIsolateHost, Target: "host-1", BlastRadius: sp.Radius, Reversibility: sp.Reversibility,
		Argv: []string{"synapse-agent-response", "isolate-host", "host-1"}, Reversal: sp.Reversal}
}

func TestActionValidateFailsClosed(t *testing.T) {
	if err := validAction().Validate(); err != nil {
		t.Fatalf("a well-formed action must validate: %v", err)
	}
	cases := map[string]func(*Action){
		"no id":            func(a *Action) { a.ID = "" },
		"unknown kind":     func(a *Action) { a.Kind = "nuke_from_orbit" },
		"no target":        func(a *Action) { a.Target = "" },
		"bad radius":       func(a *Action) { a.BlastRadius = "galactic" },
		"changed radius":   func(a *Action) { a.BlastRadius = offensivepolicy.RadiusReadOnly },
		"no reversibility": func(a *Action) { a.Reversibility = "" },
		"wrong reversibility": func(a *Action) {
			a.Reversibility = responsesaga.ReversibilityGuaranteed
		},
		"no argv":           func(a *Action) { a.Argv = nil },
		"shell in argv":     func(a *Action) { a.Argv = []string{"sh", "-c", "rm -rf / && echo pwned"} },
		"arbitrary argv":    func(a *Action) { a.Argv = []string{"synapse-agent-response", "stop-process", "host-1"} },
		"no reversal":       func(a *Action) { a.Reversal = ReversalSpec{} },
		"shell in reversal": func(a *Action) { a.Reversal.Argv = []string{"sh", "-c", "restore; echo x"} },
		"wrong reversal":    func(a *Action) { a.Reversal.Kind = ReversalRestartProcess },
		"changed reversal":  func(a *Action) { a.Reversal.Argv = []string{"synapse-agent-response", "restart-process"} },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			a := validAction()
			mut(&a)
			if err := a.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestReversalIsAlwaysStateChangingSafe(t *testing.T) {
	// Sanity: the shipped reversals are argv-only and non-empty.
	for _, s := range Catalogue() {
		if containsShell(s.Reversal.Argv) {
			t.Errorf("reversal for %s contains a shell metacharacter", s.Kind)
		}
		if s.Radius != offensivepolicy.RadiusStateChanging {
			t.Errorf("response %s should be state-changing", s.Kind)
		}
	}
}

func TestCatalogueResultsCannotMutateCommands(t *testing.T) {
	spec, ok := SpecFor(KindIsolateHost)
	if !ok {
		t.Fatal("missing isolate-host specification")
	}
	spec.Reversal.Argv[0] = "poisoned"
	all := Catalogue()
	all[0].Reversal.Argv[0] = "also-poisoned"

	action, err := NewAction("act-1", KindIsolateHost, "host-1")
	if err != nil {
		t.Fatalf("catalogue was mutated through a returned slice: %v", err)
	}
	if got := action.Reversal.Argv[0]; got != "synapse-agent-response" {
		t.Fatalf("reversal executable=%q after caller mutation", got)
	}
}

func TestCanonicalDigestBindsCompleteValidatedAction(t *testing.T) {
	action := validAction()
	digest, err := CanonicalDigest(action)
	if err != nil || len(digest) != 64 {
		t.Fatalf("canonical digest=%q err=%v", digest, err)
	}
	other := action
	other.ID = "act-2"
	otherDigest, err := CanonicalDigest(other)
	if err != nil {
		t.Fatal(err)
	}
	if otherDigest == digest {
		t.Fatal("different action identity produced the same canonical digest")
	}
	invalid := action
	invalid.Argv = []string{"sh", "-c", "true"}
	if _, err := CanonicalDigest(invalid); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid action must not be digestible: %v", err)
	}
}
