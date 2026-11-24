package acquire

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
)

// A name in lockfileNames makes a scan count as resolved. That is only honest when the SBOM producer reads
// the file: a name nothing claims lets a directory holding just that file report zero components and still
// be confident. gradle.lockfile was in this set for exactly that reason before a parser claimed it.
//
// The names below are the ones still listed without an owned parser of their own. They are recorded here so a
// new entry cannot join them unnoticed, and so the day a parser claims one this test says to take it off.
func TestLockfileNamesAreReadByAnOwnedParser(t *testing.T) {
	reg, err := ownsbom.DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}
	claimed := reg.MarkerEcosystems()

	unclaimed := map[string]string{
		"go.sum":              "go.mod is the file the Go parser reads; go.sum is its integrity companion, so a Go tree is confident on go.sum while the components come from go.mod",
		"npm-shrinkwrap.json": "no owned parser reads it, so on its own it yields no components",
	}

	for name := range lockfileNames {
		_, isClaimed := claimed[name]
		reason, isException := unclaimed[name]
		switch {
		case isClaimed && isException:
			t.Errorf("%s is now claimed by an owned parser; remove it from the exceptions", name)
		case !isClaimed && !isException:
			t.Errorf("%s counts as a resolving lockfile but no owned parser reads it; add a parser, or list it here with the reason it is safe", name)
		case isException && reason == "":
			t.Errorf("%s: an exception needs a reason", name)
		}
	}
	for name := range unclaimed {
		if !lockfileNames[name] {
			t.Errorf("%s is listed as an exception but is not in lockfileNames", name)
		}
	}
}
