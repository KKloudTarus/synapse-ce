package sca

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// A resolver that pins a lockfile-less manifest is a resolving source in exactly the sense
// completeness means: it runs the ecosystem's own lock tool and the versions it returns are as
// pinned as a committed lockfile's. Maven and Gradle already recorded a marker for this and npm and
// the manifest resolvers did not, so a scan that resolved every component still reported "Only 1171
// of 1171 components have pinned versions; some dependencies are unresolved", which tells an
// operator the opposite of what happened.
func TestCompletenessAcceptsAResolvedTreeAsASource(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
		{Name: "express", Version: "4.18.2", PURL: "pkg:npm/express@4.18.2"},
	}}

	t.Run("no resolving source at all stays incomplete", func(t *testing.T) {
		c := computeCompleteness(doc, nil, nil)
		if c.Confident {
			t.Fatal("pinned components with no resolving source must not read confident")
		}
		if !strings.Contains(c.Warning, "pinned versions") {
			t.Errorf("warning = %q, want it to name the unresolved state", c.Warning)
		}
	})

	t.Run("a resolved tree counts like a lockfile", func(t *testing.T) {
		c := computeCompleteness(doc, []string{"npm-resolved-tree"}, nil)
		if !c.Confident {
			t.Fatalf("a fully resolved tree must read confident, got warning %q", c.Warning)
		}
		if c.Warning != "" {
			t.Errorf("a confident scan must carry no warning, got %q", c.Warning)
		}
		if c.ComponentsResolved != c.ComponentsTotal {
			t.Errorf("resolved %d of %d, want all", c.ComponentsResolved, c.ComponentsTotal)
		}
	})

	t.Run("an unresolved ecosystem still wins", func(t *testing.T) {
		c := computeCompleteness(doc, []string{"npm-resolved-tree"}, []string{"gradle"})
		if c.Confident {
			t.Fatal("an unresolved build system must keep the scan incomplete")
		}
		if !strings.Contains(c.Warning, "gradle") {
			t.Errorf("warning = %q, want it to name the unresolved build system", c.Warning)
		}
	})
}
