package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const requirementsFixture = `# production deps
Flask==2.3.3
requests==2.31.0  # trailing comment
urllib3>=1.26          # a range, no resolved version -> skipped
SomeName_Pkg==1.0.0
celery[redis]==5.3.0
django==4.2 ; python_version >= "3.8"
arbitrary===9.9.9
spaced-eq == 3.1.4
spaced-arb === 2.7.1
pinned-compound==1.5.0,<2.0
-r other-requirements.txt
-e .
--hash=sha256:abc
`

func TestPyPIParse(t *testing.T) {
	comps, deps, err := PyPI{}.Parse(context.Background(), ParseInput{Path: "requirements.txt", Content: []byte(requirementsFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deps != nil {
		t.Errorf("want nil deps (edges deferred), got %v", deps)
	}
	got := map[string]sbom.Component{}
	for _, c := range comps {
		got[c.Name] = c
	}
	want := map[string]string{
		"flask":           "2.3.3",
		"requests":        "2.31.0", // trailing comment stripped
		"somename-pkg":    "1.0.0",  // PEP 503 normalized (lower-case, _ -> -)
		"celery":          "5.3.0",  // extras [redis] stripped
		"django":          "4.2",    // environment marker stripped
		"arbitrary":       "9.9.9",  // === arbitrary-equality tolerated
		"spaced-eq":       "3.1.4",  // PEP 440 space around == (whitespace-tolerant)
		"spaced-arb":      "2.7.1",  // PEP 440 space around === (whitespace-tolerant)
		"pinned-compound": "1.5.0",  // compound specifier cut at the comma
	}
	if len(comps) != len(want) {
		t.Fatalf("want %d components, got %d: %+v", len(want), len(comps), comps)
	}
	for name, ver := range want {
		c, ok := got[name]
		if !ok || c.Version != ver {
			t.Errorf("%s = %q (present=%v), want %q", name, c.Version, ok, ver)
		}
		if c.PURL != "pkg:pypi/"+name+"@"+ver {
			t.Errorf("%s PURL = %q, want pkg:pypi/%s@%s", name, c.PURL, name, ver)
		}
	}
	if _, ok := got["urllib3"]; ok {
		t.Error("an unpinned range (urllib3) must be skipped – no resolved version")
	}
	if got["flask"].Scope != sbom.ScopeProduction || got["flask"].Location != "requirements.txt" {
		t.Errorf("flask scope/location = %q/%q, want production/requirements.txt", got["flask"].Scope, got["flask"].Location)
	}
}

// TestPyPIDevScopeFromPath: the file PATH drives scope – requirements-dev.txt deps are development
// (the contract-widening payoff: a parser derives scope from ParseInput.Path).
func TestPyPIDevScopeFromPath(t *testing.T) {
	comps, _, err := PyPI{}.Parse(context.Background(), ParseInput{Path: "requirements-dev.txt", Content: []byte("pytest==8.0.0\n")})
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 || comps[0].Scope != sbom.ScopeDevelopment {
		t.Fatalf("requirements-dev.txt deps must be dev-scoped: %+v", comps)
	}
}
