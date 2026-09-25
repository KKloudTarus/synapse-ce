package ownsbom

import (
	"context"
	"testing"
)

// bunFixture mirrors what Bun's writer actually emits, including the two relaxations encoding/json
// rejects: trailing commas before a closer, and a // comment. It also carries the three shapes that must
// NOT become components, because they have no resolved version: a workspace entry, a workspace: protocol
// reference and a catalog: reference.
const bunFixture = `{
  "lockfileVersion": 1,
  // Bun writes a comment header in some versions.
  "workspaces": {
    "": {
      "name": "sanji-admin",
      "dependencies": {
        "@scope/env": "workspace:*",
        "zod": "catalog:",
      },
    },
  },
  "packages": {
    "@babel/code-frame": ["@babel/code-frame@7.29.0", "", { "dependencies": { "js-tokens": "^4.0.0" } }, "sha512-AAAA=="],
    "js-tokens": ["js-tokens@4.0.0", "", {}, "sha512-BBBB=="],
    "lodash": ["lodash@4.17.21", "", {}, "sha512-CCCC=="],
    "@scope/env": ["@scope/env@workspace:packages/env"],
    "zod": ["zod@catalog:default"],
  },
}`

func TestBunParsesResolvedPackagesAndEdges(t *testing.T) {
	b := Bun{}
	comps, deps, err := b.Parse(context.Background(), ParseInput{Path: "bun.lock", Content: []byte(bunFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.PURL
	}
	// Resolved packages become components, with the PURL scope escape the other npm-family parsers use.
	for name, wantPURL := range map[string]string{
		"@babel/code-frame": "pkg:npm/%40babel/code-frame@7.29.0",
		"js-tokens":         "pkg:npm/js-tokens@4.0.0",
		"lodash":            "pkg:npm/lodash@4.17.21",
	} {
		if got[name] != wantPURL {
			t.Errorf("%s: PURL = %q, want %q", name, got[name], wantPURL)
		}
	}
	// An unresolved reference must not enter the inventory: an unversioned row is coverage the scan
	// does not have, because no advisory can match it.
	for _, name := range []string{"@scope/env", "zod"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s has no resolved version and must not be a component", name)
		}
	}
	if len(comps) != 3 {
		t.Errorf("components = %d, want 3", len(comps))
	}

	// The edge comes from the third array element, and survives only because both endpoints are emitted.
	if len(deps) != 1 {
		t.Fatalf("deps = %d, want 1: %#v", len(deps), deps)
	}
	if deps[0].Ref != "pkg:npm/%40babel/code-frame@7.29.0" || deps[0].DependsOn[0] != "pkg:npm/js-tokens@4.0.0" {
		t.Errorf("edge = %s -> %v, want @babel/code-frame -> js-tokens", deps[0].Ref, deps[0].DependsOn)
	}
}

// TestRelaxJSONIsStringAware pins that the relaxation does not corrupt quoted values. An integrity hash
// and a URL both contain characters the comma and comment handling look for.
func TestRelaxJSONIsStringAware(t *testing.T) {
	in := `{"a": "https://example.com//path", "b": "x,y,", "c": [1, 2,], }`
	out := string(relaxJSON([]byte(in)))
	if want := `{"a": "https://example.com//path", "b": "x,y,", "c": [1, 2] }`; out != want {
		t.Fatalf("relaxJSON = %q, want %q", out, want)
	}
}

func TestBunMarkerDoesNotClaimTheBinaryLockfile(t *testing.T) {
	b := Bun{}
	for _, m := range b.Markers() {
		if m == "bun.lockb" {
			t.Fatal("bun.lockb cannot be read without Bun itself; claiming it would report an empty inventory for a repository that has dependencies")
		}
	}
}
