package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// pnpm-lock v9: `packages:` keys are name@version (peers live in snapshots:); scoped keys are quoted.
const pnpmLockV9 = `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-aaa}
    engines: {node: '>=8'}

  '@babel/core@7.23.0':
    resolution: {integrity: sha512-bbb}

snapshots:

  lodash@4.17.21: {}
`

func TestPnpmParseV9(t *testing.T) {
	comps, deps, err := Pnpm{}.Parse(context.Background(), ParseInput{Path: "pnpm-lock.yaml", Content: []byte(pnpmLockV9)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deps != nil {
		t.Errorf("components only (no edges); want nil deps, got %v", deps)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	if c := byName["lodash"]; c.Version != "4.17.21" || c.PURL != "pkg:npm/lodash@4.17.21" {
		t.Errorf("lodash = %+v, want 4.17.21 / pkg:npm/lodash@4.17.21", c)
	}
	if c := byName["@babel/core"]; c.Version != "7.23.0" || c.PURL != "pkg:npm/%40babel/core@7.23.0" {
		t.Errorf("scoped @babel/core = %+v, want 7.23.0 / pkg:npm/%%40babel/core@7.23.0", c)
	}
	// importers: deps (lodash under importers) + snapshots: keys must NOT be double-counted as components —
	// only the packages: block is the source. lodash appears once.
	if len(comps) != 2 {
		t.Fatalf("want 2 components from packages: (lodash, @babel/core), got %d: %+v", len(comps), comps)
	}
	// The resolution integrity (SRI) must be captured as a component Checksum (deferred-emission attaches it
	// to the right package key).
	if ck := byName["lodash"].Checksums; len(ck) != 1 || ck[0].Algorithm != "SHA512" || ck[0].Value != "aaa" {
		t.Errorf("lodash checksum = %+v, want [{SHA512 aaa}]", ck)
	}
	if ck := byName["@babel/core"].Checksums; len(ck) != 1 || ck[0].Value != "bbb" {
		t.Errorf("@babel/core checksum = %+v, want [{SHA512 bbb}]", ck)
	}
}

// v6 keys carry a leading `/` and a `(peer)` suffix; v5 uses `/name/version`. Both must resolve.
func TestPnpmParseV6AndV5KeyForms(t *testing.T) {
	for _, tc := range []struct{ name, lock, wantName, wantVer string }{
		{"v6 peer suffix", "packages:\n  /lodash@4.17.21(react@18.0.0):\n    resolution: {integrity: x}\n", "lodash", "4.17.21"},
		{"v6 scoped", "packages:\n  /@babel/core@7.23.0:\n    resolution: {integrity: x}\n", "@babel/core", "7.23.0"},
		{"v5 slash", "packages:\n  /lodash/4.17.21:\n    resolution: {integrity: x}\n", "lodash", "4.17.21"},
		{"v5 scoped slash", "packages:\n  /@babel/core/7.23.0:\n    resolution: {integrity: x}\n", "@babel/core", "7.23.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			comps, _, err := Pnpm{}.Parse(context.Background(), ParseInput{Path: "pnpm-lock.yaml", Content: []byte(tc.lock)})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(comps) != 1 || comps[0].Name != tc.wantName || comps[0].Version != tc.wantVer {
				t.Fatalf("want %s@%s, got %+v", tc.wantName, tc.wantVer, comps)
			}
		})
	}
}

func TestPnpmSpecNameVersion(t *testing.T) {
	cases := []struct {
		in, name, ver string
		ok            bool
	}{
		{"lodash@4.17.21", "lodash", "4.17.21", true},
		{"@babel/core@7.23.0", "@babel/core", "7.23.0", true},
		{"/lodash@4.17.21(react@18)", "lodash", "4.17.21", true},
		{"/lodash/4.17.21", "lodash", "4.17.21", true},
		{"/@babel/core/7.23.0", "@babel/core", "7.23.0", true},
		{"lodash@", "", "", false},         // empty version
		{"lodash", "", "", false},          // no version
		{"@scope/x@latest", "", "", false}, // floating version not resolved
		// degenerate / hostile keys must fail closed, never panic (security review):
		{"@", "", "", false},        // lone scope '@'
		{"/", "", "", false},        // lone slash
		{"", "", "", false},         // empty
		{"(foo", "", "", false},     // unclosed peer suffix → emptied
		{":", "", "", false},        // stray colon
		{"@scope/x", "", "", false}, // scoped name, no version
	}
	for _, c := range cases {
		n, v, ok := pnpmSpecNameVersion(c.in)
		if ok != c.ok || n != c.name || v != c.ver {
			t.Errorf("pnpmSpecNameVersion(%q) = (%q,%q,%v), want (%q,%q,%v)", c.in, n, v, ok, c.name, c.ver, c.ok)
		}
	}
}
