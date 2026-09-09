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
	// importers: deps (lodash under importers) + snapshots: keys must NOT be double-counted as components –
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

// v9: dependency edges come from the `snapshots:` block's dependencies:/optionalDependencies: sub-maps.
const pnpmLockV9Edges = `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      express:
        specifier: ^4.18.0
        version: 4.18.2

packages:

  express@4.18.2:
    resolution: {integrity: sha512-e}
  body-parser@1.20.1:
    resolution: {integrity: sha512-b}
  bytes@3.1.2:
    resolution: {integrity: sha512-by}

snapshots:

  express@4.18.2:
    dependencies:
      body-parser: 1.20.1
    optionalDependencies:
      bytes: 3.1.2

  body-parser@1.20.1:
    dependencies:
      bytes: 3.1.2

  bytes@3.1.2: {}
`

func TestPnpmParseV9Edges(t *testing.T) {
	comps, deps, err := Pnpm{}.Parse(context.Background(), ParseInput{Path: "pnpm-lock.yaml", Content: []byte(pnpmLockV9Edges)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 3 {
		t.Fatalf("want 3 components, got %d: %+v", len(comps), comps)
	}
	byRef := map[string][]string{}
	for _, d := range deps {
		byRef[d.Ref] = d.DependsOn
	}
	// express depends on body-parser (dependencies) AND bytes (optionalDependencies).
	exp := byRef["pkg:npm/express@4.18.2"]
	if !contains(exp, "pkg:npm/body-parser@1.20.1") || !contains(exp, "pkg:npm/bytes@3.1.2") {
		t.Errorf("express edges = %v, want body-parser + bytes", exp)
	}
	// body-parser depends on bytes (transitive).
	if bp := byRef["pkg:npm/body-parser@1.20.1"]; !contains(bp, "pkg:npm/bytes@3.1.2") {
		t.Errorf("body-parser edges = %v, want bytes", bp)
	}
	// bytes is a leaf (no edge with a DependsOn).
	if _, ok := byRef["pkg:npm/bytes@3.1.2"]; ok {
		t.Errorf("bytes is a leaf; must have no outgoing edge, got %v", byRef["pkg:npm/bytes@3.1.2"])
	}
	// PathToRoot: express is a top-level (direct) dep — nothing depends on it; bytes is transitive.
	if p := sbom.PathToRoot(deps, "pkg:npm/express@4.18.2"); len(p) != 1 {
		t.Errorf("express must be a direct/top-level dep (no dependents), PathToRoot=%v", p)
	}
	if p := sbom.PathToRoot(deps, "pkg:npm/bytes@3.1.2"); len(p) < 2 {
		t.Errorf("bytes must be transitive (a path to a root), PathToRoot=%v", p)
	}
}

// v6: dependency edges come from the `packages:` block (keys carry a leading / and a (peer) suffix).
const pnpmLockV6Edges = `lockfileVersion: '6.0'

packages:

  /express@4.18.2:
    resolution: {integrity: sha512-e}
    dependencies:
      body-parser: 1.20.1

  /body-parser@1.20.1:
    resolution: {integrity: sha512-b}
    dependencies:
      bytes: 3.1.2(supports-color@8.1.1)

  /bytes@3.1.2:
    resolution: {integrity: sha512-by}
`

func TestPnpmParseV6Edges(t *testing.T) {
	comps, deps, err := Pnpm{}.Parse(context.Background(), ParseInput{Path: "pnpm-lock.yaml", Content: []byte(pnpmLockV6Edges)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 3 {
		t.Fatalf("want 3 components, got %d", len(comps))
	}
	byRef := map[string][]string{}
	for _, d := range deps {
		byRef[d.Ref] = d.DependsOn
	}
	if e := byRef["pkg:npm/express@4.18.2"]; !contains(e, "pkg:npm/body-parser@1.20.1") {
		t.Errorf("express edge = %v, want body-parser", e)
	}
	// The dep value carries a (peer) suffix which must be stripped to resolve bytes@3.1.2.
	if bp := byRef["pkg:npm/body-parser@1.20.1"]; !contains(bp, "pkg:npm/bytes@3.1.2") {
		t.Errorf("body-parser edge (peer suffix stripped) = %v, want bytes", bp)
	}
}

// An edge target that is not an emitted component (a range, alias, or link) is dropped (resolution-as-filter).
func TestPnpmParseEdgesResolutionFilter(t *testing.T) {
	const lock = `lockfileVersion: '9.0'
packages:
  express@4.18.2:
    resolution: {integrity: sha512-e}
snapshots:
  express@4.18.2:
    dependencies:
      ghost: 9.9.9
      linked: link:../local
`
	_, deps, err := Pnpm{}.Parse(context.Background(), ParseInput{Path: "pnpm-lock.yaml", Content: []byte(lock)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// ghost@9.9.9 is not an emitted component and linked is a link: path — neither resolves, so express has
	// no outgoing edge at all.
	if len(deps) != 0 {
		t.Errorf("edges to non-components must be dropped, got %+v", deps)
	}
}

// v9 alias: a dependency map key is the local import name and the value is the real package id
// (name@version); the edge must target the real package, not <key>@<value>.
func TestPnpmParseV9AliasEdge(t *testing.T) {
	const lock = `lockfileVersion: '9.0'
packages:
  obug@1.0.2:
    resolution: {integrity: sha512-o}
  finalhandler@1.1.2:
    resolution: {integrity: sha512-f}
snapshots:
  finalhandler@1.1.2:
    dependencies:
      debug: obug@1.0.2(ms@2.1.3)
  obug@1.0.2: {}
`
	_, deps, err := Pnpm{}.Parse(context.Background(), ParseInput{Path: "pnpm-lock.yaml", Content: []byte(lock)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byRef := map[string][]string{}
	for _, d := range deps {
		byRef[d.Ref] = d.DependsOn
	}
	if fh := byRef["pkg:npm/finalhandler@1.1.2"]; !contains(fh, "pkg:npm/obug@1.0.2") {
		t.Errorf("aliased dep must resolve to the real package obug@1.0.2, got %v", fh)
	}
	// It must NOT invent a debug@obug... target.
	for _, on := range byRef["pkg:npm/finalhandler@1.1.2"] {
		if on != "pkg:npm/obug@1.0.2" {
			t.Errorf("unexpected edge target %q (alias mis-parsed)", on)
		}
	}
}

// Peer-context snapshot variants of one package collapse to one Ref; their targets must be merged into a
// single Dependency object.
func TestPnpmParseV9PeerVariantsMergeByRef(t *testing.T) {
	const lock = `lockfileVersion: '9.0'
packages:
  plugin@1.0.0:
    resolution: {integrity: sha512-p}
  react@17.0.0:
    resolution: {integrity: sha512-r17}
  react@18.0.0:
    resolution: {integrity: sha512-r18}
snapshots:
  plugin@1.0.0(react@17.0.0):
    dependencies:
      react: 17.0.0
  plugin@1.0.0(react@18.0.0):
    dependencies:
      react: 18.0.0
  react@17.0.0: {}
  react@18.0.0: {}
`
	_, deps, err := Pnpm{}.Parse(context.Background(), ParseInput{Path: "pnpm-lock.yaml", Content: []byte(lock)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	n := 0
	var on []string
	for _, d := range deps {
		if d.Ref == "pkg:npm/plugin@1.0.0" {
			n++
			on = d.DependsOn
		}
	}
	if n != 1 {
		t.Fatalf("plugin@1.0.0 must have exactly ONE merged Dependency, got %d", n)
	}
	if !contains(on, "pkg:npm/react@17.0.0") || !contains(on, "pkg:npm/react@18.0.0") {
		t.Errorf("merged plugin edge must include both react variants, got %v", on)
	}
}

// A v5-style `_peer` dependency value (whose peer part may contain '@') must never be misread as an alias
// package id: it is dropped (a safe missed edge), never turned into a wrong edge.
func TestPnpmParseV5PeerValueDropped(t *testing.T) {
	const lock = `lockfileVersion: '9.0'
packages:
  root@1.0.0:
    resolution: {integrity: sha512-r}
snapshots:
  root@1.0.0:
    dependencies:
      thing: 1.0.0_react@18.2.0
`
	_, deps, err := Pnpm{}.Parse(context.Background(), ParseInput{Path: "pnpm-lock.yaml", Content: []byte(lock)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("a v5 _peer value must be dropped (no wrong edge), got %+v", deps)
	}
}
