package ownsbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// edgeMap indexes emitted dependency edges by parent PURL for compact assertion.
func edgeMap(deps []sbom.Dependency) map[string][]string {
	m := map[string][]string{}
	for _, d := range deps {
		m[d.Ref] = append(m[d.Ref], d.DependsOn...)
	}
	return m
}

func scopeOf(deps []sbom.Dependency, ref, on string) string {
	for _, d := range deps {
		if d.Ref != ref {
			continue
		}
		for _, t := range d.DependsOn {
			if t == on {
				return d.Scope
			}
		}
	}
	return ""
}

func rangeOf(deps []sbom.Dependency, ref, on string) string {
	for _, d := range deps {
		if d.Ref == ref {
			return d.RequestedRanges[on]
		}
	}
	return ""
}

// --- Composer ---

const composerEdgesFixture = `{
  "packages": [
    {"name":"vendor/app","version":"1.0.0","require":{"vendor/lib":"^2.0","php":">=8.0","ext-json":"*"}},
    {"name":"vendor/lib","version":"2.3.1","require":{"vendor/core":"~1.0","vendor/lib":"self"}},
    {"name":"vendor/core","version":"1.5.0","require":{"vendor/missing":"^9.9"}}
  ],
  "packages-dev": [
    {"name":"vendor/phpunit","version":"9.0.0","require":{"vendor/lib":"^2.0"}}
  ]
}`

func TestComposerEmitsEdges(t *testing.T) {
	comps, deps, err := Composer{}.Parse(context.Background(), ParseInput{Path: "/p/composer.lock", Content: []byte(composerEdgesFixture)})
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 4 {
		t.Fatalf("want 4 components, got %d", len(comps))
	}
	em := edgeMap(deps)
	app, lib, core := "pkg:composer/vendor/app@1.0.0", "pkg:composer/vendor/lib@2.3.1", "pkg:composer/vendor/core@1.5.0"
	if on := em[app]; len(on) != 1 || on[0] != lib {
		t.Fatalf("app edges = %v, want [%s]", on, lib) // php + ext-json are platform reqs -> no edge
	}
	if on := em[lib]; len(on) != 1 || on[0] != core {
		t.Fatalf("lib edges = %v, want [%s] (self-edge dropped)", on, core)
	}
	if on, ok := em[core]; ok {
		t.Fatalf("core must have no edge (vendor/missing is not in the lock), got %v", on)
	}
	// declared ranges + dev scope
	if r := rangeOf(deps, app, lib); r != "^2.0" {
		t.Fatalf("app->lib range = %q, want ^2.0", r)
	}
	if s := scopeOf(deps, "pkg:composer/vendor/phpunit@9.0.0", lib); s != sbom.ScopeDevelopment {
		t.Fatalf("phpunit->lib scope = %q, want development", s)
	}
	// transitive vuln in core reports EVERY introducing direct dependency: app (prod) and phpunit (dev), each
	// reaching core through lib. Removing core requires bumping both introducers.
	phpunit := "pkg:composer/vendor/phpunit@9.0.0"
	if got := sbom.IntroducedBy(deps, core); len(got) != 2 || got[0] != app || got[1] != phpunit {
		t.Fatalf("IntroducedBy(core) = %v, want [%s %s]", got, app, phpunit)
	}
	ids := componentIDSet(comps)
	if sbom.IsDirect(deps, ids, lib) {
		t.Fatalf("lib is a transitive of app (a component depends on it), must not be IsDirect")
	}
	if !sbom.IsDirect(deps, ids, app) {
		t.Fatalf("app is a graph root (nothing depends on it), must be IsDirect")
	}
	if p := sbom.PathToRoot(deps, core); len(p) == 0 || p[0] != app {
		t.Fatalf("PathToRoot(core) = %v, want to start at %s", p, app)
	}
}

func TestComposerMalformedErrors(t *testing.T) {
	if _, _, err := (Composer{}).Parse(context.Background(), ParseInput{Path: "/p/composer.lock", Content: []byte("{not json")}); err == nil {
		t.Fatal("malformed composer.lock must error")
	}
}

func componentIDSet(comps []sbom.Component) map[string]bool {
	ids := map[string]bool{}
	for _, c := range comps {
		ids[sbom.ComponentID(c.Name, c.Version, c.PURL)] = true
	}
	return ids
}

// --- Elixir / Mix ---

const mixLockFixture = `%{
  "app": {:hex, :app, "1.0.0", "aaa", [:mix], [{:lib, "~> 2.0", [hex: :lib, repo: "hexpm", optional: false]}], "hexpm", "h1"},
  "lib": {:hex, :lib, "2.3.1", "bbb", [:mix], [{:core, ">= 1.0.0", [hex: :core]}, {:gone, "~> 9.0", [hex: :gone]}], "hexpm", "h2"},
  "core": {:hex, :core, "1.5.0", "ccc", [:mix], [], "hexpm", "h3"},
}`

func TestElixirEmitsEdges(t *testing.T) {
	comps, deps, err := Elixir{}.Parse(context.Background(), ParseInput{Path: "/p/mix.lock", Content: []byte(mixLockFixture)})
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 3 {
		t.Fatalf("want 3 components, got %d", len(comps))
	}
	em := edgeMap(deps)
	app, lib, core := "pkg:hex/app@1.0.0", "pkg:hex/lib@2.3.1", "pkg:hex/core@1.5.0"
	if on := em[app]; len(on) != 1 || on[0] != lib {
		t.Fatalf("app edges = %v, want [%s]", on, lib)
	}
	if on := em[lib]; len(on) != 1 || on[0] != core { // :gone is not in the lock -> dropped
		t.Fatalf("lib edges = %v, want [%s]", on, core)
	}
	if r := rangeOf(deps, app, lib); r != "~> 2.0" {
		t.Fatalf("app->lib range = %q, want ~> 2.0", r)
	}
	if got := sbom.IntroducedBy(deps, core); len(got) != 1 || got[0] != app {
		t.Fatalf("IntroducedBy(core) = %v, want [%s]", got, app)
	}
}

// --- Julia ---

const juliaManifestFixture = `[[App]]
deps = ["Lib"]
version = "1.0.0"

[[Lib]]
deps = ["Core", "Random"]
version = "2.3.1"

[[Core]]
version = "1.5.0"

[[Random]]
uuid = "9a3f8284"
`

func TestJuliaEmitsEdges(t *testing.T) {
	comps, deps, err := Julia{}.Parse(context.Background(), ParseInput{Path: "/p/Manifest.toml", Content: []byte(juliaManifestFixture)})
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 3 { // Random has no version (stdlib) -> not a component
		t.Fatalf("want 3 components, got %d: %+v", len(comps), comps)
	}
	em := edgeMap(deps)
	app, lib, core := "pkg:julia/App@1.0.0", "pkg:julia/Lib@2.3.1", "pkg:julia/Core@1.5.0"
	if on := em[app]; len(on) != 1 || on[0] != lib {
		t.Fatalf("App edges = %v, want [%s]", on, lib)
	}
	if on := em[lib]; len(on) != 1 || on[0] != core { // Random unresolved (stdlib) -> dropped
		t.Fatalf("Lib edges = %v, want [%s]", on, core)
	}
	if got := sbom.IntroducedBy(deps, core); len(got) != 1 || got[0] != app {
		t.Fatalf("IntroducedBy(Core) = %v, want [%s]", got, app)
	}
}

// --- renv ---

const renvEdgesFixture = `{"Packages":{
  "app":{"Package":"app","Version":"1.0.0","Requirements":["lib","methods"]},
  "lib":{"Package":"lib","Version":"2.3.1","Requirements":["core"]},
  "core":{"Package":"core","Version":"1.5.0","Requirements":[]}
}}`

func TestRenvEmitsEdges(t *testing.T) {
	comps, deps, err := Renv{}.Parse(context.Background(), ParseInput{Path: "/p/renv.lock", Content: []byte(renvEdgesFixture)})
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 3 {
		t.Fatalf("want 3 components, got %d", len(comps))
	}
	em := edgeMap(deps)
	app, lib, core := "pkg:cran/app@1.0.0", "pkg:cran/lib@2.3.1", "pkg:cran/core@1.5.0"
	if on := em[app]; len(on) != 1 || on[0] != lib { // "methods" is a base R package absent from Packages -> dropped
		t.Fatalf("app edges = %v, want [%s]", on, lib)
	}
	if on := em[lib]; len(on) != 1 || on[0] != core {
		t.Fatalf("lib edges = %v, want [%s]", on, core)
	}
	// renv records no ranges
	for _, d := range deps {
		if len(d.RequestedRanges) != 0 {
			t.Fatalf("renv edges must carry no ranges, got %v", d.RequestedRanges)
		}
	}
	if got := sbom.IntroducedBy(deps, core); len(got) != 1 || got[0] != app {
		t.Fatalf("IntroducedBy(core) = %v, want [%s]", got, app)
	}
}

// --- Dart ---

const dartLockFixture = `packages:
  http:
    dependency: "direct main"
    version: "0.13.5"
  path:
    dependency: transitive
    version: "1.8.0"
  test:
    dependency: "direct dev"
    version: "1.20.0"
sdks:
  dart: ">=2.17.0"
`

const dartPubspecFixture = `name: myapp
version: 0.1.0
dependencies:
  http: ^0.13.0
  flutter:
    sdk: flutter
dev_dependencies:
  test: ^1.0.0
`

func TestDartEmitsRootEdges(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pubspec.yaml"), []byte(dartPubspecFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, "pubspec.lock")
	comps, deps, err := Dart{}.Parse(context.Background(), ParseInput{Dir: dir, Path: lockPath, Content: []byte(dartLockFixture)})
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 3 { // http, path, test (root is a synthetic node, not a component)
		t.Fatalf("want 3 components, got %d: %+v", len(comps), comps)
	}
	root, httpP, testP, pathP := "pkg:pub/myapp@0.1.0", "pkg:pub/http@0.13.5", "pkg:pub/test@1.20.0", "pkg:pub/path@1.8.0"
	em := edgeMap(deps)
	on := em[root]
	if len(on) != 2 || !containsStr(on, httpP) || !containsStr(on, testP) {
		t.Fatalf("root edges = %v, want http + test (flutter sdk dropped, transitive path not a direct edge)", on)
	}
	if r := rangeOf(deps, root, httpP); r != "^0.13.0" {
		t.Fatalf("root->http range = %q, want ^0.13.0", r)
	}
	if s := scopeOf(deps, root, testP); s != sbom.ScopeDevelopment {
		t.Fatalf("root->test scope = %q, want development", s)
	}
	// http is a DIRECT dependency: its only dependent is the synthetic (non-component) root.
	ids := componentIDSet(comps)
	if !sbom.IsDirect(deps, ids, httpP) {
		t.Fatalf("http must be IsDirect (root is synthetic)")
	}
	// the transitive package `path` is not in the edge graph (pubspec.lock has no transitive edges)
	if _, ok := em[pathP]; ok {
		t.Fatalf("path must not source an edge")
	}
}

func TestDartNoCompanionNoEdges(t *testing.T) {
	dir := t.TempDir() // no pubspec.yaml written
	comps, deps, err := Dart{}.Parse(context.Background(), ParseInput{Dir: dir, Path: filepath.Join(dir, "pubspec.lock"), Content: []byte(dartLockFixture)})
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 3 || len(deps) != 0 {
		t.Fatalf("without a companion pubspec.yaml Dart must emit components only, got %d comps %d edges", len(comps), len(deps))
	}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Codex #1036 finding 1: a name in a Julia deps-line COMMENT must not become an edge.
func TestJuliaCommentNotAnEdge(t *testing.T) {
	fixture := `[[App]]
version = "1.0.0"
deps = ["Lib"] # "Core" is only a comment

[[Lib]]
version = "2.0.0"

[[Core]]
version = "3.0.0"
`
	_, deps, err := Julia{}.Parse(context.Background(), ParseInput{Path: "/p/Manifest.toml", Content: []byte(fixture)})
	if err != nil {
		t.Fatal(err)
	}
	on := edgeMap(deps)["pkg:julia/App@1.0.0"]
	if len(on) != 1 || on[0] != "pkg:julia/Lib@2.0.0" {
		t.Fatalf("App must depend only on Lib (Core is in a comment), got %v", on)
	}
}

// Codex #1036 finding 3: a dep tuple in an Elixir COMMENT must not become an edge.
func TestElixirCommentNotAnEdge(t *testing.T) {
	fixture := `%{
  "app": {:hex, :app, "1.0.0", "aaa", [:mix], [], "hexpm", "h1"}, # {:lib, "~> 2.0", [hex: :lib]}
  "lib": {:hex, :lib, "2.0.0", "bbb", [:mix], [], "hexpm", "h2"},
}`
	_, deps, err := Elixir{}.Parse(context.Background(), ParseInput{Path: "/p/mix.lock", Content: []byte(fixture)})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := edgeMap(deps)["pkg:hex/app@1.0.0"]; ok {
		t.Fatalf("app has an empty deps list; a commented tuple must not create an edge, got %v", deps)
	}
}

// Codex #1036 finding 4: a YAML inline comment must not leak into a Dart requested range.
func TestDartRangeStripsComment(t *testing.T) {
	dir := t.TempDir()
	pubspec := `name: myapp
version: 0.1.0
dependencies:
  http: ^0.13.0 # the http client
`
	lock := `packages:
  http:
    dependency: "direct main"
    version: "0.13.5"
`
	if err := os.WriteFile(filepath.Join(dir, "pubspec.yaml"), []byte(pubspec), 0o644); err != nil {
		t.Fatal(err)
	}
	_, deps, err := Dart{}.Parse(context.Background(), ParseInput{Dir: dir, Path: filepath.Join(dir, "pubspec.lock"), Content: []byte(lock)})
	if err != nil {
		t.Fatal(err)
	}
	if r := rangeOf(deps, "pkg:pub/myapp@0.1.0", "pkg:pub/http@0.13.5"); r != "^0.13.0" {
		t.Fatalf("range must strip the inline comment, got %q", r)
	}
}

// Codex #1036 finding 2: an SDK pseudo-dep (flutter, source: sdk) must never become a component or an edge.
func TestDartSdkDepNoEdge(t *testing.T) {
	dir := t.TempDir()
	pubspec := `name: myapp
version: 0.1.0
dependencies:
  flutter:
    sdk: flutter
  http: ^0.13.0
`
	lock := `packages:
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  http:
    dependency: "direct main"
    version: "0.13.5"
`
	if err := os.WriteFile(filepath.Join(dir, "pubspec.yaml"), []byte(pubspec), 0o644); err != nil {
		t.Fatal(err)
	}
	comps, deps, err := Dart{}.Parse(context.Background(), ParseInput{Dir: dir, Path: filepath.Join(dir, "pubspec.lock"), Content: []byte(lock)})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "flutter" {
			t.Fatalf("flutter (source: sdk) must not be a component")
		}
	}
	on := edgeMap(deps)["pkg:pub/myapp@0.1.0"]
	if len(on) != 1 || on[0] != "pkg:pub/http@0.13.5" {
		t.Fatalf("root must depend only on http (flutter sdk dropped), got %v", on)
	}
}

// Codex #1036 re-review: an Elixir dep renamed via `[hex: :real_package]` must resolve to the real package's
// component, not the (absent) atom name — a false-negative otherwise.
func TestElixirHexRenameResolves(t *testing.T) {
	fixture := `%{
  "aws_credentials": {:hex, :aws_credentials, "0.3.2", "aaa", [:rebar3], [{:eini, "~> 2.2.4", [hex: :eini_beam, repo: "hexpm", optional: false]}], "hexpm", "h1"},
  "eini_beam": {:hex, :eini_beam, "2.2.5", "bbb", [:rebar3], [], "hexpm", "h2"},
}`
	_, deps, err := Elixir{}.Parse(context.Background(), ParseInput{Path: "/p/mix.lock", Content: []byte(fixture)})
	if err != nil {
		t.Fatal(err)
	}
	on := edgeMap(deps)["pkg:hex/aws_credentials@0.3.2"]
	if len(on) != 1 || on[0] != "pkg:hex/eini_beam@2.2.5" {
		t.Fatalf("renamed dep must resolve to eini_beam, got %v", on)
	}
	if r := rangeOf(deps, "pkg:hex/aws_credentials@0.3.2", "pkg:hex/eini_beam@2.2.5"); r != "~> 2.2.4" {
		t.Fatalf("range = %q, want ~> 2.2.4", r)
	}
}
