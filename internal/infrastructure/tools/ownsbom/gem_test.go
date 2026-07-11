package ownsbom

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const gemfileLockFixture = `GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.8)
    rails (7.0.4)
      actionpack (= 7.0.4)
      activesupport (= 7.0.4)
    rspec (3.12.0)
    nokogiri (1.15.0-x86_64-linux)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rails (~> 7.0)
  rspec

BUNDLED WITH
   2.4.10
`

const gemfileFixture = `source "https://rubygems.org"

gem "rails", "~> 7.0"
gem "nokogiri"

group :development, :test do
  gem "rspec"
end
`

func TestGemParseWithCompanion(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "Gemfile.lock"), gemfileLockFixture)
	mustWrite(t, filepath.Join(dir, "Gemfile"), gemfileFixture)
	comps, deps, err := Gem{}.Parse(context.Background(), ParseInput{Dir: dir, Path: filepath.Join(dir, "Gemfile.lock"), Content: []byte(gemfileLockFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deps != nil {
		t.Errorf("edges deferred; want nil deps, got %v", deps)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// 4 specs (rack, rails, rspec, nokogiri); the deeper-indented actionpack/activesupport are dependency
	// CONSTRAINTS of rails, not specs.
	if len(comps) != 4 {
		t.Fatalf("want 4 spec components, got %d (%+v)", len(comps), comps)
	}
	if _, ok := byName["actionpack"]; ok {
		t.Error("a deeper-indented dependency constraint must NOT be emitted as a spec component")
	}
	if c := byName["rack"]; c.PURL != "pkg:gem/rack@3.0.8" || c.Scope == sbom.ScopeDevelopment {
		t.Errorf("rack should be a production gem: %+v", c)
	}
	if c := byName["nokogiri"]; c.Version != "1.15.0-x86_64-linux" {
		t.Errorf("a platform-qualified version is taken verbatim: %+v", c)
	}
	if c := byName["rspec"]; c.Scope != sbom.ScopeDevelopment {
		t.Errorf("rspec is in a :development,:test group → development scope: %+v", c)
	}
}

func TestGemParseNoCompanion(t *testing.T) {
	comps, _, err := Gem{}.Parse(context.Background(), ParseInput{Path: "Gemfile.lock", Content: []byte(gemfileLockFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 4 {
		t.Errorf("want 4 specs, got %d", len(comps))
	}
	for _, c := range comps {
		if c.Scope == sbom.ScopeDevelopment {
			t.Errorf("with no companion Gemfile, nothing is dev-scoped: %+v", c)
		}
	}
}

func TestGemInlineDevGroup(t *testing.T) {
	dir := t.TempDir()
	lock := "GEM\n  specs:\n    pry (0.14.2)\n    rake (13.0.6)\n"
	gemfile := "gem \"rake\"\ngem \"pry\", group: :development\n"
	mustWrite(t, filepath.Join(dir, "Gemfile.lock"), lock)
	mustWrite(t, filepath.Join(dir, "Gemfile"), gemfile)
	comps, _, err := Gem{}.Parse(context.Background(), ParseInput{Dir: dir, Path: filepath.Join(dir, "Gemfile.lock"), Content: []byte(lock)})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	if byName["pry"].Scope != sbom.ScopeDevelopment {
		t.Errorf("an inline `group: :development` must scope pry development: %+v", byName["pry"])
	}
	if byName["rake"].Scope == sbom.ScopeDevelopment {
		t.Errorf("rake (no group) must not be development: %+v", byName["rake"])
	}
}

func TestGemSkipsGitAndPathSections(t *testing.T) {
	// Only the GEM section's specs are rubygems.org packages. A GIT or PATH section's specs (a gem sourced
	// from a git repo or a local path) must NOT be emitted as pkg:gem/… components – they would get a wrong
	// rubygems PURL. The inGEM gating enforces this; this test pins it against a future refactor.
	lock := `GIT
  remote: https://github.com/example/foo.git
  revision: abc123
  specs:
    foo (1.0.0)

PATH
  remote: ./engines/bar
  specs:
    bar (2.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.8)

DEPENDENCIES
  rack
`
	comps, _, err := Gem{}.Parse(context.Background(), ParseInput{Path: "Gemfile.lock", Content: []byte(lock)})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	if _, ok := byName["foo"]; ok {
		t.Error("a GIT-sourced gem must not be emitted as a rubygems component")
	}
	if _, ok := byName["bar"]; ok {
		t.Error("a PATH-sourced gem must not be emitted as a rubygems component")
	}
	if len(comps) != 1 || byName["rack"].PURL != "pkg:gem/rack@3.0.8" {
		t.Fatalf("only the GEM section's rack should be emitted; got %+v", comps)
	}
}

func TestGemFailSoftOnJunk(t *testing.T) {
	// The gem parser is fail-soft by design: a lockfile with no GEM/specs block yields no components and no
	// error (unlike composer's JSON, which fails loud) – a junk file just contributes nothing to the SBOM.
	comps, deps, err := Gem{}.Parse(context.Background(), ParseInput{Path: "Gemfile.lock", Content: []byte("not a real lockfile\n  random: stuff\n")})
	if err != nil || len(comps) != 0 || deps != nil {
		t.Errorf("junk Gemfile.lock → empty + no error; got %d comps, deps=%v, err=%v", len(comps), deps, err)
	}
}
