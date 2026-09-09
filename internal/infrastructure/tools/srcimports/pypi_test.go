package srcimports

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writePypiFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestPypiDirectDependenciesPEP621(t *testing.T) {
	dir := t.TempDir()
	writePypiFile(t, dir, "pyproject.toml", `[project]
name = "app"
dependencies = [
  "requests>=2.0",
  "jinja2 ; python_version >= '3.8'",
  "flask[async]==2.0",
  "vcs-tool @ git+https://example.com/vcs-tool.git",
  "git+https://example.com/evil.git",
]

[project.optional-dependencies]
dev = ["pytest>=7", "black"]
`)
	got, ok := DirectDependencies(context.Background(), dir, "pypi")
	if !ok {
		t.Fatal("a pyproject.toml must be found")
	}
	for _, want := range []string{"requests", "flask", "vcs-tool"} {
		if !got[want] {
			t.Errorf("missing main direct dep %q in %v", want, got)
		}
	}
	// A PEP 508 environment marker makes a dependency conditional; it must NOT be trusted as always-installed.
	if got["winonly"] {
		t.Error("a marker-guarded (conditional) dependency must NOT be treated as an always-installed direct dep")
	}
	// optional-dependencies (extras) are NOT trusted as direct: whether the extra is installed is unknown,
	// so a package present only transitively via a main dep must not be treated as direct.
	for _, unwanted := range []string{"pytest", "black"} {
		if got[unwanted] {
			t.Errorf("optional-dependency %q must NOT be treated as a main direct dep", unwanted)
		}
	}
	// A bare VCS/URL requirement never becomes a fake direct name.
	for _, unwanted := range []string{"git", "https", "evil"} {
		if got[unwanted] {
			t.Errorf("URL/VCS string leaked a fake direct name %q: %v", unwanted, got)
		}
	}
	// A malformed two-word requirement must NOT be truncated into a real dependency name.
	if got["bogus"] {
		t.Error(`the malformed requirement "bogus ignored" must NOT be trusted as "bogus"`)
	}
}

// Poetry 2: when [project].dependencies is present, [tool.poetry.dependencies] only ENRICHES it and adds
// nothing. A package present only in the Poetry table is a constraint on a transitive, not a direct dep.
func TestPypiDirectDependenciesPoetry2Enrichment(t *testing.T) {
	dir := t.TempDir()
	writePypiFile(t, dir, "pyproject.toml", `["project"]
name = "app"
version = "0.1.0"
"dependencies" = ["requests-oauthlib>=2.0.0"]

[tool."poetry".dependencies]
requests = "^2.31"
`)
	got, ok := DirectDependencies(context.Background(), dir, "pypi")
	if !ok {
		t.Fatal("pyproject.toml must be found")
	}
	if !got["requests-oauthlib"] {
		t.Error("the PEP 621 project dependency (with a quoted section and key) must be trusted")
	}
	if got["requests"] {
		t.Error("a package only in the poetry table (enrichment) must NOT be direct when a [project] table exists, even quoted")
	}
}

// A quoted segment containing a dot is ONE key, not a path: [tool."poetry.dependencies"] is an unrelated
// tool table, not the Poetry main dependency table, so its entries must not be trusted as direct deps.
func TestPypiDirectDependenciesFakePoetrySection(t *testing.T) {
	dir := t.TempDir()
	writePypiFile(t, dir, "pyproject.toml", `[tool."poetry.dependencies"]
requests = "^2.31"

[tool." poetry ".dependencies]
flask = "^3.0"
`)
	got, ok := DirectDependencies(context.Background(), dir, "pypi")
	if !ok {
		t.Fatal("pyproject.toml must be found")
	}
	if got["requests"] {
		t.Error(`[tool."poetry.dependencies"] is not the Poetry table (segment "poetry.dependencies" is one quoted key) — must not be trusted`)
	}
	if got["flask"] {
		t.Error(`[tool." poetry ".dependencies] has a spaced quoted key " poetry " (significant) — not the Poetry table, must not be trusted`)
	}
}

func TestPypiDirectDependenciesPoetry(t *testing.T) {
	dir := t.TempDir()
	writePypiFile(t, dir, "pyproject.toml", `[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"
jinja2 = {version = "^3.1", optional = true}

[tool.poetry.extras]
templating = ["jinja2"]

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
`)
	got, ok := DirectDependencies(context.Background(), dir, "pypi")
	if !ok {
		t.Fatal("poetry pyproject.toml must be found")
	}
	if got["python"] {
		t.Error("python is the interpreter constraint, not a dependency")
	}
	if !got["requests"] {
		t.Errorf("missing poetry main direct dep requests in %v", got)
	}
	if got["jinja2"] {
		t.Error("an OPTIONAL poetry dependency must NOT be treated as an always-installed direct dep")
	}
	if got["pytest"] {
		t.Error("a poetry dev GROUP dependency must NOT be treated as a main direct dep")
	}
}

// A Poetry multiple-constraints array (per-python-version) is conditional: the package is not guaranteed
// installed, so it must not be trusted as an always-installed direct dependency even though its opening
// line's value is just "[".
func TestPypiDirectDependenciesPoetryMultiConstraint(t *testing.T) {
	dir := t.TempDir()
	writePypiFile(t, dir, "pyproject.toml", `[tool.poetry.dependencies]
python = ">=3.8"
requests = "^2.31"
idna = [
  { version = ">=2,<3", python = "<3.9" },
  { version = ">=3,<4", python = ">=3.12" },
]
`)
	got, ok := DirectDependencies(context.Background(), dir, "pypi")
	if !ok {
		t.Fatal("poetry pyproject.toml must be found")
	}
	if !got["requests"] {
		t.Error("requests is an unconditional main dep")
	}
	if got["idna"] {
		t.Error("a poetry multiple-constraints (conditional) array dep must NOT be treated as always-installed direct")
	}
}

func TestPypiDirectDependenciesPipfile(t *testing.T) {
	dir := t.TempDir()
	writePypiFile(t, dir, "Pipfile", `[packages]
requests = "*"
jinja2 = "==3.1.0"

[dev-packages]
pytest = "*"
`)
	got, ok := DirectDependencies(context.Background(), dir, "pypi")
	if !ok {
		t.Fatal("Pipfile must be found")
	}
	for _, want := range []string{"requests", "jinja2"} {
		if !got[want] {
			t.Errorf("missing Pipfile [packages] direct dep %q in %v", want, got)
		}
	}
	if got["pytest"] {
		t.Error("a Pipfile [dev-packages] dependency must NOT be treated as a main direct dep")
	}
}

// A Pipfile entry gated by ANY PEP 508 marker key (here implementation_name) is conditional and must be
// excluded, even though the key is not one this parser enumerates — the whitelist of safe keys handles it.
func TestPypiDirectDependenciesPipfileMarkerKey(t *testing.T) {
	dir := t.TempDir()
	writePypiFile(t, dir, "Pipfile", `[packages]
requests = "*"
typing-extensions = { version = "*", implementation_name = "== 'pypy'" }
quotedmarker = { version = "*", "markers" = "sys_platform == 'win32'" }
escaped = { ref = "a\"b", "markers" = "sys_platform == 'win32'" }
`)
	got, ok := DirectDependencies(context.Background(), dir, "pypi")
	if !ok {
		t.Fatal("Pipfile must be found")
	}
	if !got["requests"] {
		t.Errorf("a bare-string dependency must be trusted: %v", got)
	}
	// Any inline-table value is untrusted (not parsed): a marker, a quoted marker key, or an escaped-quote
	// value can never slip a conditional/transitive package into the trusted direct set.
	for _, cond := range []string{"typing-extensions", "quotedmarker", "escaped"} {
		if got[cond] {
			t.Errorf("an inline-table dependency %q must NOT be trusted (conditional-unless-proven policy): %v", cond, got)
		}
	}
}

// SAFETY: a requirements.txt (which pip freeze / pip-compile fills with the fully-resolved graph, direct AND
// transitive) is NOT trusted as a direct-dependency source; with no declaration manifest, no direct set is
// reported, so the reachability analyzer refuses rather than answering a transitive as dead.
func TestPypiDirectDependenciesIgnoresRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	writePypiFile(t, dir, "requirements.txt", "requests==2.0\ntransitive-dep==1.0\n")
	if _, ok := DirectDependencies(context.Background(), dir, "pypi"); ok {
		t.Error("requirements.txt must NOT be treated as a direct-dependency manifest (over-inclusion risk)")
	}
}

// TOML dotted-key semantics: an UNQUOTED dotted key is structural (nested table), not a package name, so it
// must not become a direct dep; a QUOTED dotted key is a literal package name and is trusted.
func TestPypiDirectDependenciesDottedKey(t *testing.T) {
	dir := t.TempDir()
	writePypiFile(t, dir, "Pipfile", `[packages]
botocore = "*"
zope.interface = "*"
"ruamel.yaml" = "*"
"requests ignored" = "*"
"flask\"x" = "*"
`)
	got, ok := DirectDependencies(context.Background(), dir, "pypi")
	if !ok {
		t.Fatal("Pipfile must be found")
	}
	if !got["botocore"] {
		t.Error("a bare key dependency must be trusted")
	}
	if got["zope.interface"] || got["zope-interface"] {
		t.Error("an UNQUOTED dotted key is structural TOML, not a package name — must not be trusted")
	}
	if !got["ruamel.yaml"] {
		t.Error("a QUOTED dotted key is a literal package name — must be trusted")
	}
	// A quoted key is the WHOLE name: a space or embedded quote makes it invalid; it must NOT be truncated
	// into a real dependency name (which could then suppress a transitively-present package).
	if got["requests"] {
		t.Error(`the quoted key "requests ignored" must NOT be trusted as the dependency "requests"`)
	}
	if got["flask"] {
		t.Error(`a quoted key with an embedded quote must NOT be truncated into "flask"`)
	}
}

func TestPypiDirectDependenciesNoManifest(t *testing.T) {
	if _, ok := DirectDependencies(context.Background(), t.TempDir(), "pypi"); ok {
		t.Error("no manifest → not found")
	}
}
