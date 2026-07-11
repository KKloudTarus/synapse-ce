package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Gem is the owned Ruby parser: it reads Gemfile.lock – the resolved gem set – into gem
// components, and reads the COMPANION Gemfile (via ParseInput.Dir) to scope gems declared in a
// `group:development`/`:test` block (or with an inline group: option) as development, since Gemfile.lock
// carries no group flag. Components only – a spec's deeper-indented deps are version CONSTRAINTS (edges),
// deferred. Hand-parsed (the GEM section's `specs:` block), no Ruby/Bundler dependency.
type Gem struct{}

// Ecosystem identifies this parser's package ecosystem.
func (Gem) Ecosystem() string { return "gem" }

// Markers are the lockfile basenames Gem claims.
func (Gem) Markers() []string { return []string{"Gemfile.lock"} }

// Parse extracts the resolved gems from the GEM section's `specs:` block. A spec is `name (version)` at the
// spec indent; its deeper-indented lines are dependency constraints (edges) and are skipped. Only
// the GEM section is read (a GIT/PATH section's specs are not rubygems.org packages).
func (Gem) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil { // honor cancellation before the companion read (Parse does I/O)
		return nil, nil, err
	}
	dev := gemDevGems(in.Dir) // gems in a Gemfile:development/:test group (companion, best-effort)
	baseScope := sbom.ClassifyScope(in.Path, "")

	set := newComponentSet()
	inGEM, inSpecs := false, false
	specIndent := -1
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		switch {
		case indent == 0: // a top-level section header (GEM, GIT, PATH, PLATFORMS, DEPENDENCIES, BUNDLED WITH…)
			inGEM = trimmed == "GEM"
			inSpecs, specIndent = false, -1
		case inGEM && trimmed == "specs:":
			inSpecs, specIndent = true, -1
		case inSpecs && trimmed != "":
			if specIndent == -1 {
				specIndent = indent // the first spec line sets the spec indent; deeper lines are deps
			}
			if indent == specIndent {
				if name, version, ok := parseGemSpec(trimmed); ok {
					scope := baseScope
					if dev[name] {
						scope = sbom.ScopeDevelopment
					}
					set.add(sbom.Component{Name: name, Version: version, PURL: "pkg:gem/" + name + "@" + version, Location: in.Path, Scope: scope})
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan Gemfile.lock: %w", err)
	}
	return set.components(), nil, nil
}

// parseGemSpec parses a `name (version)` spec line. A version containing a space or comma is a dependency
// CONSTRAINT (e.g. "= 7.0.4", ">= 1.0"), not a resolved spec version, so it is rejected (belt-and-suspenders
// – the spec-indent filter already excludes dep lines). A platform-qualified version (e.g.
// "1.15.0-x86_64-linux") has no space and is taken verbatim.
func parseGemSpec(line string) (name, version string, ok bool) {
	open := strings.IndexByte(line, '(')
	if open <= 0 || !strings.HasSuffix(line, ")") {
		return "", "", false
	}
	name = strings.TrimSpace(line[:open])
	version = strings.TrimSpace(line[open+1 : len(line)-1])
	if name == "" || version == "" || strings.ContainsAny(version, " ,") {
		return "", "", false
	}
	return name, version, true
}

// gemDevGems reads the companion Gemfile (if present) and returns the set of gems scoped development/test:
// those declared inside a `group:development`/`:test do … end` block, or on a `gem` line carrying an
// inline `group:`/`groups:`:development/:test option. Best-effort – no Gemfile (or unreadable) → no dev
// refinement. A balanced block stack (do-blocks + if/unless/case/begin) tracks nesting so the matching
// `end` pops the right block; a gem is dev when any enclosing block is a dev group.
func gemDevGems(dir string) map[string]bool {
	dev := map[string]bool{}
	if dir == "" {
		return dev
	}
	content, ok := readManifestFile(filepath.Join(dir, "Gemfile"))
	if !ok {
		return dev
	}
	var stack []bool // one entry per open block; true = it is a dev group
	devDepth := 0    // count of enclosing dev-group blocks
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i]) // strip a trailing comment
		}
		switch {
		case line == "end":
			if n := len(stack); n > 0 {
				if stack[n-1] {
					devDepth--
				}
				stack = stack[:n-1]
			}
		case opensBlock(line):
			isDev := strings.HasPrefix(line, "group") && groupIsDev(line)
			stack = append(stack, isDev)
			if isDev {
				devDepth++
			}
		case strings.HasPrefix(line, "gem "):
			if name := gemQuotedName(line); name != "" && (devDepth > 0 || groupIsDev(line)) {
				dev[name] = true
			}
		}
	}
	return dev
}

// opensBlock reports whether a Gemfile line opens a block that a later `end` closes: a do-block (`… do` or
// the block-arg form `… do |x|`) or a keyword block (if/unless/case/while/until at the START of the line, or
// a bare `begin`). It deliberately does NOT match the one-line modifier form `gem "x" if cond` (where the
// keyword is mid-line and there is no `end`).
func opensBlock(line string) bool {
	if strings.HasSuffix(line, " do") || (strings.Contains(line, " do |") && strings.HasSuffix(line, "|")) {
		return true
	}
	for _, kw := range []string{"if ", "unless ", "case ", "while ", "until "} {
		if strings.HasPrefix(line, kw) {
			return true
		}
	}
	return line == "begin"
}

// groupIsDev reports whether a `group …`/`gem … group(s): …` line names the:development or:test group.
func groupIsDev(line string) bool {
	return strings.Contains(line, ":development") || strings.Contains(line, ":test")
}

// gemQuotedName extracts the gem name from a `gem "name"` / `gem 'name'` line (the first quoted token).
func gemQuotedName(line string) string {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "gem"))
	if rest == "" {
		return ""
	}
	q := rest[0]
	if q != '"' && q != '\'' {
		return ""
	}
	if end := strings.IndexByte(rest[1:], q); end >= 0 {
		return rest[1 : 1+end]
	}
	return ""
}
