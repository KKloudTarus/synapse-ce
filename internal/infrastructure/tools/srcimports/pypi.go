package srcimports

import (
	"context"
	"strings"
)

// pypiDirectDependencies reads a Python project's DECLARATION manifests — pyproject.toml (PEP 621
// `[project]` and Poetry `[tool.poetry.*]`) and Pipfile — for the packages the project declares DIRECTLY,
// and reports whether any such manifest was found. It deliberately does NOT read requirements.txt or any
// lockfile: a `pip freeze` / `pip-compile` requirements.txt enumerates the fully-resolved graph (direct AND
// transitive), so trusting it would let a transitive package be treated as direct — and a transitive package
// that first-party code never imports would then be marked not-reachable and its finding suppressed. Only a
// declaration manifest reliably lists direct-only dependencies, and under-inclusion is safe (a missed direct
// dep is merely refused, never falsely answered), so those are the only sources.
func pypiDirectDependencies(ctx context.Context, dir string) (map[string]bool, bool) {
	limits := defaultScanLimits()
	out := map[string]bool{}
	found := false
	if content, ok := readBoundedFile(ctx, dir, "pyproject.toml", limits.maxFileBytes); ok {
		found = true
		for name := range pyprojectDirectDependencies(string(content)) {
			out[name] = true
		}
	}
	if content, ok := readBoundedFile(ctx, dir, "Pipfile", limits.maxFileBytes); ok {
		found = true
		for name := range pipfileTableDependencies(string(content)) {
			out[name] = true
		}
	}
	if !found {
		return nil, false
	}
	return out, true
}

// pyprojectDirectDependencies extracts the ALWAYS-INSTALLED main dependency names from a pyproject.toml: the
// PEP 621 `[project]` `dependencies = [...]` array of PEP 508 strings and the Poetry
// `[tool.poetry.dependencies]` table of `name = ...` entries. It deliberately excludes
// `[project.optional-dependencies]` extras, Poetry groups, and dev groups: whether an extra/group is
// installed is not knowable here, so trusting one could treat a package that is only present transitively
// (via a main dependency) as direct and let its finding be wrongly suppressed. Under-inclusion is safe (a
// missed direct dep is merely refused), so only the unconditional main table is trusted. Line-oriented and
// conservative — an unrecognized line is skipped, never guessed into the direct set.
func pyprojectDirectDependencies(body string) map[string]bool {
	pep621 := map[string]bool{}
	poetry := map[string]bool{}
	hasProject := false  // a `[project]` (PEP 621) table is present anywhere in the file
	var section []string // current section as its unquoted key-segment path
	inArray := false     // inside the PEP 621 `[project]` dependencies array
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(stripTOMLComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = normalizeSection(line)
			if len(section) >= 1 && section[0] == "project" {
				hasProject = true
			}
			inArray = false
			continue
		}
		switch {
		case len(section) == 1 && section[0] == "project":
			// dependencies = [ "flask>=2", ... ]  (possibly multi-line). optional-dependencies is NOT read.
			// The array bracket is detected OUTSIDE quoted strings, so a "]" inside an extras spec like
			// "flask[async]" is not mistaken for the array closer. The key may be quoted ("dependencies").
			if key, val, ok := cutTOMLKey(line); ok && unquoteKey(key) == "dependencies" && strings.Contains(stripQuoted(val), "[") {
				collectRequirementStrings(val, pep621)
				inArray = !strings.Contains(stripQuoted(val), "]")
				continue
			}
			if inArray {
				collectRequirementStrings(line, pep621)
				if strings.Contains(stripQuoted(line), "]") {
					inArray = false
				}
			}
		case isPoetryMainDepsSection(section): // main group only; [tool.poetry.group.*] excluded
			if key, val, ok := cutTOMLKey(line); ok && !conditionalDependencyValue(val) {
				if name := keyToDistribution(key); name != "" && name != "python" {
					poetry[strings.ToLower(name)] = true
				}
			}
		}
	}
	// Poetry 2: when a `[project]` table is present it is authoritative for dependencies;
	// `[tool.poetry.dependencies]` then only ENRICHES those entries (source, python-specific constraints) and
	// adds nothing — a package present only in the Poetry table is a constraint on a transitive, NOT a project
	// direct dependency, so it must not be trusted. Only when there is no `[project]` table at all (Poetry
	// 1.x) is the Poetry table the source of direct dependencies. (A `[project]` using PEP 621 `dynamic`
	// dependencies yields an empty set here — under-inclusion, which is safe — rather than trusting the table.)
	if hasProject {
		return pep621
	}
	return poetry
}

// normalizeSection turns a TOML section header line `[a.b.c]` into its ordered key SEGMENTS, each unquoted:
// `["project"]` → ["project"], `[tool."poetry".dependencies]` → ["tool","poetry","dependencies"], and
// `[project.optional-dependencies]` → ["project","optional-dependencies"]. The split on `.` happens OUTSIDE
// quotes, so a quoted segment that itself contains a `.` stays a single segment — `[tool."poetry.dependencies"]`
// → ["tool","poetry.dependencies"], which is NOT the Poetry table. Callers compare the segment list
// structurally (never a rejoined string), so a quoted-dotted segment can never be confused with a real path.
func normalizeSection(header string) []string {
	inner := strings.TrimSpace(header)
	inner = strings.TrimPrefix(inner, "[")
	inner = strings.TrimSuffix(inner, "]")
	var segs []string
	var bare, quoted strings.Builder // bare text (trimmed at flush) vs a quoted interior (verbatim)
	hadQuote := false
	var quote byte
	flush := func() {
		// A TOML dotted-key segment is either a bare word (surrounding whitespace insignificant → trim) or a
		// quoted string (interior significant, e.g. `" poetry "` is the key " poetry ", NOT "poetry"). Keeping
		// the quoted interior verbatim stops a spaced/odd quoted segment from matching a real path segment.
		if hadQuote {
			segs = append(segs, quoted.String())
		} else {
			segs = append(segs, strings.TrimSpace(bare.String()))
		}
		bare.Reset()
		quoted.Reset()
		hadQuote = false
	}
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				quoted.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
			hadQuote = true
		case c == '.':
			flush()
		default:
			bare.WriteByte(c)
		}
	}
	flush()
	return segs
}

// isPoetryMainDepsSection reports whether a section's segments are exactly [tool, poetry, dependencies] — the
// main Poetry dependency table. Comparing segments (not a rejoined path) keeps `[tool."poetry.dependencies"]`
// (segments ["tool","poetry.dependencies"], an unrelated table) from matching.
func isPoetryMainDepsSection(section []string) bool {
	return len(section) == 3 && section[0] == "tool" && section[1] == "poetry" && section[2] == "dependencies"
}

// unquoteKey strips a single pair of surrounding matching quotes from a TOML key.
func unquoteKey(k string) string {
	k = strings.TrimSpace(k)
	if len(k) >= 2 && (k[0] == '"' || k[0] == '\'') && k[len(k)-1] == k[0] {
		return k[1 : len(k)-1]
	}
	return k
}

// pipfileTableDependencies reads a Pipfile's `[packages]` table, whose keys are the project's always-installed
// direct dependencies (`name = "*"` / `name = {version = "..."}`). `[dev-packages]` is excluded for the same
// reason optional/dev groups are in pyproject.toml: a dev dependency is not part of the shipped closure, and
// trusting one could treat a transitively-present package as direct.
func pipfileTableDependencies(body string) map[string]bool {
	out := map[string]bool{}
	var section []string
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(stripTOMLComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = normalizeSection(line)
			continue
		}
		if !(len(section) == 1 && section[0] == "packages") {
			continue
		}
		if key, val, ok := cutTOMLKey(line); ok && !conditionalDependencyValue(val) {
			if name := keyToDistribution(key); name != "" {
				out[strings.ToLower(name)] = true
			}
		}
	}
	return out
}

// collectRequirementStrings pulls the package name out of every quoted PEP 508 requirement on a line (a
// dependencies-array line may hold several) and adds it to out. A requirement carrying an environment marker
// (a `;` clause, e.g. `urllib3; sys_platform == 'win32'`) is CONDITIONAL — not installed on every target —
// so it is skipped: a conditionally-installed package may still be present transitively via another
// dependency, and treating it as an always-installed direct dep would let its finding be wrongly suppressed.
func collectRequirementStrings(line string, out map[string]bool) {
	for _, q := range quotedStrings(line) {
		if strings.Contains(q, ";") {
			continue // environment marker → conditional install → not a trusted always-installed direct dep
		}
		if name := requirementName(q); name != "" {
			out[strings.ToLower(name)] = true
		}
	}
}

// conditionalDependencyValue reports whether a Poetry/Pipfile dependency value makes the dependency
// CONDITIONAL rather than guaranteed-installed. Only a BARE version string (`"*"`, `"^2.31"`, `">=1,<2"`) is
// trusted as unconditional. Every inline `{ … }` table and `[ … ]` array is treated as conditional, WITHOUT
// parsing it: a table may carry an `optional`/`markers`/environment-marker gate, and reliably parsing TOML's
// full inline-table grammar (quoted keys, `\`-escapes, literal and basic strings, nesting) is error-prone —
// a single missed gate would false-suppress a transitively-present package. Under-inclusion is safe (a
// version-with-extras/git dependency written as a table is simply not answered, never wrongly suppressed), so
// anything that is not a bare version string is conditional. A bare version string cannot express a marker.
func conditionalDependencyValue(value string) bool {
	v := strings.TrimSpace(value)
	return v == "" || strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[")
}

// requirementName returns the leading distribution name of a PEP 508 requirement or a bare key, stopping at
// the first version specifier, extras bracket, environment marker, or whitespace. It rejects (returns "") a
// URL, VCS, path, or option string — anything that is not a plain distribution reference — so a malformed
// manifest line like "git+https://x#egg=foo", "https://x", "./local", or "--extra-index-url ..." can never
// become a fake direct-dependency name. A PEP 508 URL requirement "name @ url" still yields its name (the
// leading token before the space). The name must also start and end with an alphanumeric character.
func requirementName(s string) string {
	s = strings.TrimSpace(s)
	// PEP 508 direct-URL form "name @ url": the name is the token before the "@". Take it first so the
	// URL half (which contains "://") does not cause the whole valid requirement to be rejected below.
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" || strings.Contains(s, "://") {
		return ""
	}
	for _, p := range []string{"-", ".", "/", "git+", "hg+", "svn+", "bzr+"} {
		if strings.HasPrefix(s, p) {
			return ""
		}
	}
	end := len(s)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			continue
		}
		end = i
		break
	}
	name := s[:end]
	if name == "" || !isAlnum(name[0]) || !isAlnum(name[len(name)-1]) {
		return "" // a distribution name starts and ends with an alphanumeric (PEP 503)
	}
	// After the name, a valid PEP 508 requirement continues only with an extras `[`, a version specifier
	// (`(<>=!~`), or nothing (`;` markers and `@` URLs are already handled above). Anything else — e.g. a
	// second word in `requests ignored` — means this is not a plain requirement, so reject it rather than
	// truncate it into a real dependency name that could suppress a transitively-present package.
	if rest := strings.TrimSpace(s[end:]); rest != "" {
		switch rest[0] {
		case '[', '(', '<', '>', '=', '!', '~':
		default:
			return ""
		}
	}
	return name
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// stripQuoted blanks the contents of quoted strings on a line, so structural characters (like the array
// bracket "[" / "]") can be detected without a bracket inside a quoted requirement (e.g. "flask[async]")
// being mistaken for structure.
func stripQuoted(line string) string {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			b.WriteByte(' ')
		case c == '"' || c == '\'':
			quote = c
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// quotedStrings returns the contents of every single- or double-quoted string on a line.
func quotedStrings(line string) []string {
	var out []string
	var quote byte
	start := -1
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote == 0 {
			if c == '"' || c == '\'' {
				quote = c
				start = i + 1
			}
			continue
		}
		if c == quote {
			out = append(out, line[start:i])
			quote = 0
		}
	}
	return out
}

// cutTOMLKey splits a `key = value` TOML line into the RAW (quotes-preserved) key and the value. ok is false
// when the line has no top-level `=`. Quote handling is left to keyToDistribution, which must distinguish a
// quoted literal key from an unquoted (possibly structural) one.
func cutTOMLKey(line string) (key, value string, ok bool) {
	k, v, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}
	return strings.TrimSpace(k), strings.TrimSpace(v), true
}

// keyToDistribution turns a Poetry/Pipfile dependency-table KEY into a distribution name. A KEY is the WHOLE
// package name, so unlike a PEP 508 requirement string it is validated in full (validDistributionName), never
// by leading-token extraction — a key like `"requests ignored"` is NOT the dependency `requests`, and must be
// rejected rather than truncated. A QUOTED key is a literal name (dots allowed: `"zope.interface"`); an
// UNQUOTED key containing a "." is a TOML DOTTED (structural) key, not a package name, and is skipped.
func keyToDistribution(rawKey string) string {
	k := strings.TrimSpace(rawKey)
	if len(k) >= 2 && (k[0] == '"' || k[0] == '\'') && k[len(k)-1] == k[0] {
		k = k[1 : len(k)-1] // quoted literal key content
	} else if strings.Contains(k, ".") {
		return "" // unquoted dotted key is structural TOML, not a dependency name
	}
	if !validDistributionName(k) {
		return ""
	}
	return k
}

// validDistributionName reports whether name is a syntactically valid PEP 503 distribution name: a non-empty
// run of ASCII letters, digits, `-`, `_`, `.` that starts and ends with an alphanumeric. This is a whole-string
// check, so any embedded space, quote, or other character (which would make it not a real package name)
// rejects it — a bogus key can never be truncated into a real dependency name.
func validDistributionName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return isAlnum(name[0]) && isAlnum(name[len(name)-1])
}

// stripTOMLComment removes a trailing `#` comment that is not inside a quoted string.
func stripTOMLComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			return line[:i]
		}
	}
	return line
}
