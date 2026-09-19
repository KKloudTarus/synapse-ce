// Package benchid records the identity of the benchmark-only competitor tools used in the owned-vs-competitor
// differentials, so a head-to-head is reproducible. The committed manifest pins each competitor's version and
// ruleset; a differential captures the tool's actually-reported version at runtime and logs it against the
// pinned value. Competitors are comparison data only and never gate a build, so a version mismatch is recorded,
// never fatal. This closes the #1040 acceptance criterion "competitor version/ruleset/database identity and
// known scope differences are recorded for every differential": the identity is committed here rather than
// living only in a run log or an issue comment.
package benchid

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ManifestSchema tags the committed manifest so it is never read under an incompatible shape.
const ManifestSchema = "synapse-competitor-identity-v1"

// Identity is one competitor tool's pinned benchmark identity.
type Identity struct {
	Version    string `json:"version"`
	Ruleset    string `json:"ruleset"`
	Source     string `json:"source"`
	Dimension  string `json:"dimension"`
	ScopeNotes string `json:"scope_notes"`
}

// Manifest is the committed set of competitor identities, keyed by tool name (as invoked on PATH).
type Manifest struct {
	Schema      string              `json:"schema"`
	Note        string              `json:"note"`
	Competitors map[string]Identity `json:"competitors"`
}

// Load reads and validates the committed competitor-identity manifest at path.
func Load(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read competitor-identity manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("decode competitor-identity manifest: %w", err)
	}
	if m.Schema != ManifestSchema {
		return Manifest{}, fmt.Errorf("competitor-identity manifest schema %q, want %q", m.Schema, ManifestSchema)
	}
	return m, nil
}

// Expected returns the pinned identity for a tool, and whether it is recorded.
func (m Manifest) Expected(tool string) (Identity, bool) {
	id, ok := m.Competitors[tool]
	return id, ok
}

// VersionMatches reports whether a tool's version banner names exactly the pinned version. It tokenizes the
// banner (competitors print forms like "gitleaks 8.30.1", "v8.30.1", or a bare "3.3.19") and requires a token to
// equal pinned, optionally past a leading "v". This is deliberately exact per token rather than a substring test:
// a substring check would treat observed "3.3.19" as matching pinned "3.3.1" and hide a genuine drift.
func VersionMatches(observed, pinned string) bool {
	if pinned == "" {
		return false
	}
	fields := strings.FieldsFunc(observed, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == '(' || r == ')' || r == '"' || r == '\r'
	})
	for _, f := range fields {
		if f == pinned || strings.TrimPrefix(f, "v") == pinned {
			return true
		}
	}
	return false
}

// CaptureVersion runs the tool's version command and returns the first non-empty trimmed line, so a differential
// can record which competitor build actually produced its numbers. It is bounded so a hung binary cannot stall
// the suite. An error (tool absent, version subcommand changed) returns "" and the error for the caller to log;
// a differential treats that as "identity unrecorded", never as a build failure.
func CaptureVersion(ctx context.Context, bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("capture %s version: %w", bin, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s, nil
		}
	}
	return "", nil
}
