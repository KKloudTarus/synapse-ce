// Package taintrules loads an operator-provided custom taint-rule file (Semgrep-style user rules) into the
// pure-domain taint.CustomRules type. Read-only, bounded, fail-closed on a malformed document.
package taintrules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

const maxRulesBytes = 1 << 20 // a rule file is small; cap defensively

// Load reads the custom taint-rule YAML at path. found=false only when the path is EMPTY (no custom rules
// configured), so the caller uses the built-in catalog. A configured path that is missing, unreadable,
// malformed, or invalid is an error, never a silently-empty ruleset, so an operator sees the mistake rather
// than losing the rules they intended to load.
func Load(path string) (taint.CustomRules, bool, error) {
	data, found, err := readRules(path)
	if err != nil || !found {
		return taint.CustomRules{}, found, err
	}
	rules, err := LoadBytes(data)
	if err != nil {
		return taint.CustomRules{}, true, fmt.Errorf("%s: %w", path, err)
	}
	return rules, true, nil
}

// LoadBytes parses and validates one bounded rule document. It rejects a multi-document file: a trailing
// YAML document (after a `---`) would otherwise be silently ignored, dropping the rules an operator wrote
// there.
func LoadBytes(data []byte) (taint.CustomRules, error) {
	var rules taint.CustomRules
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a misspelled key is an error, not a silently-dropped rule
	if err := dec.Decode(&rules); err != nil {
		return taint.CustomRules{}, fmt.Errorf("parse custom taint rules: %w", err)
	}
	var extra taint.CustomRules
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return taint.CustomRules{}, fmt.Errorf("custom taint rules must be a single YAML document")
	}
	if err := rules.Validate(); err != nil {
		return taint.CustomRules{}, err
	}
	return rules, nil
}

func readRules(path string) ([]byte, bool, error) {
	if path == "" {
		return nil, false, nil // no custom-rules file configured
	}
	// A path IS configured, so the file must exist: a missing file is an operator error, not a silent
	// fall-back to built-ins that would drop the rules they intended to load.
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, false, fmt.Errorf("stat custom taint rules %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxRulesBytes {
		return nil, false, fmt.Errorf("%s is not a regular rule file within %d bytes", path, maxRulesBytes)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-provided config path, regular + size-capped above
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	return data, true, nil
}
