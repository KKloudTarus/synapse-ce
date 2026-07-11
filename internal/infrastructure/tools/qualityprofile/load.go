// Package qualityprofile loads the .synapse-gate.yaml (quality gate) and .synapse-rules.yaml (rule
// profile) config files into the pure-domain qualitygate types. Read-only, bounded.
package qualityprofile

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
)

// strictUnmarshal decodes YAML rejecting unknown fields, so a misspelled top-level key (e.g. `condition:`
// instead of `conditions:`) is an error rather than a silently-empty struct that could bypass the gate.
func strictUnmarshal(data []byte, into any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(into)
}

const maxConfigBytes = 1 << 20 // a gate/profile file is small; cap defensively

// LoadGate reads a quality-gate YAML file. found=false when the path is empty or the file does not exist
// (the caller then uses qualitygate.Default()). A present-but-malformed file is an error.
func LoadGate(path string) (qualitygate.Gate, bool, error) {
	data, found, err := readConfig(path)
	if err != nil || !found {
		return qualitygate.Gate{}, found, err
	}
	var g qualitygate.Gate
	if err := strictUnmarshal(data, &g); err != nil {
		return qualitygate.Gate{}, true, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := g.Validate(); err != nil {
		return qualitygate.Gate{}, true, fmt.Errorf("invalid gate %s: %w", path, err)
	}
	return g, true, nil
}

// LoadProfile reads a rule-profile YAML file. found=false when the path is empty or the file is absent.
func LoadProfile(path string) (qualitygate.Profile, bool, error) {
	data, found, err := readConfig(path)
	if err != nil || !found {
		return qualitygate.Profile{}, found, err
	}
	var p qualitygate.Profile
	if err := strictUnmarshal(data, &p); err != nil {
		return qualitygate.Profile{}, true, fmt.Errorf("parse %s: %w", path, err)
	}
	return p, true, nil
}

func readConfig(path string) ([]byte, bool, error) {
	if path == "" {
		return nil, false, nil
	}
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxConfigBytes {
		return nil, false, fmt.Errorf("%s is not a regular config file within %d bytes", path, maxConfigBytes)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-provided config path, regular + size-capped above
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	return data, true, nil
}
