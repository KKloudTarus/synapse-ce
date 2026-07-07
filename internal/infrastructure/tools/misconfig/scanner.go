// Package misconfig is an owned, deterministic infrastructure-as-code / config scanner over a prepared
// workspace. It flags insecure Dockerfile and Kubernetes-manifest settings with first-party Go checks —
// no external policy engine (no OPA/Rego) and no network. Checks are chosen to be high-signal and
// low-false-positive: a rule fires only on an explicit insecure setting, never on an unset default.
//
// It is READ-ONLY: it classifies files by name/content, parses them, and returns located findings. A
// parse or read error is a per-file skip, never a scan failure. Results become ungated Kind=misconfig
// findings (deterministic, publishable like SCA).
package misconfig

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxFiles     = 50000   // bound the number of config files scanned
	maxEntries   = 1000000 // bound the total tree entries walked (huge non-config tree DoS guard)
	maxFileBytes = 5 << 20 // skip files larger than 5 MiB (manifests are small)
	sniffBytes   = 8 << 10 // read this much to decide binary-or-text
	maxValueLen  = 256     // cap an untrusted config value embedded in a finding
)

// Scanner implements ports.MisconfigScanner with an owned ruleset.
type Scanner struct {
	skipDirs map[string]bool
}

var _ ports.MisconfigScanner = (*Scanner)(nil)

// New returns a scanner with the default configuration.
func New() *Scanner {
	return &Scanner{
		skipDirs: set(".git", "node_modules", "vendor", "dist", "build", "target", ".idea",
			".gradle", ".venv", "venv", "__pycache__", "bin"),
	}
}

// Name identifies the source on findings.
func (s *Scanner) Name() string { return "synapse-misconfig" }

// configKind is the recognised config-file type for a path.
type configKind int

const (
	cfgNone configKind = iota
	cfgDockerfile
	cfgKubernetes
)

// ScanConfigs walks root, classifies each regular file, and returns located misconfig findings.
// Best-effort: an unreadable or unparsable file is skipped.
func (s *Scanner) ScanConfigs(ctx context.Context, root string) ([]ports.MisconfigRawFinding, error) {
	var out []ports.MisconfigRawFinding
	count := 0  // config files actually scanned
	walked := 0 // total tree entries visited
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		walked++
		if walked > maxEntries {
			return filepath.SkipAll // a pathologically large tree: stop walking regardless of file type
		}
		if d.IsDir() {
			if s.skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Only read regular files: never follow a symlink out of the (untrusted) workspace, so a planted
		// link cannot pull an out-of-root file into the scan.
		if !d.Type().IsRegular() {
			return nil
		}
		kind := classifyName(d.Name())
		if kind == cfgNone && !maybeYAML(d.Name()) {
			return nil
		}
		if count >= maxFiles {
			return filepath.SkipAll
		}
		count++
		info, e := d.Info()
		if e != nil || info.Size() == 0 || info.Size() > maxFileBytes {
			return nil
		}
		data, e := os.ReadFile(path)
		if e != nil || isBinary(data) {
			return nil
		}
		if kind == cfgNone {
			// A .yaml/.yml file is only a Kubernetes manifest if it declares apiVersion + kind.
			if !looksKubernetes(data) {
				return nil
			}
			kind = cfgKubernetes
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(path, root), string(os.PathSeparator))
		switch kind {
		case cfgDockerfile:
			out = append(out, scanDockerfile(rel, data)...)
		case cfgKubernetes:
			out = append(out, scanKubernetes(rel, data)...)
		}
		return nil
	})
	if walkErr != nil {
		return out, fmt.Errorf("misconfig scan: %w", walkErr) // e.g. context cancellation
	}
	return out, nil
}

// classifyName recognises a Dockerfile by conventional names; YAML is decided later by content.
func classifyName(name string) configKind {
	if name == "Dockerfile" || name == "Containerfile" ||
		strings.HasPrefix(name, "Dockerfile.") ||
		strings.HasSuffix(strings.ToLower(name), ".dockerfile") {
		return cfgDockerfile
	}
	return cfgNone
}

func maybeYAML(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}

// looksKubernetes is a cheap pre-filter so we only parse YAML that declares a Kubernetes object, not
// every CI/compose/config YAML in the tree.
func looksKubernetes(data []byte) bool {
	t := string(data)
	return strings.Contains(t, "apiVersion:") && strings.Contains(t, "kind:")
}

func isBinary(data []byte) bool {
	n := len(data)
	if n > sniffBytes {
		n = sniffBytes
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

// clip bounds an untrusted config value before it is embedded in a finding, so a crafted manifest or
// Dockerfile cannot push a multi-MB string into the finding, the hash-chained evidence seal, or the
// report. It trims to a whole-UTF-8 boundary so the finding text stays valid.
func clip(s string) string {
	if len(s) <= maxValueLen {
		return s
	}
	return strings.ToValidUTF8(s[:maxValueLen], "") + "…"
}
