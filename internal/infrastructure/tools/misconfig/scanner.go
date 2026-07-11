// Package misconfig is an owned, deterministic infrastructure-as-code / config scanner over a prepared
// workspace. It flags insecure settings in Dockerfiles, Kubernetes manifests, Helm charts (rendered via
// `helm template`), Terraform (HCL), and CloudFormation (YAML/JSON) with first-party Go checks – no
// external policy engine (no OPA/Rego). Explicit-insecure settings are flagged as high/medium; recommended-hardening that is absent
// (KSV/CIS/tfsec baseline: runAsNonRoot, dropped capabilities, encryption, resource limits, ...) is
// flagged as low/medium, so coverage matches comprehensive scanners while the highs stay legible.
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
	helmBin  string           // `helm` binary for rendering Helm charts
	helmRun  ports.ToolRunner // sandbox runner for helm (API path); nil = not sandboxed
	helmDir  bool             // allow a direct host exec of helm (trusted-local CLI only)
}

var _ ports.MisconfigScanner = (*Scanner)(nil)

// New returns a scanner with the default configuration. Helm rendering is OFF by default (no runner, not
// trusted-local): `helm template` executes an untrusted chart, so a caller must opt in with WithHelmRunner
// (sandboxed, for the API) or WithHelmDirect (direct exec, for the trusted-local CLI).
func New() *Scanner {
	return &Scanner{
		skipDirs: set(".git", "node_modules", "vendor", "dist", "build", "target", ".idea",
			".gradle", ".venv", "venv", "__pycache__", "bin"),
		helmBin: "helm",
	}
}

// WithHelmRunner enables Helm chart rendering confined by the given ToolRunner (the SCA sandbox), so
// `helm template` never runs unprotected on the host. Use this in the API path.
func (s *Scanner) WithHelmRunner(r ports.ToolRunner) *Scanner { s.helmRun = r; return s }

// WithHelmDirect enables Helm chart rendering via a direct host exec – ONLY for a trusted-local caller
// (the CLI), mirroring how the CLI runs the maven/gradle resolvers unsandboxed on a trusted project.
func (s *Scanner) WithHelmDirect() *Scanner { s.helmDir = true; return s }

// Name identifies the source on findings.
func (s *Scanner) Name() string { return "synapse-misconfig" }

// configKind is the recognised config-file type for a path.
type configKind int

const (
	cfgNone configKind = iota
	cfgDockerfile
	cfgKubernetes
	cfgTerraform
	cfgCloudFormation
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
		// A Helm chart (Chart.yaml) is rendered as a whole via `helm template` and its output scanned with
		// the Kubernetes rules – the raw templates carry Go-template directives and are not valid YAML.
		// Skip a Chart.yaml bundled under a parent chart's charts/ dir (the parent render covers the subchart).
		if d.Name() == "Chart.yaml" {
			if !strings.Contains(path, string(os.PathSeparator)+"charts"+string(os.PathSeparator)) && count < maxFiles {
				count++
				relDir := strings.TrimPrefix(strings.TrimPrefix(filepath.Dir(path), root), string(os.PathSeparator))
				out = append(out, scanHelmChart(ctx, s.helmRun, s.helmDir, s.helmBin, filepath.Dir(path), relDir)...)
			}
			return nil
		}
		kind := classifyName(d.Name())
		if kind == cfgNone && !maybeYAML(d.Name()) && !maybeCFN(d.Name()) {
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
			// Decide by content: a Kubernetes manifest declares apiVersion + kind; a CloudFormation
			// template declares AWSTemplateFormatVersion or a Resources map of AWS:: types.
			switch {
			case looksKubernetes(data):
				kind = cfgKubernetes
			case looksCloudFormation(data):
				kind = cfgCloudFormation
			default:
				return nil
			}
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(path, root), string(os.PathSeparator))
		switch kind {
		case cfgDockerfile:
			out = append(out, scanDockerfile(rel, data)...)
		case cfgKubernetes:
			out = append(out, scanKubernetes(rel, data)...)
		case cfgTerraform:
			out = append(out, scanTerraform(rel, data)...)
		case cfgCloudFormation:
			out = append(out, scanCloudFormation(rel, data)...)
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
	if strings.HasSuffix(strings.ToLower(name), ".tf") {
		return cfgTerraform
	}
	return cfgNone
}

func maybeYAML(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}

// maybeCFN lets a .json or .template file through to the content sniff, since CloudFormation templates
// are commonly written in either (YAML .yaml/.yml is already covered by maybeYAML).
func maybeCFN(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".json" || ext == ".template"
}

// looksKubernetes is a cheap pre-filter so we only parse YAML that declares a Kubernetes object, not
// every CI/compose/config YAML in the tree. It matches the YAML form `apiVersion:` (colon-attached), so a
// JSON-authored manifest (`"apiVersion":`) is intentionally not treated as Kubernetes here.
func looksKubernetes(data []byte) bool {
	t := string(data)
	return strings.Contains(t, "apiVersion:") && strings.Contains(t, "kind:")
}

// looksCloudFormation is a cheap pre-filter for a CloudFormation template: it declares the format version
// or a Resources map whose entries carry AWS:: types. Specific enough to skip an ordinary JSON/YAML file.
func looksCloudFormation(data []byte) bool {
	t := string(data)
	return strings.Contains(t, "AWSTemplateFormatVersion") || (strings.Contains(t, "Resources") && strings.Contains(t, "AWS::"))
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
