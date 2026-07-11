// Package grype is a DetectionSource that augments OSV. It feeds the
// EXISTING Syft SBOM to a pinned Grype binary (argv, no shell; no repository
// re-discovery, preserving reproducibility) and maps the matches to raw findings
// for correlation. It is best-effort: a missing binary or vulnerability DB
// degrades to "no contribution" rather than failing the scan.
package grype

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Source runs Grype against a Syft SBOM. bin is the pinned executable (path/name).
type Source struct {
	bin    string
	dbDir  string           // pre-synced vulnerability DB cache dir; "" = Grype's default
	runner ports.ToolRunner // optional; when set, Grype runs inside the sandbox

	mu        sync.Mutex
	version   string // grype binary version (from the scan descriptor)
	dbVersion string // vulnerability DB build/schema (reproducibility)
}

// WithRunner runs Grype through a ToolRunner (the SandboxRunner) – confining the match
// against a pre-synced DB (read-only FS, no network, dropped caps).
// Grype is offline (pinned DB, auto-update off), so the isolated sandbox fits and the
// findings are unchanged. nil keeps the direct exec.
func (s *Source) WithRunner(r ports.ToolRunner) *Source { s.runner = r; return s }

// New returns a Grype detection source using the given binary (defaults to "grype").
// dbDir, when set, pins the vulnerability DB to a pre-synced cache directory and
// disables auto-update – so scans run offline against a fixed DB build and are
// reproducible (the DB version is still captured as evidence). Empty = Grype's
// default (online auto-update).
func New(bin, dbDir string) *Source {
	if strings.TrimSpace(bin) == "" {
		bin = "grype"
	}
	return &Source{bin: bin, dbDir: strings.TrimSpace(dbDir)}
}

var (
	_ ports.DetectionSource  = (*Source)(nil)
	_ ports.SourceProvenance = (*Source)(nil)
)

// Name identifies this detection source.
func (*Source) Name() string { return "grype" }

// Provenance reports the Grype binary + vulnerability-DB version used by the most
// recent successful scan (empty if Grype did not run).
func (s *Source) Provenance() (version, dbVersion string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version, s.dbVersion
}

// Scan writes the SBOM to a temp CycloneDX file and runs `grype sbom:<file>`.
// Best-effort: a missing binary or DB returns no findings + nil error so the scan
// continues with OSV only (regression: missing Grype degrades gracefully).
func (s *Source) Scan(ctx context.Context, doc *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	if doc == nil || len(doc.Components) == 0 {
		return nil, nil
	}
	path, cleanup, err := writeCycloneDX(doc)
	if err != nil {
		return nil, nil // cannot stage the SBOM – degrade, don't fail the scan
	}
	defer cleanup()

	stdout, ok := s.run(ctx, path)
	if !ok {
		// Missing binary or a DB/runtime error: record Grype unavailable + contribute
		// nothing – the scan still succeeds (graceful degrade, regression-preserving).
		s.setProvenance("", "")
		return nil, nil
	}

	var out grypeOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		s.setProvenance("", "")
		return nil, nil // malformed output – degrade
	}
	s.setProvenance(out.Descriptor.Version, out.dbLabel())

	componentsByPURL := componentsByPURL(doc.Components)
	raws := make([]vulnerability.RawFinding, 0, len(out.Matches))
	for _, m := range out.Matches {
		if m.Artifact.Name == "" {
			continue
		}
		raws = append(raws, matchToRaw(m, componentsByPURL))
	}
	return raws, nil
}

func componentsByPURL(comps []sbom.Component) map[string]sbom.Component {
	out := make(map[string]sbom.Component, len(comps))
	for _, c := range comps {
		if c.PURL != "" {
			out[c.PURL] = c
		}
	}
	return out
}

// run executes Grype (sandboxed when a runner is set, else direct) and returns its stdout
// + whether it ran. The GRYPE_DB_* pins make it offline + reproducible.
func (s *Source) run(ctx context.Context, sbomPath string) ([]byte, bool) {
	args := []string{"sbom:" + sbomPath, "-o", "json", "-q"}
	var env []string
	if s.dbDir != "" {
		env = []string{"GRYPE_DB_CACHE_DIR=" + s.dbDir, "GRYPE_DB_AUTO_UPDATE=false", "GRYPE_DB_VALIDATE_AGE=false"}
	}
	if s.runner != nil {
		// Sandboxed: the SBOM lives under /tmp (masked by the sandbox tmpfs), so bind its
		// dir read-only. The pre-synced vulnerability DB (F2: the sandbox no longer binds
		// the whole host root, and the DB lives under $HOME/.cache which is NOT bound) must
		// also be bound read-only explicitly. GRYPE_DB_* reach Grype via the controlled env.
		ro := []string{filepath.Dir(sbomPath)}
		if s.dbDir != "" {
			ro = append(ro, s.dbDir)
		}
		res, err := s.runner.Run(ctx, ports.ToolSpec{Name: s.bin, Args: args, Env: env, ReadOnlyPaths: ro})
		if err != nil || res.ExitCode != 0 {
			return nil, false
		}
		return res.Stdout, true
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, s.bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	if err := cmd.Run(); err != nil {
		return nil, false
	}
	return stdout.Bytes(), true
}

func (s *Source) setProvenance(version, dbVersion string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version, s.dbVersion = version, dbVersion
}

// ---- CycloneDX staging (consume the existing SBOM; no re-discovery) ----

type cdxBOM struct {
	BomFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Components  []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
}

// writeCycloneDX stages the SBOM for Grype: the generator's original CycloneDX
// when available (faithful, lossless), else a minimal reconstruction from the
// parsed components (PURL-matched) as a fallback.
func writeCycloneDX(doc *sbom.SBOM) (path string, cleanup func(), err error) {
	data := doc.Raw
	if len(data) == 0 {
		bom := cdxBOM{BomFormat: "CycloneDX", SpecVersion: "1.5", Version: 1}
		for _, c := range doc.Components {
			if c.PURL == "" {
				continue // grype matches by PURL/CPE; un-purled entries cannot match
			}
			bom.Components = append(bom.Components, cdxComponent{Type: "library", Name: c.Name, Version: c.Version, PURL: c.PURL})
		}
		data, err = json.Marshal(bom)
		if err != nil {
			return "", func() {}, err
		}
	}
	// A dedicated dir (not a bare /tmp file) so the sandbox can bind ONLY the SBOM
	// read-only without re-exposing the rest of the host's /tmp.
	dir, err := os.MkdirTemp("", "synapse-grype-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	path = filepath.Join(dir, "sbom.cdx.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

// ---- Grype JSON output ----

type grypeOutput struct {
	Matches    []grypeMatch `json:"matches"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		DB      struct {
			// Grype >= 0.9x nests DB metadata under "status"; older builds had it flat.
			Built         string `json:"built"`
			SchemaVersion any    `json:"schemaVersion"`
			Status        struct {
				Built         string `json:"built"`
				SchemaVersion any    `json:"schemaVersion"`
			} `json:"status"`
		} `json:"db"`
	} `json:"descriptor"`
}

// dbLabel is a reproducibility marker for the vulnerability DB used.
func (d grypeOutput) dbLabel() string {
	built := d.Descriptor.DB.Status.Built
	if built == "" {
		built = d.Descriptor.DB.Built
	}
	schema := stringifySchema(d.Descriptor.DB.Status.SchemaVersion)
	if schema == "" {
		schema = stringifySchema(d.Descriptor.DB.SchemaVersion)
	}
	if built == "" && schema == "" {
		return ""
	}
	return fmt.Sprintf("schema-%s@%s", schema, built)
}

// stringifySchema renders a schema version that may be a string ("v6.1.7") or a
// number (older grype) as a stable string.
func stringifySchema(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%d", int(t))
	default:
		return ""
	}
}

type grypeMatch struct {
	Vulnerability struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Fix         struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
		CVSS []struct {
			Vector  string `json:"vector"`
			Metrics struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"metrics"`
		} `json:"cvss"`
	} `json:"vulnerability"`
	RelatedVulnerabilities []struct {
		ID string `json:"id"`
	} `json:"relatedVulnerabilities"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"artifact"`
}

func matchToRaw(m grypeMatch, components map[string]sbom.Component) vulnerability.RawFinding {
	aliases := []string{m.Vulnerability.ID}
	for _, rel := range m.RelatedVulnerabilities {
		aliases = append(aliases, rel.ID)
	}
	componentName := m.Artifact.Name
	componentVersion := m.Artifact.Version
	if c, ok := components[m.Artifact.PURL]; ok {
		componentName = c.Name
		if c.Version != "" {
			componentVersion = c.Version
		}
	}
	r := vulnerability.RawFinding{
		Source:      "grype",
		AdvisoryID:  preferCVE(m.Vulnerability.ID, aliases),
		Aliases:     aliases,
		Component:   componentName,
		Version:     componentVersion,
		Severity:    mapSeverity(m.Vulnerability.Severity),
		Description: m.Vulnerability.Description,
	}
	for _, c := range m.Vulnerability.CVSS {
		if c.Metrics.BaseScore > r.CVSSScore {
			r.CVSSScore = c.Metrics.BaseScore
			r.CVSSVector = c.Vector
		}
	}
	r.FixState = m.Vulnerability.Fix.State // fixed / not-fixed / wont-fix / unknown – drives --ignore-unfixed
	if m.Vulnerability.Fix.State == "fixed" && len(m.Vulnerability.Fix.Versions) > 0 {
		r.FixedVersion = m.Vulnerability.Fix.Versions[0]
	}
	return r
}

func mapSeverity(s string) shared.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return shared.SeverityCritical
	case "high":
		return shared.SeverityHigh
	case "medium":
		return shared.SeverityMedium
	case "low":
		return shared.SeverityLow
	case "negligible":
		return shared.SeverityInfo
	default:
		return shared.SeverityUnknown
	}
}

func preferCVE(id string, aliases []string) string {
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			return a
		}
	}
	return id
}
