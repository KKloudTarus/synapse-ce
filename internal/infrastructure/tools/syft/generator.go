// Package syft adapts SBOM generation to the SBOMGenerator port by shelling out
// to a pinned Syft binary. Importing Syft as a library would bloat the
// binary ~150-200 MB and pull in its vuln-DB management, so we exec it via argv.
package syft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// sourceScheme picks Syft's source scheme for a workspace path: an OCI image layout
// (container acquisition produces one via crane) is scanned with `oci-dir:` so Syft reads
// it as an image; a plain source tree is scanned with `dir:`. Both pin the source type and
// stop the path being parsed as a flag.
func sourceScheme(targetRef string) string {
	if _, err := os.Stat(filepath.Join(targetRef, "oci-layout")); err == nil {
		return "oci-dir"
	}
	return "dir"
}

// Generator runs Syft to produce an SBOM. bin is the Syft executable (path or name).
type Generator struct {
	bin    string
	runner ports.ToolRunner // optional; when set, Syft runs inside the sandbox
}

// New returns a generator using the given Syft binary (defaults to "syft" in PATH).
func New(bin string) *Generator {
	if strings.TrimSpace(bin) == "" {
		bin = "syft"
	}
	return &Generator{bin: bin}
}

// WithRunner runs Syft through a ToolRunner (the SandboxRunner) instead of a bare
// os/exec – confining the SBOM scan (read-only FS, no network, dropped caps). Syft is
// offline, so the isolated sandbox is a clean fit and the SBOM output is
// unchanged. nil keeps the direct exec.
func (g *Generator) WithRunner(r ports.ToolRunner) *Generator { g.runner = r; return g }

var _ ports.SBOMGenerator = (*Generator)(nil)

// Generate runs `syft scan dir:<target> -o cyclonedx-json` and maps the result
// to the domain SBOM. argv (no shell); the `dir:` source scheme both pins the
// source type and prevents the path from being parsed as a flag.
func (g *Generator) Generate(ctx context.Context, targetRef string) (*sbom.SBOM, error) {
	out, err := g.run(ctx, targetRef)
	if err != nil {
		return nil, err
	}
	comps, deps, ver, err := parseCycloneDX(out)
	if err != nil {
		return nil, fmt.Errorf("parse sbom: %w", err)
	}
	// Keep the raw CycloneDX so Grype can consume the exact SBOM (not a reconstruction).
	return &sbom.SBOM{TargetRef: targetRef, Source: "syft", GeneratorVersion: ver, Components: comps, Dependencies: deps, Raw: out}, nil
}

// run executes Syft (sandboxed when a runner is set, else direct os/exec) and returns the
// raw CycloneDX bytes. The sandbox does not change argv or output – only how Syft runs.
func (g *Generator) run(ctx context.Context, targetRef string) ([]byte, error) {
	args := []string{"scan", sourceScheme(targetRef) + ":" + targetRef, "-o", "cyclonedx-json", "-q"}
	if g.runner != nil {
		// Isolated sandbox: bind the target dir read-only (the acquired workspace usually
		// lives under /tmp, which the sandbox masks with a fresh tmpfs); the SBOM goes to
		// stdout (captured). Offline tool → no egress needed.
		res, err := g.runner.Run(ctx, ports.ToolSpec{Name: g.bin, Args: args, ReadOnlyPaths: []string{targetRef}})
		if err != nil {
			return nil, fmt.Errorf("syft scan %q (sandboxed): %w: %s", targetRef, err, truncate(string(res.Stderr), 300))
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("syft scan %q: exit %d: %s", targetRef, res.ExitCode, truncate(string(res.Stderr), 300))
		}
		return res.Stdout, nil
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, g.bin, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("syft scan %q: %w: %s", targetRef, err, truncate(stderr.String(), 300))
	}
	return out, nil
}

// --- CycloneDX JSON (minimal subset we consume) ---

type cdxDoc struct {
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxMetadata struct {
	// CycloneDX 1.5+ encodes tools as {"components":[...]}; 1.4 as a JSON array.
	Tools json.RawMessage `json:"tools"`
}

type cdxTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	BOMRef     string             `json:"bom-ref"`
	Name       string             `json:"name"`
	Version    string             `json:"version"`
	PURL       string             `json:"purl"`
	Scope      string             `json:"scope"` // required | optional | excluded (npm dev -> excluded)
	Supplier   cdxSupplier        `json:"supplier"`
	Licenses   []cdxLicenseChoice `json:"licenses"`
	Properties []cdxProperty      `json:"properties"`
	Hashes     []cdxHash          `json:"hashes"`
}

// cdxSupplier is the CycloneDX component.supplier object; only its name is consumed (the NTIA supplier element).
type cdxSupplier struct {
	Name string `json:"name"`
}

type cdxHash struct {
	Alg     string `json:"alg"`     // e.g. "SHA-1", "SHA-256"
	Content string `json:"content"` // lowercase hex digest
}

// sha1 returns the component's lowercase-hex SHA-1 from the CycloneDX hashes, or "" if absent. This is
// the artifact fingerprint used to recover a shaded/metadata-less JAR's coordinate.
func (c cdxComponent) sha1() string {
	for _, h := range c.Hashes {
		if strings.EqualFold(h.Alg, "SHA-1") && h.Content != "" {
			return strings.ToLower(strings.TrimSpace(h.Content))
		}
	}
	return ""
}

// checksums maps every CycloneDX hash Syft emitted for the component to a domain Checksum, normalizing the
// algorithm to an SPDX-style name ("SHA-256" -> "SHA256"). This is the general integrity-digest capture (the
// separate sha1() stays for JAR-coordinate recovery). Returns nil when the component carries no hashes.
func (c cdxComponent) checksums() []sbom.Checksum {
	var out []sbom.Checksum
	for _, h := range c.Hashes {
		v := strings.TrimSpace(h.Content)
		if v == "" {
			continue
		}
		out = append(out, sbom.Checksum{Algorithm: strings.ToUpper(strings.ReplaceAll(h.Alg, "-", "")), Value: v})
	}
	return out
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// primaryLocation returns the package's on-disk manifest path AND the container
// layer (diff_id) that holds it, from Syft's `syft:location:N:path` /
// `syft:location:N:layerID` properties. The path is used to classify scope by
// directory (examples/, testdata/, …); the layerID attributes the component to
// the image layer that introduced it (Epic D), empty for non-image scans.
func (c cdxComponent) primaryLocation() (path, layerID string) {
	// Group properties by their location index N so a path and its layerID stay paired.
	type loc struct{ path, layer string }
	byIdx := map[string]*loc{}
	order := []string{}
	for _, p := range c.Properties {
		if !strings.HasPrefix(p.Name, "syft:location:") {
			continue
		}
		rest := strings.TrimPrefix(p.Name, "syft:location:") // "N:path" | "N:layerID"
		i := strings.IndexByte(rest, ':')
		if i <= 0 {
			continue
		}
		idx, field := rest[:i], rest[i+1:]
		l := byIdx[idx]
		if l == nil {
			l = &loc{}
			byIdx[idx] = l
			order = append(order, idx)
		}
		switch field {
		case "path":
			l.path = p.Value
		case "layerID":
			l.layer = p.Value
		}
	}
	// Prefer the MOST SPECIFIC location for scope classification: a per-directory
	// manifest (e.g. examples/x/package.json) over a hoisted root lockfile, and the
	// deepest path among those – so a workspace's scope wins over the shared lock.
	bestRank, bestDepth := -1, -1
	for _, idx := range order {
		l := byIdx[idx]
		if l.path == "" {
			continue
		}
		r, d := locRank(l.path), depth(l.path)
		if r > bestRank || (r == bestRank && d > bestDepth) {
			path, layerID, bestRank, bestDepth = l.path, l.layer, r, d
		}
	}
	return path, layerID
}

// rootLockfiles are hoisted lockfiles whose path carries no per-workspace scope
// signal (all workspaces' deps are flattened into them).
var rootLockfiles = map[string]bool{
	"package-lock.json": true, "pnpm-lock.yaml": true, "yarn.lock": true, "npm-shrinkwrap.json": true,
	"gemfile.lock": true, "go.sum": true, "cargo.lock": true, "poetry.lock": true, "pipfile.lock": true,
	"composer.lock": true,
}

// locRank ranks a location: a non-lockfile manifest (1) beats a lockfile (0), so
// the workspace directory wins over the shared lock when both are recorded.
func locRank(path string) int {
	base := path
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		base = path[i+1:]
	}
	if rootLockfiles[strings.ToLower(base)] {
		return 0
	}
	return 1
}

func depth(path string) int { return strings.Count(path, "/") }

type cdxLicenseChoice struct {
	License    *cdxLicenseRef `json:"license"`
	Expression string         `json:"expression"`
}

type cdxLicenseRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// parseCycloneDX maps CycloneDX components to domain components, the dependency
// graph to domain edges, and extracts the Syft version. It skips main-module /
// file-level entries Syft emits without a package identity. License
// classification is deferred to the license scanner.
func parseCycloneDX(data []byte) ([]sbom.Component, []sbom.Dependency, string, error) {
	var doc cdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, "", err
	}
	version := syftVersion(doc.Metadata.Tools)
	out := make([]sbom.Component, 0, len(doc.Components))
	refToID := make(map[string]string, len(doc.Components)) // CycloneDX bom-ref -> component identity
	for _, c := range doc.Components {
		if c.PURL == "" && (c.Name == "" || c.Version == "") {
			continue // skip entries that don't identify a package
		}
		loc, layerID := c.primaryLocation()
		supplier, supplierSrc := sbom.SupplierWithSource(c.Supplier.Name, c.PURL)
		comp := sbom.Component{
			Name: c.Name, Version: c.Version, PURL: c.PURL,
			Location:       loc,
			Scope:          sbom.ClassifyScope(loc, c.Scope),
			Supplier:       supplier,
			SupplierSource: supplierSrc,
			LayerID:        layerID,
			SHA1:           c.sha1(),
			Checksums:      c.checksums(),
		}
		for _, lc := range c.Licenses {
			switch {
			case lc.License != nil && lc.License.ID != "":
				comp.Licenses = append(comp.Licenses, sbom.License{SPDXID: lc.License.ID, Name: lc.License.ID, Category: sbom.LicenseUnknown})
			case lc.License != nil && lc.License.URL != "":
				comp.Licenses = append(comp.Licenses, sbom.License{Name: lc.License.URL, Category: sbom.LicenseUnknown})
			case lc.License != nil && lc.License.Name != "":
				comp.Licenses = append(comp.Licenses, sbom.License{Name: lc.License.Name, Category: sbom.LicenseUnknown})
			case lc.Expression != "":
				comp.Licenses = append(comp.Licenses, sbom.License{Name: lc.Expression, Category: sbom.LicenseUnknown})
			}
		}
		out = append(out, comp)
		if c.BOMRef != "" {
			refToID[c.BOMRef] = componentID(c.Name, c.Version, c.PURL)
		}
	}

	// Translate bom-ref edges to component-identity edges, dropping any endpoint
	// that didn't resolve to a kept component (e.g. the skipped main module).
	deps := make([]sbom.Dependency, 0, len(doc.Dependencies))
	for _, d := range doc.Dependencies {
		ref, ok := refToID[d.Ref]
		if !ok {
			continue
		}
		on := make([]string, 0, len(d.DependsOn))
		seen := map[string]bool{ref: true} // de-dup targets and guard self-edges (duplicate PURLs)
		for _, t := range d.DependsOn {
			if id, ok := refToID[t]; ok && !seen[id] {
				seen[id] = true
				on = append(on, id)
			}
		}
		if len(on) > 0 {
			deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: on})
		}
	}
	// Syft emits the same package as several components from different evidence sources – some
	// carrying the resolved license, some none. Collapse them by identity (PURL / name@version) and
	// union their licenses, so a license-less twin can't surface as a phantom "UNKNOWN" downstream
	// (license coverage, component audit, Excel export). Dependency edges key on component identity,
	// which is the same merge key, so they remain valid against the deduped set.
	out = sbom.DedupeComponents(out)
	return out, deps, version, nil
}

// componentID is the stable identity of a component for graph edges: its PURL,
// or name@version when it has no PURL. The web builds node ids the same way.
func componentID(name, version, purl string) string {
	if purl != "" {
		return purl
	}
	if version != "" {
		return name + "@" + version
	}
	return name
}

// syftVersion extracts Syft's version from CycloneDX metadata.tools, handling
// both the 1.5+ object form ({"components":[...]}) and the 1.4 array form.
func syftVersion(tools json.RawMessage) string {
	if len(tools) == 0 {
		return ""
	}
	var obj struct {
		Components []cdxTool `json:"components"`
	}
	if json.Unmarshal(tools, &obj) == nil {
		if v := findTool(obj.Components, "syft"); v != "" {
			return v
		}
	}
	var arr []cdxTool
	if json.Unmarshal(tools, &arr) == nil {
		if v := findTool(arr, "syft"); v != "" {
			return v
		}
	}
	return ""
}

func findTool(tools []cdxTool, name string) string {
	for _, t := range tools {
		if strings.EqualFold(t.Name, name) {
			return t.Version
		}
	}
	return ""
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
