// Package licensefile recovers component licenses by classifying the LICENSE / COPYING
// files present in the prepared workspace – the cross-ecosystem equivalent of Trivy's
// `--license-full`, but for ANY language (not just JARs, which jarlicense handles).
//
// It walks the workspace, classifies each license file's TEXT via the shared licensetext
// classifier (google/licensecheck → SPDX id + confidence), and attaches the result to the
// matching component:
// a license file at the workspace root → the project's own (FIRST-PARTY) components,
// not every dependency declared in the root manifest (that would mis-license deps);
// node_modules/<pkg>/LICENSE, vendor/<mod>/LICENSE, packages/<pkg>/LICENSE, etc. →
// the enclosing dependency, by directory name.
//
// Deterministic, offline, read-only, best-effort, and bounded. It only fills components
// that still have NO license (never overwrites declared/registry data).
package licensefile

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/licensetext"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxFiles        = 50000   // bound the walk (workspace size is capped upstream)
	maxLicenseBytes = 1 << 20 // a LICENSE file is small; cap the read defensively
)

// skipDir names are never worth walking for license files.
var skipDir = map[string]bool{".git": true, ".hg": true, ".svn": true, ".idea": true, ".vscode": true}

// Resolver classifies workspace LICENSE files and fills missing component licenses.
type Resolver struct{}

// New returns a resolver.
func New() *Resolver { return &Resolver{} }

var _ ports.LicenseFileResolver = (*Resolver)(nil)

// Resolve walks wsDir for license files and fills the license of any component that still
// has none and matches a file by directory. Returns the number of components resolved.
func (r *Resolver) Resolve(ctx context.Context, wsDir string, comps []sbom.Component) int {
	if strings.TrimSpace(wsDir) == "" {
		return 0
	}
	need := false
	for i := range comps {
		if len(comps[i].Licenses) == 0 {
			need = true
			break
		}
	}
	if !need {
		return 0
	}

	// Index components for directory matching. A name seen on two components is ambiguous
	// (never guessed). A root-level license file attaches only to FIRST-PARTY components
	// (the project itself) – never to dependencies, which carry their own licenses.
	byName := map[string]int{}
	ambiguous := map[string]bool{}
	var firstParty []int
	for i := range comps {
		if n := strings.ToLower(strings.TrimSpace(comps[i].Name)); n != "" {
			if _, ok := byName[n]; ok {
				ambiguous[n] = true
			} else {
				byName[n] = i
			}
		}
		if comps[i].FirstParty {
			firstParty = append(firstParty, i)
		}
	}

	resolved, count := 0, 0
	_ = filepath.WalkDir(wsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Only regular files: a symlink named LICENSE could redirect the read outside the
		// workspace (e.g. LICENSE -> /etc/passwd). d.Type() comes from the dirent (Lstat),
		// so it identifies the symlink WITHOUT following it – mirrors enry/detector + acquirer.
		if !d.Type().IsRegular() {
			return nil
		}
		if !isLicenseFileName(d.Name()) {
			return nil
		}
		if count >= maxFiles {
			return filepath.SkipAll
		}
		count++

		rel, relErr := filepath.Rel(wsDir, p)
		if relErr != nil {
			return nil
		}
		targets := matchComponents(rel, byName, ambiguous, firstParty)
		if len(targets) == 0 {
			return nil
		}
		// Skip the read+classify entirely unless a target still needs a license.
		needAny := false
		for _, i := range targets {
			if len(comps[i].Licenses) == 0 {
				needAny = true
				break
			}
		}
		if !needAny {
			return nil
		}
		id, confidence, ok := licensetext.Classify(readCapped(p), 0)
		if !ok {
			return nil
		}
		for _, i := range targets {
			c := &comps[i]
			if len(c.Licenses) > 0 {
				continue
			}
			c.Licenses = []sbom.License{{SPDXID: id, Name: id}}
			c.LicenseSource = sbom.LicenseSourceLicenseFile
			c.LicenseConfidence = "declared"
			c.LicenseConfidencePct = confidence
			c.UnknownReason = ""
			resolved++
		}
		return nil
	})
	return resolved
}

// matchComponents maps a license file (path relative to the workspace) to component
// indices: a file at the root → the first-party project components; otherwise the
// enclosing dependency by directory name (node_modules/vendor/packages/…), deepest wins.
func matchComponents(rel string, byName map[string]int, ambiguous map[string]bool, firstParty []int) []int {
	rel = filepath.ToSlash(rel)
	dir := strings.Trim(filepath.ToSlash(filepath.Dir(rel)), "/")
	if dir == "" || dir == "." {
		return firstParty // license at the workspace root → the project itself (first-party only)
	}
	segs := strings.Split(dir, "/")
	// node_modules/<pkg> or node_modules/@scope/<pkg>
	for i, s := range segs {
		if s == "node_modules" && i+1 < len(segs) {
			name := segs[i+1]
			if strings.HasPrefix(name, "@") && i+2 < len(segs) {
				name += "/" + segs[i+2]
			}
			if idx, ok := lookup(byName, ambiguous, name); ok {
				return []int{idx}
			}
		}
	}
	// Deepest directory segment that names a component (vendor/<mod>, packages/<pkg>, …).
	for i := len(segs) - 1; i >= 0; i-- {
		if idx, ok := lookup(byName, ambiguous, segs[i]); ok {
			return []int{idx}
		}
	}
	return nil
}

func lookup(byName map[string]int, ambiguous map[string]bool, name string) (int, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || ambiguous[n] {
		return 0, false
	}
	idx, ok := byName[n]
	return idx, ok
}

// isLicenseFileName matches common license-text file names (NOTICE is attribution, not a
// license, so it is intentionally excluded).
func isLicenseFileName(name string) bool {
	base := strings.ToLower(name)
	for _, p := range []string{"license", "licence", "copying", "unlicense"} {
		if base == p || strings.HasPrefix(base, p+".") {
			return true
		}
	}
	return false
}

func readCapped(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxLicenseBytes))
	if err != nil {
		return nil
	}
	return data
}

// Chain runs multiple license-file resolvers in order (e.g. jarlicense then this
// workspace scanner), summing how many components each resolved. Nil resolvers are skipped.
type Chain struct{ resolvers []ports.LicenseFileResolver }

// NewChain composes resolvers into one ports.LicenseFileResolver.
func NewChain(rs ...ports.LicenseFileResolver) *Chain {
	out := make([]ports.LicenseFileResolver, 0, len(rs))
	for _, r := range rs {
		if r != nil {
			out = append(out, r)
		}
	}
	return &Chain{resolvers: out}
}

var _ ports.LicenseFileResolver = (*Chain)(nil)

func (c *Chain) Resolve(ctx context.Context, wsDir string, comps []sbom.Component) int {
	total := 0
	for _, r := range c.resolvers {
		total += r.Resolve(ctx, wsDir, comps)
	}
	return total
}
