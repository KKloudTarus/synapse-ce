package misconfig

import (
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Kustomize overlays PATCH base Kubernetes manifests, so an insecure setting can be introduced (or removed)
// by a patch that neither the base nor the overlay file shows alone. Comprehensive scanners evaluate a
// kustomization by RENDERING it (`kustomize build`) and scanning the output, exactly like Helm.
//
// Rendering an UNTRUSTED kustomization must not run unprotected on the host: kustomize can pull remote bases
// (an SSRF / exfil vector) and exec configured plugins. So this mirrors the Helm posture: a caller-supplied
// ToolRunner confines the exec with egress denied (the API path), or an explicit trusted-local direct exec is
// used (the CLI). With NEITHER set, kustomize rendering is skipped and the manifests are scanned raw.
//
// SOUNDNESS. Findings are additive presence facts and must never be suppressed:
//   - Only ROOT kustomizations (an overlay no other kustomization references) are rendered.
//   - A manifest file is skipped from the RAW scan ONLY when it is an EXPLICIT resource in the transitive
//     closure of a root whose render SUCCEEDED. So a render failure (missing binary, timeout, denied remote
//     base, malformed input, a reference cycle) skips nothing, and a file that a kustomization does not
//     actually reference is still scanned raw. This avoids the double count (a base resource reported twice,
//     once unpatched) without ever hiding a real finding.

const (
	kustomizeRenderTimeout = 45 * time.Second // bound a single `kustomize build` render
	maxKustomizeRenders    = 200              // bound the total renders on a hostile tree with many roots
)

// isKustomizationName recognizes a kustomization root file by its conventional names.
func isKustomizationName(name string) bool {
	switch name {
	case "kustomization.yaml", "kustomization.yml", "Kustomization":
		return true
	}
	return false
}

// kustomizeDoc is the subset of a kustomization.yaml we parse: the LOCAL path references (resources, bases,
// components) that make a directory a base of another, plus the patch file references, all of which kustomize
// consumes and which therefore must not be scanned raw when the render succeeds.
type kustomizeDoc struct {
	Resources             []string       `yaml:"resources"`
	Bases                 []string       `yaml:"bases"` // deprecated but still valid
	Components            []string       `yaml:"components"`
	PatchesStrategicMerge []string       `yaml:"patchesStrategicMerge"`
	Patches               []kustomizePat `yaml:"patches"`
}

type kustomizePat struct {
	Path string `yaml:"path"`
}

// kustomization is one parsed kustomization directory: the absolute path of its file, the manifest FILES it
// references directly, and the sub-kustomization DIRS it references directly (for the transitive closure).
type kustomization struct {
	file string
	dir  string
	refs []string // absolute paths of directly-referenced local resources/bases/components/patches
}

// collectKustomizations finds every kustomization directory under root, parses its local references, and
// returns an index (abs dir -> kustomization) plus the RENDER ROOTS (a directory no other kustomization
// references as a base/component). Best-effort: an unreadable or unparsable kustomization is skipped.
func collectKustomizations(ctx context.Context, root string) (index map[string]*kustomization, roots []string) {
	index = map[string]*kustomization{}
	referenced := map[string]bool{}
	walked := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		walked++
		if walked > maxEntries {
			return filepath.SkipAll
		}
		if d.IsDir() || !d.Type().IsRegular() || !isKustomizationName(d.Name()) {
			return nil
		}
		dir := filepath.Dir(path)
		k := &kustomization{file: path, dir: dir}
		index[dir] = k
		data, e := os.ReadFile(path)
		if e != nil || len(data) == 0 || int64(len(data)) > maxFileBytes || isBinary(data) {
			return nil
		}
		var kd kustomizeDoc
		if yaml.Unmarshal(data, &kd) != nil {
			return nil
		}
		for _, ref := range kustomizeRefs(kd) {
			ref = strings.TrimSpace(ref)
			// A remote base (a URL or a git spec) is not a local file and the sandbox denies its egress; only
			// a LOCAL, in-tree path can make a directory a referenced base or be skipped from the raw scan.
			if ref == "" || strings.Contains(ref, "://") || strings.HasPrefix(ref, "git@") || filepath.IsAbs(ref) {
				continue
			}
			abs := filepath.Clean(filepath.Join(dir, ref))
			if !within(root, abs) { // never let a `../` ref escape the scanned tree
				continue
			}
			k.refs = append(k.refs, abs)
			referenced[abs] = true // if abs is a base DIR, it is now referenced (not a root)
		}
		return nil
	})
	for dir := range index {
		if !referenced[dir] {
			roots = append(roots, dir)
		}
	}
	sort.Strings(roots) // deterministic render order
	return index, roots
}

func kustomizeRefs(kd kustomizeDoc) []string {
	out := make([]string, 0, len(kd.Resources)+len(kd.Bases)+len(kd.Components)+len(kd.PatchesStrategicMerge)+len(kd.Patches))
	out = append(out, kd.Resources...)
	out = append(out, kd.Bases...)
	out = append(out, kd.Components...)
	out = append(out, kd.PatchesStrategicMerge...)
	for _, p := range kd.Patches {
		if p.Path != "" {
			out = append(out, p.Path)
		}
	}
	return out
}

// within reports whether abs is inside root (so a `../` reference cannot escape the scanned tree).
func within(root, abs string) bool {
	rel, err := filepath.Rel(root, abs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// coveredFiles returns the set of manifest FILES (absolute paths) in the transitive closure of rootDir: the
// kustomization's own file, its directly-referenced files, and, recursively, the files of every referenced
// sub-kustomization directory. These are exactly the files the successful render of rootDir covers, so they
// must not be scanned raw. A reference cycle is bounded by the visited set.
func coveredFiles(rootDir string, index map[string]*kustomization) map[string]bool {
	covered := map[string]bool{}
	visited := map[string]bool{}
	var visit func(dir string)
	visit = func(dir string) {
		if visited[dir] {
			return
		}
		visited[dir] = true
		k, ok := index[dir]
		if !ok {
			return
		}
		covered[k.file] = true
		for _, ref := range k.refs {
			if _, isKustomizeDir := index[ref]; isKustomizeDir {
				visit(ref) // a referenced sub-kustomization directory
				continue
			}
			covered[ref] = true // a referenced manifest / patch file
		}
	}
	visit(rootDir)
	return covered
}

// renderKustomization runs `kustomize build dir` (sandboxed or direct, per the Scanner's configuration) and
// scans the rendered manifests with the Kubernetes rules. root is bound read-only in the sandbox so a base
// referenced from a sibling directory (../base) is readable. It returns ok=false when rendering is not
// enabled or the render FAILED, so the caller can leave the raw scan in place rather than suppress findings.
func (s *Scanner) renderKustomization(ctx context.Context, root, dir, relDir string) (k8sScanResult, bool) {
	if s.kustomizeBin == "" {
		return k8sScanResult{}, false
	}
	args := []string{"build", dir}
	var rendered []byte
	switch {
	case s.kustomizeRun != nil:
		res, err := s.kustomizeRun.Run(ctx, ports.ToolSpec{
			Name:           s.kustomizeBin,
			Args:           args,
			ReadOnlyPaths:  []string{root}, // bases can live anywhere under the scanned tree
			Timeout:        kustomizeRenderTimeout,
			MaxOutputBytes: maxRenderedBytes,
			// No EgressPolicy: a build needs no network, so full isolation neutralizes a remote-base fetch.
		})
		// Truncated output drops trailing manifests, so a covered resource might never be scanned: treat it as
		// a failed render (ok=false) so those files fall back to the raw scan instead of being hidden.
		if err != nil || res.ExitCode != 0 || res.Truncated {
			return k8sScanResult{}, false
		}
		rendered = res.Stdout
	case s.kustomizeDir:
		if _, err := exec.LookPath(s.kustomizeBin); err != nil {
			return k8sScanResult{}, false
		}
		cctx, cancel := context.WithTimeout(ctx, kustomizeRenderTimeout)
		defer cancel()
		cmd := exec.CommandContext(cctx, s.kustomizeBin, args...)
		cw := &cappedBuffer{max: maxRenderedBytes}
		cmd.Stdout, cmd.Stderr = cw, io.Discard
		if err := cmd.Run(); err != nil || cw.truncated {
			return k8sScanResult{}, false // truncation would hide trailing manifests: fall back to raw scan
		}
		rendered = cw.buf.Bytes()
	default:
		return k8sScanResult{}, false // kustomize rendering not enabled
	}
	return scanKubernetes(filepath.Join(relDir, "kustomization.yaml"), rendered), true
}
