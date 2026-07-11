// Package gomodgraph resolves the transitive dependency EDGES of a Go module by shelling out to
// `go mod graph` via argv and mapping its module-graph output onto the SBOM's existing golang
// components. go.mod alone carries only the (flattened) requirement list – not the edge graph – and the
// transitive graph lives in the module cache, which `go mod graph` reads; so an owned, no-exec parse cannot
// produce edges. This adapter fills that gap as a best-effort, post-SBOM enrichment.
//
// SAFETY: `go mod graph` only READS go.mod files (from the workspace + module cache) – it does NOT compile
// the target (unlike govulncheck/taint), so it is low-risk; it still runs sandbox-confined when a runner is
// set (the module dir bound READ-ONLY, GOPROXY=off so it never reaches the network – cache-only, fail-fast
// offline; GOTOOLCHAIN=local so a hostile `toolchain` directive can never trigger a toolchain fetch+exec).
// It is BEST-EFFORT: a non-Go target, an un-resolvable graph (no module cache), or any tool error
// adds NO edges and never fails the scan. Edges are RESOLUTION-AS-FILTER: an edge is emitted only when BOTH
// endpoints are already golang components in the SBOM, so a `go mod graph` line for an unselected module
// version (the graph lists every version considered by MVS) is dropped – never a phantom edge.
package gomodgraph

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Resolver runs `go mod graph` to add Go dependency edges to an SBOM. bin is the go executable (path/name).
type Resolver struct {
	bin    string
	runner ports.ToolRunner // optional; when set, go mod graph runs inside the sandbox
}

// New returns a resolver using the given go binary (defaults to "go" in PATH).
func New(bin string) *Resolver {
	if strings.TrimSpace(bin) == "" {
		bin = "go"
	}
	return &Resolver{bin: bin}
}

// WithRunner runs `go mod graph` through a ToolRunner (the SandboxRunner) instead of a bare os/exec. The
// module dir is bound READ-ONLY; `go mod graph` reads the module cache (HOME/go/pkg/mod in the sandbox's
// ephemeral env) – binding a populated cache offline is an operational follow-up shared with
// govulncheck, so until then a sandboxed run is best-effort (no cache ⇒ no edges, never a false graph).
func (r *Resolver) WithRunner(runner ports.ToolRunner) *Resolver { r.runner = runner; return r }

var _ ports.DependencyGraphResolver = (*Resolver)(nil)

// ResolveEdges runs `go mod graph` over dir and adds the resolved Go dependency edges to doc, in place.
// It no-ops (0, nil) when doc has no golang components (not a Go target – nothing to resolve, and the tool
// would be pointless). Returns the number of edges (DependsOn entries) added. Best-effort: a tool error is
// returned for the caller to log+ignore; doc is left unchanged on error.
func (r *Resolver) ResolveEdges(ctx context.Context, dir string, doc *sbom.SBOM) (int, error) {
	if doc == nil {
		return 0, nil
	}
	have := make(map[string]bool) // existing golang component PURLs – the resolution-as-filter set
	for _, c := range doc.Components {
		if strings.HasPrefix(c.PURL, "pkg:golang/") {
			have[c.PURL] = true
		}
	}
	if len(have) == 0 {
		return 0, nil // not a Go project (or no resolved go components) – don't run the tool
	}
	out, err := r.run(ctx, dir)
	if err != nil {
		return 0, fmt.Errorf("go mod graph %q: %w", dir, err)
	}
	// Group resolved edges by source PURL (resolution-as-filter: both endpoints must be real components).
	byRef := make(map[string]map[string]bool)
	for _, e := range parseModGraph(out) {
		from, to := modTokenToPURL(e.from), modTokenToPURL(e.to)
		if from == "" || to == "" || from == to || !have[from] || !have[to] {
			continue
		}
		if byRef[from] == nil {
			byRef[from] = make(map[string]bool)
		}
		byRef[from][to] = true
	}
	return mergeEdges(doc, byRef), nil
}

// containmentEnv is the offline/containment environment applied on BOTH the sandboxed and direct paths:
// GOPROXY=off (cache-only, never the network) + GOTOOLCHAIN=local (use the running toolchain only – a
// hostile go.mod `toolchain` directive can never trigger a fetch+exec). The module dir is bound read-only
// and `go mod graph` does not write, so the default -mod=readonly is correct (NEVER -mod=mod, which would
// permit writes against the read-only mount + a network go.sum sync).
var containmentEnv = []string{"GOPROXY=off", "GOTOOLCHAIN=local"}

// run executes `go -C <dir> mod graph` (sandboxed when a runner is set, else direct os/exec), returning the
// raw graph text. The `-C dir` global flag makes it cwd-independent (Go 1.20+); argv only, no shell. On the
// sandboxed path `dir` is both the `-C` target AND a ReadOnlyPaths bind (no Workdir), so the tool reaches it.
func (r *Resolver) run(ctx context.Context, dir string) ([]byte, error) {
	args := []string{"-C", dir, "mod", "graph"}
	if r.runner != nil {
		res, err := r.runner.Run(ctx, ports.ToolSpec{
			Name: r.bin, Args: args,
			ReadOnlyPaths: []string{dir}, // the module is read-only; go mod graph never writes it
			Env:           containmentEnv,
		})
		if err != nil {
			return nil, fmt.Errorf("sandboxed: %w: %s", err, truncate(string(res.Stderr), 300))
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("exit %d: %s", res.ExitCode, truncate(string(res.Stderr), 300))
		}
		return res.Stdout, nil
	}
	// Direct exec is the dev path; production runs via WithRunner. Trusts the pinned/hash-verified go binary
	// (parity with the govulncheck/syft adapters). The containment env is applied here too (append wins on
	// duplicate keys) so the offline/no-toolchain-switch posture holds on the dev path, not just sandboxed.
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Env = append(os.Environ(), containmentEnv...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, truncate(stderr.String(), 300))
	}
	return out, nil
}

// modEdge is one `go mod graph` line: a requiring module → a required module, each a raw `path@version`
// token (the main module appears with NO @version).
type modEdge struct{ from, to string }

// parseModGraph parses `go mod graph` output: each non-empty line is exactly two space-separated module
// tokens (`from to`). Malformed lines are skipped. The testable core (no exec).
func parseModGraph(data []byte) []modEdge {
	var out []modEdge
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		out = append(out, modEdge{from: f[0], to: f[1]})
	}
	return out
}

// modTokenToPURL converts a `go mod graph` module token (`path@version`) to its golang PURL. A token with
// no `@` is the MAIN module (the root) – not a dependency component – and maps to "" (skipped). Module
// paths cannot contain `@`, so the single `@` cleanly splits path from version.
func modTokenToPURL(token string) string {
	at := strings.IndexByte(token, '@')
	if at <= 0 || at == len(token)-1 {
		return "" // main module (no @), or a malformed token with an empty path/version
	}
	return "pkg:golang/" + token[:at] + "@" + token[at+1:]
}

// mergeEdges merges the resolved per-source edge sets into doc.Dependencies (in place), deterministically.
// It folds into an existing Dependency with the same Ref (so it composes with any edges another parser
// already emitted) and appends a new Dependency otherwise; new sources are appended in sorted Ref order.
// Returns the count of NEW DependsOn targets added.
func mergeEdges(doc *sbom.SBOM, byRef map[string]map[string]bool) int {
	if len(byRef) == 0 {
		return 0
	}
	idx := make(map[string]int, len(doc.Dependencies)) // Ref -> index in doc.Dependencies
	for i, d := range doc.Dependencies {
		idx[d.Ref] = i
	}
	added := 0
	refs := make([]string, 0, len(byRef))
	for ref := range byRef {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		targets := sortedKeys(byRef[ref])
		if i, ok := idx[ref]; ok {
			existing := make(map[string]bool, len(doc.Dependencies[i].DependsOn))
			for _, t := range doc.Dependencies[i].DependsOn {
				existing[t] = true
			}
			for _, t := range targets {
				if !existing[t] {
					doc.Dependencies[i].DependsOn = append(doc.Dependencies[i].DependsOn, t)
					added++
				}
			}
			continue
		}
		doc.Dependencies = append(doc.Dependencies, sbom.Dependency{Ref: ref, DependsOn: targets})
		idx[ref] = len(doc.Dependencies) - 1
		added += len(targets)
	}
	return added
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// truncate caps a diagnostic string at n bytes without splitting a UTF-8 rune (mirrors the govulncheck adapter).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
