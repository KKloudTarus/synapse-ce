// Package govulncheck adapts the Go call-graph builder to the CallGraphBuilder port
// by shelling out to a pinned govulncheck binary via argv. It runs `govulncheck -json
// -scan=symbol` over an acquired Go module and reconstructs the deterministic domain callgraph.Graph from
// the emitted finding traces – the vuln-reachability witness paths that reachability PROOF
// consumes. Importing govulncheck/x-tools as a library would compile the (untrusted) target in our
// address space and bloat the binary, so it is exec'd and sandbox-confined instead.
//
// Per the verified govulncheck v1.0.0 schema: the `-json` stream is newline-delimited Message
// objects in NO guaranteed order with repeated findings, and a finding's Trace is ordered VULN-SYMBOL →
// ENTRYPOINT (Trace[0] is the vulnerable symbol, the last frame is the entrypoint). The parser therefore
// streams + dedupes, and walks each trace tail-to-head to build caller→callee edges.
package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// protocolVersion is the govulncheck JSON protocol this parser is written against. govulncheck explicitly
// allows its output to drift across versions, so a mismatch fails closed rather than mis-parsing.
const protocolVersion = "v1.0.0"

// Builder runs govulncheck to produce a Go call graph. bin is the executable (path or name).
type Builder struct {
	bin    string
	runner ports.ToolRunner // optional; when set, govulncheck runs inside the sandbox
}

// New returns a builder using the given govulncheck binary (defaults to "govulncheck" in PATH).
func New(bin string) *Builder {
	if strings.TrimSpace(bin) == "" {
		bin = "govulncheck"
	}
	return &Builder{bin: bin}
}

// WithRunner runs govulncheck through a ToolRunner (the SandboxRunner) instead of a bare os/exec. NOTE
// govulncheck SOURCE mode does a real build of the target, so the sandbox must bind a
// pre-fetched, buildable workspace + module cache; full cache binding is an operational
// follow-up. nil keeps the direct exec.
func (b *Builder) WithRunner(r ports.ToolRunner) *Builder { b.runner = r; return b }

var _ ports.CallGraphBuilder = (*Builder)(nil)

// Build runs `govulncheck -json -scan=symbol./...` in the target module and reconstructs the call graph
// from its finding traces. A target with no reachable vulns yields an empty (non-nil) Graph – never an
// error for "nothing reachable" – so a caller degrades to a lower reachability tier, not a false negative.
func (b *Builder) Build(ctx context.Context, targetRef string) (*callgraph.Graph, error) {
	out, err := b.run(ctx, targetRef)
	if err != nil {
		return nil, err
	}
	g, err := parseGovulncheck(out)
	if err != nil {
		return nil, fmt.Errorf("parse govulncheck: %w", err)
	}
	return g, nil
}

// run executes govulncheck (sandboxed when a runner is set, else direct os/exec in the module dir) and
// returns the raw NDJSON stream. argv only (no shell).
func (b *Builder) run(ctx context.Context, targetRef string) ([]byte, error) {
	args := []string{"-json", "-scan=symbol", "./..."}
	if b.runner != nil {
		// Bind the module READ-ONLY (so a compromised tool can't mutate the acquired source tree and taint
		// later-stage evidence); govulncheck's build cache goes to the runner's ephemeral Workdir tmpfs
		// (left unset here). The full module-cache binding govulncheck source-mode needs is an
		// operational follow-up, wired with the composition root.
		res, err := b.runner.Run(ctx, ports.ToolSpec{Name: b.bin, Args: args, ReadOnlyPaths: []string{targetRef}})
		if err != nil {
			return nil, fmt.Errorf("govulncheck %q (sandboxed): %w: %s", targetRef, err, truncate(string(res.Stderr), 300))
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("govulncheck %q: exit %d: %s", targetRef, res.ExitCode, truncate(string(res.Stderr), 300))
		}
		return res.Stdout, nil
	}
	// Direct exec is the dev path; production runs via WithRunner (sandboxed + output-capped). cmd.Output()
	// buffers stdout unbounded, so the direct path trusts the pinned/hash-verified binary (F5) – parity
	// with the syft adapter's accepted precedent.
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, b.bin, args...)
	cmd.Dir = targetRef // govulncheck analyzes the module rooted at the working directory
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("govulncheck %q: %w: %s", targetRef, err, truncate(stderr.String(), 300))
	}
	return out, nil
}

// --- pure parse (the testable core) ---

type message struct {
	Config  *config  `json:"config,omitempty"`
	Finding *finding `json:"finding,omitempty"`
}

type config struct {
	ProtocolVersion string `json:"protocol_version,omitempty"`
	// TODO: also capture ScannerVersion + DB/DBLastModified + GoVersion here and thread them as the
	// reproducibility/provenance fingerprint of an audited Tier-2 override (the domain Graph has no slot
	// for it today; mirrors Grype's Provenance()).
}

type finding struct {
	OSV   string  `json:"osv,omitempty"`
	Trace []frame `json:"trace,omitempty"`
}

type frame struct {
	Package  string `json:"package,omitempty"`
	Receiver string `json:"receiver,omitempty"`
	Function string `json:"function,omitempty"`
}

// node composes a frame into the "importPath.Symbol" identity (matching OSV AffectedSymbols, incl.
// methods via the receiver). Returns "" when the frame is not a symbol (module/package-level frame).
func (f frame) node() string {
	if f.Package == "" || f.Function == "" {
		return ""
	}
	if r := strings.TrimPrefix(f.Receiver, "*"); r != "" {
		return f.Package + "." + r + "." + f.Function
	}
	return f.Package + "." + f.Function
}

// parseGovulncheck reconstructs a deterministic callgraph.Graph from the govulncheck `-json` NDJSON
// stream. It decodes message-by-message (the stream is unordered + repeats findings), and for each
// finding walks the trace TAIL-TO-HEAD (entrypoint → vuln) so consecutive frames become caller→callee
// edges; the trace's last frame is the entrypoint. Edges + entrypoints are de-duplicated and emitted in
// sorted order, so the Graph is canonical regardless of the stream's (unspecified) message/finding order.
func parseGovulncheck(data []byte) (*callgraph.Graph, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	entrypoints := map[string]bool{}
	adj := map[string]map[string]bool{}
	for {
		var m message
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode message stream: %w", err)
		}
		if m.Config != nil && m.Config.ProtocolVersion != "" && m.Config.ProtocolVersion != protocolVersion {
			return nil, fmt.Errorf("unsupported govulncheck protocol %q (want %s)", m.Config.ProtocolVersion, protocolVersion)
		}
		if m.Finding == nil {
			continue
		}
		// Collect the symbol nodes of this trace in emitted order (vuln-symbol → entrypoint), skipping
		// non-symbol (module/package-level) frames.
		var ids []string
		for _, fr := range m.Finding.Trace {
			if id := fr.node(); id != "" {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			continue // a module/package-level finding: no symbol path to prove
		}
		// ids[len-1] is the entrypoint; walk tail-to-head so caller (nearer entry) -> callee (nearer vuln).
		entrypoints[ids[len(ids)-1]] = true
		for i := len(ids) - 1; i > 0; i-- {
			caller, callee := ids[i], ids[i-1]
			if adj[caller] == nil {
				adj[caller] = map[string]bool{}
			}
			adj[caller][callee] = true
		}
	}
	return &callgraph.Graph{Entrypoints: sortedKeys(entrypoints), Edges: edgesOf(adj)}, nil
}

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// edgesOf flattens the adjacency set into sorted, de-duplicated callgraph.Edges (caller order + callee
// order both stable) – the canonical form that keeps the Graph + its query results deterministic.
func edgesOf(adj map[string]map[string]bool) []callgraph.Edge {
	if len(adj) == 0 {
		return nil
	}
	callers := make([]string, 0, len(adj))
	for c := range adj {
		callers = append(callers, c)
	}
	sort.Strings(callers)
	out := make([]callgraph.Edge, 0, len(callers))
	for _, c := range callers {
		out = append(out, callgraph.Edge{Caller: c, Callees: sortedKeys(adj[c])})
	}
	return out
}

// truncate caps a diagnostic string at n bytes without splitting a UTF-8 rune at the boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
