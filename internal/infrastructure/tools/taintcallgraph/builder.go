package taintcallgraph

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Builder produces a general first-party call graph by shelling out to the synapse-callgraph binary (which
// runs the go/ssa builder over the target). bin is the executable (path or name); runner, when set, runs it
// inside the sandbox. Mirrors the govulncheck builder's exec/sandbox shape.
type Builder struct {
	bin    string
	runner ports.ToolRunner // optional; when set, the binary runs inside the sandbox
}

// New returns a builder using the given synapse-callgraph binary (defaults to "synapse-callgraph" in PATH).
func New(bin string) *Builder {
	if strings.TrimSpace(bin) == "" {
		bin = "synapse-callgraph"
	}
	return &Builder{bin: bin}
}

// WithRunner runs synapse-callgraph through a ToolRunner (the SandboxRunner) – REQUIRED in production: the
// binary compiles UNTRUSTED target source via go/packages, so it must be confined (cgo is also disabled
// here as defense-in-depth). Like govulncheck source-mode, the target needs a buildable, pre-fetched module
// cache bound into the sandbox (an operational follow-up); missing deps → fail-closed (no graph),
// a degrade, not a false negative. nil keeps the direct exec dev path.
func (b *Builder) WithRunner(r ports.ToolRunner) *Builder { b.runner = r; return b }

var _ ports.CallGraphBuilder = (*Builder)(nil)

// Build runs `synapse-callgraph build-callgraph <targetRef>` and parses its wire output into the domain
// call graph. A load/type error in the target fails closed (the binary exits non-zero) – never a partial
// graph, which would drop taint paths.
func (b *Builder) Build(ctx context.Context, targetRef string) (*callgraph.Graph, error) {
	out, err := b.run(ctx, targetRef)
	if err != nil {
		return nil, err
	}
	g, err := parseCallgraph(out)
	if err != nil {
		return nil, fmt.Errorf("parse synapse-callgraph: %w", err)
	}
	return g, nil
}

// run executes the binary (sandboxed when a runner is set, else direct os/exec) and returns its raw wire
// JSON. argv only (no shell).
func (b *Builder) run(ctx context.Context, targetRef string) ([]byte, error) {
	args := []string{"build-callgraph", targetRef}
	if b.runner != nil {
		// Bind the target READ-ONLY (a compromised analyzer can't mutate the acquired source) + disable cgo
		// so a malicious target can't get its C compiled during load. The SandboxRunner hands a CLEAN base
		// env (PATH/HOME only – the worker's GOPACKAGESDRIVER/CC/GOFLAGS never pass through) plus its
		// configured cgroup/egress confinement, so this spec only adds CGO_ENABLED=0 on top.
		res, err := b.runner.Run(ctx, ports.ToolSpec{
			Name:          b.bin,
			Args:          args,
			ReadOnlyPaths: []string{targetRef},
			Env:           []string{"CGO_ENABLED=0"},
		})
		if err != nil {
			return nil, fmt.Errorf("synapse-callgraph %q (sandboxed): %w: %s", targetRef, err, truncate(string(res.Stderr), 300))
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("synapse-callgraph %q: exit %d: %s", targetRef, res.ExitCode, truncate(string(res.Stderr), 300))
		}
		return res.Stdout, nil
	}
	// Direct exec is the dev path; production runs via WithRunner (sandboxed). The pinned/hash-verified
	// binary is trusted; cgo is disabled for parity with the sandboxed run.
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, b.bin, args...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("synapse-callgraph %q: %w: %s", targetRef, err, truncate(stderr.String(), 300))
	}
	return out, nil
}

// truncate caps a tool stderr for an error message – compiler diagnostics can quote target source, so the
// captured text is bounded (and must be kept out of the LLM transcript + audit, GR3).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) { // back up to a rune boundary so the cut never yields invalid UTF-8
		n--
	}
	return s[:n] + "…"
}
