// Package ast adapts the synapse-ast sidecar to the ports.ASTProvider port: it shells out (argv only, no
// shell) to the binary, which parses the target with tree-sitter and returns per-language function counts
// as JSON. This adapter is pure Go and imports no tree-sitter, so the server and CLI that use it stay
// CGO-free; the sidecar is the only binary that links the grammars. Mirrors the taintcallgraph builder's
// exec/sandbox shape.
package ast

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// exitUnavailable is the sidecar's exit code when it was built without the tree-sitter backend (CGO-free
// build). It maps to available=false, not an error, so callers degrade to their own counting.
const exitUnavailable = 3

// Provider runs the synapse-ast binary. bin is the executable (path or name); runner, when set, confines
// it in the sandbox (the sidecar parses UNTRUSTED source with C grammars, so production should set it).
type Provider struct {
	bin    string
	runner ports.ToolRunner
}

// New returns a provider using the given synapse-ast binary (defaults to "synapse-ast" in PATH).
func New(bin string) *Provider {
	if strings.TrimSpace(bin) == "" {
		bin = "synapse-ast"
	}
	return &Provider{bin: bin}
}

// WithRunner confines the sidecar via a ToolRunner (the SandboxRunner) — recommended in production, since
// the binary parses untrusted target source. nil keeps the direct-exec dev path. The target is bound
// read-only. Unlike synapse-callgraph, cgo is NOT disabled: the tree-sitter backend requires it.
func (p *Provider) WithRunner(r ports.ToolRunner) *Provider { p.runner = r; return p }

var _ ports.ASTProvider = (*Provider)(nil)

// FunctionCounts runs `synapse-ast functions <root>` and returns per-language function counts. A sidecar
// built without the tree-sitter backend exits exitUnavailable, which maps to (nil, false, nil) so the
// caller falls back to its own counting rather than treating it as an error.
func (p *Provider) FunctionCounts(ctx context.Context, root string) (map[string]int, bool, error) {
	if strings.TrimSpace(root) == "" {
		return nil, false, nil
	}
	out, exit, err := p.run(ctx, root)
	if exit == exitUnavailable {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var res struct {
		Functions map[string]int `json:"functions"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, false, fmt.Errorf("parse synapse-ast output: %w", err)
	}
	return res.Functions, true, nil
}

// run executes the sidecar (sandboxed when a runner is set, else direct os/exec) and returns stdout, the
// process exit code, and any error. argv only (no shell).
func (p *Provider) run(ctx context.Context, root string) ([]byte, int, error) {
	args := []string{"functions", root}
	if p.runner != nil {
		res, err := p.runner.Run(ctx, ports.ToolSpec{
			Name:          p.bin,
			Args:          args,
			ReadOnlyPaths: []string{root},
		})
		if err != nil {
			// The sidecar could not be run (absent binary / sandbox setup). Like the direct path, degrade
			// to unavailable rather than failing the inventory — this provider is optional enrichment.
			return nil, exitUnavailable, nil
		}
		if res.ExitCode != 0 && res.ExitCode != exitUnavailable {
			return nil, res.ExitCode, fmt.Errorf("synapse-ast %q: exit %d: %s", root, res.ExitCode, truncate(string(res.Stderr), 300))
		}
		return res.Stdout, res.ExitCode, nil
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, p.bin, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code := ee.ExitCode()
			if code == exitUnavailable {
				return nil, code, nil // built without cgo: not an error, just unavailable
			}
			return nil, code, fmt.Errorf("synapse-ast %q: exit %d", root, code)
		}
		// The process could not be started (binary absent / not executable). The sidecar is optional
		// enrichment, so degrade to Go-only counting rather than failing the whole inventory.
		return nil, exitUnavailable, nil
	}
	return out, 0, nil
}

// truncate caps sidecar stderr in an error message to a bounded, UTF-8-valid prefix.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
