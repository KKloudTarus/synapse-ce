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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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

// New returns a provider using the given synapse-ast binary. An empty bin triggers zero-setup discovery
// (resolveSidecar): the sidecar shipped ALONGSIDE the running executable is used automatically, so a
// distribution that bundles synapse-cli + synapse-ast "just works" with no SYNAPSE_AST_BIN and no PATH
// entry; otherwise it falls back to "synapse-ast" resolved on PATH by exec.
func New(bin string) *Provider {
	if strings.TrimSpace(bin) == "" {
		bin = resolveSidecar()
	}
	return &Provider{bin: bin}
}

// sidecarName is the sidecar executable's basename for the current OS.
func sidecarName() string {
	if runtime.GOOS == "windows" {
		return "synapse-ast.exe"
	}
	return "synapse-ast"
}

// resolveSidecar finds the synapse-ast sidecar with zero configuration. It prefers a copy sitting next to
// the running executable (the common "bundled distribution" layout), then the plain name for a PATH
// lookup at exec time. Returning the bare name (not "") keeps the existing behavior when nothing is
// bundled: a missing binary later degrades to available=false, never an error.
func resolveSidecar() string {
	exe, err := os.Executable()
	if err != nil {
		return sidecarName()
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return resolveSidecarIn(filepath.Dir(exe))
}

// ResolveSidecar exposes the same zero-configuration sidecar discovery used by Provider. It is useful for
// read-only preflight surfaces that need to report whether a bundled synapse-ast binary is discoverable
// without actually parsing a target tree.
func ResolveSidecar() string {
	return resolveSidecar()
}

// resolveSidecarIn returns the bundled sidecar path if a runnable copy exists in exeDir, else the bare
// name (PATH lookup at exec time). Split out from resolveSidecar so the discovery logic is unit-testable.
// It requires a regular, executable file: a non-executable stub (0-byte / partial download / wrong perms)
// next to the launcher must NOT shadow a working copy on PATH — falling through lets PATH still resolve.
func resolveSidecarIn(exeDir string) string {
	cand := filepath.Join(exeDir, sidecarName())
	if fi, err := os.Stat(cand); err == nil && fi.Mode().IsRegular() {
		if runtime.GOOS == "windows" || fi.Mode().Perm()&0o111 != 0 { // exec bit is meaningless on Windows
			return cand
		}
	}
	return sidecarName()
}

// WithRunner confines the sidecar via a ToolRunner (the SandboxRunner) – recommended in production, since
// the binary parses untrusted target source. nil keeps the direct-exec dev path. The target is bound
// read-only. Unlike synapse-callgraph, cgo is NOT disabled: the tree-sitter backend requires it.
func (p *Provider) WithRunner(r ports.ToolRunner) *Provider { p.runner = r; return p }

var (
	_ ports.ASTProvider         = (*Provider)(nil)
	_ ports.CodeMetricsProvider = (*Provider)(nil)
	_ ports.BugDetector         = (*Provider)(nil)
	_ ports.CodeAnalyzer        = (*Provider)(nil)
)

// FunctionCounts runs `synapse-ast functions <root>` and returns per-language function counts. A sidecar
// built without the tree-sitter backend exits exitUnavailable, which maps to (nil, false, nil) so the
// caller falls back to its own counting rather than treating it as an error.
func (p *Provider) FunctionCounts(ctx context.Context, root string) (map[string]int, bool, error) {
	if strings.TrimSpace(root) == "" {
		return nil, false, nil
	}
	out, exit, err := p.run(ctx, "functions", root)
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

// Complexity runs `synapse-ast metrics <root>` and returns per-function cyclomatic + cognitive complexity.
// A sidecar built without the tree-sitter backend (or an absent binary) maps to available=false so the
// caller degrades rather than erroring.
func (p *Provider) Complexity(ctx context.Context, root string) (measure.ComplexityReport, bool, error) {
	if strings.TrimSpace(root) == "" {
		return measure.ComplexityReport{}, false, nil
	}
	out, exit, err := p.run(ctx, "metrics", root)
	if exit == exitUnavailable {
		return measure.ComplexityReport{}, false, nil
	}
	if err != nil {
		return measure.ComplexityReport{}, false, err
	}
	var wire struct {
		Functions []measure.FunctionComplexity `json:"functions"`
		Truncated bool                         `json:"truncated"`
	}
	if err := json.Unmarshal(out, &wire); err != nil {
		return measure.ComplexityReport{}, false, fmt.Errorf("parse synapse-ast metrics: %w", err)
	}
	return measure.ComplexityReport{Functions: wire.Functions, Truncated: wire.Truncated}, true, nil
}

// Bugs runs `synapse-ast bugs <root>` and returns the deterministic reliability defects. A sidecar built
// without the tree-sitter backend (or an absent binary) maps to available=false so the caller degrades.
func (p *Provider) Bugs(ctx context.Context, root string) ([]ports.BugFinding, bool, error) {
	if strings.TrimSpace(root) == "" {
		return nil, false, nil
	}
	out, exit, err := p.run(ctx, "bugs", root)
	if exit == exitUnavailable {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var wire struct {
		Bugs []struct {
			File    string `json:"file"`
			Line    int    `json:"line"`
			Rule    string `json:"rule"`
			Message string `json:"message"`
		} `json:"bugs"`
	}
	if err := json.Unmarshal(out, &wire); err != nil {
		return nil, false, fmt.Errorf("parse synapse-ast bugs: %w", err)
	}
	findings := make([]ports.BugFinding, 0, len(wire.Bugs))
	for _, b := range wire.Bugs {
		findings = append(findings, ports.BugFinding{Rule: b.Rule, Message: b.Message, File: b.File, Line: b.Line})
	}
	return findings, true, nil
}

// Analyze runs `synapse-ast quality <root>` and returns language-aware structural findings. An absent or
// CGO-free sidecar is optional enrichment and returns no findings without an error.
func (p *Provider) Analyze(ctx context.Context, root string) ([]ports.CodeAnalysisRawFinding, error) {
	if strings.TrimSpace(root) == "" {
		return nil, nil
	}
	out, exit, err := p.run(ctx, "quality", root)
	if exit == exitUnavailable {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var wire struct {
		Findings []struct {
			Kind        string          `json:"kind"`
			Rule        string          `json:"rule"`
			CWE         string          `json:"cwe"`
			Severity    shared.Severity `json:"severity"`
			Title       string          `json:"title"`
			Description string          `json:"description"`
			File        string          `json:"file"`
			Line        int             `json:"line"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &wire); err != nil {
		return nil, fmt.Errorf("parse synapse-ast quality: %w", err)
	}
	findings := make([]ports.CodeAnalysisRawFinding, 0, len(wire.Findings))
	for _, f := range wire.Findings {
		findings = append(findings, ports.CodeAnalysisRawFinding{Kind: f.Kind, RuleID: f.Rule, CWE: f.CWE, Severity: f.Severity, Title: f.Title, Description: f.Description, File: f.File, Line: f.Line})
	}
	return findings, nil
}

// run executes the sidecar (sandboxed when a runner is set, else direct os/exec) and returns stdout, the
// process exit code, and any error. argv only (no shell).
func (p *Provider) run(ctx context.Context, cmd, root string) ([]byte, int, error) {
	args := []string{cmd, root}
	if p.runner != nil {
		res, err := p.runner.Run(ctx, ports.ToolSpec{
			Name:          p.bin,
			Args:          args,
			ReadOnlyPaths: []string{root},
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			if res.TimedOut {
				return nil, 0, err
			}
			// The sidecar could not be run (absent binary / sandbox setup). Like the direct path, degrade
			// to unavailable rather than failing the inventory – this provider is optional enrichment.
			return nil, exitUnavailable, nil
		}
		if res.ExitCode != 0 && res.ExitCode != exitUnavailable {
			return nil, res.ExitCode, fmt.Errorf("synapse-ast %q: exit %d: %s", root, res.ExitCode, truncate(string(res.Stderr), 300))
		}
		return res.Stdout, res.ExitCode, nil
	}
	var stderr bytes.Buffer
	ec := exec.CommandContext(ctx, p.bin, args...)
	ec.Stderr = &stderr
	out, err := ec.Output()
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
