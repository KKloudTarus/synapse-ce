// Package sandboxcheck runs conformance checks through the production sandbox runner.
package sandboxcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/platform/binregistry"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Status string

const (
	StatusPass       Status = "pass"
	StatusFail       Status = "fail"
	StatusUnenforced Status = "unenforced"
)

type CheckResult struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Status   Status `json:"status"`
	Detail   string `json:"detail"`
}

type Report struct {
	Mode                 string        `json:"mode"`
	Strict               bool          `json:"strict"`
	CgroupLimitsEnforced bool          `json:"cgroupLimitsEnforced"`
	Checks               []CheckResult `json:"checks"`
}

type conformanceVault struct{}

func (conformanceVault) Put(context.Context, shared.ID, string, []byte) error {
	return errors.New("conformance vault is read-only")
}

func (conformanceVault) Resolve(_ context.Context, _ shared.ID, name string) ([]byte, error) {
	if name != "REDACTION_MARKER" {
		return nil, fmt.Errorf("unknown conformance secret %q", name)
	}
	return []byte("synapse-conformance-redaction-marker"), nil
}

func (conformanceVault) List(context.Context, shared.ID) ([]ports.CredentialMeta, error) {
	return nil, nil
}

func (conformanceVault) Delete(context.Context, shared.ID, string) error {
	return errors.New("conformance vault is read-only")
}

type checkSpec struct {
	name     string
	category string
	spec     ports.ToolSpec
	evaluate func(ports.ToolResult, error) CheckResult
}

func Run(mode string, strict bool, readyWait time.Duration) (Report, error) {
	cfg := config.Load()
	// Strict conformance gates whether the worker may start at all. At first boot the
	// delegated memory and PID controllers can appear moments after the unit starts,
	// so wait a bounded time without weakening the fail-closed outcome.
	var runner *sandbox.Runner
	var err error
	if strict && readyWait > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), readyWait)
		defer cancel()
		runner, err = sandbox.NewRunnerReady(ctx, cfg.ReconTimeout, cfg.ReconMaxOutput, cfg.SandboxMemMax, cfg.SandboxPidsMax, 250*time.Millisecond)
	} else {
		runner, err = sandbox.NewRunner(cfg.ReconTimeout, cfg.ReconMaxOutput, cfg.SandboxMemMax, cfg.SandboxPidsMax)
	}
	if err != nil {
		return Report{}, fmt.Errorf("construct production sandbox runner: %w", err)
	}
	runner.SetVault(conformanceVault{})
	self, err := os.Executable()
	if err != nil {
		return Report{}, fmt.Errorf("resolve conformance executable: %w", err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return Report{}, fmt.Errorf("resolve conformance executable symlink: %w", err)
	}
	startupWorkdir, err := os.MkdirTemp("", "synapse-sandbox-startup-")
	if err != nil {
		return Report{}, fmt.Errorf("create startup sandbox workdir: %w", err)
	}
	defer os.RemoveAll(startupWorkdir)

	r := Report{Mode: mode, Strict: strict, CgroupLimitsEnforced: runner.CgroupLimitsEnforced()}
	r.Checks = append(r.Checks, runCheck(runner, trueSpec(startupWorkdir)))
	r.Checks = append(r.Checks, runCheck(runner, probeSpec(self, "capabilities")))
	r.Checks = append(r.Checks, runCheck(runner, probeSpec(self, "network")))
	if mode == "full" {
		r.Checks = append(r.Checks, fullChecks(runner, self)...)
	}
	return r, nil
}

func BaseSpec(name string) ports.ToolSpec {
	return ports.ToolSpec{Name: name, CapAdd: nil, EgressPolicy: nil, HostNetwork: false}
}

func ProbeSpec(self, probe string, extra ...string) ports.ToolSpec {
	return probeSpec(self, probe, extra...).spec
}

func trueSpec(workdir string) checkSpec {
	return checkSpec{name: "runner-ready", category: "startup", spec: ports.ToolSpec{Name: "/bin/true", Workdir: workdir}, evaluate: func(res ports.ToolResult, err error) CheckResult {
		if err != nil || res.ExitCode != 0 {
			return FailResult("runner-ready", "startup", resultDetail(err, res))
		}
		return PassResult("runner-ready", "startup", "production runner executed /bin/true")
	}}
}

func probeSpec(self, probe string, extra ...string) checkSpec {
	spec := BaseSpec(self)
	spec.Args = append([]string{"-probe=" + probe}, extra...)
	return checkSpec{name: probe, category: probeCategory(probe), spec: spec, evaluate: func(res ports.ToolResult, err error) CheckResult {
		if err != nil || res.ExitCode != 0 || !strings.Contains(string(res.Stdout), "PASS") {
			return FailResult(probe, probeCategory(probe), resultDetail(err, res))
		}
		return PassResult(probe, probeCategory(probe), probeDetail(probe))
	}}
}

func probeCategory(probe string) string {
	switch probe {
	case "capabilities":
		return "capability"
	case "network":
		return "network"
	case "seccomp":
		return "syscall"
	default:
		return "filesystem"
	}
}

func probeDetail(probe string) string {
	switch probe {
	case "capabilities":
		return "effective capabilities are empty"
	case "network":
		return "default-deny network namespace blocked outbound TCP"
	case "seccomp":
		return "ptrace syscall was denied by the seccomp allowlist"
	default:
		return "probe completed"
	}
}

func fullChecks(runner *sandbox.Runner, self string) []CheckResult {
	work, err := os.MkdirTemp("", "synapse-sandbox-work-")
	if err != nil {
		return []CheckResult{FailResult("filesystem", "filesystem", "create temporary workdir: "+redact.String(err.Error(), nil))}
	}
	defer os.RemoveAll(work)
	hiddenDir, err := os.MkdirTemp("", "synapse-sandbox-hidden-")
	if err != nil {
		return []CheckResult{FailResult("filesystem", "filesystem", "create temporary hidden path: "+redact.String(err.Error(), nil))}
	}
	defer os.RemoveAll(hiddenDir)
	hiddenPath := filepath.Join(hiddenDir, "host-only")
	if err := os.WriteFile(hiddenPath, []byte("conformance host-only"), 0o600); err != nil {
		return []CheckResult{FailResult("filesystem", "filesystem", "prepare unreadable host path: "+redact.String(err.Error(), nil))}
	}

	filesystem := probeSpec(self, "filesystem", "-workdir="+work, "-hidden="+hiddenPath)
	filesystem.name, filesystem.category = "filesystem", "filesystem"
	filesystem.spec.Workdir = work
	filesystem.evaluate = func(res ports.ToolResult, err error) CheckResult {
		if err != nil || res.ExitCode != 0 || !strings.Contains(string(res.Stdout), "PASS") {
			return FailResult("filesystem", "filesystem", resultDetail(err, res))
		}
		return PassResult("filesystem", "filesystem", "declared workdir writable; root read-only; unbound host path unreadable")
	}

	checks := []CheckResult{runCheck(runner, filesystem), runCheck(runner, probeSpec(self, "seccomp"))}
	checks = append(checks, runCheck(runner, timeoutSpec(self)))
	if runner.CgroupLimitsEnforced() {
		checks = append(checks, runCheck(runner, pidsSpec(self)), runCheck(runner, memorySpec(self)))
	} else {
		checks = append(checks,
			UnenforcedResult("pids-limit", "resource", "delegated cgroup and systemd-run limits are unavailable"),
			UnenforcedResult("memory-limit", "resource", "delegated cgroup and systemd-run limits are unavailable"),
		)
	}
	checks = append(checks, integrityCheck(runner, self), runCheck(runner, outputSpec(self)), runCheck(runner, redactionSpec(self)), runCheck(runner, recoverySpec(self)))
	return checks
}

func timeoutSpec(self string) checkSpec {
	spec := BaseSpec(self)
	spec.Args = []string{"-probe=sleep"}
	spec.Timeout = 100 * time.Millisecond
	return checkSpec{name: "timeout", category: "resource", spec: spec, evaluate: func(res ports.ToolResult, err error) CheckResult {
		if !res.TimedOut {
			return FailResult("timeout", "resource", resultDetail(err, res))
		}
		return PassResult("timeout", "resource", "long-running tool was killed at its timeout")
	}}
}

func pidsSpec(self string) checkSpec {
	spec := BaseSpec(self)
	spec.Args = []string{"-probe=pids"}
	spec.PidsMax = 32
	return checkSpec{name: "pids-limit", category: "resource", spec: spec, evaluate: func(res ports.ToolResult, err error) CheckResult {
		if err != nil || res.ExitCode != 0 || !strings.Contains(string(res.Stdout), "PIDS_BLOCKED") {
			return FailResult("pids-limit", "resource", resultDetail(err, res))
		}
		return PassResult("pids-limit", "resource", "pids.max prevented additional child processes")
	}}
}

func memorySpec(self string) checkSpec {
	spec := BaseSpec(self)
	spec.Args = []string{"-probe=memory"}
	spec.MemMaxBytes = 64 << 20
	spec.Timeout = 10 * time.Second
	return checkSpec{name: "memory-limit", category: "resource", spec: spec, evaluate: func(res ports.ToolResult, err error) CheckResult {
		if err != nil || res.ExitCode == 0 || res.TimedOut {
			return FailResult("memory-limit", "resource", resultDetail(err, res))
		}
		return PassResult("memory-limit", "resource", "memory.max terminated the allocating tool")
	}}
}

func outputSpec(self string) checkSpec {
	spec := BaseSpec(self)
	spec.Args = []string{"-probe=output", "-bytes=8192"}
	spec.MaxOutputBytes = 128
	return checkSpec{name: "output-truncation", category: "output", spec: spec, evaluate: func(res ports.ToolResult, err error) CheckResult {
		if err != nil || res.ExitCode != 0 || !res.Truncated {
			return FailResult("output-truncation", "output", resultDetail(err, res))
		}
		return PassResult("output-truncation", "output", "output cap set Truncated")
	}}
}

func redactionSpec(self string) checkSpec {
	const secret = "synapse-conformance-redaction-marker"
	spec := BaseSpec(self)
	spec.Args = []string{"-probe=redaction"}
	spec.Env = []string{"SYNAPSE_PROBE_SECRET={{secret:REDACTION_MARKER}}"}
	return checkSpec{name: "secret-redaction", category: "output", spec: spec, evaluate: func(res ports.ToolResult, err error) CheckResult {
		output := append(append([]byte(nil), res.Stdout...), res.Stderr...)
		if err != nil || res.ExitCode != 0 || bytes.Contains(output, []byte(secret)) || !bytes.Contains(output, []byte(redact.Placeholder)) {
			return FailResult("secret-redaction", "output", resultDetail(err, res))
		}
		return PassResult("secret-redaction", "output", "resolved secret was redacted from captured output")
	}}
}

func recoverySpec(self string) checkSpec {
	spec := BaseSpec(self)
	spec.Args = []string{"-probe=ok"}
	return checkSpec{name: "recovery", category: "recovery", spec: spec, evaluate: func(res ports.ToolResult, err error) CheckResult {
		if err != nil || res.ExitCode != 0 || !strings.Contains(string(res.Stdout), "PASS") {
			return FailResult("recovery", "recovery", resultDetail(err, res))
		}
		return PassResult("recovery", "recovery", "healthy tool completed after denied and killed probes")
	}}
}

func integrityCheck(runner *sandbox.Runner, self string) CheckResult {
	dir, err := os.MkdirTemp("", "synapse-sandbox-integrity-")
	if err != nil {
		return FailResult("binary-integrity", "integrity", "create temporary tool: "+redact.String(err.Error(), nil))
	}
	defer os.RemoveAll(dir)
	copyPath := filepath.Join(dir, "probe")
	contents, err := os.ReadFile(self)
	if err != nil {
		return FailResult("binary-integrity", "integrity", "read conformance executable: "+redact.String(err.Error(), nil))
	}
	if err := os.WriteFile(copyPath, contents, 0o755); err != nil {
		return FailResult("binary-integrity", "integrity", "write temporary tool: "+redact.String(err.Error(), nil))
	}
	runner.SetBinaryRegistry(binregistry.New(nil, true))
	if _, err := runner.Run(context.Background(), ports.ToolSpec{Name: copyPath, Args: []string{"-probe=ok"}, Workdir: dir}); err != nil {
		return FailResult("binary-integrity", "integrity", "initial binary pin failed: "+redact.String(err.Error(), nil))
	}
	if err := os.WriteFile(copyPath, append(contents, '\n'), 0o755); err != nil {
		return FailResult("binary-integrity", "integrity", "tamper temporary tool: "+redact.String(err.Error(), nil))
	}
	_, err = runner.Run(context.Background(), ports.ToolSpec{Name: copyPath, Args: []string{"-probe=ok"}, Workdir: dir})
	if !errors.Is(err, shared.ErrValidation) {
		return FailResult("binary-integrity", "integrity", "tampered binary was not rejected")
	}
	return PassResult("binary-integrity", "integrity", "tampered TOFU-pinned binary was rejected before execution")
}

func runCheck(runner *sandbox.Runner, c checkSpec) CheckResult {
	res, err := runner.Run(context.Background(), c.spec)
	return c.evaluate(res, err)
}

func PassResult(name, category, detail string) CheckResult {
	return CheckResult{Name: name, Category: category, Status: StatusPass, Detail: redact.String(detail, nil)}
}

func FailResult(name, category, detail string) CheckResult {
	return CheckResult{Name: name, Category: category, Status: StatusFail, Detail: redact.String(detail, nil)}
}

func UnenforcedResult(name, category, detail string) CheckResult {
	return CheckResult{Name: name, Category: category, Status: StatusUnenforced, Detail: redact.String(detail, nil)}
}

func resultDetail(err error, res ports.ToolResult) string {
	parts := []string{fmt.Sprintf("exit=%d timedOut=%t truncated=%t", res.ExitCode, res.TimedOut, res.Truncated)}
	if err != nil {
		parts = append(parts, redact.String(err.Error(), nil))
	}
	return strings.Join(parts, "; ")
}

func Failed(r Report) bool {
	if r.Strict {
		for _, c := range r.Checks {
			if c.Status == StatusUnenforced {
				return true
			}
		}
	}
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return true
		}
	}
	return false
}

func WriteReport(path string, r Report, stdout, stderr io.Writer) error {
	if path == "" {
		return writeSummary(stdout, r)
	}
	var out io.Writer = stdout
	var file *os.File
	if path != "-" {
		var err error
		file, err = os.Create(path)
		if err != nil {
			return fmt.Errorf("create JSON report: %w", err)
		}
		defer file.Close()
		out = file
	}
	if err := json.NewEncoder(out).Encode(r); err != nil {
		return fmt.Errorf("encode JSON report: %w", err)
	}
	if file != nil {
		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync JSON report: %w", err)
		}
		return writeSummary(stdout, r)
	}
	return writeSummary(stderr, r)
}

func writeSummary(w io.Writer, r Report) error {
	if _, err := fmt.Fprintf(w, "sandbox conformance mode=%s strict=%t cgroupLimitsEnforced=%t\n", r.Mode, r.Strict, r.CgroupLimitsEnforced); err != nil {
		return fmt.Errorf("write summary header: %w", err)
	}
	for _, c := range r.Checks {
		if _, err := fmt.Fprintf(w, "%s %-20s %-12s %s\n", c.Status, c.Category, c.Name, c.Detail); err != nil {
			return fmt.Errorf("write summary result: %w", err)
		}
	}
	return nil
}
