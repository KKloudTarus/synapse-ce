package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

// processReportAPI is optional so the run-loop test doubles need not implement it. The production fleet
// client satisfies it. The behavior baseline (#594 D) had no input before this: the agent shipped host
// packages but never its processes.
type processReportAPI interface {
	ReportProcesses(ctx context.Context, token string, procs []fleetclient.ReportedProcess, complete bool) error
}

// maxReportedProcesses caps one report from the agent side, mirroring the server cap so a report is never
// rejected for size. The baseline features saturate far below this.
const maxReportedProcesses = 4096

// collectProcesses enumerates the host's live processes from a procfs-style tree (default /proc): one
// entry per numeric pid, with its command (comm) and resolved executable path (exe). It reads only
// metadata, never process memory, and never executes anything. On a platform without /proc it finds no
// entries and returns an empty slice, so the caller simply reports nothing. Errors on individual
// processes (a pid that exited mid-scan, an exe link the agent may not resolve) are skipped, not fatal.
func collectProcesses(procRoot string) []fleetclient.ReportedProcess {
	if procRoot == "" {
		procRoot = "/proc"
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	out := make([]fleetclient.ReportedProcess, 0, 256)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue // only numeric pid directories are processes
		}
		p := fleetclient.ReportedProcess{PID: pid, Running: true}
		if comm, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm")); err == nil {
			p.Comm = strings.TrimSpace(string(comm))
		}
		if exe, err := os.Readlink(filepath.Join(procRoot, e.Name(), "exe")); err == nil {
			p.Path = exe
		}
		out = append(out, p)
		if len(out) >= maxReportedProcesses {
			break
		}
	}
	return out
}

// reportProcesses ships the host's running-process snapshot for the behavior baseline. Best-effort: a
// failure is logged and retried on the next sweep, never blocking the agent. It runs only after the
// inventory report has bound the host asset (the server resolves the asset from the agent, and refuses a
// report before the binding exists), and only when the client supports it.
func (r *runner) reportProcesses(ctx context.Context, cred fleetclient.Credential) {
	if !r.cfg.processReportEnabled {
		return
	}
	client, ok := r.api.(processReportAPI)
	if !ok {
		return
	}
	procs := collectProcesses(r.cfg.procRoot)
	if len(procs) == 0 {
		return // nothing to report (or no procfs on this platform); never send a spurious empty clear
	}
	// complete = the agent enumerated every live process (it did not hit its cap), so the server may
	// replace the host's running set and retire processes that exited since the last sweep.
	complete := len(procs) < maxReportedProcesses
	if err := client.ReportProcesses(ctx, cred.Token, procs, complete); err != nil {
		log.Printf("process report: %v", err)
	}
}
