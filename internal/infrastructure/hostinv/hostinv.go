// Package hostinv collects a fleet VM agent's host inventory (#410): host facts and installed OS
// packages, read from the host filesystem under a configurable root. It REUSES the engine's owned
// OS-package cataloger (internal/infrastructure/tools/ospkg) rather than reimplementing package
// parsing, and adds the coverage honesty the cataloger does not: an unreadable database or an
// absent one becomes an explicit CoverageIssue so a partial inventory is never reported as complete.
//
// Collection is path-based and read-only: it only reads files under root and never spawns a shell.
// Listeners/services (procfs, systemd), local-config evaluation, and source-tree scanning are
// deferred follow-ups; this package delivers the facts + package surface.
package hostinv

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ospkg"
)

// notCollectedDimensions are host-assessment dimensions the scan.host capability is meant to cover but
// that this agent release does not yet gather (#410 requirements 2/4/5). They are declared as explicit
// coverage issues so the platform never implies they were assessed and found empty — the exact
// silent-partial failure the hostinventory model exists to prevent. Collection lands in follow-ups.
var notCollectedDimensions = []string{
	"listening-sockets",
	"running-services",
	"local-configuration",
	"source-tree",
}

// Collect reads the host inventory under root ("/" on a real host; a fixture dir in tests). It never
// returns a partial result silently: every gap is a coverage issue and Normalize derives Complete.
func Collect(ctx context.Context, root string) (hostinventory.HostInventory, error) {
	if err := ctx.Err(); err != nil {
		return hostinventory.HostInventory{}, err
	}
	var inv hostinventory.HostInventory
	inv.Facts = collectFacts(root, &inv)

	res, err := ospkg.New().Catalog(ctx, root)
	if err != nil {
		return hostinventory.HostInventory{}, fmt.Errorf("hostinv: catalog packages: %w", err) // context cancellation only
	}
	inv.Packages = res.Components
	addPackageCoverage(root, &inv)
	for _, dim := range notCollectedDimensions {
		inv.AddIssue(hostinventory.CoverageNotCollected, dim+": not collected by this agent release")
	}
	return inv.Normalize(), nil
}

func collectFacts(root string, inv *hostinventory.HostInventory) hostinventory.HostFacts {
	f := hostinventory.HostFacts{OS: runtime.GOOS, Arch: runtime.GOARCH}
	if h, err := os.Hostname(); err == nil {
		f.Hostname = h
	}
	if v := osReleaseVersion(filepath.Join(root, "etc/os-release")); v != "" {
		f.OSVersion = v
	} else {
		inv.AddIssue(hostinventory.CoverageMissingFact, "etc/os-release not readable")
	}
	if id := firstLine(filepath.Join(root, "etc/machine-id")); id != "" {
		f.MachineID = id
	} else {
		inv.AddIssue(hostinventory.CoverageMissingFact, "etc/machine-id not readable")
	}
	if k := firstLine(filepath.Join(root, "proc/sys/kernel/osrelease")); k != "" {
		f.Kernel = k
	}
	return f
}

// addPackageCoverage records a coverage issue for any package DB that is present but unreadable, and
// for the case where no supported database exists at all (so an empty package list is never silently
// treated as "nothing installed"). Lstat + a regular-file guard mirror the cataloger: it reads only
// regular files, so a DB path that exists as a symlink or directory is a present-but-unreadable DB
// (degraded coverage), not a "found and read" one — recording it here closes the silent-gap where the
// cataloger would emit zero packages from such a path with no coverage signal.
func addPackageCoverage(root string, inv *hostinventory.HostInventory) {
	found := false
	for _, rel := range ospkg.SupportedDBPaths() {
		p := filepath.Join(root, rel)
		info, err := os.Lstat(p)
		if err != nil {
			continue // absent is fine; only a present-but-unreadable DB is an issue
		}
		found = true
		if !info.Mode().IsRegular() {
			// Present but not a regular file: the cataloger will not read it -> untrustworthy (degraded).
			inv.AddIssue(hostinventory.CoverageUnreadableDB, rel+": not a regular file")
			continue
		}
		if fh, oerr := os.Open(p); oerr != nil {
			inv.AddIssue(hostinventory.CoverageUnreadableDB, rel+": "+oerr.Error())
		} else {
			_ = fh.Close()
		}
	}
	if !found {
		inv.AddIssue(hostinventory.CoverageNoPackageDB, "no supported OS package database found under root")
	}
}

func osReleaseVersion(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "VERSION_ID="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func firstLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
}
