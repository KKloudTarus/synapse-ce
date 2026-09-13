// Package runtimeevidence is the fleet-agent collector that turns observed shared-library loads into a
// runtime-reachability report (EPIC #1042 #1060/#1061): the OS packages that own the loaded objects, scoped
// to the loaded set, with filesystem identity (device+inode) for the misattribution-safe server-side join.
//
// It reads the host package database directly (dpkg and apk are plain-text and rooted, so the collector is
// testable against a fixture tree and never spawns a shell), and it is coverage-honest: an unreadable or
// unsupported package database is a declared CoverageReason, never a silent partial. Runtime reachability
// is raise-only, so missing evidence forgoes an urgency raise and never hides a finding.
package runtimeevidence

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
)

// Collector resolves package ownership of loaded shared objects under a root ("/" on a real host, a fixture
// tree in tests).
type Collector struct {
	root string
}

// NewCollector returns a collector rooted at root. An empty root defaults to "/".
func NewCollector(root string) *Collector {
	if strings.TrimSpace(root) == "" {
		root = "/"
	}
	return &Collector{root: root}
}

// Collect resolves the OS packages that own the observed loaded shared objects and builds a report scoped
// to those packages, filling device+inode for each owned file and each load. loadedPaths are the absolute
// logical paths the eBPF sensor observed opened (a host path such as /usr/lib/.../libssl.so.3). The report
// is coverage-honest and never errors: an unsupported or unreadable package DB is recorded as a coverage
// reason and yields no packages, which the raise-only join treats as no evidence.
func (c *Collector) Collect(loadedPaths []string) runtimereach.Report {
	loads, loadedSet := c.buildLoads(loadedPaths)
	report := runtimereach.Report{Loads: loads}
	if len(loadedSet) == 0 {
		return report.Normalize()
	}
	switch {
	case c.exists("var/lib/dpkg/status"):
		pkgs, cov := c.collectDpkg(loadedSet)
		report.PackageFiles, report.Coverage = pkgs, cov
	case c.exists("lib/apk/db/installed"):
		pkgs, cov := c.collectApk(loadedSet)
		report.PackageFiles, report.Coverage = pkgs, cov
	case c.exists("var/lib/rpm/rpmdb.sqlite") || c.exists("var/lib/rpm/Packages") || c.exists("var/lib/rpm/Packages.db"):
		// The rpm database is a binary store; file-ownership extraction from it is not yet collected here, so
		// declare the gap rather than pass an rpm host off as "no vulnerable library loaded".
		report.Coverage = []runtimereach.CoverageReason{runtimereach.CoverageUnreadablePackageDB}
	default:
		report.Coverage = []runtimereach.CoverageReason{runtimereach.CoverageUnsupportedPlatform}
	}
	return report.Normalize()
}

// buildLoads converts observed load paths into LoadEvents with filesystem identity, symlink-resolved real
// path, and the deleted marker, and returns the set of cleaned load paths to match ownership against.
//
// The device+inode is stat'd HERE, at sweep time, not captured at the observed open: the library-load
// sensor (#1060) reports only the path, so a file replaced between the open and the sweep (a package
// upgrade in that window) resolves to the CURRENT owner of the path. This is raise-only safe: the worst
// case is raising the finding of the version now at that path instead of the one that briefly loaded, a
// precision loss in the raise direction, never a suppression. An unlinked file is caught by the "(deleted)"
// marker; capturing load-time identity would require the eBPF program to emit dev+inode, a #1060 change.
func (c *Collector) buildLoads(loadedPaths []string) ([]runtimereach.LoadEvent, map[string]struct{}) {
	set := make(map[string]struct{}, len(loadedPaths))
	loads := make([]runtimereach.LoadEvent, 0, len(loadedPaths))
	seen := map[string]struct{}{}
	for _, raw := range loadedPaths {
		deleted := strings.HasSuffix(strings.TrimSpace(raw), " (deleted)")
		p := cleanLoadPath(raw)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		set[p] = struct{}{}
		ev := runtimereach.LoadEvent{Path: p, Deleted: deleted}
		abs := filepath.Join(c.root, filepath.FromSlash(p))
		if id, ok := fileID(abs); ok {
			ev.ID = id
		}
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			if logical := c.logicalPath(real); logical != "" && logical != p {
				ev.RealPath = logical
				// The package database records the file under its REAL path (on a usrmerge host a load of
				// /lib/x/libc.so.6 is recorded as /usr/lib/x/libc.so.6). Match ownership against the real path
				// too so the owning package is scoped in; the server-side join then confirms by device+inode.
				set[logical] = struct{}{}
			}
		}
		loads = append(loads, ev)
	}
	return loads, set
}

// logicalPath maps an absolute on-disk path back to the host-logical path by stripping the collector root,
// so a fixture-tree scan reports the same paths a real "/" scan would.
func (c *Collector) logicalPath(abs string) string {
	if c.root == "/" || c.root == "" {
		return filepath.ToSlash(abs)
	}
	rel, err := filepath.Rel(c.root, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	return "/" + filepath.ToSlash(rel)
}

func (c *Collector) exists(rel string) bool {
	_, err := os.Stat(filepath.Join(c.root, filepath.FromSlash(rel)))
	return err == nil
}

// ownedFile builds an OwnedFile for a package's logical file path, filling device+inode from the on-disk
// file under the root when it can be stat'd.
func (c *Collector) ownedFile(logical string) runtimereach.OwnedFile {
	f := runtimereach.OwnedFile{Path: logical}
	if id, ok := fileID(filepath.Join(c.root, filepath.FromSlash(logical))); ok {
		f.ID = id
	}
	return f
}

// cleanLoadPath normalizes an observed load path: trims the kernel "(deleted)" marker, collapses duplicate
// separators, and keeps it absolute. It mirrors the server-side cleanPath so an agent load and a package
// file compare identically.
func cleanLoadPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimSuffix(p, " (deleted)")
	p = strings.TrimSpace(p)
	if p == "" || !strings.HasPrefix(p, "/") {
		return ""
	}
	return path.Clean(p)
}
