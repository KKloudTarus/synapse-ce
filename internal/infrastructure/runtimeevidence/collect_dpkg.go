package runtimeevidence

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
)

// collectDpkg resolves, from the Debian package database under the collector root, the packages that own any
// of the loaded objects, returning each such package's full file list (with device+inode). It reads the
// plain-text dpkg metadata directly (no shell): package versions from var/lib/dpkg/status and per-package
// file lists from var/lib/dpkg/info/<pkg>.list.
func (c *Collector) collectDpkg(loadedSet map[string]struct{}) ([]runtimereach.PackageFiles, []runtimereach.CoverageReason) {
	versions, err := c.dpkgVersions()
	if err != nil {
		return nil, []runtimereach.CoverageReason{runtimereach.CoverageUnreadablePackageDB}
	}
	infoDir := filepath.Join(c.root, "var", "lib", "dpkg", "info")
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return nil, []runtimereach.CoverageReason{runtimereach.CoverageUnreadablePackageDB}
	}
	var out []runtimereach.PackageFiles
	var coverage []runtimereach.CoverageReason
	unreadable := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".list") {
			continue
		}
		// The .list basename is "<pkg>[:arch]"; the dpkg package NAME (and the SBOM component name the
		// finding keys on) drops the :arch multiarch qualifier.
		listID := strings.TrimSuffix(entry.Name(), ".list")
		pkgName := listID
		if i := strings.IndexByte(pkgName, ':'); i >= 0 {
			pkgName = pkgName[:i]
		}
		files, owns, readErr := c.dpkgListFiles(filepath.Join(infoDir, entry.Name()), loadedSet)
		if readErr != nil {
			unreadable = true
			continue
		}
		if !owns {
			continue // this package owns none of the loaded objects; skip it (scoped report)
		}
		// Prefer the arch-qualified key: with libc6:amd64 and libc6:i386 both installed at different
		// versions, status has two "Package: libc6" stanzas and a name-only key would keep only the last,
		// attributing one arch's files the other arch's version. The .list basename carries the arch, so
		// listID ("libc6:amd64") selects the right stanza; fall back to the bare name for a single-arch install.
		version := versions[listID]
		if version == "" {
			version = versions[pkgName]
		}
		if version == "" {
			// A package that owns a loaded object but whose version we cannot read cannot be joined to a
			// finding; declare the gap rather than emit an unversioned, unmatchable entry.
			coverage = appendUnique(coverage, runtimereach.CoverageUnreadablePackageDB)
			continue
		}
		out = append(out, runtimereach.PackageFiles{
			Package: runtimereach.PackageRef{Name: pkgName, Version: version},
			Files:   files, // Collect() Normalizes (sorts) before shipping, so no per-package sort here
		})
	}
	if unreadable {
		coverage = appendUnique(coverage, runtimereach.CoverageUnreadablePackageDB)
	}
	return out, coverage
}

// dpkgVersions parses var/lib/dpkg/status into a version map keyed by BOTH the bare package name and the
// arch-qualified "name:arch" form. The status file is a series of blank-line-separated stanzas with
// "Package:", "Version:" and "Architecture:" fields. Keying by name:arch lets a multiarch host (two
// architectures of the same package installed at different versions) resolve each .list to its own version;
// the bare-name key stays for a single-arch install and for a lookup that has no arch. A bare-name key
// under multiarch is last-stanza-wins, which the caller only reaches as a fallback when the arch-qualified
// key is absent.
func (c *Collector) dpkgVersions() (map[string]string, error) {
	f, err := os.Open(filepath.Join(c.root, "var", "lib", "dpkg", "status"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	versions := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	name, version, arch := "", "", ""
	flush := func() {
		if name != "" && version != "" {
			versions[name] = version
			if arch != "" {
				versions[name+":"+arch] = version
			}
		}
		name, version, arch = "", "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Package:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		case strings.HasPrefix(line, "Version:"):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Architecture:"):
			arch = strings.TrimSpace(strings.TrimPrefix(line, "Architecture:"))
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return versions, nil
}

// dpkgListFiles reads one package's .list and, ONLY if the package owns one of the loaded objects, returns
// its owned files with device+inode. It is deliberately two-pass: a cheap first pass reads the paths and
// tests loadedSet membership (a string compare), and the os.Stat per file runs only for the handful of
// packages that own a load. On a host with a few thousand packages the whole database is O(F) file lines
// but only O(files-in-owning-packages) stats, instead of stat'ing (and allocating an OwnedFile for) every
// file of every package each sweep. A .list lists absolute paths, including directories; directories are
// stat'd like any file and contribute their own device+inode, which is harmless for the join (a load is a
// file).
func (c *Collector) dpkgListFiles(listPath string, loadedSet map[string]struct{}) ([]runtimereach.OwnedFile, bool, error) {
	f, err := os.Open(listPath)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	var paths []string
	owns := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		p := cleanLoadPath(sc.Text())
		if p == "" {
			continue
		}
		paths = append(paths, p)
		if _, ok := loadedSet[p]; ok {
			owns = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, false, err
	}
	if !owns {
		return nil, false, nil // owns no loaded object: skip the O(files) stat + allocation entirely
	}
	files := make([]runtimereach.OwnedFile, 0, len(paths))
	for _, p := range paths {
		files = append(files, c.ownedFile(p))
	}
	return files, true, nil
}

func appendUnique(reasons []runtimereach.CoverageReason, r runtimereach.CoverageReason) []runtimereach.CoverageReason {
	for _, existing := range reasons {
		if existing == r {
			return reasons
		}
	}
	return append(reasons, r)
}
