package runtimeevidence

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
)

// collectApk resolves, from the Alpine package database under the collector root, the packages that own any
// of the loaded objects. lib/apk/db/installed is a plain-text record stream: blank-line-separated packages,
// "P:" name, "V:" version, "F:" the current directory (no leading slash), and "R:" a file within it.
func (c *Collector) collectApk(loadedSet map[string]struct{}) ([]runtimereach.PackageFiles, []runtimereach.CoverageReason) {
	f, err := os.Open(filepath.Join(c.root, "lib", "apk", "db", "installed"))
	if err != nil {
		return nil, []runtimereach.CoverageReason{runtimereach.CoverageUnreadablePackageDB}
	}
	defer func() { _ = f.Close() }()

	var out []runtimereach.PackageFiles
	var coverage []runtimereach.CoverageReason
	name, version, dir := "", "", ""
	var paths []string
	owns := false

	// flush stats a package's files ONLY when it owns a loaded object, so the O(files) stat runs for the
	// handful of owning packages, not every installed package each sweep. Collect() Normalizes (sorts)
	// before shipping, so no per-package sort here.
	flush := func() {
		if owns {
			if name == "" || version == "" {
				// The record owns a loaded object but has no usable identity to join a finding on; declare the
				// gap rather than drop it silently (mirrors the dpkg path, keeps coverage honest).
				coverage = appendUnique(coverage, runtimereach.CoverageUnreadablePackageDB)
			} else {
				files := make([]runtimereach.OwnedFile, 0, len(paths))
				for _, p := range paths {
					files = append(files, c.ownedFile(p))
				}
				out = append(out, runtimereach.PackageFiles{Package: runtimereach.PackageRef{Name: name, Version: version}, Files: files})
			}
		}
		name, version, dir, owns, paths = "", "", "", false, nil
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		key, val := line[0], line[2:]
		switch key {
		case 'P':
			name = strings.TrimSpace(val)
		case 'V':
			version = strings.TrimSpace(val)
		case 'F':
			dir = strings.Trim(strings.TrimSpace(val), "/")
		case 'R':
			file := strings.TrimSpace(val)
			if file == "" {
				continue
			}
			p := "/" + file
			if dir != "" {
				p = "/" + dir + "/" + file
			}
			p = path.Clean(p)
			paths = append(paths, p)
			if _, ok := loadedSet[p]; ok {
				owns = true
			}
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, []runtimereach.CoverageReason{runtimereach.CoverageUnreadablePackageDB}
	}
	return out, coverage
}
