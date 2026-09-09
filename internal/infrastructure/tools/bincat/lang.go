package bincat

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// This file extends the rootfs cataloger to the LANGUAGE package inventories an installed image carries on
// disk that a lockfile scan misses: Java archives (the embedded Maven pom.properties, including the
// dependency jars a Spring Boot / WAR / EAR archive nests), installed Node.js packages
// (node_modules/<pkg>/package.json), and installed Ruby gems (the serialized specifications/*.gemspec). Each
// emits a component keyed exactly as the owned advisory matcher expects (pkg:maven/<group>/<artifact>, Name
// "<group>:<artifact>"; pkg:npm/<name>; pkg:gem/<name>) so an OSV/GHSA advisory matches it with no producer
// change. All three are conservative: a component is emitted only when the name AND a CONCRETE version parse
// cleanly, because a wrong version becomes a wrong CVE match.

const (
	maxJarEntries    = 20_000    // central-directory entries allowed per archive (an entry-bomb jar is rejected)
	maxJarPomEntries = 4_096     // pom.properties entries actually READ per archive (bounds total read on a hostile jar)
	maxJarBytes      = 64 << 10  // per-entry uncompressed read cap; a real pom.properties is a few lines
	maxJarFileBytes  = 256 << 20 // reject an implausibly large archive before archive/zip parses its central directory
	maxNestedDepth   = 2         // Spring Boot BOOT-INF/lib/*.jar, WAR WEB-INF/lib, EAR lib/ nest one level; a small margin
	maxNestedJars    = 4_096     // nested archives opened across one top-level jar (bounds a nested-jar bomb)
	maxNestedBytes   = 128 << 20 // total nested-archive bytes read across one top-level jar
	maxPackageBytes  = 1 << 20   // package.json read cap
	maxGemspecBytes  = 1 << 20   // serialized gemspec read cap
	maxMavenCoordLen = 512       // clip an over-long Maven coordinate segment
)

// isJar reports whether path is a Java archive by extension. The ZIP magic is confirmed on open, so a
// mislabeled file simply yields nothing.
func isJar(path string) bool {
	return isArchiveName(path)
}

// isArchiveName reports whether a name has a Java-archive extension (.jar/.war/.ear), used both for the
// top-level file and for nested archives inside it.
func isArchiveName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jar", ".war", ".ear":
		return true
	}
	return false
}

// jarBudget bounds the recursive walk of one top-level archive so a nested-jar bomb cannot exhaust memory.
type jarBudget struct {
	nestedJars  int
	nestedBytes int64
}

// jarComponents reads a Java archive's embedded Maven metadata (META-INF/maven/<group>/<artifact>/
// pom.properties, the coordinate Maven itself writes) into pkg:maven components. A fat/shaded jar embeds one
// pom.properties per bundled dependency; a Spring Boot / WAR / EAR archive instead NESTS its dependency jars
// (BOOT-INF/lib, WEB-INF/lib, lib/), each carrying its own pom.properties, so nested archives are scanned to
// a bounded depth. A non-zip or unreadable file yields nothing.
func jarComponents(path string) (comps []sbom.Component) {
	// archive/zip reads attacker-controlled offsets; recover so one malformed archive in an untrusted image
	// contributes nothing rather than unwinding out of the rootfs walk.
	defer func() {
		if recover() != nil {
			comps = nil
		}
	}()
	// Reject an entry-bomb archive BEFORE archive/zip allocates a record per central-directory entry.
	if n, ok := zipEntryCount(path, maxJarFileBytes); !ok || n > maxJarEntries {
		return nil
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer func() { _ = zr.Close() }()
	seen := map[string]bool{}
	budget := &jarBudget{}
	scanArchiveForMaven(&zr.Reader, 0, seen, budget, &comps)
	return comps
}

// scanArchiveForMaven appends a component for every pom.properties in zr (deduped by PURL via seen) and
// recurses into nested archives up to maxNestedDepth, sharing budget across the whole tree.
func scanArchiveForMaven(zr *zip.Reader, depth int, seen map[string]bool, budget *jarBudget, out *[]sbom.Component) {
	if len(zr.File) > maxJarEntries {
		return // a nested archive whose entry count exceeds the cap (size-bounded already, but bail cheaply)
	}
	pomsRead := 0
	for _, f := range zr.File {
		if pomsRead >= maxJarPomEntries {
			break
		}
		switch {
		case isPomProperties(f.Name):
			if f.UncompressedSize64 > maxJarBytes {
				continue // an implausibly large pom.properties is not the real thing; skip, never a false coord
			}
			pomsRead++
			// Read one byte past the cap: a stream that expands beyond maxJarBytes (a lying UncompressedSize64)
			// is skipped rather than parsed as a truncated prefix, which could carry a wrong version.
			data := readZipEntry(f, maxJarBytes+1)
			if int64(len(data)) > maxJarBytes {
				continue
			}
			group, artifact, version, ok := parsePomProperties(data)
			if !ok {
				continue
			}
			purl := "pkg:maven/" + group + "/" + artifact + "@" + version
			if seen[purl] {
				continue
			}
			seen[purl] = true
			*out = append(*out, sbom.Component{Name: group + ":" + artifact, Version: version, PURL: purl, Scope: sbom.ScopeProduction})
		case depth < maxNestedDepth && isArchiveName(f.Name):
			scanNestedArchive(f, depth, seen, budget, out)
		}
	}
}

// scanNestedArchive reads one nested archive within the shared budget and recurses into it. The nested bytes
// are read into memory (bounded by the remaining budget) because archive/zip needs random access.
func scanNestedArchive(f *zip.File, depth int, seen map[string]bool, budget *jarBudget, out *[]sbom.Component) {
	if budget.nestedJars >= maxNestedJars || budget.nestedBytes >= maxNestedBytes {
		return
	}
	if f.UncompressedSize64 > maxNestedBytes {
		return // a single nested archive larger than the whole budget is not scanned
	}
	remaining := maxNestedBytes - budget.nestedBytes
	data := readZipEntry(f, remaining)
	if len(data) == 0 {
		return
	}
	budget.nestedJars++
	budget.nestedBytes += int64(len(data))
	reader := bytes.NewReader(data)
	// Reject an entry-bomb nested archive BEFORE zip.NewReader pre-allocates a record slice sized to the
	// declared (possibly ZIP64, uint64) central-directory count, exactly as the top-level path does.
	if n, ok := zipCentralDirEntries(reader, int64(len(data)), maxNestedBytes); !ok || n > maxJarEntries {
		return
	}
	nr, err := zip.NewReader(reader, int64(len(data)))
	if err != nil {
		return
	}
	scanArchiveForMaven(nr, depth+1, seen, budget, out)
}

// zipEntryCount opens path and returns its central-directory entry count via zipCentralDirEntries. Returns
// ok=false when the file is larger than sizeCap or the central directory cannot be parsed.
func zipEntryCount(path string, sizeCap int64) (int, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return 0, false
	}
	return zipCentralDirEntries(f, fi.Size(), sizeCap)
}

// zipCentralDirEntries counts the central-directory records in a zip so an entry-bomb archive is rejected
// before archive/zip parses it (a real OOM that recover cannot catch). It does NOT trust the EOCD's declared
// count: archive/zip reads records until the central directory ends regardless of that count, so an attacker
// can under-declare it (count 0) or, in ZIP64, over-declare it to force a huge pre-allocation. Instead this
// walks the central directory from its start offset, counting headers up to maxJarEntries+1 (so the work is
// bounded even on a hostile archive). Returns ok=false when the file exceeds sizeCap or the central directory
// cannot be located/parsed, so an untrustworthy archive is skipped rather than opened.
func zipCentralDirEntries(ra io.ReaderAt, size, sizeCap int64) (int, bool) {
	if size < 22 || size > sizeCap { // 22 bytes is the minimum EOCD record
		return 0, false
	}
	const maxEOCD = 22 + 65535 // EOCD record + maximum trailing comment
	readLen := int64(maxEOCD)
	if readLen > size {
		readLen = size
	}
	tail := make([]byte, readLen)
	if _, err := ra.ReadAt(tail, size-readLen); err != nil {
		return 0, false
	}
	idx := bytes.LastIndex(tail, []byte{0x50, 0x4b, 0x05, 0x06}) // EOCD signature
	if idx < 0 || idx+22 > len(tail) {
		return 0, false
	}
	cdOffset := int64(binary.LittleEndian.Uint32(tail[idx+16 : idx+20]))
	if uint32(cdOffset) == 0xffffffff { // ZIP64: the real CD offset lives in the ZIP64 EOCD record
		loc := bytes.LastIndex(tail[:idx], []byte{0x50, 0x4b, 0x06, 0x07}) // ZIP64 EOCD locator
		if loc < 0 || loc+20 > len(tail) {
			return 0, false
		}
		z64Off := int64(binary.LittleEndian.Uint64(tail[loc+8 : loc+16]))
		if z64Off < 0 || z64Off+56 > size {
			return 0, false
		}
		var z64 [56]byte
		if _, err := ra.ReadAt(z64[:], z64Off); err != nil {
			return 0, false
		}
		if !bytes.Equal(z64[0:4], []byte{0x50, 0x4b, 0x06, 0x06}) { // ZIP64 EOCD signature
			return 0, false
		}
		cdOffset = int64(binary.LittleEndian.Uint64(z64[48:56])) // offset of CD start
	}
	if cdOffset < 0 || cdOffset >= size {
		return 0, false
	}
	// Walk central-directory file headers (sig PK\x01\x02), counting up to the cap; stop at the first
	// non-header signature (end of the central directory) or on a truncated/overrunning record.
	pos := cdOffset
	count := 0
	var hdr [46]byte
	for count <= maxJarEntries {
		if pos+46 > size {
			break
		}
		if _, err := ra.ReadAt(hdr[:], pos); err != nil {
			return 0, false
		}
		if !bytes.Equal(hdr[0:4], []byte{0x50, 0x4b, 0x01, 0x02}) {
			break // reached the EOCD (or ZIP64 EOCD): the central directory has ended
		}
		nameLen := int64(binary.LittleEndian.Uint16(hdr[28:30]))
		extraLen := int64(binary.LittleEndian.Uint16(hdr[30:32]))
		commentLen := int64(binary.LittleEndian.Uint16(hdr[32:34]))
		pos += 46 + nameLen + extraLen + commentLen
		count++
	}
	return count, true
}

// isPomProperties reports whether a zip entry is a Maven-written coordinate file
// (META-INF/maven/<group>/<artifact>/pom.properties).
func isPomProperties(name string) bool {
	return strings.HasPrefix(name, "META-INF/maven/") && strings.HasSuffix(name, "/pom.properties")
}

// readZipEntry reads a zip entry's content up to max bytes; an unopenable entry yields nil.
func readZipEntry(f *zip.File, max int64) []byte {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, max))
	if err != nil {
		return nil
	}
	return data
}

// parsePomProperties parses the Java-properties body of a pom.properties into a Maven coordinate. Only a
// complete, syntactically valid (group, artifact, concrete-version) triple is accepted.
func parsePomProperties(data []byte) (group, artifact, version string, ok bool) {
	if data == nil {
		return "", "", "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "groupId":
			group = v
		case "artifactId":
			artifact = v
		case "version":
			version = v
		}
	}
	if !validMavenSegment(group) || !validMavenSegment(artifact) || !sbom.IsResolvedVersion(version) || !validIdent(version) {
		return "", "", "", false
	}
	return group, artifact, version, true
}

// validMavenSegment reports whether a groupId/artifactId is a safe, bounded PURL segment: non-empty and free
// of the characters that would break the "pkg:maven/<group>/<artifact>@<version>" grammar. A real Maven
// coordinate contains only letters, digits, '.', '-', and '_'.
func validMavenSegment(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxMavenCoordLen {
		return false
	}
	return !strings.ContainsAny(s, "/@?#: \t\r\n%\\") && !hasControl(s)
}

// isNodePackageManifest reports whether path is the root manifest of an INSTALLED Node.js package: a
// package.json whose directory is a package directory directly under a node_modules tree
// (node_modules/<pkg>/package.json or node_modules/@scope/<pkg>/package.json). Restricting to that shape
// avoids cataloging a nested fixture/config package.json (e.g. node_modules/x/test/package.json) as an
// installed dependency.
func isNodePackageManifest(path string) bool {
	if filepath.Base(path) != "package.json" {
		return false
	}
	dir := filepath.Dir(path)                  // .../node_modules/<pkg>  OR  .../node_modules/@scope/<pkg>
	parent := filepath.Base(filepath.Dir(dir)) // node_modules  OR  @scope
	if parent == "node_modules" {
		return true // unscoped: node_modules/<pkg>/package.json
	}
	if strings.HasPrefix(parent, "@") && filepath.Base(filepath.Dir(filepath.Dir(dir))) == "node_modules" {
		return true // scoped: node_modules/@scope/<pkg>/package.json
	}
	return false
}

// nodeComponent parses an installed package.json into a pkg:npm component, trusting the manifest's own name
// (scope preserved) and version. Only a concrete name+version pair is accepted; a workspace/private root
// manifest without a version, or a dist-tag such as "latest", yields nothing.
func nodeComponent(path string) (sbom.Component, bool) {
	data := readBounded(path, maxPackageBytes)
	if data == nil {
		return sbom.Component{}, false
	}
	var manifest struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return sbom.Component{}, false
	}
	name := strings.TrimSpace(manifest.Name)
	version := strings.TrimSpace(manifest.Version)
	if !validNpmName(name) || !sbom.IsResolvedVersion(version) || !validIdent(version) {
		return sbom.Component{}, false
	}
	return sbom.Component{Name: name, Version: version, PURL: "pkg:npm/" + npmPURLName(name) + "@" + version, Scope: sbom.ScopeProduction}, true
}

// npmPURLName percent-encodes the leading '@' of a scoped npm name (@scope/name -> %40scope/name) per the
// PURL spec, matching the owned lockfile producer so a scoped package meets the same advisory key.
func npmPURLName(name string) string {
	if strings.HasPrefix(name, "@") {
		return "%40" + name[1:]
	}
	return name
}

// validNpmName reports whether a name is a plausible npm package id: an optional @scope/ prefix then a
// package segment, bounded, without whitespace/control or PURL-breaking characters beyond the single scope
// separator. Fails closed on anything it cannot key soundly.
func validNpmName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxModulePath {
		return false
	}
	body := name
	if strings.HasPrefix(name, "@") {
		scope, pkg, ok := strings.Cut(name[1:], "/")
		if !ok || scope == "" || pkg == "" || strings.ContainsRune(pkg, '/') {
			return false
		}
		body = scope + pkg
	} else if strings.ContainsRune(name, '/') {
		return false // an unscoped npm name has no slash
	}
	return !strings.ContainsAny(body, "@?# \t\r\n%\\") && !hasControl(body)
}

// isInstalledGemspec reports whether path is a RubyGems-installed spec: a *.gemspec under a specifications/
// directory, or under specifications/default/ where RubyGems keeps DEFAULT gems (rexml, uri, ...). Those
// files are the SERIALIZED spec (Gem::Specification#to_ruby output), not a hand-written source .gemspec, so
// their name/version are literal strings rather than interpolated Ruby.
func isInstalledGemspec(path string) bool {
	if !strings.HasSuffix(path, ".gemspec") {
		return false
	}
	parent := filepath.Base(filepath.Dir(path))
	if parent == "specifications" {
		return true
	}
	return parent == "default" && filepath.Base(filepath.Dir(filepath.Dir(path))) == "specifications"
}

// gemNameRE / gemVersionRE match the serialized-spec assignments RubyGems' to_ruby emits inside
// `Gem::Specification.new do |s| ... end`: `s.name = "rails".freeze` and `s.version = "7.0.4".freeze` (or the
// older `Gem::Version.new("7.0.4")`). The literal-string form is why an installed gemspec is safe to read
// without executing Ruby.
var (
	gemNameRE    = regexp.MustCompile(`(?m)^\s*\w+\.name\s*=\s*"([^"]+)"`)
	gemVersionRE = regexp.MustCompile(`(?m)^\s*\w+\.version\s*=\s*(?:Gem::Version\.new\(\s*)?"([^"]+)"`)
)

// gemComponent parses an installed, serialized gemspec into a pkg:gem component from its literal name and
// version assignments. The version is the clean Gem::Version string (no platform suffix, which lives on a
// separate s.platform line). Only a concrete name+version pair is accepted.
func gemComponent(path string) (sbom.Component, bool) {
	data := readBounded(path, maxGemspecBytes)
	if data == nil {
		return sbom.Component{}, false
	}
	// Require EXACTLY ONE literal s.name and s.version assignment. A serialized (to_ruby) spec has exactly
	// one of each; two or more means this is not a standard installed spec, so fail closed rather than pick a
	// match that disagrees with the value Ruby's last-assignment-wins semantics would load.
	nameMatches := gemNameRE.FindAllSubmatch(data, 2)
	versionMatches := gemVersionRE.FindAllSubmatch(data, 2)
	if len(nameMatches) != 1 || len(versionMatches) != 1 {
		return sbom.Component{}, false
	}
	name := strings.TrimSpace(string(nameMatches[0][1]))
	version := strings.TrimSpace(string(versionMatches[0][1]))
	if !validIdent(name) || !sbom.IsResolvedVersion(version) || !validIdent(version) {
		return sbom.Component{}, false
	}
	return sbom.Component{Name: name, Version: version, PURL: "pkg:gem/" + name + "@" + version, Scope: sbom.ScopeProduction}, true
}
