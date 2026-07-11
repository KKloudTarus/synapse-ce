// Package mavencoord recovers authoritative Maven coordinates for SBOM components
// whose groupId was mis-derived during SBOM generation. Syft, scanning a packaged
// app (a fat JAR or a container filesystem) without reliable pom metadata, infers the
// groupId from a JAR's Java package namespace – e.g. "io.grpc.internal" instead of
// "io.grpc", "org.aspectj.weaver" instead of "org.aspectj". A wrong group makes the
// downstream registry license lookup (deps.dev) 404, so the license stays "unknown"
// even though the package is published under a known license.
//
// The fix is deterministic and offline: every Maven JAR embeds its real coordinates in
// META-INF/maven/<group>/<artifact>/pom.properties. This resolver walks the prepared
// workspace, reads those properties from each JAR (descending one level into nested
// JARs, e.g. a Spring Boot BOOT-INF/lib/*.jar), and corrects the component PURL in
// place so the registry lookup hits the right package. It only ever READS files (no
// exec, no network) and is bounded against pathological inputs.
package mavencoord

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxJARs          = 20000    // bound the workspace walk (total workspace size is already capped upstream)
	maxNestedBytes   = 96 << 20 // read a nested JAR into memory only if under this size
	maxEntriesPerJAR = 100000   // bound entries scanned per archive
	maxPropsBytes    = 1 << 20  // a pom.properties is tiny; cap the read defensively
)

// Resolver corrects mis-derived Maven groupIds from embedded pom.properties.
type Resolver struct{}

// New returns a resolver.
func New() *Resolver { return &Resolver{} }

var _ ports.MavenCoordResolver = (*Resolver)(nil)

// Resolve reads JAR pom.properties under wsDir and corrects each Maven component's PURL
// group when it disagrees with the authoritative coordinate. Returns the number of
// components corrected. Best-effort: an unreadable JAR is skipped, never fatal; an
// artifact@version seen under two different groups is left untouched (never guessed).
func (r *Resolver) Resolve(ctx context.Context, wsDir string, comps []sbom.Component) int {
	if strings.TrimSpace(wsDir) == "" {
		return 0
	}
	index, ambiguous := scanWorkspace(ctx, wsDir)
	if len(index) == 0 {
		return 0
	}
	corrected := 0
	for i := range comps {
		c := &comps[i]
		group, artifact, version, ok := parseMavenPURL(c.PURL)
		if !ok {
			continue
		}
		key := artifact + "@" + version
		if ambiguous[key] {
			continue
		}
		real, found := index[key]
		if !found || real == "" || real == group {
			continue
		}
		c.PURL = fmt.Sprintf("pkg:maven/%s/%s@%s", real, artifact, version)
		corrected++
	}
	return corrected
}

type coord struct{ group, artifact, version string }

// scanWorkspace walks wsDir for JARs and indexes "artifact@version" -> groupId. A key
// seen with two different groups is marked ambiguous and removed (we never guess).
func scanWorkspace(ctx context.Context, wsDir string) (index map[string]string, ambiguous map[string]bool) {
	index = map[string]string{}
	ambiguous = map[string]bool{}
	count := 0
	add := func(c coord) {
		if c.group == "" || c.artifact == "" || c.version == "" {
			return
		}
		key := c.artifact + "@" + c.version
		if ambiguous[key] {
			return
		}
		if prev, ok := index[key]; ok {
			if prev != c.group {
				ambiguous[key] = true
				delete(index, key)
			}
			return
		}
		index[key] = c.group
	}
	_ = filepath.WalkDir(wsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() || !isJAR(d.Name()) {
			return nil
		}
		if count >= maxJARs {
			return filepath.SkipAll
		}
		count++
		for _, c := range coordsFromJARFile(path) {
			add(c)
		}
		return nil
	})
	return index, ambiguous
}

func isJAR(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".jar") || strings.HasSuffix(n, ".war") || strings.HasSuffix(n, ".ear")
}

// coordsFromJARFile opens a JAR on disk and returns the coordinates declared in its
// (and one nested level of) pom.properties.
func coordsFromJARFile(path string) []coord {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer func() { _ = zr.Close() }()
	return coordsFromZip(&zr.Reader, 1)
}

// coordsFromZip extracts pom.properties coords, descending into nested JAR entries up
// to depth more levels (Spring Boot fat jars nest their dependency JARs).
func coordsFromZip(zr *zip.Reader, depth int) []coord {
	var out []coord
	for i, f := range zr.File {
		if i >= maxEntriesPerJAR {
			break
		}
		switch {
		case strings.HasPrefix(f.Name, "META-INF/maven/") && strings.HasSuffix(f.Name, "/pom.properties"):
			if c, ok := readPomProperties(f); ok {
				out = append(out, c)
			}
		case depth > 0 && isJAR(f.Name) && f.UncompressedSize64 > 0 && f.UncompressedSize64 <= maxNestedBytes:
			out = append(out, coordsFromNestedJAR(f, depth-1)...)
		}
	}
	return out
}

func readPomProperties(f *zip.File) (coord, bool) {
	rc, err := f.Open()
	if err != nil {
		return coord{}, false
	}
	defer func() { _ = rc.Close() }()
	return parsePomProperties(io.LimitReader(rc, maxPropsBytes))
}

func coordsFromNestedJAR(f *zip.File, depth int) []coord {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, maxNestedBytes))
	if err != nil {
		return nil
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	return coordsFromZip(zr, depth)
}

// parsePomProperties reads a Java.properties stream for groupId/artifactId/version.
func parsePomProperties(r io.Reader) (coord, bool) {
	var c coord
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxPropsBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "groupId":
			c.group = strings.TrimSpace(v)
		case "artifactId":
			c.artifact = strings.TrimSpace(v)
		case "version":
			c.version = strings.TrimSpace(v)
		}
	}
	if c.group == "" || c.artifact == "" || c.version == "" {
		return coord{}, false
	}
	return c, true
}

// parseMavenPURL parses pkg:maven/<group>/<artifact>@<version> (qualifiers/subpath stripped).
func parseMavenPURL(purl string) (group, artifact, version string, ok bool) {
	if !strings.HasPrefix(purl, "pkg:maven/") {
		return "", "", "", false
	}
	rest := strings.TrimPrefix(purl, "pkg:maven/")
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return "", "", "", false
	}
	ga, version := rest[:at], rest[at+1:]
	slash := strings.LastIndex(ga, "/")
	if slash < 0 {
		return "", "", "", false
	}
	group, artifact = ga[:slash], ga[slash+1:]
	if group == "" || artifact == "" || version == "" {
		return "", "", "", false
	}
	return group, artifact, version, true
}
