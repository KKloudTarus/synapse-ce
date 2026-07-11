package jvmreach

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxArchives      = 20000     // bound the workspace jar walk (workspace size is capped upstream)
	maxEntriesPerJAR = 200000    // bound entries scanned per archive
	maxClassBytes    = 4 << 20   // a single.class is small; cap the read defensively
	maxNestedJARSize = 128 << 20 // read a nested (fat-jar BOOT-INF/lib) jar into memory only if under this
	maxClasses       = 2_000_000 // hard cap on total classes graphed (runaway guard)
)

// Analyzer computes coarse JVM class-reachability over a prepared workspace.
type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

var _ ports.JVMReachabilityAnalyzer = (*Analyzer)(nil)

// graph is the class-reference graph built from a workspace.
type graph struct {
	refs         map[string][]string        // class internal name -> classes it references
	roots        map[string]bool            // application (first-party) classes = closure seeds
	coordClasses map[string]map[string]bool // "group:artifact" -> set of classes that coordinate provides
	classes      int                        // total classes ingested (bound guard)
}

func newGraph() *graph {
	return &graph{refs: map[string][]string{}, roots: map[string]bool{}, coordClasses: map[string]map[string]bool{}}
}

// Analyze tags each JVM component with a coarse reachability verdict, in place, and returns the number
// tagged. It reads the app's compiled classes (target/classes, build/classes, or a fat jar's
// BOOT-INF/classes) as closure roots and every dependency jar's classes, then marks a component
// Reachable when any of its classes is in the transitive class-reference closure from the app, else
// Unreferenced. Components whose classes were not found (jar absent, non-JVM) are left unknown.
//
// It is BEST-EFFORT and CONSERVATIVE: if no application root classes are found (source not built), it
// tags NOTHING and returns 0 – an "unreferenced" verdict is never emitted without app roots to anchor
// it, so a not-built project can never be mislabeled as having dead dependencies. Non-nil error only on
// a walk that could not start; a per-file parse error is skipped.
func (a *Analyzer) Analyze(ctx context.Context, wsDir string, comps []sbom.Component) (int, error) {
	if strings.TrimSpace(wsDir) == "" {
		return 0, nil
	}
	g := newGraph()
	scanWorkspace(ctx, wsDir, g)
	if len(g.roots) == 0 || g.classes == 0 {
		return 0, nil // not built / no JVM classes → cannot compute; never guess "unreferenced"
	}
	reachable := reachClosure(g.refs, g.roots)

	tagged := 0
	for i := range comps {
		c := &comps[i]
		key := coordKeyOf(*c)
		if key == "" {
			continue
		}
		classes := g.coordClasses[key]
		if len(classes) == 0 {
			continue // this component's classes weren't found in the workspace → leave unknown
		}
		verdict := sbom.ReachabilityUnreferenced
		for cls := range classes {
			if reachable[cls] {
				verdict = sbom.ReachabilityReachable
				break
			}
		}
		c.Reachability = verdict
		tagged++
	}
	return tagged, nil
}

// coordKeyOf derives a component's "group:artifact" key for matching against the jar-derived coordinates.
// A pkg:maven PURL is authoritative (works for syft-cataloged components, whose Name is just the
// artifactId); the resolver-set "group:artifact" Name is the fallback.
func coordKeyOf(c sbom.Component) string {
	if rest, ok := strings.CutPrefix(c.PURL, "pkg:maven/"); ok {
		if at := strings.IndexByte(rest, '@'); at >= 0 {
			rest = rest[:at]
		}
		if slash := strings.LastIndexByte(rest, '/'); slash > 0 && slash+1 < len(rest) {
			return rest[:slash] + ":" + rest[slash+1:]
		}
	}
	if strings.IndexByte(c.Name, ':') > 0 {
		return c.Name
	}
	return ""
}

// reachClosure returns the set of classes reachable from roots by following reference edges (BFS). Coarse
// over-approximation of "used": a class reference is not a proven call, but an UNreferenced class is one
// the app's compiled closure never mentions.
func reachClosure(refs map[string][]string, roots map[string]bool) map[string]bool {
	reachable := make(map[string]bool, len(roots))
	queue := make([]string, 0, len(roots))
	for r := range roots {
		if !reachable[r] {
			reachable[r] = true
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		cur := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, next := range refs[cur] {
			if !reachable[next] {
				reachable[next] = true
				queue = append(queue, next)
			}
		}
	}
	return reachable
}

// scanWorkspace walks wsDir: loose.class files under a "classes" dir (not test-classes) are app roots;
// each jar's classes are attributed to that jar's Maven coordinate, and a Spring-Boot fat jar's
// BOOT-INF/classes are app roots while its BOOT-INF/lib nested jars are dependencies.
func scanWorkspace(ctx context.Context, wsDir string, g *graph) {
	archives := 0
	_ = filepath.WalkDir(wsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		lower := strings.ToLower(d.Name())
		switch {
		case strings.HasSuffix(lower, ".class"):
			if isAppClassPath(p) {
				addClass(g, readFile(p), "", true)
			}
		case isArchive(lower):
			if archives >= maxArchives {
				return filepath.SkipAll
			}
			archives++
			ingestJAR(ctx, p, g)
		}
		return nil
	})
}

// isAppClassPath reports whether a loose.class file is application (first-party) compiled output – under
// a "classes" build-output dir (Maven target/classes, Gradle build/classes/java/main), excluding tests.
func isAppClassPath(p string) bool {
	segs := strings.Split(filepath.ToSlash(p), "/")
	for _, s := range segs {
		if s == "test-classes" {
			return false
		}
	}
	for _, s := range segs {
		if s == "classes" {
			return true
		}
	}
	return false
}

func isArchive(nameLower string) bool {
	return strings.HasSuffix(nameLower, ".jar") || strings.HasSuffix(nameLower, ".war") || strings.HasSuffix(nameLower, ".ear")
}

// ingestJAR reads a jar file and folds its classes into the graph, handling Spring-Boot fat-jar layout.
func ingestJAR(ctx context.Context, jarPath string, g *graph) {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return
	}
	defer func() { _ = zr.Close() }()
	ingestZip(ctx, &zr.Reader, g, 1)
}

// ingestZip folds one archive's classes into the graph. coord is derived from the archive's own
// pom.properties (dependency jars); BOOT-INF/classes entries are app roots; BOOT-INF/lib (or WEB-INF/lib)
// nested jars are recursed one level as their own dependencies. depth bounds nested-jar recursion.
func ingestZip(ctx context.Context, zr *zip.Reader, g *graph, depth int) {
	coord := coordOfArchive(zr)
	for i, f := range zr.File {
		if i >= maxEntriesPerJAR || ctx.Err() != nil || g.classes >= maxClasses {
			return
		}
		name := f.Name
		switch {
		case strings.HasSuffix(name, ".class"):
			isApp := strings.HasPrefix(name, "BOOT-INF/classes/") || strings.HasPrefix(name, "WEB-INF/classes/")
			addClass(g, readZipEntry(f, maxClassBytes), coord, isApp)
		case depth > 0 && isArchive(strings.ToLower(name)) &&
			(strings.HasPrefix(name, "BOOT-INF/lib/") || strings.HasPrefix(name, "WEB-INF/lib/")):
			if data := readZipEntry(f, maxNestedJARSize); len(data) > 0 {
				if nr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
					ingestZip(ctx, nr, g, depth-1)
				}
			}
		}
	}
}

// addClass parses one.class blob and records its edges + coordinate ownership. app=true seeds a root.
func addClass(g *graph, data []byte, coord string, app bool) {
	if len(data) == 0 || g.classes >= maxClasses {
		return
	}
	name, refs, err := parseClass(data)
	if err != nil || name == "" {
		return
	}
	g.classes++
	// First-writer-wins on a duplicate internal class name (common with fat-jar shading/relocation): the
	// first copy's references define the edges, but every owning coordinate still claims the class below –
	// so a shaded duplicate may attribute reachability to more than one component. Acceptable for a coarse,
	// deprioritize-only signal (it can only ever mark MORE components reachable, never fewer / never suppress).
	if _, ok := g.refs[name]; !ok {
		g.refs[name] = refs
	}
	if app {
		g.roots[name] = true
	}
	if coord != "" {
		set := g.coordClasses[coord]
		if set == nil {
			set = map[string]bool{}
			g.coordClasses[coord] = set
		}
		set[name] = true
	}
}

// coordOfArchive reads an archive's own Maven coordinate ("group:artifact") from its embedded
// META-INF/maven/<g>/<a>/pom.properties. "" when absent (the archive's classes then contribute edges to
// the closure but can't be attributed to a component).
func coordOfArchive(zr *zip.Reader) string {
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "META-INF/maven/") && strings.HasSuffix(f.Name, "/pom.properties") {
			g, a := propsGA(readZipEntry(f, maxClassBytes))
			if g != "" && a != "" {
				return g + ":" + a
			}
		}
	}
	return ""
}

// propsGA extracts groupId + artifactId from a Maven pom.properties body.
func propsGA(data []byte) (group, artifact string) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "groupId="):
			group = strings.TrimSpace(strings.TrimPrefix(line, "groupId="))
		case strings.HasPrefix(line, "artifactId="):
			artifact = strings.TrimSpace(strings.TrimPrefix(line, "artifactId="))
		}
	}
	return group, artifact
}

func readFile(p string) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxClassBytes))
	if err != nil {
		return nil
	}
	return data
}

func readZipEntry(f *zip.File, limit int64) []byte {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil {
		return nil
	}
	return data
}
