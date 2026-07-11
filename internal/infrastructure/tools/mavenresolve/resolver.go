// Package mavenresolve resolves a Maven project's full dependency tree (direct + transitive, with the
// real versions) by shelling out to `mvn dependency:list` via argv, then parsing the
// resolved coordinates into SBOM components. A static pom.xml parse cannot do this: Spring-Boot-style
// versions are managed by the parent BOM (so syft reports the direct starters as version=UNKNOWN) and
// the transitive tree – where most CVEs live (spring-core, snakeyaml, tomcat-embed-core, …) – is not
// listed in pom.xml at all. This adapter fills that gap as a best-effort, opt-in, post-SBOM step.
//
// SECURITY: this RUNS the Maven toolchain over UNTRUSTED project configuration (the pom.xml, its
// parent POM chain, and the dependency plugin) and reaches a package repository for metadata – so it
// is materially higher-risk than the read-only `go mod graph` resolver. For a SINGLE module the standalone
// `dependency:list` goal avoids the build lifecycle (no compile/test/package, no app code run); a
// MULTI-MODULE reactor additionally runs `install -DskipTests` so a module can resolve its sibling
// modules (this compiles the project – a `mvn package`-class surface – but is still sandbox-confined).
// Either way it is NOT inert: POM/parent-POM evaluation + plugin/extension resolution (and, multi-module,
// compilation) is a code-execution + egress surface. So in production it MUST run through a
// ToolRunner (the sandbox), which confines the filesystem and restricts egress to the Maven repo; the
// synapse-api composition root REFUSES to enable it without a sandbox (fail-closed). Direct-exec is the
// synapse-cli dogfood path for a TRUSTED local project only. It is OPT-IN (SYNAPSE_MAVEN_RESOLVE_ENABLED)
// and BEST-EFFORT: no pom.xml, a missing mvn, or any error yields no components and never fails the scan.
package mavenresolve

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxPomReadBytes = 1 << 20 // a resolved.pom is small; cap the read defensively
	maxParentDepth  = 8       // bound the <parent> walk when a dep inherits its <licenses>
	maxProjectRoots = 200     // bound the sub-project discovery walk (a monorepo of N services)
)

// mavenCentralHosts is the egress allow-list for the sandboxed run: Maven Central (where mvn fetches
// dependency + parent POM metadata). A project pointing at a private mirror needs its host added here
// or via settings.xml + the sandbox egress config; absent egress, mvn fails fast and the step no-ops.
var mavenCentralHosts = []string{"repo1.maven.org", "repo.maven.apache.org"}

// Resolver runs `mvn dependency:list` to resolve a Maven project's full dependency tree. bin is the
// mvn executable (path/name).
type Resolver struct {
	bin       string
	runner    ports.ToolRunner // optional; when set, mvn runs sandbox-confined (REQUIRED in production)
	repoHosts []string         // extra Maven-repo hosts to allow egress to (private mirror), beyond Central
	localRepo string           // persistent Maven local-repo dir (-Dmaven.repo.local); "" = ephemeral cache
}

// New returns a resolver using the given mvn binary (defaults to "mvn" in PATH).
func New(bin string) *Resolver {
	if strings.TrimSpace(bin) == "" {
		bin = "mvn"
	}
	return &Resolver{bin: bin}
}

// WithRunner runs mvn through a ToolRunner (the SandboxRunner): the project dir is bound and egress is
// restricted to the Maven repository, confining the build tooling that processes untrusted POMs. nil
// keeps the direct exec (dev/CLI; trusted project only).
func (r *Resolver) WithRunner(runner ports.ToolRunner) *Resolver { r.runner = runner; return r }

// WithRepoHosts adds extra Maven-repository hosts to the sandbox egress allow-list (for a corporate
// mirror / the Apache plugin repo). Empty keeps Central-only; a project pointing elsewhere otherwise
// fails fast and no-ops. Has no effect on the direct-exec path (no egress filter there).
func (r *Resolver) WithRepoHosts(hosts []string) *Resolver {
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			r.repoHosts = append(r.repoHosts, h)
		}
	}
	return r
}

// WithLocalRepo pins Maven's local repository to a PERSISTENT dir (`-Dmaven.repo.local`), so the
// resolved POM/JAR metadata is cached across scans instead of re-downloaded every time. Empty keeps
// the default (ephemeral under the sandbox's tmpfs HOME). In the sandbox the dir is bound read-WRITE.
func (r *Resolver) WithLocalRepo(dir string) *Resolver {
	dir = strings.TrimSpace(dir)
	if dir != "" {
		if abs, err := filepath.Abs(dir); err == nil { // absolute so a sandbox bind/`-Dmaven.repo.local` can't be relative
			dir = abs
		}
	}
	r.localRepo = dir
	return r
}

var _ ports.MavenResolver = (*Resolver)(nil)

// Resolve resolves every Maven project under dir and returns the union of their components (direct +
// transitive, with versions), deduped by PURL. When dir is itself a Maven project it resolves that one;
// when dir is a monorepo PARENT with no root pom.xml but sub-folders that each have one (a common layout
// – e.g. 20 services under one directory), it discovers and resolves EACH sub-project (without this, the
// resolver saw no root pom.xml and skipped entirely, so the whole tree fell back to syft's pom-only view
// → severe under-count). No-ops ([], nil) when no pom.xml exists anywhere under dir.
//
// Resolution is best-effort PER project: a project that fails to resolve (bad POM, unreachable repo,
// missing sibling) does not discard the ones that succeed. Whenever ANY project failed, the first
// failure's reason is returned as the error ALONGSIDE the components that did resolve – so the caller
// keeps the partial tree AND can surface the failure (a partial monorepo resolve is still an under-count
// worth flagging). A total failure returns no components + the error; a clean run returns (comps, nil).
func (r *Resolver) Resolve(ctx context.Context, dir string) ([]sbom.Component, error) {
	roots := projectRoots(dir)
	if len(roots) == 0 {
		return nil, nil // no Maven project anywhere under dir
	}
	seen := map[string]bool{}
	var all []sbom.Component
	var firstErr error
	for _, root := range roots {
		if ctx.Err() != nil {
			break
		}
		out, err := r.run(ctx, root)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", filepath.Base(root), err)
			}
			continue
		}
		comps := parseDependencyList(out)
		r.fillDeclaredLicenses(ctx, comps)
		for _, c := range comps {
			if !seen[c.PURL] {
				seen[c.PURL] = true
				all = append(all, c)
			}
		}
	}
	if firstErr != nil {
		// Return the error WITH any components that resolved: total failure → (nil, err); partial
		// failure → (partial comps, err) so the caller keeps the good projects and still surfaces the gap.
		return all, fmt.Errorf("mvn dependency:list: %w", firstErr)
	}
	return all, nil
}

// projectRoots finds the Maven project roots under dir: each directory that holds a pom.xml, WITHOUT
// descending into a found project (its own sub-modules are resolved by running mvn on its root pom).
// dir itself is a root when it has a pom.xml (the single-project fast path). Build-output/VCS/tooling
// dirs are skipped. Bounded to maxProjectRoots.
func projectRoots(dir string) []string {
	var roots []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if p != dir {
			switch d.Name() {
			case "target", "build", "node_modules", ".git", ".idea", ".mvn":
				return filepath.SkipDir // never a project root to run mvn on
			}
		}
		if _, e := os.Stat(filepath.Join(p, "pom.xml")); e == nil {
			roots = append(roots, p)
			if len(roots) >= maxProjectRoots {
				return filepath.SkipAll
			}
			return filepath.SkipDir // this dir is a project root; its sub-modules are mvn's job
		}
		return nil
	})
	return roots
}

// fillDeclaredLicenses populates each component's DECLARED license from its resolved.pom's <licenses>
// block (walking the <parent> chain for inherited declarations), read OFFLINE from the Maven local
// repository that `dependency:list` just populated. This is the authoritative legal declaration – the
// same source Trivy uses – and, crucially, the SCA pipeline REPLACES syft's entire pkg:maven view with
// this resolved tree (mergeResolvedJVM, completeScopes=true), so a clean declared license here also
// eliminates syft's embedded-text license SPRAY (e.g. mysql-connector-java: syft concludes ~10 SPDX ids
// from bundled third-party notices → the pom declares 1). Best-effort: a missing repo/POM leaves the
// component's license empty for a downstream resolver to fill; never fails resolution. Declared names are
// emitted verbatim; the downstream license scanner normalizes them to SPDX ids.
func (r *Resolver) fillDeclaredLicenses(ctx context.Context, comps []sbom.Component) {
	repo := r.localRepoDir()
	if repo == "" {
		return
	}
	if fi, err := os.Stat(repo); err != nil || !fi.IsDir() {
		return // repo not populated/accessible (e.g. ephemeral sandbox cache) → downstream fills licenses
	}
	cache := map[string][]string{} // "g:a:v" -> declared names; shared parents are read once
	for i := range comps {
		if ctx.Err() != nil {
			return // honor cancellation/timeout – stop reading POMs
		}
		c := &comps[i]
		gi := strings.IndexByte(c.Name, ':') // Name is "group:artifact"
		if gi <= 0 {
			continue
		}
		names := declaredLicensesFromRepo(repo, c.Name[:gi], c.Name[gi+1:], c.Version, cache, 0)
		if len(names) == 0 {
			continue
		}
		lics := make([]sbom.License, 0, len(names))
		for _, n := range names {
			lics = append(lics, sbom.License{Name: n})
		}
		c.Licenses = lics
		c.LicenseSource = sbom.LicenseSourceManifest
		c.LicenseConfidence = "declared"
	}
}

// localRepoDir is the Maven local repository the resolver reads resolved POMs from: the configured
// -Dmaven.repo.local, else the standard ~/.m2/repository. Empty when it can't be determined.
func (r *Resolver) localRepoDir() string {
	if r.localRepo != "" {
		return r.localRepo
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".m2", "repository")
}

// declaredLicensesFromRepo returns the license names declared in <g:a:v>'s resolved.pom, walking the
// <parent> chain when the artifact inherits its <licenses>. Cached per coordinate (shared parents cost
// one read) and depth-bounded (cycle/pathological-parent guard).
func declaredLicensesFromRepo(repo, g, a, v string, cache map[string][]string, depth int) []string {
	if depth > maxParentDepth {
		return nil
	}
	key := g + ":" + a + ":" + v
	if names, ok := cache[key]; ok {
		return names
	}
	cache[key] = nil // guard re-entry on a parent cycle before we recurse
	names, pg, pa, pv := readPomLicenses(repo, g, a, v)
	if len(names) == 0 && pg != "" && pa != "" && pv != "" {
		names = declaredLicensesFromRepo(repo, pg, pa, pv, cache, depth+1)
	}
	cache[key] = names
	return names
}

// readPomLicenses reads a resolved.pom and returns its declared license names plus its <parent> coord.
// XML matching is by local name, so the Maven POM namespace needs no hard-coding.
func readPomLicenses(repo, g, a, v string) (names []string, pg, pa, pv string) {
	p := pomFilePath(repo, g, a, v)
	if p == "" {
		return nil, "", "", ""
	}
	data, err := os.ReadFile(p)
	if err != nil || len(data) == 0 || len(data) > maxPomReadBytes {
		return nil, "", "", ""
	}
	var doc struct {
		Licenses []struct {
			Name string `xml:"name"`
			URL  string `xml:"url"`
		} `xml:"licenses>license"`
		Parent struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Version    string `xml:"version"`
		} `xml:"parent"`
	}
	if xml.Unmarshal(data, &doc) != nil {
		return nil, "", "", ""
	}
	for _, l := range doc.Licenses {
		n := strings.TrimSpace(l.Name)
		if n == "" {
			n = strings.TrimSpace(l.URL) // some poms declare only a URL
		}
		if n != "" {
			names = append(names, n)
		}
	}
	return names, strings.TrimSpace(doc.Parent.GroupID), strings.TrimSpace(doc.Parent.ArtifactID), strings.TrimSpace(doc.Parent.Version)
}

// pomFilePath builds the local-repo path for a coordinate's.pom, refusing any coord that could escape
// the repo root (the coords come from resolving untrusted POMs). "" when the coord is unsafe.
func pomFilePath(repo, g, a, v string) string {
	if g == "" || a == "" || v == "" ||
		strings.Contains(g, "..") || strings.Contains(a, "..") || strings.Contains(v, "..") {
		return ""
	}
	full := filepath.Join(repo, strings.ReplaceAll(g, ".", "/"), a, v, a+"-"+v+".pom")
	if !strings.HasPrefix(filepath.Clean(full), filepath.Clean(repo)+string(os.PathSeparator)) {
		return ""
	}
	return full
}

// args is the mvn invocation. For a SINGLE-module project it runs only the standalone `dependency:list`
// goal (no build lifecycle – fast, and resolves from POMs even when the source wouldn't compile). A
// MULTI-MODULE reactor is special: a module may depend on a SIBLING module that isn't published, which
// `dependency:list` alone cannot resolve (it aborts → no output). So when the root POM declares
// <modules>, prepend `install -DskipTests` to build + install every module first, after which
// `dependency:list` emits the full union across modules. Test-scope is filtered in the parser.
func (r *Resolver) args(dir string) []string {
	pom := filepath.Join(dir, "pom.xml")
	args := []string{"-B", "-ntp", "-f", pom}
	if r.localRepo != "" {
		args = append(args, "-Dmaven.repo.local="+r.localRepo)
	}
	if pomDeclaresModules(readBounded(pom)) {
		// install compiles the project (a larger exec surface than dependency:list alone) – still
		// sandbox-confined on the server. maven.test.skip=true skips compiling AND running tests, so no
		// test code is built or executed. install runs first (a lifecycle segment), then dependency:list.
		// NOTE: install writes each module's target/ inside the project; on the SERVER the project is
		// bound read-only, so multi-module install may fail there → best-effort no-op (falls back to the
		// pom-only INCOMPLETE result, never wrong). The CLI direct path (writable project) handles it.
		args = append(args, "-Dmaven.test.skip=true", "install")
	}
	return append(args, "dependency:list")
}

// pomDeclaresModules reports whether a POM is a multi-module aggregator (has a <module> entry). A naive
// substring check is enough – a false positive only adds a harmless `install`, never a wrong result.
func pomDeclaresModules(pom []byte) bool { return bytes.Contains(pom, []byte("<module>")) }

// readBounded reads a small file (the POM), capped; any error → nil (treated as single-module).
func readBounded(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 4<<20 {
		return nil
	}
	return data
}

// allowedHosts is the egress allow-list: Maven Central plus any configured private-mirror hosts.
func (r *Resolver) allowedHosts() []string {
	return append(append([]string{}, mavenCentralHosts...), r.repoHosts...)
}

func (r *Resolver) run(ctx context.Context, dir string) ([]byte, error) {
	args := r.args(dir)
	if r.runner != nil {
		res, err := r.runner.Run(ctx, ports.ToolSpec{
			Name:          r.bin,
			Args:          args,
			ReadOnlyPaths: []string{dir},
			// Persistent local-repo (when set) is the one writable bind – mvn caches the resolved tree
			// there across scans; empty leaves the ephemeral tmpfs HOME (re-download each scan).
			Workdir: r.localRepo,
			// mvn must reach the Maven repository for POM/metadata resolution; confine egress to it
			// (Central + any configured mirror). Default-deny blocks a POM redirecting mvn elsewhere.
			EgressPolicy: &ports.EgressPolicy{AllowDomains: r.allowedHosts()},
		})
		if err != nil {
			return nil, fmt.Errorf("sandboxed: %w: %s", err, truncate(string(res.Stderr), 300))
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("exit %d: %s", res.ExitCode, truncate(string(res.Stderr), 300))
		}
		return res.Stdout, nil
	}
	// Direct exec: dev/CLI path for a TRUSTED local project (parity with the syft/go adapters). mvn
	// evaluates the project's POM/plugin config, which can read the process env, so scrub SYNAPSE_*
	// secrets from the child – the resolver needs none of them (defense-in-depth on the unsandboxed path).
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Env = scrubSynapseEnv(os.Environ())
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, truncate(stderr.String(), 300))
	}
	return stdout.Bytes(), nil
}

// coordRE matches one resolved Maven coordinate as printed by dependency:list (after the leading
// "[INFO]" + whitespace is stripped): groupId:artifactId:type[:classifier]:version:scope. groupId and
// artifactId can contain., -, _; the type is jar/pom/etc.; scope is one of the Maven scopes. Newer
// maven-dependency-plugin appends a Java-module note (" -- module … [auto]") after the scope, so an
// optional trailing " …" is allowed (and ignored).
var coordRE = regexp.MustCompile(`^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):[A-Za-z0-9_.-]+:(?:[A-Za-z0-9_.-]+:)?([A-Za-z0-9_.+-]+):(compile|provided|runtime|system|test|import)(?:\s.*)?$`)

// parseDependencyList parses `mvn dependency:list` output into Maven components. It is the testable
// core (no exec): each line is stripped of an optional "[INFO]" prefix + whitespace and matched
// against coordRE; test-scope entries are dropped (not shipped); duplicates (by PURL) are collapsed.
func parseDependencyList(data []byte) []sbom.Component {
	var out []sbom.Component
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "[INFO]"))
		m := coordRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		group, artifact, version, scope := m[1], m[2], m[3], m[4]
		if scope == "test" { // test deps aren't shipped – exclude (avoids test-only CVE noise)
			continue
		}
		purl := "pkg:maven/" + group + "/" + artifact + "@" + version
		if seen[purl] {
			continue
		}
		seen[purl] = true
		out = append(out, sbom.Component{
			// "group:artifact" matches every other Maven adapter (ownsbom/manifest) + the owned-advisory
			// Maven key, so the finding's component label + dedup fallback are consistent across the tree.
			Name:    group + ":" + artifact,
			Version: version,
			PURL:    purl,
			Scope:   sbom.ScopeProduction,
		})
	}
	return out
}

// scrubSynapseEnv drops SYNAPSE_* entries from an environment list – the resolver needs none, and on the
// unsandboxed path the build tool runs untrusted code that could read+exfiltrate secrets via the env.
func scrubSynapseEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, "SYNAPSE_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
