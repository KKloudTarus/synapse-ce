// Package gradleresolve resolves a Gradle project's full dependency tree (direct + transitive, with
// the resolved versions) by shelling out to `gradle dependencies` via argv and parsing the
// dependency tree into SBOM components. A static build.gradle parse cannot do this: versions are often
// supplied by a platform/BOM or version catalog (so the declaration carries no version) and the
// transitive tree – where most CVEs live – is not listed. This adapter fills that gap as a best-effort,
// opt-in, post-SBOM step. Gradle uses Maven coordinates, so the components are pkg:maven PURLs.
//
// SECURITY: this is HIGHER-risk than the Maven resolver. Evaluating `settings.gradle` + `build.gradle`
// RUNS ARBITRARY Groovy/Kotlin build logic at configuration time (the `dependencies` task still
// configures the project) – untrusted code execution by design. Mitigations: it invokes a PINNED
// `gradle` binary, NEVER the project's own `./gradlew` wrapper (which would download+run an
// attacker-chosen Gradle distribution); `--no-daemon` so nothing persists; in production it MUST run
// through a ToolRunner (the sandbox) that confines the filesystem and restricts egress to the
// configured repositories – the synapse-api composition root REFUSES to enable it without a sandbox
// (fail-closed). Direct-exec is the synapse-cli dogfood path for a TRUSTED local project only. OPT-IN
// (SYNAPSE_GRADLE_RESOLVE_ENABLED) + BEST-EFFORT: no build script / missing gradle / any error yields
// no components and never fails the scan.
package gradleresolve

import (
	"bufio"
	"bytes"
	"context"
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

const maxBuildRoots = 200 // bound the sub-project discovery walk (a monorepo of N Gradle builds)

// defaultRepoHosts is the egress allow-list for the sandboxed run: Maven Central + the Gradle plugin
// portal / distribution services Gradle reaches to resolve plugins and dependency metadata. Extra
// private-mirror hosts are added via WithRepoHosts.
var defaultRepoHosts = []string{"repo1.maven.org", "repo.maven.apache.org", "plugins.gradle.org", "services.gradle.org"}

// buildFiles are the project markers that indicate a Gradle build (Groovy or Kotlin DSL).
var buildFiles = []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}

// Resolver runs `gradle dependencies` to resolve a Gradle project's full dependency tree. bin is the
// pinned gradle executable (path/name) – NOT the project's./gradlew.
type Resolver struct {
	bin        string
	runner     ports.ToolRunner
	repoHosts  []string
	gradleHome string // persistent GRADLE_USER_HOME (cache) dir; "" = ephemeral
}

// New returns a resolver using the given gradle binary (defaults to "gradle" in PATH).
func New(bin string) *Resolver {
	if strings.TrimSpace(bin) == "" {
		bin = "gradle"
	}
	return &Resolver{bin: bin}
}

// WithRunner runs gradle through a ToolRunner (the SandboxRunner): the project dir is bound and egress
// is restricted to the configured repositories, confining the build logic that runs at configuration
// time. nil keeps the direct exec (dev/CLI; trusted project only).
func (r *Resolver) WithRunner(runner ports.ToolRunner) *Resolver { r.runner = runner; return r }

// WithRepoHosts adds extra repository hosts to the sandbox egress allow-list (private mirror).
func (r *Resolver) WithRepoHosts(hosts []string) *Resolver {
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			r.repoHosts = append(r.repoHosts, h)
		}
	}
	return r
}

// WithGradleHome pins GRADLE_USER_HOME to a PERSISTENT dir so the resolved metadata + downloaded
// artifacts are cached across scans. Empty keeps the default (ephemeral under the sandbox tmpfs HOME).
func (r *Resolver) WithGradleHome(dir string) *Resolver {
	dir = strings.TrimSpace(dir)
	if dir != "" {
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
	}
	r.gradleHome = dir
	return r
}

var _ ports.GradleResolver = (*Resolver)(nil)

// Resolve resolves every Gradle build under dir and returns the union of their Maven-coordinate
// components, deduped by PURL. When dir is itself a Gradle build it resolves that one; when dir is a
// monorepo PARENT with no root build script but sub-folders that each hold one (many independent builds
// under one directory), it discovers and resolves EACH (without this, the resolver saw no root build
// file and skipped entirely → the whole tree fell back to syft's build.gradle-only view → under-count).
// No-ops ([], nil) when no Gradle build exists anywhere under dir.
//
// Resolution is best-effort PER build: a build that fails does not discard the ones that succeed.
// Whenever ANY build failed, the first failure's reason is returned as the error ALONGSIDE the components
// that did resolve – so the caller keeps the partial tree AND can surface the gap. A total failure returns
// no components + the error; a clean run returns (comps, nil).
func (r *Resolver) Resolve(ctx context.Context, dir string) ([]sbom.Component, error) {
	roots := buildRoots(dir)
	if len(roots) == 0 {
		return nil, nil // no Gradle build anywhere under dir
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
				firstErr = fmt.Errorf("%s: %w", relOrBase(dir, root), err)
			}
			continue
		}
		for _, c := range parseGradleDeps(out) {
			if !seen[c.PURL] {
				seen[c.PURL] = true
				all = append(all, c)
			}
		}
	}
	if firstErr != nil {
		// Return the error WITH any components that resolved (partial keeps the good builds).
		return all, fmt.Errorf("gradle dependencies: %w", firstErr)
	}
	return all, nil
}

// relOrBase labels a failing build root by its path relative to the scan dir (so same-named sub-builds
// like two `app/` dirs are distinguishable in the surfaced warning), falling back to the base name.
func relOrBase(dir, root string) string {
	if rel, err := filepath.Rel(dir, root); err == nil && rel != "" && rel != "." {
		return rel
	}
	return filepath.Base(root)
}

func hasBuildFile(dir string) bool {
	for _, f := range buildFiles {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

// buildRoots finds the Gradle build roots under dir: each directory holding a build script
// (build.gradle[.kts] / settings.gradle[.kts]), WITHOUT descending into it – a multi-project build's
// included sub-projects are resolved by running gradle on the build root (the settings.gradle dir), just
// as `gradle -p <root> dependencies` configures the whole build. dir itself is a root when it has a build
// file (single-build fast path). Gradle output/VCS/tooling dirs are skipped. Bounded to maxBuildRoots.
func buildRoots(dir string) []string {
	var roots []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if p != dir {
			switch d.Name() {
			case "build", "target", ".gradle", "buildSrc", "node_modules", ".git", ".idea":
				return filepath.SkipDir // Gradle output / build-logic / VCS / tooling – never a build root to run gradle on
			}
		}
		if hasBuildFile(p) {
			roots = append(roots, p)
			if len(roots) >= maxBuildRoots {
				return filepath.SkipAll
			}
			return filepath.SkipDir // this dir is a build root; its included sub-projects are gradle's job
		}
		return nil
	})
	return roots
}

// args is the gradle invocation: the read-only `dependencies` task for the deployed runtimeClasspath
// (compile + runtime; excludes test), plain console (no ANSI), no daemon (nothing persists). `-p` sets
// the project dir; `-Dmaven.repo.local` has no gradle analogue – the cache is GRADLE_USER_HOME (env).
func (r *Resolver) args(dir string) []string {
	return []string{"--no-daemon", "--console=plain", "-q", "-p", dir, "dependencies", "--configuration", "runtimeClasspath"}
}

func (r *Resolver) allowedHosts() []string {
	return append(append([]string{}, defaultRepoHosts...), r.repoHosts...)
}

func (r *Resolver) run(ctx context.Context, dir string) ([]byte, error) {
	args := r.args(dir)
	var env []string
	if r.gradleHome != "" {
		env = []string{"GRADLE_USER_HOME=" + r.gradleHome}
	}
	if r.runner != nil {
		res, err := r.runner.Run(ctx, ports.ToolSpec{
			Name:          r.bin,
			Args:          args,
			ReadOnlyPaths: []string{dir},
			Workdir:       r.gradleHome, // persistent cache (when set) is the one writable bind
			Env:           env,
			EgressPolicy:  &ports.EgressPolicy{AllowDomains: r.allowedHosts()},
		})
		if err != nil {
			return nil, fmt.Errorf("sandboxed: %w: %s", err, truncate(string(res.Stderr), 300))
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("exit %d: %s", res.ExitCode, truncate(string(res.Stderr), 300))
		}
		return res.Stdout, nil
	}
	// Direct exec: dev/CLI path for a TRUSTED local project. build.gradle runs arbitrary code that can
	// read the process env, so scrub SYNAPSE_* secrets (API keys, signing seeds, …) from the child – the
	// resolver needs none of them (defense-in-depth on the unsandboxed path; the sandbox path uses a
	// controlled env already).
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Env = append(scrubSynapseEnv(os.Environ()), env...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, truncate(stderr.String(), 300))
	}
	return stdout.Bytes(), nil
}

// gradleCoordRE matches a Gradle dependency-tree coordinate once the tree-drawing prefix is stripped:
// "group:artifact[:requestedVersion]" optionally followed by "-> resolvedVersion". The RESOLVED version
// (after "->", Gradle's conflict-resolution winner) wins; else the declared version. Trailing
// annotations like "(*)", "(c)", "(n)" are stripped before matching.
var gradleCoordRE = regexp.MustCompile(`^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)(?::([^\s(]+))?(?:\s*->\s*([A-Za-z0-9_.+-]+))?$`)

// parseGradleDeps parses `gradle dependencies` tree output into pkg:maven components. The testable core
// (no exec): strip the tree prefix + trailing annotation per line, take the resolved version (post-`->`)
// or the declared one, drop entries with no resolvable version (BOM imports, `project:x` modules,
// `(n)` unresolved), and dedup by PURL.
func parseGradleDeps(data []byte) []sbom.Component {
	var out []sbom.Component
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		// Strip leading tree-drawing chars ("+--- ", "\--- ", "| ") – coords start with an alnum group.
		line := strings.TrimLeft(sc.Text(), " |+\\-")
		line, skip := gradleLine(strings.TrimSpace(line))
		if skip {
			continue
		}
		m := gradleCoordRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		group, artifact, declared, resolved := m[1], m[2], m[3], m[4]
		version := resolved
		if version == "" {
			version = declared
		}
		if !sbom.IsResolvedVersion(version) { // no version, a range, or a {strictly …} form we won't guess
			continue
		}
		purl := "pkg:maven/" + group + "/" + artifact + "@" + version
		if seen[purl] {
			continue
		}
		seen[purl] = true
		out = append(out, sbom.Component{
			Name:    group + ":" + artifact, // matches the other Maven adapters + the owned-advisory key
			Version: version,
			PURL:    purl,
			// Production is correct because args() resolves only `runtimeClasspath` (excludes test); if
			// that configuration is ever broadened, revisit this so test deps aren't mislabeled.
			Scope: sbom.ScopeProduction,
		})
	}
	return out
}

// gradleLine handles a Gradle dependency-tree node's trailing marker and reports whether to SKIP it:
// " (c)" – a dependency CONSTRAINT (constraints{}/platform()/BOM import), NOT necessarily an artifact
// on the resolved classpath; a BOM is a pom, not a running jar, so emitting it would be a phantom
// component + false-positive CVEs. SKIP – a constraint that IS resolved reappears on a normal line.
// " (n)" – not resolved. SKIP.
// " (*)" – subtree shown earlier; the coordinate/version here is the real resolved one. Strip + keep.
// " (e)" – strip + keep (defensive; treat like a plain coordinate).
//
// Returns the cleaned coordinate text and skip=true when the line must be dropped.
func gradleLine(line string) (string, bool) {
	switch {
	case strings.HasSuffix(line, " (c)"), strings.HasSuffix(line, " (n)"):
		return "", true
	case strings.HasSuffix(line, " (*)"):
		return strings.TrimSpace(line[:len(line)-len(" (*)")]), false
	case strings.HasSuffix(line, " (e)"):
		return strings.TrimSpace(line[:len(line)-len(" (e)")]), false
	}
	return line, false
}

// scrubSynapseEnv drops SYNAPSE_* entries from an environment list. The resolver needs none of them,
// and on the unsandboxed direct-exec path the build tool runs untrusted code that could read+exfiltrate
// secrets (SYNAPSE_LLM_API_KEY, signing seeds, …) via System.getenv(). Non-SYNAPSE vars (PATH, JAVA_HOME,
// HOME, …) are preserved.
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
