// Package gradleresolve resolves a Gradle project's full dependency tree (direct + transitive, with the
// resolved versions) by shelling out (argv only) to a pinned `gradle` with a Synapse init script that
// walks the resolution-result GRAPH of the `runtimeClasspath` of EVERY project in the build (root + all
// subprojects) and prints each resolved Maven module. A static build.gradle parse cannot do this: versions
// are often supplied by a platform/BOM or version catalog (so the declaration carries no version) and the
// transitive tree – where most CVEs live – is not listed; and the per-project `dependencies` task reports
// only the root project, so a multi-project `include` build (aggregator root + java subprojects) was badly
// under-reported. This adapter fills that gap as a best-effort, opt-in, post-SBOM step. Gradle uses Maven
// coordinates, so the components are pkg:maven PURLs.
//
// The graph is read from METADATA ONLY (no artifact/JAR download): a module is reported even when its jar
// can't be fetched, and — critically for a security scan — a dependency that could NOT be resolved (e.g.
// one that lives only on an unreachable private mirror) is emitted as an explicit unresolved marker rather
// than silently dropped, so an incomplete tree surfaces to the caller as INCOMPLETE (a source_warning)
// instead of reading as a clean scan (false-negative).
//
// SECURITY: this is HIGHER-risk than the Maven resolver. Evaluating `settings.gradle` + `build.gradle`
// RUNS ARBITRARY Groovy/Kotlin build logic at configuration time (resolving a configuration configures the
// project) – untrusted code execution by design. Mitigations: it invokes a PINNED
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
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxBuildRoots = 200 // bound the sub-project discovery walk (a monorepo of N Gradle builds)

// defaultRepoHosts is the egress allow-list for the sandboxed run: Maven Central + the Gradle plugin
// portal / distribution services Gradle reaches to resolve plugins and dependency metadata. Extra
// private-mirror hosts are added via WithRepoHosts.
var defaultRepoHosts = []string{"repo1.maven.org", "repo.maven.apache.org", "plugins.gradle.org", "services.gradle.org"}

// Resolver runs a pinned gradle with a Synapse init script to resolve a Gradle project's full dependency
// tree. bin is the pinned gradle executable (path/name) – NOT the project's ./gradlew.
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
	// Materialize the all-projects resolver init script once; every build root reuses it.
	initDir, err := os.MkdirTemp("", "synapse-gradleinit-")
	if err != nil {
		return nil, fmt.Errorf("gradle resolve: init script: %w", err)
	}
	defer func() { _ = os.RemoveAll(initDir) }()
	initPath := filepath.Join(initDir, "synapse-resolve.init.gradle")
	if err := os.WriteFile(initPath, []byte(initScript), 0o600); err != nil {
		return nil, fmt.Errorf("gradle resolve: write init script: %w", err)
	}
	seen := map[string]bool{}
	var all []sbom.Component
	var firstErr error
	for _, root := range roots {
		if ctx.Err() != nil {
			break
		}
		out, err := r.run(ctx, root, initPath)
		if err != nil {
			// The build root could not be configured/run at all (missing/broken gradle, bad JAVA_HOME, a
			// build-script config error). An aggregator / non-Java root simply emits nothing and exits 0,
			// so this is a genuine failure worth surfacing.
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", relOrBase(dir, root), err)
			}
			continue
		}
		comps, unresolved := parseGradleDeps(out)
		for _, c := range comps {
			if !seen[c.PURL] {
				seen[c.PURL] = true
				all = append(all, c)
			}
		}
		// A build root can resolve+exit-0 yet leave individual modules unresolved (metadata unreachable —
		// e.g. a dependency that lives only on an unreachable private mirror). Lenient resolution keeps the
		// modules that DID resolve, but the gap MUST surface: an incomplete tree reported as clean is a
		// false-negative for a security scan. Turn it into the resolve error so the caller degrades
		// completeness (the SCA service emits a "result INCOMPLETE" source_warning).
		if len(unresolved) > 0 && firstErr == nil {
			firstErr = fmt.Errorf("%s: %d dependency(ies) NOT resolved (e.g. %q — repository unreachable or artifact missing)",
				relOrBase(dir, root), len(unresolved), unresolved[0])
		}
	}
	if firstErr != nil {
		// Return the error WITH any components that resolved (partial keeps the good builds).
		return all, fmt.Errorf("gradle resolve: %w", firstErr)
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

// settingsFiles mark an INDEPENDENT Gradle build (its own root project): a standard multi-project build
// has one only at the top, while a composite build (`includeBuild`) — and a monorepo of independent
// service builds — has one in EACH included build.
var settingsFiles = []string{"settings.gradle", "settings.gradle.kts"}

func hasSettingsFile(dir string) bool {
	for _, f := range settingsFiles {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

// hasBuildScript reports whether dir has a build.gradle[.kts] (a project build script, ignoring settings).
func hasBuildScript(dir string) bool {
	for _, f := range []string{"build.gradle", "build.gradle.kts"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

// buildRoots finds the Gradle build roots under dir. Each directory with a SETTINGS file is an
// independent build and becomes a root, and the walk keeps descending past it so that composite/included
// builds (`includeBuild ...`) — e.g. a monorepo whose root settings.gradle pulls each service in as its
// own build — are all discovered and resolved individually. (Running `gradle -p <root> dependencies` only
// reports the ROOT project, so an aggregator root with no runtimeClasspath contributes nothing on its own;
// the included builds are where the real dependency trees live.) When there is NO settings file anywhere,
// a bare build.gradle at dir is the single build root (the common single-module fast path). Gradle
// output/VCS/tooling/source dirs are skipped; bounded to maxBuildRoots.
func buildRoots(dir string) []string {
	var roots []string
	var covered []string // settings-root paths: a build.gradle-only dir beneath one is a subproject, not a root
	underCovered := func(p string) bool {
		for _, c := range covered {
			if strings.HasPrefix(p, c+string(os.PathSeparator)) {
				return true
			}
		}
		return false
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if p != dir {
			switch d.Name() {
			case "build", "target", ".gradle", "buildSrc", "node_modules", ".git", ".idea", "src":
				return filepath.SkipDir // Gradle output / build-logic / VCS / tooling / sources – never a build root
			}
		}
		switch {
		case hasSettingsFile(p):
			// An independent build (its own root project). Composite builds (`includeBuild`) nest one per
			// included build, so KEEP descending to find them; its build.gradle-only subdirs are its
			// subprojects (marked covered below), resolved by gradle on this root.
			roots = append(roots, p)
			covered = append(covered, p)
		case hasBuildScript(p):
			if underCovered(p) {
				return filepath.SkipDir // a subproject of an enclosing settings-root build – not a separate root
			}
			roots = append(roots, p) // a standalone single-module build (no settings file)
			if len(roots) >= maxBuildRoots {
				return filepath.SkipAll
			}
			return filepath.SkipDir // its own subprojects belong to this build
		}
		if len(roots) >= maxBuildRoots {
			return filepath.SkipAll
		}
		return nil
	})
	return roots
}

// initScript walks the resolution-result GRAPH of the runtimeClasspath of EVERY project in the build (root
// + all subprojects, so a standard multi-project `include` build is fully covered — the per-project
// `dependencies` task only reported the root) and prints each resolved Maven module as a
// `SYNAPSE_DEP group:module:version` line, plus a `SYNAPSE_RESOLVE_ERROR <notation>` line for each
// dependency it could NOT resolve.
//
// The resolutionResult is read from METADATA only (it does NOT download artifacts): this both avoids a
// download-amplification vector from a hostile build and, unlike a lenient artifact view, still reports a
// graph module whose jar is unreachable — and it records an unresolvable dependency as an
// UnresolvedDependencyResult node instead of aborting, so we can emit it as an explicit gap marker rather
// than silently under-reporting. The per-project resolve is wrapped in try/catch so one bad project (or a
// hard resolve failure) can't abort the others; a caught throwable is itself surfaced as a resolve error.
// It fires in projectsEvaluated so the configurations exist. Composite/included builds are covered because
// Resolve runs this per build root.
const initScript = `gradle.projectsEvaluated {
    rootProject.allprojects { p ->
        def cfg = p.configurations.findByName('runtimeClasspath')
        if (cfg != null && cfg.canBeResolved) {
            try {
                def rr = cfg.incoming.resolutionResult
                rr.allComponents { c ->
                    def cid = c.id
                    if (cid instanceof org.gradle.api.artifacts.component.ModuleComponentIdentifier) {
                        println "SYNAPSE_DEP ${cid.group}:${cid.module}:${cid.version}"
                    }
                }
                rr.allDependencies { d ->
                    if (d instanceof org.gradle.api.artifacts.result.UnresolvedDependencyResult) {
                        println "SYNAPSE_RESOLVE_ERROR ${d.requested.displayName}"
                    }
                }
            } catch (Throwable t) {
                println "SYNAPSE_RESOLVE_ERROR ${p.path} (${t.getClass().simpleName})"
            }
        }
    }
}
`

// defaultHTTPTimeoutMS bounds how long gradle waits on a repository connection/read. Kept short so an
// UNREACHABLE private mirror (a very common first entry in enterprise repo lists) fails fast and the scan
// does not hang for minutes; override via SYNAPSE_GRADLE_HTTP_TIMEOUT_MS.
const defaultHTTPTimeoutMS = 15000

func httpTimeoutMS() string {
	if v := strings.TrimSpace(os.Getenv("SYNAPSE_GRADLE_HTTP_TIMEOUT_MS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return v
		}
	}
	return strconv.Itoa(defaultHTTPTimeoutMS)
}

// args is the gradle invocation: run the trivial `help` task with our init script attached (which resolves
// every project's runtimeClasspath at configuration time and prints SYNAPSE_DEP lines), plain console (no
// ANSI), no daemon (nothing persists). Short HTTP timeouts make an unreachable repo fail fast rather than
// hang. `-p` sets the build root; the cache is GRADLE_USER_HOME (env).
func (r *Resolver) args(dir, initPath string) []string {
	to := httpTimeoutMS()
	return []string{
		"--no-daemon", "--console=plain", "-q",
		"--init-script", initPath,
		"-Dorg.gradle.internal.http.connectionTimeout=" + to,
		"-Dorg.gradle.internal.http.socketTimeout=" + to,
		"-p", dir, "help",
	}
}

func (r *Resolver) allowedHosts() []string {
	return append(append([]string{}, defaultRepoHosts...), r.repoHosts...)
}

func (r *Resolver) run(ctx context.Context, dir, initPath string) ([]byte, error) {
	args := r.args(dir, initPath)
	var env []string
	if r.gradleHome != "" {
		env = []string{"GRADLE_USER_HOME=" + r.gradleHome}
	}
	if r.runner != nil {
		res, err := r.runner.Run(ctx, ports.ToolSpec{
			Name:          r.bin,
			Args:          args,
			ReadOnlyPaths: []string{dir, filepath.Dir(initPath)}, // bind the init script (read-only) for gradle
			Workdir:       r.gradleHome,                          // persistent cache (when set) is the one writable bind
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
	// Gradle refuses to run if JAVA_HOME is unset or points at an absent JDK (a common local-dev state).
	// On the trusted-local direct-exec path, auto-detect a JDK and inject it so resolution succeeds
	// instead of failing with "JAVA_HOME is set to an invalid directory"; if none is found the env is
	// left as-is and Gradle's own error is surfaced (via source_warnings).
	cmd.Env = ensureJavaHome(append(scrubSynapseEnv(os.Environ()), env...), func() string { return detectJDK(ctx) })
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, truncate(stderr.String(), 300))
	}
	return stdout.Bytes(), nil
}

// parseGradleDeps parses the init script's stdout into pkg:maven components and the list of unresolved
// dependency notations. The testable core (no exec): one `SYNAPSE_DEP group:module:version` line per
// resolved Maven module (from the resolution-result graph) becomes a deduped-by-PURL component; malformed /
// BOM / version-less coords are dropped. Each `SYNAPSE_RESOLVE_ERROR <notation>` line (a dependency gradle
// could not resolve) is collected so Resolve can surface an incomplete tree instead of a false-clean.
//
// SECURITY: both markers are ordinary stdout, so a hostile project build script — which runs arbitrary
// Groovy at configuration time (under the sandbox in production) — could `println` a forged SYNAPSE_DEP /
// SYNAPSE_RESOLVE_ERROR line. Impact is bounded to ADDING spurious components / warnings; it cannot
// suppress the real coordinates our init script prints, and a target can already misdeclare its own
// dependencies. This is inherent to parsing gradle stdout (gradle exposes no target-inaccessible output
// channel here) and was equally true of the prior tree parser — accepted as defense-in-depth, not a gap.
func parseGradleDeps(data []byte) (comps []sbom.Component, unresolved []string) {
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "SYNAPSE_DEP "):
			coord := strings.TrimSpace(strings.TrimPrefix(line, "SYNAPSE_DEP "))
			parts := strings.Split(coord, ":") // group:module:version (the init script emits exactly 3 parts)
			if len(parts) != 3 {
				continue
			}
			group, artifact, version := parts[0], parts[1], parts[2]
			if group == "" || artifact == "" || !sbom.IsResolvedVersion(version) {
				continue
			}
			purl := "pkg:maven/" + group + "/" + artifact + "@" + version
			if seen[purl] {
				continue
			}
			seen[purl] = true
			comps = append(comps, sbom.Component{
				Name:    group + ":" + artifact, // matches the other Maven adapters + the owned-advisory key
				Version: version,
				PURL:    purl,
				// Production is correct because the init script resolves only `runtimeClasspath` (excludes test).
				Scope: sbom.ScopeProduction,
			})
		case strings.HasPrefix(line, "SYNAPSE_RESOLVE_ERROR "):
			if n := strings.TrimSpace(strings.TrimPrefix(line, "SYNAPSE_RESOLVE_ERROR ")); n != "" {
				unresolved = append(unresolved, n)
			}
		}
	}
	return comps, unresolved
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

// ensureJavaHome returns env with a usable JAVA_HOME. If env's JAVA_HOME is missing or points at a
// directory that is not a JDK, it calls detect() to find one and sets it; if detect finds nothing the env
// is returned unchanged (Gradle then surfaces its own JAVA_HOME error). detect is a parameter so tests can
// inject a deterministic result.
func ensureJavaHome(env []string, detect func() string) []string {
	if javaHomeValid(envValue(env, "JAVA_HOME")) {
		return env
	}
	jdk := detect()
	if jdk == "" {
		return env
	}
	return setEnvVar(env, "JAVA_HOME", jdk)
}

// javaHomeValid reports whether dir looks like a JDK home. Gradle needs a JDK (not just a JRE), so it
// requires BOTH bin/java and bin/javac (the compiler is JDK-only).
func javaHomeValid(dir string) bool {
	if strings.TrimSpace(dir) == "" {
		return false
	}
	hasExe := func(names ...string) bool {
		for _, name := range names {
			if fi, err := os.Stat(filepath.Join(dir, "bin", name)); err == nil && !fi.IsDir() {
				return true
			}
		}
		return false
	}
	return hasExe("java", "java.exe") && hasExe("javac", "javac.exe")
}

// detectJDK finds a JDK home on the local host (trusted-local path only). It prefers the macOS
// java_home helper, then well-known install roots on macOS/Linux/Homebrew. Returns "" when none is found.
func detectJDK(ctx context.Context) string {
	if out, err := exec.CommandContext(ctx, "/usr/libexec/java_home").Output(); err == nil { // macOS
		if p := strings.TrimSpace(string(out)); javaHomeValid(p) {
			return p
		}
	}
	globs := []string{
		"/usr/lib/jvm/*",
		"/Library/Java/JavaVirtualMachines/*/Contents/Home",
		filepath.Join(os.Getenv("HOME"), "Library/Java/JavaVirtualMachines/*/Contents/Home"),
		"/opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
		"/opt/homebrew/opt/openjdk*",
		"/usr/local/opt/openjdk*",
	}
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			if javaHomeValid(m) {
				return m
			}
		}
	}
	return ""
}

// envValue returns the last value of key in an environment list ("" if absent).
func envValue(env []string, key string) string {
	prefix := key + "="
	val := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			val = kv[len(prefix):]
		}
	}
	return val
}

// setEnvVar returns env with key set to val, removing any prior entries for key (last-wins on all OSes).
func setEnvVar(env []string, key, val string) []string {
	prefix := key + "="
	out := env[:0:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, prefix) {
			out = append(out, kv)
		}
	}
	return append(out, prefix+val)
}
