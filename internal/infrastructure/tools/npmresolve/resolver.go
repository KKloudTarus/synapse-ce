// Package npmresolve resolves an npm project's dependency tree (direct + transitive, with pinned
// versions) from a package.json that has NO committed lockfile — the common raw-source state where the
// manifest declares only semver RANGES (^1.2.3, ~1.0, >=2) and the SBOM otherwise sees no resolvable
// version to advisory-match. It shells out (argv only, no shell) to a pinned `npm` binary running
// `npm install --package-lock-only --ignore-scripts`, which resolves the full tree from the registry into
// a package-lock.json WITHOUT downloading node_modules and WITHOUT running any lifecycle script, then
// reuses the owned package-lock.json parser to emit pkg:npm components. Zero-setup: the user does not have
// to run `npm install` first.
//
// SECURITY: package.json can declare preinstall/install/postinstall lifecycle scripts that run arbitrary
// code. `--ignore-scripts` disables them, and `--package-lock-only` skips node_modules/build entirely, so
// no project code executes. The command runs against a COPY of package.json in a throwaway temp dir, so
// the user's project is never mutated. It invokes a PINNED `npm` (never a project-vendored one). In
// production it MUST run through a ToolRunner (the sandbox) confining the filesystem and restricting egress
// to the configured registry; the API composition root refuses to enable it without a sandbox
// (fail-closed). Direct-exec is the trusted-local CLI dogfood path. OPT-IN (SYNAPSE_NPM_RESOLVE_ENABLED) +
// BEST-EFFORT: no package.json / a committed lockfile / missing npm / any error yields no components and
// never fails the scan.
package npmresolve

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// defaultRegistryHosts is the egress allow-list for the sandboxed run: the public npm registry. Private
// registries are added via WithRegistryHosts.
var defaultRegistryHosts = []string{"registry.npmjs.org"}

// lockfileNames are the committed lockfiles that make resolution redundant (the owned NPM/other parsers
// already read them on their own marker pass), so the resolver stays a no-op when one is present.
var lockfileNames = []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}

// Resolver runs `npm install --package-lock-only` to resolve a package.json with no committed lockfile.
type Resolver struct {
	bin      string
	runner   ports.ToolRunner
	regHosts []string
}

// New returns a resolver using the given npm binary (defaults to "npm" in PATH).
func New(bin string) *Resolver {
	if strings.TrimSpace(bin) == "" {
		bin = "npm"
	}
	return &Resolver{bin: bin}
}

// WithRunner runs npm through a ToolRunner (the SandboxRunner): the throwaway workdir is the one writable
// bind and egress is restricted to the configured registry. nil keeps the direct exec (dev/CLI; trusted).
func (r *Resolver) WithRunner(runner ports.ToolRunner) *Resolver { r.runner = runner; return r }

// WithRegistryHosts adds extra registry hosts to the sandbox egress allow-list (private mirror).
func (r *Resolver) WithRegistryHosts(hosts []string) *Resolver {
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			r.regHosts = append(r.regHosts, h)
		}
	}
	return r
}

var _ ports.NPMResolver = (*Resolver)(nil)

// Resolve returns the resolved pkg:npm component tree for a package.json under dir with no committed
// lockfile. It is a no-op (nil, nil) when there is no package.json, a lockfile is already present, or npm
// is unavailable; any resolution error is returned alongside whatever resolved so a failure is diagnosable.
func (r *Resolver) Resolve(ctx context.Context, dir string) ([]sbom.Component, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pkgJSON := filepath.Join(dir, "package.json")
	if fi, err := os.Stat(pkgJSON); err != nil || !fi.Mode().IsRegular() {
		return nil, nil // not an npm project (root)
	}
	for _, ln := range lockfileNames {
		if fi, err := os.Stat(filepath.Join(dir, ln)); err == nil && fi.Mode().IsRegular() {
			return nil, nil // a committed lockfile is parsed directly; resolution would be redundant
		}
	}

	// Work in a throwaway dir so npm never writes into the user's project. npm needs a writable HOME +
	// cache; keep both inside the temp dir so nothing leaks onto the host.
	work, err := os.MkdirTemp("", "synapse-npmresolve-")
	if err != nil {
		return nil, fmt.Errorf("npm resolve: temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(work) }()
	data, err := os.ReadFile(pkgJSON)
	if err != nil {
		return nil, fmt.Errorf("npm resolve: read package.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(work, "package.json"), data, 0o600); err != nil {
		return nil, fmt.Errorf("npm resolve: stage package.json: %w", err)
	}

	if err := r.run(ctx, work); err != nil {
		return nil, err
	}
	lock, err := os.ReadFile(filepath.Join(work, "package-lock.json"))
	if err != nil {
		return nil, fmt.Errorf("npm resolve: no package-lock.json produced: %w", err)
	}
	comps, _, err := ownsbom.NPM{}.Parse(ctx, ownsbom.ParseInput{Dir: dir, Path: pkgJSON, Content: lock})
	if err != nil {
		return nil, fmt.Errorf("npm resolve: parse generated lock: %w", err)
	}
	return comps, nil
}

// args resolves the lockfile only, with all script execution and interactive/telemetry noise disabled.
func (r *Resolver) args() []string {
	return []string{
		"install", "--package-lock-only", "--ignore-scripts",
		"--no-audit", "--no-fund", "--no-update-notifier", "--loglevel=error",
	}
}

func (r *Resolver) allowedHosts() []string {
	return append(append([]string{}, defaultRegistryHosts...), r.regHosts...)
}

// run executes npm in the prepared work dir. env keeps npm's HOME and cache inside the throwaway dir.
func (r *Resolver) run(ctx context.Context, work string) error {
	env := []string{
		"HOME=" + work,
		"npm_config_cache=" + filepath.Join(work, ".npm"),
		"npm_config_fund=false",
		"npm_config_audit=false",
		"npm_config_update_notifier=false",
	}
	if r.runner != nil {
		res, err := r.runner.Run(ctx, ports.ToolSpec{
			Name:         r.bin,
			Args:         r.args(),
			Workdir:      work, // the one writable bind (package.json copy + generated lock + cache)
			Env:          env,
			EgressPolicy: &ports.EgressPolicy{AllowDomains: r.allowedHosts()},
		})
		if err != nil {
			return fmt.Errorf("npm resolve (sandboxed): %w: %s", err, truncate(string(res.Stderr), 300))
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("npm resolve: exit %d: %s", res.ExitCode, truncate(string(res.Stderr), 300))
		}
		return nil
	}
	// Direct exec: dev/CLI path for a TRUSTED local project. --ignore-scripts still holds, so no project
	// code runs; scrub SYNAPSE_* secrets from the child regardless (defense-in-depth).
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.bin, r.args()...)
	cmd.Dir = work
	cmd.Env = append(scrubSynapseEnv(os.Environ()), env...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm resolve: %w: %s", err, truncate(stderr.String(), 300))
	}
	return nil
}

// scrubSynapseEnv drops SYNAPSE_* entries so the child npm (and any transitively-run tooling) cannot read
// Synapse secrets from the environment. Non-SYNAPSE vars (PATH, npm config, ...) are preserved.
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
