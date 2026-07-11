// Package manifestresolve resolves the dependency tree of a lockfile-less package manifest by shelling
// out (argv only, no shell) to the ecosystem's own tool in a LOCK-ONLY, NO-SCRIPTS mode over a THROWAWAY
// COPY of the manifest, then reusing the owned lockfile parser to emit pinned components. It generalizes
// the npm resolver to the long tail of lockfile-only ecosystems whose human-authored manifest declares
// only version RANGES (so the SBOM otherwise has no resolvable version to advisory-match):
//
//	composer  composer.json  -> composer update --no-install --no-scripts --no-plugins  -> composer.lock
//	gem       Gemfile        -> bundle lock                                              -> Gemfile.lock
//	poetry    pyproject.toml -> poetry lock                                              -> poetry.lock
//
// SECURITY mirrors npmresolve: each tool runs with lifecycle scripts/plugins DISABLED so no project code
// executes; it runs against a temp copy so the user's project is never mutated; it invokes a PINNED tool
// (never a project-vendored one) with SYNAPSE_*/credential env scrubbed; in production it MUST run through
// a ToolRunner (the sandbox) with egress restricted to the ecosystem registry, and the API composition
// root refuses to enable it without a sandbox (fail-closed). Direct-exec is the trusted-local CLI path.
// Best-effort + OPT-IN: no manifest / a committed lockfile / a missing tool / any error is a no-op and
// never fails the scan.
package manifestresolve

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

// spec describes how to resolve one ecosystem's lockfile-less manifest.
type spec struct {
	ecosystem    string   // short label for tracing/warnings ("composer", "gem", "poetry")
	defaultBin   string   // the resolving tool ("composer", "bundle", "poetry")
	manifest     string   // the human-authored manifest that triggers resolution
	lockfiles    []string // committed lockfiles that make resolution redundant (short-circuit no-op)
	produced     string   // the lockfile the resolve writes into the temp dir
	args         []string // lock-only, no-scripts resolve argv
	registryHost string   // default egress allow-host for the sandbox
	// parse turns the produced lockfile bytes into components (the owned parser).
	parse func(ctx context.Context, in ownsbom.ParseInput) ([]sbom.Component, []sbom.Dependency, error)
}

// specs is the built-in ecosystem table. Each reuses the OWNED lockfile parser (one implementation).
var specs = map[string]spec{
	"composer": {
		ecosystem: "composer", defaultBin: "composer", manifest: "composer.json",
		lockfiles: []string{"composer.lock"}, produced: "composer.lock",
		args:         []string{"update", "--no-install", "--no-scripts", "--no-plugins", "--no-audit", "--no-interaction"},
		registryHost: "repo.packagist.org",
		parse: func(ctx context.Context, in ownsbom.ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
			return ownsbom.Composer{}.Parse(ctx, in)
		},
	},
	"gem": {
		ecosystem: "gem", defaultBin: "bundle", manifest: "Gemfile",
		lockfiles: []string{"Gemfile.lock"}, produced: "Gemfile.lock",
		args:         []string{"lock"},
		registryHost: "rubygems.org",
		parse: func(ctx context.Context, in ownsbom.ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
			return ownsbom.Gem{}.Parse(ctx, in)
		},
	},
	"poetry": {
		ecosystem: "poetry", defaultBin: "poetry", manifest: "pyproject.toml",
		lockfiles: []string{"poetry.lock"}, produced: "poetry.lock",
		args:         []string{"lock", "--no-interaction"},
		registryHost: "pypi.org",
		parse: func(ctx context.Context, in ownsbom.ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
			return ownsbom.Poetry{}.Parse(ctx, in)
		},
	},
}

// Resolver resolves one ecosystem (chosen at construction) via manifestresolve.New(ecosystem, bin).
type Resolver struct {
	spec     spec
	bin      string
	runner   ports.ToolRunner
	regHosts []string
}

// New returns a resolver for the given ecosystem ("composer"/"gem"/"poetry"). bin overrides the default
// tool binary ("" = the ecosystem default). An unknown ecosystem yields a resolver whose Resolve is a
// no-op, so a caller need not special-case it.
func New(ecosystem, bin string) *Resolver {
	s := specs[ecosystem]
	if strings.TrimSpace(bin) == "" {
		bin = s.defaultBin
	}
	return &Resolver{spec: s, bin: bin}
}

// Ecosystem identifies the resolver (for tracing/source warnings).
func (r *Resolver) Ecosystem() string { return r.spec.ecosystem }

// WithRunner confines the tool in a ToolRunner (the sandbox): the throwaway workdir is the one writable
// bind and egress is restricted to the ecosystem registry. nil keeps the direct exec (trusted-local CLI).
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

var _ ports.ManifestResolver = (*Resolver)(nil)

// Resolve returns the resolved component tree for the ecosystem's lockfile-less manifest under dir. It is
// a no-op (nil, nil) when the ecosystem is unknown, there is no manifest, or a committed lockfile is
// present. A missing tool or any resolution error returns (nil, err) — surfaced as a source warning,
// never failing the scan; components are returned only on success. Only the top-level dir is inspected.
func (r *Resolver) Resolve(ctx context.Context, dir string) ([]sbom.Component, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.spec.manifest == "" { // unknown ecosystem
		return nil, nil
	}
	manifest := filepath.Join(dir, r.spec.manifest)
	if fi, err := os.Stat(manifest); err != nil || !fi.Mode().IsRegular() {
		return nil, nil
	}
	for _, ln := range r.spec.lockfiles {
		if fi, err := os.Stat(filepath.Join(dir, ln)); err == nil && fi.Mode().IsRegular() {
			return nil, nil // a committed lockfile is parsed directly; resolution would be redundant
		}
	}

	work, err := os.MkdirTemp("", "synapse-manifestresolve-")
	if err != nil {
		return nil, fmt.Errorf("%s resolve: temp dir: %w", r.spec.ecosystem, err)
	}
	defer func() { _ = os.RemoveAll(work) }()
	data, err := os.ReadFile(manifest)
	if err != nil {
		return nil, fmt.Errorf("%s resolve: read %s: %w", r.spec.ecosystem, r.spec.manifest, err)
	}
	if err := os.WriteFile(filepath.Join(work, r.spec.manifest), data, 0o600); err != nil {
		return nil, fmt.Errorf("%s resolve: stage %s: %w", r.spec.ecosystem, r.spec.manifest, err)
	}
	if err := r.run(ctx, work); err != nil {
		return nil, err
	}
	lock, err := os.ReadFile(filepath.Join(work, r.spec.produced))
	if err != nil {
		return nil, fmt.Errorf("%s resolve: no %s produced: %w", r.spec.ecosystem, r.spec.produced, err)
	}
	comps, _, err := r.spec.parse(ctx, ownsbom.ParseInput{Dir: dir, Path: manifest, Content: lock})
	if err != nil {
		return nil, fmt.Errorf("%s resolve: parse generated lock: %w", r.spec.ecosystem, err)
	}
	return comps, nil
}

func (r *Resolver) allowedHosts() []string {
	return append([]string{r.spec.registryHost}, r.regHosts...)
}

func (r *Resolver) run(ctx context.Context, work string) error {
	env := []string{"HOME=" + work} // keep the tool's home/cache inside the throwaway dir
	if r.runner != nil {
		res, err := r.runner.Run(ctx, ports.ToolSpec{
			Name:         r.bin,
			Args:         r.spec.args,
			Workdir:      work,
			Env:          env,
			EgressPolicy: &ports.EgressPolicy{AllowDomains: r.allowedHosts()},
		})
		if err != nil {
			return fmt.Errorf("%s resolve (sandboxed): %w: %s", r.spec.ecosystem, err, truncate(string(res.Stderr), 300))
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("%s resolve: exit %d: %s", r.spec.ecosystem, res.ExitCode, truncate(string(res.Stderr), 300))
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.bin, r.spec.args...)
	cmd.Dir = work
	cmd.Env = append(scrubSensitiveEnv(os.Environ()), env...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s resolve: %w: %s", r.spec.ecosystem, err, truncate(stderr.String(), 300))
	}
	return nil
}

// scrubSensitiveEnv drops SYNAPSE_* and common credential env vars so a resolution subprocess can't read
// Synapse or host secrets. Mirrors npmresolve.scrubSensitiveEnv.
func scrubSensitiveEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if strings.HasPrefix(name, "SYNAPSE_") {
			continue
		}
		u := strings.ToUpper(name)
		sensitive := false
		for _, frag := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "APIKEY", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL"} {
			if strings.Contains(u, frag) {
				sensitive = true
				break
			}
		}
		if !sensitive {
			out = append(out, kv)
		}
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
