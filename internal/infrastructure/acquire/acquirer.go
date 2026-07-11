// Package acquire prepares an isolated workspace for an SCA target.
// The artifact is fetched/validated and only ever read, never executed.
//
// Scope + authorization-window enforcement happens in the SCA use case BEFORE
// Acquire is called; this package assumes the target was authorized.
package acquire

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MaxWorkspaceBytes caps the total size of a prepared workspace.
// Configurable per-engagement later; a const backstop for now.
const MaxWorkspaceBytes = 2 << 30 // 2 GiB

// credsRE matches `scheme://userinfo@` so credentials can be redacted from logs.
var credsRE = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@`)

// Acquirer prepares isolated workspaces for SCA targets.
type Acquirer struct {
	sandbox           ports.ToolRunner // when set, git clone + image pull ALWAYS run sandboxed (F4)
	egressScoped      bool             // when true, scope egress to the repo/registry host; else host-net sandbox
	imageTool         string           // crane (go-containerregistry CLI) binary for daemonless image pulls
	maxWorkspaceBytes int64            // prepared-workspace size cap; <=0 ⇒ the MaxWorkspaceBytes default
	materializeRootFS bool             // when true, an image pull also assembles the layers into a walkable rootfs
}

// New returns a new Acquirer.
func New() *Acquirer { return &Acquirer{imageTool: "crane", maxWorkspaceBytes: MaxWorkspaceBytes} }

// WithImageTool overrides the crane binary used for container-image acquisition.
func (a *Acquirer) WithImageTool(bin string) *Acquirer {
	if strings.TrimSpace(bin) != "" {
		a.imageTool = bin
	}
	return a
}

// WithMaxWorkspaceBytes overrides the prepared-workspace size cap (wired from
// SYNAPSE_MAX_WORKSPACE_BYTES at the composition root). A value <= 0 is ignored, so the
// MaxWorkspaceBytes default (2 GiB) stands. Lower it to fail fast in CI; raise it for a
// legitimately large monorepo. The same cap also bounds archive extraction (bomb guard).
func (a *Acquirer) WithMaxWorkspaceBytes(n int64) *Acquirer {
	if n > 0 {
		a.maxWorkspaceBytes = n
	}
	return a
}

// WithImageRootFS makes an image pull ALSO materialize the assembled root filesystem from the OCI layout
// (layers applied with whiteouts) into the workspace, exposed on Workspace.RootFS, so owned parsers can read
// on-disk OS-package DBs and /etc/os-release. Off by default (extra disk + time); wired from
// SYNAPSE_IMAGE_ROOTFS_ENABLED at the composition root.
func (a *Acquirer) WithImageRootFS(enabled bool) *Acquirer {
	a.materializeRootFS = enabled
	return a
}

// WithSandbox makes git clone + image pull ALWAYS run inside the sandbox (F4) – caps
// dropped, seccomp-filtered, curated read-only FS, cgroup-limited, workspace the only
// writable path – so a hostile repo/server/hook/image cannot touch the host or read its
// secrets. egressScoped selects the network posture: true confines the fetch to a netns
// whose egress is DNS-pinned to the repo/registry host (needs CAP_NET_ADMIN); false
// shares the host network un-scoped (still fully sandboxed otherwise) for an unprivileged
// deployment that cannot build a netns. A nil runner is the only path that execs directly.
func (a *Acquirer) WithSandbox(r ports.ToolRunner, egressScoped bool) *Acquirer {
	a.sandbox, a.egressScoped = r, egressScoped
	return a
}

// sandboxNet returns the network fields for an acquisition ToolSpec: an egress-scoped
// policy when available, else a host-network (un-scoped but sandboxed) request.
func (a *Acquirer) sandboxNet(allowHosts []string) (*ports.EgressPolicy, bool) {
	if a.egressScoped {
		return &ports.EgressPolicy{AllowDomains: allowHosts}, false
	}
	return nil, true // HostNetwork: sandboxed, host net, no egress scoping
}

var _ ports.Acquirer = (*Acquirer)(nil)

// Acquire dispatches on the target kind. local is scanned in place; git is
// shallow-cloned into a temp workspace that is cleaned up after the scan.
func (a *Acquirer) Acquire(ctx context.Context, req ports.AcquireRequest) (*ports.Workspace, error) {
	switch req.Kind {
	case "", ports.TargetLocal:
		return acquireLocal(req.Value, a.maxWorkspaceBytes)
	case ports.TargetGit:
		return a.acquireGit(ctx, req.Value, req.Ref)
	case ports.TargetArchive:
		return acquireArchive(req.Value, a.maxWorkspaceBytes)
	case ports.TargetImage:
		return a.acquireImage(ctx, req.Value)
	default:
		return nil, fmt.Errorf("%w: unknown target kind %q", shared.ErrValidation, req.Kind)
	}
}

func acquireLocal(value string, maxBytes int64) (*ports.Workspace, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("%w: target value is required", shared.ErrValidation)
	}
	fi, err := os.Lstat(value) // do not follow a symlinked root
	if err != nil {
		return nil, fmt.Errorf("stat target: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: target path is a symlink", shared.ErrValidation)
	}
	lockfiles, localModules, unresolved, err := inspectWorkspace(value, maxBytes)
	if err != nil {
		return nil, err
	}
	// Scanned in place (no container isolation until P3); per-file symlink/special
	// guards live in the detector, which re-walks this dir.
	return &ports.Workspace{Dir: value, Lockfiles: lockfiles, LocalModules: localModules, UnresolvedEcosystems: unresolved}, nil
}

func (a *Acquirer) acquireGit(ctx context.Context, url, ref string) (*ports.Workspace, error) {
	if err := validateGitURL(url); err != nil {
		return nil, err
	}
	if err := validateGitRef(ref); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "synapse-ws-*")
	if err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(dir) }

	// argv (no shell), shallow, no tags, restricted transports, no prompts.
	args := []string{
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=never",
		"clone", "--depth", "1", "--no-tags", "--single-branch",
	}
	if ref != "" {
		args = append(args, "--branch", ref) // validated: no option injection
	}
	args = append(args, "--", url, dir)
	gitEnv := []string{"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "GCM_INTERACTIVE=never"}

	if a.sandbox != nil {
		// Sandboxed clone (E15/F4): confine git with the workspace as the only writable path.
		// validateGitURL guarantees an http(s) URL, so Hostname() is the host to allow when
		// egress can be scoped; otherwise the clone runs host-net but still fully sandboxed.
		host, herr := gitHost(url)
		if herr != nil {
			_ = cleanup()
			return nil, herr
		}
		if herr := rejectInternalAcquisitionHost(host); herr != nil {
			_ = cleanup()
			return nil, herr
		}
		egress, hostNet := a.sandboxNet([]string{host})
		res, rerr := a.sandbox.Run(ctx, ports.ToolSpec{
			Name:         "git",
			Args:         args,
			Env:          gitEnv,
			Workdir:      dir, // the only writable path; git clones here
			EgressPolicy: egress,
			HostNetwork:  hostNet,
		})
		if rerr != nil {
			_ = cleanup()
			return nil, fmt.Errorf("git clone (sandboxed) failed: %w", rerr)
		}
		if res.ExitCode != 0 {
			_ = cleanup()
			combined := redactCreds(string(res.Stdout) + string(res.Stderr))
			return nil, fmt.Errorf("git clone failed: exit %d: %s", res.ExitCode, truncate(combined, 400))
		}
	} else {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Env = append(os.Environ(), gitEnv...)
		if out, err := cmd.CombinedOutput(); err != nil {
			_ = cleanup()
			// Redact any embedded credentials before the message reaches logs.
			return nil, fmt.Errorf("git clone failed: %w: %s", err, truncate(redactCreds(string(out)), 400))
		}
	}

	lockfiles, localModules, unresolved, err := inspectWorkspace(dir, a.maxWorkspaceBytes)
	if err != nil {
		_ = cleanup()
		return nil, err
	}
	return &ports.Workspace{Dir: dir, Lockfiles: lockfiles, LocalModules: localModules, UnresolvedEcosystems: unresolved, Cleanup: cleanup}, nil
}

// rejectInternalAcquisitionHost refuses an acquisition target whose host resolves to a
// loopback or link-local address (re-audit SSRF fix). A scan/clone URL is operator-
// supplied and the egress is then scoped TO its host, so without this a target like
// https://169.254.169.254/… (cloud metadata) or https://127.0.0.1/… would be reachable.
// Link-local (169.254/16, fe80::/10) + loopback are NEVER legitimate code/image sources;
// RFC1918 is allowed (an internal git/registry server is a valid acquisition target).
func rejectInternalAcquisitionHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("%w: empty acquisition host", shared.ErrValidation)
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if resolved, err := net.LookupIP(host); err == nil {
		ips = resolved
	} else {
		return nil // unresolvable: the egress pin / fetch fails closed downstream anyway
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("%w: acquisition host %q resolves to a loopback/link-local address (%s) – refused (SSRF/metadata guard)", shared.ErrValidation, host, ip)
		}
	}
	return nil
}

// gitHost extracts the host to allow through egress from a validated http(s) clone URL.
func gitHost(rawURL string) (string, error) {
	u, err := neturl.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("%w: cannot determine git host from URL", shared.ErrValidation)
	}
	return u.Hostname(), nil
}

// imageRefRE bounds a container image reference to safe characters (no shell metacharacters
// or whitespace); crane gets argv (no shell), and validateImageRef also blocks a leading
// dash so the ref cannot be parsed as a flag.
var imageRefRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]*$`)

// acquireImage pulls a container image's rootfs into an OCI layout for SCA: a
// DAEMONLESS pull (crane / go-containerregistry – never `docker run`), pinned to one
// platform, written into the workspace. When a sandbox is set, the pull runs confined
// with egress restricted to the registry. syft auto-detects the layout (oci-dir scan).
func (a *Acquirer) acquireImage(ctx context.Context, ref string) (*ports.Workspace, error) {
	ref = strings.TrimSpace(ref)
	if err := validateImageRef(ref); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "synapse-ws-*")
	if err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(dir) }
	layout := filepath.Join(dir, "image") // crane writes the OCI layout here; syft scans it
	args := []string{"pull", "--format=oci", "--platform=linux/amd64", ref, layout}

	regHosts := registryHosts(ref)
	for _, h := range regHosts {
		if herr := rejectInternalAcquisitionHost(h); herr != nil {
			_ = cleanup()
			return nil, herr
		}
	}
	if a.sandbox != nil {
		egress, hostNet := a.sandboxNet(regHosts)
		res, rerr := a.sandbox.Run(ctx, ports.ToolSpec{
			Name:         a.imageTool,
			Args:         args,
			Workdir:      dir, // the only writable path; crane writes the layout here
			EgressPolicy: egress,
			HostNetwork:  hostNet,
		})
		if rerr != nil {
			_ = cleanup()
			return nil, fmt.Errorf("image pull (sandboxed) failed: %w", rerr)
		}
		if res.ExitCode != 0 {
			_ = cleanup()
			return nil, fmt.Errorf("image pull failed: exit %d: %s", res.ExitCode, truncate(redactCreds(string(res.Stderr)), 400))
		}
	} else {
		cmd := exec.CommandContext(ctx, a.imageTool, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			_ = cleanup()
			return nil, fmt.Errorf("image pull failed: %w: %s", err, truncate(redactCreds(string(out)), 400))
		}
	}
	// The packages live in the image layers (syft oci-dir scans the layout); there are no
	// host-side lockfiles to inspect, so the workspace carries just the layout dir. Recover
	// image metadata (layer stack + build history) from the OCI config for layer attribution
	// (Epic D) – best-effort: nil if the config is unreadable, never fails the acquisition.
	ws := &ports.Workspace{Dir: layout, Image: readImageInfo(layout, ref), Cleanup: cleanup}
	// Optionally assemble the layers into a walkable root filesystem (owned OS-package cataloging reads it).
	// BEST-EFFORT: the rootfs is supplementary – syft still scans the OCI layout in Dir regardless – and the
	// extractor is fail-closed, so a failure (a hostile layer the hardening refused, an unsupported
	// compression, a malformed layer) SKIPS the rootfs with a recorded reason rather than aborting the scan.
	// RootFS is left empty so no partial tree is ever consumed.
	if a.materializeRootFS {
		rootfs := filepath.Join(dir, "rootfs")
		if err := extractOCIRootFS(ctx, layout, rootfs, a.maxWorkspaceBytes); err != nil {
			ws.RootFSNote = truncate(redactCreds(err.Error()), 200)
		} else {
			ws.RootFS = rootfs
		}
	}
	return ws, nil
}

// registryHosts is the egress allow-list for pulling ref: the registry host, plus the
// auth/CDN hosts the well-known public registries serve tokens/blobs from. A private or
// self-hosted registry is typically single-host.
func registryHosts(ref string) []string {
	reg := "docker.io"
	if i := strings.IndexByte(ref, '/'); i > 0 {
		if first := ref[:i]; strings.ContainsAny(first, ".:") || first == "localhost" {
			reg = first
		}
	}
	switch reg {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		// registry + token + the AWS CloudFront blob CDN Docker Hub serves layers from.
		return []string{"registry-1.docker.io", "auth.docker.io", "production.cloudfront.docker.com", "index.docker.io"}
	case "ghcr.io":
		return []string{"ghcr.io", "pkg-containers.githubusercontent.com"}
	case "quay.io":
		return []string{"quay.io", "cdn.quay.io", "cdn01.quay.io", "cdn02.quay.io", "cdn03.quay.io"}
	default:
		return []string{reg} // private / self-hosted registry (single host)
	}
}

// validateImageRef rejects refs with whitespace or shell metacharacters and any leading
// dash (option injection); crane still gets argv (no shell).
func validateImageRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("%w: image reference is required", shared.ErrValidation)
	}
	if !imageRefRE.MatchString(ref) {
		return fmt.Errorf("%w: invalid image reference %q", shared.ErrValidation, ref)
	}
	return nil
}

// validateGitURL allows only http(s) transports and blocks option injection.
// Plaintext git:// is rejected (unauthenticated, MITM-able).
func validateGitURL(url string) error {
	url = strings.TrimSpace(url)
	if url == "" || strings.HasPrefix(url, "-") {
		return fmt.Errorf("%w: invalid git URL", shared.ErrValidation)
	}
	// Require https – plaintext http:// is unauthenticated + on-path-tamperable (the same
	// reason git:// is rejected): a MITM'd clone could plant a malicious lockfile/source the
	// SCA pipeline then parses. The egress pin limits WHERE the clone connects, not the
	// integrity of what comes back.
	if strings.HasPrefix(strings.ToLower(url), "https://") {
		return nil
	}
	return fmt.Errorf("%w: git URL must be https://", shared.ErrValidation)
}

// gitRefPattern allows a branch/tag name: starts alphanumeric, then word chars,
// dot, dash, slash. Blocks leading '-' (option injection) and shell/control chars.
var gitRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

// validateGitRef accepts an empty ref (default branch) or a conservative branch/tag.
func validateGitRef(ref string) error {
	if ref == "" {
		return nil
	}
	if len(ref) > 255 || !gitRefPattern.MatchString(ref) {
		return fmt.Errorf("%w: invalid git ref", shared.ErrValidation)
	}
	return nil
}

// lockfileNames are dependency lockfiles whose presence indicates resolved,
// pinned versions (and thus a complete SCA result). Lowercased for matching.
var lockfileNames = map[string]bool{
	"package-lock.json": true, "npm-shrinkwrap.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"gemfile.lock": true, "poetry.lock": true, "pipfile.lock": true, "uv.lock": true,
	"go.sum": true, "cargo.lock": true, "composer.lock": true, "gradle.lockfile": true,
}

var goModModuleRE = regexp.MustCompile(`(?m)^module\s+(\S+)`)

// inspectWorkspace enforces the size cap, collects recognized lockfile basenames
// (completeness signal), and collects local module identities – module paths from
// go.mod files + package.json names – which mark first-party components. Symlinks
// are not followed.
func inspectWorkspace(root string, maxBytes int64) (lockfiles, localModules, unresolvedEco []string, err error) {
	if maxBytes <= 0 {
		maxBytes = MaxWorkspaceBytes
	}
	var total int64
	seenLock := map[string]bool{}
	seenMod := map[string]bool{}
	// build manifest basename -> (ecosystem, lockfile that would resolve it)
	hasManifest := map[string]bool{} // ecosystem -> manifest present
	hasResolved := map[string]bool{} // ecosystem -> resolving lockfile present
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		base := strings.ToLower(d.Name())
		if lockfileNames[base] {
			seenLock[base] = true
		}
		// Track build systems + whether each has a resolving lockfile. A manifest with
		// no lockfile means the SBOM under-reports that ecosystem's transitive deps.
		switch base {
		case "build.gradle", "build.gradle.kts":
			hasManifest["gradle"] = true
		case "gradle.lockfile":
			hasResolved["gradle"] = true
		case "pom.xml":
			hasManifest["maven"] = true // Maven has no standard lockfile; always a resolution risk
		}
		switch base {
		case "go.mod":
			if m := readGoModule(path); m != "" {
				seenMod[m] = true
			}
		case "package.json":
			if m := readPackageName(path); m != "" {
				seenMod[m] = true
			}
		}
		fi, e := d.Info()
		if e != nil {
			return nil
		}
		total += fi.Size()
		if total > maxBytes {
			return fmt.Errorf("%w: target exceeds the %d-byte workspace cap", shared.ErrValidation, maxBytes)
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, nil, walkErr
	}
	unresolved := map[string]bool{}
	for eco := range hasManifest {
		if !hasResolved[eco] {
			unresolved[eco] = true
		}
	}
	return sortedKeys(seenLock), sortedKeys(seenMod), sortedKeys(unresolved), nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// readGoModule extracts the `module` path from a go.mod (bounded read).
func readGoModule(path string) string {
	data, err := readCapped(path, 64<<10)
	if err != nil {
		return ""
	}
	if m := goModModuleRE.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// readPackageName extracts the top-level "name" from a package.json (bounded read).
func readPackageName(path string) string {
	data, err := readCapped(path, 256<<10)
	if err != nil {
		return ""
	}
	var pkg struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return ""
	}
	return strings.TrimSpace(pkg.Name)
}

func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, max))
}

func redactCreds(s string) string { return credsRE.ReplaceAllString(s, "$1***@") }

// truncate shortens s to at most n runes (never splits a UTF-8 rune).
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
