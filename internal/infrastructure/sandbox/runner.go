// Package sandbox implements ports.ToolRunner by confining each argv tool run in an
// unprivileged sandbox (see docs/08-security-model.md for the
// as-built control set). It orchestrates bubblewrap (bwrap) – the vetted, minimal-trust
// namespace sandbox (Flatpak's engine) – to give every run: a CURATED read-only OS tree
// (NOT the whole host root – $HOME/secrets are absent, F2), a single read-write scoped
// workdir, a fresh tmpfs, all namespaces unshared (user/net/pid/ipc/uts/cgroup), every
// capability dropped, a default-DENY seccomp syscall filter (F1, fail-closed), and a new
// session. The fresh network namespace is the DEFAULT-DENY egress backstop: a tool can
// reach nothing off-host until the egress allowlist opens scope-derived destinations
// inside that netns. cgroup memory.max/pids.max are applied via a per-run cgroup the tool
// is cloned into (F3), on every path; systemd-run is a best-effort fallback for
// unprivileged runs that cannot create a cgroup.
//
// It is argv-only: the runner builds `[systemd-run …] bwrap … -- tool
// args…` as an argv array and delegates the actual exec – timeout, output cap, and
// whole-process-group kill – to the existing ExecRunner, so there is one execution
// primitive. bwrap is Linux-only; on a host without it (macOS dev) NewRunner returns
// ErrUnavailable so the caller degrades rather than running unsandboxed.
package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/toolrunner"
	"github.com/KKloudTarus/synapse-ce/internal/platform/binregistry"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ErrUnavailable means a required sandbox control is unavailable on this host. The caller
// must fail closed for sandbox-required runs, never silently run unsandboxed.
var ErrUnavailable = errors.New("sandbox unavailable")

// secretRe matches a {{secret:NAME}} placeholder in a ToolSpec env value.
var secretRe = regexp.MustCompile(`\{\{secret:([A-Za-z0-9_.-]+)\}\}`)

// Runner confines tool execution with bubblewrap, delegating exec to an ExecRunner.
type applierEnforcer struct {
	applier *egress.Applier
}

func (a *applierEnforcer) Probe(ctx context.Context) error { return a.applier.Probe(ctx) }

func (a *applierEnforcer) Setup(ctx context.Context, name string, idx, pid int, _, _ string, policy ports.EgressPolicy) (ports.EgressNamespace, error) {
	return a.applier.SetupForPID(ctx, name, idx, policy, pid)
}

type bwrapStatus struct {
	ChildPID int `json:"child-pid"`
}

func readBwrapChildPID(r *os.File) (int, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return 0, fmt.Errorf("read bubblewrap status: %w", err)
		}
		return 0, errors.New("bubblewrap status closed before child pid")
	}
	var status bwrapStatus
	if err := json.Unmarshal(scanner.Bytes(), &status); err != nil {
		return 0, fmt.Errorf("decode bubblewrap status: %w", err)
	}
	if status.ChildPID <= 1 {
		return 0, fmt.Errorf("bubblewrap reported invalid child pid %d", status.ChildPID)
	}
	return status.ChildPID, nil
}

type Runner struct {
	inner            *toolrunner.ExecRunner
	bwrap            string                // resolved bwrap path
	systemdRun       string                // resolved systemd-run path, or "" when its fallback is unavailable
	directCgroupRoot string                // systemd-delegated cgroup v2 subtree, or "" when unavailable
	memMax           int64                 // default cgroup memory.max
	pidsMax          int                   // default cgroup pids.max
	vault            ports.CredentialVault // optional; resolves {{secret:NAME}} env placeholders
	egress           ports.EgressEnforcer  // optional; enforces a per-run scope egress netns
	connMon          *ebpf.Monitor         // optional; eBPF connect-logger for egress runs
	binreg           *binregistry.Registry // optional; verifies tool-binary integrity before exec (F5)
	lookupNetIP      egressLookup          // host-side exact-domain resolver; defaults to net.DefaultResolver
	netnsSlots       chan int              // free-list of netns/subnet slots [0,63] (ops: no wrap-collision)
	runSeq           atomic.Int64          // disambiguates per-run cgroups (F3)
}

// netnsSlotCount bounds concurrent egress runs (the /30 subnet space the applier carves).
const netnsSlotCount = 64

// curatedEtc is the allowlist of PUBLIC /etc paths bound read-only into the sandbox (F2
// re-audit fix). It deliberately omits /etc/shadow, /etc/gshadow, /etc/ssl/private,
// /etc/pki/tls/private, /etc/krb5.keytab and any service-credential files – binding only
// the TLS trust store (public certs), name resolution, account names, loader, and tz.
// Covers RHEL (/etc/pki) and Debian (/etc/ssl) layouts; missing paths are skipped.
var curatedEtc = []string{
	"/etc/ssl/certs", "/etc/ssl/openssl.cnf", // Debian/General TLS trust (public certs only)
	"/etc/pki/tls/certs", "/etc/pki/tls/cert.pem", "/etc/pki/tls/openssl.cnf", "/etc/pki/ca-trust", // RHEL/AL2023 TLS trust
	"/etc/ca-certificates", "/etc/ca-certificates.conf", "/etc/crypto-policies",
	"/etc/nsswitch.conf", "/etc/resolv.conf", "/etc/host.conf", "/etc/hosts", "/etc/gai.conf",
	"/etc/protocols", "/etc/services",
	"/etc/passwd", "/etc/group", // account NAMES only (no shadow)
	"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
	"/etc/localtime", "/etc/mime.types", "/etc/gitconfig", "/etc/xdg",
}

// curatedRoot lists the OS trees bwrapArgs already binds read-only. A tool inside one of them
// needs no extra bind; anything else must be bound explicitly.
var curatedRoot = []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}

// resolveToolPath settles the path bwrap will bind and exec. It returns the name unchanged whenever
// it must not or cannot be resolved, in which case bwrap resolves it inside the sandbox and surfaces
// any not-found itself.
//
// An ALREADY-ABSOLUTE name is returned as given and needs no lookup: it is operator authority (the
// documented /opt/synapse/bin/synapse-cspm layout), which is what makes it bindable.
//
// A bare name is resolved through the host PATH only when hostPATHIsAuthority is set, which callers
// tie to integrity verification being enabled. Host PATH is otherwise NOT an authority for what may
// be bound into the sandbox: resolving it unconditionally would let an inherited entry such as
// /tmp/attacker/tool be resolved on the host and then explicitly bound in, where bwrap would instead
// resolve the bare name against the sandbox's own curated PATH and a binary outside the curated root
// would fail closed.
func prepareEgressHostsFile(policy ports.EgressPolicy) (string, error) {
	if len(policy.PinnedHosts) == 0 {
		return "", nil
	}
	pins := make(map[string][]netip.Addr, len(policy.PinnedHosts))
	for rawHost, addrs := range policy.PinnedHosts {
		host := strings.TrimSpace(strings.ToLower(rawHost))
		if host == "" || strings.ContainsAny(host, "\x00\r\n \t") {
			return "", fmt.Errorf("invalid pinned host %q", host)
		}
		pins[host] = append(pins[host], addrs...)
	}
	hosts := make([]string, 0, len(pins))
	for host := range pins {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	var pinned strings.Builder
	for _, host := range hosts {
		addrs := append([]netip.Addr(nil), pins[host]...)
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
		for _, addr := range addrs {
			addr = addr.Unmap()
			if !addr.IsValid() || !addr.Is4() {
				return "", fmt.Errorf("pinned host %q contains a non-IPv4 address", host)
			}
			fmt.Fprintf(&pinned, "%s %s\n", addr, host)
		}
	}
	if pinned.Len() == 0 {
		return "", nil
	}
	f, err := os.CreateTemp("", "synapse-hosts-*")
	if err != nil {
		return "", err
	}
	failed := true
	defer func() {
		_ = f.Close()
		if failed {
			_ = os.Remove(f.Name())
		}
	}()
	if _, err := f.WriteString("127.0.0.1 localhost\n::1 localhost\n" + pinned.String()); err != nil {
		return "", err
	}
	if err := f.Chmod(0o644); err != nil {
		return "", err
	}
	failed = false
	return f.Name(), nil
}

func resolveToolPath(name string, hostPATHIsAuthority bool) string {
	// A Linux container path is absolute even when this argv builder runs on a Windows host, where
	// filepath.IsAbs("/opt/...") is false.
	if strings.HasPrefix(name, "/") || filepath.IsAbs(name) {
		return name
	}
	if !hostPATHIsAuthority {
		return name
	}
	if resolved, err := exec.LookPath(name); err == nil {
		return resolved
	}
	return name
}

// underCuratedRoot reports whether an absolute path already lives inside the curated read-only
// root. Matching is segment-aligned so "/libexec/evil" is not mistaken for "/lib".
func underCuratedRoot(p string) bool {
	// path, not path/filepath: these are Linux container paths regardless of the host GOOS.
	clean := path.Clean(p)
	for _, root := range curatedRoot {
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
}

// SetBinaryRegistry enables tool-binary integrity verification (F5): before each run the
// resolved binary's sha256 is checked against its pin (config-supplied and/or TOFU); a
// mismatch refuses the run. Optional – without it, binaries are trusted by PATH (legacy).
func (r *Runner) SetBinaryRegistry(b *binregistry.Registry) { r.binreg = b }

// SetVault enables {{secret:NAME}} resolution from the credential vault. Optional – with
// no vault a spec that references a secret fails closed.
func (r *Runner) SetVault(v ports.CredentialVault) { r.vault = v }

// SetEgress enables per-run scope egress enforcement: a spec carrying an
// EgressPolicy is run inside a network namespace whose kernel filter allows only in-scope
// destinations. Optional – without it, an EgressPolicy-bearing spec fails closed.
func (r *Runner) SetEgress(a *egress.Applier) { r.egress = &applierEnforcer{applier: a} }

// SetEgressEnforcer configures an out-of-process egress enforcer, such as the
// non-privileged Unix-socket client used by native production workers.
func (r *Runner) SetEgressEnforcer(enforcer ports.EgressEnforcer) { r.egress = enforcer }

// SetConnMonitor enables the eBPF connect-logger: each egress run is placed in a
// cgroup whose connect4/connect6 hooks capture every outbound connect() attempt (incl.
// ones the egress filter drops) into the run's ToolResult.ConnectLog. Optional + best-
// effort – a missing/unprivileged logger never fails the run (it is observability).
func (r *Runner) SetConnMonitor(m *ebpf.Monitor) { r.connMon = m }

var _ ports.ToolRunner = (*Runner)(nil)

// NewRunner resolves bubblewrap (required) and systemd-run (optional, for cgroup
// limits, probed for actual usability). Returns ErrUnavailable when a required control is absent.
func NewRunner(timeout time.Duration, maxOut int, memMax int64, pidsMax int) (*Runner, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("%w: bubblewrap (bwrap) not found", ErrUnavailable)
	}
	// F1 fail-closed: a sandbox without a syscall filter is NOT a sandbox. If seccomp
	// cannot be built on this platform, refuse to construct the runner – the caller then
	// degrades rather than silently running tools with the full syscall table.
	if !seccompSupported {
		return nil, fmt.Errorf("%w: seccomp filtering is required but unsupported on this platform", ErrUnavailable)
	}
	filter, err := seccompFile()
	if err != nil {
		return nil, fmt.Errorf("%w: seccomp self-check failed: %v", ErrUnavailable, err)
	}
	defer func() { _ = filter.Close() }()
	// Finding bwrap on PATH is insufficient in a container: the runtime seccomp profile or
	// kernel policy can still deny namespace/mount setup. Exercise the same namespace and
	// seccomp primitives used for real runs so production startup fails before accepting work.
	if err := probeBubblewrap(bwrap, filter); err != nil {
		return nil, fmt.Errorf("%w: bubblewrap isolation self-check failed: %v", ErrUnavailable, err)
	}
	slots := make(chan int, netnsSlotCount)
	for i := 0; i < netnsSlotCount; i++ {
		slots <- i
	}
	r := &Runner{
		inner:       toolrunner.NewExecRunner(timeout, maxOut),
		bwrap:       bwrap,
		memMax:      memMax,
		pidsMax:     pidsMax,
		lookupNetIP: net.DefaultResolver.LookupNetIP,
		netnsSlots:  slots,
	}
	if root, cgErr := prepareDelegatedCgroup(); cgErr == nil {
		probeMem := memMax
		if probeMem <= 0 {
			probeMem = 1 << 30
		}
		probePids := pidsMax
		if probePids <= 0 {
			probePids = 512
		}
		if cg, probeErr := newRunCgroup(root, r.runSeq.Add(1), probeMem, probePids); probeErr == nil {
			r.directCgroupRoot = root
			cg.Close()
		}
	}
	if sd, err := exec.LookPath("systemd-run"); err == nil && probeSystemdRun(sd) {
		r.systemdRun = sd
	}
	return r, nil
}

// NewRunnerReady constructs the production runner, retrying until cgroup v2 resource limits are
// actually available or ctx expires. NewRunner resolves the limiter exactly once, and at first
// boot systemd may not yet have delegated the memory/pids controllers to this unit's slice, so a
// single attempt can report an unenforced limiter on a host that is merely still starting. It
// remains fail-closed: when the deadline passes without a limiter the last error is returned and
// the caller refuses to accept work.
func NewRunnerReady(ctx context.Context, timeout time.Duration, maxOut int, memMax int64, pidsMax int, interval time.Duration) (*Runner, error) {
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	var lastErr error
	for {
		runner, err := NewRunner(timeout, maxOut, memMax, pidsMax)
		switch {
		case err != nil:
			lastErr = err
		case runner.CgroupLimitsEnforced():
			return runner, nil
		default:
			lastErr = fmt.Errorf("%w: cgroup limits are required: no delegated cgroup or systemd-run fallback", ErrUnavailable)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, lastErr
		case <-timer.C:
		}
	}
}

// probeBubblewrap verifies that this process can create the namespace, mount, and seccomp
// boundary required by the runner. It executes only /bin/true in a read-only view of the host;
// no user-controlled argv, environment, or filesystem content enters this startup check.
func probeBubblewrap(bwrap string, filter *os.File) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bwrap,
		"--unshare-all",
		"--die-with-parent",
		"--new-session",
		"--ro-bind", "/", "/",
		"--seccomp", "3",
		"--", "/bin/true",
	)
	cmd.ExtraFiles = []*os.File{filter}
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("probe timed out: %w", ctx.Err())
	}
	message := strings.TrimSpace(string(output))
	if len(message) > 512 {
		message = message[:512]
	}
	if message == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, message)
}

// CgroupLimitsEnforced reports whether either the systemd-delegated cgroup v2 path
// or the verified systemd-run fallback can apply resource limits on this host.
func (r *Runner) CgroupLimitsEnforced() bool {
	return r.directCgroupRoot != "" || r.systemdRun != ""
}

// Run confines spec in bubblewrap and executes it via the inner ExecRunner.
func (r *Runner) Run(ctx context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	if spec.Name == "" {
		return ports.ToolResult{}, fmt.Errorf("%w: sandbox empty command name", shared.ErrValidation)
	}
	if spec.HostNetwork {
		return ports.ToolResult{}, fmt.Errorf("%w: host-network sandbox execution is not supported; use an egress policy with authoritative execution identity", shared.ErrValidation)
	}
	if spec.EgressPolicy != nil {
		if strings.TrimSpace(spec.EgressExecutionKind) == "" || strings.TrimSpace(spec.EgressExecutionID) == "" {
			return ports.ToolResult{}, fmt.Errorf("%w: egress policy requires authoritative execution kind and id", shared.ErrValidation)
		}
		if r.egress == nil {
			return ports.ToolResult{}, fmt.Errorf("%w: spec carries an egress policy but egress enforcement is not configured", shared.ErrValidation)
		}
	}
	// Build a CONTROLLED child environment (never inherit the worker's, which holds the
	// vault master key, DB password, and signing seed – secrets never enter logs). Secrets are
	// resolved into env values here, immediately before exec, and reach the tool via the
	// environment, not argv.
	env, secrets, err := r.childEnv(ctx, spec)
	if err != nil {
		return ports.ToolResult{}, err
	}
	// F1: build the seccomp filter fd for THIS run; bwrap loads it via `--seccomp 3` (the
	// fd's child number, since it is the first ExtraFile). Fail closed – never run a tool
	// without the syscall filter the sandbox promises.
	seccompF, serr := seccompFile()
	if serr != nil {
		return ports.ToolResult{}, fmt.Errorf("%w: build seccomp filter: %v", shared.ErrValidation, serr)
	}
	defer func() { _ = seccompF.Close() }()
	// Settle PATH lookup before verification. An absolute name is kept as given; the registry below
	// then resolves any symlinks and returns the exact path it hashed. The host PATH counts as an
	// authority for a bare name only when that name will also be integrity-verified.
	hostPATHIsAuthority := r.binreg != nil
	spec.Name = resolveToolPath(spec.Name, hostPATHIsAuthority)
	// F5: verify the tool binary's integrity before it runs, then bind and execute the returned
	// symlink-resolved path. This prevents a symlink swap from selecting a different target after
	// verification. It does not eliminate the residual window in which that target's contents could
	// be replaced between hashing and exec; fully closing that requires an fd-based execution path.
	if r.binreg != nil {
		verifiedPath, verr := r.binreg.Verify(spec.Name)
		if verr != nil {
			return ports.ToolResult{}, fmt.Errorf("%w: %v", shared.ErrValidation, verr)
		}
		spec.Name = verifiedPath
	}
	// F3: a per-run cgroup v2 with hard memory.max + pids.max so a memory/fork bomb is
	// contained on EVERY path (egress and isolated), independent of systemd-run. The tool
	// is cloned into it (CgroupFD). A native worker creates the child only under its
	// systemd-delegated subtree; development can use the verified systemd-run fallback.
	mem, pids := spec.MemMaxBytes, spec.PidsMax
	if mem <= 0 {
		mem = r.memMax
	}
	if pids <= 0 {
		pids = r.pidsMax
	}
	var runCG *runCgroup
	var cgroupErr error
	if r.directCgroupRoot != "" {
		runCG, cgroupErr = newRunCgroup(r.directCgroupRoot, r.runSeq.Add(1), mem, pids)
		if cgroupErr == nil {
			defer runCG.Close()
		}
	}
	if runCG == nil && r.systemdRun == "" && (mem > 0 || pids > 0) {
		if cgroupErr == nil {
			cgroupErr = errors.New("no delegated cgroup or systemd-run fallback")
		}
		return ports.ToolResult{}, fmt.Errorf("%w: cgroup limits are required: %v", ErrUnavailable, cgroupErr)
	}

	// Egress mode starts Bubblewrap with a fresh network namespace and pauses it on a
	// private block fd. Only after the direct child exists does the fixed root broker attach
	// that exact namespace and apply canonical scope rules. The non-root worker never runs
	// ip/iptables or a privileged command wrapper. If broker setup fails, ExecRunner kills
	// the still-paused process group before this method closes the block pipe.
	egressNS := ""
	hostsFile := ""
	var egressHandle ports.EgressNamespace
	var blockReader, blockWriter *os.File
	var statusReader, statusWriter *os.File
	blockChildFD, statusChildFD := 0, 0
	var connSess *ebpf.Session
	var allowRules []ports.EgressRule
	if spec.EgressPolicy != nil {
		var idx int
		select {
		case idx = <-r.netnsSlots:
		default:
			return ports.ToolResult{}, fmt.Errorf("%w: too many concurrent egress runs (netns slots exhausted)", shared.ErrValidation)
		}
		defer func() { r.netnsSlots <- idx }()
		egressNS = fmt.Sprintf("syn%d", idx)
		blockReader, blockWriter, err = os.Pipe()
		if err != nil {
			return ports.ToolResult{}, fmt.Errorf("create egress synchronization pipe: %w", err)
		}
		statusReader, statusWriter, err = os.Pipe()
		if err != nil {
			_ = blockReader.Close()
			_ = blockWriter.Close()
			return ports.ToolResult{}, fmt.Errorf("create bubblewrap status pipe: %w", err)
		}
		defer func() {
			_ = blockReader.Close()
			_ = blockWriter.Close()
			_ = statusReader.Close()
			_ = statusWriter.Close()
		}()
		// seccomp is fd 3; caller descriptors retain fd 4+; block and status follow.
		blockChildFD = 4 + len(spec.ExtraFiles)
		statusChildFD = blockChildFD + 1
		if r.connMon != nil {
			if runCG != nil {
				if s, merr := r.connMon.Attach(runCG.Path()); merr == nil {
					connSess = s
				}
			}
		}
	}
	const seccompChildFD = 3
	var resolvedEgressPolicy *ports.EgressPolicy
	if spec.EgressPolicy != nil {
		resolved, resolveErr := resolveEgressPolicy(ctx, *spec.EgressPolicy, r.lookupNetIP)
		if resolveErr != nil {
			return ports.ToolResult{}, fmt.Errorf("resolve egress policy: %w", resolveErr)
		}
		resolvedEgressPolicy = &resolved
		var prepareErr error
		hostsFile, prepareErr = prepareEgressHostsFile(resolved)
		if prepareErr != nil {
			return ports.ToolResult{}, fmt.Errorf("prepare pinned egress hosts: %w", prepareErr)
		}
		if hostsFile != "" {
			defer func() { _ = os.Remove(hostsFile) }()
		}
	}
	argv := r.command(spec, egressNS, hostsFile, seccompChildFD, blockChildFD, statusChildFD, runCG != nil)
	extraFiles := make([]*os.File, 0, 3+len(spec.ExtraFiles))
	extraFiles = append(extraFiles, seccompF)
	extraFiles = append(extraFiles, spec.ExtraFiles...)
	if blockReader != nil {
		extraFiles = append(extraFiles, blockReader, statusWriter)
	}
	wrapped := ports.ToolSpec{
		Name:           argv[0],
		Args:           argv[1:],
		Stdin:          spec.Stdin,
		Timeout:        spec.Timeout,
		MaxOutputBytes: spec.MaxOutputBytes,
		Env:            env,
		ExtraFiles:     extraFiles,
	}
	if runCG != nil {
		wrapped.CgroupFD = runCG.FD()
	} else if connSess != nil {
		wrapped.CgroupFD = connSess.CgroupFD()
	}
	if spec.EgressPolicy != nil {
		idx, _ := strconv.Atoi(strings.TrimPrefix(egressNS, "syn"))
		wrapped.Started = func(startCtx context.Context) error {
			_ = statusWriter.Close()
			pid, statusErr := readBwrapChildPID(statusReader)
			if statusErr != nil {
				return statusErr
			}
			policy := *resolvedEgressPolicy
			policy.PinnedHosts = nil
			ns, setupErr := r.egress.Setup(startCtx, egressNS, idx, pid, spec.EgressExecutionKind, spec.EgressExecutionID, policy)
			if setupErr != nil {
				return fmt.Errorf("egress netns setup: %w", setupErr)
			}
			egressHandle = ns
			allowRules = ns.Rules()
			if _, writeErr := blockWriter.Write([]byte{1}); writeErr != nil {
				return fmt.Errorf("release configured sandbox: %w", writeErr)
			}
			if closeErr := blockWriter.Close(); closeErr != nil {
				return fmt.Errorf("close sandbox block pipe: %w", closeErr)
			}
			return nil
		}
	}
	res, runErr := r.inner.Run(ctx, wrapped)
	if egressHandle != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if cleanupErr := egressHandle.Teardown(cleanupCtx); cleanupErr != nil && runErr == nil {
			runErr = fmt.Errorf("teardown egress namespace: %w", cleanupErr)
		}
		cancel()
	}
	if connSess != nil {
		res.ConnectLog = labelConnEvents(connSess.Close(), allowRules)
	}
	// Belt-and-suspenders: scrub any resolved secret the tool may have
	// echoed (plus URL-embedded creds) from the output BEFORE it reaches the recon log
	// broker or the evidence seal downstream. This is the single chokepoint covering
	// both sinks, since they consume this ToolResult.
	res.Stdout = redact.Bytes(res.Stdout, secrets)
	res.Stderr = redact.Bytes(res.Stderr, secrets)
	return res, runErr
}

// childEnv builds the minimal, controlled environment handed to bwrap (and through it to
// the tool): a clean base (PATH/HOME) plus the spec's Env with any {{secret:NAME}}
// placeholders resolved from the vault. It deliberately does NOT inherit the worker's
// environment, so the master key / DB DSN / signing seed never reach a tool.
func (r *Runner) childEnv(ctx context.Context, spec ports.ToolSpec) (env []string, secrets [][]byte, err error) {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	home := spec.Workdir
	if home == "" {
		home = "/tmp"
	}
	env = []string{"PATH=" + path, "HOME=" + home}
	// The systemd-run --user wrapper needs these to reach the user session bus; they are
	// not secrets. Pass ONLY them through from the worker – everything else (the vault
	// master key, DB DSN, signing seed) is dropped by omission (allowlist).
	if r.systemdRun != "" {
		for _, k := range []string{"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
			if v := os.Getenv(k); v != "" {
				env = append(env, k+"="+v)
			}
		}
	}
	for _, kv := range spec.Env {
		key, val, found := strings.Cut(kv, "=")
		if !found {
			// Reject a malformed entry rather than forwarding it verbatim: a missing '='
			// means any {{secret:}} in it would reach the tool unresolved (and a spec author
			// likely made a mistake). Fail closed.
			return nil, nil, fmt.Errorf("%w: malformed env entry %q (missing '=')", shared.ErrValidation, kv)
		}
		resolved, secs, serr := r.substituteSecrets(ctx, spec.EngagementID, val)
		if serr != nil {
			return nil, nil, serr
		}
		secrets = append(secrets, secs...)
		env = append(env, key+"="+resolved)
	}
	return env, secrets, nil
}

// substituteSecrets replaces every {{secret:NAME}} in val with the vault plaintext for
// (engagementID, NAME), returning the resolved values so the caller can scrub them from
// tool output. With no vault, or an unresolved name, it fails closed.
func (r *Runner) substituteSecrets(ctx context.Context, engagementID shared.ID, val string) (string, [][]byte, error) {
	if !secretRe.MatchString(val) {
		return val, nil, nil
	}
	if r.vault == nil {
		return "", nil, fmt.Errorf("%w: spec references a {{secret:…}} but no credential vault is configured", shared.ErrValidation)
	}
	var (
		resolveErr error
		secrets    [][]byte
	)
	out := secretRe.ReplaceAllStringFunc(val, func(m string) string {
		name := secretRe.FindStringSubmatch(m)[1]
		secret, err := r.vault.Resolve(ctx, engagementID, name)
		if err != nil {
			resolveErr = fmt.Errorf("resolve secret %q: %w", name, err)
			return ""
		}
		secrets = append(secrets, secret)
		return string(secret)
	})
	if resolveErr != nil {
		return "", nil, resolveErr
	}
	return out, secrets, nil
}

// command builds the full argv. Isolated run: `[systemd-run …] bwrap <flags> -- tool`.
// Egress run (egressNS set): `[sudo] ip netns exec <ns> bwrap <flags, shared net> -- tool`
// – entering the prepared netns; systemd-run is skipped there (it conflicts with the
// netns-enter privilege). cgroup memory/pids limits ARE applied on egress runs via the
// per-run cgroup the tool is cloned into (F3, directCgroup), not via systemd-run.
func (r *Runner) command(spec ports.ToolSpec, egressNS, hostsFile string, seccompFD, blockFD, statusFD int, directCgroup bool) []string {
	// Egress runs create their own fresh network namespace and pause on --block-fd
	// until the fixed root broker attaches and configures that exact namespace. Run rejects
	// HostNetwork before command construction, so ordinary execution always unshares net.
	sharedNet := false
	full := append([]string{r.bwrap}, r.bwrapArgs(spec, sharedNet, hostsFile, seccompFD, blockFD, statusFD)...)
	full = append(full, "--", spec.Name)
	full = append(full, spec.Args...)
	// directCgroup (F3): the run is already cloned into a limit cgroup, so skip systemd-run
	// (it would create a second, redundant scope). systemd-run stays the fallback limiter
	// only when no direct cgroup could be created (unprivileged in-process runs).
	if !directCgroup && r.systemdRun != "" {
		return append(r.systemdArgs(spec), full...)
	}
	return full
}

// bwrapArgs builds the bubblewrap confinement flags. Order matters: the read-only root
// is bound first, then read-only extras, then the single read-write workdir overmounts
// its own path.
func (r *Runner) bwrapArgs(spec ports.ToolSpec, sharedNet bool, hostsFile string, seccompFD, blockFD, statusFD int) []string {
	args := []string{
		// F2: a CURATED read-only OS tree – NOT the whole host root. Only the dirs a tool
		// needs to run (binaries, shared libs, CA bundle, nsswitch) are bound. $HOME, /root,
		// /var, /opt, /srv, /mnt, /media, /boot are NOT bound, so ~/.ssh, ~/.aws,
		// ~/.docker and other host secrets are ABSENT (ENOENT), not merely read-only. The
		// tool's source/DB are bound explicitly via Workdir + ReadOnlyPaths.
		"--ro-bind-try", "/usr", "/usr",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/sbin", "/sbin",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--dev", "/dev", // a minimal /dev (null/zero/urandom/…)
		"--proc", "/proc",
		"--tmpfs", "/tmp", // fresh writable scratch
		"--die-with-parent",
		"--new-session",
		"--cap-drop", "ALL",
	}
	// F2 (re-audit fix): bind a CURATED set of /etc files, NOT all of /etc. The tool may run
	// as mapped root on the privileged worker, so binding the whole /etc would expose
	// root-readable secrets (/etc/shadow, /etc/ssl/private/*.key, /etc/krb5.keytab, service
	// creds). Only public OS config a tool needs (CA trust, nsswitch, passwd/group, TLS
	// config, loader cache, timezone) is bound – never the private dirs. Missing paths are
	// skipped (--ro-bind-try), covering both RHEL (/etc/pki) and Debian (/etc/ssl) layouts.
	for _, p := range curatedEtc {
		args = append(args, "--ro-bind-try", p, p)
	}
	// F1: load the default-deny seccomp filter from the inherited fd. bwrap sets
	// no_new_privs alongside, so the filter cannot be escaped by a setuid helper.
	if seccompFD > 0 {
		args = append(args, "--seccomp", strconv.Itoa(seccompFD))
	}
	if blockFD > 0 {
		args = append(args, "--block-fd", strconv.Itoa(blockFD))
	}
	if statusFD > 0 {
		args = append(args, "--json-status-fd", strconv.Itoa(statusFD))
	}
	if sharedNet {
		// Egress mode: the broker configures Bubblewrap's fresh network namespace while
		// the child is paused. Bubblewrap unshares every other namespace here.
		args = append(args, "--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup")
		// Host-net acquisition (hostsFile=="" means no /etc/hosts pin → real DNS): make
		// the resolver config readable. /etc/resolv.conf is often a symlink into /run
		// (systemd-resolved), which the curated /etc bind does not cover.
		if hostsFile == "" {
			if real, err := filepath.EvalSymlinks("/etc/resolv.conf"); err == nil {
				if d := filepath.Dir(real); d != "/etc" {
					args = append(args, "--ro-bind-try", d, d)
				}
			}
		}
	} else {
		// Isolated mode: fresh netns too – default-deny egress by construction (E9 default).
		args = append(args, "--unshare-all")
	}
	// Bind the tool binary ITSELF when it lives outside the curated root. The curated root
	// deliberately omits /opt, /srv and friends so host secrets stay ENOENT, which also made every
	// owned helper installed there (the documented /opt/synapse/bin/synapse-cspm layout) die with
	// "bwrap: execvp ...: No such file or directory". Bind the single resolved FILE read-only, never
	// its directory, so nothing else in that tree becomes visible. Only an absolute path is bound,
	// and resolveToolPath keeps the host PATH from making a bare name absolute unless it is also
	// integrity-verified. When the registry is enabled, spec.Name is also the symlink-resolved path
	// it hashed, so a later symlink retarget cannot change this bind or the exec path.
	if bin := strings.TrimSpace(spec.Name); strings.HasPrefix(bin, "/") && !underCuratedRoot(bin) {
		args = append(args, "--ro-bind-try", bin, bin)
	}
	for _, p := range spec.ReadOnlyPaths {
		if strings.TrimSpace(p) != "" {
			args = append(args, "--ro-bind", p, p)
		}
	}
	if strings.TrimSpace(spec.Workdir) != "" {
		args = append(args, "--bind", spec.Workdir, spec.Workdir, "--chdir", spec.Workdir)
	}
	// overmount /etc/hosts with the pinned in-scope domains → allowed IPs, so the
	// tool resolves in-scope names with no DNS egress at all (no exfil channel).
	if strings.TrimSpace(hostsFile) != "" {
		args = append(args, "--ro-bind", hostsFile, "/etc/hosts")
	}
	// Bubblewrap creates synthetic parent directories for the curated file binds. Remount the
	// completed root read-only after every bind and before exec so /etc and other synthetic
	// parents cannot be modified by the sandboxed tool.
	args = append(args, "--remount-ro", "/")
	// Re-add ONLY the allowlisted capability (CAP_NET_RAW for naabu). Anything else is
	// dropped silently so a future tool can't smuggle CAP_SYS_ADMIN through a spec.
	for _, c := range allowedCaps(spec.CapAdd) {
		args = append(args, "--cap-add", c)
	}
	return args
}

// systemdArgs builds the `systemd-run --user --scope` prefix that applies cgroup v2
// memory/pids limits to the run.
func (r *Runner) systemdArgs(spec ports.ToolSpec) []string {
	mem := spec.MemMaxBytes
	if mem <= 0 {
		mem = r.memMax
	}
	pids := spec.PidsMax
	if pids <= 0 {
		pids = r.pidsMax
	}
	a := []string{r.systemdRun, "--user", "--scope", "--quiet", "--collect"}
	if mem > 0 {
		a = append(a, "-p", fmt.Sprintf("MemoryMax=%d", mem))
	}
	if pids > 0 {
		a = append(a, "-p", fmt.Sprintf("TasksMax=%d", pids))
	}
	return append(a, "--")
}

// labelConnEvents marks each captured connect attempt allowed/denied against the run's
// resolved egress allow-set (the same rules the kernel filters on), so the sealed
// connect-log distinguishes in-scope traffic from attempted out-of-scope connects.
func labelConnEvents(events []ports.ConnEvent, allow []ports.EgressRule) []ports.ConnEvent {
	for i := range events {
		events[i].Allowed = connAllowed(events[i], allow)
	}
	return events
}

func connAllowed(e ports.ConnEvent, allow []ports.EgressRule) bool {
	ip, err := netip.ParseAddr(e.IP)
	if err != nil {
		return false
	}
	for _, r := range allow {
		if !r.Allow || !r.Net.Contains(ip) {
			continue
		}
		if len(r.Ports) == 0 {
			return true
		}
		for _, p := range r.Ports {
			if int(p) == e.Port {
				return true
			}
		}
	}
	return false
}

// allowedCaps filters a CapAdd request to the single permitted capability. Only
// CAP_NET_RAW (naabu's raw sockets) is ever re-added; everything else is refused by
// omission.
//
// RESIDUAL RISK (audit): CAP_NET_RAW also authorizes AF_PACKET (link-layer) sockets, whose
// TX frames do NOT traverse the netns's iptables filter/OUTPUT chain – so a COMPROMISED or
// replaced tool binary holding this cap could craft packets that egress the veth outside
// the scope allowlist (the host's FORWARD -s subnet -j ACCEPT then forwards them). The
// allowlist therefore bounds a well-behaved tool's L3 traffic, not a malicious one's L2
// traffic. Mitigation today: only the pinned naabu adapter requests the cap, and the gate
// + sandbox confine everything else. Hardening follow-ups: pin the tool
// binary by hash before granting the cap, and express the allow/deny set as host-side
// raw/mangle rules keyed to the subnet so injected frames still hit a host filter.
func allowedCaps(reqs []string) []string {
	var out []string
	for _, c := range reqs {
		if strings.EqualFold(strings.TrimSpace(c), "CAP_NET_RAW") {
			out = append(out, "CAP_NET_RAW")
		}
	}
	return out
}

// probeSystemdRun checks that `systemd-run --user --scope` actually works here (it
// needs a user systemd session + DBus). A daemon without one degrades to no cgroup
// limits rather than failing every run.
func probeSystemdRun(sd string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, sd, "--user", "--scope", "--quiet", "--collect", "--", "true").Run() == nil
}
