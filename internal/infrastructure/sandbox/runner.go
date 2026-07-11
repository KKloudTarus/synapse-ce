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
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// ErrUnavailable means the sandbox cannot run on this host (no bubblewrap). The caller
// must fail closed for sandbox-required runs, never silently run unsandboxed.
var ErrUnavailable = errors.New("sandbox unavailable: bubblewrap (bwrap) not found")

// secretRe matches a {{secret:NAME}} placeholder in a ToolSpec env value.
var secretRe = regexp.MustCompile(`\{\{secret:([A-Za-z0-9_.-]+)\}\}`)

// Runner confines tool execution with bubblewrap, delegating exec to an ExecRunner.
type Runner struct {
	inner      *toolrunner.ExecRunner
	bwrap      string                // resolved bwrap path
	systemdRun string                // resolved systemd-run path, or "" when cgroup limits aren't available
	memMax     int64                 // default cgroup memory.max
	pidsMax    int                   // default cgroup pids.max
	vault      ports.CredentialVault // optional; resolves {{secret:NAME}} env placeholders
	egress     *egress.Applier       // optional; enforces a per-run scope egress netns
	connMon    *ebpf.Monitor         // optional; eBPF connect-logger for egress runs
	binreg     *binregistry.Registry // optional; verifies tool-binary integrity before exec (F5)
	netnsSlots chan int              // free-list of netns/subnet slots [0,63] (ops: no wrap-collision)
	runSeq     atomic.Int64          // disambiguates per-run cgroups (F3)
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
func (r *Runner) SetEgress(a *egress.Applier) { r.egress = a }

// SetConnMonitor enables the eBPF connect-logger: each egress run is placed in a
// cgroup whose connect4/connect6 hooks capture every outbound connect() attempt (incl.
// ones the egress filter drops) into the run's ToolResult.ConnectLog. Optional + best-
// effort – a missing/unprivileged logger never fails the run (it is observability).
func (r *Runner) SetConnMonitor(m *ebpf.Monitor) { r.connMon = m }

var _ ports.ToolRunner = (*Runner)(nil)

// NewRunner resolves bubblewrap (required) and systemd-run (optional, for cgroup
// limits, probed for actual usability). Returns ErrUnavailable when bwrap is absent.
func NewRunner(timeout time.Duration, maxOut int, memMax int64, pidsMax int) (*Runner, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, ErrUnavailable
	}
	// F1 fail-closed: a sandbox without a syscall filter is NOT a sandbox. If seccomp
	// cannot be built on this platform, refuse to construct the runner – the caller then
	// degrades rather than silently running tools with the full syscall table.
	if !seccompSupported {
		return nil, fmt.Errorf("%w: seccomp filtering is required but unsupported on this platform", ErrUnavailable)
	}
	if f, serr := seccompFile(); serr != nil {
		return nil, fmt.Errorf("%w: seccomp self-check failed: %v", ErrUnavailable, serr)
	} else {
		_ = f.Close()
	}
	slots := make(chan int, netnsSlotCount)
	for i := 0; i < netnsSlotCount; i++ {
		slots <- i
	}
	r := &Runner{
		inner:      toolrunner.NewExecRunner(timeout, maxOut),
		bwrap:      bwrap,
		memMax:     memMax,
		pidsMax:    pidsMax,
		netnsSlots: slots,
	}
	if sd, err := exec.LookPath("systemd-run"); err == nil && probeSystemdRun(sd) {
		r.systemdRun = sd
	}
	return r, nil
}

// CgroupLimitsEnforced reports whether cgroup resource limits are actually applied
// (systemd-run usable). When false, only the timeout/process-group kill bounds a run.
func (r *Runner) CgroupLimitsEnforced() bool { return r.systemdRun != "" }

// Run confines spec in bubblewrap and executes it via the inner ExecRunner.
func (r *Runner) Run(ctx context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	if spec.Name == "" {
		return ports.ToolResult{}, fmt.Errorf("%w: sandbox empty command name", shared.ErrValidation)
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
	// fd's child number, since it is the sole ExtraFile). Fail closed – never run a tool
	// without the syscall filter the sandbox promises.
	seccompF, serr := seccompFile()
	if serr != nil {
		return ports.ToolResult{}, fmt.Errorf("%w: build seccomp filter: %v", shared.ErrValidation, serr)
	}
	defer func() { _ = seccompF.Close() }()
	// F5: verify the tool binary's integrity before it runs. The resolved on-disk binary
	// must match its pin (operator hash and/or trust-on-first-use); a replaced binary is
	// refused. Defends the "compromised tool binary" threat the audit named.
	if r.binreg != nil {
		binPath, lerr := exec.LookPath(spec.Name)
		if lerr != nil {
			binPath = spec.Name // not on PATH; let bwrap surface the not-found, but still try to verify
		}
		if verr := r.binreg.Verify(binPath); verr != nil {
			return ports.ToolResult{}, fmt.Errorf("%w: %v", shared.ErrValidation, verr)
		}
		// Exec the EXACT path we verified (absolute) – so bwrap does not re-resolve spec.Name
		// via PATH to a possibly-different binary (closes the verify-path != exec-path gap).
		spec.Name = binPath
	}
	// F3: a per-run cgroup v2 with hard memory.max + pids.max so a memory/fork bomb is
	// contained on EVERY path (egress and isolated), independent of systemd-run. The tool
	// is cloned into it (CgroupFD). Best-effort: creation needs cgroup write access, which
	// the privileged egress/worker path always has; an unprivileged in-process run falls
	// back to the systemd-run limiter (command()).
	mem, pids := spec.MemMaxBytes, spec.PidsMax
	if mem <= 0 {
		mem = r.memMax
	}
	if pids <= 0 {
		pids = r.pidsMax
	}
	var runCG *runCgroup
	if cg, cgErr := newRunCgroup(r.runSeq.Add(1), mem, pids); cgErr == nil {
		runCG = cg
		defer runCG.Close()
	}
	// Egress mode: an EgressPolicy means the tool runs inside a netns whose kernel
	// filter allows only in-scope destinations. Fail closed if a policy is set but no
	// applier is configured (never silently run with unrestricted egress).
	egressNS, hostsFile := "", ""
	var connSess *ebpf.Session
	var allowRules []ports.EgressRule
	if spec.EgressPolicy != nil {
		if r.egress == nil {
			return ports.ToolResult{}, fmt.Errorf("%w: spec carries an egress policy but egress enforcement is not configured", shared.ErrValidation)
		}
		// Ops fix: allocate a netns/subnet slot from a FREE-LIST (not seq%64). A free slot
		// is held only while its netns is live, so two concurrent runs can never collide on
		// a netns name/subnet (the old modulo wrapped at 64 and could tear down a live run's
		// namespace). Exhaustion fails the run cleanly instead of corrupting another's.
		var idx int
		select {
		case idx = <-r.netnsSlots:
		default:
			return ports.ToolResult{}, fmt.Errorf("%w: too many concurrent egress runs (netns slots exhausted)", shared.ErrValidation)
		}
		defer func() { r.netnsSlots <- idx }() // return the slot AFTER teardown (LIFO defer order)
		egressNS = fmt.Sprintf("syn%d", idx)
		ns, serr := r.egress.Setup(ctx, egressNS, idx, *spec.EgressPolicy)
		if serr != nil {
			return ports.ToolResult{}, fmt.Errorf("egress netns setup: %w", serr)
		}
		defer func() { _ = ns.Teardown(context.Background()) }()
		hostsFile = ns.HostsFile // pinned in-scope domains → allowed IPs
		allowRules = ns.AllowedRules
		// capture every connect() the tool attempts (incl. dropped out-of-scope
		// ones). Attach to the SAME per-run cgroup the limits are on (so one clone-into-
		// cgroup both limits and logs); fall back to a logger-owned cgroup if F3's cgroup
		// could not be created. Best-effort – observability never fails the run.
		if r.connMon != nil {
			if runCG != nil {
				if s, merr := r.connMon.Attach(runCG.Path()); merr == nil {
					connSess = s
				}
			} else if s, merr := r.connMon.Start(egressNS); merr == nil {
				connSess = s
			}
		}
	}
	const seccompChildFD = 3 // ExtraFiles[0] → child fd 3 (CgroupFD is a SysProcAttr fd, not counted)
	argv := r.command(spec, egressNS, hostsFile, seccompChildFD, runCG != nil)
	wrapped := ports.ToolSpec{
		Name:           argv[0],
		Args:           argv[1:],
		Stdin:          spec.Stdin,
		Timeout:        spec.Timeout,
		MaxOutputBytes: spec.MaxOutputBytes,
		Env:            env,
		ExtraFiles:     []*os.File{seccompF},
	}
	// Clone the tool into the limit cgroup (preferred) or, failing that, the logger's own.
	if runCG != nil {
		wrapped.CgroupFD = runCG.FD()
	} else if connSess != nil {
		wrapped.CgroupFD = connSess.CgroupFD()
	}
	res, runErr := r.inner.Run(ctx, wrapped)
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
func (r *Runner) command(spec ports.ToolSpec, egressNS, hostsFile string, seccompFD int, directCgroup bool) []string {
	// Share the net namespace when entering an egress netns OR when HostNetwork is requested
	// (host-net acquisition without egress scoping); otherwise unshare net (the isolated default).
	sharedNet := egressNS != "" || spec.HostNetwork
	full := append([]string{r.bwrap}, r.bwrapArgs(spec, sharedNet, hostsFile, seccompFD)...)
	full = append(full, "--", spec.Name)
	full = append(full, spec.Args...)
	if egressNS != "" {
		return append(r.egress.ExecPrefix(egressNS), full...)
	}
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
func (r *Runner) bwrapArgs(spec ports.ToolSpec, sharedNet bool, hostsFile string, seccompFD int) []string {
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
	if sharedNet {
		// Egress mode: KEEP the inherited (egress-filtered) netns from `ip netns exec`, so
		// unshare every namespace EXCEPT net. The kernel egress filter is the boundary.
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
