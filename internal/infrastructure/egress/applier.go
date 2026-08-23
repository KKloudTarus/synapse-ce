// Package egress applies a compiled egress.Policy as a real, kernel-enforced network
// namespace. It is the structural scope-enforcement backstop: the gate refuses to
// LAUNCH an out-of-scope run; this makes the kernel DROP any out-of-scope packet a tool
// emits. Setup builds a per-run netns with a veth to the host, NAT, and a default-DENY
// egress filter that ACCEPTs only the policy's in-scope destinations; Teardown removes it.
//
// It is argv-only: every step is an `ip`/`iptables` argv invocation, no
// shell. The host validated the recipe (allowed dest reachable, denied dropped, coexists
// with Docker's FORWARD DROP). Privileged operations run only in the root-owned broker in
// production; CmdPrefix remains a development/test hook for direct integration tests.
//
// Scope/limits of THIS layer: it enforces IP/CIDR (+ optional ports) allow/deny on
// pre-resolved addresses, never on a hostname string. The unprivileged runner resolves
// exact domains once and binds the same answers into the child through /etc/hosts.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ErrUnavailable means egress enforcement cannot run here (no `ip`/`iptables`, i.e. not
// Linux). Callers fail closed for egress-required runs rather than running unfiltered.
var ErrUnavailable = errors.New("egress enforcement unavailable: ip/iptables not found")

const networkNamespaceDir = "/run/netns"

// Applier creates + tears down egress-filtered network namespaces.
type Applier struct {
	ip          string   // resolved `ip` path
	iptables    string   // resolved `iptables` path
	ip6tables   string   // resolved `ip6tables` path ("" if absent) – IPv6 default-drop fail-closed
	sysctl      string   // resolved `sysctl` path ("" if absent) – IPv6 disable fail-closed
	cmdPrefix   []string // prepended to every privileged command (e.g. {"sudo"}); empty when already privileged
	netnsDir    string   // standard ip-netns directory in production; injectable in tests
	commandHook func(context.Context, []string) error
}

// NewApplier resolves the `ip` + `iptables` binaries (Linux only). cmdPrefix is prepended
// to each command for development/test drivers. Production constructs the applier only in
// the root-owned broker; the worker has no network-administration capabilities.
func NewApplier(cmdPrefix ...string) (*Applier, error) {
	ipBin, err := exec.LookPath("ip")
	if err != nil {
		return nil, fmt.Errorf("%w: `ip` not found (egress enforcement is Linux-only)", ErrUnavailable)
	}
	ipt, err := exec.LookPath("iptables")
	if err != nil {
		return nil, fmt.Errorf("%w: `iptables` not found", ErrUnavailable)
	}
	sysctlBin, _ := exec.LookPath("sysctl") // IPv6 fail-closed (disable_ipv6)
	ip6Bin, _ := exec.LookPath("ip6tables") // IPv6 fail-closed (default-DROP); one of the two must work
	return &Applier{ip: ipBin, iptables: ipt, ip6tables: ip6Bin, sysctl: sysctlBin, cmdPrefix: cmdPrefix, netnsDir: networkNamespaceDir}, nil
}

// Probe verifies egress enforcement actually works here – i.e. the process has enough
// privilege (CAP_NET_ADMIN + CAP_SYS_ADMIN) to build a netns + veth + NAT + iptables – by
// creating and tearing down a throwaway namespace. Returns nil when usable, so the
// composition root can enable egress only when it will succeed (else degrade to isolated).
func (a *Applier) Probe(ctx context.Context) error {
	ns, err := a.Setup(ctx, "synprobe", 63, ports.EgressPolicy{})
	if err != nil {
		return err
	}
	return ns.Teardown(ctx)
}

// RecoverStale removes broker-owned namespace state left behind by a prior broker
// process. It is called before the broker accepts requests, while no live runs can
// be active. Only the broker's tightly bounded syn0..syn63 names are eligible.
func (a *Applier) RecoverStale(ctx context.Context) error {
	dir := a.netnsDir
	if dir == "" {
		dir = networkNamespaceDir
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list stale egress namespaces: %w", err)
	}
	var firstErr error
	for _, entry := range entries {
		name := entry.Name()
		idx, ok := managedNamespaceIndex(name)
		if !ok {
			continue
		}
		hostVeth := "vh-" + name
		_, _, subnet := linkAddrs(idx)
		checksAndDeletes := [][2][]string{
			{{a.iptables, "-C", "FORWARD", "-d", subnet, "-j", "ACCEPT"}, {a.iptables, "-D", "FORWARD", "-d", subnet, "-j", "ACCEPT"}},
			{{a.iptables, "-C", "FORWARD", "-s", subnet, "-j", "ACCEPT"}, {a.iptables, "-D", "FORWARD", "-s", subnet, "-j", "ACCEPT"}},
			{{a.iptables, "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"}, {a.iptables, "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"}},
			{{a.ip, "link", "show", "dev", hostVeth}, {a.ip, "link", "del", hostVeth}},
		}
		for _, pair := range checksAndDeletes {
			if err := a.run(ctx, pair[0]); err != nil {
				continue
			}
			if err := a.run(ctx, pair[1]); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("clean stale egress namespace %q: %w", name, err)
			}
		}
		if err := removePinnedNetworkNamespace(filepath.Join(dir, name)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("remove stale egress namespace %q: %w", name, err)
		}
	}
	return firstErr
}

func managedNamespaceIndex(name string) (int, bool) {
	if name == "synprobe" {
		return 63, true
	}
	if !strings.HasPrefix(name, "syn") {
		return 0, false
	}
	idx, err := strconv.Atoi(strings.TrimPrefix(name, "syn"))
	return idx, err == nil && idx >= 0 && idx < 64
}

// Netns is a live egress-filtered namespace. Run a tool inside it with
// `ip netns exec <Name> …`; always Teardown when done (the steps reverse Setup, even on
// partial failure).
type Netns struct {
	Name string
	// HostsFile is a pinned /etc/hosts (in-scope domain → allowed IP) the caller binds
	// into the sandboxed tool so it resolves in-scope names without any DNS egress.
	// Empty when the policy has no resolvable in-scope domains.
	HostsFile string
	// AllowedRules is the resolved allow-set this netns enforces (scope rules + pinned
	// domain IPs). Exposed so the connect-logger can label each captured attempt
	// allowed/denied against the same set the kernel filters on.
	AllowedRules []ports.EgressRule
	hostVeth     string
	subnet       string // e.g. 10.211.0.0/30
	a            *Applier
	cleanup      [][]string // reverse-order teardown steps (argv, or {rmSentinel, path})
}

func (n *Netns) NamespaceName() string { return n.Name }

func (n *Netns) HostsPath() string { return n.HostsFile }

func (n *Netns) Rules() []ports.EgressRule {
	return append([]ports.EgressRule(nil), n.AllowedRules...)
}

// rmSentinel marks a cleanup entry as "remove this file" rather than an argv command.
const rmSentinel = "__synapse_rm__"

// host/peer addressing for the /30 link. Derived per-netns from a small index so two
// concurrent runs don't collide.
func linkAddrs(idx int) (host, peer, subnet string) {
	// 10.210.<idx*4.. >/30 blocks; idx in [0,63] → 10.210.0.0/30 … 10.210.0.252/30.
	base := (idx % 64) * 4
	host = fmt.Sprintf("10.210.0.%d/30", base+1)
	peer = fmt.Sprintf("10.210.0.%d/30", base+2)
	subnet = fmt.Sprintf("10.210.0.%d/30", base)
	return
}

// Setup builds the filtered netns from p. idx disambiguates concurrent runs' subnets.
func (a *Applier) Setup(ctx context.Context, name string, idx int, p ports.EgressPolicy) (*Netns, error) {
	return a.setup(ctx, name, idx, p, []string{a.ip, "netns", "add", name})
}

// SetupForPID configures the network namespace already created by a paused,
// non-root Bubblewrap child. The broker attaches that namespace under the fixed
// run name, applies the same default-deny recipe, then lets the worker release
// Bubblewrap's block fd. No privileged executable is handed back to the worker.
func (a *Applier) SetupForPID(ctx context.Context, name string, idx int, p ports.EgressPolicy, pid int) (*Netns, error) {
	if pid <= 1 {
		return nil, fmt.Errorf("%w: invalid sandbox pid %d", shared.ErrValidation, pid)
	}
	return a.setup(ctx, name, idx, p, []string{a.ip, "netns", "attach", name, strconv.Itoa(pid)})
}

// SetupForNamespaceFD configures a network namespace pinned by an open descriptor.
// The broker opens this descriptor only after authenticating the paused Bubblewrap
// process, avoiding namespace selection through a reusable numeric PID.
func (a *Applier) SetupForNamespaceFD(ctx context.Context, name string, idx int, p ports.EgressPolicy, namespaceFD int) (ns *Netns, err error) {
	if namespaceFD < 0 {
		return nil, fmt.Errorf("%w: invalid sandbox network namespace descriptor", shared.ErrValidation)
	}
	if len("vh-"+name) > 15 || len("vp-"+name) > 15 {
		return nil, fmt.Errorf("%w: netns name %q too long for a veth name (max ~12)", shared.ErrValidation, name)
	}
	dir := a.netnsDir
	if dir == "" {
		dir = networkNamespaceDir
	}
	pinned, err := pinNetworkNamespaceAt(dir, name, namespaceFD)
	if err != nil {
		return nil, fmt.Errorf("pin network namespace %q: %w", name, err)
	}
	defer func() {
		if err != nil {
			_ = removePinnedNetworkNamespace(pinned)
		}
	}()
	ns, err = a.setup(ctx, name, idx, p, nil)
	if err != nil {
		return nil, err
	}
	return ns, nil
}

func (a *Applier) setup(ctx context.Context, name string, idx int, p ports.EgressPolicy, attach []string) (*Netns, error) {
	// Domain authority must be resolved and pinned before any privileged namespace
	// operation. The applier accepts only canonical IP/CIDR rules; otherwise a
	// compromised caller could turn the root-owned boundary into a DNS authority.
	if len(p.AllowDomains) != 0 || len(p.DenyDomains) != 0 || len(p.AllowDomainRules) != 0 || len(p.DenyDomainRules) != 0 {
		return nil, errors.New("egress setup requires pre-resolved domain rules")
	}

	hostAddr, peerAddr, subnet := linkAddrs(idx)
	hostVeth, peerVeth := "vh-"+name, "vp-"+name
	if len(hostVeth) > 15 || len(peerVeth) > 15 {
		return nil, fmt.Errorf("%w: netns name %q too long for a veth name (max ~12)", shared.ErrValidation, name)
	}
	ns := &Netns{Name: name, hostVeth: hostVeth, subnet: subnet, a: a}

	// Each entry: the command to run, and (optionally) the teardown to register on success.
	steps := []struct {
		args     []string
		teardown []string
	}{}
	if attach != nil {
		steps = append(steps, struct {
			args     []string
			teardown []string
		}{attach, []string{a.ip, "netns", "del", name}})
	} else {
		// SetupForNamespaceFD already pinned the namespace at the standard ip-netns path.
		// Register cleanup before any subsequent operation can fail.
		ns.cleanup = append(ns.cleanup, []string{a.ip, "netns", "del", name})
	}
	steps = append(steps, []struct {
		args     []string
		teardown []string
	}{
		{[]string{a.ip, "link", "add", hostVeth, "type", "veth", "peer", "name", peerVeth}, []string{a.ip, "link", "del", hostVeth}},
		{[]string{a.ip, "link", "set", peerVeth, "netns", name}, nil},
		{[]string{a.ip, "addr", "add", hostAddr, "dev", hostVeth}, nil},
		{[]string{a.ip, "link", "set", hostVeth, "up"}, nil},
		{[]string{a.ip, "netns", "exec", name, a.ip, "addr", "add", peerAddr, "dev", peerVeth}, nil},
		{[]string{a.ip, "netns", "exec", name, a.ip, "link", "set", peerVeth, "up"}, nil},
		{[]string{a.ip, "netns", "exec", name, a.ip, "link", "set", "lo", "up"}, nil},
		{[]string{a.ip, "netns", "exec", name, a.ip, "route", "add", "default", "via", trimPrefix(hostAddr)}, nil},
		// NAT for the netns subnet + FORWARD allow (coexists with Docker's FORWARD DROP).
		{[]string{a.iptables, "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"}, []string{a.iptables, "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"}},
		{[]string{a.iptables, "-I", "FORWARD", "-s", subnet, "-j", "ACCEPT"}, []string{a.iptables, "-D", "FORWARD", "-s", subnet, "-j", "ACCEPT"}},
		{[]string{a.iptables, "-I", "FORWARD", "-d", subnet, "-j", "ACCEPT"}, []string{a.iptables, "-D", "FORWARD", "-d", subnet, "-j", "ACCEPT"}},
		// Always allow loopback egress inside the netns.
		{[]string{a.ip, "netns", "exec", name, a.iptables, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"}, nil},
	}...)
	for _, s := range steps {
		if err := a.run(ctx, s.args); err != nil {
			_ = ns.Teardown(context.Background()) // best-effort unwind
			return nil, fmt.Errorf("egress setup %q: %w", strings.Join(s.args[len(a.cmdPrefix):], " "), err)
		}
		if s.teardown != nil {
			ns.cleanup = append(ns.cleanup, s.teardown)
		}
	}

	// IPv6 fail-closed, UNCONDITIONAL (re-audit fix): the v4 rules above don't touch v6, and
	// a fresh netns autoconfigures an IPv6 link-local. We do not yet compile v6 allow rules,
	// so v6 must be locked down. Apply BOTH available mechanisms and require at least one to
	// succeed – never silently leave v6 open: (1) sysctl disable_ipv6 (flushes addresses),
	// (2) ip6tables default-DROP on OUTPUT+FORWARD. If neither tool exists, FAIL the setup.
	v6Locked := false
	if a.sysctl != "" {
		if err := a.run(ctx, []string{a.ip, "netns", "exec", name, a.sysctl, "-w",
			"net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1", "net.ipv6.conf.lo.disable_ipv6=1"}); err == nil {
			v6Locked = true
		}
	}
	if a.ip6tables != "" {
		okOut := a.run(ctx, []string{a.ip, "netns", "exec", name, a.ip6tables, "-P", "OUTPUT", "DROP"}) == nil
		okFwd := a.run(ctx, []string{a.ip, "netns", "exec", name, a.ip6tables, "-P", "FORWARD", "DROP"}) == nil
		if okOut && okFwd {
			v6Locked = true
		}
	}
	if !v6Locked {
		_ = ns.Teardown(context.Background())
		return nil, fmt.Errorf("egress: cannot lock down IPv6 in the netns (need sysctl or ip6tables) – refusing to run with unfiltered v6")
	}

	denyRules := filterRules(p.Rules, false)
	allowRules := filterRules(p.Rules, true)
	hosts := pinnedHosts(p.PinnedHosts)
	ns.AllowedRules = allowRules // expose the resolved allow-set for the connection-observer verdict

	// Deny first (out-of-scope wins), then allow, then default DROP.
	for _, r := range denyRules {
		if err := a.outputRule(ctx, name, "DROP", r); err != nil {
			_ = ns.Teardown(context.Background())
			return nil, err
		}
	}
	for _, r := range allowRules {
		if err := a.outputRule(ctx, name, "ACCEPT", r); err != nil {
			_ = ns.Teardown(context.Background())
			return nil, err
		}
	}
	if err := a.run(ctx, []string{a.ip, "netns", "exec", name, a.iptables, "-P", "OUTPUT", "DROP"}); err != nil {
		_ = ns.Teardown(context.Background())
		return nil, err
	}

	// Write the pinned /etc/hosts (the SandboxRunner binds it into the tool). The netns
	// has no DNS egress, so this is the ONLY way the tool resolves an in-scope name.
	if hosts != "" {
		hf, herr := writeHostsFile(hosts)
		if herr != nil {
			_ = ns.Teardown(context.Background())
			return nil, fmt.Errorf("egress pinned hosts: %w", herr)
		}
		ns.HostsFile = hf
		ns.cleanup = append(ns.cleanup, []string{rmSentinel, hf}) // Teardown removes the file
	}
	return ns, nil
}

// domainRules combines backwards-compatible hostname-wide rules with structured
// hostname-and-port rules. The structured form keeps URL authorization's effective
// port through host-side resolution and into the kernel rule set.
// resolvePins resolves each non-wildcard domain on the host and returns pinned
// /etc/hosts lines + the matching allow-by-IP rules. A domain that fails to resolve is
// skipped (fail-closed: it simply stays unreachable). Wildcards can't be pre-resolved.
// writeHostsFile writes a pinned hosts file (with the usual localhost entries) to a temp
// path, world-readable so the sandboxed tool (any uid) can read it.
func writeHostsFile(pinned string) (string, error) {
	f, err := os.CreateTemp("", "synapse-hosts-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("127.0.0.1 localhost\n::1 localhost\n" + pinned); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Chmod(0o644); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// filterRules returns the rules with the given Allow value, preserving order.
func pinnedHosts(pins map[string][]netip.Addr) string {
	if len(pins) == 0 {
		return ""
	}
	hosts := make([]string, 0, len(pins))
	for host := range pins {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	var b strings.Builder
	for _, host := range hosts {
		addrs := append([]netip.Addr(nil), pins[host]...)
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
		for _, addr := range addrs {
			if addr.IsValid() {
				fmt.Fprintf(&b, "%s %s\n", addr.Unmap(), host)
			}
		}
	}
	return b.String()
}

func filterRules(rules []ports.EgressRule, allow bool) []ports.EgressRule {
	var out []ports.EgressRule
	for _, r := range rules {
		if r.Allow == allow {
			out = append(out, r)
		}
	}
	return out
}

// outputRule appends an OUTPUT rule for one policy rule (per-port when set, else all
// protocols to the destination). IPv6 rules are skipped here (iptables is v4; ip6tables
// is the v6 sibling – a follow-up).
func (a *Applier) outputRule(ctx context.Context, ns, verdict string, r ports.EgressRule) error {
	if !r.Net.Addr().Is4() {
		return nil // v4 enforcement only in this layer
	}
	dst := r.Net.String()
	if len(r.Ports) == 0 {
		return a.run(ctx, []string{a.ip, "netns", "exec", ns, a.iptables, "-A", "OUTPUT", "-d", dst, "-j", verdict})
	}
	for _, port := range r.Ports {
		for _, proto := range []string{"tcp", "udp"} {
			if err := a.run(ctx, []string{a.ip, "netns", "exec", ns, a.iptables, "-A", "OUTPUT", "-d", dst, "-p", proto, "--dport", strconv.Itoa(int(port)), "-j", verdict}); err != nil {
				return err
			}
		}
	}
	return nil
}

// Teardown reverses Setup (registered steps, in reverse order). Best-effort: it attempts
// every step even if some fail, so a partial setup is fully cleaned.
func (n *Netns) Teardown(ctx context.Context) error {
	var firstErr error
	for i := len(n.cleanup) - 1; i >= 0; i-- {
		step := n.cleanup[i]
		if len(step) == 2 && step[0] == rmSentinel {
			if err := os.Remove(step[1]); err != nil && !os.IsNotExist(err) && firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := n.a.run(ctx, step); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	n.cleanup = nil
	return firstErr
}

func (a *Applier) run(ctx context.Context, args []string) error {
	if a.commandHook != nil {
		return a.commandHook(ctx, append([]string(nil), args...))
	}
	full := append(append([]string{}, a.cmdPrefix...), args...)
	cmd := exec.CommandContext(ctx, full[0], full[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args[:min(3, len(args))], " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func trimPrefix(addr string) string {
	if pfx, err := netip.ParsePrefix(addr); err == nil {
		return pfx.Addr().String()
	}
	return addr
}
