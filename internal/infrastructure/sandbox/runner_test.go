package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeRunner builds a Runner without LookPath so the argv-construction logic (the
// security-critical part) is unit-testable on any platform.
func fakeRunner(systemdRun string) *Runner {
	return &Runner{bwrap: "/usr/bin/bwrap", systemdRun: systemdRun, memMax: 256 << 20, pidsMax: 128, lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil }}
}

// invalidCgroupRoot returns a missing parent, which cannot be made into a per-run
// cgroup by any platform-specific implementation.
func invalidCgroupRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "missing-cgroup-parent")
}

func TestErrUnavailableDoesNotMisidentifyTheMissingControl(t *testing.T) {
	if got := ErrUnavailable.Error(); got != "sandbox unavailable" {
		t.Fatalf("ErrUnavailable = %q, want generic sentinel", got)
	}
	err := fmt.Errorf("%w: cgroup limits are required", ErrUnavailable)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "cgroup limits are required") {
		t.Fatalf("wrapped error must retain sentinel and control detail: %v", err)
	}
}

func TestSandboxRejectsUntrustedNetworkPosturesBeforeExecution(t *testing.T) {
	policy := &ports.EgressPolicy{}
	tests := []struct {
		name string
		spec ports.ToolSpec
		want string
	}{
		{
			name: "host network",
			spec: ports.ToolSpec{Name: "tool", HostNetwork: true},
			want: "host-network sandbox execution is not supported",
		},
		{
			name: "missing execution kind",
			spec: ports.ToolSpec{Name: "tool", EgressPolicy: policy, EgressExecutionID: "execution-1"},
			want: "egress policy requires authoritative execution kind and id",
		},
		{
			name: "missing execution id",
			spec: ports.ToolSpec{Name: "tool", EgressPolicy: policy, EgressExecutionKind: "recon"},
			want: "egress policy requires authoritative execution kind and id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := fakeRunner("")
			// inner remains nil: reaching the execution adapter would panic rather than
			// returning the required validation error.
			_, err := r.Run(context.Background(), tt.spec)
			if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Run() error = %v, want validation containing %q", err, tt.want)
			}
		})
	}
}

func TestProbeBubblewrapRejectsMissingExecutable(t *testing.T) {
	if !seccompSupported {
		t.Skip("seccomp probe is Linux-only")
	}
	filter, err := seccompFile()
	if err != nil {
		t.Fatalf("build seccomp filter: %v", err)
	}
	defer func() { _ = filter.Close() }()
	if err := probeBubblewrap(filepath.Join(t.TempDir(), "missing-bwrap"), filter); err == nil {
		t.Fatal("probeBubblewrap must reject an unusable executable")
	}
}

func TestSandboxArgvConfinesTheRun(t *testing.T) {
	r := fakeRunner("")
	argv := r.command(ports.ToolSpec{Name: "subfinder", Args: []string{"-d", "example.com"}, Workdir: "/run/work"}, "", "", 3, 0, 0, false)
	joined := strings.Join(argv, " ")

	// bwrap is arg 0, the tool is after the `--` separator, args preserved.
	if argv[0] != "/usr/bin/bwrap" {
		t.Fatalf("argv[0] = %q, want bwrap", argv[0])
	}
	sep := slices.Index(argv, "--")
	if sep < 0 || argv[sep+1] != "subfinder" || argv[sep+2] != "-d" || argv[sep+3] != "example.com" {
		t.Fatalf("tool not placed after `--`: %v", argv)
	}
	// The confinement flags must all be present.
	for _, want := range []string{
		"--ro-bind-try /usr /usr", "--ro-bind-try /etc/ssl/certs /etc/ssl/certs", // F2: curated OS tree + TLS trust
		"--ro-bind-try /etc/nsswitch.conf /etc/nsswitch.conf", "--remount-ro /",
		"--unshare-all", "--die-with-parent", "--cap-drop ALL",
		"--tmpfs /tmp", "--bind /run/work /run/work", "--chdir /run/work",
		"--seccomp 3", // F1: the default-deny syscall filter fd is always passed
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing confinement flag %q in: %s", want, joined)
		}
	}
	// F2: neither the whole host root NOR the whole /etc may be bound (no ~/.ssh exposure,
	// no /etc/shadow or /etc/ssl/private exposure).
	if strings.Contains(joined, "--ro-bind / /") || strings.Contains(joined, "--ro-bind-try /etc /etc") {
		t.Errorf("the whole host root / whole /etc must NOT be bound: %s", joined)
	}
}

func TestSandboxOnlyAllowsCapNetRaw(t *testing.T) {
	r := fakeRunner("")
	// naabu asks for CAP_NET_RAW (allowed) + a smuggled CAP_SYS_ADMIN (must be dropped).
	argv := r.command(ports.ToolSpec{Name: "naabu", CapAdd: []string{"CAP_NET_RAW", "CAP_SYS_ADMIN"}}, "", "", 3, 0, 0, false)
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--cap-add CAP_NET_RAW") {
		t.Error("CAP_NET_RAW should be re-added for naabu")
	}
	if strings.Contains(joined, "CAP_SYS_ADMIN") {
		t.Error("a smuggled CAP_SYS_ADMIN must NOT be added")
	}
}

func TestSandboxNoCapAddByDefault(t *testing.T) {
	r := fakeRunner("")
	argv := r.command(ports.ToolSpec{Name: "httpx"}, "", "", 3, 0, 0, false)
	if strings.Contains(strings.Join(argv, " "), "--cap-add") {
		t.Error("a non-capability-sensitive tool must run with no added caps")
	}
}

func TestSandboxWrapsInSystemdRunForLimits(t *testing.T) {
	r := fakeRunner("/usr/bin/systemd-run")
	argv := r.command(ports.ToolSpec{Name: "syft", MemMaxBytes: 512 << 20, PidsMax: 64}, "", "", 3, 0, 0, true)
	if argv[0] != "/usr/bin/systemd-run" {
		t.Fatalf("argv[0] = %q, want systemd-run prefix", argv[0])
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--user --scope") || !strings.Contains(joined, "MemoryMax=536870912") || !strings.Contains(joined, "TasksMax=64") {
		t.Errorf("systemd-run cgroup limits missing: %s", joined)
	}
	// bwrap still wraps the tool inside the scope (appears after systemd-run, before the tool).
	if bw, tool := slices.Index(argv, "/usr/bin/bwrap"), slices.Index(argv, "syft"); !(bw > 0 && tool > bw) {
		t.Errorf("bwrap must wrap the tool inside the systemd scope: %v", argv)
	}
}

func TestSandboxDirectCgroupSkipsSystemdRun(t *testing.T) {
	r := fakeRunner("/usr/bin/systemd-run")
	// useSystemd=false means the direct cgroup already limits this run, so a redundant
	// systemd scope must not be added.
	argv := r.command(ports.ToolSpec{Name: "syft"}, "", "", 3, 0, 0, false)
	if argv[0] == "/usr/bin/systemd-run" {
		t.Errorf("direct cgroup run must NOT also wrap in systemd-run: %v", argv)
	}
	if argv[0] != "/usr/bin/bwrap" {
		t.Errorf("argv[0] should be bwrap directly: %v", argv)
	}
}

func TestNewRunnerReadyAcceptsFallbackOnlyCgroupLimiter(t *testing.T) {
	fallback := &Runner{systemdRun: "/usr/bin/systemd-run"}
	attempts := 0

	runner, err := newRunnerReady(context.Background(), time.Second, 0, 0, 0, time.Nanosecond, false, func(time.Duration, int, int64, int) (*Runner, error) {
		attempts++
		return fallback, nil
	})
	if err != nil {
		t.Fatalf("newRunnerReady() error = %v", err)
	}
	if runner != fallback {
		t.Fatalf("newRunnerReady() = %#v, want fallback runner", runner)
	}
	if runner.directCgroupRequired || runner.ControlSetIdentity() != "" {
		t.Fatalf("ordinary ready runner must not require or attest a direct cgroup: %#v", runner)
	}
	if attempts != 1 {
		t.Fatalf("constructor calls = %d, want 1", attempts)
	}
}

func TestNewDirectCgroupRunnerReadyWaitsForDirectDelegatedCgroup(t *testing.T) {
	fallback := &Runner{systemdRun: "/usr/bin/systemd-run"}
	direct := &Runner{directCgroupRoot: "/sys/fs/cgroup/synapse"}
	attempts := 0

	runner, err := newDirectCgroupRunnerReady(context.Background(), time.Second, 0, 0, 0, time.Nanosecond, func(time.Duration, int, int64, int) (*Runner, error) {
		attempts++
		switch attempts {
		case 1:
			return fallback, nil
		case 2:
			return direct, nil
		default:
			t.Fatalf("constructor called %d times", attempts)
			return nil, nil
		}
	})
	if err != nil {
		t.Fatalf("newDirectCgroupRunnerReady() error = %v", err)
	}
	if runner != direct || !runner.directCgroupRequired {
		t.Fatalf("newDirectCgroupRunnerReady() = %#v, want direct-only runner", runner)
	}
	if got := runner.ControlSetIdentity(); got != ControlSetIdentityBubblewrapSeccompCgroupV2 {
		t.Fatalf("ControlSetIdentity() = %q, want %q", got, ControlSetIdentityBubblewrapSeccompCgroupV2)
	}
	if attempts != 2 {
		t.Fatalf("constructor calls = %d, want 2", attempts)
	}
}

func TestNewDirectCgroupRunnerReadyRetriesNilAndErrorConstructionResults(t *testing.T) {
	direct := &Runner{directCgroupRoot: "/sys/fs/cgroup/synapse"}
	attempts := 0

	runner, err := newDirectCgroupRunnerReady(context.Background(), time.Second, 0, 0, 0, time.Nanosecond, func(time.Duration, int, int64, int) (*Runner, error) {
		attempts++
		switch attempts {
		case 1:
			return nil, nil
		case 2:
			return nil, errors.New("constructor unavailable")
		case 3:
			return direct, nil
		default:
			t.Fatalf("constructor called %d times", attempts)
			return nil, nil
		}
	})
	if err != nil {
		t.Fatalf("newDirectCgroupRunnerReady() error = %v", err)
	}
	if runner != direct || !runner.directCgroupRequired {
		t.Fatalf("newDirectCgroupRunnerReady() = %#v, want direct-only runner", runner)
	}
	if attempts != 3 {
		t.Fatalf("constructor calls = %d, want 3", attempts)
	}
}

func TestNewDirectCgroupRunnerReadyCancellationWithoutDirectDelegatedCgroupReturnsUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0

	runner, err := newDirectCgroupRunnerReady(ctx, time.Second, 0, 0, 0, time.Hour, func(time.Duration, int, int64, int) (*Runner, error) {
		attempts++
		cancel()
		return &Runner{systemdRun: "/usr/bin/systemd-run"}, nil
	})
	if runner != nil {
		t.Fatalf("newDirectCgroupRunnerReady() runner = %#v, want nil", runner)
	}
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "direct delegated cgroup") {
		t.Fatalf("newDirectCgroupRunnerReady() error = %v, want unavailable direct delegated cgroup", err)
	}
	if attempts != 1 {
		t.Fatalf("constructor calls = %d, want 1 after cancellation", attempts)
	}
}

func TestControlSetIdentityAttestsOnlyDirectCgroupRunners(t *testing.T) {
	tests := []struct {
		name string
		r    *Runner
		want string
	}{
		{name: "nil"},
		{name: "fallback only", r: &Runner{systemdRun: "/usr/bin/systemd-run"}},
		{name: "ordinary direct plus fallback", r: &Runner{directCgroupRoot: "/sys/fs/cgroup/synapse", systemdRun: "/usr/bin/systemd-run"}},
		{name: "direct only", r: &Runner{directCgroupRoot: "/sys/fs/cgroup/synapse", directCgroupRequired: true}, want: ControlSetIdentityBubblewrapSeccompCgroupV2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.ControlSetIdentity(); got != tt.want {
				t.Fatalf("ControlSetIdentity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCgroupExecutionDirectRunnerFailureDoesNotSelectSystemdFallback(t *testing.T) {
	tests := []struct {
		name             string
		directCgroupRoot string
	}{
		{name: "missing direct root"},
		{name: "missing cgroup parent", directCgroupRoot: invalidCgroupRoot(t)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Runner{
				directCgroupRoot:     tt.directCgroupRoot,
				systemdRun:           "/usr/bin/systemd-run",
				directCgroupRequired: true,
			}

			direct, useSystemd, err := r.cgroupExecution(256<<20, 128)
			if direct != nil || useSystemd {
				t.Fatalf("cgroupExecution() = (%v, fallback=%t), want no cgroup and no fallback", direct, useSystemd)
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("cgroupExecution() error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestCgroupExecutionOrdinaryDirectFailureRetainsSystemdFallback(t *testing.T) {
	r := &Runner{
		directCgroupRoot: invalidCgroupRoot(t),
		systemdRun:       "/usr/bin/systemd-run",
	}

	direct, useSystemd, err := r.cgroupExecution(256<<20, 128)
	if err != nil {
		t.Fatalf("cgroupExecution() error = %v", err)
	}
	if direct != nil || !useSystemd {
		t.Fatalf("cgroupExecution() = (%v, fallback=%t), want systemd fallback", direct, useSystemd)
	}
	argv := r.command(ports.ToolSpec{Name: "syft"}, "", "", 3, 0, 0, useSystemd)
	if argv[0] != "/usr/bin/systemd-run" {
		t.Fatalf("command() argv[0] = %q, want systemd-run fallback", argv[0])
	}
}

func TestDirectCgroupRunnerPolicySupportsConcurrentIdentityReads(t *testing.T) {
	r := &Runner{
		directCgroupRoot:     "/sys/fs/cgroup/synapse",
		directCgroupRequired: true,
	}
	const workers = 32
	const readsPerWorker = 1_000
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < readsPerWorker; j++ {
				if got := r.ControlSetIdentity(); got != ControlSetIdentityBubblewrapSeccompCgroupV2 {
					errs <- fmt.Errorf("ControlSetIdentity() = %q", got)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSandboxReadOnlyExtraBinds(t *testing.T) {
	r := fakeRunner("")
	argv := r.command(ports.ToolSpec{Name: "grype", ReadOnlyPaths: []string{"/var/grypedb", "/src"}}, "", "", 3, 0, 0, false)
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--ro-bind /var/grypedb /var/grypedb") || !strings.Contains(joined, "--ro-bind /src /src") {
		t.Errorf("read-only extra binds missing: %s", joined)
	}
}

// TestSandboxBindsToolBinaryOutsideCuratedRoot pins the bind for owned helpers installed outside
// the curated read-only root. The root deliberately omits /opt so host secrets stay ENOENT, which
// also made the DOCUMENTED /opt/synapse/bin/synapse-cspm layout unrunnable: every CSPM run died
// with "bwrap: execvp /opt/synapse/synapse-cspm: No such file or directory", retried three times
// and dead-lettered. Only the verified FILE is bound - never its directory.
func TestSandboxBindsToolBinaryOutsideCuratedRoot(t *testing.T) {
	r := fakeRunner("")
	argv := r.command(ports.ToolSpec{Name: "/opt/synapse/bin/synapse-cspm"}, "", "", 3, 0, 0, false)
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--ro-bind-try /opt/synapse/bin/synapse-cspm /opt/synapse/bin/synapse-cspm") {
		t.Errorf("helper binary was not bound into the sandbox: %s", joined)
	}
	if strings.Contains(joined, "--ro-bind-try /opt/synapse/bin /opt/synapse/bin") || strings.Contains(joined, "--ro-bind-try /opt /opt") {
		t.Errorf("bound the helper's DIRECTORY, widening the curated root: %s", joined)
	}
}

// TestSandboxDoesNotRebindCuratedRootTools keeps the bind narrow: tools already inside the curated
// root need no extra bind, and a lookalike path must not be treated as being inside it.
func TestSandboxDoesNotRebindCuratedRootTools(t *testing.T) {
	r := fakeRunner("")
	joined := strings.Join(r.command(ports.ToolSpec{Name: "/usr/bin/syft"}, "", "", 3, 0, 0, false), " ")
	if strings.Contains(joined, "--ro-bind-try /usr/bin/syft /usr/bin/syft") {
		t.Errorf("re-bound a tool already inside the curated root: %s", joined)
	}
	for _, name := range []string{"/libexec/synapse/helper", "/lib-evil/helper"} {
		joined = strings.Join(r.command(ports.ToolSpec{Name: name}, "", "", 3, 0, 0, false), " ")
		if !strings.Contains(joined, "--ro-bind-try "+name+" "+name) {
			t.Errorf("%s was treated as inside the curated root: %s", name, joined)
		}
	}
	// A relative name still resolves through PATH inside the sandbox; binding it would be wrong.
	joined = strings.Join(r.command(ports.ToolSpec{Name: "grype"}, "", "", 3, 0, 0, false), " ")
	if strings.Contains(joined, "--ro-bind-try grype") {
		t.Errorf("bound a relative tool name: %s", joined)
	}
}

// ---- secret substitution + worker-env exclusion (argv-construction level) ----

func TestChildEnvResolvesSecretsCleanly(t *testing.T) {
	c, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	mv := vault.NewMemoryVault(c, nil)
	if err := mv.Put(context.Background(), "eng1", "API_KEY", []byte("s3cr3t")); err != nil {
		t.Fatal(err)
	}
	r := &Runner{bwrap: "/usr/bin/bwrap", vault: mv}
	env, secrets, err := r.childEnv(context.Background(), ports.ToolSpec{
		EngagementID: "eng1",
		Workdir:      "/work",
		Env:          []string{"TOOL_TOKEN={{secret:API_KEY}}", "PLAIN=value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || string(secrets[0]) != "s3cr3t" {
		t.Errorf("childEnv should return the resolved secret values for scrubbing: %q", secrets)
	}
	has := func(want string) bool {
		for _, e := range env {
			if e == want {
				return true
			}
		}
		return false
	}
	if !has("TOOL_TOKEN=s3cr3t") {
		t.Errorf("secret should be resolved into the env: %v", env)
	}
	if !has("PLAIN=value") || !has("HOME=/work") {
		t.Errorf("plain env + HOME should be present: %v", env)
	}
	// A clean base env only – the worker's environment must NOT be inherited.
	for _, e := range env {
		if strings.HasPrefix(e, "SYNAPSE_") {
			t.Errorf("worker env leaked into the child: %q", e)
		}
	}
}

func TestChildEnvFailsClosedWithoutVault(t *testing.T) {
	r := &Runner{bwrap: "/usr/bin/bwrap"} // no vault
	_, _, err := r.childEnv(context.Background(), ports.ToolSpec{
		EngagementID: "eng1",
		Env:          []string{"TOK={{secret:API_KEY}}"},
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a secret placeholder with no vault must fail closed, got %v", err)
	}
}

func TestSecretsNeverEnterArgv(t *testing.T) {
	c, _ := vault.NewCipher(make([]byte, 32))
	mv := vault.NewMemoryVault(c, nil)
	_ = mv.Put(context.Background(), "eng1", "TOK", []byte("PLAINTEXT_SECRET"))
	r := &Runner{bwrap: "/usr/bin/bwrap", vault: mv}
	// The argv (command) must reference the placeholder name at most, never resolve it.
	argv := r.command(ports.ToolSpec{Name: "tool", EngagementID: "eng1", Env: []string{"TOK={{secret:TOK}}"}}, "", "", 3, 0, 0, false)
	if strings.Contains(strings.Join(argv, " "), "PLAINTEXT_SECRET") {
		t.Fatal("a resolved secret must NEVER appear in the argv")
	}
}

// TestResolveToolPathKeepsHostPathOutOfSandboxAuthority pins the resolution contract. bwrapArgs binds
// the binary only when spec.Name is ABSOLUTE, so an operator-configured absolute helper (the
// documented /opt/synapse/bin/synapse-cspm layout) must survive untouched - that is what makes it
// bindable. A BARE name is a different case: resolving it through the host PATH without integrity
// verification would let an inherited entry such as /tmp/attacker/tool be resolved on the host and
// then explicitly bound in, where bwrap would otherwise resolve it against the sandbox's own curated
// PATH and fail closed.
func TestResolveToolPathKeepsHostPathOutOfSandboxAuthority(t *testing.T) {
	dir := t.TempDir()
	name := "synapse-fake-helper"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	bare := strings.TrimSuffix(name, ".exe")
	if runtime.GOOS == "windows" {
		bare = name
	}

	// Verified: a bare name resolves, so the verified path is the bound and executed path.
	if got := resolveToolPath(bare, true); !filepath.IsAbs(got) {
		t.Errorf("resolveToolPath(%q, hostPATHIsAuthority) = %q, want an absolute path", bare, got)
	}
	// Unverified: host PATH is not an authority for what gets bound; leave it to bwrap.
	if got := resolveToolPath(bare, false); got != bare {
		t.Errorf("resolveToolPath(%q, !hostPATHIsAuthority) = %q, want the bare name so bwrap resolves it inside the sandbox", bare, got)
	}
	// An absolute operator-configured path is returned as given, verified or not.
	const absolute = "/opt/synapse/bin/synapse-cspm"
	for _, hostPATHIsAuthority := range []bool{true, false} {
		if got := resolveToolPath(absolute, hostPATHIsAuthority); got != absolute {
			t.Errorf("resolveToolPath(%q, %v) = %q, want it unchanged", absolute, hostPATHIsAuthority, got)
		}
	}
	// An unresolvable name is returned unchanged so bwrap surfaces the not-found itself.
	if got := resolveToolPath("synapse-definitely-not-on-path", true); got != "synapse-definitely-not-on-path" {
		t.Errorf("resolveToolPath(missing) = %q, want the name unchanged", got)
	}
}

func TestPrepareEgressHostsFileUsesOnlyPinnedAddresses(t *testing.T) {
	path, err := prepareEgressHostsFile(ports.EgressPolicy{PinnedHosts: map[string][]netip.Addr{
		"api.example.com": {netip.MustParseAddr("203.0.113.8"), netip.MustParseAddr("203.0.113.7")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "203.0.113.7 api.example.com\n203.0.113.8 api.example.com\n") {
		t.Fatalf("hosts file = %q", got)
	}
}

func TestPrepareEgressHostsFileCanonicalizesMixedCasePins(t *testing.T) {
	path, err := prepareEgressHostsFile(ports.EgressPolicy{PinnedHosts: map[string][]netip.Addr{
		"API.Example.COM": {netip.MustParseAddr("203.0.113.8")},
		"api.example.com": {netip.MustParseAddr("203.0.113.7")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); !strings.Contains(got, "203.0.113.7 api.example.com\n203.0.113.8 api.example.com\n") {
		t.Fatalf("hosts file = %q", got)
	}
}

func TestPrepareEgressHostsFileRejectsUnsafeOrIPv6Pins(t *testing.T) {
	for name, policy := range map[string]ports.EgressPolicy{
		"unsafe host": {PinnedHosts: map[string][]netip.Addr{"example.com\ninvalid": {netip.MustParseAddr("203.0.113.7")}}},
		"ipv6":        {PinnedHosts: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("2001:db8::1")}}},
	} {
		t.Run(name, func(t *testing.T) {
			if path, err := prepareEgressHostsFile(policy); err == nil {
				_ = os.Remove(path)
				t.Fatal("unsafe pinned host policy must fail closed")
			}
		})
	}
}

// TestSandboxBindsResolvedBinaryOnTheLegacyPath is the argv-level half: a runner with NO binary
// registry (legacy PATH trust) must still emit the bind for a resolved out-of-root helper.
func TestSandboxBindsResolvedBinaryOnTheLegacyPath(t *testing.T) {
	r := fakeRunner("")
	if r.binreg != nil {
		t.Fatal("this test must exercise the legacy PATH-trust path (binreg == nil)")
	}
	joined := strings.Join(r.command(ports.ToolSpec{Name: "/opt/synapse/bin/synapse-cspm"}, "", "", 3, 0, 0, false), " ")
	if !strings.Contains(joined, "--ro-bind-try /opt/synapse/bin/synapse-cspm /opt/synapse/bin/synapse-cspm") {
		t.Errorf("no bind emitted without a binary registry: %s", joined)
	}
}
