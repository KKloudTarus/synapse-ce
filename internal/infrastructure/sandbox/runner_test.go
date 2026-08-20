package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeRunner builds a Runner without LookPath so the argv-construction logic (the
// security-critical part) is unit-testable on any platform.
func fakeRunner(systemdRun string) *Runner {
	return &Runner{bwrap: "/usr/bin/bwrap", systemdRun: systemdRun, memMax: 256 << 20, pidsMax: 128}
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
	argv := r.command(ports.ToolSpec{Name: "subfinder", Args: []string{"-d", "example.com"}, Workdir: "/run/work"}, "", "", 3, false)
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
		"--ro-bind-try /etc/nsswitch.conf /etc/nsswitch.conf",
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
	argv := r.command(ports.ToolSpec{Name: "naabu", CapAdd: []string{"CAP_NET_RAW", "CAP_SYS_ADMIN"}}, "", "", 3, false)
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
	argv := r.command(ports.ToolSpec{Name: "httpx"}, "", "", 3, false)
	if strings.Contains(strings.Join(argv, " "), "--cap-add") {
		t.Error("a non-capability-sensitive tool must run with no added caps")
	}
}

func TestSandboxWrapsInSystemdRunForLimits(t *testing.T) {
	r := fakeRunner("/usr/bin/systemd-run")
	argv := r.command(ports.ToolSpec{Name: "syft", MemMaxBytes: 512 << 20, PidsMax: 64}, "", "", 3, false)
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
	// directCgroup=true → the run is already in a limit cgroup; systemd-run must be skipped
	// to avoid a redundant scope (F3).
	argv := r.command(ports.ToolSpec{Name: "syft"}, "", "", 3, true)
	if argv[0] == "/usr/bin/systemd-run" {
		t.Errorf("direct cgroup run must NOT also wrap in systemd-run: %v", argv)
	}
	if argv[0] != "/usr/bin/bwrap" {
		t.Errorf("argv[0] should be bwrap directly: %v", argv)
	}
}

func TestSandboxReadOnlyExtraBinds(t *testing.T) {
	r := fakeRunner("")
	argv := r.command(ports.ToolSpec{Name: "grype", ReadOnlyPaths: []string{"/var/grypedb", "/src"}}, "", "", 3, false)
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
	argv := r.command(ports.ToolSpec{Name: "/opt/synapse/bin/synapse-cspm"}, "", "", 3, false)
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
	joined := strings.Join(r.command(ports.ToolSpec{Name: "/usr/bin/syft"}, "", "", 3, false), " ")
	if strings.Contains(joined, "--ro-bind-try /usr/bin/syft /usr/bin/syft") {
		t.Errorf("re-bound a tool already inside the curated root: %s", joined)
	}
	for _, name := range []string{"/libexec/synapse/helper", "/lib-evil/helper"} {
		joined = strings.Join(r.command(ports.ToolSpec{Name: name}, "", "", 3, false), " ")
		if !strings.Contains(joined, "--ro-bind-try "+name+" "+name) {
			t.Errorf("%s was treated as inside the curated root: %s", name, joined)
		}
	}
	// A relative name still resolves through PATH inside the sandbox; binding it would be wrong.
	joined = strings.Join(r.command(ports.ToolSpec{Name: "grype"}, "", "", 3, false), " ")
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
	argv := r.command(ports.ToolSpec{Name: "tool", EngagementID: "eng1", Env: []string{"TOK={{secret:TOK}}"}}, "", "", 3, false)
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

// TestSandboxBindsResolvedBinaryOnTheLegacyPath is the argv-level half: a runner with NO binary
// registry (legacy PATH trust) must still emit the bind for a resolved out-of-root helper.
func TestSandboxBindsResolvedBinaryOnTheLegacyPath(t *testing.T) {
	r := fakeRunner("")
	if r.binreg != nil {
		t.Fatal("this test must exercise the legacy PATH-trust path (binreg == nil)")
	}
	joined := strings.Join(r.command(ports.ToolSpec{Name: "/opt/synapse/bin/synapse-cspm"}, "", "", 3, false), " ")
	if !strings.Contains(joined, "--ro-bind-try /opt/synapse/bin/synapse-cspm /opt/synapse/bin/synapse-cspm") {
		t.Errorf("no bind emitted without a binary registry: %s", joined)
	}
}
