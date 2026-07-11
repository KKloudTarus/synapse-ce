package sandbox

import (
	"context"
	"errors"
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
