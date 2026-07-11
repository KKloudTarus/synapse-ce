//go:build linux

package sandbox_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const seccompProbeC = `
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
static void t(const char*n,long nr,long a1){errno=0;long r=syscall(nr,a1,0,0,0,0,0);printf("%s rc=%ld errno=%d\n",n,r,errno);}
int main(){
  t("ptrace",SYS_ptrace,0);
  t("bpf",SYS_bpf,0);
  t("keyctl",SYS_keyctl,0);
  t("add_key",SYS_add_key,0);
  t("userfaultfd",SYS_userfaultfd,0);
  t("unshare",SYS_unshare,0x10000000);
  t("mount",SYS_mount,0);
  t("setns",SYS_setns,0);
  errno=0;long p=syscall(SYS_socket,17,3,0,0,0,0);printf("af_packet rc=%ld errno=%d\n",p,errno);
  t("getpid",SYS_getpid,0);
  return 0;
}
`

// TestSeccompDeniesDangerousSyscalls proves F1: under the sandbox's seccomp filter, the
// dangerous syscalls the audit named return EPERM, while an allowlisted one (getpid)
// works and a real Go tool (syft) still runs. Needs bwrap + gcc + syft (a real Linux host).
func TestSeccompDeniesDangerousSyscalls(t *testing.T) {
	for _, b := range []string{"bwrap", "gcc"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not installed", b)
		}
	}
	sb, err := sandbox.NewRunner(60*time.Second, 8<<20, 1<<30, 256)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "probe.c"), []byte(seccompProbeC), 0o644)
	probe := filepath.Join(dir, "probe")
	if out, err := exec.Command("gcc", "-O0", "-o", probe, filepath.Join(dir, "probe.c")).CombinedOutput(); err != nil {
		t.Fatalf("compile probe: %v\n%s", err, out)
	}
	res, err := sb.Run(context.Background(), ports.ToolSpec{Name: probe, Workdir: dir})
	if err != nil {
		t.Fatalf("run probe: %v", err)
	}
	out := string(res.Stdout)
	t.Logf("probe output:\n%s", out)

	denied := []string{"ptrace", "af_packet", "bpf", "keyctl", "add_key", "userfaultfd", "unshare", "mount", "setns"}
	for _, name := range denied {
		// Expect "<name> rc=-1 errno=1" (EPERM) – the seccomp filter blocked it.
		line := lineFor(out, name)
		if !strings.Contains(line, "rc=-1") || !strings.Contains(line, "errno=1") {
			t.Errorf("syscall %q was NOT seccomp-denied (want rc=-1 errno=1): %q", name, line)
		}
	}
	// Sanity: an allowlisted syscall must succeed (getpid returns a real pid, errno 0).
	if g := lineFor(out, "getpid"); strings.Contains(g, "rc=-1") {
		t.Errorf("allowlisted getpid was wrongly denied: %q", g)
	}
}

// TestSeccompAllowsRealTool proves the allowlist is complete enough to run a real Go tool.
func TestSeccompAllowsRealTool(t *testing.T) {
	for _, b := range []string{"bwrap", "syft"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not installed", b)
		}
	}
	sb, err := sandbox.NewRunner(120*time.Second, 32<<20, 1<<30, 512)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "package-lock.json"),
		[]byte(`{"name":"t","version":"1.0.0","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.4"}}}`), 0o644)
	res, err := sb.Run(context.Background(), ports.ToolSpec{
		Name: "syft", Args: []string{"scan", "dir:" + dir, "-o", "cyclonedx-json", "-q"},
		Workdir: dir, ReadOnlyPaths: []string{dir},
	})
	if err != nil {
		t.Fatalf("syft under seccomp: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(string(res.Stdout), "lodash") {
		t.Fatalf("syft under seccomp did not produce a valid SBOM: exit=%d stderr=%s", res.ExitCode, res.Stderr)
	}
	t.Logf("syft ran fully under seccomp (SBOM with lodash produced)")
}

func lineFor(out, name string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, name+" ") {
			return l
		}
	}
	return ""
}
