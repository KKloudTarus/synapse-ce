//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnifiedCgroupRoot(t *testing.T) {
	root := t.TempDir()
	got, err := unifiedCgroupRoot(root, []byte("0::/system.slice/synapse-worker.service\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "system.slice", "synapse-worker.service")
	if got != want {
		t.Fatalf("root = %q, want %q", got, want)
	}
}

func TestUnifiedCgroupRootRejectsLegacyMembership(t *testing.T) {
	if _, err := unifiedCgroupRoot(t.TempDir(), []byte("2:memory:/service\n")); err == nil {
		t.Fatal("legacy cgroup membership must be rejected")
	}
}

func TestPrepareDelegatedCgroupAt(t *testing.T) {
	root := t.TempDir()
	unit := filepath.Join(root, "system.slice", "synapse-worker.service")
	manager := filepath.Join(unit, cgroupManagerName)
	if err := os.MkdirAll(manager, 0o755); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{
		filepath.Join(unit, "cgroup.controllers"):     "cpu memory pids\n",
		filepath.Join(unit, "cgroup.subtree_control"): "",
		filepath.Join(manager, "cgroup.procs"):        "",
	} {
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := prepareDelegatedCgroupAt(root, []byte("0::/system.slice/synapse-worker.service\n"), 4321)
	if err != nil {
		t.Fatal(err)
	}
	if got != unit {
		t.Fatalf("delegated root = %q, want %q", got, unit)
	}
	assertFileContains(t, filepath.Join(manager, "cgroup.procs"), "4321")
	assertFileContains(t, filepath.Join(unit, "cgroup.subtree_control"), "+memory +pids")
}

func TestPrepareDelegatedCgroupAtIsIdempotentFromManagerChild(t *testing.T) {
	root := t.TempDir()
	unit := filepath.Join(root, "system.slice", "synapse-worker.service")
	manager := filepath.Join(unit, cgroupManagerName)
	if err := os.MkdirAll(manager, 0o755); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{
		filepath.Join(unit, "cgroup.controllers"):     "cpu memory pids\n",
		filepath.Join(unit, "cgroup.subtree_control"): "",
		filepath.Join(manager, "cgroup.procs"):        "already-member\n",
	} {
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := prepareDelegatedCgroupAt(root, []byte("0::/system.slice/synapse-worker.service/synapse-manager\n"), 4321)
	if err != nil {
		t.Fatal(err)
	}
	if got != unit {
		t.Fatalf("delegated root = %q, want %q", got, unit)
	}
	assertFileContains(t, filepath.Join(manager, "cgroup.procs"), "already-member")
	assertFileContains(t, filepath.Join(unit, "cgroup.subtree_control"), "+memory +pids")
	if _, err := os.Stat(filepath.Join(manager, cgroupManagerName)); !os.IsNotExist(err) {
		t.Fatalf("nested manager child must not be created: %v", err)
	}
}

func TestPrepareDelegatedCgroupAtRequiresControllers(t *testing.T) {
	root := t.TempDir()
	unit := filepath.Join(root, "service")
	if err := os.MkdirAll(unit, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unit, "cgroup.controllers"), []byte("pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareDelegatedCgroupAt(root, []byte("0::/service\n"), 1); err == nil {
		t.Fatal("missing memory controller must fail closed")
	}
}

func TestNewRunCgroupWritesLimits(t *testing.T) {
	root := t.TempDir()
	cg, err := newRunCgroup(root, 7, 64<<20, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer cg.Close()
	assertFileContains(t, filepath.Join(cg.Path(), "memory.max"), "67108864")
	assertFileContains(t, filepath.Join(cg.Path(), "pids.max"), "32")
}

func assertFileContains(t *testing.T, path, want string) {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(value)) != want {
		t.Fatalf("%s = %q, want %q", path, value, want)
	}
}
