package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCollectProcessesReadsAProcfsTree builds a tiny procfs-shaped directory and checks the enumerator
// reads one entry per numeric pid with its comm, skips non-numeric and non-directory entries, and never
// fails on a pid missing an exe link. This runs on every platform (no real /proc dependency).
func TestCollectProcessesReadsAProcfsTree(t *testing.T) {
	root := t.TempDir()
	mkproc := func(pid, comm string, withExe bool) {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if withExe {
			target := filepath.Join(root, "bin-"+pid)
			if err := os.WriteFile(target, []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "exe")); err != nil {
				t.Skipf("symlink unsupported here: %v", err)
			}
		}
	}
	mkproc("1", "systemd", true)
	mkproc("4242", "sshd", false) // a pid whose exe link the agent cannot resolve is still reported
	// Noise that must be ignored: procfs has many non-pid entries.
	if err := os.WriteFile(filepath.Join(root, "cmdline"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}

	procs := collectProcesses(root)
	if len(procs) != 2 {
		t.Fatalf("want 2 processes (only numeric pids), got %d: %+v", len(procs), procs)
	}
	byPID := map[int]string{}
	paths := map[int]string{}
	for _, p := range procs {
		byPID[p.PID] = p.Comm
		paths[p.PID] = p.Path
		if !p.Running {
			t.Errorf("enumerated process %d must be marked running", p.PID)
		}
	}
	if byPID[1] != "systemd" || byPID[4242] != "sshd" {
		t.Fatalf("comm mismatch: %+v", byPID)
	}
	if paths[1] == "" {
		t.Errorf("pid 1 should carry its resolved exe path")
	}
	if paths[4242] != "" {
		t.Errorf("pid 4242 had no exe link; its path must be empty, got %q", paths[4242])
	}
}

// TestCollectProcessesMissingRoot: a procfs root that does not exist (a non-Linux host) yields no
// processes and no panic, so the reporter simply ships nothing.
func TestCollectProcessesMissingRoot(t *testing.T) {
	if got := collectProcesses(filepath.Join(t.TempDir(), "nonexistent")); len(got) != 0 {
		t.Fatalf("a missing procfs root must yield no processes, got %d", len(got))
	}
}
