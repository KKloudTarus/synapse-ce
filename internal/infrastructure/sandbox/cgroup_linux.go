//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const cgroupRoot = "/sys/fs/cgroup"

// runCgroup is a per-run cgroup v2 with hard resource limits (F3). The tool is created
// inside it via clone-into-cgroup (CgroupFD), so memory.max + pids.max bound a memory or
// fork bomb on EVERY execution path – egress and isolated alike – without depending on
// systemd-run. Creating a cgroup needs write access to /sys/fs/cgroup (root / CAP delegated);
// the egress path always has it, so the privileged runs that touch hostile networks are
// always limited. When creation isn't permitted, newRunCgroup errors and the caller falls
// back to the best-effort systemd-run limiter.
type runCgroup struct {
	path string
	dir  *os.File
}

// newRunCgroup creates the cgroup, writes the limits (checked – a failed limit write is an
// error, never a silently-unlimited cgroup), and opens its dir fd for clone-into-cgroup.
func newRunCgroup(seq int64, memMax int64, pidsMax int) (*runCgroup, error) {
	path := filepath.Join(cgroupRoot, fmt.Sprintf("synapse-run-%d", seq))
	_ = os.Remove(path) // defensive: clear a stale dir from a crashed prior run
	if err := os.Mkdir(path, 0o755); err != nil {
		return nil, fmt.Errorf("create cgroup: %w", err)
	}
	cg := &runCgroup{path: path}
	write := func(file, val string) error {
		if err := os.WriteFile(filepath.Join(path, file), []byte(val), 0o644); err != nil {
			return fmt.Errorf("set %s=%s: %w", file, val, err)
		}
		return nil
	}
	if memMax > 0 {
		if err := write("memory.max", strconv.FormatInt(memMax, 10)); err != nil {
			cg.Close()
			return nil, err
		}
		// No swap escape hatch – a memory bomb must not spill into swap to evade memory.max.
		// Checked: if the controller is present but the write fails, fail the cgroup (the
		// caller falls back) rather than silently allowing swap-based evasion. Skipped only
		// when swap accounting is absent (file missing → write returns an error we tolerate).
		if _, statErr := os.Stat(filepath.Join(path, "memory.swap.max")); statErr == nil {
			if err := write("memory.swap.max", "0"); err != nil {
				cg.Close()
				return nil, err
			}
		}
	}
	if pidsMax > 0 {
		if err := write("pids.max", strconv.Itoa(pidsMax)); err != nil {
			cg.Close()
			return nil, err
		}
	}
	dir, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		cg.Close()
		return nil, fmt.Errorf("open cgroup dir: %w", err)
	}
	cg.dir = dir
	return cg, nil
}

// FD is the cgroup directory fd for SysProcAttr.CgroupFD (clone-into-cgroup).
func (c *runCgroup) FD() int { return int(c.dir.Fd()) }

// Path is the cgroup directory path (for the eBPF connect-logger to attach to).
func (c *runCgroup) Path() string { return c.path }

// Close drops the dir fd and removes the (now-empty, tool exited) cgroup. Best-effort.
func (c *runCgroup) Close() {
	if c.dir != nil {
		_ = c.dir.Close()
		c.dir = nil
	}
	if c.path != "" {
		_ = os.Remove(c.path)
		c.path = ""
	}
}
