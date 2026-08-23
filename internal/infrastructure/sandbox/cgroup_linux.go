//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	cgroupRoot        = "/sys/fs/cgroup"
	cgroupManagerName = "synapse-manager"
)

// runCgroup is a per-run cgroup v2 with hard resource limits (F3). The service
// uses systemd Delegate=yes, moves itself into a manager child, and creates run
// siblings beneath the assigned unit cgroup. It never writes outside that subtree.
type runCgroup struct {
	path string
	dir  *os.File
}

// newRunCgroup creates the cgroup, writes the limits (checked – a failed limit write is an
// error, never a silently-unlimited cgroup), and opens its dir fd for clone-into-cgroup.
// prepareDelegatedCgroup prepares the service's systemd-delegated cgroup v2 subtree.
func prepareDelegatedCgroup() (string, error) {
	membership, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", fmt.Errorf("read cgroup membership: %w", err)
	}
	return prepareDelegatedCgroupAt(cgroupRoot, membership, os.Getpid())
}

func prepareDelegatedCgroupAt(root string, membership []byte, pid int) (string, error) {
	membershipRoot, err := unifiedCgroupRoot(root, membership)
	if err != nil {
		return "", err
	}
	unitRoot := membershipRoot
	if filepath.Base(membershipRoot) == cgroupManagerName {
		unitRoot = filepath.Dir(membershipRoot)
	}
	controllers, err := os.ReadFile(filepath.Join(unitRoot, "cgroup.controllers"))
	if err != nil {
		return "", fmt.Errorf("read delegated controllers: %w", err)
	}
	available := make(map[string]bool)
	for _, controller := range strings.Fields(string(controllers)) {
		available[controller] = true
	}
	for _, required := range []string{"memory", "pids"} {
		if !available[required] {
			return "", fmt.Errorf("delegated cgroup controller %q is unavailable", required)
		}
	}

	manager := filepath.Join(unitRoot, cgroupManagerName)
	if err := os.Mkdir(manager, 0o755); err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("create cgroup manager child: %w", err)
	}
	if membershipRoot != manager {
		if err := os.WriteFile(filepath.Join(manager, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
			return "", fmt.Errorf("move service into cgroup manager child: %w", err)
		}
	}
	if err := os.WriteFile(filepath.Join(unitRoot, "cgroup.subtree_control"), []byte("+memory +pids"), 0o644); err != nil {
		return "", fmt.Errorf("enable delegated cgroup controllers: %w", err)
	}
	return unitRoot, nil
}

func unifiedCgroupRoot(root string, membership []byte) (string, error) {
	var relative string
	for _, line := range strings.Split(strings.TrimSpace(string(membership)), "\n") {
		if strings.HasPrefix(line, "0::") {
			relative = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if relative == "" || !strings.HasPrefix(relative, "/") {
		return "", fmt.Errorf("unified cgroup v2 membership is unavailable")
	}
	for _, part := range strings.Split(relative, "/") {
		if part == ".." {
			return "", fmt.Errorf("invalid unified cgroup path")
		}
	}
	cleanRoot := filepath.Clean(root)
	joined := filepath.Join(cleanRoot, filepath.FromSlash(strings.TrimPrefix(relative, "/")))
	if joined != cleanRoot && !strings.HasPrefix(joined, cleanRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("unified cgroup path escapes cgroup root")
	}
	return joined, nil
}

func newRunCgroup(root string, seq int64, memMax int64, pidsMax int) (*runCgroup, error) {
	if root == "" {
		return nil, fmt.Errorf("delegated cgroup root is unavailable")
	}
	path := filepath.Join(root, fmt.Sprintf("synapse-run-%d-%d", os.Getpid(), seq))
	_ = os.Remove(path) // defensive: clear a stale empty dir from a failed setup
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
