//go:build !linux

package sandbox

import "errors"

// On non-Linux platforms cgroup v2 does not exist; newRunCgroup always errors so the
// runner falls back (the sandbox itself is already unavailable off Linux – no bwrap).
type runCgroup struct{}

func newRunCgroup(int64, int64, int) (*runCgroup, error) {
	return nil, errors.New("cgroup v2 unavailable off Linux")
}

func (c *runCgroup) FD() int      { return -1 }
func (c *runCgroup) Path() string { return "" }
func (c *runCgroup) Close()       {}
