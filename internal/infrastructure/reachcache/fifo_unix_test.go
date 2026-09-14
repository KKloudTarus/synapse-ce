//go:build !windows

package reachcache

import (
	"path/filepath"
	"syscall"
	"testing"
)

func makeFIFO(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(filepath.Clean(path), 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
}
