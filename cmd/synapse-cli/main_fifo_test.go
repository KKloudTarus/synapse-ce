//go:build !windows

package main

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestGoModulePathFIFONotOpened(t *testing.T) {
	odd := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(odd, "go.mod"), 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan string, 1)
	go func() { done <- goModulePath(odd) }()
	select {
	case got := <-done:
		if got != "" {
			t.Fatalf("a non-regular go.mod must read as no module, got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("goModulePath blocked on a FIFO named go.mod: the regular-file check is missing")
	}
}
