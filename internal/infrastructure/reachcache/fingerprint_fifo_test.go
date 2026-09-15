//go:build !windows

package reachcache

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestTreeFingerprintGoModFIFONotOpened(t *testing.T) {
	dir := writeTree(t, map[string]string{"main.go": "package main"})
	if err := syscall.Mkfifo(filepath.Join(dir, "go.mod"), 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	done := make(chan struct{})
	go func() { _, _, _ = NewTreeFingerprinter().FingerprintSource(context.Background(), dir); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("FingerprintSource hung: a FIFO named go.mod must not be opened")
	}
}

func TestTreeFingerprintFIFONotOpened(t *testing.T) {
	dir := writeTree(t, map[string]string{"main.go": "package main"})
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	done := make(chan struct{})
	var src string
	go func() {
		src, _, _ = NewTreeFingerprinter().FingerprintSource(context.Background(), dir)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("FingerprintSource hung: a FIFO must not be opened")
	}
	if src == "" {
		t.Fatal("expected a source hash with a FIFO present")
	}
}
