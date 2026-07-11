package acquire

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAcquireLocal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ws, err := New().Acquire(context.Background(), ports.AcquireRequest{Kind: "local", Value: dir})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if ws.Dir != dir {
		t.Errorf("workspace dir = %q, want %q", ws.Dir, dir)
	}
	if err := ws.Close(); err != nil { // local has no cleanup
		t.Errorf("Close: %v", err)
	}
}

func TestAcquireLocalMissing(t *testing.T) {
	_, err := New().Acquire(context.Background(), ports.AcquireRequest{Kind: "local", Value: filepath.Join(t.TempDir(), "nope")})
	if err == nil {
		t.Fatal("want error for missing path")
	}
}

func TestAcquireLocalRejectsSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, err := New().Acquire(context.Background(), ports.AcquireRequest{Kind: "local", Value: link}); err == nil {
		t.Fatal("want error: symlinked target root must be refused")
	}
}

func TestAcquireUnknownAndUnimplementedKinds(t *testing.T) {
	for _, kind := range []string{"archive", "image", "bogus"} {
		if _, err := New().Acquire(context.Background(), ports.AcquireRequest{Kind: kind, Value: "x"}); err == nil {
			t.Errorf("kind %q: want error", kind)
		}
	}
}

func TestValidateGitURL(t *testing.T) {
	ok := []string{"https://github.com/x/y.git"}
	for _, u := range ok {
		if err := validateGitURL(u); err != nil {
			t.Errorf("validateGitURL(%q) = %v, want nil", u, err)
		}
	}
	// http:// is now rejected (MITM-able, same as git://) – https only.
	bad := []string{"", "-x", "http://h/x", "git://h/x", "ssh://h/x", "git@github.com:x/y.git", "ext::sh -c id", "file:///etc/passwd", "/local/path"}
	for _, u := range bad {
		if err := validateGitURL(u); err == nil {
			t.Errorf("validateGitURL(%q) = nil, want error", u)
		}
	}
}

func TestValidateGitRef(t *testing.T) {
	ok := []string{"", "main", "v1.2.3", "release-2.x", "feature/foo", "1.0.0"}
	for _, r := range ok {
		if err := validateGitRef(r); err != nil {
			t.Errorf("validateGitRef(%q) = %v, want nil", r, err)
		}
	}
	// Leading '-' is option injection (e.g. --upload-pack); spaces/meta are rejected.
	bad := []string{"-x", "--upload-pack=sh", "a b", "a;b", "a$(id)", "../x", "a\tb"}
	for _, r := range bad {
		if err := validateGitRef(r); err == nil {
			t.Errorf("validateGitRef(%q) = nil, want error", r)
		}
	}
}

func TestRejectInternalAcquisitionHost(t *testing.T) {
	// loopback + link-local (incl. cloud metadata) must be refused; public + RFC1918 allowed.
	for _, h := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0"} {
		if err := rejectInternalAcquisitionHost(h); err == nil {
			t.Errorf("host %q (loopback/link-local) must be refused", h)
		}
	}
	for _, h := range []string{"140.82.112.3" /*github*/, "10.0.0.5" /*internal git, allowed*/} {
		if err := rejectInternalAcquisitionHost(h); err != nil {
			t.Errorf("host %q should be allowed, got %v", h, err)
		}
	}
}
