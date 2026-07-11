package httpapi

import (
	"os"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
)

func scopeOf(in []engagement.Target, out ...engagement.Target) engagement.Scope {
	return engagement.Scope{InScope: in, OutOfScope: out}
}

func TestLocalSourceDir(t *testing.T) {
	dir := t.TempDir()
	// A repo target whose value is an existing directory is returned.
	got := localSourceDir(scopeOf([]engagement.Target{
		{Kind: engagement.TargetDomain, Value: "app.example.com"},
		{Kind: engagement.TargetRepo, Value: dir},
	}))
	if got != dir {
		t.Errorf("want %q, got %q", dir, got)
	}
	// A repo target pointing at a non-existent path is ignored (no arbitrary path leaks).
	if s := localSourceDir(scopeOf([]engagement.Target{{Kind: engagement.TargetRepo, Value: "/no/such/dir/xyz"}})); s != "" {
		t.Errorf("non-existent path must yield \"\", got %q", s)
	}
	// A repo target pointing at a FILE (not a dir) is ignored.
	f := dir + "/afile"
	os.WriteFile(f, []byte("x"), 0o644)
	if s := localSourceDir(scopeOf([]engagement.Target{{Kind: engagement.TargetRepo, Value: f}})); s != "" {
		t.Errorf("file target must yield \"\", got %q", s)
	}
	// Non-repo kinds (image/url) never match.
	if s := localSourceDir(scopeOf([]engagement.Target{{Kind: engagement.TargetImage, Value: dir}})); s != "" {
		t.Errorf("non-repo kind must yield \"\", got %q", s)
	}
	// A repo that is also out-of-scope must be rejected (out-of-scope always wins).
	if s := localSourceDir(scopeOf(
		[]engagement.Target{{Kind: engagement.TargetRepo, Value: dir}},
		engagement.Target{Kind: engagement.TargetRepo, Value: dir},
	)); s != "" {
		t.Errorf("out-of-scope repo must yield \"\", got %q", s)
	}
	if s := localSourceDir(scopeOf(nil)); s != "" {
		t.Errorf("empty targets must yield \"\", got %q", s)
	}
}
