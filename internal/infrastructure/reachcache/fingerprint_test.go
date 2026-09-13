package reachcache

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func hashOf(t *testing.T, dir string) string {
	t.Helper()
	src, env, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("FingerprintSource: %v", err)
	}
	if src == "" || env == "" {
		t.Fatalf("empty fingerprint: src=%q env=%q", src, env)
	}
	return src
}

// The same tree content yields the same source hash across two independent walks (order-independent).
func TestTreeFingerprintStable(t *testing.T) {
	files := map[string]string{"main.go": "package main", "pkg/a.go": "package pkg", "go.mod": "module x"}
	if hashOf(t, writeTree(t, files)) != hashOf(t, writeTree(t, files)) {
		t.Fatal("identical trees must hash equal")
	}
}

// Editing a file's content changes the source hash.
func TestTreeFingerprintContentChange(t *testing.T) {
	base := hashOf(t, writeTree(t, map[string]string{"main.go": "package main", "go.mod": "module x"}))
	changed := hashOf(t, writeTree(t, map[string]string{"main.go": "package main // v2", "go.mod": "module x"}))
	if base == changed {
		t.Fatal("a content change must change the source hash")
	}
}

// Adding a file changes the hash (the file count and the new digest both move).
func TestTreeFingerprintAddFile(t *testing.T) {
	base := hashOf(t, writeTree(t, map[string]string{"main.go": "package main"}))
	added := hashOf(t, writeTree(t, map[string]string{"main.go": "package main", "extra.go": "package main"}))
	if base == added {
		t.Fatal("adding a file must change the source hash")
	}
}

// Removing a file changes the hash.
func TestTreeFingerprintRemoveFile(t *testing.T) {
	full := hashOf(t, writeTree(t, map[string]string{"a.go": "package a", "b.go": "package b"}))
	fewer := hashOf(t, writeTree(t, map[string]string{"a.go": "package a"}))
	if full == fewer {
		t.Fatal("removing a file must change the source hash")
	}
}

// Renaming a file (same content, different path) changes the hash, because the path is bound.
func TestTreeFingerprintRename(t *testing.T) {
	a := hashOf(t, writeTree(t, map[string]string{"a.go": "package main"}))
	b := hashOf(t, writeTree(t, map[string]string{"b.go": "package main"}))
	if a == b {
		t.Fatal("a rename must change the source hash (path is bound)")
	}
}

// The .git directory is excluded, so a VCS-only change does not invalidate the cache.
func TestTreeFingerprintExcludesGit(t *testing.T) {
	dir := writeTree(t, map[string]string{"main.go": "package main"})
	before := hashOf(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main"), 0o644); err != nil {
		t.Fatal(err)
	}
	if before != hashOf(t, dir) {
		t.Fatal(".git content must not change the source hash")
	}
}

// A missing target directory is an error, which disables the cache (never a fabricated hash).
func TestTreeFingerprintMissingDirErrors(t *testing.T) {
	_, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatal("a missing directory must return an error")
	}
}

// A file (not a directory) target is an error.
func TestTreeFingerprintNonDirErrors(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(f, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), f); err == nil {
		t.Fatal("a non-directory target must return an error")
	}
}

// A cancelled context aborts the walk with an error (no partial hash).
func TestTreeFingerprintContextCancel(t *testing.T) {
	dir := writeTree(t, map[string]string{"a.go": "package a", "b.go": "package b"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := NewTreeFingerprinter().FingerprintSource(ctx, dir); err == nil {
		t.Fatal("a cancelled context must return an error")
	}
}

// Changing a file's mode changes the source hash (mode is bound).
func TestTreeFingerprintModeChange(t *testing.T) {
	dir := writeTree(t, map[string]string{"run.sh": "echo hi"})
	before := hashOf(t, dir)
	if err := os.Chmod(filepath.Join(dir, "run.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if before == hashOf(t, dir) {
		t.Fatal("a mode change must change the source hash")
	}
}

// An IN-TREE symlink is fine: the file it points at is walked as its own entry, so its content is already
// bound. Editing that in-tree target changes the hash (via the target's own entry, not the link).
func TestTreeFingerprintInTreeSymlink(t *testing.T) {
	dir := writeTree(t, map[string]string{"real.go": "package main"})
	if err := os.Symlink(filepath.Join(dir, "real.go"), filepath.Join(dir, "link.go")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	before := hashOf(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "real.go"), []byte("package main // v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if before == hashOf(t, dir) {
		t.Fatal("editing an in-tree symlink target must change the source hash")
	}
}

// An OUT-OF-TREE symlink is an error, which disables the cache: content behind it can change invisibly, so
// serving a cached graph would risk a stale not_reachable. This is the QA-identified soundness boundary.
func TestTreeFingerprintOutOfTreeSymlinkErrors(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "shared.go")
	if err := os.WriteFile(target, []byte("package shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := writeTree(t, map[string]string{"main.go": "package main"})
	if err := os.Symlink(target, filepath.Join(dir, "shared.go")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("an out-of-tree symlink must error (disable the cache), never hash only the link string")
	}
}

// A dangling (broken) symlink is not an error: there is no readable content behind it, so hashing the link
// string is sound, and its target string still contributes to the hash.
func TestTreeFingerprintDanglingSymlinkOK(t *testing.T) {
	dir := writeTree(t, map[string]string{"main.go": "package main"})
	if err := os.Symlink("./nonexistent-target", filepath.Join(dir, "dangling")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err != nil {
		t.Fatalf("a dangling in-tree symlink must not error: %v", err)
	}
}

// Codex finding 1: when the target ROOT is itself a symlink, the fingerprinter must resolve and walk the
// real directory (WalkDir does not descend a symlinked root), so content behind it is seen. Editing a file
// under the real dir must change the hash even when fingerprinting via the symlink.
func TestTreeFingerprintSymlinkedRootIsWalked(t *testing.T) {
	real := writeTree(t, map[string]string{"main.go": "package main"})
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	before := hashOf(t, link)
	if err := os.WriteFile(filepath.Join(real, "main.go"), []byte("package main // v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if before == hashOf(t, link) {
		t.Fatal("a symlinked target root must be walked: content drift behind it must change the hash")
	}
}

// Codex finding 3: an in-tree symlink whose target lives under an excluded dir (.git, which the walk skips)
// is NOT covered, so its content is never hashed. It must be an error (disable cache), not a link-string hash.
func TestTreeFingerprintSymlinkIntoExcludedDirErrors(t *testing.T) {
	dir := writeTree(t, map[string]string{"main.go": "package main"})
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "generated.go"), []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, ".git", "generated.go"), filepath.Join(dir, "vuln.go")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("a symlink into an excluded (unhashed) dir must error, never hash only the link string")
	}
}

// Codex finding 2: a Go module with a local replace pointing OUTSIDE the tree makes the build read source the
// fingerprint cannot see, so caching must be disabled (error).
func TestTreeFingerprintExternalGoReplaceErrors(t *testing.T) {
	outside := t.TempDir() // a sibling dir, resolved outside the target tree
	dir := writeTree(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.26\n\nrequire example.com/lib v0.0.0\n\nreplace example.com/lib => " + filepath.ToSlash(outside) + "\n",
		"main.go": "package main",
	})
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("an out-of-tree local replace must disable the cache (error)")
	}
}

// An INTERNAL replace (target inside the tree) is fine: its content is already hashed by the walk.
func TestTreeFingerprintInternalGoReplaceOK(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":              "module example.com/app\n\ngo 1.26\n\nrequire example.com/lib v0.0.0\n\nreplace example.com/lib => ./internal/lib\n",
		"main.go":             "package main",
		"internal/lib/lib.go": "package lib",
	})
	if err := os.MkdirAll(filepath.Join(dir, "internal", "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err != nil {
		t.Fatalf("an in-tree replace must not error: %v", err)
	}
}

// Codex re-review finding 1: a local replace pointing INTO an excluded dir (.git) is not covered by the walk
// (that dir is skipped), so it must disable the cache even though the target is under realRoot.
func TestTreeFingerprintReplaceIntoExcludedDirErrors(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./.git/dep\n",
		"main.go": "package main",
	})
	if err := os.MkdirAll(filepath.Join(dir, ".git", "dep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "dep", "dep.go"), []byte("package dep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("a replace into an excluded (unhashed) dir must disable the cache (error)")
	}
}

// Codex 3rd pass finding 1: a replace whose LITERAL path traverses an excluded dir (.git) must error even
// when it resolves (through a symlink) to an in-tree file, because the .git entry that redirects it is not
// hashed.
func TestTreeFingerprintReplaceThroughExcludedSymlinkErrors(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":        "module example.com/app\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./.git/dep\n",
		"main.go":       "package main",
		"dep-v1/dep.go": "package dep",
	})
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "dep-v1"), filepath.Join(dir, ".git", "dep")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("a replace whose literal path traverses .git must disable the cache (error)")
	}
}

// Codex 3rd pass finding 2: a SYMLINKED go.mod that resolves to an in-tree regular manifest must still be
// parsed for external replaces (skipping it would miss the external reference).
func TestTreeFingerprintSymlinkedManifestParsed(t *testing.T) {
	outside := t.TempDir()
	dir := writeTree(t, map[string]string{
		"manifests/app.mod": "module example.com/app\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => " + filepath.ToSlash(outside) + "\n",
		"main.go":           "package main",
	})
	if err := os.Symlink(filepath.Join(dir, "manifests", "app.mod"), filepath.Join(dir, "go.mod")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("a symlinked in-tree go.mod with an external replace must be parsed and disable the cache")
	}
}

// Codex 3rd pass finding 3: a double-dash GOFLAGS -overlay must be caught (Go treats -x and --x alike).
func TestTreeFingerprintGOFLAGSDoubleDashOverlayErrors(t *testing.T) {
	t.Setenv("GOFLAGS", "--overlay=/tmp/overlay.json")
	dir := writeTree(t, map[string]string{"main.go": "package main"})
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("a double-dash GOFLAGS --overlay must disable the cache (error)")
	}
}

// Codex 3rd pass finding 4: GO111MODULE=off (GOPATH mode) resolves source outside the tree; disable the cache.
func TestTreeFingerprintGO111ModuleOffErrors(t *testing.T) {
	t.Setenv("GO111MODULE", "off")
	dir := writeTree(t, map[string]string{"main.go": "package main"})
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("GO111MODULE=off must disable the cache (error)")
	}
}

// Codex 3rd pass finding 5: a go.work in an ANCESTOR of the tree would be auto-discovered by Go; disable it.
func TestTreeFingerprintAncestorGoWorkErrors(t *testing.T) {
	t.Setenv("GOWORK", "") // auto
	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, "go.work"), []byte("go 1.26\n\nuse ./app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "app")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), target); err == nil {
		t.Fatal("an ancestor go.work (auto-discovered) must disable the cache (error)")
	}
}

// Codex re-review finding 3: a go.mod that is a FIFO must not be opened by the external-source parse (it would
// block); it is not collected as a manifest, so fingerprinting completes.
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

// Codex re-review finding 2: an ambient GOWORK pointing outside the tree must disable the cache.
func TestTreeFingerprintExternalGOWORKErrors(t *testing.T) {
	outside := t.TempDir()
	work := filepath.Join(outside, "go.work")
	if err := os.WriteFile(work, []byte("go 1.26\n\nuse .\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", work)
	dir := writeTree(t, map[string]string{"main.go": "package main"})
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("an external GOWORK must disable the cache (error)")
	}
}

// Codex 4th pass finding: an explicit in-tree GOWORK file (not named go.work) with a `use` pointing outside
// the tree must be PARSED and disable the cache; checking only the file's own path is insufficient.
func TestTreeFingerprintExplicitGOWORKExternalUseErrors(t *testing.T) {
	outside := t.TempDir()
	dir := writeTree(t, map[string]string{
		"custom.work": "go 1.26\n\nuse (\n\t.\n\t" + filepath.ToSlash(outside) + "\n)\n",
		"go.mod":      "module example.com/app\n\ngo 1.26\n",
		"main.go":     "package main",
	})
	t.Setenv("GOWORK", filepath.Join(dir, "custom.work"))
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("an explicit in-tree GOWORK with an external use must be parsed and disable the cache")
	}
}

// An explicit GOWORK path OUTSIDE the tree must be rejected even if it resolves (via symlink) to an in-tree file.
func TestTreeFingerprintExplicitGOWORKOutOfTreePathErrors(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"real.work": "go 1.26\n\nuse .\n",
		"go.mod":    "module example.com/app\n\ngo 1.26\n",
		"main.go":   "package main",
	})
	outside := filepath.Join(t.TempDir(), "ws")
	if err := os.Symlink(filepath.Join(dir, "real.work"), outside); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	t.Setenv("GOWORK", outside) // literal path is out-of-tree even though it resolves in-tree
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("an out-of-tree GOWORK path must be rejected even if it resolves in-tree")
	}
}

// A GOFLAGS -overlay remaps source and must disable the cache.
func TestTreeFingerprintGOFLAGSOverlayErrors(t *testing.T) {
	t.Setenv("GOFLAGS", "-overlay=/tmp/overlay.json")
	dir := writeTree(t, map[string]string{"main.go": "package main"})
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("a GOFLAGS -overlay must disable the cache (error)")
	}
}

// GOWORK=off (the sandboxed/deterministic case) does not disable the cache.
func TestTreeFingerprintGOWORKOffOK(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := writeTree(t, map[string]string{"main.go": "package main"})
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err != nil {
		t.Fatalf("GOWORK=off must not disable the cache: %v", err)
	}
}

// Codex finding 2 (workspace): a go.work using a module outside the tree must disable the cache.
func TestTreeFingerprintExternalGoWorkErrors(t *testing.T) {
	outside := t.TempDir()
	dir := writeTree(t, map[string]string{
		"go.work": "go 1.26\n\nuse (\n\t.\n\t" + filepath.ToSlash(outside) + "\n)\n",
		"go.mod":  "module example.com/app\n\ngo 1.26\n",
		"main.go": "package main",
	})
	if _, _, err := NewTreeFingerprinter().FingerprintSource(context.Background(), dir); err == nil {
		t.Fatal("a go.work use of an out-of-tree module must disable the cache (error)")
	}
}

// A non-regular file (FIFO) must never be opened (opening a FIFO with no writer blocks forever); it is
// fingerprinted by identity only, so FingerprintSource completes and is stable.
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
