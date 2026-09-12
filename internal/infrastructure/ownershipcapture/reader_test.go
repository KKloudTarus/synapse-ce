package ownershipcapture

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/toolrunner"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func writeCaptureFile(t *testing.T, dir, path, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestOwnershipCapturePrecedenceAndBounds(t *testing.T) {
	dir := t.TempDir()
	writeCaptureFile(t, dir, "docs/CODEOWNERS", "* @docs")
	writeCaptureFile(t, dir, "CODEOWNERS", "* @root")
	writeCaptureFile(t, dir, ".github/CODEOWNERS", "")
	file, err := readWorkspace(context.Background(), dir)
	if err != nil || file.Path != ".github/CODEOWNERS" || file.Content != "" {
		t.Fatalf("empty preferred file must win: %+v %v", file, err)
	}
	writeCaptureFile(t, dir, ".github/CODEOWNERS", strings.Repeat("x", maxContent+1))
	if _, err := readWorkspace(context.Background(), dir); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversize capture: %v", err)
	}
	writeCaptureFile(t, dir, ".github/CODEOWNERS", "* @team\x00")
	if _, err := readWorkspace(context.Background(), dir); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("NUL capture: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readWorkspace(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled capture: %v", err)
	}
}

func TestOwnershipCapturePinsGitHeadAndBase(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git required")
	}
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
		data, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %s %v", args, data, err)
		}
		return strings.TrimSpace(string(data))
	}
	git("init", "--quiet")
	git("config", "user.name", "Ownership test")
	git("config", "user.email", "ownership@example.invalid")
	writeCaptureFile(t, dir, "CODEOWNERS", "* @base-team\n")
	git("add", "--", "CODEOWNERS")
	git("commit", "--quiet", "-m", "base")
	base := git("rev-parse", "HEAD")
	writeCaptureFile(t, dir, ".github/CODEOWNERS", "* @head-team\n")
	git("add", "--", ".github/CODEOWNERS")
	git("commit", "--quiet", "-m", "head")
	head := git("rev-parse", "HEAD")
	// A later workspace edit must not masquerade as bytes from the pinned commit.
	writeCaptureFile(t, dir, ".github/CODEOWNERS", "* @workspace-edit\n")
	reader := New(toolrunner.NewExecRunner(15*time.Second, maxContent+1))
	ws := &ports.Workspace{Dir: dir, Commit: head, BaseCommit: base}
	capture, err := reader.ReadOwnershipSource(context.Background(), ports.AcquireRequest{Kind: ports.TargetGit, Value: "https://example.invalid/repo.git", BaseCommit: base}, ws)
	if err != nil || len(capture.Files) != 2 {
		t.Fatalf("capture: %+v %v", capture, err)
	}
	if capture.Revision != "git:"+head || capture.BaseRevision != "git:"+base || capture.Files[0].Content != "* @head-team\n" || capture.Files[1].Content != "* @base-team\n" || !capture.Files[1].Base {
		t.Fatalf("head/base evidence mixed: %+v", capture)
	}
	ws.BaseCommit = ""
	missing, err := reader.ReadOwnershipSource(context.Background(), ports.AcquireRequest{Kind: ports.TargetGit, BaseRef: "main"}, ws)
	if err != nil || missing.Reason != "missing_base_snapshot" || len(missing.Files) != 1 || missing.Files[0].Base {
		t.Fatalf("head promoted to missing base: %+v %v", missing, err)
	}
	// Captured bytes survive workspace cleanup without another filesystem read.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if capture.Files[1].Content != "* @base-team\n" {
		t.Fatal("capture depended on workspace lifetime")
	}
}

func TestOwnershipApplicationPathIsolation(t *testing.T) {
	dir := t.TempDir()
	reader := New(nil)
	for _, path := range []string{"src/handler.go", "services/payment/package-lock.json", "node_modules/library/package.json", "vendor/library/go.mod", "lib/library.py"} {
		writeCaptureFile(t, dir, path, "fixture")
	}
	for _, path := range []string{"services/payment/package-lock.json", filepath.Join(dir, "services", "payment", "package-lock.json")} {
		got, err := reader.OwnershipPath(dir, path, true)
		if err != nil || got != "services/payment/package-lock.json" {
			t.Fatalf("manifest path %q: %q %v", path, got, err)
		}
	}
	for _, path := range []string{"../package.json", "node_modules/library/package.json", "vendor/library/go.mod", "lib/library.py", "missing/package.json", filepath.Join(t.TempDir(), "package.json")} {
		if _, err := reader.OwnershipPath(dir, path, true); err == nil {
			t.Fatalf("unsafe/nonmanifest path accepted: %q", path)
		}
	}
	if path, err := reader.OwnershipPath(dir, "src/handler.go", false); err != nil || path != "src/handler.go" {
		t.Fatalf("first-party path: %q %v", path, err)
	}
	outside := t.TempDir()
	writeCaptureFile(t, outside, "package.json", "outside")
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Logf("symlink case unavailable on this host: %v", err)
		return
	}
	if _, err := reader.OwnershipPath(dir, "escape/package.json", true); err == nil {
		t.Fatal("symlink outside workspace accepted")
	}
}
