package gitdiff

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
)

func TestParseRawChangesAndHunks(t *testing.T) {
	raw := []byte(":100644 100644 aaaaaaa bbbbbbb M\x00a file.go\x00")
	changes, err := parseRawChanges(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Status != projectanalysis.FileStatusModified || changes[0].OldPath != "a file.go" {
		t.Fatalf("changes=%+v", changes)
	}

	hunks, err := parseHunks([]byte("@@ -1,2 +1,2 @@\n one\n-old\n+new\n\\ No newline at end of file\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(hunks) != 1 || len(hunks[0].Rows) != 3 {
		t.Fatalf("hunks=%+v", hunks)
	}
	if got := hunks[0].Rows[2]; got.Kind != projectanalysis.DiffRowAdded || got.NewLine != 2 || !got.NoFinalNewline {
		t.Fatalf("added row=%+v", got)
	}
	added, removed, modified := changedRanges(hunks)
	if len(added) != 1 || added[0] != (projectanalysis.LineRange{Start: 2, End: 2}) ||
		len(removed) != 1 || removed[0] != (projectanalysis.LineRange{Start: 2, End: 2}) ||
		len(modified) != 1 || modified[0] != added[0] {
		t.Fatalf("ranges added=%+v removed=%+v modified=%+v", added, removed, modified)
	}
}

func TestFileChangesPreservesRenameHunks(t *testing.T) {
	dir := t.TempDir()
	gitFileChanges(t, dir, "init", "-b", "main")
	gitFileChanges(t, dir, "config", "user.email", "test@example.com")
	gitFileChanges(t, dir, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(dir, "old.go"), []byte("one\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitFileChanges(t, dir, "add", "old.go")
	gitFileChanges(t, dir, "commit", "-m", "base")
	base := strings.TrimSpace(gitFileChanges(t, dir, "rev-parse", "HEAD"))
	gitFileChanges(t, dir, "mv", "old.go", "new.go")
	if err := os.WriteFile(filepath.Join(dir, "new.go"), []byte("one\nupdated\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitFileChanges(t, dir, "add", "new.go")
	gitFileChanges(t, dir, "commit", "-m", "rename")
	head := strings.TrimSpace(gitFileChanges(t, dir, "rev-parse", "HEAD"))

	changes, err := FileChanges(context.Background(), dir, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Status != projectanalysis.FileStatusRenamed || changes[0].OldPath != "old.go" || changes[0].NewPath != "new.go" {
		t.Fatalf("changes=%+v", changes)
	}
	if len(changes[0].Hunks) != 1 || len(changes[0].Hunks[0].Rows) != 4 {
		t.Fatalf("hunks=%+v", changes[0].Hunks)
	}
	if got := changes[0].Hunks[0].Rows[1]; got.Kind != projectanalysis.DiffRowRemoved || got.OldLine != 2 {
		t.Fatalf("removed row=%+v", got)
	}
	if got := changes[0].Hunks[0].Rows[2]; got.Kind != projectanalysis.DiffRowAdded || got.NewLine != 2 {
		t.Fatalf("added row=%+v", got)
	}
}

func TestFileChangesKeepsCopyAndSourceHunksSeparate(t *testing.T) {
	dir := t.TempDir()
	gitFileChanges(t, dir, "init", "-b", "main")
	gitFileChanges(t, dir, "config", "user.email", "test@example.com")
	gitFileChanges(t, dir, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(dir, "source.go"), []byte("one\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitFileChanges(t, dir, "add", "source.go")
	gitFileChanges(t, dir, "commit", "-m", "base")
	base := strings.TrimSpace(gitFileChanges(t, dir, "rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(dir, "copy.go"), []byte("one\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "source.go"), []byte("one\nupdated\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitFileChanges(t, dir, "add", "source.go", "copy.go")
	gitFileChanges(t, dir, "commit", "-m", "copy and edit source")
	head := strings.TrimSpace(gitFileChanges(t, dir, "rev-parse", "HEAD"))

	changes, err := FileChanges(context.Background(), dir, base, head)
	if err != nil {
		t.Fatal(err)
	}
	var copyChange, sourceChange *projectanalysis.FileChange
	for i := range changes {
		switch changes[i].Status {
		case projectanalysis.FileStatusCopied:
			copyChange = &changes[i]
		case projectanalysis.FileStatusModified:
			sourceChange = &changes[i]
		}
	}
	if copyChange == nil || sourceChange == nil {
		t.Fatalf("changes=%+v", changes)
	}
	if len(copyChange.Hunks) != 0 || len(copyChange.Added) != 0 {
		t.Fatalf("copy must not own source edit hunks: %+v", copyChange)
	}
	if len(sourceChange.Hunks) != 1 || len(sourceChange.Added) != 1 || sourceChange.Added[0] != (projectanalysis.LineRange{Start: 2, End: 2}) {
		t.Fatalf("source=%+v", sourceChange)
	}
}

func gitFileChanges(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func TestParseRawRename(t *testing.T) {
	raw := []byte(":100644 100644 aaaaaaa bbbbbbb R100\x00old.go\x00new.go\x00")
	changes, err := parseRawChanges(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Status != projectanalysis.FileStatusRenamed || changes[0].OldPath != "old.go" || changes[0].NewPath != "new.go" {
		t.Fatalf("changes=%+v", changes)
	}
}
