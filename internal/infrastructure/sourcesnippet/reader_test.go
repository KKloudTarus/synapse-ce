package sourcesnippet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSnippetContextHashesCompleteSource(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "app.go")
	first := "package app\n\nfunc target() {}\n\nconst outside = 1\n"
	if err := os.WriteFile(path, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	reader := Reader{Root: root}
	snippet1, hash1, err := reader.SnippetContext(context.Background(), "app.go", 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	second := "package app\n\nfunc target() {}\n\nconst outside = 2\n"
	if err := os.WriteFile(path, []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	snippet2, hash2, err := reader.SnippetContext(context.Background(), "app.go", 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snippet1 != snippet2 {
		t.Fatalf("test requires an unchanged model window: %q != %q", snippet1, snippet2)
	}
	if hash1 == hash2 {
		t.Fatal("a change outside the snippet must invalidate the complete-source hash")
	}
}

func TestOversizedSourceRemainsAvailableUncached(t *testing.T) {
	root := t.TempDir()
	data := make([]byte, maxSnippetFileBytes+1)
	copy(data, "target_line\n")
	if err := os.WriteFile(filepath.Join(root, "large.go"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	reader := Reader{Root: root}
	if snippet, err := reader.Snippet(context.Background(), "large.go", 1, 0); err != nil || snippet != "1: target_line\n" {
		t.Fatalf("ordinary best-effort snippet changed: snippet=%q err=%v", snippet, err)
	}
	if _, _, err := reader.SnippetContext(context.Background(), "large.go", 1, 0); err == nil {
		t.Fatal("an incomplete whole-file hash must disable caching")
	}
}
