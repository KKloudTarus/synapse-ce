package sourceartifact

import (
	"context"
	"testing"
)

// TestPublishArchiveStoresOnlyInventoryListedFiles pins the sharpest property of the publish endpoint:
// the server decides WHICH files it will accept, from the persisted scanner-owned inventory, and a
// client cannot introduce a file the scanner never saw. "evil.go" below is canonical, a regular file,
// and passes sourcepolicy.RetainPath -- it fails only because it is not in the allowlist. Nothing
// asserted that: dropping the allowlist term left this behaviour untested.
func TestPublishArchiveStoresOnlyInventoryListedFiles(t *testing.T) {
	store := New(t.TempDir(), 0, 0, 0)
	result, err := store.PublishArchive(context.Background(), "tenant", "project", "analysis", testWriter(),
		[]string{"main.go"},
		publishTar(t, []tarEntry{
			{name: "main.go", body: "listed\n"},
			{name: "evil.go", body: "never inventoried\n"},
		}))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	for _, file := range result.Manifest.Files {
		if file.Path == "evil.go" {
			t.Fatalf("a path absent from the scanner inventory was stored: %+v", result.Manifest.Files)
		}
	}
	if len(result.Manifest.Files) != 1 || result.Manifest.Files[0].Path != "main.go" {
		t.Fatalf("manifest must contain exactly the inventoried file, got %+v", result.Manifest.Files)
	}
}
