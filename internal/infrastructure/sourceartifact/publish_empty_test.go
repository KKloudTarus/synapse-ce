package sourceartifact

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestPublishArchiveRejectsZeroRetainedFilesAndReleasesClaim(t *testing.T) {
	ctx := context.Background()
	store := New(t.TempDir(), 0, 0, 0)
	analysisID := "empty-retained"
	_, err := store.PublishArchive(ctx, "tenant", "project", analysisID, testWriter(), []string{"main.go"}, publishTar(t, []tarEntry{{name: "outside.txt", body: "not in analysis\n"}}))
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero-retained publish error=%v, want validation", err)
	}
	// A false-success attempt must not reserve the immutable namespace.
	if _, err := store.PublishArchive(ctx, "tenant", "project", analysisID, testWriter(), []string{"main.go"}, publishTar(t, []tarEntry{{name: "main.go", body: "package main\n"}})); err != nil {
		t.Fatalf("corrected retry failed after zero-retained archive: %v", err)
	}
}
