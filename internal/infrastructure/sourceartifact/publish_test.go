package sourceartifact

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func publishTar(t *testing.T, entries []tarEntry) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		data := []byte(entry.body)
		hdr := &tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(data)), Typeflag: typeflag, Linkname: entry.linkname}
		if typeflag != tar.TypeReg {
			hdr.Size = 0
			data = nil
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(data) > 0 {
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

type tarEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

func testWriter() projectanalysis.SourceWriter {
	return projectanalysis.SourceWriter{Actor: "ci-bot", ToolVersion: "synapse-cli/test", PublishedAt: time.Unix(1_700_000_000, 0).UTC()}
}

func TestPublishArchiveIsCreateOnlyAndSealsWriterProvenance(t *testing.T) {
	ctx := context.Background()
	store := New(t.TempDir(), 0, 0, 0)
	first, err := store.PublishArchive(ctx, "tenant", "project", "analysis", testWriter(), []string{"main.go"}, publishTar(t, []tarEntry{{name: "main.go", body: "first\n"}}))
	if err != nil {
		t.Fatal(err)
	}
	if first.Manifest.Writer == nil || first.Manifest.Digest == "" || first.Manifest.Digest != first.Manifest.ArtifactDigest() {
		t.Fatalf("manifest=%+v", first.Manifest)
	}
	tampered := first.Manifest
	writer := *tampered.Writer
	writer.Actor = "mallory"
	tampered.Writer = &writer
	if tampered.ArtifactDigest() == first.Manifest.Digest {
		t.Fatal("writer provenance is not covered by the manifest digest")
	}

	second, err := store.PublishArchive(ctx, "tenant", "project", "analysis", testWriter(), []string{"main.go"}, publishTar(t, []tarEntry{{name: "main.go", body: "replacement\n"}}))
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second publish error=%v, want conflict", err)
	}
	if second.Capabilities.Source.Reason != projectanalysis.UnavailableAlreadyRetained {
		t.Fatalf("second publish reason=%q, want %q", second.Capabilities.Source.Reason, projectanalysis.UnavailableAlreadyRetained)
	}
	data, _, err := store.Load(ctx, "tenant", "project", "analysis", "main.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first\n" {
		t.Fatalf("existing artifact was clobbered: %q", data)
	}
}

func TestPublishArchiveConcurrentPublishersHaveExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	store := New(t.TempDir(), 0, 0, 0)
	const contenders = 8
	type result struct {
		body string
		err  error
	}
	archives := make([]*bytes.Reader, contenders)
	bodies := make([]string, contenders)
	for i := range contenders {
		bodies[i] = fmt.Sprintf("winner-%d\n", i)
		archives[i] = publishTar(t, []tarEntry{{name: "main.go", body: bodies[i]}})
	}
	start := make(chan struct{})
	results := make(chan result, contenders)
	for i := range contenders {
		go func(i int) {
			<-start
			_, err := store.PublishArchive(ctx, "tenant", "project", "concurrent-analysis", testWriter(), []string{"main.go"}, archives[i])
			results <- result{body: bodies[i], err: err}
		}(i)
	}
	close(start)

	winner := ""
	conflicts := 0
	for range contenders {
		got := <-results
		switch {
		case got.err == nil:
			if winner != "" {
				t.Fatalf("more than one publisher succeeded: %q and %q", winner, got.body)
			}
			winner = got.body
		case errors.Is(got.err, shared.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent publish error: %v", got.err)
		}
	}
	if winner == "" || conflicts != contenders-1 {
		t.Fatalf("winner=%q conflicts=%d, want one winner and %d conflicts", winner, conflicts, contenders-1)
	}
	data, _, err := store.Load(ctx, "tenant", "project", "concurrent-analysis", "main.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != winner {
		t.Fatalf("retained bytes=%q, winning publisher sent %q", data, winner)
	}
}

func TestPublishArchiveRejectsUnsafeTransportAndRollsBackClaim(t *testing.T) {
	ctx := context.Background()
	store := New(t.TempDir(), 0, 0, 0)
	for _, tc := range []struct {
		name    string
		entries []tarEntry
	}{
		{name: "traversal", entries: []tarEntry{{name: "../main.go", body: "bad"}}},
		{name: "symlink", entries: []tarEntry{{name: "main.go", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}}},
		{name: "duplicate", entries: []tarEntry{{name: "main.go", body: "one"}, {name: "main.go", body: "two"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			analysisID := "bad-" + tc.name
			if _, err := store.PublishArchive(ctx, "tenant", "project", analysisID, testWriter(), []string{"main.go"}, publishTar(t, tc.entries)); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("error=%v, want validation", err)
			}
			// A rejected archive must release its filesystem claim; otherwise a corrected retry
			// would be permanently blocked by a half-published directory.
			if _, err := store.PublishArchive(ctx, "tenant", "project", analysisID, testWriter(), []string{"main.go"}, publishTar(t, []tarEntry{{name: "main.go", body: "fixed\n"}})); err != nil {
				t.Fatalf("corrected retry failed after rejected archive: %v", err)
			}
		})
	}
}

func TestPublishArchiveRequiresAbsoluteOperatorOwnedRoot(t *testing.T) {
	store := New("relative/artifacts", 0, 0, 0)
	_, err := store.PublishArchive(context.Background(), "tenant", "project", "analysis", testWriter(), []string{"main.go"}, publishTar(t, []tarEntry{{name: "main.go", body: "package main\n"}}))
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("error=%v, want validation", err)
	}
}
