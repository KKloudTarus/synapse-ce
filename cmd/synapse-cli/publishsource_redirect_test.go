package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
)

func TestPublishSourceFromAnalysisRefusesRedirects(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	analysis := projectanalysis.Analysis{
		ID: "analysis", ProjectKey: "project",
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindLocal, Head: "workspace"},
		Snapshot:       measure.Snapshot{Nodes: []measure.Node{{Path: "main.go", Kind: measure.NodeFile}}},
	}
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Errorf("bearer credential reached redirect target")
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(analysis)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		writer := projectanalysis.SourceWriter{Actor: "redirect-target", ToolVersion: "test", PublishedAt: time.Unix(1_700_000_000, 0).UTC()}
		manifest := projectanalysis.SourceManifest{Writer: &writer, Files: []projectanalysis.SourceFile{{Path: "main.go", Digest: "fixture", Bytes: 13, Lines: 1, Available: true}}}
		manifest.SetArtifactDigest()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(manifest)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	_, err := publishSourceFromAnalysis(context.Background(), redirector.Client(), redirector.URL, "token", "project", "analysis", root, "test")
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect error=%v, want explicit 307 refusal", err)
	}
	if got := redirected.Load(); got != 0 {
		t.Fatalf("redirect target received %d request(s), want 0", got)
	}
}
