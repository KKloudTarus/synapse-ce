package main

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
)

func TestPublishSourceFromAnalysisStreamsOnlyRetainableInventory(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("src/main.go", "package main\n")
	write(".env", "fixture-blocked-by-path\n")
	write("keys/private.pem", "fixture-blocked-by-path\n")
	write("ignored.txt", "scanner did not inventory this\n")

	analysis := projectanalysis.Analysis{
		ID: "analysis", ProjectKey: "project",
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindLocal, Head: "workspace"},
		Snapshot: measure.Snapshot{Nodes: []measure.Node{
			{Path: "", Kind: measure.NodeProject},
			{Path: "src/main.go", Kind: measure.NodeFile},
			// Deliberately model scanner inventory drift: credential denylist still wins.
			{Path: ".env", Kind: measure.NodeFile},
			{Path: "keys/private.pem", Kind: measure.NodeFile},
		}},
	}
	var (
		mu       sync.Mutex
		uploaded []string
		bodies   = map[string]string{}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("authorization=%q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/project/analyses/analysis":
			_ = json.NewEncoder(w).Encode(analysis)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/project/analyses/analysis/source":
			if r.Header.Get("Content-Type") != "application/x-tar" || r.Header.Get("X-Synapse-Tool-Version") != "test-version" {
				t.Errorf("publish headers content-type=%q version=%q", r.Header.Get("Content-Type"), r.Header.Get("X-Synapse-Tool-Version"))
			}
			tr := tar.NewReader(r.Body)
			for {
				hdr, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Errorf("tar: %v", err)
					return
				}
				data, err := io.ReadAll(tr)
				if err != nil {
					t.Errorf("read tar file: %v", err)
					return
				}
				mu.Lock()
				uploaded = append(uploaded, hdr.Name)
				bodies[hdr.Name] = string(data)
				mu.Unlock()
			}
			writer := projectanalysis.SourceWriter{Actor: "ci-user", ToolVersion: "test-version", PublishedAt: time.Unix(1_700_000_000, 0).UTC()}
			manifest := projectanalysis.SourceManifest{Writer: &writer, Files: []projectanalysis.SourceFile{{Path: "src/main.go", Digest: "fixture", Bytes: 13, Lines: 1, Available: true}}}
			manifest.SetArtifactDigest()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(manifest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	manifest, err := publishSourceFromAnalysis(context.Background(), server.Client(), server.URL, "token", "project", "analysis", root, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Writer == nil || manifest.Writer.Actor != "ci-user" {
		t.Fatalf("manifest=%+v", manifest)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(uploaded, []string{"src/main.go"}) {
		t.Fatalf("uploaded=%v, want only scanner-inventoried non-secret source", uploaded)
	}
	if bodies["src/main.go"] != "package main\n" {
		t.Fatalf("main.go body=%q", bodies["src/main.go"])
	}
	for _, forbidden := range []string{".env", "keys/private.pem", "ignored.txt"} {
		if _, ok := bodies[forbidden]; ok {
			t.Fatalf("forbidden file %q crossed the publish transport", forbidden)
		}
	}
}

func TestPublishSourceFromAnalysisPropagatesServerRefusal(t *testing.T) {
	analysis := projectanalysis.Analysis{
		ID: "analysis", ProjectKey: "project",
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindLocal, Head: "workspace"},
		Snapshot:       measure.Snapshot{Nodes: []measure.Node{{Path: "main.go", Kind: measure.NodeFile}}},
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(analysis)
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":"source snapshot already retained"}`)
	}))
	defer server.Close()

	_, err := publishSourceFromAnalysis(context.Background(), server.Client(), server.URL, "token", "project", "analysis", root, "test")
	if err == nil || !strings.Contains(err.Error(), "409") || !strings.Contains(err.Error(), "already retained") {
		t.Fatalf("error=%v", err)
	}
}

func TestPublishSourceFromAnalysisRejectsNonDirectoryBeforeNetwork(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app.jar")
	if err := os.WriteFile(root, []byte("jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	_, err := publishSourceFromAnalysis(context.Background(), server.Client(), server.URL, "token", "project", "analysis", root, "test")
	if err == nil || !strings.Contains(err.Error(), "source directory") {
		t.Fatalf("error=%v", err)
	}
	if calls != 0 {
		t.Fatalf("network calls=%d, want 0", calls)
	}
}
