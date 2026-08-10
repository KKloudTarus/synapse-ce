package main

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo"
)

func runPublishSource(args []string) error {
	fs := flag.NewFlagSet("publish-source", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	server := fs.String("server", strings.TrimSpace(os.Getenv("SYNAPSE_API_URL")), "Synapse API base URL")
	projectKey := fs.String("project", "", "server-owned project key")
	analysisID := fs.String("analysis", "", "server-owned analysis id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("publish-source accepts at most one source directory")
	}
	root := "."
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	}
	token := strings.TrimSpace(os.Getenv("SYNAPSE_API_TOKEN"))
	if strings.TrimSpace(*server) == "" || strings.TrimSpace(*projectKey) == "" || strings.TrimSpace(*analysisID) == "" || token == "" {
		return fmt.Errorf("publish-source requires --server, --project, --analysis and SYNAPSE_API_TOKEN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	manifest, err := publishSourceFromAnalysis(ctx, http.DefaultClient, *server, token, *projectKey, *analysisID, root, buildinfo.App())
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(manifest)
}

func publishSourceFromAnalysis(ctx context.Context, client *http.Client, server, token, projectKey, analysisID, root, toolVersion string) (projectanalysis.SourceManifest, error) {
	if client == nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("http client is required")
	}
	client = sourcePublishNoRedirectClient(client)
	base, err := sourcePublishBaseURL(server)
	if err != nil {
		return projectanalysis.SourceManifest{}, err
	}
	if strings.TrimSpace(token) == "" || strings.TrimSpace(projectKey) == "" || strings.TrimSpace(analysisID) == "" || strings.TrimSpace(toolVersion) == "" {
		return projectanalysis.SourceManifest{}, fmt.Errorf("source publication identity is incomplete")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("resolve source directory: %w", err)
	}
	info, err := os.Lstat(absRoot)
	if err != nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("inspect source directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return projectanalysis.SourceManifest{}, fmt.Errorf("publish-source target must be a source directory")
	}

	analysisURL := sourcePublishURL(base, projectKey, analysisID, false)
	analysis, err := fetchPublishAnalysis(ctx, client, analysisURL, token)
	if err != nil {
		return projectanalysis.SourceManifest{}, err
	}
	if analysis.ID != analysisID || analysis.ProjectKey != projectKey || !analysis.SourceRevision.Kind.Valid() {
		return projectanalysis.SourceManifest{}, fmt.Errorf("server returned an incompatible source analysis")
	}
	paths := retainableAnalysisPaths(analysis)
	if len(paths) == 0 {
		return projectanalysis.SourceManifest{}, fmt.Errorf("analysis has no retainable source files")
	}

	pr, pw := io.Pipe()
	writeErr := make(chan error, 1)
	go func() {
		err := writeAnalysisSourceTar(absRoot, paths, pw)
		_ = pw.CloseWithError(err)
		writeErr <- err
	}()

	publishURL := sourcePublishURL(base, projectKey, analysisID, true)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, publishURL, pr)
	if err != nil {
		_ = pr.CloseWithError(err)
		<-writeErr
		return projectanalysis.SourceManifest{}, fmt.Errorf("build source publish request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-tar")
	req.Header.Set("X-Synapse-Tool-Version", toolVersion)
	resp, err := client.Do(req)
	if err != nil {
		_ = pr.CloseWithError(err)
		<-writeErr
		return projectanalysis.SourceManifest{}, fmt.Errorf("publish source: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_ = pr.Close()
	streamErr := <-writeErr
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return projectanalysis.SourceManifest{}, sourcePublishHTTPError(resp)
	}
	if streamErr != nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("stream source archive: %w", streamErr)
	}
	var manifest projectanalysis.SourceManifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&manifest); err != nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("decode source publish response: %w", err)
	}
	if manifest.Digest == "" || manifest.Digest != manifest.ArtifactDigest() || manifest.Writer == nil {
		return projectanalysis.SourceManifest{}, fmt.Errorf("server returned an invalid source manifest")
	}
	return manifest, nil
}

func sourcePublishNoRedirectClient(client *http.Client) *http.Client {
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}

func sourcePublishBaseURL(raw string) (*url.URL, error) {
	base, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") || base.User != nil {
		return nil, fmt.Errorf("invalid Synapse API URL")
	}
	base.RawQuery, base.Fragment = "", ""
	return base, nil
}

func sourcePublishURL(base *url.URL, projectKey, analysisID string, source bool) string {
	u := base.JoinPath("api", "v1", "projects", projectKey, "analyses", analysisID)
	if source {
		u = u.JoinPath("source")
	}
	return u.String()
}

func fetchPublishAnalysis(ctx context.Context, client *http.Client, endpoint, token string) (projectanalysis.Analysis, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return projectanalysis.Analysis{}, fmt.Errorf("build analysis request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return projectanalysis.Analysis{}, fmt.Errorf("fetch analysis: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return projectanalysis.Analysis{}, sourcePublishHTTPError(resp)
	}
	var analysis projectanalysis.Analysis
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&analysis); err != nil {
		return projectanalysis.Analysis{}, fmt.Errorf("decode analysis: %w", err)
	}
	return analysis, nil
}

func sourcePublishHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil && strings.TrimSpace(payload.Error) != "" {
		return fmt.Errorf("synapse API returned %s: %s", resp.Status, strings.TrimSpace(payload.Error))
	}
	return fmt.Errorf("synapse API returned %s", resp.Status)
}

func retainableAnalysisPaths(analysis projectanalysis.Analysis) []string {
	seen := make(map[string]struct{})
	paths := make([]string, 0, len(analysis.Snapshot.Nodes))
	for _, node := range analysis.Snapshot.Nodes {
		if node.Kind != measure.NodeFile || !sourcepolicy.RetainPath(node.Path) {
			continue
		}
		if _, ok := seen[node.Path]; ok {
			continue
		}
		seen[node.Path] = struct{}{}
		paths = append(paths, node.Path)
	}
	sort.Strings(paths)
	return paths
}

func writeAnalysisSourceTar(absRoot string, paths []string, dst io.Writer) error {
	root, err := os.OpenRoot(absRoot)
	if err != nil {
		return fmt.Errorf("open source directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	tw := tar.NewWriter(dst)
	for _, canonical := range paths {
		if !sourcepolicy.RetainPath(canonical) {
			continue
		}
		name := filepath.FromSlash(canonical)
		before, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			_ = tw.Close()
			return fmt.Errorf("inspect source file %q: %w", canonical, err)
		}
		if !before.Mode().IsRegular() {
			continue
		}
		file, err := root.Open(name)
		if err != nil {
			_ = tw.Close()
			return fmt.Errorf("open source file %q: %w", canonical, err)
		}
		after, err := file.Stat()
		if err != nil {
			_ = file.Close()
			_ = tw.Close()
			return fmt.Errorf("stat source file %q: %w", canonical, err)
		}
		if !after.Mode().IsRegular() || !os.SameFile(before, after) {
			_ = file.Close()
			_ = tw.Close()
			return fmt.Errorf("source file %q changed type while publishing", canonical)
		}
		hdr := &tar.Header{Name: canonical, Mode: 0o600, Size: after.Size(), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = file.Close()
			_ = tw.Close()
			return fmt.Errorf("write source archive header: %w", err)
		}
		if _, err := io.CopyN(tw, file, after.Size()); err != nil {
			_ = file.Close()
			_ = tw.Close()
			return fmt.Errorf("stream source file %q: %w", canonical, err)
		}
		if err := file.Close(); err != nil {
			_ = tw.Close()
			return fmt.Errorf("close source file %q: %w", canonical, err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close source archive: %w", err)
	}
	return nil
}
