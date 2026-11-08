package httpapi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	nethtml "golang.org/x/net/html"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
)

// TestWorkerScanAcceptance exercises a separately provisioned API and durable worker.
// SYNAPSE_ACCEPTANCE_API_URL, SYNAPSE_ACCEPTANCE_BEARER and
// SYNAPSE_ACCEPTANCE_PHASE=renderers-present|missing-helm are required when opted in with
// SYNAPSE_ACCEPTANCE_WORKER_SCAN=1. Both phases require Python taint, IaC, real Syft,
// and an isolated offline advisory configuration. The missing-helm phase runs
// against a restarted worker without Helm; unrelated unavailable engines stay visible.
// The lab operator must accept its AUP beforehand; this test never accepts legal terms.
func TestWorkerScanAcceptance(t *testing.T) {
	if os.Getenv("SYNAPSE_ACCEPTANCE_WORKER_SCAN") != "1" {
		t.Skip("set SYNAPSE_ACCEPTANCE_WORKER_SCAN=1 for the isolated worker lab")
	}
	base := strings.TrimRight(os.Getenv("SYNAPSE_ACCEPTANCE_API_URL"), "/")
	token := os.Getenv("SYNAPSE_ACCEPTANCE_BEARER")
	phase := os.Getenv("SYNAPSE_ACCEPTANCE_PHASE")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || token == "" || (phase != "renderers-present" && phase != "missing-helm") {
		t.Fatal("worker acceptance requires API URL, bearer, and phase renderers-present or missing-helm")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(method, path, contentType string, body []byte, want int, dst any) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s: status %d, want %d", method, path, resp.StatusCode, want)
		}
		if dst != nil {
			reflect.ValueOf(dst).Elem().SetZero()
			if json.Unmarshal(data, dst) != nil {
				t.Fatalf("%s %s: invalid JSON", method, path)
			}
		}
		return data
	}
	archive := workerAcceptanceArchive(t)
	sum := sha256.Sum256(archive)
	digest := hex.EncodeToString(sum[:])
	var upload bytes.Buffer
	mw := multipart.NewWriter(&upload)
	if err := mw.WriteField("metadata", `{"name":"Scanner acceptance fixture","client":"local acceptance"}`); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("source", "fixture.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(archive); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	var engagement struct {
		ID string `json:"id"`
	}
	request("POST", "/api/v1/engagements", mw.FormDataContentType(), upload.Bytes(), http.StatusCreated, &engagement)
	if engagement.ID == "" {
		t.Fatal("create returned no engagement id")
	}
	root := "/api/v1/engagements/" + url.PathEscape(engagement.ID)
	var source struct {
		VersionID string `json:"version_id"`
		SHA256    string `json:"sha256"`
		Target    string `json:"target"`
	}
	request("GET", root+"/source", "", nil, http.StatusOK, &source)
	if source.VersionID == "" || source.SHA256 != digest || source.Target == "" {
		t.Fatal("uploaded source metadata does not bind the archive and version")
	}
	body, err := json.Marshal(map[string]any{"engagement_id": engagement.ID, "kind": "upload", "target": "", "source_version_id": source.VersionID, "mode": "full", "code_quality": true})
	if err != nil {
		t.Fatal(err)
	}
	// A caller cannot supply an arbitrary target for an uploaded package.
	invalid, err := json.Marshal(map[string]any{"engagement_id": engagement.ID, "kind": "upload", "target": "untrusted", "source_version_id": source.VersionID})
	if err != nil {
		t.Fatal(err)
	}
	request("POST", "/api/v1/sca/scans", "application/json", invalid, http.StatusBadRequest, nil)
	request("PUT", root+"/status", "application/json", []byte(`{"status":"active"}`), http.StatusOK, nil)
	past := []byte(`{"authorized_from":"2000-01-01T00:00:00Z","authorized_to":"2000-01-02T00:00:00Z","timezone":"UTC"}`)
	request("PUT", root+"/authorization-window", "application/json", past, http.StatusOK, nil)
	request("POST", "/api/v1/sca/scans", "application/json", body, http.StatusForbidden, nil)
	now := time.Now().UTC()
	currentWindow, err := json.Marshal(map[string]string{
		"authorized_from": now.Add(-time.Minute).Format(time.RFC3339),
		"authorized_to":   now.Add(time.Hour).Format(time.RFC3339),
		"timezone":        "UTC",
	})
	if err != nil {
		t.Fatal(err)
	}
	request("PUT", root+"/authorization-window", "application/json", currentWindow, http.StatusOK, nil)
	var job struct {
		ID             string                  `json:"id"`
		Status         string                  `json:"status"`
		EngineOutcomes []scanrun.EngineOutcome `json:"engine_outcomes"`
		EngineCoverage scanrun.EngineCoverage  `json:"engine_coverage"`
	}
	request("POST", "/api/v1/sca/scans", "application/json", body, http.StatusAccepted, &job)
	if job.ID == "" {
		t.Fatal("accepted scan returned no job id")
	}
	jobPath := "/api/v1/sca/scans/" + url.PathEscape(job.ID)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		request("GET", jobPath, "", nil, http.StatusOK, &job)
		if job.Status == "succeeded" {
			break
		}
		if job.Status == "failed" {
			t.Fatal("worker reported failed scan")
		}
		if job.Status != "running" {
			t.Fatalf("unexpected job status %q", job.Status)
		}
		select {
		case <-ctx.Done():
			t.Fatal("worker scan exceeded acceptance deadline")
		case <-ticker.C:
		}
	}
	var result struct {
		EngineOutcomes []scanrun.EngineOutcome `json:"engine_outcomes"`
		EngineCoverage scanrun.EngineCoverage  `json:"engine_coverage"`
		SBOM           struct {
			Source           string
			GeneratorVersion string
			Components       []struct {
				Name    string
				Version string
			}
		} `json:"sbom"`
		Findings []struct{ RuleKey string } `json:"findings"`
	}
	request("GET", root+"/scan", "", nil, http.StatusOK, &result)
	if result.SBOM.Source != "syft" || result.SBOM.GeneratorVersion == "" {
		t.Fatal("persisted inventory lacks real Syft producer identity")
	}
	byEngine := func(outcomes []scanrun.EngineOutcome) map[string]scanrun.EngineOutcome {
		t.Helper()
		facts := make(map[string]scanrun.EngineOutcome, len(outcomes))
		for _, outcome := range outcomes {
			if _, exists := facts[outcome.Engine]; exists {
				t.Fatalf("duplicate outcome for %s", outcome.Engine)
			}
			facts[outcome.Engine] = outcome
		}
		return facts
	}
	if !reflect.DeepEqual(byEngine(job.EngineOutcomes), byEngine(result.EngineOutcomes)) || job.EngineCoverage != result.EngineCoverage {
		t.Fatalf("job and persisted scan disagree on engine facts: job=%+v latest=%+v", job.EngineOutcomes, result.EngineOutcomes)
	}
	outcome := func(name string) scanrun.EngineOutcome {
		t.Helper()
		for _, o := range result.EngineOutcomes {
			if o.Engine == name {
				return o
			}
		}
		t.Fatalf("missing %s engine outcome", name)
		return scanrun.EngineOutcome{}
	}
	python := outcome("taint_python")
	if !python.Required || python.Execution != scanrun.EngineCompleted || python.Coverage != scanrun.CoverageComplete {
		t.Fatalf("selected Python engine did not complete with complete coverage: %+v", python)
	}
	goTaint := outcome("taint_go")
	if goTaint.Required || goTaint.Reason != scanrun.ReasonNotSelected {
		t.Fatalf("disabled Go taint has misleading outcome: %+v", goTaint)
	}
	iac := outcome("iac")
	if !iac.Required || iac.Execution != scanrun.EngineCompleted || iac.Counts[scanrun.MeasureFindings] == 0 {
		t.Fatalf("IaC did not retain positive findings: %+v", iac)
	}
	if phase == "missing-helm" {
		if iac.Coverage != scanrun.CoveragePartial || iac.Reason != scanrun.ReasonUnrenderedCharts || iac.Counts[scanrun.MeasureUnrenderedCharts] == 0 || result.EngineCoverage.Status == scanrun.CoverageComplete {
			t.Fatalf("missing renderer was not reported as a coverage gap: %+v", iac)
		}
	} else if iac.Coverage != scanrun.CoverageComplete {
		t.Fatalf("complete renderer phase has IaC gap: %+v", iac)
	}
	foundPackage, foundIaC := false, false
	for _, c := range result.SBOM.Components {
		if c.Name == "lodash" && c.Version == "4.17.21" {
			foundPackage = true
		}
	}
	for _, f := range result.Findings {
		if f.RuleKey == "kubernetes-privileged" {
			foundIaC = true
		}
	}
	if !foundPackage || !foundIaC {
		t.Fatalf("persisted result missing producer facts: npm=%t privileged_iac=%t", foundPackage, foundIaC)
	}
	report := request("GET", root+"/report.html", "", nil, http.StatusOK, nil)
	workerAcceptanceReportEngines(t, report, result.EngineOutcomes)
	var runs []struct {
		CompleteCoverage bool `json:"complete_coverage"`
		SourcePackage    struct {
			VersionID string `json:"version_id"`
			SHA256    string `json:"sha256"`
		} `json:"source_package"`
		Manifest struct {
			SBOMSHA256 string `json:"sbom_sha256"`
		} `json:"manifest"`
	}
	request("GET", root+"/scan-runs", "", nil, http.StatusOK, &runs)
	matched := false
	for _, run := range runs {
		if run.SourcePackage.VersionID == source.VersionID && run.SourcePackage.SHA256 == digest && run.Manifest.SBOMSHA256 != "" {
			if result.EngineCoverage.Status != scanrun.CoverageComplete && run.CompleteCoverage {
				t.Fatal("scan history incorrectly claims complete coverage")
			}
			matched = true
		}
	}
	if !matched {
		t.Fatal("scan history lost the uploaded source and SBOM provenance")
	}
}

func workerAcceptanceReportEngines(t *testing.T, document []byte, outcomes []scanrun.EngineOutcome) {
	t.Helper()
	root, err := nethtml.Parse(bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	expected := make(map[string]scanrun.EngineOutcome, len(outcomes))
	for _, outcome := range outcomes {
		expected[outcome.Engine] = outcome
	}
	seen := make(map[string]bool, len(outcomes))
	var walk func(*nethtml.Node)
	walk = func(node *nethtml.Node) {
		if node.Type == nethtml.ElementNode && node.Data == "tr" {
			var cells []string
			for cell := node.FirstChild; cell != nil; cell = cell.NextSibling {
				if cell.Type != nethtml.ElementNode || cell.Data != "td" {
					continue
				}
				var text strings.Builder
				var collect func(*nethtml.Node)
				collect = func(child *nethtml.Node) {
					if child.Type == nethtml.TextNode {
						text.WriteString(child.Data)
					}
					for next := child.FirstChild; next != nil; next = next.NextSibling {
						collect(next)
					}
				}
				collect(cell)
				cells = append(cells, strings.TrimSpace(text.String()))
			}
			if len(cells) == 4 {
				if outcome, exists := expected[cells[0]]; exists {
					if seen[cells[0]] || cells[1] != string(outcome.Execution) || cells[2] != string(outcome.Coverage) || cells[3] != string(outcome.Reason) {
						t.Fatalf("report contradicts stored %s engine facts: %q", cells[0], cells)
					}
					seen[cells[0]] = true
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	for engine := range expected {
		if !seen[engine] {
			t.Fatalf("report omitted %s engine facts", engine)
		}
	}
}

func workerAcceptanceArchive(t *testing.T) []byte {
	t.Helper()
	files := []struct{ name, data string }{
		{"app.py", "from flask import Flask, request\nimport os, subprocess\napp = Flask(__name__)\n@app.get('/unsafe')\ndef unsafe():\n    command = request.args.get('command')\n    os.system(command)\n    return 'ok'\n@app.get('/safe')\ndef safe():\n    subprocess.run(['/usr/bin/id'], shell=False)\n    return 'ok'\n"},
		{"package-lock.json", `{"name":"acceptance-fixture","version":"1.0.0","lockfileVersion":2,"requires":true,"packages":{"":{"name":"acceptance-fixture","version":"1.0.0","dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}},"dependencies":{"lodash":{"version":"4.17.21"}}}`},
		{"pod.json", `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"fixture"},"spec":{"containers":[{"name":"app","image":"nginx:latest","securityContext":{"privileged":true}}]}}`},
		{"chart/Chart.yaml", "apiVersion: v2\nname: fixture\nversion: 0.1.0\n"},
		{"chart/templates/pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Release.Name }}\nspec:\n  containers:\n    - name: app\n      image: nginx:latest\n      securityContext:\n        privileged: true\n"},
		{"overlay/kustomization.yaml", "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - pod.yaml\n"},
		{"overlay/pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: overlay\nspec:\n  containers:\n    - name: app\n      image: nginx:latest\n      securityContext:\n        privileged: true\n"},
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0600, Size: int64(len(f.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
