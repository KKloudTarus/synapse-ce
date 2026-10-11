package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func completed(engine string) scanrun.EngineOutcome {
	return scanrun.EngineOutcome{Engine: engine, Required: true, Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete}
}

func excluded(engine string, reason scanrun.EngineReason) scanrun.EngineOutcome {
	return scanrun.EngineOutcome{Engine: engine, Execution: scanrun.EngineNotRun, Coverage: scanrun.CoverageNotApplicable, Reason: reason}
}

func timedOut(engine string) scanrun.EngineOutcome {
	return scanrun.EngineOutcome{Engine: engine, Required: true, Execution: scanrun.EngineTimedOut, Coverage: scanrun.CoveragePartial, Reason: scanrun.ReasonDeadlineExceeded}
}

// summarize builds the result the way the scan service does, with coverage computed from the
// outcomes, so a test cannot pass on a hand-written coverage the outcomes contradict.
func summarize(t *testing.T, warnings []string, outcomes ...scanrun.EngineOutcome) []string {
	t.Helper()
	if _, err := scanrun.CanonicalEngineOutcomes(outcomes); err != nil {
		t.Fatalf("test outcomes are not valid: %v", err)
	}
	res := &scauc.ScanResult{EngineOutcomes: outcomes, EngineCoverage: scanrun.ComputeEngineCoverage(outcomes), SourceWarnings: warnings}
	var buf bytes.Buffer
	writeScanCompletionSummary(&buf, res)
	return strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
}

func incompleteLines(lines []string) []string {
	var out []string
	for _, line := range lines {
		if strings.Contains(line, "incomplete:") {
			out = append(out, line)
		}
	}
	return out
}

func TestScanCompletionSummaryOfACompleteZeroFindingScan(t *testing.T) {
	lines := summarize(t, nil,
		completed("inventory"), completed("dependency_resolution"), completed("sca"),
		excluded("licenses", scanrun.ReasonNotSelected), excluded("sast", scanrun.ReasonNotApplicable))
	if lines[0] != "synapse-cli: engine coverage complete: 3 of 3 required engine(s) completed" {
		t.Fatalf("headline = %q", lines[0])
	}
	if got := incompleteLines(lines); len(got) != 0 {
		t.Fatalf("a complete scan reported incomplete engines: %q", got)
	}
	if !contains(lines, "synapse-cli:   excluded from this scan: licenses (not_selected), sast (not_applicable)") {
		t.Fatalf("exclusions are not reported on their own line:\n%s", strings.Join(lines, "\n"))
	}
	if len(lines) != 2 {
		t.Fatalf("a complete scan with no warnings printed extra lines:\n%s", strings.Join(lines, "\n"))
	}
}

// An engine left out on purpose is not a failure, and an engine that failed is not an exclusion.
func TestScanCompletionSummarySeparatesExclusionsFromIncompleteEngines(t *testing.T) {
	failed := scanrun.EngineOutcome{Engine: "secrets", Required: true, Execution: scanrun.EngineFailed, Coverage: scanrun.CoverageUnknown, Reason: scanrun.ReasonEngineError}
	lines := summarize(t, nil, completed("inventory"), failed, excluded("iac", scanrun.ReasonNotSelected))
	if lines[0] != "synapse-cli: engine coverage partial: 1 of 2 required engine(s) completed" {
		t.Fatalf("headline = %q", lines[0])
	}
	incomplete := incompleteLines(lines)
	if len(incomplete) != 1 || incomplete[0] != "synapse-cli:   incomplete: secrets failed (engine_error), coverage unknown" {
		t.Fatalf("incomplete lines = %q, want only the failed required engine", incomplete)
	}
	if !contains(lines, "synapse-cli:   excluded from this scan: iac (not_selected)") {
		t.Fatalf("the excluded engine is missing from its line:\n%s", strings.Join(lines, "\n"))
	}
}

func budgetExhausted(engine string) scanrun.EngineOutcome {
	return scanrun.EngineOutcome{Engine: engine, Required: true, Execution: scanrun.EngineNotRun, Coverage: scanrun.CoverageUnknown, Reason: scanrun.ReasonBudgetExhausted}
}

// One shared deadline expiring mid-scan stops the engine that was running and leaves the ones after it
// unstarted; a real `SYNAPSE_SCAN_TIMEOUT=80ms` run produced exactly this shape. Each engine must be
// named with its reason, not folded into a count, so a reader sees which ones produced nothing.
func TestScanCompletionSummaryOfASharedDeadlineCascade(t *testing.T) {
	warning := "static analysis did not finish within the scan time budget (SYNAPSE_SCAN_TIMEOUT); its findings are ABSENT, so a zero count there is a gap in the scan rather than a clean result"
	lines := summarize(t, []string{warning},
		completed("inventory"), completed("dependency_resolution"), completed("sca"), completed("licenses"),
		timedOut("sast"), budgetExhausted("secrets"), budgetExhausted("iac"))
	if lines[0] != "synapse-cli: engine coverage partial: 4 of 7 required engine(s) completed" {
		t.Fatalf("headline = %q", lines[0])
	}
	want := []string{
		"synapse-cli:   incomplete: sast timed_out (deadline_exceeded), coverage partial",
		"synapse-cli:   incomplete: secrets not_run (budget_exhausted), coverage unknown",
		"synapse-cli:   incomplete: iac not_run (budget_exhausted), coverage unknown",
	}
	if got := incompleteLines(lines); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("cascade lines =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if lines[len(lines)-1] != "synapse-cli: warning: "+warning {
		t.Fatalf("last line = %q, want the source warning", lines[len(lines)-1])
	}
}

func TestScanCompletionSummaryNamesAnUnavailableRequiredEngine(t *testing.T) {
	unavailable := scanrun.EngineOutcome{Engine: "sast", Required: true, Execution: scanrun.EngineNotRun, Coverage: scanrun.CoverageUnknown, Reason: scanrun.ReasonUnavailable}
	lines := summarize(t, nil, completed("inventory"), unavailable)
	if got := incompleteLines(lines); len(got) != 1 || got[0] != "synapse-cli:   incomplete: sast not_run (unavailable), coverage unknown" {
		t.Fatalf("incomplete lines = %q", got)
	}
}

// A result with no recorded outcomes, such as one from an older reporter, says so instead of claiming
// a ratio of nothing.
func TestScanCompletionSummaryWithoutOutcomes(t *testing.T) {
	lines := summarize(t, nil)
	if len(lines) != 1 || lines[0] != "synapse-cli: engine coverage unknown: no required engine outcome was recorded" {
		t.Fatalf("summary = %q", lines)
	}
}

func TestScanCompletionSummaryPrintsWarningsInFull(t *testing.T) {
	long := "dependency resolution stopped: " + strings.Repeat("x", 10_000) + " END"
	lines := summarize(t, []string{"first warning", long}, completed("inventory"))
	if !contains(lines, "synapse-cli: warning: first warning") || !contains(lines, "synapse-cli: warning: "+long) {
		t.Fatalf("warnings are missing or truncated; last line has %d bytes", len(lines[len(lines)-1]))
	}
}

func contains(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}

// captureOutput runs fn with os.Stdout and os.Stderr redirected, so a run() writing to either can be
// checked for which stream each line landed on.
func captureOutput(t *testing.T, fn func() error) (stdout, stderr string, err error) {
	t.Helper()
	outR, outW, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	errR, errW, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	savedOut, savedErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	var wg sync.WaitGroup
	var outBuf, errBuf bytes.Buffer
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&outBuf, outR) }()
	go func() { defer wg.Done(); _, _ = io.Copy(&errBuf, errR) }()
	defer func() {
		os.Stdout, os.Stderr = savedOut, savedErr
	}()
	err = fn()
	_ = outW.Close()
	_ = errW.Close()
	wg.Wait()
	return outBuf.String(), errBuf.String(), err
}

func TestPushStatusWriterLeavesAMachineDocumentAloneOnStdout(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		jsonOut, sbomOut, sarif bool
		sarifPath               string
		want                    *os.File
	}{
		{name: "human report", want: os.Stdout},
		{name: "--json", jsonOut: true, want: os.Stderr},
		{name: "--sbom", sbomOut: true, want: os.Stderr},
		{name: "--sarif to stdout", sarif: true, want: os.Stderr},
		{name: "--sarif-out FILE keeps the human report on stdout", sarif: true, sarifPath: "out.sarif", want: os.Stdout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pushStatusWriter(tc.jsonOut, tc.sbomOut, tc.sarif, tc.sarifPath); got != io.Writer(tc.want) {
				t.Fatalf("pushStatusWriter = %v, want %s", got, tc.want.Name())
			}
		})
	}
}

// offlineScanDSN gives run() a local detection source: the owned advisory store on a freshly
// migrated, empty database. An offline CLI scan has no other source without a network or a Grype DB.
func offlineScanDSN(t *testing.T) string {
	t.Helper()
	sharedDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if sharedDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the offline scan end to end")
	}
	parsed, err := url.Parse(sharedDSN)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatalf("parse PostgreSQL test DSN: %v", err)
	}
	databaseName := fmt.Sprintf("synapse_cli_json_scan_%d", time.Now().UnixNano())
	databaseIdent := pgx.Identifier{databaseName}.Sanitize()
	ctx := context.Background()
	admin, err := postgres.Connect(ctx, sharedDSN)
	if err != nil {
		t.Fatalf("connect database admin: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+databaseIdent); err != nil {
		admin.Close()
		t.Fatalf("create isolated database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = admin.Exec(cleanupCtx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, databaseName)
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+databaseIdent); err != nil {
			t.Errorf("drop isolated database: %v", err)
		}
		admin.Close()
	})
	isolated := *parsed
	isolated.Path = "/" + databaseName
	isolated.RawPath = ""
	if err := postgres.Migrate(ctx, isolated.String()); err != nil {
		t.Fatalf("migrate isolated database: %v", err)
	}
	return isolated.String()
}

// jsonScanWithPush runs a real offline `scan --json` of a one-file tree, pushing to a test server that
// answers with respond, and returns what landed on each stream and which paths the server saw.
func jsonScanWithPush(t *testing.T, push func(server string) pushTarget, respond func(w http.ResponseWriter, r *http.Request)) (stdout, stderr string, hits map[string]int) {
	t.Helper()
	t.Setenv("SYNAPSE_DB_DSN", offlineScanDSN(t))
	t.Setenv("SYNAPSE_DETECTION_SOURCES", "advisory-store")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("console.log('hello')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	hits = map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		respond(w, r)
	}))
	defer srv.Close()

	stdout, stderr, err := captureOutput(t, func() error {
		return run(root, shared.SeverityCritical, scauc.ScanModeFull, "", "", "", false, false, false, true, true, false, "", false, false, false, false, push(srv.URL))
	})
	if err != nil {
		t.Fatalf("run: %v\nstderr:\n%s", err, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	return stdout, stderr, hits
}

// assertOneJSONResult checks stdout decodes as exactly one JSON value, and that it is the scan result.
func assertOneJSONResult(t *testing.T, stdout string) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stdout is not a JSON document: %v\n%s", err, stdout)
	}
	if _, ok := doc["engine_coverage"]; !ok {
		t.Fatalf("stdout JSON is not the scan result: keys %v", keys(doc))
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("stdout carries more than one JSON document (next decode: %v); stdout:\n%s", err, stdout)
	}
}

// assertSummaryLast checks the push status reached stderr and the coverage summary came after it.
func assertSummaryLast(t *testing.T, stderr, status string) {
	t.Helper()
	at := strings.Index(stderr, status)
	summary := strings.LastIndex(stderr, "synapse-cli: engine coverage ")
	if at < 0 || summary < 0 {
		t.Fatalf("stderr is missing %q or the coverage summary:\n%s", status, stderr)
	}
	if summary < at {
		t.Fatalf("the coverage summary is not the final report; it precedes %q:\n%s", status, stderr)
	}
}

// --json with an engagement push of findings and SBOM: the ingest and import lines belong on stderr.
func TestRunJSONWithEngagementPushKeepsStdoutOneDocument(t *testing.T) {
	stdout, stderr, hits := jsonScanWithPush(t,
		func(server string) pushTarget {
			return pushTarget{server: server, engagement: "eng-1", token: "tok", sbom: true}
		},
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accepted":0,"deduplicated":0,"matched_first_party":0,"refused":[],"coverage":[]}`))
		})
	if hits["POST /api/v1/engagements/eng-1/sarif"] != 1 || hits["POST /api/v1/engagements/eng-1/sbom"] != 1 {
		t.Fatalf("the engagement findings and SBOM were not both pushed: %v", hits)
	}
	assertOneJSONResult(t, stdout)
	assertSummaryLast(t, stderr, "Engagement eng-1:")
	if !strings.Contains(stderr, "SBOM imported:") {
		t.Fatalf("the SBOM import line is not on stderr:\n%s", stderr)
	}
}

// --json with a project analysis push and --push-source: the source publication line belongs on stderr.
func TestRunJSONWithProjectSourcePushKeepsStdoutOneDocument(t *testing.T) {
	analysis := projectanalysis.Analysis{
		ID: "an-1", ProjectKey: "app",
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindLocal, Head: "workspace"},
	}
	stdout, stderr, hits := jsonScanWithPush(t,
		func(server string) pushTarget {
			return pushTarget{server: server, project: "app", token: "tok", source: true}
		},
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/app/analyses/import":
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id":"an-1","origin":"ci","gate":{"passed":true},"gate_info":{"name":"synapse-way"},"issues":{"total":0},"new_code":{"counts":{"total":0}}}`))
			case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/app/analyses/an-1":
				_ = json.NewEncoder(w).Encode(analysis)
			case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/app/analyses/an-1/code/files":
				_, _ = w.Write([]byte(`{"files":[{"path":"app.js"}]}`))
			case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/app/analyses/an-1/source":
				writer := projectanalysis.SourceWriter{Actor: "ci-user", ToolVersion: "test-version", PublishedAt: time.Unix(1_700_000_000, 0).UTC()}
				manifest := projectanalysis.SourceManifest{Writer: &writer, Files: []projectanalysis.SourceFile{{Path: "app.js", Digest: "fixture", Bytes: 21, Lines: 1, Available: true}}}
				manifest.SetArtifactDigest()
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(manifest)
			default:
				http.NotFound(w, r)
			}
		})
	if hits["POST /api/v1/projects/app/analyses/import"] != 1 || hits["POST /api/v1/projects/app/analyses/an-1/source"] != 1 {
		t.Fatalf("the analysis and its source were not both pushed: %v", hits)
	}
	assertOneJSONResult(t, stdout)
	assertSummaryLast(t, stderr, "Source published for the Code view:")
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
