package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchcore"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const (
	manifestPath = "../../docs/benchmarks/closure-manifest-v1.json"
	oraclePath   = "../../internal/usecase/scabench/corpus/oracle.json"
	catalogPath  = "../../internal/usecase/scabench/corpus/catalog.json"
	profile      = "sca.component-advisory.v1"
)

func runOK(t *testing.T, want int, args ...string) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != want {
		t.Fatalf("%v: exit %d, want %d; stderr %s", args, code, want, stderr.String())
	}
	return stdout.Bytes()
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// legacySet writes a legacy observation set in which every engine reports every affected relation.
func legacySet(t *testing.T, dir string) string {
	t.Helper()
	cf, err := os.Open(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cf.Close() }()
	catalog, err := scabench.DecodeCatalog(cf)
	if err != nil {
		t.Fatal(err)
	}
	of, err := os.Open(oraclePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = of.Close() }()
	oracle, err := scabench.DecodeOracle(of)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := scabench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	hex := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	set := scabench.ObservationSet{SchemaVersion: scabench.ObservationSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: digest}
	for _, engine := range scabench.Engines() {
		for _, target := range catalog.Targets {
			o := scabench.Observation{SchemaVersion: scabench.ObservationSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: digest,
				Engine: engine, EngineVersion: "v1", EngineBinaryDigest: hex("c"), DatabaseBuild: "db", DatabaseDigest: hex("d"),
				EnvironmentID: "linux", EnvironmentDigest: hex("e"), TargetID: target.ID, TargetDigest: target.Digest, SBOMDigest: target.SBOMDigest,
				State: scabench.ObservationComplete, RawOutputDigest: hex("f"), ConfigDigest: hex("1")}
			for _, c := range oracle.Cases {
				if c.TargetID == target.ID && c.Truth == scabench.TruthAffected {
					o.Findings = append(o.Findings, scabench.Finding{Component: c.Component, AdvisoryID: c.AdvisoryID})
				}
			}
			set.Observations = append(set.Observations, o)
		}
	}
	var buf bytes.Buffer
	if err := scabench.EncodeObservationSet(&buf, set); err != nil {
		t.Fatal(err)
	}
	return writeFile(t, dir, "observations.json", buf.Bytes())
}

// TestCLIScoresTwoEnginesThroughOneCore runs the documented flow over the committed manifest: controls,
// truth, one observation file per engine, a receipt, a scorecard per engine, and the closure status.
func TestCLIScoresTwoEnginesThroughOneCore(t *testing.T) {
	dir := t.TempDir()
	var controls []benchcore.ControlSuiteResult
	if err := json.Unmarshal(runOK(t, exitOK, "controls", "-manifest", manifestPath), &controls); err != nil || len(controls) != 2 || !controls[0].Passed || !controls[1].Passed {
		t.Fatalf("controls = %+v, %v", controls, err)
	}
	truth := writeFile(t, dir, "truth.json", runOK(t, exitOK, "truth-from-scabench", "-oracle", oraclePath, "-catalog", catalogPath, "-profile", profile, "-version", "oracle@same-sbom-linux-20260922"))
	digest := strings.TrimSpace(string(runOK(t, exitOK, "digest", "-kind", "truth", "-file", truth)))
	m, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(m), digest) {
		t.Fatalf("truth digest %s is not the one the manifest froze", digest)
	}
	set := legacySet(t, dir)
	receipt := writeFile(t, dir, "receipt.json", runOK(t, exitOK, "receipt", "-manifest", manifestPath, "-profile", profile, "-run-key", "cli-test", "-commit", "test", "-runner", "go-test"))
	var cards []string
	for _, engine := range []string{"owned", "grype", "trivy", "osv-scanner"} {
		obs := writeFile(t, dir, engine+"-obs.json", runOK(t, exitOK, "observe-scabench", "-observations", set, "-manifest", manifestPath, "-profile", profile, "-engine", engine))
		cardJSON := runOK(t, exitOK, "score", "-manifest", manifestPath, "-receipt", receipt, "-truth", truth, "-observations", obs)
		var card benchcore.Scorecard
		if err := json.Unmarshal(cardJSON, &card); err != nil {
			t.Fatal(err)
		}
		if card.Engine.EngineID != engine || card.Validity.Status != "valid" || card.EngineGrade != benchcore.GradeDescriptive {
			t.Fatalf("%s card: engine %s validity %+v grade %s", engine, card.Engine.EngineID, card.Validity, card.EngineGrade)
		}
		cardPath := writeFile(t, dir, engine+"-card.json", cardJSON)
		cards = append(cards, cardPath)
		runOK(t, exitOK, "verify", "-manifest", manifestPath, "-receipt", receipt, "-truth", truth, "-observations", obs, "-card", cardPath)
		// A card whose content was edited and its id recomputed is consistent but not what the core computed.
		var forged map[string]any
		if err := json.Unmarshal(cardJSON, &forged); err != nil {
			t.Fatal(err)
		}
		forged["engine_grade"] = "pass"
		forged["id"] = "sha256:" + strings.Repeat("a", 64)
		raw, err := json.Marshal(forged)
		if err != nil {
			t.Fatal(err)
		}
		runOK(t, exitError, "verify", "-manifest", manifestPath, "-receipt", receipt, "-truth", truth, "-observations", obs, "-card", writeFile(t, dir, engine+"-forged.json", raw))
	}
	statusJSON := runOK(t, exitNotClosed, append([]string{"status", "-manifest", manifestPath}, cards...)...)
	var status statusReport
	if err := json.Unmarshal(statusJSON, &status); err != nil {
		t.Fatal(err)
	}
	if status.Closed || status.Profiles[profile] != benchcore.ProfileExecuted || status.Profiles["work_package:E"] != benchcore.WorkPackageNotEntered {
		t.Fatalf("status = %+v", status)
	}
	// Three of the four enrolled engines leave the profile unexecuted.
	statusJSON = runOK(t, exitNotClosed, append([]string{"status", "-manifest", manifestPath}, cards[:3]...)...)
	if err := json.Unmarshal(statusJSON, &status); err != nil {
		t.Fatal(err)
	}
	if status.Profiles[profile] != benchcore.ProfileNotExecuted {
		t.Fatalf("status with three engines = %+v", status)
	}
}

// TestCLIRefusesAnUnenrolledEngineAndBadUsage covers the error exits.
func TestCLIRefusesAnUnenrolledEngineAndBadUsage(t *testing.T) {
	dir := t.TempDir()
	set := legacySet(t, dir)
	raw, err := os.ReadFile(set)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["catalog_digest"] = "sha256:" + strings.Repeat("0", 64)
	for _, o := range doc["observations"].([]any) {
		o.(map[string]any)["catalog_digest"] = doc["catalog_digest"]
	}
	other, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	runOK(t, exitError, "observe-scabench", "-observations", writeFile(t, dir, "other-catalog.json", other), "-manifest", manifestPath, "-profile", profile, "-engine", "owned")
	runOK(t, exitError, "observe-scabench", "-observations", set, "-manifest", manifestPath, "-profile", profile, "-engine", "unknown-engine")
	runOK(t, exitUsage, "score", "-manifest", manifestPath)
	runOK(t, exitUsage, "score", "-controls", "x.json")
	runOK(t, exitUsage, "no-such-command")
	runOK(t, exitUsage)
}
