//go:build ignore

// Score the current owned matcher on the frozen three-target inputs and committed oracle.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

type ownedWire struct {
	SchemaVersion      string `json:"schema_version"`
	EngineVersion      string `json:"engine_version"`
	AdvisoriesIngested int    `json:"advisories_ingested"`
	AdvisoriesSkipped  int    `json:"advisories_skipped"`
	Findings           []struct {
		PURL       string `json:"purl"`
		Version    string `json:"version"`
		AdvisoryID string `json:"advisory_id"`
	} `json:"findings"`
}

type targetScore struct {
	TargetID       string             `json:"target_id"`
	SBOMDigest     string             `json:"sbom_digest"`
	DatabaseDigest string             `json:"database_digest"`
	Metrics        bench.EngineResult `json:"metrics"`
	Passed         bool               `json:"passed"`
	Breaches       []string           `json:"breaches"`
}

type acceptedCapture struct {
	Accepted      bool              `json:"accepted"`
	SchemaVersion string            `json:"schema_version"`
	WorkflowRunID string            `json:"workflow_run_id"`
	InputDigests  map[string]string `json:"input_digests"`
}

func main() {
	catalogPath := flag.String("catalog", "", "committed catalog")
	oraclePath := flag.String("oracle", "", "committed oracle")
	ratchetPath := flag.String("ratchet", "", "committed ratchet")
	acceptedPath := flag.String("accepted-capture", "", "committed historical accepted capture")
	wireDir := flag.String("wire-dir", "", "directory of current owned wire results")
	inputDir := flag.String("input-dir", "", "verified frozen input directory")
	binaryPath := flag.String("binary", "", "current owned scanner binary")
	archiveDigest := flag.String("archive-sha256", "", "verified frozen input archive digest")
	sourceSHA := flag.String("source-sha", "", "exact source revision")
	outputPath := flag.String("output", "", "machine-readable result")
	flag.Parse()
	if flag.NArg() != 0 || *catalogPath == "" || *oraclePath == "" || *ratchetPath == "" || *acceptedPath == "" || *wireDir == "" || *inputDir == "" || *binaryPath == "" || *archiveDigest == "" || *sourceSHA == "" || *outputPath == "" {
		fail("all score inputs are required")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(*sourceSHA) || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*archiveDigest) {
		fail("source or archive identity is invalid")
	}
	if err := score(*catalogPath, *oraclePath, *ratchetPath, *acceptedPath, *wireDir, *inputDir, *binaryPath, *archiveDigest, *sourceSHA, *outputPath); err != nil {
		fail("%v", err)
	}
}

func score(catalogPath, oraclePath, ratchetPath, acceptedPath, wireDir, inputDir, binaryPath, archiveDigest, sourceSHA, outputPath string) error {
	catalogFile, err := os.Open(catalogPath)
	if err != nil {
		return fmt.Errorf("open catalog: %w", err)
	}
	defer catalogFile.Close()
	catalog, err := bench.DecodeCatalog(catalogFile)
	if err != nil {
		return fmt.Errorf("decode catalog: %w", err)
	}
	oracleFile, err := os.Open(oraclePath)
	if err != nil {
		return fmt.Errorf("open oracle: %w", err)
	}
	defer oracleFile.Close()
	oracle, err := bench.DecodeOracle(oracleFile)
	if err != nil {
		return fmt.Errorf("decode oracle: %w", err)
	}
	ratchetFile, err := os.Open(ratchetPath)
	if err != nil {
		return fmt.Errorf("open ratchet: %w", err)
	}
	defer ratchetFile.Close()
	ratchet, err := bench.DecodeRatchet(ratchetFile)
	if err != nil {
		return fmt.Errorf("decode ratchet: %w", err)
	}
	if err := ratchet.Validate(); err != nil {
		return fmt.Errorf("validate ratchet: %w", err)
	}
	if len(catalog.Targets) != 3 || len(oracle.Cases) == 0 {
		return errors.New("hosted SCA replay requires the three-target independent oracle")
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return err
	}
	oracleDigest, err := bench.DigestOracle(oracle)
	if err != nil {
		return err
	}
	ratchetDigest, err := bench.DigestRatchet(ratchet)
	if err != nil {
		return err
	}
	if ratchet.CatalogDigest != catalogDigest || ratchet.OracleDigest != oracleDigest {
		return errors.New("committed ratchet does not match catalog and oracle")
	}
	acceptedRunID, err := acceptedReference(acceptedPath, catalogDigest, oracleDigest, ratchetDigest)
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read current scanner binary: %w", err)
	}
	binaryDigest := digest(binary)
	environmentDigest := digest([]byte(runtime.GOOS + "/" + runtime.GOARCH + "/" + runtime.Version()))
	floors := map[string]bench.RatchetFloor{}
	for _, floor := range ratchet.Floors {
		if floor.Expected.Engine == bench.EngineOwned {
			if err := validateOwnedFloor(floor); err != nil {
				return err
			}
			floors[floor.Expected.TargetID] = floor
		}
	}
	if len(floors) != len(catalog.Targets) {
		return errors.New("owned ratchet floor coverage is incomplete")
	}
	observations := make([]bench.Observation, 0, len(catalog.Targets))
	databaseDigests := make(map[string]string, len(catalog.Targets))
	for _, target := range catalog.Targets {
		floor, ok := floors[target.ID]
		if !ok {
			return fmt.Errorf("missing owned floor for %s", target.ID)
		}
		if floor.Expected.TargetDigest != target.Digest || floor.Expected.SBOMDigest != target.SBOMDigest {
			return fmt.Errorf("owned floor target pin mismatch for %s", target.ID)
		}
		databaseName := ""
		databaseFormat := ""
		switch target.ID {
		case "debian-12-13-slim-amd64":
			databaseName, databaseFormat = "owned-debian", "oval"
		case "rhel-9-8-ubi-amd64":
			databaseName, databaseFormat = "owned-redhat", "csaf-json"
		case "sles-15-6-bci-base-45-31-amd64":
			databaseName, databaseFormat = "owned-sles", "oval"
		default:
			return fmt.Errorf("unrecognized hosted target %s", target.ID)
		}
		sbomBytes, err := os.ReadFile(filepath.Join(inputDir, "sboms", target.ID+".cdx.json"))
		if err != nil || digest(sbomBytes) != target.SBOMDigest {
			return fmt.Errorf("frozen SBOM does not match catalog pin for %s", target.ID)
		}
		databaseDigest, err := capture.HashTree(filepath.Join(inputDir, "databases", databaseName))
		if err != nil {
			return fmt.Errorf("digest frozen owned feed for %s: %w", target.ID, err)
		}
		if databaseDigest != floor.Expected.DatabaseDigest {
			return fmt.Errorf("frozen owned feed does not match ratchet pin for %s", target.ID)
		}
		databaseDigests[target.ID] = databaseDigest
		wirePath := filepath.Join(wireDir, target.ID+".json")
		raw, err := os.ReadFile(wirePath)
		if err != nil {
			return fmt.Errorf("read owned wire for %s: %w", target.ID, err)
		}
		if len(raw) > 2<<20 {
			return fmt.Errorf("owned wire for %s exceeds size limit", target.ID)
		}
		var wire ownedWire
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&wire); err != nil {
			return fmt.Errorf("decode owned wire for %s: %w", target.ID, err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return fmt.Errorf("owned wire for %s has trailing data", target.ID)
		}
		if wire.SchemaVersion != "synapse-sca-benchmark-owned-wire-v2" || strings.TrimSpace(wire.EngineVersion) == "" || wire.AdvisoriesIngested <= 0 || wire.AdvisoriesSkipped != 0 || len(wire.Findings) == 0 {
			return fmt.Errorf("owned wire for %s is missing a complete scan", target.ID)
		}
		observation := bench.Observation{
			SchemaVersion: bench.ObservationSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest,
			Engine: bench.EngineOwned, EngineVersion: wire.EngineVersion, EngineBinaryDigest: binaryDigest,
			DatabaseBuild: floor.Expected.DatabaseBuild, DatabaseDigest: databaseDigest,
			EnvironmentID: "github-hosted-linux", EnvironmentDigest: environmentDigest,
			TargetID: target.ID, TargetDigest: target.Digest, SBOMDigest: target.SBOMDigest,
			State: bench.ObservationComplete, RawOutputDigest: digest(raw), ConfigDigest: digest([]byte("owned-helper/" + databaseFormat)),
		}
		for _, finding := range wire.Findings {
			observation.Findings = append(observation.Findings, bench.Finding{Component: bench.Component{PURL: finding.PURL, Version: finding.Version}, AdvisoryID: finding.AdvisoryID})
		}
		observations = append(observations, observation)
	}
	result, err := bench.Reduce(catalog, oracle, observations)
	if err != nil {
		return fmt.Errorf("reduce current owned observations: %w", err)
	}
	scores := make([]targetScore, 0, len(catalog.Targets))
	passed := true
	for _, metric := range result.RunMetrics {
		if metric.Run.Engine != bench.EngineOwned {
			continue
		}
		floor := floors[metric.Run.TargetID]
		breaches := checkFloor(metric.Metrics, floor)
		scores = append(scores, targetScore{TargetID: metric.Run.TargetID, SBOMDigest: metric.Run.SBOMDigest, DatabaseDigest: databaseDigests[metric.Run.TargetID], Metrics: metric.Metrics, Passed: len(breaches) == 0, Breaches: breaches})
		passed = passed && len(breaches) == 0
	}
	if len(scores) != len(catalog.Targets) {
		return errors.New("current owned target result is missing")
	}
	sort.Slice(scores, func(i, j int) bool { return scores[i].TargetID < scores[j].TargetID })
	output := map[string]any{
		"schema_version": "synapse-sca-hosted-owned-replay-v1", "source_sha": sourceSHA,
		"input_archive_sha256": archiveDigest, "catalog_digest": catalogDigest, "oracle_digest": oracleDigest,
		"ratchet_digest": ratchetDigest, "scanner_binary_sha256": binaryDigest,
		"comparison": "current-owned-vs-committed-ratchet", "historical_acceptance_workflow_run_id": acceptedRunID,
		"target_count": len(scores), "targets": scores, "passed": passed,
	}
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	encodeErr := json.NewEncoder(file).Encode(output)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if !passed {
		return errors.New("current owned result breached the committed target floor")
	}
	return nil
}

func validateOwnedFloor(floor bench.RatchetFloor) error {
	// The hosted replay evaluates only owned cells, while the core ratchet requires
	// the full vendor matrix. Keep this adapter limited to complete accuracy floors.
	if (floor.Mode != "" && floor.Mode != bench.FloorGateModeAccuracy) || floor.AllowUndefinedPrecision {
		return fmt.Errorf("hosted replay does not support owned floor mode or undefined precision for %s", floor.Expected.TargetID)
	}
	return nil
}

func acceptedReference(path, catalogDigest, oracleDigest, ratchetDigest string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read accepted capture: %w", err)
	}
	var accepted acceptedCapture
	if err := json.Unmarshal(raw, &accepted); err != nil {
		return "", fmt.Errorf("decode accepted capture: %w", err)
	}
	if !accepted.Accepted || accepted.SchemaVersion != "synapse-sca-trusted-acceptance-report-v1" || !regexp.MustCompile(`^[0-9]+$`).MatchString(accepted.WorkflowRunID) {
		return "", errors.New("historical capture is not accepted or lacks a valid run ID")
	}
	if accepted.InputDigests["catalog"] != catalogDigest || accepted.InputDigests["oracle"] != oracleDigest || accepted.InputDigests["ratchet"] != ratchetDigest {
		return "", errors.New("historical accepted capture pins differ from committed corpus")
	}
	return accepted.WorkflowRunID, nil
}

func checkFloor(actual bench.EngineResult, floor bench.RatchetFloor) []string {
	breaches := []string{}
	min := func(name string, value int, bound *int) {
		if bound == nil || value < *bound {
			breaches = append(breaches, name)
		}
	}
	max := func(name string, value int, bound *int) {
		if bound == nil || value > *bound {
			breaches = append(breaches, name)
		}
	}
	min("covered", actual.Covered, floor.MinimumCovered)
	min("affected_relations", actual.AffectedRelations, floor.MinimumAffectedRelations)
	min("negative_relations", actual.NegativeRelations, floor.MinimumNegativeRelations)
	max("false_positives", actual.FalsePositives, floor.MaximumFalsePositives)
	max("false_negatives", actual.FalseNegatives, floor.MaximumFalseNegatives)
	max("unknown", actual.Unknown, floor.MaximumUnknown)
	max("incomplete", actual.Incomplete, floor.MaximumIncomplete)
	max("unsupported", actual.Unsupported, floor.MaximumUnsupported)
	if !actual.MetricsComplete || actual.Precision == nil || actual.Recall == nil || floor.MinimumPrecision == nil || floor.MinimumRecall == nil || *actual.Precision < *floor.MinimumPrecision || *actual.Recall < *floor.MinimumRecall {
		breaches = append(breaches, "precision_or_recall")
	}
	return breaches
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "SCA hosted score: "+format+"\n", args...)
	os.Exit(1)
}
