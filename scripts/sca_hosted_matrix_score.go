//go:build ignore

// Score the current owned matcher and pinned offline comparators on one oracle.
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

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

type ownedMatrixWire struct {
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

type cellScore struct {
	TargetID         string                 `json:"target_id"`
	Engine           bench.Engine           `json:"engine"`
	State            bench.ObservationState `json:"state"`
	BinaryDigest     string                 `json:"binary_digest"`
	DatabaseDigest   string                 `json:"database_digest"`
	RawOutputDigest  string                 `json:"raw_output_digest"`
	CapabilityDigest string                 `json:"capability_digest,omitempty"`
	Metrics          bench.EngineResult     `json:"metrics"`
	Breaches         []string               `json:"breaches"`
}

func main() {
	catalogPath := flag.String("catalog", "", "committed catalog")
	oraclePath := flag.String("oracle", "", "committed oracle")
	ratchetPath := flag.String("ratchet", "", "committed numerical ratchet")
	inputDir := flag.String("input-dir", "", "digest-verified offline inputs")
	wireDir := flag.String("wire-dir", "", "current scanner outputs and retained capability statements")
	ownedBinary := flag.String("owned-binary", "", "current owned scanner binary")
	archiveDigest := flag.String("archive-sha256", "", "verified offline archive digest")
	sourceSHA := flag.String("source-sha", "", "exact source revision")
	outputPath := flag.String("output", "", "sanitized score output")
	flag.Parse()
	if flag.NArg() != 0 || *catalogPath == "" || *oraclePath == "" || *ratchetPath == "" || *inputDir == "" || *wireDir == "" || *ownedBinary == "" || *archiveDigest == "" || *sourceSHA == "" || *outputPath == "" {
		fatal("all matrix score inputs are required")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(*sourceSHA) || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*archiveDigest) {
		fatal("source or archive identity is invalid")
	}
	if err := scoreMatrix(*catalogPath, *oraclePath, *ratchetPath, *inputDir, *wireDir, *ownedBinary, *archiveDigest, *sourceSHA, *outputPath); err != nil {
		fatal("%v", err)
	}
}

func scoreMatrix(catalogPath, oraclePath, ratchetPath, inputDir, wireDir, ownedBinary, archiveDigest, sourceSHA, outputPath string) error {
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
	if len(catalog.Targets) != 3 || len(oracle.Cases) == 0 || len(ratchet.Floors) != len(catalog.Targets)*len(bench.Engines()) {
		return errors.New("matrix requires three targets, a nonempty oracle, and all twelve ratchet cells")
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
		return errors.New("ratchet does not bind the committed catalog and oracle")
	}
	ownedDigest, err := fileDigest(ownedBinary)
	if err != nil {
		return fmt.Errorf("hash current owned binary: %w", err)
	}
	environmentID := "github-hosted-offline-sca"
	environmentDigest := digest([]byte(runtime.GOOS + "/" + runtime.GOARCH + "/" + runtime.Version()))
	targets := make(map[string]bench.Target, len(catalog.Targets))
	for _, target := range catalog.Targets {
		if got, err := fileDigest(filepath.Join(inputDir, "sboms", target.ID+".cdx.json")); err != nil || got != target.SBOMDigest {
			return fmt.Errorf("SBOM pin mismatch for %s: %v", target.ID, err)
		}
		targets[target.ID] = target
	}
	databaseDigests := map[string]string{}
	observations := make([]bench.Observation, 0, len(ratchet.Floors))
	for _, floor := range ratchet.Floors {
		target, ok := targets[floor.Expected.TargetID]
		if !ok || floor.Expected.TargetDigest != target.Digest || floor.Expected.SBOMDigest != target.SBOMDigest {
			return fmt.Errorf("ratchet target pin mismatch for %s/%s", floor.Expected.TargetID, floor.Expected.Engine)
		}
		engine := floor.Expected.Engine
		dbPath, err := databasePath(inputDir, target.ID, engine)
		if err != nil {
			return err
		}
		dbDigest, ok := databaseDigests[dbPath]
		if !ok {
			dbDigest, err = capture.HashTree(dbPath)
			if err != nil {
				return fmt.Errorf("hash %s database: %w", engine, err)
			}
			databaseDigests[dbPath] = dbDigest
		}
		if dbDigest != floor.Expected.DatabaseDigest {
			return fmt.Errorf("%s/%s database does not match committed pin", target.ID, engine)
		}
		binaryDigest := ownedDigest
		if engine != bench.EngineOwned {
			binaryDigest, err = fileDigest(filepath.Join(inputDir, "tools", string(engine)))
			if err != nil || binaryDigest != floor.Expected.EngineBinaryDigest {
				return fmt.Errorf("%s comparator binary does not match committed pin: %v", engine, err)
			}
		}
		observation := bench.Observation{
			SchemaVersion: bench.ObservationSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest,
			Engine: engine, EngineVersion: floor.Expected.EngineVersion, EngineBinaryDigest: binaryDigest,
			DatabaseBuild: floor.Expected.DatabaseBuild, DatabaseDigest: dbDigest,
			EnvironmentID: environmentID, EnvironmentDigest: environmentDigest,
			TargetID: target.ID, TargetDigest: target.Digest, SBOMDigest: target.SBOMDigest,
			ConfigDigest: digest([]byte("hosted-offline/" + string(engine) + "/v1")),
		}
		if floor.Mode == bench.FloorGateModeUnsupportedOnly {
			if engine != bench.EngineOSVScanner || floor.Expected.CapabilityKind == "" {
				return fmt.Errorf("unexpected unsupported floor for %s/%s", target.ID, engine)
			}
			capabilityPath := filepath.Join(inputDir, "capability", target.ID+".json")
			capabilityBytes, err := readBounded(capabilityPath, 1<<20)
			if err != nil {
				return err
			}
			var statement capture.CapabilityStatement
			if err := strictJSON(capabilityBytes, &statement); err != nil {
				return fmt.Errorf("decode %s capability: %w", target.ID, err)
			}
			if err := statement.Validate(); err != nil {
				return fmt.Errorf("validate %s capability: %w", target.ID, err)
			}
			if statement.Kind != floor.Expected.CapabilityKind || statement.TargetID != target.ID || statement.TargetDigest != target.Digest || statement.SBOMDigest != target.SBOMDigest || statement.EngineBinaryDigest != binaryDigest || statement.DatabaseDigest != dbDigest {
				return fmt.Errorf("frozen %s capability does not match retained scanner and target inputs", target.ID)
			}
			for _, source := range statement.Sources {
				path := ""
				switch source.Reference {
				case "https://github.com/google/osv-scanner/blob/c84fa4568f2526d0333e9a914ea8a0a5f74ad68b/internal/utility/purl/purl_to_package.go":
					path = filepath.Join(inputDir, "repository", "capability", "osv-scanner-v2.5.1", "purl_to_package.go")
				case "https://github.com/google/osv-scalibr/blob/23fa66ca68dd17bfdbe0b8b3536d1887a3a940da/purl/ecosystem/ecosystem.go":
					path = filepath.Join(inputDir, "repository", "capability", "osv-scanner-v2.5.1", "ecosystem.go")
				default:
					return fmt.Errorf("unrecognized %s capability source", target.ID)
				}
				if got, err := fileDigest(path); err != nil || got != source.Digest {
					return fmt.Errorf("%s capability source digest mismatch: %v", target.ID, err)
				}
			}
			observation.State = bench.ObservationUnsupported
			observation.RawOutputDigest = digest(capabilityBytes)
			observation.CapabilityKind = statement.Kind
			observation.CapabilityDigest = digest(capabilityBytes)
		} else {
			wirePath := filepath.Join(wireDir, string(engine)+"-"+target.ID+".json")
			wireBytes, err := readBounded(wirePath, int64(bench.MaxJSONBytes))
			if err != nil {
				return err
			}
			if engine == bench.EngineOwned {
				var wire ownedMatrixWire
				if err := strictJSON(wireBytes, &wire); err != nil {
					return fmt.Errorf("decode owned %s: %w", target.ID, err)
				}
				if wire.SchemaVersion != "synapse-sca-benchmark-owned-wire-v2" || wire.EngineVersion == "" || wire.AdvisoriesIngested <= 0 || wire.AdvisoriesSkipped != 0 || len(wire.Findings) == 0 {
					return fmt.Errorf("owned %s scan is incomplete", target.ID)
				}
				observation.EngineVersion = wire.EngineVersion
				for _, finding := range wire.Findings {
					observation.Findings = append(observation.Findings, bench.Finding{Component: bench.Component{PURL: finding.PURL, Version: finding.Version}, AdvisoryID: finding.AdvisoryID})
				}
			} else {
				var probe []byte
				if engine == bench.EngineOSVScanner {
					probe, err = readBounded(filepath.Join(wireDir, "osv-version.txt"), 4096)
					if err != nil {
						return err
					}
				}
				observation.Findings, err = capture.ParseHostedExternalOutput(engine, target, floor.Expected.EngineVersion, wireBytes, probe)
				if err != nil {
					return fmt.Errorf("parse %s/%s: %w", target.ID, engine, err)
				}
			}
			observation.State = bench.ObservationComplete
			observation.RawOutputDigest = digest(wireBytes)
		}
		observations = append(observations, observation)
	}
	result, err := bench.Reduce(catalog, oracle, observations)
	if err != nil {
		return fmt.Errorf("reduce matrix: %w", err)
	}
	targetIDs := make([]string, 0, len(catalog.Targets))
	for _, target := range catalog.Targets {
		targetIDs = append(targetIDs, target.ID)
	}
	parityErr := bench.ValidateMeasuredPerTargetRecallParity(result, targetIDs)
	byCell := make(map[string]bench.RunMetric, len(result.RunMetrics))
	for _, metric := range result.RunMetrics {
		byCell[metric.Run.TargetID+"/"+string(metric.Run.Engine)] = metric
	}
	cells := make([]cellScore, 0, len(ratchet.Floors))
	passed := parityErr == nil
	for _, floor := range ratchet.Floors {
		key := floor.Expected.TargetID + "/" + string(floor.Expected.Engine)
		metric, ok := byCell[key]
		if !ok {
			return fmt.Errorf("missing measured matrix cell %s", key)
		}
		breaches := numericalBreaches(metric.Metrics, metric.Run.State, floor)
		if len(breaches) > 0 {
			passed = false
		}
		cells = append(cells, cellScore{TargetID: metric.Run.TargetID, Engine: metric.Run.Engine, State: metric.Run.State, BinaryDigest: metric.Run.EngineBinaryDigest, DatabaseDigest: metric.Run.DatabaseDigest, RawOutputDigest: observationDigest(observations, metric.Run.TargetID, metric.Run.Engine), CapabilityDigest: metric.Run.CapabilityDigest, Metrics: metric.Metrics, Breaches: breaches})
	}
	sort.Slice(cells, func(i, j int) bool {
		if cells[i].TargetID == cells[j].TargetID {
			return cells[i].Engine < cells[j].Engine
		}
		return cells[i].TargetID < cells[j].TargetID
	})
	parityStatus := "passed"
	if parityErr != nil {
		parityStatus = parityErr.Error()
	}
	output := map[string]any{"schema_version": "synapse-sca-hosted-matrix-v1", "source_sha": sourceSHA, "input_archive_sha256": archiveDigest, "catalog_digest": catalogDigest, "oracle_digest": oracleDigest, "ratchet_digest": ratchetDigest, "environment_id": environmentID, "environment_digest": environmentDigest, "target_count": len(catalog.Targets), "cell_count": len(cells), "diagnostic_count": len(result.Diagnostics), "parity": parityStatus, "cells": cells, "passed": passed, "historical_acceptance": false}
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
		return errors.New("current hosted matrix breached parity or a committed numerical floor; see sanitized result")
	}
	return nil
}

func databasePath(root, targetID string, engine bench.Engine) (string, error) {
	switch engine {
	case bench.EngineGrype:
		return filepath.Join(root, "databases", "grype"), nil
	case bench.EngineTrivy:
		return filepath.Join(root, "databases", "trivy"), nil
	case bench.EngineOSVScanner:
		return filepath.Join(root, "databases", "osv"), nil
	case bench.EngineOwned:
		switch targetID {
		case "debian-12-13-slim-amd64":
			return filepath.Join(root, "databases", "owned-debian"), nil
		case "rhel-9-8-ubi-amd64":
			return filepath.Join(root, "databases", "owned-redhat"), nil
		case "sles-15-6-bci-base-45-31-amd64":
			return filepath.Join(root, "databases", "owned-sles"), nil
		}
	}
	return "", fmt.Errorf("unsupported database route %s/%s", targetID, engine)
}

func numericalBreaches(metrics bench.EngineResult, state bench.ObservationState, floor bench.RatchetFloor) []string {
	breaches := []string{}
	if floor.Mode == bench.FloorGateModeUnsupportedOnly {
		if state != bench.ObservationUnsupported || !metrics.MetricsComplete || metrics.Covered != 0 || metrics.Unsupported == 0 || metrics.Unsupported > *floor.MaximumUnsupported || metrics.Unknown != 0 || metrics.Incomplete != 0 {
			breaches = append(breaches, "unsupported_contract")
		}
		return breaches
	}
	if state != bench.ObservationComplete || !metrics.MetricsComplete {
		breaches = append(breaches, "incomplete_scan")
	}
	if metrics.Covered < *floor.MinimumCovered {
		breaches = append(breaches, "covered")
	}
	if metrics.AffectedRelations < *floor.MinimumAffectedRelations {
		breaches = append(breaches, "affected_relations")
	}
	if metrics.NegativeRelations < *floor.MinimumNegativeRelations {
		breaches = append(breaches, "negative_relations")
	}
	if metrics.FalsePositives > *floor.MaximumFalsePositives {
		breaches = append(breaches, "false_positives")
	}
	if metrics.FalseNegatives > *floor.MaximumFalseNegatives {
		breaches = append(breaches, "false_negatives")
	}
	if metrics.Unknown > *floor.MaximumUnknown {
		breaches = append(breaches, "unknown")
	}
	if metrics.Incomplete > *floor.MaximumIncomplete {
		breaches = append(breaches, "incomplete")
	}
	if metrics.Unsupported > *floor.MaximumUnsupported {
		breaches = append(breaches, "unsupported")
	}
	if metrics.Precision == nil {
		if !floor.AllowUndefinedPrecision {
			breaches = append(breaches, "precision_unavailable")
		}
	} else if *metrics.Precision < *floor.MinimumPrecision {
		breaches = append(breaches, "precision")
	}
	if metrics.Recall == nil || *metrics.Recall < *floor.MinimumRecall {
		breaches = append(breaches, "recall")
	}
	return breaches
}

func observationDigest(observations []bench.Observation, target string, engine bench.Engine) string {
	for _, observation := range observations {
		if observation.TargetID == target && observation.Engine == engine {
			return observation.RawOutputDigest
		}
	}
	return ""
}

func readBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > limit {
		return nil, fmt.Errorf("%s is empty, special, or exceeds %d bytes", path, limit)
	}
	return os.ReadFile(path)
}

func strictJSON(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %s", path)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "SCA hosted matrix: "+format+"\n", args...)
	os.Exit(1)
}
