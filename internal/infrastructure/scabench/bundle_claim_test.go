package scabench

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestBundleClaimIgnoresRawProcessFormatting(t *testing.T) {
	observation := bench.Observation{
		CatalogRevision: "catalog", CatalogDigest: digestByte('a'), TargetID: "target", TargetDigest: digestByte('b'),
		SBOMDigest: digestByte('c'), Engine: bench.EngineGrype, EngineVersion: "1.2.3", EngineBinaryDigest: digestByte('d'),
		DatabaseBuild: "database", DatabaseDigest: digestByte('e'), EnvironmentID: "environment", EnvironmentDigest: digestByte('f'),
		ConfigDigest: digestByte('0'), State: bench.ObservationComplete, RawOutputDigest: digestByte('1'),
	}
	left := bundleClaim(observation, Evidence{ParserStatus: ParserOK, InputIntegrity: InputsVerified, FailureCode: FailureNone, Scan: &ProcessEvidence{ExitKnown: true, ExitCode: 0, Redacted: true, ParsedEngineVersion: "1.2.3", Stdout: []byte("first formatting"), Stderr: []byte("first timing")}}, bench.ObservationComplete)
	observation.RawOutputDigest = digestByte('2')
	right := bundleClaim(observation, Evidence{ParserStatus: ParserOK, InputIntegrity: InputsVerified, FailureCode: FailureNone, Scan: &ProcessEvidence{ExitKnown: true, ExitCode: 0, Redacted: true, ParsedEngineVersion: "1.2.3", Stdout: []byte("second formatting"), Stderr: []byte("second timing")}}, bench.ObservationComplete)
	leftJSON, err := bench.CanonicalJSON(left)
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := bench.CanonicalJSON(right)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leftJSON, rightJSON) {
		t.Fatal("raw streams and raw output digest became repeat claims")
	}
}

func TestBundleClaimIncludesFailureAndFindingSemantics(t *testing.T) {
	observation := bench.Observation{Engine: bench.EngineTrivy, TargetID: "target", State: bench.ObservationComplete, Findings: []bench.Finding{{AdvisoryID: "CVE-2026-0001", Component: bench.Component{PURL: "pkg:deb/debian/a@1", Version: "1"}}}}
	left := bundleClaim(observation, Evidence{ParserStatus: ParserOK, InputIntegrity: InputsVerified, FailureCode: FailureNone}, bench.ObservationComplete)
	rightObservation := observation
	rightObservation.Findings = nil
	right := bundleClaim(rightObservation, Evidence{ParserStatus: ParserFailed, InputIntegrity: InputsVerified, FailureCode: FailureParser}, bench.ObservationComplete)
	leftJSON, err := bench.CanonicalJSON(left)
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := bench.CanonicalJSON(right)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(leftJSON, rightJSON) {
		t.Fatal("finding, parser, and failure changes must remain repeat claims")
	}
}

func TestCompareBundlesForCellValidatesBundlesBeforeSemanticProjection(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	firstRunner := &fakeRunner{resultForSpec: func(ports.ToolSpec) ports.ToolResult {
		return ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}
	}}
	secondRunner := &fakeRunner{resultForSpec: func(ports.ToolSpec) ports.ToolResult {
		return ports.ToolResult{Stdout: []byte("{\n  \"descriptor\": {\"name\": \"grype\", \"version\": \"1.2.3\"},\n  \"matches\": []\n}\n")}
	}}
	first, err := NewCapturer(firstRunner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCapturer(secondRunner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if first.Observation().RawOutputDigest == second.Observation().RawOutputDigest {
		t.Fatal("test setup did not produce distinct raw provenance")
	}
	root := t.TempDir()
	leftPath := filepath.Join(root, "first")
	rightPath := filepath.Join(root, "second")
	if err := WriteBundle(leftPath, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(rightPath, second); err != nil {
		t.Fatal(err)
	}
	comparison, err := CompareBundlesForCell(leftPath, rightPath, manifest.TargetID, manifest.Engine, bench.ObservationComplete)
	if err != nil {
		t.Fatalf("compare validated semantic bundles: %v", err)
	}
	if !comparison.SemanticEqual || comparison.Left.RawOutputDigest == comparison.Right.RawOutputDigest {
		t.Fatal("semantic comparison did not retain distinct raw provenance while accepting equal claims")
	}
}
