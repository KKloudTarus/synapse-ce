package reachbench

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func TestBuildBaselineAllowlistNormalizesExactDiff(t *testing.T) {
	allowlist, err := BuildBaselineAllowlist("reviewed-harness-delta", []byte(
		"M\x00internal/infrastructure/reachbench/runner.go\x00"+
			"A\x00cmd/synapse-reachability-cycle/main.go\x00",
	))
	if err != nil {
		t.Fatal(err)
	}
	want := []BaselineAllowlistEntry{
		{Status: "A", Path: "cmd/synapse-reachability-cycle/main.go"},
		{Status: "M", Path: "internal/infrastructure/reachbench/runner.go"},
	}
	if !sameCanonical(allowlist.Entries, want) {
		t.Fatalf("allowlist entries = %#v, want %#v", allowlist.Entries, want)
	}
	for _, raw := range [][]byte{
		[]byte("D\x00internal/infrastructure/reachbench/runner.go\x00"),
		[]byte("M\x00internal/infrastructure/reachbench/runner.go"),
	} {
		if _, err := BuildBaselineAllowlist("reviewed-harness-delta", raw); err == nil {
			t.Fatalf("unsafe diff %q produced an allowlist", raw)
		}
	}
}

func TestBuildProtectedBaselineControllerAssetsIsDeterministicAndRouteScoped(t *testing.T) {
	fixture := newFixture(t)
	first := buildProtectedAssets(t, fixture)
	second := buildProtectedAssets(t, fixture)
	for name, pair := range map[string]struct{ left, right []byte }{
		"baseline input":     {first.BaselineInputJSON, second.BaselineInputJSON},
		"baseline allowlist": {first.BaselineAllowlistJSON, second.BaselineAllowlistJSON},
		"trusted bundle":     {first.TrustedBundleJSON, second.TrustedBundleJSON},
		"envelope":           {first.EnvelopeJSON, second.EnvelopeJSON},
	} {
		if !bytes.Equal(pair.left, pair.right) {
			t.Fatalf("%s bytes are not deterministic", name)
		}
		assertOneNewline(t, name, pair.left)
	}
	if first.BaselineInputRef.Digest != benchmark.SHA256Digest(trimOneNewline(t, first.BaselineInputJSON)) {
		t.Fatal("baseline input reference does not bind canonical bytes")
	}
	if err := first.TrustedBundle.ValidateRoute(RouteProtectedBaseline); err != nil {
		t.Fatalf("baseline-only bundle rejected on protected route: %v", err)
	}
	if err := first.TrustedBundle.ValidateRoute(RouteCandidate); err == nil {
		t.Fatal("baseline-only bundle was accepted on candidate route")
	}
	if err := first.TrustedBundle.ValidateRoute(RouteLocalDiagnostic); err == nil {
		t.Fatal("baseline-only bundle was accepted on local route")
	}
	if first.TrustedBundle.CandidateInput != nil {
		t.Fatal("protected baseline bundle unexpectedly contains a candidate input")
	}
	wrongAnalyzer := fixture.baselineAnalyzer
	wrongAnalyzer.Commit = strings.Repeat("f", 40)
	if _, err := BuildProtectedBaselineControllerAssets(fixture.baselineAllowlist, fixture.harness, wrongAnalyzer, "controller", reference("review-record")); err == nil {
		t.Fatal("protected baseline assets accepted an analyzer identity other than the fixed baseline revision")
	}
}

func TestBuildCandidateControllerAssetsBindsCapturedBaselineAndIdentityEvidence(t *testing.T) {
	fixture := newFixture(t)
	protected := buildProtectedAssets(t, fixture)
	report, manifest := captureProtectedBaseline(t, fixture, protected)
	if manifest.BaselineAllowlist == nil {
		t.Fatal("protected baseline did not publish its allowlist result")
	}
	assets, err := BuildCandidateControllerAssets(
		report,
		manifest,
		*manifest.BaselineAllowlist,
		fixture.baselineAllowlist,
		reference("candidate-review"),
		reference("candidate-disposition"),
		CheckpointActors{Producer: "producer", Reviewer: "reviewer", Maintainer: "maintainer"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := assets.CandidateInput.Validate(); err != nil {
		t.Fatalf("generated candidate input is invalid: %v", err)
	}
	if assets.CandidateInput.Baseline == nil || assets.CandidateInput.Checkpoint == nil || assets.CandidateInput.Ratchet == nil {
		t.Fatal("candidate input omits required lifecycle artifacts")
	}
	if assets.Checkpoint.Producer == assets.Checkpoint.Reviewer || assets.Checkpoint.Reviewer == assets.Checkpoint.Maintainer || assets.Checkpoint.Producer == assets.Checkpoint.Maintainer {
		t.Fatalf("checkpoint actors are not distinct: %+v", assets.Checkpoint)
	}
	if err := assets.TrustedBundle.ValidateRoute(RouteCandidate); err != nil {
		t.Fatalf("candidate bundle rejected on candidate route: %v", err)
	}
	if err := assets.TrustedBundle.ValidateRoute(RouteLocalDiagnostic); err != nil {
		t.Fatalf("candidate bundle rejected on local route: %v", err)
	}
	for name, encoded := range map[string][]byte{
		"baseline input":            assets.BaselineInputJSON,
		"candidate input":           assets.CandidateInputJSON,
		"baseline allowlist":        assets.BaselineAllowlistJSON,
		"baseline allowlist result": assets.BaselineAllowlistResultJSON,
		"trusted bundle":            assets.TrustedBundleJSON,
		"baseline report":           assets.BaselineReportJSON,
		"checkpoint":                assets.CheckpointJSON,
		"ratchet":                   assets.RatchetJSON,
	} {
		assertOneNewline(t, name, encoded)
	}
	if assets.CandidateInputRef.Digest != benchmark.SHA256Digest(trimOneNewline(t, assets.CandidateInputJSON)) {
		t.Fatal("candidate input reference does not bind canonical bytes")
	}
	if assets.CheckpointRef.Digest != benchmark.SHA256Digest(trimOneNewline(t, assets.CheckpointJSON)) {
		t.Fatal("checkpoint reference does not bind canonical bytes")
	}
	if assets.BaselineAllowlistResultRef.Digest != benchmark.SHA256Digest(trimOneNewline(t, assets.BaselineAllowlistResultJSON)) {
		t.Fatal("baseline allowlist result reference does not bind canonical bytes")
	}
	if assets.Checkpoint.AllowlistEvidence != assets.BaselineAllowlistResultRef {
		t.Fatalf("checkpoint allowlist evidence = %+v, want published result %+v", assets.Checkpoint.AllowlistEvidence, assets.BaselineAllowlistResultRef)
	}
	candidateRoot := t.TempDir()
	for path, encoded := range map[string][]byte{
		"baseline-input.json":     assets.BaselineInputJSON,
		"candidate-input.json":    assets.CandidateInputJSON,
		"baseline-allowlist.json": assets.BaselineAllowlistJSON,
		"trusted-bundle.json":     assets.TrustedBundleJSON,
	} {
		if err := os.WriteFile(filepath.Join(candidateRoot, path), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &Runner{}
	bundle, _, err := runner.loadBundle(candidateRoot, RouteCandidate)
	if err != nil {
		t.Fatalf("candidate asset bundle cannot be loaded: %v", err)
	}
	if _, err := runner.loadInputTemplate(candidateRoot, *bundle.CandidateInput, measurement.CandidateAcceptance); err != nil {
		t.Fatalf("candidate asset input cannot be loaded: %v", err)
	}

	wrongManifest := manifest
	wrongManifest.Bundle = reference("substituted-bundle")
	if _, err := BuildCandidateControllerAssets(report, wrongManifest, *manifest.BaselineAllowlist, fixture.baselineAllowlist, reference("candidate-review"), reference("candidate-disposition"), CheckpointActors{Producer: "producer", Reviewer: "reviewer", Maintainer: "maintainer"}); err == nil {
		t.Fatal("candidate assets accepted a substituted protected-baseline bundle")
	}
	mutatedAllowlistResult := *manifest.BaselineAllowlist
	mutatedAllowlistResult.ChangedEntryDigest = reference("substituted-entry-digest").Digest
	if _, err := BuildCandidateControllerAssets(report, manifest, mutatedAllowlistResult, fixture.baselineAllowlist, reference("candidate-review"), reference("candidate-disposition"), CheckpointActors{Producer: "producer", Reviewer: "reviewer", Maintainer: "maintainer"}); err == nil {
		t.Fatal("candidate assets accepted a mutated published baseline allowlist result")
	}
	if _, err := BuildCandidateControllerAssets(report, manifest, *manifest.BaselineAllowlist, fixture.baselineAllowlist, reference("candidate-review"), reference("candidate-review"), CheckpointActors{Producer: "producer", Reviewer: "reviewer", Maintainer: "maintainer"}); err == nil {
		t.Fatal("candidate assets accepted identical review and disposition evidence")
	}
	if _, err := BuildCandidateControllerAssets(report, manifest, *manifest.BaselineAllowlist, fixture.baselineAllowlist, reference("candidate-review"), reference("candidate-disposition"), CheckpointActors{Producer: "same", Reviewer: "same", Maintainer: "maintainer"}); err == nil {
		t.Fatal("candidate assets accepted non-independent checkpoint actors")
	}
}

func TestFrozenTemplateStaticContractRejectsSubstitution(t *testing.T) {
	input, err := measurement.DefaultBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	input.ActiveSnapshot.Source = reference("substituted-source")
	if err := input.Validate(); err != nil {
		t.Fatalf("substitution test input must remain structurally valid: %v", err)
	}
	root := t.TempDir()
	encoded := canonicalTestJSON(t, input)
	writeCanonicalTestFile(t, filepath.Join(root, "baseline-input.json"), input)
	runner := &Runner{}
	if _, err := runner.loadInputTemplate(root, BundleAsset{Path: "baseline-input.json", Digest: benchmark.SHA256Digest(encoded)}, measurement.BaselineMeasurement); err == nil || !strings.Contains(err.Error(), "frozen default contract") {
		t.Fatalf("template loader accepted a static contract substitution: %v", err)
	}
}

func buildProtectedAssets(t *testing.T, fixture fixture) ProtectedBaselineControllerAssets {
	t.Helper()
	assets, err := BuildProtectedBaselineControllerAssets(
		fixture.baselineAllowlist,
		fixture.harness,
		fixture.baselineAnalyzer,
		"controller",
		reference("review-record"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return assets
}

func captureProtectedBaseline(t *testing.T, fixture fixture, assets ProtectedBaselineControllerAssets) (measurement.MeasurementReport, LifecycleManifest) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.controllerBundleRoot, "baseline-input.json"), assets.BaselineInputJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.controllerBundleRoot, "baseline-allowlist.json"), assets.BaselineAllowlistJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.controllerBundleRoot, "trusted-bundle.json"), assets.TrustedBundleJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(fixture.tempRoot, filepath.FromSlash(controllerEnvelopeDirectory), assets.EnvelopeFileName)
	if err := os.MkdirAll(filepath.Dir(envelopePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envelopePath, assets.EnvelopeJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(
		fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: envelopePath}),
		captureFunc(validCapture(fixture.expected)),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var report measurement.MeasurementReport
	if _, err := readCanonicalJSON(filepath.Join(result.Output, "repetition-1", "report.json"), &report); err != nil {
		t.Fatal(err)
	}
	return report, result.Manifest
}

func assertOneNewline(t *testing.T, name string, encoded []byte) {
	t.Helper()
	if len(encoded) < 2 || encoded[len(encoded)-1] != '\n' || encoded[len(encoded)-2] == '\n' {
		t.Fatalf("%s is not exactly one-newline canonical JSON", name)
	}
}

func trimOneNewline(t *testing.T, encoded []byte) []byte {
	t.Helper()
	assertOneNewline(t, "canonical JSON", encoded)
	return encoded[:len(encoded)-1]
}
