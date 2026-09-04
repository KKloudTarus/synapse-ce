package findinglineage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestSCAMatcherV1GoldenAliasVersionAndPackageNormalization(t *testing.T) {
	matcher, err := NewSCAMatcherV1([]SCAAdvisoryAliasSetV1{{
		Primary: "CVE-2026-1234", Aliases: []string{"GHSA-AAAA-BBBB-CCCC", "OSV-2026-1"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := matcher.Descriptor().Validate(); err != nil {
		t.Fatal(err)
	}
	first, err := matcher.Build(SCAFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", AdvisoryID: "cve-2026-1234",
		PackagePURL:    "pkg:NPM/%40scope/package@1.0.0?B=2&a=1#src",
		DependencyPath: []string{"pkg:npm/root@1.0.0", "pkg:npm/%40scope/package@1.0.0?b=2&a=1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := matcher.Build(SCAFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", AdvisoryID: "ghsa-aaaa-bbbb-cccc",
		PackagePURL:    "pkg:npm/%40scope/package@9.9.9?a=1&b=2",
		DependencyPath: []string{"pkg:npm/root@2.0.0", "pkg:npm/%40scope/package@9.9.9?a=1&b=2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstFingerprint, err := domain.CanonicalizeFingerprintV1(first.FingerprintInput)
	if err != nil {
		t.Fatal(err)
	}
	secondFingerprint, err := domain.CanonicalizeFingerprintV1(second.FingerprintInput)
	if err != nil {
		t.Fatal(err)
	}
	if firstFingerprint.Fingerprint != secondFingerprint.Fingerprint {
		t.Fatalf("alias or package version changed lineage: %s != %s", firstFingerprint.Fingerprint, secondFingerprint.Fingerprint)
	}
	const wantFingerprint = "e5d98c5ff678117dc71f9dabb82b23603ae42d9bd3daa3a7e41e22d736ad690c"
	if firstFingerprint.Fingerprint != wantFingerprint {
		t.Fatalf("fingerprint=%s want=%s canonical=%s", firstFingerprint.Fingerprint, wantFingerprint, firstFingerprint.Bytes)
	}
	if strings.Contains(string(firstFingerprint.Bytes), "1.0.0") || strings.Contains(string(firstFingerprint.Bytes), "9.9.9") {
		t.Fatalf("component version leaked into identity: %s", firstFingerprint.Bytes)
	}

	reversed := first
	reversed.FingerprintInput.IdentityFields = cloneCanonicalFields(first.FingerprintInput.IdentityFields)
	reversed.FingerprintInput.IdentityFields["dependency_path"] = domain.OrderedArray(
		domain.Text("pkg:npm/%40scope/package?a=1&b=2"), domain.Text("pkg:npm/root"),
	)
	reversedFingerprint, err := domain.CanonicalizeFingerprintV1(reversed.FingerprintInput)
	if err != nil {
		t.Fatal(err)
	}
	if reversedFingerprint.Fingerprint == firstFingerprint.Fingerprint {
		t.Fatal("dependency path order must be semantic")
	}
}

func TestSCAMatcherV1InstancesConflictAndLegacyFallback(t *testing.T) {
	matcher, err := NewSCAMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := SCAFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", AdvisoryID: "CVE-2026-44",
		PackageEcosystem: "PyPI", PackageName: "Django.rest_framework", DependencyInstanceID: "lock:1",
	}
	first, err := matcher.Build(base)
	if err != nil {
		t.Fatal(err)
	}
	base.DependencyInstanceID = "lock:2"
	second, err := matcher.Build(base)
	if err != nil {
		t.Fatal(err)
	}
	firstFingerprint, _ := domain.CanonicalizeFingerprintV1(first.FingerprintInput)
	secondFingerprint, _ := domain.CanonicalizeFingerprintV1(second.FingerprintInput)
	if firstFingerprint.Fingerprint == secondFingerprint.Fingerprint {
		t.Fatal("distinct dependency instances collapsed")
	}
	if !strings.Contains(string(firstFingerprint.Bytes), `"package_coordinate":"pkg:pypi/django-rest-framework"`) {
		t.Fatalf("PyPI coordinate was not normalized: %s", firstFingerprint.Bytes)
	}

	conflict, err := matcher.Build(SCAFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", AdvisoryID: "CVE-2026-1", AdvisoryAliases: []string{"CVE-2026-2"},
		PackagePURL: "pkg:golang/example.com/mod@v1.0.0", DependencyInstanceID: "go.mod:example.com/mod",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !conflict.Ambiguous || conflict.ReviewReason != domain.ReasonMerge || conflict.ReasonCode != "advisory_alias_conflict" {
		t.Fatalf("conflict plan=%+v", conflict)
	}

	legacy, err := matcher.Build(SCAFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", PackageEcosystem: "npm", PackageName: "left-pad",
		DependencyInstanceID: "package-lock:17", LegacyDedupKey: "vuln:CVE-2026-9:left-pad:1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Ambiguous || legacy.ReasonCode != "sca_identity_complete" {
		t.Fatalf("legacy plan=%+v", legacy)
	}
	legacyFingerprint, err := domain.CanonicalizeFingerprintV1(legacy.FingerprintInput)
	if err != nil || strings.Contains(string(legacyFingerprint.Bytes), "1.0.0") {
		t.Fatalf("legacy fingerprint=%s err=%v", legacyFingerprint.Bytes, err)
	}

	mapped := SCAFingerprintInputFromVulnerabilityV1("repo:example", vulnerability.Vulnerability{
		ID: "CVE-2026-10", Ecosystem: "npm", Component: "left-pad", Version: "4.0.0",
		PackagePURL: "pkg:npm/left-pad@4.0.0", Path: []string{"pkg:npm/root@1", "pkg:npm/left-pad@4"},
	}, []string{"GHSA-AAAA-BBBB-DDDD"}, "vuln:CVE-2026-10:left-pad:4.0.0", "")
	if mapped.AdvisoryID != "CVE-2026-10" || mapped.PackagePURL == "" || len(mapped.DependencyPath) != 2 || mapped.LegacyDedupKey == "" {
		t.Fatalf("mapped vulnerability=%+v", mapped)
	}
}

func TestSCAMatcherV1CorrelatesUpgradeAndPersistsProvisionalReview(t *testing.T) {
	matcher, err := NewSCAMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	repository := memory.NewFindingLineageRepository()
	clock := fixedClock{now: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)}
	service, err := NewService(repository, immediateTransactions{}, &collectingAudit{}, clock, &sequenceIDs{}, &collectingObserver{})
	if err != nil {
		t.Fatal(err)
	}

	build := func(version, snapshot, source string) Result {
		plan, err := matcher.Build(SCAFingerprintInputV1{
			TargetIdentityCanonical: "repo:example", AdvisoryID: "CVE-2026-77",
			PackagePURL: "pkg:npm/left-pad@" + version, DependencyInstanceID: "package-lock:17",
		})
		if err != nil {
			t.Fatal(err)
		}
		input := plan.Apply(correlateInput(snapshot, "unused"))
		input.SnapshotID = shared.ID(snapshot)
		input.Observation.ID = shared.ID("observation-" + snapshot)
		input.Observation.SourceFindingID = source
		input.Observation.ComponentVersion = version
		result, err := service.Correlate(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := build("1.0.0", "snapshot-1", "source-1")
	second := build("2.0.0", "snapshot-2", "source-2")
	if first.Outcome != OutcomeCreated || second.Outcome != OutcomeMatched || first.Identity.ID != second.Identity.ID {
		t.Fatalf("upgrade correlation first=%+v second=%+v", first, second)
	}

	plan, err := matcher.Build(SCAFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", AdvisoryID: "CVE-2026-88", PackagePURL: "pkg:npm/other@1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ProvisionalIdentity || plan.ReasonCode != "insufficient_dependency_instance" {
		t.Fatalf("provisional plan=%+v", plan)
	}
	input := plan.Apply(correlateInput("provisional", "unused"))
	input.Observation.SourceFindingID = "producer-secret-free-id"
	result, err := service.Correlate(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeReview || result.Identity == nil || result.Observation == nil || result.Candidate == nil || result.Reason != "insufficient_dependency_instance" {
		t.Fatalf("provisional result=%+v", result)
	}
	if len(result.Candidate.Refs) != 2 || result.Candidate.Refs[1].IdentityID != result.Identity.ID {
		t.Fatalf("provisional refs=%+v", result.Candidate.Refs)
	}
	if strings.Contains(string(result.Identity.CanonicalIdentityFields), input.Observation.SourceFindingID) {
		t.Fatalf("raw source id leaked into provisional identity: %s", result.Identity.CanonicalIdentityFields)
	}
}

func TestSCAMatcherV1RejectsMissingTargetAndServiceOwnedField(t *testing.T) {
	matcher, err := NewSCAMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := matcher.Build(SCAFingerprintInputV1{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing target error=%v", err)
	}
	if _, err := matcher.Build(SCAFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", AdvisoryID: "CVE-2026-1",
		PackagePURL: "pkg:npm/left-pad@1?api_token=must-not-hash", DependencyInstanceID: "lock:1",
	}); !errors.Is(err, domain.ErrSensitiveInput) {
		t.Fatalf("sensitive qualifier error=%v", err)
	}
	if _, err := matcher.Build(SCAFingerprintInputV1{
		TargetIdentityCanonical: "https://user:password@example.test/repo", AdvisoryID: "CVE-2026-1",
		PackagePURL: "pkg:npm/left-pad@1", DependencyInstanceID: "lock:1",
	}); !errors.Is(err, domain.ErrSensitiveInput) {
		t.Fatalf("sensitive target error=%v", err)
	}
	input := correlateInput("reserved", "rule")
	input.FingerprintInput.IdentityFields["provisional_source_reference_hash"] = domain.Text("caller-controlled")
	if _, err := (&Service{}).Correlate(context.Background(), input); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("reserved field error=%v", err)
	}
}

func cloneCanonicalFields(input map[string]domain.CanonicalValue) map[string]domain.CanonicalValue {
	output := make(map[string]domain.CanonicalValue, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
