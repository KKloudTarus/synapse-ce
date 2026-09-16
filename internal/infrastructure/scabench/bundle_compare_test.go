package scabench

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestCompareBundlesValidatesBothAndRetainsRawRoots(t *testing.T) {
	left := writeComparableGrypeBundle(t, `{"descriptor":{"name":"grype","version":"1.2.3","timestamp":"2026-01-01T00:00:00Z"},"matches":[]}`)
	right := writeComparableGrypeBundle(t, `{"descriptor":{"name":"grype","version":"1.2.3","timestamp":"2026-01-01T00:00:01Z"},"matches":[]}`)
	report, err := CompareBundles(left, right, bench.EngineGrype)
	if err != nil {
		t.Fatal(err)
	}
	if !report.SemanticEqual || len(report.AllowedDifferences) != 1 || report.Left.RootDigest == report.Right.RootDigest {
		t.Fatalf("semantic report = %+v", report)
	}
	if report.AllowedDifferences[0].Path != "$.scan.stdout.$.descriptor.timestamp" {
		t.Fatalf("allowed difference = %+v", report.AllowedDifferences[0])
	}
	identity, err := BundleIdentityFromPath(left)
	if err != nil {
		t.Fatalf("derive bundle identity: %v", err)
	}
	_, observation, _, err := inspectBundleIdentity(left)
	if err != nil {
		t.Fatal(err)
	}
	cycleIdentity, err := CycleEvidenceIdentityFromBundle(identity, bench.NativeTargetEvidence{TargetID: observation.TargetID, TargetDigest: observation.TargetDigest, PackageFamily: "deb", Comparisons: []bench.NativeComparisonRecord{{SchemaVersion: bench.NativeComparisonSchemaVersion, ID: "comparison", TargetID: observation.TargetID, TargetDigest: observation.TargetDigest, PackageFamily: "deb", PackageIdentity: "binary:fixture", CandidateEVR: "1", FixedEVR: "2", Relation: "before", Method: "target-native-dpkg", ExecutionDigest: digestByte('a')}}})
	if err != nil || cycleIdentity.NativeComparisonDigest == "" {
		t.Fatalf("derive cycle evidence identity = %+v, %v", cycleIdentity, err)
	}

	if err := os.WriteFile(filepath.Join(right, "unexpected.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CompareBundles(left, right, bench.EngineGrype); err == nil {
		t.Fatal("comparison accepted an invalid bundle")
	}
}

func TestSemanticRawPoliciesFailClosedOnUnclassifiedChanges(t *testing.T) {
	grypeLeft := []byte(`{"descriptor":{"timestamp":"one"},"matches":[]}`)
	grypeRight := []byte(`{"descriptor":{"timestamp":"two","unexpected":true},"matches":[]}`)
	if _, differences := compareGrypeRaw(grypeLeft, grypeRight); len(differences) == 0 {
		t.Fatal("grype policy accepted an unclassified field")
	}
	if _, differences := compareGrypeRaw([]byte(`{"descriptor":{"timestamp":"one","timestamp":"two"},"matches":[]}`), grypeLeft); len(differences) == 0 {
		t.Fatal("grype policy accepted duplicate JSON keys")
	}

	trivyLeft := []byte(`{"CreatedAt":"one","ReportID":"one","Results":[{"Vulnerabilities":[{"Fingerprint":"one","FixedVersion":"1"}]}]}`)
	trivyRight := []byte(`{"CreatedAt":"two","ReportID":"two","Results":[{"Vulnerabilities":[{"Fingerprint":"two","FixedVersion":"1"}]}]}`)
	if allowed, differences := compareTrivyRaw(trivyLeft, trivyRight); len(differences) != 0 || len(allowed) != 3 {
		t.Fatalf("trivy narrow policy = allowed=%+v differences=%v", allowed, differences)
	}
	trivyRight = []byte(`{"CreatedAt":"two","ReportID":"two","Results":[{"Vulnerabilities":[{"Fingerprint":"two","FixedVersion":"2"}]}]}`)
	if _, differences := compareTrivyRaw(trivyLeft, trivyRight); len(differences) == 0 {
		t.Fatal("trivy policy accepted a fixed-version change")
	}

	osvLeft := []byte("Neither CPE nor PURL found for package: {\"Name\":\"a\",\"Hashes\":[\"one\"]}\nEnd status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time\n")
	osvRight := []byte("Neither CPE nor PURL found for package: {\"Name\":\"a\",\"Hashes\":[\"two\"]}\nEnd status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 3ms elapsed, 4ms wall time\n")
	if allowed, differences := compareOSVRaw(osvLeft, osvRight); len(differences) != 0 || len(allowed) != 2 {
		t.Fatalf("OSV narrow policy = allowed=%+v differences=%v", allowed, differences)
	}
	osvRight = []byte("Neither CPE nor PURL found for package: {\"Name\":\"a\",\"Hashes\":null}\nEnd status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 3ms elapsed, 4ms wall time\n")
	if _, differences := compareOSVRaw(osvLeft, osvRight); len(differences) == 0 {
		t.Fatal("OSV policy accepted pointer versus nil")
	}
}

func TestCompareOSVRawNormalizesLivePointerDiagnostics(t *testing.T) {
	left := []byte(
		osvPointerDiagnosticPrefix + "{Type:library Name:a Hashes:0xc000010100 ExternalReferences:0xc000010200 Properties:0xc000010300 SWID:0xc000010400}\n" +
			osvPointerDiagnosticPrefix + "{Type:library Name:b Hashes:0xc000010500 ExternalReferences:<nil> Properties:<nil> SWID:<nil>}\n" +
			"End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time\n" +
			"stable post-scan status\n",
	)
	right := []byte(
		osvPointerDiagnosticPrefix + "{Type:library Name:a Hashes:0xc000020100 ExternalReferences:0xc000020200 Properties:0xc000020300 SWID:0xc000020400}\n" +
			osvPointerDiagnosticPrefix + "{Type:library Name:b Hashes:0xc000020500 ExternalReferences:<nil> Properties:<nil> SWID:<nil>}\n" +
			"End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 3ms elapsed, 4ms wall time\n" +
			"stable post-scan status\n",
	)
	allowed, differences := compareOSVRaw(left, right)
	if len(differences) != 0 || len(allowed) != 6 {
		t.Fatalf("OSV live-shaped policy = allowed=%+v differences=%v", allowed, differences)
	}
	paths := make(map[string]struct{}, len(allowed))
	for _, difference := range allowed {
		paths[difference.Path] = struct{}{}
	}
	for _, path := range []string{
		"$.scan.stderr.lines[0].ExternalReferences",
		"$.scan.stderr.lines[0].Hashes",
		"$.scan.stderr.lines[0].Properties",
		"$.scan.stderr.lines[0].SWID",
		"$.scan.stderr.lines[1].Hashes",
		"$.scan.stderr.lines[2].timing",
	} {
		if _, exists := paths[path]; !exists {
			t.Fatalf("OSV allowed differences omit %s: %+v", path, allowed)
		}
	}
}

func TestCompareOSVRawRejectsUnclassifiedLiveDiagnosticChanges(t *testing.T) {
	valid := osvPointerDiagnosticPrefix + "{Type:library Name:a Hashes:0xc000010100 ExternalReferences:<nil> Properties:<nil> SWID:<nil>}\n"
	tests := map[string][2]string{
		"semantic field": {
			valid,
			osvPointerDiagnosticPrefix + "{Type:library Name:b Hashes:0xc000020100 ExternalReferences:<nil> Properties:<nil> SWID:<nil>}\n",
		},
		"unknown pointer field": {
			osvPointerDiagnosticPrefix + "{Type:library Name:a Supplier:0xc000010100 Hashes:<nil>}\n",
			osvPointerDiagnosticPrefix + "{Type:library Name:a Supplier:0xc000020100 Hashes:<nil>}\n",
		},
		"duplicate selected field": {
			osvPointerDiagnosticPrefix + "{Type:library Name:a Hashes:0xc000010100 Hashes:0xc000010200}\n",
			valid,
		},
		"malformed struct": {
			osvPointerDiagnosticPrefix + "{Type:library Name:a Hashes:0xc000010100\n",
			valid,
		},
		"malformed pointer": {
			osvPointerDiagnosticPrefix + "{Type:library Name:a Hashes:0xwrong}\n",
			valid,
		},
		"invalid selected field": {
			osvPointerDiagnosticPrefix + "{Type:library Name:a Hashes:garbage}\n",
			valid,
		},
		"duplicate terminal timing": {
			valid +
				"End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time\n" +
				"End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 3ms elapsed, 4ms wall time\n",
			valid +
				"End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 5ms elapsed, 6ms wall time\n",
		},
		"timing counters": {
			valid +
				"End status: 1 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time\n",
			valid +
				"End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 3ms elapsed, 4ms wall time\n",
		},
		"pointer to nil": {
			valid,
			osvPointerDiagnosticPrefix + "{Type:library Name:a Hashes:<nil> ExternalReferences:<nil> Properties:<nil> SWID:<nil>}\n",
		},
	}
	for name, streams := range tests {
		t.Run(name, func(t *testing.T) {
			if _, differences := compareOSVRaw([]byte(streams[0]), []byte(streams[1])); len(differences) == 0 {
				t.Fatal("OSV policy accepted an unclassified live diagnostic change")
			}
		})
	}
}

func writeComparableGrypeBundle(t *testing.T, raw string) string {
	t.Helper()
	catalog, manifest := testFixture(t, bench.EngineGrype)
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(raw)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle")
	if err := WriteBundle(output, result); err != nil {
		t.Fatal(err)
	}
	return output
}
