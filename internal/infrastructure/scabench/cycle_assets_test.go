package scabench

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestVerifyFreshCycleAssetsRequiresResolvableDigestCheckedRegularAssets(t *testing.T) {
	root := t.TempDir()
	writeCycleAsset(t, root, "sources/oracle.json", []byte("source"))
	writeCycleAsset(t, root, "citations/case-a.json", []byte("citation"))
	freeze, candidate := freshCycleAssets(t, root)
	if err := VerifyFreshCycleAssets(root, freeze, candidate); err != nil {
		t.Fatalf("verify fresh cycle assets: %v", err)
	}

	candidate.Cases[0].Citations[0].Digest = digestByte('f')
	if err := VerifyFreshCycleAssets(root, freeze, candidate); err == nil {
		t.Fatal("VerifyFreshCycleAssets accepted a citation digest mismatch")
	}
}

func TestRepositoryAssetLocatorsRejectEscapeForms(t *testing.T) {
	for _, locator := range []string{
		"file:///outside.json",
		"/outside.json",
		"../outside.json",
		"sources/../outside.json",
		"C:/outside.json",
		"sources\\outside.json",
	} {
		t.Run(locator, func(t *testing.T) {
			asset := bench.ContentReference{Locator: locator, Digest: digestByte('a'), Size: 1}
			if err := asset.Validate(); err == nil {
				t.Fatal("ContentReference.Validate accepted an escaping locator")
			}
		})
	}
}

func TestVerifyRepositoryAssetsRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	writeCycleAsset(t, root, "sources/real.json", []byte("real"))
	link := filepath.Join(root, "sources", "link.json")
	if err := os.Symlink(filepath.Join(root, "sources", "real.json"), link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	asset := bench.ContentReference{Locator: "sources/link.json", Digest: bench.SHA256Digest([]byte("real")), Size: int64(len("real"))}
	if err := VerifyRepositoryAssets(root, []bench.ContentReference{asset}); err == nil {
		t.Fatal("VerifyRepositoryAssets accepted a symlink")
	}
}

func freshCycleAssets(t *testing.T, root string) (bench.SourceFreeze, bench.OracleCandidate) {
	t.Helper()
	source := []byte("source")
	citation := []byte("citation")
	writeCycleAsset(t, root, "reviews/github/review-1.json", testGitHubReviewCapture("approved"))
	assets := []bench.ContentReference{{Locator: "sources/oracle.json", Digest: bench.SHA256Digest(source), Size: int64(len(source))}}
	contentDigest, err := bench.DigestContentReferences(assets)
	if err != nil {
		t.Fatal(err)
	}
	freeze := bench.SourceFreeze{SchemaVersion: bench.SourceFreezeSchemaVersion, CycleID: "fresh-cycle", Assets: assets, ContentDigest: contentDigest}
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	candidate := bench.OracleCandidate{
		SchemaVersion:      bench.OracleCandidateSchemaVersion,
		CycleID:            freeze.CycleID,
		SourceFreezeDigest: freezeDigest,
		Cases: []bench.OracleCandidateCase{{
			ID: "case-a", TargetID: "target-a", Component: bench.Component{PURL: "pkg:deb/debian/a@1", Version: "1"}, AdvisoryID: "CVE-2026-0001", Truth: bench.TruthAffected, Rationale: "public independent source", Citations: []bench.ContentReference{{Locator: "citations/case-a.json", Digest: bench.SHA256Digest(citation), Size: int64(len(citation))}},
		}},
	}
	return freeze, candidate
}

func testGitHubReviewCapture(decision string) []byte {
	state := "COMMENTED"
	switch decision {
	case "approved":
		state = "APPROVED"
	case "rejected":
		state = "CHANGES_REQUESTED"
	}
	return []byte(fmt.Sprintf(`{"schema_version":%q,"id":"1","url":"https://github.com/example/repository/pull/1#pullrequestreview-1","login":"reviewer","state":%q,"submitted_at":"2026-09-15T12:00:00Z","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","body":%q}`,
		bench.GitHubReviewCaptureSchemaVersion, state, "decision: "+decision))
}

func writeCycleAsset(t *testing.T, root, relative string, content []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
