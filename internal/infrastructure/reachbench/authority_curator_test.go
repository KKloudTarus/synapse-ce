package reachbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func TestAuthorityGitEnvironmentDropsCaseVariantGitSelectors(t *testing.T) {
	t.Setenv("gIt_DiR", filepath.Join(t.TempDir(), "untrusted-git-directory"))
	for _, entry := range authorityGitEnvironment() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "gIt_DiR") {
			t.Fatalf("authority Git environment retained inherited selector %q", entry)
		}
	}
}

type curatorGitFixture struct {
	root         string
	harness      HarnessIdentity
	baselineTree string
	status       []byte
	shallow      string
	ancestryErr  error
	diff         []byte
}

func newCuratorGitFixture(t *testing.T, entries []BaselineAllowlistEntry) curatorGitFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	return curatorGitFixture{
		root: root,
		harness: HarnessIdentity{
			ID: ReviewedHarnessID, Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40),
		},
		baselineTree: strings.Repeat("5", 40),
		shallow:      "false\n",
		diff:         encodeChangedEntries(entries),
	}
}

func (fixture curatorGitFixture) curator(t *testing.T) *AuthorityCurator {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(fixture.root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	curator, err := NewAuthorityCurator(AuthorityCuratorDependencies{
		Command: func(_ context.Context, binary string, args ...string) ([]byte, error) {
			if binary != "git" {
				return nil, fmt.Errorf("unexpected command %q", binary)
			}
			if reflect.DeepEqual(args, authorityGitInvocation("", "rev-parse", "--absolute-git-dir")) {
				return []byte(filepath.Join(fixture.root, ".git") + "\n"), nil
			}
			if reflect.DeepEqual(args, authorityGitInvocation("", "rev-parse", "--show-toplevel")) {
				return []byte(fixture.root + "\n"), nil
			}
			prefix := authorityGitInvocation(fixture.root)
			if len(args) < len(prefix) || !reflect.DeepEqual(args[:len(prefix)], prefix) {
				return nil, fmt.Errorf("unexpected Git safety argv %q", args)
			}
			switch strings.Join(args[len(prefix):], "\x00") {
			case "rev-parse\x00--absolute-git-dir":
				return []byte(filepath.Join(fixture.root, ".git") + "\n"), nil
			case "config\x00--null\x00--name-only\x00--local\x00--no-includes\x00--list",
				"config\x00--null\x00--name-only\x00--worktree\x00--no-includes\x00--list":
				return nil, nil
			case "for-each-ref\x00--format=%(refname)\x00refs/replace":
				return nil, nil
			case "rev-parse\x00--git-path\x00objects/info/alternates":
				return []byte(filepath.Join(fixture.root, ".git", "objects", "info", "alternates") + "\n"), nil
			case "rev-parse\x00--git-path\x00info/grafts":
				return []byte(filepath.Join(fixture.root, ".git", "info", "grafts") + "\n"), nil
			case "status\x00--porcelain=v1\x00-z\x00--untracked-files=all\x00--ignored=matching":
				return append([]byte(nil), fixture.status...), nil
			case "rev-parse\x00--is-shallow-repository":
				return []byte(fixture.shallow), nil
			case "rev-parse\x00--verify\x00HEAD^{commit}":
				return []byte(fixture.harness.Commit + "\n"), nil
			case "rev-parse\x00--verify\x00" + fixture.harness.Commit + "^{tree}":
				return []byte(fixture.harness.Tree + "\n"), nil
			case "rev-parse\x00--verify\x00" + measurement.TrustedBaselineRevision + "^{commit}":
				return []byte(measurement.TrustedBaselineRevision + "\n"), nil
			case "rev-parse\x00--verify\x00" + measurement.TrustedBaselineRevision + "^{tree}":
				return []byte(fixture.baselineTree + "\n"), nil
			case "merge-base\x00--is-ancestor\x00" + measurement.TrustedBaselineRevision + "\x00" + fixture.harness.Commit:
				return nil, fixture.ancestryErr
			case "diff\x00--no-ext-diff\x00--no-textconv\x00--name-status\x00--no-renames\x00-z\x00" + measurement.TrustedBaselineRevision + "..." + fixture.harness.Commit:
				return append([]byte(nil), fixture.diff...), nil
			default:
				return nil, fmt.Errorf("unexpected git argv %q", args)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return curator
}

func authorityOutput(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "output")
}

func assertAuthorityOutputAbsent(t *testing.T, output string) {
	t.Helper()
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("rejected output exists: %v", err)
	}
}

func TestAuthorityCuratorPrepareBaselineStagesDeterministicVerifiedAssets(t *testing.T) {
	entries := []BaselineAllowlistEntry{{Status: "A", Path: "cmd/synapse-reachability-cycle/main.go"}, {Status: "M", Path: "internal/infrastructure/reachbench/authority_curator.go"}}
	fixture := newCuratorGitFixture(t, entries)
	review := writeReviewEvidence(t, "baseline-review.json", "review-evidence-from-document", fixture.harness, RevisionIdentity{ID: AnalyzerSubjectID, Commit: measurement.TrustedBaselineRevision, Tree: fixture.baselineTree}, entries)
	first := authorityOutput(t)
	second := authorityOutput(t)

	if err := fixture.curator(t).PrepareBaseline(context.Background(), review, first); err != nil {
		t.Fatal(err)
	}
	if err := fixture.curator(t).PrepareBaseline(context.Background(), review, second); err != nil {
		t.Fatal(err)
	}
	firstFiles := authorityFileBytes(t, first)
	secondFiles := authorityFileBytes(t, second)
	if !reflect.DeepEqual(firstFiles, secondFiles) {
		t.Fatal("repeated protected-baseline curation did not produce byte-identical assets")
	}
	want := []string{
		"authority/baseline-review-evidence.json",
		"envelopes/baseline-" + fixture.harness.Commit + ".json",
		"trusted-bundle/baseline-allowlist.json",
		"trusted-bundle/baseline-input.json",
		"trusted-bundle/trusted-bundle.json",
	}
	if got := sortedAuthorityPaths(firstFiles); !reflect.DeepEqual(got, want) {
		t.Fatalf("staged baseline paths = %q, want %q", got, want)
	}

	bundleRoot := filepath.Join(first, authorityBundleDirectory)
	runner := &Runner{}
	bundle, bundleRef, err := runner.loadBundle(bundleRoot, RouteProtectedBaseline)
	if err != nil {
		t.Fatalf("staged baseline bundle cannot be read: %v", err)
	}
	if _, err := runner.loadInputTemplate(bundleRoot, bundle.BaselineInput, measurement.BaselineMeasurement); err != nil {
		t.Fatalf("staged baseline input cannot be read: %v", err)
	}
	if bundleRef.ID == "" || bundle.BaselineAllowlist.Path != "baseline-allowlist.json" {
		t.Fatalf("staged baseline bundle = %+v, ref = %+v", bundle, bundleRef)
	}
	parsedReview, err := readBaselineReviewEvidence(context.Background(), review)
	if err != nil {
		t.Fatal(err)
	}
	if parsedReview.Reference.ID != "review-evidence-from-document" {
		t.Fatalf("baseline review reference id = %q, want document id", parsedReview.Reference.ID)
	}
}

func TestAuthorityCuratorPrepareBaselineRejectsUntrustedCheckoutState(t *testing.T) {
	entries := []BaselineAllowlistEntry{{Status: "A", Path: "cmd/synapse-reachability-cycle/main.go"}}
	for _, test := range []struct {
		name    string
		mutate  func(*curatorGitFixture)
		contain string
	}{
		{
			name: "dirty", mutate: func(fixture *curatorGitFixture) { fixture.status = []byte("?? residue\x00") },
			contain: "pristine checkout",
		},
		{
			name: "shallow", mutate: func(fixture *curatorGitFixture) { fixture.shallow = "true\n" },
			contain: "non-shallow",
		},
		{
			name: "wrong ancestry", mutate: func(fixture *curatorGitFixture) { fixture.ancestryErr = errors.New("not ancestor") },
			contain: "baseline ancestry",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCuratorGitFixture(t, entries)
			test.mutate(&fixture)
			output := authorityOutput(t)
			review := writeReviewEvidence(t, "baseline-review.json", "baseline-review", fixture.harness, RevisionIdentity{ID: AnalyzerSubjectID, Commit: measurement.TrustedBaselineRevision, Tree: fixture.baselineTree}, entries)
			err := fixture.curator(t).PrepareBaseline(context.Background(), review, output)
			if err == nil || !strings.Contains(err.Error(), test.contain) {
				t.Fatalf("PrepareBaseline() error = %v, want %q", err, test.contain)
			}
			assertAuthorityOutputAbsent(t, output)
		})
	}
}

func TestAuthorityCuratorPrepareBaselineRejectsUnsafeInputsAndOutput(t *testing.T) {
	entries := []BaselineAllowlistEntry{{Status: "A", Path: "cmd/synapse-reachability-cycle/main.go"}}
	fixture := newCuratorGitFixture(t, entries)
	validReview := writeReviewEvidence(t, "baseline-review.json", "baseline-review", fixture.harness, RevisionIdentity{ID: AnalyzerSubjectID, Commit: measurement.TrustedBaselineRevision, Tree: fixture.baselineTree}, entries)

	nonemptyOutput := t.TempDir()
	if err := os.WriteFile(filepath.Join(nonemptyOutput, "present"), []byte("present"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.curator(t).PrepareBaseline(context.Background(), validReview, nonemptyOutput); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output error = %v", err)
	}

	nonregularReview := t.TempDir()
	if err := fixture.curator(t).PrepareBaseline(context.Background(), nonregularReview, t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("nonregular input error = %v", err)
	}

	target := validReview
	link := filepath.Join(t.TempDir(), "review-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("create review symlink: %v", err)
	}
	if err := fixture.curator(t).PrepareBaseline(context.Background(), link, t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("symlink input error = %v", err)
	}
}

func TestAuthorityCuratorPrepareBaselineRejectsReviewForDifferentHead(t *testing.T) {
	entries := []BaselineAllowlistEntry{{Status: "A", Path: "cmd/synapse-reachability-cycle/main.go"}}
	fixture := newCuratorGitFixture(t, entries)
	staleHarness := fixture.harness
	staleHarness.Commit = strings.Repeat("9", 40)
	review := writeReviewEvidence(t, "stale-review.json", "stale-review", staleHarness, RevisionIdentity{
		ID: AnalyzerSubjectID, Commit: measurement.TrustedBaselineRevision, Tree: fixture.baselineTree,
	}, entries)
	output := authorityOutput(t)
	err := fixture.curator(t).PrepareBaseline(context.Background(), review, output)
	if err == nil || !strings.Contains(err.Error(), "does not bind the inspected harness") {
		t.Fatalf("stale review error = %v", err)
	}
	assertAuthorityOutputAbsent(t, output)
}

func TestAuthorityCuratorRejectsMalformedEvidenceIdentityAndSchemas(t *testing.T) {
	validHarness := HarnessIdentity{ID: ReviewedHarnessID, Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40)}
	validAnalyzer := RevisionIdentity{ID: AnalyzerSubjectID, Commit: measurement.TrustedBaselineRevision, Tree: strings.Repeat("5", 40)}
	validReview := writeReviewEvidence(t, "review.json", "review-id", validHarness, validAnalyzer, []BaselineAllowlistEntry{{Status: "A", Path: "reviewed.go"}})
	if _, err := readBaselineReviewEvidence(context.Background(), validReview); err != nil {
		t.Fatalf("valid review evidence rejected: %v", err)
	}
	validDisposition := writeDispositionEvidence(t, "disposition.json", "disposition-id", "")
	if _, err := readBaselineDispositionEvidence(context.Background(), validDisposition); err != nil {
		t.Fatalf("valid disposition evidence rejected: %v", err)
	}

	readReview := func(ctx context.Context, file string) error {
		_, err := readBaselineReviewEvidence(ctx, file)
		return err
	}
	readDisposition := func(ctx context.Context, file string) error {
		_, err := readBaselineDispositionEvidence(ctx, file)
		return err
	}
	for _, test := range []struct {
		name string
		body string
		read func(context.Context, string) error
	}{
		{"review scalar", `"not-an-object"`, readReview},
		{"review empty object", `{}`, readReview},
		{"review missing id", `{"schema_version":"synapse-reachability-baseline-review-evidence-v1"}`, readReview},
		{"review wrong schema", `{"schema_version":"wrong","id":"review-id"}`, readReview},
		{"disposition scalar", `"not-an-object"`, readDisposition},
		{"disposition empty object", `{}`, readDisposition},
		{"disposition missing id", `{"schema_version":"synapse-reachability-baseline-disposition-evidence-v1"}`, readDisposition},
		{"disposition wrong schema", `{"schema_version":"wrong","id":"disposition-id"}`, readDisposition},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := writeRawEvidence(t, "invalid.json", test.body)
			if err := test.read(context.Background(), file); err == nil {
				t.Fatal("invalid evidence was accepted")
			}
		})
	}
}

func TestAuthorityCuratorDeriveCandidateStagesCommitReadyAssetsWithoutEnvelope(t *testing.T) {
	fixture, baselineGit, baselineAuthority, publication, review := curatedBaseline(t)
	disposition := writeDispositionEvidence(t, "candidate-disposition.json", "disposition-from-document", publication)
	first := authorityOutput(t)
	second := authorityOutput(t)
	curator := baselineGit.curator(t)
	if err := curator.DeriveCandidate(context.Background(), publication, baselineAuthority, review, disposition, first); err != nil {
		t.Fatal(err)
	}
	if err := curator.DeriveCandidate(context.Background(), publication, baselineAuthority, review, disposition, second); err != nil {
		t.Fatal(err)
	}
	firstFiles := authorityFileBytes(t, first)
	if !reflect.DeepEqual(firstFiles, authorityFileBytes(t, second)) {
		t.Fatal("repeated candidate derivation did not produce byte-identical assets")
	}
	if got := sortedAuthorityPaths(firstFiles); !reflect.DeepEqual(got, expectedCandidateAuthorityFiles()) {
		t.Fatalf("commit-ready candidate asset paths = %q, want %q", got, expectedCandidateAuthorityFiles())
	}
	if _, err := os.Stat(filepath.Join(first, authorityEnvelopeDirectory)); !os.IsNotExist(err) {
		t.Fatalf("derive candidate created envelope directory: %v", err)
	}
	provenance, err := os.ReadFile(filepath.Join(first, filepath.FromSlash(authorityProvenancePath)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(provenance, []byte("candidate_envelope")) {
		t.Fatal("candidate provenance contains an envelope reference")
	}
	for _, evidence := range []struct {
		source string
		staged string
	}{
		{review, authorityReviewEvidencePath},
		{disposition, authorityDispositionPath},
	} {
		source, err := os.ReadFile(evidence.source)
		if err != nil {
			t.Fatal(err)
		}
		staged, err := os.ReadFile(filepath.Join(first, filepath.FromSlash(evidence.staged)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(staged, source) {
			t.Fatalf("staged %s bytes differ from reviewed document", evidence.staged)
		}
	}
	authority, err := loadCandidateAuthority(context.Background(), first)
	if err != nil {
		t.Fatalf("commit-ready candidate authority cannot be loaded: %v", err)
	}
	if authority.manifest.Harness != fixture.harness {
		t.Fatalf("candidate authority baseline harness = %+v, want %+v", authority.manifest.Harness, fixture.harness)
	}
	runner := &Runner{}
	bundle, _, err := runner.loadBundle(first, RouteCandidate)
	if err != nil {
		t.Fatalf("candidate bundle cannot be read: %v", err)
	}
	if _, err := runner.loadInputTemplate(first, *bundle.CandidateInput, measurement.CandidateAcceptance); err != nil {
		t.Fatalf("candidate input cannot be read: %v", err)
	}
}

func TestAuthorityCuratorDeriveCandidateRejectsMismatchedReviewReference(t *testing.T) {
	fixture, baselineGit, baselineAuthority, publication, _ := curatedBaseline(t)
	mismatched := writeReviewEvidence(t, "different-review.json", "different-review", fixture.harness, fixture.baselineAnalyzer, fixture.baselineAllowlist.Entries)
	output := authorityOutput(t)
	err := baselineGit.curator(t).DeriveCandidate(context.Background(), publication, baselineAuthority, mismatched, writeDispositionEvidence(t, "disposition.json", "disposition-id", publication), output)
	if err == nil || !strings.Contains(err.Error(), "does not match the published baseline manifest") {
		t.Fatalf("mismatched review reference error = %v", err)
	}
	assertAuthorityOutputAbsent(t, output)
}

func TestAuthorityCuratorDeriveCandidateRejectsMismatchedDispositionReferences(t *testing.T) {
	_, baselineGit, baselineAuthority, publication, review := curatedBaseline(t)
	output := authorityOutput(t)
	disposition := writeDispositionEvidence(t, "wrong-disposition.json", "wrong-disposition", "")
	err := baselineGit.curator(t).DeriveCandidate(context.Background(), publication, baselineAuthority, review, disposition, output)
	if err == nil || !strings.Contains(err.Error(), "does not bind the published baseline artifacts") {
		t.Fatalf("mismatched disposition error = %v", err)
	}
	assertAuthorityOutputAbsent(t, output)
}

func TestCandidateAuthorityLoaderReproducesDerivedAuthorityBytes(t *testing.T) {
	fixture, baselineGit, baselineAuthority, publication, review := curatedBaseline(t)
	candidateSource := authorityOutput(t)
	disposition := writeDispositionEvidence(t, "disposition.json", "disposition-id", publication)
	if err := baselineGit.curator(t).DeriveCandidate(context.Background(), publication, baselineAuthority, review, disposition, candidateSource); err != nil {
		t.Fatal(err)
	}
	committedAuthority := filepath.Join(fixture.repositoryRoot, filepath.FromSlash(TrustedBundleRelativePath))
	copyAuthorityTree(t, candidateSource, committedAuthority)
	authority, err := loadCandidateAuthority(context.Background(), committedAuthority)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"baseline-input.json", "candidate-input.json", "baseline-allowlist.json", "trusted-bundle.json"} {
		source, err := os.ReadFile(filepath.Join(committedAuthority, name))
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		switch name {
		case "baseline-input.json":
			got = authority.baselineInputFile
		case "candidate-input.json":
			got = authority.candidateInputFile
		case "baseline-allowlist.json":
			got = authority.baselineAllowlistFile
		case "trusted-bundle.json":
			got = authority.bundleFile
		}
		if !bytes.Equal(got, source) {
			t.Fatalf("loaded authority %s does not reproduce committed bytes", name)
		}
	}
}

func TestAuthorityDirectoryInCheckoutRejectsGitMetadata(t *testing.T) {
	if _, err := authorityDirectoryInCheckout(context.Background(), t.TempDir(), ".git"); err == nil || !strings.Contains(err.Error(), ".git") {
		t.Fatalf("Git metadata authority path error = %v", err)
	}
}

func TestValidateAuthorityOutputDestinationRejectsInputOverlap(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "output")
	if err := validateAuthorityOutputDestination(output, root); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("input-overlapping output error = %v", err)
	}
}

func curatedBaseline(t *testing.T) (fixture, curatorGitFixture, string, string, string) {
	t.Helper()
	fixture := newFixture(t)
	baselineGit := newCuratorGitFixture(t, fixture.baselineAllowlist.Entries)
	baselineGit.root = fixture.repositoryRoot
	baselineGit.harness = fixture.harness
	baselineGit.baselineTree = fixture.baselineAnalyzer.Tree
	review := writeReviewEvidence(t, "baseline-review.json", "review-evidence-from-document", fixture.harness, fixture.baselineAnalyzer, fixture.baselineAllowlist.Entries)
	baselineAuthority := authorityOutput(t)
	if err := baselineGit.curator(t).PrepareBaseline(context.Background(), review, baselineAuthority); err != nil {
		t.Fatal(err)
	}
	reviewEvidence, err := readBaselineReviewEvidence(context.Background(), review)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := BuildProtectedBaselineControllerAssets(fixture.baselineAllowlist, fixture.harness, fixture.baselineAnalyzer, authorityControllerID, reviewEvidence.Reference)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, baselineGit, baselineAuthority, captureBaselinePublication(t, fixture, protected, reviewEvidence), review
}

func captureBaselinePublication(t *testing.T, fixture fixture, assets ProtectedBaselineControllerAssets, review baselineReviewEvidence) string {
	t.Helper()
	for name, body := range map[string][]byte{
		"baseline-input.json":     assets.BaselineInputJSON,
		"baseline-allowlist.json": assets.BaselineAllowlistJSON,
		"trusted-bundle.json":     assets.TrustedBundleJSON,
	} {
		if err := os.WriteFile(filepath.Join(fixture.controllerBundleRoot, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	envelopePath := filepath.Join(fixture.tempRoot, filepath.FromSlash(controllerEnvelopeDirectory), assets.EnvelopeFileName)
	if err := os.MkdirAll(filepath.Dir(envelopePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envelopePath, assets.EnvelopeJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	provisionBaselineReviewTrust(t, fixture.facts("local/fixed").controllerRoot, review)
	runner, err := NewRunner(fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: envelopePath}), captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return result.Output
}

func writeReviewEvidence(t *testing.T, name, id string, harness HarnessIdentity, analyzer RevisionIdentity, entries []BaselineAllowlistEntry) string {
	t.Helper()
	diff := encodeChangedEntries(entries)
	encodedEntries, err := benchmark.CanonicalJSON(entries)
	if err != nil {
		t.Fatal(err)
	}
	added := 0
	modified := 0
	for _, entry := range entries {
		switch entry.Status {
		case "A":
			added++
		case "M":
			modified++
		}
	}
	return writeCanonicalEvidence(t, name, baselineReviewEvidenceDocument{
		SchemaVersion: baselineReviewEvidenceSchema,
		ID:            id,
		Harness:       harness,
		Analyzer:      analyzer,
		SourceDelta: baselineReviewSourceDelta{
			Range:                 measurement.TrustedBaselineRevision + "..." + harness.Commit,
			RawDiffByteCount:      len(diff),
			RawDiffDigest:         benchmark.SHA256Digest(diff),
			NormalizedEntryCount:  len(entries),
			AddedEntryCount:       added,
			ModifiedEntryCount:    modified,
			NormalizedEntryDigest: benchmark.SHA256Digest(encodedEntries),
		},
		Checkpoints: []baselineReviewCheckpoint{{
			Name: "exact-head-review", ReviewedHead: harness.Commit, Verdict: "PASS", Confidence: "high", Findings: 0,
		}},
		CurrentChecks: []baselineReviewCheck{{Name: "focused-tests", Status: "PASS", Evidence: "focused checks passed"}},
		Findings:      []string{},
	})
}

func writeDispositionEvidence(t *testing.T, name, id, publicationDirectory string) string {
	t.Helper()
	baselineResult := measurement.ArtifactReference{ID: "baseline", Digest: "sha256:" + strings.Repeat("a", 64)}
	lifecycleManifest := measurement.ArtifactReference{ID: "manifest", Digest: "sha256:" + strings.Repeat("b", 64)}
	semanticRepeat := measurement.ArtifactReference{ID: "repeat", Digest: "sha256:" + strings.Repeat("c", 64)}
	allowlistResult := measurement.ArtifactReference{ID: "allowlist", Digest: "sha256:" + strings.Repeat("d", 64)}
	if publicationDirectory != "" {
		publication, err := loadPublishedBaseline(context.Background(), publicationDirectory)
		if err != nil {
			t.Fatal(err)
		}
		_, reportCanonical, err := canonicalMeasurementReportFile(publication.report)
		if err != nil {
			t.Fatal(err)
		}
		manifestCanonical, err := benchmark.CanonicalJSON(publication.manifest)
		if err != nil {
			t.Fatal(err)
		}
		repeatCanonical, err := benchmark.CanonicalJSON(publication.repeat)
		if err != nil {
			t.Fatal(err)
		}
		allowlistCanonical, err := benchmark.CanonicalJSON(publication.allowlistResult)
		if err != nil {
			t.Fatal(err)
		}
		baselineResult = canonicalReference(publication.report.ID, reportCanonical)
		lifecycleManifest = canonicalReference("baseline-lifecycle-manifest.json", manifestCanonical)
		semanticRepeat = canonicalReference("baseline-semantic-repeat.json", repeatCanonical)
		allowlistResult = canonicalReference("baseline-allowlist-result.json", allowlistCanonical)
	}
	return writeCanonicalEvidence(t, name, baselineDispositionEvidenceDocument{
		SchemaVersion:     baselineDispositionSchema,
		ID:                id,
		BaselineResult:    baselineResult,
		LifecycleManifest: lifecycleManifest,
		SemanticRepeat:    semanticRepeat,
		AllowlistResult:   allowlistResult,
		Decision:          "accepted_as_procedural_baseline",
		Producer:          "baseline-producer",
		Reviewer:          "baseline-reviewer",
		Maintainer:        "baseline-maintainer",
		Checks:            []baselineReviewCheck{{Name: "baseline-disposition", Status: "PASS", Evidence: "reviewed baseline accepted"}},
	})
}

func writeCanonicalEvidence(t *testing.T, name string, value any) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), name)
	encoded, _, err := canonicalJSONFile(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func writeRawEvidence(t *testing.T, name, value string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(file, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func copyAuthorityTree(t *testing.T, source, destination string) {
	t.Helper()
	files := authorityFileBytes(t, source)
	for relative, contents := range files {
		target := filepath.Join(destination, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func authorityFileBytes(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files, err := regularRelativeFiles(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]byte, len(files))
	for _, file := range files {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
		if err != nil {
			t.Fatal(err)
		}
		out[file] = body
	}
	return out
}

func sortedAuthorityPaths(files map[string][]byte) []string {
	paths := make([]string, 0, len(files))
	for file := range files {
		paths = append(paths, file)
	}
	sort.Strings(paths)
	return paths
}
