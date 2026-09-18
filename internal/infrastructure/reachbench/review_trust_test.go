package reachbench

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func newFixtureReviewTrust(t *testing.T, harness HarnessIdentity, analyzer RevisionIdentity, snapshot measurement.SnapshotIdentity, bundle measurement.ArtifactReference) (baselineReviewEvidence, baselineDispositionEvidence, candidateReviewSubject, measurement.ArtifactReference, map[string][]byte) {
	t.Helper()
	reviewDocument := baselineReviewEvidenceDocument{
		SchemaVersion: baselineReviewEvidenceSchema,
		ID:            "fixture-baseline-review",
		Harness:       harness,
		Analyzer:      analyzer,
		SourceDelta: baselineReviewSourceDelta{
			Range:                 measurement.TrustedBaselineRevision + "..." + harness.Commit,
			RawDiffByteCount:      1,
			RawDiffDigest:         benchmark.SHA256Digest([]byte("fixture-delta")),
			NormalizedEntryCount:  1,
			AddedEntryCount:       1,
			ModifiedEntryCount:    0,
			NormalizedEntryDigest: benchmark.SHA256Digest([]byte("fixture-entry")),
		},
		Checkpoints:   []baselineReviewCheckpoint{{Name: "fixture-head", ReviewedHead: harness.Commit, Verdict: "PASS", Confidence: "high", Findings: 0}},
		CurrentChecks: []baselineReviewCheck{{Name: "fixture-check", Status: "PASS", Evidence: "fixture evidence"}},
		Findings:      []string{},
	}
	review := canonicalBaselineReviewEvidence(t, reviewDocument)
	dispositionDocument := baselineDispositionEvidenceDocument{
		SchemaVersion:     baselineDispositionSchema,
		ID:                "fixture-baseline-disposition",
		BaselineResult:    reference("fixture-baseline-result"),
		LifecycleManifest: reference("fixture-lifecycle"),
		SemanticRepeat:    reference("fixture-repeat"),
		AllowlistResult:   reference("fixture-allowlist"),
		Decision:          "accepted_as_procedural_baseline",
		Producer:          "fixture-producer",
		Reviewer:          "fixture-reviewer",
		Maintainer:        "fixture-maintainer",
		Checks:            []baselineReviewCheck{{Name: "fixture-disposition", Status: "PASS", Evidence: "fixture evidence"}},
	}
	disposition := canonicalBaselineDispositionEvidence(t, dispositionDocument)
	objects := make(map[string][]byte, len(expectedCandidateAuthorityFiles()))
	inventory := make([]candidateAuthorityInventoryEntry, 0, len(expectedCandidateAuthorityFiles()))
	for index, relative := range expectedCandidateAuthorityFiles() {
		object := fmt.Sprintf("%040x", index+1)
		body := []byte("fixture committed authority " + relative)
		objects[object] = body
		inventory = append(inventory, candidateAuthorityInventoryEntry{Path: relative, Mode: "100644", Digest: benchmark.SHA256Digest(body)})
	}
	inventoryDigest, err := candidateAuthorityInventoryDigest(inventory)
	if err != nil {
		t.Fatal(err)
	}
	subject := candidateReviewSubject{
		SchemaVersion:               candidateReviewSubjectSchema,
		ID:                          "candidate-review-" + harness.Commit,
		RepositoryID:                reachabilityRepositoryID,
		Harness:                     harness,
		AuthorityRoot:               TrustedBundleRelativePath,
		AuthorityInventoryDigest:    inventoryDigest,
		BaselineReviewEvidence:      review.Reference,
		BaselineDispositionEvidence: disposition.Reference,
		Bundle:                      bundle,
		Snapshot:                    snapshot,
		Approval:                    candidateReviewApproval,
	}
	if err := subject.Validate(); err != nil {
		t.Fatal(err)
	}
	_, canonical, err := canonicalJSONFile(subject)
	if err != nil {
		t.Fatal(err)
	}
	return review, disposition, subject, canonicalReference(subject.ID, canonical), objects
}

func canonicalBaselineReviewEvidence(t *testing.T, document baselineReviewEvidenceDocument) baselineReviewEvidence {
	t.Helper()
	if err := validateBaselineReviewEvidence(document); err != nil {
		t.Fatal(err)
	}
	file, canonical, err := canonicalJSONFile(document)
	if err != nil {
		t.Fatal(err)
	}
	return baselineReviewEvidence{
		canonicalEvidence: canonicalEvidence{Reference: canonicalReference(document.ID, canonical), File: file},
		Document:          document,
	}
}

func canonicalBaselineDispositionEvidence(t *testing.T, document baselineDispositionEvidenceDocument) baselineDispositionEvidence {
	t.Helper()
	if err := validateBaselineDispositionEvidence(document); err != nil {
		t.Fatal(err)
	}
	file, canonical, err := canonicalJSONFile(document)
	if err != nil {
		t.Fatal(err)
	}
	return baselineDispositionEvidence{
		canonicalEvidence: canonicalEvidence{Reference: canonicalReference(document.ID, canonical), File: file},
		Document:          document,
	}
}

func (fixture fixture) candidateAuthorityTree() []byte {
	tree := make([]byte, 0, len(fixture.candidateAuthorityObjects)*160)
	for index, relative := range expectedCandidateAuthorityFiles() {
		object := fmt.Sprintf("%040x", index+1)
		tree = append(tree, "100644 blob "...)
		tree = append(tree, object...)
		tree = append(tree, '\t')
		tree = append(tree, TrustedBundleRelativePath+"/"+relative...)
		tree = append(tree, 0)
	}
	return tree
}

func reviewTrustTestPolicy() reviewTrustPolicy {
	principals := []struct {
		principal string
		keyID     string
		role      reviewRole
		seed      byte
	}{
		{"fixture-baseline-reviewer", "fixture-baseline-review-key", baselineReviewerRole, 1},
		{"fixture-baseline-maintainer", "fixture-baseline-maintainer-key", baselineMaintainerRole, 2},
		{"fixture-candidate-reviewer", "fixture-candidate-review-key", candidateReviewerRole, 3},
	}
	policy := reviewTrustPolicy{SchemaVersion: reviewTrustPolicySchema, Principals: make([]reviewTrustPrincipal, 0, len(principals))}
	for _, item := range principals {
		public := reviewTrustTestPrivateKey(item.seed).Public().(ed25519.PublicKey)
		policy.Principals = append(policy.Principals, reviewTrustPrincipal{
			PrincipalID: item.principal,
			KeyID:       item.keyID, KeyFingerprint: benchmark.SHA256Digest(public),
			PublicKey: base64.StdEncoding.EncodeToString(public), Role: item.role,
		})
	}
	return policy
}

func reviewTrustTestPrivateKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(repeatedTestByte(seed))
}

func reviewTrustTestKeyForRole(role reviewRole) ed25519.PrivateKey {
	switch role {
	case baselineReviewerRole:
		return ed25519.NewKeyFromSeed(repeatedTestByte(1))
	case baselineMaintainerRole:
		return ed25519.NewKeyFromSeed(repeatedTestByte(2))
	default:
		return ed25519.NewKeyFromSeed(repeatedTestByte(3))
	}
}

func repeatedTestByte(value byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = value
	}
	return seed
}

func (fixture fixture) provisionExternalReviewTrust(t *testing.T) {
	t.Helper()
	provisionReviewTrust(t, fixture.facts("local/fixed").controllerRoot, fixture.baselineReview, &fixture.baselineDisposition, &fixture.candidateReview)
}

func provisionBaselineReviewTrust(t *testing.T, controllerRoot string, review baselineReviewEvidence) {
	t.Helper()
	provisionReviewTrust(t, controllerRoot, review, nil, nil)
}

func provisionReviewTrust(t *testing.T, controllerRoot string, review baselineReviewEvidence, disposition *baselineDispositionEvidence, subject *candidateReviewSubject) {
	t.Helper()
	authorityRoot := filepath.Join(controllerRoot, "authority")
	if err := os.MkdirAll(authorityRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := reviewTrustTestPolicy()
	writeCanonicalTestFile(t, filepath.Join(authorityRoot, filepath.Base(controllerReviewTrustPolicyPath)), policy)
	writeTestReviewDocument(t, filepath.Join(authorityRoot, filepath.Base(authorityReviewEvidencePath)), review.File)
	writeDetachedReviewSignature(t, filepath.Join(authorityRoot, filepath.Base(controllerBaselineReviewSignaturePath)), policy, baselineReviewerRole, baselineReviewSignatureContext, review.File[:len(review.File)-1])
	if disposition != nil {
		writeTestReviewDocument(t, filepath.Join(authorityRoot, filepath.Base(authorityDispositionPath)), disposition.File)
		writeDetachedReviewSignature(t, filepath.Join(authorityRoot, filepath.Base(controllerDispositionSignaturePath)), policy, baselineMaintainerRole, baselineDispositionSignatureContext, disposition.File[:len(disposition.File)-1])
	}
	if subject != nil {
		writeCanonicalTestFile(t, filepath.Join(authorityRoot, filepath.Base(controllerCandidateReviewSubjectPath)), *subject)
		canonical := canonicalTestJSON(t, *subject)
		writeDetachedReviewSignature(t, filepath.Join(authorityRoot, filepath.Base(controllerCandidateReviewSignaturePath)), policy, candidateReviewerRole, candidateReviewSignatureContext, canonical)
	}
}

func writeTestReviewDocument(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeDetachedReviewSignature(t *testing.T, path string, policy reviewTrustPolicy, role reviewRole, context string, document []byte) {
	t.Helper()
	var keyID string
	for _, principal := range policy.Principals {
		if principal.Role == role {
			keyID = principal.KeyID
			break
		}
	}
	if keyID == "" {
		t.Fatal("test review role has no key id")
	}
	signature := detachedReviewSignature{
		SchemaVersion: detachedReviewSignatureSchema,
		KeyID:         keyID,
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(reviewTrustTestKeyForRole(role), domainSeparatedReviewBytes(context, document))),
	}
	writeCanonicalTestFile(t, path, signature)
}

func TestAuthenticatedControllerTrustFailsClosedAtAuthorityIngress(t *testing.T) {
	fixture := newFixture(t)
	authorityRoot := filepath.Join(fixture.facts("local/fixed").controllerRoot, "authority")
	authenticateCandidate := func(t *testing.T) error {
		t.Helper()
		runner := &Runner{dependencies: fixture.dependencies(map[string]string{})}
		envelope := fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
		return runner.authenticateAuthoritativeController(context.Background(), fixture.facts("local/fixed"), envelope, fixture.controllerBundleRef)
	}
	reset := func(t *testing.T) { fixture.provisionExternalReviewTrust(t) }

	reset(t)
	if err := authenticateCandidate(t); err != nil {
		t.Fatalf("valid candidate authority was rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*testing.T)
	}{
		{
			name: "missing baseline signature",
			mutate: func(t *testing.T) {
				if err := os.Remove(filepath.Join(authorityRoot, filepath.Base(controllerBaselineReviewSignaturePath))); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed signature",
			mutate: func(t *testing.T) {
				writeCanonicalTestFile(t, filepath.Join(authorityRoot, filepath.Base(controllerBaselineReviewSignaturePath)), detachedReviewSignature{SchemaVersion: detachedReviewSignatureSchema, KeyID: "fixture-baseline-review-key"})
			},
		},
		{
			name: "truncated signature",
			mutate: func(t *testing.T) {
				writeCanonicalTestFile(t, filepath.Join(authorityRoot, filepath.Base(controllerBaselineReviewSignaturePath)), detachedReviewSignature{SchemaVersion: detachedReviewSignatureSchema, KeyID: "fixture-baseline-review-key", Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize-1))})
			},
		},
		{
			name: "oversized signature",
			mutate: func(t *testing.T) {
				writeCanonicalTestFile(t, filepath.Join(authorityRoot, filepath.Base(controllerBaselineReviewSignaturePath)), detachedReviewSignature{SchemaVersion: detachedReviewSignatureSchema, KeyID: "fixture-baseline-review-key", Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize+1))})
			},
		},
		{
			name: "foreign signature",
			mutate: func(t *testing.T) {
				signature := detachedReviewSignature{SchemaVersion: detachedReviewSignatureSchema, KeyID: "fixture-baseline-review-key", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(reviewTrustTestPrivateKey(99), domainSeparatedReviewBytes(baselineReviewSignatureContext, fixture.baselineReview.File[:len(fixture.baselineReview.File)-1])))}
				writeCanonicalTestFile(t, filepath.Join(authorityRoot, filepath.Base(controllerBaselineReviewSignaturePath)), signature)
			},
		},
		{
			name: "wrong role",
			mutate: func(t *testing.T) {
				signature := detachedReviewSignature{SchemaVersion: detachedReviewSignatureSchema, KeyID: "fixture-baseline-maintainer-key", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(reviewTrustTestKeyForRole(baselineMaintainerRole), domainSeparatedReviewBytes(baselineReviewSignatureContext, fixture.baselineReview.File[:len(fixture.baselineReview.File)-1])))}
				writeCanonicalTestFile(t, filepath.Join(authorityRoot, filepath.Base(controllerBaselineReviewSignaturePath)), signature)
			},
		},
		{
			name: "same reviewer and maintainer principal",
			mutate: func(t *testing.T) {
				policy := reviewTrustTestPolicy()
				policy.Principals[1].PrincipalID = policy.Principals[0].PrincipalID
				writeCanonicalTestFile(t, filepath.Join(authorityRoot, filepath.Base(controllerReviewTrustPolicyPath)), policy)
			},
		},
		{
			name: "distinct labels and key ids reuse baseline reviewer key",
			mutate: func(t *testing.T) {
				policy := reviewTrustTestPolicy()
				policy.Principals[2].KeyID = "fixture-reused-candidate-key"
				policy.Principals[2].KeyFingerprint = policy.Principals[0].KeyFingerprint
				policy.Principals[2].PublicKey = policy.Principals[0].PublicKey
				writeCanonicalTestFile(t, filepath.Join(authorityRoot, filepath.Base(controllerReviewTrustPolicyPath)), policy)
			},
		},
		{
			name: "one byte baseline evidence change",
			mutate: func(t *testing.T) {
				path := filepath.Join(authorityRoot, filepath.Base(authorityReviewEvidencePath))
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for index, value := range body {
					if value == 'f' {
						body[index] = 'F'
						break
					}
				}
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "cross context signature reuse",
			mutate: func(t *testing.T) {
				writeDetachedReviewSignature(t, filepath.Join(authorityRoot, filepath.Base(controllerCandidateReviewSignaturePath)), reviewTrustTestPolicy(), candidateReviewerRole, baselineReviewSignatureContext, canonicalTestJSON(t, fixture.candidateReview))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			reset(t)
			test.mutate(t)
			if err := authenticateCandidate(t); err == nil {
				t.Fatal("tampered authenticated authority was accepted")
			}
		})
	}
}

func TestCandidateReviewSubjectRejectsRuntimeBindingMismatches(t *testing.T) {
	fixture := newFixture(t)
	authorityRoot := filepath.Join(fixture.facts("local/fixed").controllerRoot, "authority")
	for _, test := range []struct {
		name   string
		mutate func(*candidateReviewSubject)
	}{
		{"commit", func(subject *candidateReviewSubject) {
			subject.Harness.Commit = strings.Repeat("3", 40)
			subject.ID = "candidate-review-" + subject.Harness.Commit
		}},
		{"tree", func(subject *candidateReviewSubject) { subject.Harness.Tree = strings.Repeat("4", 40) }},
		{"authority path", func(subject *candidateReviewSubject) { subject.AuthorityRoot = "other/authority" }},
		{"authority inventory", func(subject *candidateReviewSubject) {
			subject.AuthorityInventoryDigest = reference("different-inventory").Digest
		}},
		{"bundle", func(subject *candidateReviewSubject) { subject.Bundle = reference("different-bundle") }},
		{"baseline review", func(subject *candidateReviewSubject) { subject.BaselineReviewEvidence = reference("different-review") }},
		{"baseline disposition", func(subject *candidateReviewSubject) {
			subject.BaselineDispositionEvidence = reference("different-disposition")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture.provisionExternalReviewTrust(t)
			subject := fixture.candidateReview
			test.mutate(&subject)
			if err := subject.Validate(); err != nil && test.name != "authority path" {
				t.Fatalf("test subject must remain structurally valid: %v", err)
			}
			writeCanonicalTestFile(t, filepath.Join(authorityRoot, filepath.Base(controllerCandidateReviewSubjectPath)), subject)
			canonical := canonicalTestJSON(t, subject)
			writeDetachedReviewSignature(t, filepath.Join(authorityRoot, filepath.Base(controllerCandidateReviewSignaturePath)), reviewTrustTestPolicy(), candidateReviewerRole, candidateReviewSignatureContext, canonical)
			envelope := fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
			envelope.Authority.ReviewEvidence = canonicalReference(subject.ID, canonical)
			runner := &Runner{dependencies: fixture.dependencies(map[string]string{})}
			if err := runner.authenticateAuthoritativeController(context.Background(), fixture.facts("local/fixed"), envelope, fixture.controllerBundleRef); err == nil {
				t.Fatal("mismatched candidate review subject was accepted")
			}
		})
	}
}

func TestControllerTrustRejectsAmbiguousPathsAndDirectEnvelopeInjection(t *testing.T) {
	fixture := newFixture(t)
	authorityRoot := filepath.Join(fixture.facts("local/fixed").controllerRoot, "authority")
	candidateEnvelope := fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
	for _, test := range []struct {
		name   string
		mutate func(*testing.T)
	}{
		{
			name: "trailing policy bytes",
			mutate: func(t *testing.T) {
				path := filepath.Join(authorityRoot, filepath.Base(controllerReviewTrustPolicyPath))
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(body, ' '), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "nonregular trust policy",
			mutate: func(t *testing.T) {
				path := filepath.Join(authorityRoot, filepath.Base(controllerReviewTrustPolicyPath))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(path) })
			},
		},
		{
			name: "unknown sidecar field",
			mutate: func(t *testing.T) {
				body := `{"key_id":"fixture-baseline-review-key","schema_version":"synapse-reachability-detached-review-signature-v1","signature":"` + base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) + `","unexpected":true}` + "\n"
				if err := os.WriteFile(filepath.Join(authorityRoot, filepath.Base(controllerBaselineReviewSignaturePath)), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "nonregular sidecar",
			mutate: func(t *testing.T) {
				path := filepath.Join(authorityRoot, filepath.Base(controllerBaselineReviewSignaturePath))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(path) })
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture.provisionExternalReviewTrust(t)
			test.mutate(t)
			runner := &Runner{dependencies: fixture.dependencies(map[string]string{})}
			if err := runner.authenticateAuthoritativeController(context.Background(), fixture.facts("local/fixed"), candidateEnvelope, fixture.controllerBundleRef); err == nil {
				t.Fatal("ambiguous external trust input was accepted")
			}
		})
	}

	t.Run("signature symlink", func(t *testing.T) {
		fixture.provisionExternalReviewTrust(t)
		path := filepath.Join(authorityRoot, filepath.Base(controllerBaselineReviewSignaturePath))
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(t.TempDir(), "foreign.signature.json"), path); err != nil {
			t.Skipf("create signature symlink: %v", err)
		}
		runner := &Runner{dependencies: fixture.dependencies(map[string]string{})}
		if err := runner.authenticateAuthoritativeController(context.Background(), fixture.facts("local/fixed"), candidateEnvelope, fixture.controllerBundleRef); err == nil {
			t.Fatal("signature symlink was accepted")
		}
	})

	t.Run("policy symlink", func(t *testing.T) {
		fixture.provisionExternalReviewTrust(t)
		path := filepath.Join(authorityRoot, filepath.Base(controllerReviewTrustPolicyPath))
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(t.TempDir(), "foreign-policy.json"), path); err != nil {
			t.Skipf("create policy symlink: %v", err)
		}
		runner := &Runner{dependencies: fixture.dependencies(map[string]string{})}
		if err := runner.authenticateAuthoritativeController(context.Background(), fixture.facts("local/fixed"), candidateEnvelope, fixture.controllerBundleRef); err == nil {
			t.Fatal("policy symlink was accepted")
		}
	})

	t.Run("direct envelope injection cannot bypass absent trust", func(t *testing.T) {
		fixture.provisionExternalReviewTrust(t)
		envelopePath := fixture.writeEnvelope(t, candidateEnvelope)
		if err := os.Remove(filepath.Join(authorityRoot, filepath.Base(controllerReviewTrustPolicyPath))); err != nil {
			t.Fatal(err)
		}
		captures := 0
		runner, err := NewRunner(fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: envelopePath}), captureFunc(func(context.Context, CaptureRequest) (CaptureResult, error) {
			captures++
			return CaptureResult{}, errors.New("must not capture")
		}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Run(context.Background(), nil); err == nil || captures != 0 {
			t.Fatalf("direct envelope injection bypassed external trust: err=%v captures=%d", err, captures)
		}
	})
}

func TestLocalDiagnosticNeedsNoReviewTrustMaterial(t *testing.T) {
	fixture := newFixture(t)
	runner, err := NewRunner(fixture.dependencies(map[string]string{}), captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Authoritative || result.Manifest.Route != RouteLocalDiagnostic {
		t.Fatalf("unsigned local diagnostic route = %+v", result.Manifest)
	}
}

func TestReviewTrustPolicyRejectsDistinctLabelsThatReuseOneKey(t *testing.T) {
	policy := reviewTrustTestPolicy()
	policy.Principals[2].KeyID = "fixture-reused-candidate-key"
	policy.Principals[2].KeyFingerprint = policy.Principals[0].KeyFingerprint
	policy.Principals[2].PublicKey = policy.Principals[0].PublicKey

	if err := policy.Validate(); err == nil {
		t.Fatal("policy accepted distinct labels and key ids that reuse one public key and fingerprint")
	}
}

func TestCandidateAuthorizationRequiresPairwiseDistinctAuthenticatedCredentials(t *testing.T) {
	policy := reviewTrustTestPolicy()
	principals := make([]authenticatedReviewPrincipal, 0, len(policy.Principals))
	for _, principal := range policy.Principals {
		publicKey, err := principal.publicKey()
		if err != nil {
			t.Fatal(err)
		}
		principals = append(principals, authenticatedReviewPrincipal{
			PrincipalID:    principal.PrincipalID,
			KeyID:          principal.KeyID,
			KeyFingerprint: principal.KeyFingerprint,
			PublicKey:      publicKey,
			Role:           principal.Role,
		})
	}
	if err := validateDistinctCandidateReviewPrincipals(principals...); err != nil {
		t.Fatalf("valid distinct candidate authorization rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func([]authenticatedReviewPrincipal)
	}{
		{
			name: "principal id",
			mutate: func(actual []authenticatedReviewPrincipal) {
				actual[2].PrincipalID = actual[0].PrincipalID
			},
		},
		{
			name: "key id",
			mutate: func(actual []authenticatedReviewPrincipal) {
				actual[2].KeyID = actual[0].KeyID
			},
		},
		{
			name: "key fingerprint",
			mutate: func(actual []authenticatedReviewPrincipal) {
				actual[2].KeyFingerprint = actual[0].KeyFingerprint
			},
		},
		{
			name: "canonical public key bytes",
			mutate: func(actual []authenticatedReviewPrincipal) {
				actual[2].PublicKey = append(ed25519.PublicKey(nil), actual[0].PublicKey...)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual := append([]authenticatedReviewPrincipal(nil), principals...)
			test.mutate(actual)
			if err := validateDistinctCandidateReviewPrincipals(actual...); err == nil {
				t.Fatalf("candidate authorization accepted reused %s", test.name)
			}
		})
	}
}
