package reachbench

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

const (
	reviewTrustPolicySchema       = "synapse-reachability-review-trust-v1"
	detachedReviewSignatureSchema = "synapse-reachability-detached-review-signature-v1"
	candidateReviewSubjectSchema  = "synapse-reachability-candidate-review-subject-v1"

	baselineReviewSignatureContext      = "synapse-reachability/baseline-review-evidence/v1"
	baselineDispositionSignatureContext = "synapse-reachability/baseline-disposition-evidence/v1"
	candidateReviewSignatureContext     = "synapse-reachability/candidate-review-evidence/v1"

	controllerReviewTrustPolicyPath        = "authority/review-trust.json"
	controllerBaselineReviewSignaturePath  = "authority/baseline-review-evidence.signature.json"
	controllerDispositionSignaturePath     = "authority/baseline-disposition-evidence.signature.json"
	controllerCandidateReviewSubjectPath   = "authority/candidate-review-subject.json"
	controllerCandidateReviewSignaturePath = "authority/candidate-review-subject.signature.json"
	reachabilityRepositoryID               = "github.com/KKloudTarus/synapse-ce"
	candidateReviewApproval                = "approve_candidate_acceptance"
	maxReviewTrustPrincipals               = 3
)

type reviewRole string

const (
	baselineReviewerRole   reviewRole = "baseline_reviewer"
	baselineMaintainerRole reviewRole = "baseline_maintainer"
	candidateReviewerRole  reviewRole = "candidate_reviewer"
)

// reviewTrustPolicy is externally provisioned under the controller root. It
// contains verification material only; the curator never creates it.
type reviewTrustPolicy struct {
	SchemaVersion string                 `json:"schema_version"`
	Principals    []reviewTrustPrincipal `json:"principals"`
}

type reviewTrustPrincipal struct {
	PrincipalID    string     `json:"principal_id"`
	KeyID          string     `json:"key_id"`
	KeyFingerprint string     `json:"key_fingerprint"`
	PublicKey      string     `json:"public_key"`
	Role           reviewRole `json:"role"`
}

type detachedReviewSignature struct {
	SchemaVersion string `json:"schema_version"`
	KeyID         string `json:"key_id"`
	Signature     string `json:"signature"`
}

type authenticatedReviewPrincipal struct {
	PrincipalID    string
	KeyID          string
	KeyFingerprint string
	PublicKey      ed25519.PublicKey
	Role           reviewRole
}

// candidateReviewSubject is deliberately independent of the envelope. Its
// signature attests to the final committed authority source and the values the
// envelope is permitted to carry, without creating an envelope-signature cycle.
type candidateReviewSubject struct {
	SchemaVersion               string                        `json:"schema_version"`
	ID                          string                        `json:"id"`
	RepositoryID                string                        `json:"repository_id"`
	Harness                     HarnessIdentity               `json:"harness"`
	AuthorityRoot               string                        `json:"authority_root"`
	AuthorityInventoryDigest    string                        `json:"authority_inventory_digest"`
	BaselineReviewEvidence      measurement.ArtifactReference `json:"baseline_review_evidence"`
	BaselineDispositionEvidence measurement.ArtifactReference `json:"baseline_disposition_evidence"`
	Bundle                      measurement.ArtifactReference `json:"bundle"`
	Snapshot                    measurement.SnapshotIdentity  `json:"snapshot"`
	Approval                    string                        `json:"approval"`
}

type candidateAuthorityInventoryEntry struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Digest string `json:"digest"`
}

func (policy reviewTrustPolicy) Validate() error {
	if policy.SchemaVersion != reviewTrustPolicySchema || len(policy.Principals) != maxReviewTrustPrincipals {
		return errors.New("review trust policy must contain exactly the required bounded principal inventory")
	}
	seenPrincipals := make(map[string]struct{}, len(policy.Principals))
	seenKeys := make(map[string]struct{}, len(policy.Principals))
	seenFingerprints := make(map[string]struct{}, len(policy.Principals))
	seenPublicKeys := make(map[string]struct{}, len(policy.Principals))
	seenRoles := make(map[reviewRole]struct{}, len(policy.Principals))
	for _, principal := range policy.Principals {
		if !bounded(principal.PrincipalID) || !bounded(principal.KeyID) {
			return errors.New("review trust policy contains an unbounded principal or key id")
		}
		if _, exists := seenPrincipals[principal.PrincipalID]; exists {
			return errors.New("review trust policy contains a duplicate principal id")
		}
		if _, exists := seenKeys[principal.KeyID]; exists {
			return errors.New("review trust policy contains a duplicate key id")
		}
		if _, exists := seenFingerprints[principal.KeyFingerprint]; exists {
			return errors.New("review trust policy contains a duplicate key fingerprint")
		}
		if !validReviewRole(principal.Role) {
			return errors.New("review trust policy contains an unsupported role")
		}
		if _, exists := seenRoles[principal.Role]; exists {
			return errors.New("review trust policy contains a duplicate role")
		}
		publicKey, err := principal.publicKey()
		if err != nil {
			return err
		}
		if _, exists := seenPublicKeys[string(publicKey)]; exists {
			return errors.New("review trust policy contains duplicate canonical public-key bytes")
		}
		seenPrincipals[principal.PrincipalID] = struct{}{}
		seenKeys[principal.KeyID] = struct{}{}
		seenFingerprints[principal.KeyFingerprint] = struct{}{}
		seenPublicKeys[string(publicKey)] = struct{}{}
		seenRoles[principal.Role] = struct{}{}
	}
	for _, role := range []reviewRole{baselineReviewerRole, baselineMaintainerRole, candidateReviewerRole} {
		if _, found := seenRoles[role]; !found {
			return errors.New("review trust policy omits a required role")
		}
	}
	return nil
}

func (principal reviewTrustPrincipal) publicKey() (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(principal.PublicKey)
	if err != nil || base64.StdEncoding.EncodeToString(key) != principal.PublicKey {
		return nil, errors.New("review trust policy public key is not canonical base64")
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("review trust policy public key has an invalid Ed25519 length")
	}
	if principal.KeyFingerprint != benchmark.SHA256Digest(key) {
		return nil, errors.New("review trust policy key fingerprint does not match its public key")
	}
	return ed25519.PublicKey(key), nil
}

func validReviewRole(role reviewRole) bool {
	switch role {
	case baselineReviewerRole, baselineMaintainerRole, candidateReviewerRole:
		return true
	default:
		return false
	}
}

func (signature detachedReviewSignature) validate() ([]byte, error) {
	if signature.SchemaVersion != detachedReviewSignatureSchema || !bounded(signature.KeyID) {
		return nil, errors.New("detached review signature has an invalid schema or key id")
	}
	encoded, err := base64.StdEncoding.Strict().DecodeString(signature.Signature)
	if err != nil || len(encoded) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(encoded) != signature.Signature {
		return nil, errors.New("detached review signature has an invalid Ed25519 signature")
	}
	return encoded, nil
}

func (policy reviewTrustPolicy) verify(role reviewRole, context string, document []byte, signature detachedReviewSignature) (authenticatedReviewPrincipal, error) {
	if err := policy.Validate(); err != nil {
		return authenticatedReviewPrincipal{}, err
	}
	encodedSignature, err := signature.validate()
	if err != nil {
		return authenticatedReviewPrincipal{}, err
	}
	for _, principal := range policy.Principals {
		if principal.KeyID != signature.KeyID {
			continue
		}
		if principal.Role != role {
			return authenticatedReviewPrincipal{}, errors.New("detached review signature key does not have the required role")
		}
		publicKey, err := principal.publicKey()
		if err != nil {
			return authenticatedReviewPrincipal{}, err
		}
		if !ed25519.Verify(publicKey, domainSeparatedReviewBytes(context, document), encodedSignature) {
			return authenticatedReviewPrincipal{}, errors.New("detached review signature verification failed")
		}
		return authenticatedReviewPrincipal{
			PrincipalID:    principal.PrincipalID,
			KeyID:          principal.KeyID,
			KeyFingerprint: principal.KeyFingerprint,
			PublicKey:      append(ed25519.PublicKey(nil), publicKey...),
			Role:           principal.Role,
		}, nil
	}
	return authenticatedReviewPrincipal{}, errors.New("detached review signature key is not trusted")
}

func domainSeparatedReviewBytes(context string, document []byte) []byte {
	message := make([]byte, 0, len(context)+len(document)+48)
	message = append(message, "synapse-reachability-detached-review-signature-v1\x00"...)
	message = append(message, context...)
	message = append(message, 0)
	message = append(message, document...)
	return message
}

func validateDistinctCandidateReviewPrincipals(principals ...authenticatedReviewPrincipal) error {
	roles := []reviewRole{baselineReviewerRole, baselineMaintainerRole, candidateReviewerRole}
	if len(principals) != len(roles) {
		return errors.New("candidate authority requires the complete authenticated review-role set")
	}
	for index, principal := range principals {
		if principal.Role != roles[index] || !bounded(principal.PrincipalID) || !bounded(principal.KeyID) ||
			!validDigest(principal.KeyFingerprint) || len(principal.PublicKey) != ed25519.PublicKeySize {
			return errors.New("candidate authority contains an invalid authenticated review principal")
		}
	}
	for left := range principals {
		for right := left + 1; right < len(principals); right++ {
			if principals[left].PrincipalID == principals[right].PrincipalID {
				return errors.New("candidate authority requires pairwise-distinct authenticated review principal ids")
			}
			if principals[left].KeyID == principals[right].KeyID {
				return errors.New("candidate authority requires pairwise-distinct authenticated review key ids")
			}
			if principals[left].KeyFingerprint == principals[right].KeyFingerprint {
				return errors.New("candidate authority requires pairwise-distinct authenticated review key fingerprints")
			}
			if bytes.Equal(principals[left].PublicKey, principals[right].PublicKey) {
				return errors.New("candidate authority requires pairwise-distinct authenticated review public keys")
			}
		}
	}
	return nil
}

func loadControllerReviewTrustPolicy(ctx context.Context, controllerRoot string) (reviewTrustPolicy, error) {
	path, err := controllerAuthorityFile(controllerRoot, filepath.Base(controllerReviewTrustPolicyPath))
	if err != nil {
		return reviewTrustPolicy{}, fmt.Errorf("resolve controller review trust policy: %w", err)
	}
	var policy reviewTrustPolicy
	if _, err := readCanonicalJSONContext(ctx, path, &policy); err != nil {
		return reviewTrustPolicy{}, fmt.Errorf("read controller review trust policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return reviewTrustPolicy{}, err
	}
	return policy, nil
}

func readControllerDetachedSignature(ctx context.Context, controllerRoot, relative string) (detachedReviewSignature, error) {
	path, err := controllerAuthorityFile(controllerRoot, filepath.Base(relative))
	if err != nil {
		return detachedReviewSignature{}, fmt.Errorf("resolve controller detached review signature: %w", err)
	}
	var signature detachedReviewSignature
	if _, err := readCanonicalJSONContext(ctx, path, &signature); err != nil {
		return detachedReviewSignature{}, fmt.Errorf("read controller detached review signature: %w", err)
	}
	if _, err := signature.validate(); err != nil {
		return detachedReviewSignature{}, err
	}
	return signature, nil
}

func readControllerCandidateReviewSubject(ctx context.Context, controllerRoot string) (candidateReviewSubject, []byte, measurement.ArtifactReference, error) {
	path, err := controllerAuthorityFile(controllerRoot, filepath.Base(controllerCandidateReviewSubjectPath))
	if err != nil {
		return candidateReviewSubject{}, nil, measurement.ArtifactReference{}, fmt.Errorf("resolve controller candidate review subject: %w", err)
	}
	var subject candidateReviewSubject
	canonical, err := readCanonicalJSONContext(ctx, path, &subject)
	if err != nil {
		return candidateReviewSubject{}, nil, measurement.ArtifactReference{}, fmt.Errorf("read controller candidate review subject: %w", err)
	}
	if err := subject.Validate(); err != nil {
		return candidateReviewSubject{}, nil, measurement.ArtifactReference{}, err
	}
	return subject, canonical, canonicalReference(subject.ID, canonical), nil
}

func readControllerBaselineReviewEvidence(ctx context.Context, controllerRoot string) (baselineReviewEvidence, []byte, error) {
	path, err := controllerAuthorityFile(controllerRoot, filepath.Base(authorityReviewEvidencePath))
	if err != nil {
		return baselineReviewEvidence{}, nil, fmt.Errorf("resolve controller baseline review evidence: %w", err)
	}
	evidence, err := readBaselineReviewEvidence(ctx, path)
	if err != nil {
		return baselineReviewEvidence{}, nil, fmt.Errorf("read controller baseline review evidence: %w", err)
	}
	canonical := evidence.File[:len(evidence.File)-1]
	return evidence, canonical, nil
}

func readControllerBaselineDispositionEvidence(ctx context.Context, controllerRoot string) (baselineDispositionEvidence, []byte, error) {
	path, err := controllerAuthorityFile(controllerRoot, filepath.Base(authorityDispositionPath))
	if err != nil {
		return baselineDispositionEvidence{}, nil, fmt.Errorf("resolve controller baseline disposition evidence: %w", err)
	}
	evidence, err := readBaselineDispositionEvidence(ctx, path)
	if err != nil {
		return baselineDispositionEvidence{}, nil, fmt.Errorf("read controller baseline disposition evidence: %w", err)
	}
	canonical := evidence.File[:len(evidence.File)-1]
	return evidence, canonical, nil
}

func controllerAuthorityFile(controllerRoot, name string) (string, error) {
	root, err := benchcycle.RealDirectory(controllerRoot)
	if err != nil {
		return "", err
	}
	authorityRoot, err := benchcycle.RealDirectory(filepath.Join(root, "authority"))
	if err != nil {
		return "", fmt.Errorf("controller authority root must be a real directory: %w", err)
	}
	return benchcycle.BelowRoot(authorityRoot, name)
}

func (subject candidateReviewSubject) Validate() error {
	if subject.SchemaVersion != candidateReviewSubjectSchema || subject.RepositoryID != reachabilityRepositoryID ||
		subject.AuthorityRoot != TrustedBundleRelativePath || subject.Approval != candidateReviewApproval {
		return errors.New("candidate review subject has unsupported fixed semantics")
	}
	if !bounded(subject.ID) || subject.ID != "candidate-review-"+subject.Harness.Commit || validateHarness(subject.Harness) != nil ||
		!validDigest(subject.AuthorityInventoryDigest) || validateArtifact(subject.BaselineReviewEvidence) != nil ||
		validateArtifact(subject.BaselineDispositionEvidence) != nil || validateArtifact(subject.Bundle) != nil || subject.BaselineReviewEvidence == subject.BaselineDispositionEvidence {
		return errors.New("candidate review subject contains invalid identity or evidence bindings")
	}
	if err := subject.Snapshot.Validate(); err != nil {
		return fmt.Errorf("candidate review subject snapshot: %w", err)
	}
	return nil
}

func buildCandidateReviewSubject(authority candidateAuthority, harness HarnessIdentity) (candidateReviewSubject, []byte, measurement.ArtifactReference, error) {
	if authority.inventoryDigest == "" || !validDigest(authority.inventoryDigest) {
		return candidateReviewSubject{}, nil, measurement.ArtifactReference{}, errors.New("candidate authority has no committed inventory digest")
	}
	if err := authority.assets.CandidateInput.Validate(); err != nil {
		return candidateReviewSubject{}, nil, measurement.ArtifactReference{}, fmt.Errorf("validate candidate review input: %w", err)
	}
	subject := candidateReviewSubject{
		SchemaVersion:               candidateReviewSubjectSchema,
		ID:                          "candidate-review-" + harness.Commit,
		RepositoryID:                reachabilityRepositoryID,
		Harness:                     harness,
		AuthorityRoot:               TrustedBundleRelativePath,
		AuthorityInventoryDigest:    authority.inventoryDigest,
		BaselineReviewEvidence:      authority.reviewEvidence.Reference,
		BaselineDispositionEvidence: authority.dispositionEvidence.Reference,
		Bundle:                      authority.assets.BundleRef,
		Snapshot:                    authority.assets.CandidateInput.ActiveSnapshot,
		Approval:                    candidateReviewApproval,
	}
	if err := subject.Validate(); err != nil {
		return candidateReviewSubject{}, nil, measurement.ArtifactReference{}, err
	}
	file, canonical, err := canonicalJSONFile(subject)
	if err != nil {
		return candidateReviewSubject{}, nil, measurement.ArtifactReference{}, fmt.Errorf("encode candidate review subject: %w", err)
	}
	return subject, file, canonicalReference(subject.ID, canonical), nil
}

func candidateAuthorityInventoryDigest(entries []candidateAuthorityInventoryEntry) (string, error) {
	expected := expectedCandidateAuthorityFiles()
	if len(entries) != len(expected) {
		return "", errors.New("candidate authority inventory is not exact")
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Path < entries[right].Path })
	for index, entry := range entries {
		if entry.Path != expected[index] || entry.Mode != "100644" || !validDigest(entry.Digest) {
			return "", errors.New("candidate authority inventory contains an invalid path, mode, or blob digest")
		}
	}
	canonical, err := benchmark.CanonicalJSON(entries)
	if err != nil {
		return "", fmt.Errorf("encode candidate authority inventory: %w", err)
	}
	return benchmark.SHA256Digest(canonical), nil
}

func (runner *Runner) authenticateAuthoritativeController(ctx context.Context, facts runtimeFacts, envelope RunEnvelope, bundle measurement.ArtifactReference) error {
	policy, err := loadControllerReviewTrustPolicy(ctx, facts.controllerRoot)
	if err != nil {
		return err
	}
	baselineReview, baselineReviewCanonical, err := readControllerBaselineReviewEvidence(ctx, facts.controllerRoot)
	if err != nil {
		return err
	}
	baselineSignature, err := readControllerDetachedSignature(ctx, facts.controllerRoot, controllerBaselineReviewSignaturePath)
	if err != nil {
		return err
	}
	baselineReviewer, err := policy.verify(baselineReviewerRole, baselineReviewSignatureContext, baselineReviewCanonical, baselineSignature)
	if err != nil {
		return fmt.Errorf("authenticate baseline review evidence: %w", err)
	}
	switch envelope.Route {
	case RouteProtectedBaseline:
		if envelope.Authority.ReviewEvidence != baselineReview.Reference {
			return errors.New("protected baseline envelope does not bind authenticated baseline review evidence")
		}
		if baselineReview.Document.Harness != facts.harness || baselineReview.Document.Analyzer != envelope.Analyzer || !reviewContainsHead(baselineReview.Document, facts.harness.Commit) {
			return errors.New("authenticated baseline review evidence does not bind the runtime protected-baseline harness and analyzer")
		}
		return nil
	case RouteCandidate:
		disposition, dispositionCanonical, err := readControllerBaselineDispositionEvidence(ctx, facts.controllerRoot)
		if err != nil {
			return err
		}
		dispositionSignature, err := readControllerDetachedSignature(ctx, facts.controllerRoot, controllerDispositionSignaturePath)
		if err != nil {
			return err
		}
		maintainer, err := policy.verify(baselineMaintainerRole, baselineDispositionSignatureContext, dispositionCanonical, dispositionSignature)
		if err != nil {
			return fmt.Errorf("authenticate baseline disposition evidence: %w", err)
		}
		subject, subjectCanonical, subjectRef, err := readControllerCandidateReviewSubject(ctx, facts.controllerRoot)
		if err != nil {
			return err
		}
		candidateSignature, err := readControllerDetachedSignature(ctx, facts.controllerRoot, controllerCandidateReviewSignaturePath)
		if err != nil {
			return err
		}
		candidateReviewer, err := policy.verify(candidateReviewerRole, candidateReviewSignatureContext, subjectCanonical, candidateSignature)
		if err != nil {
			return fmt.Errorf("authenticate candidate review subject: %w", err)
		}
		if err := validateDistinctCandidateReviewPrincipals(baselineReviewer, maintainer, candidateReviewer); err != nil {
			return err
		}
		if envelope.Authority.ReviewEvidence != subjectRef {
			return errors.New("candidate envelope does not bind authenticated exact-candidate review evidence")
		}
		if subject.Harness != facts.harness || subject.Bundle != bundle || subject.Snapshot != envelope.Snapshot ||
			subject.BaselineReviewEvidence != baselineReview.Reference || subject.BaselineDispositionEvidence != disposition.Reference {
			return errors.New("authenticated candidate review subject does not bind the runtime harness, envelope, bundle, snapshot, and baseline evidence")
		}
		inventoryDigest, err := runner.deriveCandidateAuthorityInventory(ctx, facts)
		if err != nil {
			return err
		}
		if subject.AuthorityInventoryDigest != inventoryDigest {
			return errors.New("authenticated candidate review subject does not bind the exact committed authority inventory")
		}
		return nil
	default:
		return errors.New("authenticated controller selected an unsupported route")
	}
}

func reviewContainsHead(evidence baselineReviewEvidenceDocument, head string) bool {
	for _, checkpoint := range evidence.Checkpoints {
		if checkpoint.ReviewedHead == head {
			return true
		}
	}
	return false
}

func (runner *Runner) deriveCandidateAuthorityInventory(ctx context.Context, facts runtimeFacts) (string, error) {
	entries, err := runner.dependencies.Command(ctx, "git", "ls-tree", "-r", "-z", "--full-tree", facts.harness.Tree, "--", TrustedBundleRelativePath)
	if err != nil {
		return "", fmt.Errorf("inspect runtime candidate authority tree with git argv: %w", err)
	}
	actual, err := parseAuthorityTreeEntries(entries, TrustedBundleRelativePath)
	if err != nil {
		return "", err
	}
	expected := expectedCandidateAuthorityEntries()
	if len(actual) != len(expected) {
		return "", errors.New("runtime candidate authority inventory is not exact")
	}
	inventory := make([]candidateAuthorityInventoryEntry, 0, len(expected))
	for _, relative := range expectedCandidateAuthorityFiles() {
		entry, found := actual[relative]
		if !found || entry.mode != "100644" || entry.objectType != "blob" || !benchcycle.FullSHA(entry.object) {
			return "", errors.New("runtime candidate authority requires ordinary 100644 blobs with exact inventory")
		}
		body, err := runner.dependencies.Command(ctx, "git", "cat-file", "blob", entry.object)
		if err != nil {
			return "", fmt.Errorf("read runtime candidate authority blob %q with git argv: %w", relative, err)
		}
		if int64(len(body)) > benchmark.MaxJSONBytes {
			return "", fmt.Errorf("runtime candidate authority blob %q exceeds JSON size bound", relative)
		}
		inventory = append(inventory, candidateAuthorityInventoryEntry{Path: relative, Mode: entry.mode, Digest: benchmark.SHA256Digest(body)})
	}
	return candidateAuthorityInventoryDigest(inventory)
}
