package judgment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
)

func suppressionTestArtifact(t *testing.T, id string) ArtifactIdentity {
	t.Helper()
	sum := sha256.Sum256([]byte(id))
	identity, err := NewArtifactIdentity(id, "sha256:"+hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("new artifact identity %q: %v", id, err)
	}
	return identity
}

func suppressionTestInput(t *testing.T) ReachabilitySuppressionProofInput {
	t.Helper()
	registry, err := NewInitialReachabilityAuthorityRegistry()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := registry.Lookup(string(CohortGo), string(ModeSourceTier2))
	if err != nil {
		t.Fatal(err)
	}
	approval, ok := policy.Approval()
	if !ok {
		t.Fatal("go/source_tier2 must be suppression eligible")
	}
	snapshot, err := NewReachabilitySnapshotIdentity(
		suppressionTestArtifact(t, "source"),
		suppressionTestArtifact(t, "sbom"),
		suppressionTestArtifact(t, "run"),
	)
	if err != nil {
		t.Fatal(err)
	}
	contract := approval.Contract()
	return ReachabilitySuppressionProofInput{
		SubjectID:            "finding-1",
		BoundaryID:           "analysis-boundary",
		Cohort:               string(CohortGo),
		Mode:                 string(ModeSourceTier2),
		Snapshot:             snapshot,
		Analyzer:             suppressionTestArtifact(t, "analyzer"),
		Configuration:        suppressionTestArtifact(t, "configuration"),
		CompletenessContract: suppressionTestArtifactWithDigest(t, contract.ID(), contract.Digest()),
		Authority:            approval.Authority(),
		AuthorityCheckpoint:  suppressionTestArtifact(t, "authority-checkpoint"),
		Proposer:             approval.Proposer(),
		Verifier:             approval.Verifier(),
	}
}

func suppressionTestArtifactWithDigest(t *testing.T, id, digest string) ArtifactIdentity {
	t.Helper()
	identity, err := NewArtifactIdentity(id, digest)
	if err != nil {
		t.Fatalf("new artifact identity %q: %v", id, err)
	}
	return identity
}

func sealedSuppressionTestProof(t *testing.T) (ReachabilitySuppressionProof, ReachabilitySuppressionContext) {
	t.Helper()
	proof, err := NewReachabilitySuppressionProof(suppressionTestInput(t))
	if err != nil {
		t.Fatal(err)
	}
	proof, err = proof.WithProposalEvidence(suppressionTestArtifact(t, "proposal-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	proof, err = proof.WithVerdictEvidence(suppressionTestArtifact(t, "verdict-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	return proof, ReachabilitySuppressionContext{
		Snapshot:            proof.snapshot,
		BoundaryID:          proof.boundaryID,
		Analyzer:            proof.analyzer,
		Configuration:       proof.configuration,
		AuthorityCheckpoint: proof.authorityCheckpoint,
		ProposalEvidence:    proof.proposalEvidence,
		VerdictEvidence:     proof.verdictEvidence,
	}
}

func suppressionTestNegative(proof ReachabilitySuppressionProof) Judgment {
	storedProof := cloneReachabilitySuppressionProof(proof)
	return Judgment{
		ID:               "negative",
		EngagementID:     "engagement-1",
		Capability:       CapReachability,
		SubjectKind:      SubjectFinding,
		SubjectID:        "finding-1",
		Claim:            ReachabilityClaim{Reachable: NotReachable, Tier: Tier2, Confidence: 90, EntrypointsPresent: true},
		State:            StateConfirmed,
		EvidenceScore:    90,
		ProposedBy:       proof.proposer,
		VerifiedBy:       proof.verifier,
		Version:          2,
		SuppressionProof: &storedProof,
	}
}

func TestWinningReachabilityDispositionsAuthorizesCompleteSealedProof(t *testing.T) {
	proof, context := sealedSuppressionTestProof(t)
	result := WinningReachabilityDispositions([]Judgment{suppressionTestNegative(proof)}, &context)["finding-1"]
	if !result.Suppresses || result.State != NotReachable || result.JudgmentID != "negative" {
		t.Fatalf("complete approved proof disposition = %+v", result)
	}

	if result := WinningReachabilityDispositions([]Judgment{suppressionTestNegative(proof)}, nil)["finding-1"]; result.Suppresses {
		t.Fatalf("a missing current authority context must fail closed: %+v", result)
	}
}

func TestWinningReachabilityDispositionsRequiresDeterministicEvidenceScore(t *testing.T) {
	proof, context := sealedSuppressionTestProof(t)
	negative := suppressionTestNegative(proof)
	negative.EvidenceScore = verdict.DeterministicProofScore - 1
	result := WinningReachabilityDispositions([]Judgment{negative}, &context)["finding-1"]
	if result.Suppresses {
		t.Fatalf("sub-deterministic evidence score granted suppression: %+v", result)
	}
}

func TestReachabilitySuppressionProofRejectsUndeclaredMissingIdentity(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ReachabilitySuppressionProofInput)
	}{
		{"subject", func(input *ReachabilitySuppressionProofInput) { input.SubjectID = "" }},
		{"boundary", func(input *ReachabilitySuppressionProofInput) { input.BoundaryID = "" }},
		{"source snapshot", func(input *ReachabilitySuppressionProofInput) { input.Snapshot.source = ArtifactIdentity{} }},
		{"sbom snapshot", func(input *ReachabilitySuppressionProofInput) { input.Snapshot.sbom = ArtifactIdentity{} }},
		{"run snapshot", func(input *ReachabilitySuppressionProofInput) { input.Snapshot.run = ArtifactIdentity{} }},
		{"analyzer", func(input *ReachabilitySuppressionProofInput) { input.Analyzer = ArtifactIdentity{} }},
		{"configuration", func(input *ReachabilitySuppressionProofInput) { input.Configuration = ArtifactIdentity{} }},
		{"completeness contract", func(input *ReachabilitySuppressionProofInput) { input.CompletenessContract = ArtifactIdentity{} }},
		{"authority checkpoint", func(input *ReachabilitySuppressionProofInput) { input.AuthorityCheckpoint = ArtifactIdentity{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := suppressionTestInput(t)
			tc.mutate(&input)
			if _, err := NewReachabilitySuppressionProof(input); err == nil {
				t.Fatal("missing identity without an explicit provenance gap was accepted")
			}
		})
	}
}

func TestWinningReachabilityDispositionsFailsClosedForExplicitGaps(t *testing.T) {
	cases := []struct {
		name   string
		gap    SuppressionProvenanceGap
		mutate func(*ReachabilitySuppressionProof)
	}{
		{"missing subject", ProvenanceMissingSubject, func(proof *ReachabilitySuppressionProof) { proof.subjectID = "" }},
		{"missing boundary", ProvenanceMissingBoundary, func(proof *ReachabilitySuppressionProof) { proof.boundaryID = "" }},
		{"missing source", ProvenanceMissingSourceSnapshot, func(proof *ReachabilitySuppressionProof) { proof.snapshot.source = ArtifactIdentity{} }},
		{"missing sbom", ProvenanceMissingSBOMSnapshot, func(proof *ReachabilitySuppressionProof) { proof.snapshot.sbom = ArtifactIdentity{} }},
		{"missing run", ProvenanceMissingRunSnapshot, func(proof *ReachabilitySuppressionProof) { proof.snapshot.run = ArtifactIdentity{} }},
		{"missing analyzer", ProvenanceMissingAnalyzer, func(proof *ReachabilitySuppressionProof) { proof.analyzer = ArtifactIdentity{} }},
		{"missing configuration", ProvenanceMissingConfiguration, func(proof *ReachabilitySuppressionProof) { proof.configuration = ArtifactIdentity{} }},
		{"missing completeness contract", ProvenanceMissingCompletenessContract, func(proof *ReachabilitySuppressionProof) { proof.completenessContract = ArtifactIdentity{} }},
		{"missing authority checkpoint", ProvenanceMissingAuthorityCheckpoint, func(proof *ReachabilitySuppressionProof) { proof.authorityCheckpoint = ArtifactIdentity{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof, context := sealedSuppressionTestProof(t)
			tc.mutate(&proof)
			proof.missingProvenance = []SuppressionProvenanceGap{tc.gap}
			if err := proof.validatePersisted(); err != nil {
				t.Fatalf("declared provenance gap must remain persistable: %v", err)
			}
			if got := WinningReachabilityDispositions([]Judgment{suppressionTestNegative(proof)}, &context)["finding-1"]; got.Suppresses {
				t.Fatalf("explicit %s gap granted suppression: %+v", tc.name, got)
			}
		})
	}
}

func TestWinningReachabilityDispositionsFailsClosedForMismatchedIdentity(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ReachabilitySuppressionProof, *ReachabilitySuppressionContext)
	}{
		{"subject", func(proof *ReachabilitySuppressionProof, _ *ReachabilitySuppressionContext) {
			proof.subjectID = "other-finding"
		}},
		{"boundary", func(_ *ReachabilitySuppressionProof, context *ReachabilitySuppressionContext) {
			context.BoundaryID = "other-boundary"
		}},
		{"source snapshot", func(_ *ReachabilitySuppressionProof, context *ReachabilitySuppressionContext) {
			context.Snapshot.source = suppressionTestArtifact(t, "other-source")
		}},
		{"sbom snapshot", func(_ *ReachabilitySuppressionProof, context *ReachabilitySuppressionContext) {
			context.Snapshot.sbom = suppressionTestArtifact(t, "other-sbom")
		}},
		{"run snapshot", func(_ *ReachabilitySuppressionProof, context *ReachabilitySuppressionContext) {
			context.Snapshot.run = suppressionTestArtifact(t, "other-run")
		}},
		{"analyzer", func(_ *ReachabilitySuppressionProof, context *ReachabilitySuppressionContext) {
			context.Analyzer = suppressionTestArtifact(t, "other-analyzer")
		}},
		{"configuration", func(_ *ReachabilitySuppressionProof, context *ReachabilitySuppressionContext) {
			context.Configuration = suppressionTestArtifact(t, "other-configuration")
		}},
		{"completeness contract", func(proof *ReachabilitySuppressionProof, _ *ReachabilitySuppressionContext) {
			proof.completenessContract = suppressionTestArtifact(t, "other-contract")
		}},
		{"authority checkpoint", func(_ *ReachabilitySuppressionProof, context *ReachabilitySuppressionContext) {
			context.AuthorityCheckpoint = suppressionTestArtifact(t, "other-checkpoint")
		}},
		{"proposal evidence", func(_ *ReachabilitySuppressionProof, context *ReachabilitySuppressionContext) {
			context.ProposalEvidence = suppressionTestArtifact(t, "other-proposal-evidence")
		}},
		{"verdict evidence", func(_ *ReachabilitySuppressionProof, context *ReachabilitySuppressionContext) {
			context.VerdictEvidence = suppressionTestArtifact(t, "other-verdict-evidence")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof, context := sealedSuppressionTestProof(t)
			tc.mutate(&proof, &context)
			if got := WinningReachabilityDispositions([]Judgment{suppressionTestNegative(proof)}, &context)["finding-1"]; got.Suppresses {
				t.Fatalf("mismatched %s granted suppression: %+v", tc.name, got)
			}
		})
	}
}

func TestWinningReachabilityDispositionsFailsClosedForProvenanceUncertainty(t *testing.T) {
	for _, gap := range []SuppressionProvenanceGap{
		ProvenanceIncomplete,
		ProvenanceStale,
		ProvenanceMismatched,
		ProvenanceLegacy,
		ProvenanceUnsupported,
		ProvenanceSkipped,
		ProvenanceOpaque,
		ProvenancePartial,
		ProvenanceFailed,
	} {
		t.Run(string(gap), func(t *testing.T) {
			proof, context := sealedSuppressionTestProof(t)
			proof.missingProvenance = []SuppressionProvenanceGap{gap}
			if err := proof.validatePersisted(); err != nil {
				t.Fatal(err)
			}
			if got := WinningReachabilityDispositions([]Judgment{suppressionTestNegative(proof)}, &context)["finding-1"]; got.Suppresses {
				t.Fatalf("%q provenance gap granted suppression: %+v", gap, got)
			}
		})
	}
}

func TestWinningReachabilityDispositionsRequiresSealedEvidence(t *testing.T) {
	proof, context := sealedSuppressionTestProof(t)
	proof.proposalEvidence = ArtifactIdentity{}
	if got := WinningReachabilityDispositions([]Judgment{suppressionTestNegative(proof)}, &context)["finding-1"]; got.Suppresses {
		t.Fatalf("missing proposal evidence granted suppression: %+v", got)
	}

	proof, context = sealedSuppressionTestProof(t)
	proof.verdictEvidence = ArtifactIdentity{}
	if got := WinningReachabilityDispositions([]Judgment{suppressionTestNegative(proof)}, &context)["finding-1"]; got.Suppresses {
		t.Fatalf("missing verdict evidence granted suppression: %+v", got)
	}
}

func TestWinningReachabilityDispositionsStaleNegativeCannotShadowReachable(t *testing.T) {
	proof, context := sealedSuppressionTestProof(t)
	context.Snapshot.run = suppressionTestArtifact(t, "new-run")
	reachable := Judgment{
		ID: "reachable", EngagementID: "engagement-1", Capability: CapReachability, SubjectKind: SubjectFinding,
		SubjectID: "finding-1", Claim: ReachabilityClaim{Reachable: Reachable, Tier: Tier1, Confidence: 90},
		State: StateConfirmed, EvidenceScore: 90,
	}
	winner := WinningReachabilityDispositions([]Judgment{suppressionTestNegative(proof), reachable}, &context)["finding-1"]
	if winner.State != Reachable || winner.JudgmentID != "reachable" || winner.Suppresses {
		t.Fatalf("stale negative shadowed reachable judgment: %+v", winner)
	}
}

func TestReachabilitySuppressionProofLifecycleAndPersistence(t *testing.T) {
	input := suppressionTestInput(t)
	proof, err := NewReachabilitySuppressionProof(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalReachabilitySuppressionProof(&proof); err == nil {
		t.Fatal("draft proof was accepted for persistence")
	}
	proposalPayload, err := MarshalReachabilitySuppressionProposalProof(&proof)
	if err != nil || !bytes.Contains(proposalPayload, []byte(reachabilitySuppressionProofSchemaVersion)) {
		t.Fatalf("marshal draft proof for proposal evidence = %q, %v", proposalPayload, err)
	}
	if _, err := MarshalReachabilitySuppressionVerdictProof(&proof); err == nil {
		t.Fatal("draft proof was accepted for verdict evidence")
	}
	if _, err := proof.WithVerdictEvidence(suppressionTestArtifact(t, "verdict-evidence")); err == nil {
		t.Fatal("verdict evidence was accepted before proposal evidence")
	}
	proof, err = proof.WithProposalEvidence(suppressionTestArtifact(t, "proposal-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	verdictPayload, err := MarshalReachabilitySuppressionVerdictProof(&proof)
	if err != nil || !bytes.Contains(verdictPayload, []byte(`"proposal_evidence"`)) {
		t.Fatalf("marshal proposal-sealed proof for verdict evidence = %q, %v", verdictPayload, err)
	}
	proof, err = proof.WithVerdictEvidence(suppressionTestArtifact(t, "verdict-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalReachabilitySuppressionProof(&proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalReachabilitySuppressionProof(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded == nil || !decoded.proposalEvidence.Equal(proof.proposalEvidence) || !decoded.verdictEvidence.Equal(proof.verdictEvidence) {
		t.Fatalf("proof did not round trip sealed evidence: %#v", decoded)
	}
	if _, err := UnmarshalReachabilitySuppressionProof([]byte(`{"unexpected":true}`)); err == nil {
		t.Fatal("malformed persisted proof was accepted")
	}
	sealed, context := sealedSuppressionTestProof(t)
	negative := suppressionTestNegative(sealed)
	negative.SuppressionProof = MalformedReachabilitySuppressionProof()
	if got := WinningReachabilityDispositions([]Judgment{negative}, &context)["finding-1"]; got.Suppresses {
		t.Fatalf("malformed persisted proof granted suppression: %+v", got)
	}
}

func TestReachabilitySuppressionProofRequiresDistinctApprovedActors(t *testing.T) {
	input := suppressionTestInput(t)
	input.Verifier = input.Proposer
	if _, err := NewReachabilitySuppressionProof(input); err == nil {
		t.Fatal("self-verifying proof was accepted")
	}

	proof, context := sealedSuppressionTestProof(t)
	negative := suppressionTestNegative(proof)
	negative.VerifiedBy = negative.ProposedBy
	if got := WinningReachabilityDispositions([]Judgment{negative}, &context)["finding-1"]; got.Suppresses {
		t.Fatalf("self-verifying judgment granted suppression: %+v", got)
	}
}

func TestWithSuppressionProofCannotReplaceProposalProvenance(t *testing.T) {
	draft, _ := sealedSuppressionTestProof(t)
	draft.stage = suppressionProofDraft
	draft.proposalEvidence = ArtifactIdentity{}
	draft.verdictEvidence = ArtifactIdentity{}
	item, err := NewWithSuppressionProof("judgment-1", "engagement-1", CapReachability, SubjectFinding, "finding-1", ReachabilityClaim{Reachable: NotReachable, Tier: Tier2, EntrypointsPresent: true}, draft.proposer, draft, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := draft.WithProposalEvidence(suppressionTestArtifact(t, "proposal-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	item, err = item.WithSuppressionProof(proposal)
	if err != nil {
		t.Fatal(err)
	}

	replacementInput := suppressionTestInput(t)
	replacementInput.BoundaryID = "other-boundary"
	replacement, err := NewReachabilitySuppressionProof(replacementInput)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err = replacement.WithProposalEvidence(suppressionTestArtifact(t, "replacement-proposal-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := item.WithSuppressionProof(replacement); err == nil {
		t.Fatal("replacement proof with different provenance was accepted")
	}
}

func TestNewWithSuppressionProofBindsSubjectAndProposer(t *testing.T) {
	proof, _ := sealedSuppressionTestProof(t)
	proof.stage = suppressionProofDraft
	proof.proposalEvidence = ArtifactIdentity{}
	proof.verdictEvidence = ArtifactIdentity{}
	if _, err := NewWithSuppressionProof("judgment-1", "engagement-1", CapReachability, SubjectFinding, "other-finding", ReachabilityClaim{Reachable: NotReachable, Tier: Tier2, EntrypointsPresent: true}, proof.proposer, proof, time.Unix(1, 0).UTC()); err == nil {
		t.Fatal("proof with a mismatched subject was accepted")
	}
}
