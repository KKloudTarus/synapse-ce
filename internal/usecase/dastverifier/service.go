// Package dastverifier ingests runtime-verifier results for AppSec findings.
//
// It deliberately does not run probes, send packets, execute payloads, or own approval/scope
// decisions. Those live upstream in the governed executor/HITL path. This package is the custody
// handoff: given an existing gated CapSAST judgment and a distinct verifier's result, validate the
// structured verifier input and delegate to analysis.Verify, which seals the verdict before moving
// score/state.
package dastverifier

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
)

// judgmentVerifier is the narrow runtime-verify slice of analysis.Service. It is VerifyRuntime (not the
// generic Verify): a confirmation here came from a safe runtime probe, so a confirmed CapSAST judgment
// projects to a Kind=dast finding (dynamically proven) rather than Kind=sast.
type judgmentVerifier interface {
	VerifyRuntime(ctx context.Context, verifier string, engagementID, judgmentID shared.ID, score int, rationale string, expectedVersion int) (judgment.Judgment, error)
}

// Service validates a runtime-verifier result and applies it through the Judgment gate.
type Service struct {
	verifier judgmentVerifier
}

// NewService wires the verifier ingestion use case. The dependency is intentionally the narrow
// analysis.Verify shape, not the analysis service concrete type.
func NewService(verifier judgmentVerifier) (*Service, error) {
	if verifier == nil {
		return nil, fmt.Errorf("%w: dast verifier requires a judgment verifier", shared.ErrValidation)
	}
	return &Service{verifier: verifier}, nil
}

// Result is the structured runtime-verifier observation produced by an approved verifier run or a
// distinct human verifier. It is metadata/rationale only; raw probe output belongs in sealed
// evidence owned by the runner and should not be passed through this struct.
type Result struct {
	JudgmentID      shared.ID
	Verifier        string
	Score           int
	ProofClass      ProofClass
	Rationale       string
	ExpectedVersion int
}

// ProofClass describes what kind of runtime signal was obtained, using closed tokens so the
// result cannot smuggle arbitrary execution instructions.
type ProofClass string

const (
	ProofClassRuntimeConfirmed ProofClass = "runtime_confirmed"
	ProofClassRuntimeRefuted   ProofClass = "runtime_refuted"
	ProofClassNeedsMoreProof   ProofClass = "needs_more_proof"
)

func (p ProofClass) Valid() bool {
	switch p {
	case ProofClassRuntimeConfirmed, ProofClassRuntimeRefuted, ProofClassNeedsMoreProof:
		return true
	default:
		return false
	}
}

// Apply validates and applies a verifier result to a gated CapSAST judgment. analysis.Verify
// enforces distinct verifier, version, score bar, verdict sealing, and state transition.
func (s *Service) Apply(ctx context.Context, engagementID shared.ID, r Result) (judgment.Judgment, error) {
	if engagementID == "" {
		return judgment.Judgment{}, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	if r.JudgmentID == "" {
		return judgment.Judgment{}, fmt.Errorf("%w: judgment id is required", shared.ErrValidation)
	}
	if strings.TrimSpace(r.Verifier) == "" {
		return judgment.Judgment{}, fmt.Errorf("%w: verifier is required", shared.ErrValidation)
	}
	if !r.ProofClass.Valid() {
		return judgment.Judgment{}, fmt.Errorf("%w: proof_class must be runtime_confirmed|runtime_refuted|needs_more_proof", shared.ErrValidation)
	}
	if strings.TrimSpace(r.Rationale) == "" {
		return judgment.Judgment{}, fmt.Errorf("%w: verifier rationale is required", shared.ErrValidation)
	}
	// The closed proof_class token and the numeric score must AGREE before anything is sealed, so the
	// sealed evidence can never be internally inconsistent (a "runtime_confirmed" rationale on a sub-bar
	// verdict, or a "refuted"/"needs_more_proof" rationale on a bar-clearing one that then confirms). The
	// numeric score remains the authoritative bar in analysis.Verify; this just refuses a contradictory pair.
	if (r.ProofClass == ProofClassRuntimeConfirmed) != verdict.MeetsBar(r.Score) {
		return judgment.Judgment{}, fmt.Errorf("%w: proof_class %q is inconsistent with score %d: runtime_confirmed must clear the evidence bar (>= %d) and runtime_refuted/needs_more_proof must not",
			shared.ErrValidation, r.ProofClass, r.Score, verdict.EvidenceThreshold)
	}
	rationale := fmt.Sprintf("proof_class=%s; %s", r.ProofClass, strings.TrimSpace(r.Rationale))
	return s.verifier.VerifyRuntime(ctx, r.Verifier, engagementID, r.JudgmentID, r.Score, rationale, r.ExpectedVersion)
}
