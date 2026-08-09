package jsreach

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachproof"
)

// Recorder runs a Tier-1 JavaScript reachability pass against the SBOM the caller just produced, and
// promotes the results through the existing judgment gate.
//
// The SBOM is HANDED OVER rather than re-derived. A component purl is only meaningful relative to one
// document: if the analyzer regenerated its own SBOM it could legitimately differ from the one the
// subjects were minted from (a different producer, different enrichment, different cache state), and
// every subject would then miss and be sealed as not-reachable. Handing the document over makes that
// class of false negative impossible rather than unlikely.
type Recorder struct {
	scanner   importScanner
	resolver  importResolver
	judgments recorderPort
	audit     ports.AuditLogger
	clock     ports.Clock
}

// recorderPort is the narrow judgment-lifecycle slice the reachproof coordinator needs.
type recorderPort interface {
	Propose(ctx context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error)
	Verify(ctx context.Context, verifier string, engagementID, judgmentID shared.ID, score int, rationale string, expectedVersion int) (judgment.Judgment, error)
	List(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
}

// NewRecorder validates and returns the recorder.
func NewRecorder(scanner importScanner, resolver importResolver, judgments recorderPort, audit ports.AuditLogger, clock ports.Clock) (*Recorder, error) {
	if scanner == nil || resolver == nil || judgments == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: jsreach recorder is missing a dependency", shared.ErrValidation)
	}
	return &Recorder{scanner: scanner, resolver: resolver, judgments: judgments, audit: audit, clock: clock}, nil
}

// RecordWithSBOM analyses the target against doc and mints Tier-1 JavaScript reachability judgments.
//
// Subjects the analyzer cannot answer for — a transitive package, or one absent from this document — are
// DROPPED before minting rather than allowed to fail the pass. The coordinator mints a claim for every
// subject it is given and reads "no result" as not-reachable, so an unanswerable subject must never reach
// it: dropping leaves the prior tier standing, while passing it through would seal a false negative.
//
// A fresh analyzer is built per call so the handed-over document is never shared between concurrent
// scans. A no-coverage error aborts the whole pass and mints nothing.
func (r *Recorder) RecordWithSBOM(ctx context.Context, engagementID shared.ID, targetRef string, doc *sbom.SBOM, subjects []ports.ReachabilitySubject) (int, error) {
	if doc == nil {
		return 0, fmt.Errorf("%w: jsreach recorder needs the sbom the subjects were minted from", shared.ErrValidation)
	}
	analyzer, err := New(r.scanner, r.resolver, staticSBOM{doc: doc})
	if err != nil {
		return 0, err
	}

	answerable, err := analyzer.answerableSubjects(ctx, targetRef, subjects)
	if err != nil {
		return 0, err
	}
	if len(answerable) == 0 {
		return 0, nil
	}

	coordinator, err := reachproof.NewCoordinatorForLanguage(
		analyzer, r.judgments, r.audit, r.clock, judgment.Tier1, reachproof.LanguageJavaScript,
	)
	if err != nil {
		return 0, err
	}
	return coordinator.Record(ctx, engagementID, targetRef, answerable)
}

// staticSBOM hands the caller's document to the analyzer unchanged.
type staticSBOM struct{ doc *sbom.SBOM }

func (s staticSBOM) SBOMFor(context.Context, string) (*sbom.SBOM, error) { return s.doc, nil }
