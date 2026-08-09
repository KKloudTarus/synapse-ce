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

// SymbolRecorder runs the Tier-2 JavaScript pass and promotes its results through the existing judgment
// gate, minting Tier-2 claims.
//
// The tier is honest per analyzer. A Tier-1 import proof answers "is this package used at all"; this
// answers "is this affected export reached", which is a strictly stronger statement, so it is minted at
// Tier-2 and supersedes the Tier-1 judgment for the same subject under the existing stronger-tier-wins
// rule. It is NOT inflated further: this is a binding-and-property-read proof over a first-party module
// graph, not an interprocedural call graph, and the sealed rationale says so.
type SymbolRecorder struct {
	scanner   importScanner
	resolver  importResolver
	judgments recorderPort
	audit     ports.AuditLogger
	clock     ports.Clock
}

// NewSymbolRecorder validates and returns the Tier-2 recorder.
func NewSymbolRecorder(scanner importScanner, resolver importResolver, judgments recorderPort, audit ports.AuditLogger, clock ports.Clock) (*SymbolRecorder, error) {
	if scanner == nil || resolver == nil || judgments == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: jsreach symbol recorder is missing a dependency", shared.ErrValidation)
	}
	return &SymbolRecorder{scanner: scanner, resolver: resolver, judgments: judgments, audit: audit, clock: clock}, nil
}

// RecordWithSBOM analyses the target against doc and mints Tier-2 JavaScript reachability judgments.
//
// The SBOM is handed over rather than re-derived, for the same reason as Tier-1: a component PURL is
// only meaningful relative to one document, and regenerating it could legitimately produce different
// identities, at which point every subject would miss and be sealed as not-reachable.
//
// Subjects the analyzer cannot answer — a transitive package, one absent from this document, or an
// export whose reachability is UNKNOWN because something escaped observation — are DROPPED before
// minting. The coordinator mints a claim for every subject it is given and reads "no result" as
// not-reachable, so an unanswerable subject must never reach it: dropping leaves the Tier-1 judgment
// standing, while passing it through would seal a false negative at full confidence.
func (r *SymbolRecorder) RecordWithSBOM(ctx context.Context, engagementID shared.ID, targetRef string, doc *sbom.SBOM, subjects []ports.ReachabilitySubject) (int, error) {
	if doc == nil {
		return 0, fmt.Errorf("%w: jsreach symbol recorder needs the sbom the subjects were minted from", shared.ErrValidation)
	}
	analyzer, err := NewSymbolAnalyzer(r.scanner, r.resolver, staticSBOM{doc: doc})
	if err != nil {
		return 0, err
	}

	answerable, err := analyzer.answerableSymbolSubjects(ctx, targetRef, subjects)
	if err != nil {
		return 0, err
	}
	if len(answerable) == 0 {
		return 0, nil
	}

	coordinator, err := reachproof.NewCoordinatorForTier(analyzer, r.judgments, r.audit, r.clock, judgment.Tier2)
	if err != nil {
		return 0, err
	}
	return coordinator.Record(ctx, engagementID, targetRef, answerable)
}
