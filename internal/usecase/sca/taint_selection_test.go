package sca

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// selectionTaintScanner is a no-op semantic engine, enough to be a wired adapter.
type selectionTaintScanner struct{}

func (*selectionTaintScanner) Scan(context.Context, shared.ID, string) (int, error) { return 0, nil }

func taintOutcome(t *testing.T, svc *Service, engine string) scanrun.EngineOutcome {
	t.Helper()
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	outcome, ok := result.engineOutcome(engine)
	if !ok {
		t.Fatalf("%s carries no outcome", engine)
	}
	return outcome
}

func newSelectionSvc(t *testing.T) *Service {
	t.Helper()
	return newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
}

// An engine the operator selected that this process could not build is unavailable, not unselected. The
// outcome used to be derived from the adapter, so a missing prerequisite erased the operator's intent.
func TestSelectedSemanticEngineWithoutAnAdapterIsUnavailable(t *testing.T) {
	svc := newSelectionSvc(t)
	svc.SetTaintSelection(TaintSelection{Supported: true, Python: true})
	outcome := taintOutcome(t, svc, "taint_python")
	if !outcome.Required || outcome.Execution != scanrun.EngineNotRun || outcome.Reason != scanrun.ReasonUnavailable {
		t.Fatalf("taint_python outcome %+v, want required/not_run/unavailable", outcome)
	}
	if outcome.Coverage != scanrun.CoverageUnknown {
		t.Fatalf("an engine that was selected and did not run cannot claim coverage: %+v", outcome)
	}
}

// An entry point that does not run semantic taint says so, rather than reporting an engine nobody asked
// for. The outcome is not required, because the capability is unsupported here and not merely missing.
func TestSelectedSemanticEngineOnAnUnsupportedEntryPointIsNotApplicable(t *testing.T) {
	svc := newSelectionSvc(t)
	svc.SetTaintSelection(TaintSelection{Supported: false, Python: true, Java: true})
	for _, engine := range []string{"taint_python", "taint_java"} {
		outcome := taintOutcome(t, svc, engine)
		if outcome.Required || outcome.Reason != scanrun.ReasonNotApplicable || outcome.Coverage != scanrun.CoverageNotApplicable {
			t.Fatalf("%s outcome %+v, want not required/not_applicable", engine, outcome)
		}
	}
}

// An engine nobody selected still reports not_selected, so a deliberate exclusion stays distinct from work
// that was required and unavailable.
func TestUnselectedSemanticEngineStaysNotSelected(t *testing.T) {
	svc := newSelectionSvc(t)
	svc.SetTaintSelection(TaintSelection{Supported: true})
	outcome := taintOutcome(t, svc, "taint_javascript")
	if outcome.Required || outcome.Reason != scanrun.ReasonNotSelected {
		t.Fatalf("taint_javascript outcome %+v, want not required/not_selected", outcome)
	}
}

// A selected engine whose adapter was built runs and is required, so its coverage gates.
func TestSelectedSemanticEngineWithAnAdapterIsRequired(t *testing.T) {
	svc := newSelectionSvc(t)
	svc.SetTaintSelection(TaintSelection{Supported: true, Python: true})
	svc.SetPythonTaint(&selectionTaintScanner{})
	outcome := taintOutcome(t, svc, "taint_python")
	if !outcome.Required || outcome.Reason == scanrun.ReasonUnavailable {
		t.Fatalf("taint_python outcome %+v, want required and available", outcome)
	}
}

// A composition root that records no selection keeps the earlier behaviour, in which a wired adapter is
// read as its own selection.
func TestUnrecordedSelectionFallsBackToTheAdapter(t *testing.T) {
	svc := newSelectionSvc(t)
	svc.SetPythonTaint(&selectionTaintScanner{})
	outcome := taintOutcome(t, svc, "taint_python")
	if !outcome.Required {
		t.Fatalf("a wired adapter must stay selected without an explicit selection: %+v", outcome)
	}
}
