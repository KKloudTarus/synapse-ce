package identityfoundation

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type cutoverStoreFake struct {
	state    ports.IdentityCutoverState
	evidence ports.IdentityCutoverEvidence
}

func (f *cutoverStoreFake) RecordCutoverWriterHeartbeat(context.Context, shared.ID, string, string, time.Time) error {
	return nil
}

func (f *cutoverStoreFake) CutoverState(context.Context, shared.ID) (ports.IdentityCutoverState, error) {
	return f.state, nil
}
func (f *cutoverStoreFake) PrepareCutover(_ context.Context, _ shared.ID, v int, _ string, _ time.Time) (ports.IdentityCutoverState, error) {
	f.state.Phase = ports.IdentityCutoverShadow
	f.state.PolicyVersion = v + 1
	return f.state, nil
}
func (f *cutoverStoreFake) CanaryCutover(context.Context, shared.ID) (ports.IdentityShadowReport, error) {
	return ports.IdentityShadowReport{Ready: true, RollbackPrepared: true}, nil
}
func (f *cutoverStoreFake) DeclareCutover(_ context.Context, _ shared.ID, v int, e ports.IdentityCutoverEvidence, _ string, _ time.Time) (ports.IdentityCutoverState, error) {
	f.evidence = e
	f.state.Phase = ports.IdentityCutoverDeclared
	f.state.Declared = true
	f.state.PolicyVersion = v + 1
	return f.state, nil
}
func (f *cutoverStoreFake) ContractCutover(context.Context, shared.ID, int, string, time.Time) (ports.IdentityCutoverState, error) {
	return f.state, nil
}
func (f *cutoverStoreFake) AbortCutover(context.Context, shared.ID, int, string, time.Time) (ports.IdentityCutoverState, error) {
	return f.state, nil
}

func TestCutoverServiceDelegatesDeclarationEvidence(t *testing.T) {
	f := &cutoverStoreFake{}
	s, err := NewCutoverService(f, idgen.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	e := ports.IdentityCutoverEvidence{ShadowReportID: "clean-shadow", OldWriterGeneration: "shared-authentication:test", MigrationVersion: 209}
	if _, err = s.Declare(context.Background(), "tenant", 4, e, "operator"); err != nil {
		t.Fatal(err)
	}
	if f.evidence != e {
		t.Fatalf("evidence lost: %+v", f.evidence)
	}
}
