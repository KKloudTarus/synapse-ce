package reachbench

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/toolrunner"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func TestGoBinaryProductionCaptureUsesRaiseOnlyEntrypointCallProof(t *testing.T) {
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain unavailable")
	}
	execRunner := toolrunner.NewExecRunner(0, 0)
	runner := &fixtureToolRunner{run: func(ctx context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
		if isFixtureToolchainProbe("go", spec) {
			return matchingFixtureToolchainProbe("go"), nil
		}
		return execRunner.Run(ctx, spec)
	}}
	materializer, err := NewFixtureMaterializer(FixtureMaterializerDependencies{
		ToolRunner: runner,
		Platform:   func() string { return "linux/amd64" },
		LocateTool: func(name string) (string, error) {
			if name != "go" {
				return "", fmt.Errorf("unexpected fixture tool %q", name)
			}
			return goPath, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	specification := materializerFixture(t, "go-binary-input")
	fixture, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
		Specification: specification,
		WorkRoot:      privateMaterializerRoot(t),
		CellKey:       "sha256:" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}

	lifecycle, err := newCaptureLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	positive := fixtureSubjectByID(t, specification, "pkg:reachbench/go/binary#reachableDependency")
	if _, err := runGoBinary(context.Background(), nil, fixture, positive, lifecycle); err != nil {
		t.Fatal(err)
	}
	judgments, err := lifecycle.judgments.List(context.Background(), productionCaptureEngagementID)
	if err != nil {
		t.Fatal(err)
	}
	claims := judgment.WinningReachabilityClaims(judgments)
	claim, found := claims[positive.Subject.ID]
	if !found || claim.Reachable != judgment.Reachable || claim.SuppressesFinding() {
		t.Fatalf("positive Go-binary capture claim = %#v, want a non-suppressing reachable claim", claim)
	}

	unreachedLifecycle, err := newCaptureLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	unreached := fixtureSubjectByID(t, specification, "pkg:reachbench/go/binary#controlUnreachable")
	if _, err := runGoBinary(context.Background(), nil, fixture, unreached, unreachedLifecycle); err != nil {
		t.Fatal(err)
	}
	unreachedJudgments, err := unreachedLifecycle.judgments.List(context.Background(), productionCaptureEngagementID)
	if err != nil {
		t.Fatal(err)
	}
	if len(unreachedJudgments) != 0 {
		t.Fatalf("retained uncalled PCLNTAB symbol minted judgments: %#v", unreachedJudgments)
	}
}

func fixtureSubjectByID(t *testing.T, specification measurement.FixtureSpecification, id string) measurement.ResolvedFixtureSubject {
	t.Helper()
	for _, subject := range specification.Subjects {
		if subject.ID == id {
			return measurement.ResolvedFixtureSubject{Specification: specification, Subject: subject}
		}
	}
	t.Fatalf("fixture %q has no subject %q", specification.ID, id)
	return measurement.ResolvedFixtureSubject{}
}
