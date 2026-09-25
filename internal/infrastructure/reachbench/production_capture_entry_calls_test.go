package reachbench

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func TestGoBinaryProductionCaptureUsesRaiseOnlyEntrypointCallProof(t *testing.T) {
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain unavailable")
	}
	build := func(t *testing.T, source string) (MaterializedFixture, string) {
		t.Helper()
		root := t.TempDir()
		for name, body := range map[string]string{
			"go.mod": "module example.invalid/capture-fixture\n\ngo 1.27\n\nrequire (\n\tgolang.org/x/net v0.59.0\n\tgolang.org/x/text v0.42.0 // indirect\n)\n",
			"go.sum": "golang.org/x/net v0.59.0 h1:5zfYln+w5XCxwrnMMJPufRgNoXEaGxl0wo5GqPXyues=\n" +
				"golang.org/x/net v0.59.0/go.mod h1:2DA/G1UfVbCpQPeWTmMPGY7Cs2PkBkwu743bVX5PIVg=\n" +
				"golang.org/x/text v0.42.0 h1:JbOZXgfeCPU9gacVtYliJqOhD+zhrEqK4LfdpmlUZqI=\n" +
				"golang.org/x/text v0.42.0/go.mod h1:ojzP1Z+2QtioaF8DTtO8K5q7JWVVYwZKenzujK0Zd0E=\n",
			"main.go": source,
		} {
			if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		output := filepath.Join(root, "capture-binary")
		command := exec.Command(goPath, "build", "-trimpath", "-o", output, ".")
		command.Dir = root
		command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOPROXY=off", "GOTOOLCHAIN=local")
		if buildOutput, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build versioned Go-binary capture fixture: %v: %s", err, buildOutput)
		}
		buildInfo, err := exec.Command(goPath, "version", "-m", output).CombinedOutput()
		if err != nil || !strings.Contains(string(buildInfo), "dep\tgolang.org/x/net\tv0.59.0\t") {
			t.Fatalf("fixture lacks pinned x/net build identity: %v: %s", err, buildInfo)
		}
		return MaterializedFixture{Root: root}, output
	}
	fixture, _ := build(t, "package main\nimport \"golang.org/x/net/idna\"\n"+
		"func main() { _, _ = idna.ToASCII(\"example.test\") }\n")
	positive := measurement.ResolvedFixtureSubject{Subject: measurement.FixtureSubject{
		ID:              "versioned-dependency-positive",
		PackageIdentity: "golang:golang.org/x/net@v0.59.0",
		Locator: measurement.FixtureLocator{
			Kind:   measurement.FixtureLocatorSourceSymbol,
			Symbol: "golang.org/x/net/idna.ToASCII",
		},
	}}
	lifecycle, err := newCaptureLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runGoBinary(context.Background(), nil, fixture, positive, lifecycle); err != nil {
		t.Fatal(err)
	}
	judgments, err := lifecycle.judgments.List(context.Background(), productionCaptureEngagementID)
	if err != nil {
		t.Fatal(err)
	}
	claim, found := judgment.WinningReachabilityClaims(judgments)[positive.Subject.ID]
	if !found || claim.Reachable != judgment.Reachable || claim.SuppressesFinding() {
		t.Fatalf("versioned Go-binary capture claim = %#v, want a non-suppressing reachable claim", claim)
	}

	unreached := positive
	unreached.Subject.ID = "versioned-dependency-absent"
	unreached.Subject.Locator.Symbol = "golang.org/x/net/idna.NotCalled"
	unreachedLifecycle, err := newCaptureLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runGoBinary(context.Background(), nil, fixture, unreached, unreachedLifecycle); err != nil {
		t.Fatal(err)
	}
	unreachedJudgments, err := unreachedLifecycle.judgments.List(context.Background(), productionCaptureEngagementID)
	if err != nil {
		t.Fatal(err)
	}
	if len(unreachedJudgments) != 0 {
		t.Fatalf("unproven Go-binary symbol minted judgments: %#v", unreachedJudgments)
	}

	for _, tc := range []struct {
		name   string
		source string
		output string
	}{
		{
			name: "retained but uncalled",
			source: "package main\nimport \"golang.org/x/net/idna\"\n" +
				"var retained = []func(){controlUnreached}\n" +
				"func main() { if retained[0] == nil { panic(\"missing control\") } }\n" +
				"//go:noinline\nfunc controlUnreached() { _, _ = idna.ToASCII(\"example.test\") }\n",
		},
		{
			name: "indirect function value call",
			source: "package main\nimport (\n\"fmt\"\n\"os\"\n\"golang.org/x/net/idna\"\n)\n" +
				"var indirectEntry = func() { value, _ := idna.ToASCII(\"bücher.example\"); fmt.Println(value) }\n" +
				"func main() { if len(os.Args) == 2 && os.Args[1] == \"invoke\" { invoke(indirectEntry) } }\n" +
				"//go:noinline\nfunc invoke(call func()) { call() }\n",
			output: "xn--bcher-kva.example\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture, binary := build(t, tc.source)
			if tc.name == "retained but uncalled" {
				symbols, err := exec.Command(goPath, "tool", "nm", binary).CombinedOutput()
				if err != nil || !strings.Contains(string(symbols), " T main.controlUnreached") {
					t.Fatalf("retained control symbol missing: %v", err)
				}
			}
			if tc.output != "" && runtime.GOOS == "linux" {
				output, err := exec.Command(binary, "invoke").CombinedOutput()
				if err != nil || string(output) != tc.output {
					t.Fatalf("indirect runtime call = %q, error %v; want %q", output, err, tc.output)
				}
			}
			control := positive
			control.Subject.ID = tc.name
			lifecycle, err := newCaptureLifecycle()
			if err != nil {
				t.Fatal(err)
			}
			executed, err := runGoBinary(context.Background(), nil, fixture, control, lifecycle)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := (&ProductionCapture{}).observation(context.Background(), CaptureRequest{
				Cell: ExecutionCell{CaseID: tc.name, BindingID: "worker", AnalyzerID: "entry-call", SubjectID: control.Subject.ID},
			}, lifecycle, executed)
			if err != nil {
				t.Fatal(err)
			}
			if observation.Outcome != measurement.OutcomeNoAnalysis || observation.Coverage.Status != measurement.CoverageUnavailable {
				t.Fatalf("unproven call observation = %s/%s, want no_analysis/unavailable", observation.Outcome, observation.Coverage.Status)
			}
			judgments, err := lifecycle.judgments.List(context.Background(), productionCaptureEngagementID)
			if err != nil {
				t.Fatal(err)
			}
			if len(judgments) != 0 {
				t.Fatalf("unproven call minted judgments: %#v", judgments)
			}
		})
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
