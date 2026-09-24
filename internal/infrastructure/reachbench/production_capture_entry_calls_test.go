package reachbench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func TestVersionedGoBinaryFixtureFilesMatchProposal(t *testing.T) {
	root := filepath.Join("testdata", "go_binary_versioned")
	data, err := os.ReadFile(filepath.Join(root, "proposal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var proposal struct {
		Status  string `json:"status"`
		Fixture struct {
			FilesSHA256 map[string]string `json:"files_sha256"`
		} `json:"fixture"`
		DiagnosticObservations []struct {
			ID             string `json:"id"`
			Source         string `json:"source"`
			QueryIdentity  string `json:"query_identity"`
			ReachableClaim bool   `json:"reachable_claim"`
		} `json:"diagnostic_observations"`
	}
	if err := json.Unmarshal(data, &proposal); err != nil {
		t.Fatal(err)
	}
	if proposal.Status != "diagnostic_only" || len(proposal.Fixture.FilesSHA256) != 5 {
		t.Fatalf("Go-binary proposal status or file inventory changed: %#v", proposal)
	}
	wantCases := map[string]struct {
		source, identity string
		reachable        bool
	}{
		"direct-call":           {"direct.go.txt", "pkg:golang/golang.org/x/net@v0.59.0", true},
		"retained-but-uncalled": {"retained.go.txt", "pkg:golang/golang.org/x/net@v0.59.0", false},
		"retained-and-called":   {"retained_called.go.txt", "pkg:golang/golang.org/x/net@v0.59.0", true},
		"unversioned-identity":  {"direct.go.txt", "pkg:golang/golang.org/x/net", false},
		"wrong-version":         {"direct.go.txt", "pkg:golang/golang.org/x/net@v0.58.0", false},
	}
	if len(proposal.DiagnosticObservations) != len(wantCases) {
		t.Fatalf("Go-binary proposal observation count = %d, want %d", len(proposal.DiagnosticObservations), len(wantCases))
	}
	for _, observation := range proposal.DiagnosticObservations {
		want, exists := wantCases[observation.ID]
		if !exists || observation.Source != want.source || observation.QueryIdentity != want.identity || observation.ReachableClaim != want.reachable {
			t.Fatalf("Go-binary proposal observation = %#v, want %q with its pinned source, identity, and result", observation, observation.ID)
		}
		delete(wantCases, observation.ID)
	}
	for name, want := range proposal.Fixture.FilesSHA256 {
		contents, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		actual := sha256.Sum256(contents)
		if got := hex.EncodeToString(actual[:]); got != want {
			t.Fatalf("Go-binary fixture %q digest = %s, want %s", name, got, want)
		}
	}
}

func TestGoBinaryProductionCaptureUsesRaiseOnlyEntrypointCallProof(t *testing.T) {
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain unavailable")
	}
	const symbol = "golang.org/x/net/idna.ToASCII"
	build := func(source string) string {
		t.Helper()
		root := t.TempDir()
		for name, sourceName := range map[string]string{
			"go.mod":  "go.mod",
			"go.sum":  "go.sum",
			"main.go": source,
		} {
			contents, err := os.ReadFile(filepath.Join("testdata", "go_binary_versioned", sourceName))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, name), contents, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		binary := filepath.Join(root, "capture-binary")
		command := exec.Command(goPath, "build", "-trimpath", "-o", binary, ".")
		command.Dir = root
		command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOTOOLCHAIN=local")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build versioned Go-binary fixture %q: %v: %s", source, err, output)
		}
		buildInfo, err := exec.Command(goPath, "version", "-m", binary).CombinedOutput()
		if err != nil || !strings.Contains(string(buildInfo), "dep\tgolang.org/x/net\tv0.59.0\t") {
			t.Fatalf("fixture %q lacks pinned x/net build identity: %v", source, err)
		}
		if strings.HasPrefix(source, "retained") {
			symbols, err := exec.Command(goPath, "tool", "nm", binary).CombinedOutput()
			if err != nil || !strings.Contains(string(symbols), " T main.controlUnreached") {
				t.Fatalf("fixture %q does not retain controlUnreached: %v", source, err)
			}
		}
		return root
	}
	directRoot := build("direct.go.txt")
	retainedRoot := build("retained.go.txt")
	retainedCalledRoot := build("retained_called.go.txt")

	for _, tc := range []struct {
		name            string
		root            string
		packageIdentity string
		wantReachable   bool
		wantEntrypoint  bool
	}{
		{name: "direct call", root: directRoot, packageIdentity: "pkg:golang/golang.org/x/net@v0.59.0", wantReachable: true, wantEntrypoint: true},
		{name: "retained but uncalled", root: retainedRoot, packageIdentity: "pkg:golang/golang.org/x/net@v0.59.0"},
		{name: "retained and called", root: retainedCalledRoot, packageIdentity: "pkg:golang/golang.org/x/net@v0.59.0", wantReachable: true, wantEntrypoint: true},
		{name: "unversioned identity", root: directRoot, packageIdentity: "pkg:golang/golang.org/x/net"},
		{name: "wrong version", root: directRoot, packageIdentity: "pkg:golang/golang.org/x/net@v0.58.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved := measurement.ResolvedFixtureSubject{Subject: measurement.FixtureSubject{
				ID:              "versioned-dependency",
				PackageIdentity: tc.packageIdentity,
				Locator: measurement.FixtureLocator{
					Kind:   measurement.FixtureLocatorSourceSymbol,
					Symbol: symbol,
				},
			}}
			lifecycle, err := newCaptureLifecycle()
			if err != nil {
				t.Fatal(err)
			}
			executed, err := runGoBinary(context.Background(), nil, MaterializedFixture{Root: tc.root}, resolved, lifecycle)
			if err != nil {
				t.Fatal(err)
			}
			if executed.analyzerError != nil || executed.analyzer == nil || executed.analyzer.result == nil {
				t.Fatalf("Go-binary analysis did not complete: %#v", executed.analyzerError)
			}
			if tc.wantEntrypoint && (len(executed.analyzer.result.Entrypoints) != 1 || executed.analyzer.result.Entrypoints[0] != "main.main") {
				t.Fatalf("Go-binary entrypoints = %v, want main.main", executed.analyzer.result.Entrypoints)
			}
			judgments, err := lifecycle.judgments.List(context.Background(), productionCaptureEngagementID)
			if err != nil {
				t.Fatal(err)
			}
			claim, found := judgment.WinningReachabilityClaims(judgments)[resolved.Subject.ID]
			if tc.wantReachable {
				if !found || claim.Reachable != judgment.Reachable || claim.SuppressesFinding() {
					t.Fatalf("Go-binary claim = %#v, want a non-suppressing reachable claim", claim)
				}
				if len(claim.Path) < 2 || claim.Path[0] != "main.main" || claim.Path[len(claim.Path)-1] != symbol {
					t.Fatalf("Go-binary witness = %v, want main.main to %s", claim.Path, symbol)
				}
				return
			}
			if found || len(judgments) != 0 {
				t.Fatalf("unproven Go-binary call minted judgments: %#v", judgments)
			}
		})
	}
}

func TestVersionedGoBinaryProposalCannotChangeFrozenTrustedInventory(t *testing.T) {
	input, err := measurement.DefaultBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for cohortIndex := range input.Inventory.Cohorts {
		cohort := &input.Inventory.Cohorts[cohortIndex]
		if cohort.ID != "go" || cohort.Mode != "binary" {
			continue
		}
		for bindingIndex := range cohort.Bindings {
			binding := &cohort.Bindings[bindingIndex]
			if binding.ID == "worker" {
				binding.State = measurement.BindingEnabled
				binding.Reason = ""
				changed = true
			}
		}
	}
	if !changed {
		t.Fatal("frozen inventory has no Go-binary worker binding")
	}
	if err := validateFrozenTemplateStaticContract(input); err == nil || !strings.Contains(err.Error(), "inventory") {
		t.Fatalf("modified trusted inventory error = %v, want frozen inventory rejection", err)
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
