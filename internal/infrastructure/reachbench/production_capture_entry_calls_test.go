package reachbench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

type versionedGoBinaryCandidateObservation struct {
	ID               string `json:"id"`
	Source           string `json:"source"`
	Materialization  string `json:"materialization"`
	QueryIdentity    string `json:"query_identity"`
	ObservedOutcome  string `json:"observed_outcome"`
	ObservedCoverage string `json:"observed_coverage"`
	JudgmentState    string `json:"judgment_state"`
}

type versionedGoBinaryProposal struct {
	Status        string `json:"status"`
	Authoritative bool   `json:"authoritative"`
	Fixture       struct {
		FilesSHA256 map[string]string `json:"files_sha256"`
	} `json:"fixture"`
	ProposedOracleMapping struct {
		Status        string `json:"status"`
		Authoritative bool   `json:"authoritative"`
		Cases         []struct {
			ID               string `json:"id"`
			SourceTruth      string `json:"source_truth"`
			ExpectedOutcome  string `json:"expected_outcome"`
			ExpectedCoverage string `json:"expected_coverage"`
		} `json:"cases"`
	} `json:"proposed_oracle_mapping"`
	CandidateObservations  []versionedGoBinaryCandidateObservation `json:"candidate_observations"`
	DiagnosticObservations []struct {
		ID             string `json:"id"`
		Source         string `json:"source"`
		QueryIdentity  string `json:"query_identity"`
		ReachableClaim bool   `json:"reachable_claim"`
	} `json:"diagnostic_observations"`
}

func loadVersionedGoBinaryProposal(t *testing.T) versionedGoBinaryProposal {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "go_binary_versioned", "proposal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var proposal versionedGoBinaryProposal
	if err := json.Unmarshal(data, &proposal); err != nil {
		t.Fatal(err)
	}
	return proposal
}

func candidateObservationByID(t *testing.T, proposal versionedGoBinaryProposal, id string) versionedGoBinaryCandidateObservation {
	t.Helper()
	for _, observation := range proposal.CandidateObservations {
		if observation.ID == id {
			return observation
		}
	}
	t.Fatalf("Go-binary proposal has no candidate observation %q", id)
	return versionedGoBinaryCandidateObservation{}
}

func TestVersionedGoBinaryFixtureFilesMatchProposal(t *testing.T) {
	root := filepath.Join("testdata", "go_binary_versioned")
	proposal := loadVersionedGoBinaryProposal(t)
	if proposal.Status != "pending_independent_review" || proposal.Authoritative || len(proposal.Fixture.FilesSHA256) != 6 {
		t.Fatalf("Go-binary proposal status or file inventory changed: %#v", proposal)
	}
	wantOracleCases := map[string]struct{ outcome, coverage string }{
		"direct-call":                  {string(measurement.OutcomeReachable), string(measurement.CoverageComplete)},
		"retained-but-uncalled":        {string(measurement.OutcomePresentUnreached), string(measurement.CoverageComplete)},
		"retained-and-called":          {string(measurement.OutcomeReachable), string(measurement.CoverageComplete)},
		"indirect-function-value-call": {string(measurement.OutcomeConditionallyReachable), string(measurement.CoveragePartial)},
		"empty-root-unavailable":       {string(measurement.OutcomeNoAnalysis), string(measurement.CoverageUnavailable)},
	}
	if proposal.ProposedOracleMapping.Status != "pending_independent_review" || proposal.ProposedOracleMapping.Authoritative || len(proposal.ProposedOracleMapping.Cases) != len(wantOracleCases) {
		t.Fatalf("Go-binary proposed oracle mapping is not pending, non-authoritative five-case review material: %#v", proposal.ProposedOracleMapping)
	}
	for _, oracleCase := range proposal.ProposedOracleMapping.Cases {
		want, exists := wantOracleCases[oracleCase.ID]
		if !exists || strings.TrimSpace(oracleCase.SourceTruth) == "" || oracleCase.ExpectedOutcome != want.outcome || oracleCase.ExpectedCoverage != want.coverage {
			t.Fatalf("Go-binary proposed oracle case = %#v, want independently reviewable source truth and expected mapping", oracleCase)
		}
		delete(wantOracleCases, oracleCase.ID)
	}
	wantCandidateObservations := map[string]struct {
		source, materialization, identity, outcome, coverage, judgment string
	}{
		"direct-call":                  {"direct.go.txt", "linux-amd64-go-build", "pkg:golang/golang.org/x/net@v0.59.0", string(measurement.OutcomeReachable), string(measurement.CoverageComplete), "non_suppressing"},
		"retained-but-uncalled":        {"retained.go.txt", "linux-amd64-go-build", "pkg:golang/golang.org/x/net@v0.59.0", string(measurement.OutcomeNoAnalysis), string(measurement.CoverageUnavailable), "non_suppressing"},
		"retained-and-called":          {"retained_called.go.txt", "linux-amd64-go-build", "pkg:golang/golang.org/x/net@v0.59.0", string(measurement.OutcomeReachable), string(measurement.CoverageComplete), "non_suppressing"},
		"indirect-function-value-call": {"indirect.go.txt", "linux-amd64-go-build", "pkg:golang/golang.org/x/net@v0.59.0", string(measurement.OutcomeNoAnalysis), string(measurement.CoverageUnavailable), "non_suppressing"},
		"empty-root-unavailable":       {"empty-root", "empty-analysis-root", "pkg:golang/golang.org/x/net@v0.59.0", string(measurement.OutcomeNoAnalysis), string(measurement.CoverageUnavailable), "non_suppressing"},
	}
	if len(proposal.CandidateObservations) != len(wantCandidateObservations) {
		t.Fatalf("Go-binary candidate observation count = %d, want %d", len(proposal.CandidateObservations), len(wantCandidateObservations))
	}
	for _, observation := range proposal.CandidateObservations {
		want, exists := wantCandidateObservations[observation.ID]
		if !exists || observation.Source != want.source || observation.Materialization != want.materialization || observation.QueryIdentity != want.identity || observation.ObservedOutcome != want.outcome || observation.ObservedCoverage != want.coverage || observation.JudgmentState != want.judgment {
			t.Fatalf("Go-binary candidate observation = %#v, want complete production measurement metadata", observation)
		}
		delete(wantCandidateObservations, observation.ID)
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
	proposal := loadVersionedGoBinaryProposal(t)
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain unavailable")
	}
	const symbol = "golang.org/x/net/idna.ToASCII"
	build := func(source string) (string, string) {
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
		return root, binary
	}
	directRoot, _ := build("direct.go.txt")
	retainedRoot, _ := build("retained.go.txt")
	retainedCalledRoot, _ := build("retained_called.go.txt")
	indirectRoot, indirectBinary := build("indirect.go.txt")
	if runtime.GOOS == "linux" {
		if output, err := exec.Command(indirectBinary).CombinedOutput(); err != nil {
			t.Fatalf("run non-invoking indirect function-value Go-binary fixture: %v: %s", err, output)
		} else if got := string(output); got != "" {
			t.Fatalf("non-invoking indirect function-value Go-binary output = %q, want empty", got)
		}
		if output, err := exec.Command(indirectBinary, "invoke").CombinedOutput(); err != nil {
			t.Fatalf("run invoking indirect function-value Go-binary fixture: %v: %s", err, output)
		} else if got, want := string(output), "xn--bcher-kva.example\n"; got != want {
			t.Fatalf("indirect function-value Go-binary output = %q, want %q", got, want)
		}
	}

	for _, tc := range []struct {
		name            string
		root            string
		packageIdentity string
		wantReachable   bool
		wantEntrypoint  bool
		candidateID     string
		wantOutcome     measurement.Outcome
		wantCoverage    measurement.CoverageStatus
	}{
		{name: "direct call", root: directRoot, packageIdentity: "pkg:golang/golang.org/x/net@v0.59.0", wantReachable: true, wantEntrypoint: true, candidateID: "direct-call"},
		// The retained source control is pending oracle review as present/unreached;
		// the current analyzer observation is unavailable and must remain distinct.
		{name: "retained but uncalled", root: retainedRoot, packageIdentity: "pkg:golang/golang.org/x/net@v0.59.0", candidateID: "retained-but-uncalled"},
		{name: "retained and called", root: retainedCalledRoot, packageIdentity: "pkg:golang/golang.org/x/net@v0.59.0", wantReachable: true, wantEntrypoint: true, candidateID: "retained-and-called"},
		// The source truth remains a runtime-reachable function-value call. Its current
		// analyzer observation is deliberately recorded separately from that pending oracle.
		{name: "indirect function-value call", root: indirectRoot, packageIdentity: "pkg:golang/golang.org/x/net@v0.59.0", candidateID: "indirect-function-value-call"},
		{name: "unversioned identity", root: directRoot, packageIdentity: "pkg:golang/golang.org/x/net", wantOutcome: measurement.OutcomeNoAnalysis, wantCoverage: measurement.CoverageUnavailable},
		{name: "wrong version", root: directRoot, packageIdentity: "pkg:golang/golang.org/x/net@v0.58.0", wantOutcome: measurement.OutcomeNoAnalysis, wantCoverage: measurement.CoverageUnavailable},
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
			captureObservation, err := (&ProductionCapture{}).observation(context.Background(), CaptureRequest{Cell: ExecutionCell{CaseID: "versioned-go-binary", BindingID: "worker", AnalyzerID: "entry-call", SubjectID: resolved.Subject.ID}}, lifecycle, executed)
			if err != nil {
				t.Fatal(err)
			}
			wantOutcome, wantCoverage := tc.wantOutcome, tc.wantCoverage
			if tc.candidateID != "" {
				candidate := candidateObservationByID(t, proposal, tc.candidateID)
				wantOutcome, wantCoverage = measurement.Outcome(candidate.ObservedOutcome), measurement.CoverageStatus(candidate.ObservedCoverage)
				if candidate.JudgmentState != "non_suppressing" {
					t.Fatalf("candidate observation %q judgment state = %q, want non_suppressing", candidate.ID, candidate.JudgmentState)
				}
			}
			if captureObservation.Outcome != wantOutcome || captureObservation.Coverage.Status != wantCoverage {
				t.Fatalf("production capture observation = outcome %s, coverage %s; want %s/%s", captureObservation.Outcome, captureObservation.Coverage.Status, wantOutcome, wantCoverage)
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

	t.Run("empty root unavailable", func(t *testing.T) {
		resolved := measurement.ResolvedFixtureSubject{Subject: measurement.FixtureSubject{
			ID:              "versioned-dependency",
			PackageIdentity: "pkg:golang/golang.org/x/net@v0.59.0",
			Locator:         measurement.FixtureLocator{Kind: measurement.FixtureLocatorSourceSymbol, Symbol: symbol},
		}}
		lifecycle, err := newCaptureLifecycle()
		if err != nil {
			t.Fatal(err)
		}
		executed, err := runGoBinary(context.Background(), nil, MaterializedFixture{Root: t.TempDir()}, resolved, lifecycle)
		if err != nil {
			t.Fatal(err)
		}
		observation, err := (&ProductionCapture{}).observation(context.Background(), CaptureRequest{Cell: ExecutionCell{CaseID: "versioned-go-binary", BindingID: "worker", AnalyzerID: "entry-call", SubjectID: resolved.Subject.ID}}, lifecycle, executed)
		if err != nil {
			t.Fatal(err)
		}
		candidate := candidateObservationByID(t, proposal, "empty-root-unavailable")
		if candidate.JudgmentState != "non_suppressing" {
			t.Fatalf("empty-root candidate judgment state = %q, want non_suppressing", candidate.JudgmentState)
		}
		if observation.Outcome != measurement.Outcome(candidate.ObservedOutcome) || observation.Coverage.Status != measurement.CoverageStatus(candidate.ObservedCoverage) {
			t.Fatalf("empty-root observation = outcome %s, coverage %s; want %s/%s", observation.Outcome, observation.Coverage.Status, candidate.ObservedOutcome, candidate.ObservedCoverage)
		}
		judgments, err := lifecycle.judgments.List(context.Background(), productionCaptureEngagementID)
		if err != nil {
			t.Fatal(err)
		}
		if len(judgments) != 0 {
			t.Fatalf("empty-root analysis minted judgments: %#v", judgments)
		}
	})
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
	if err := validateFrozenTemplateStaticContract(input); err == nil {
		t.Fatal("modified trusted inventory resolved to a registered benchmark profile")
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
