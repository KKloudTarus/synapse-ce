package reachbench

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func TestCurrentGoBinarySourceClean(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  []byte
		gitErr  error
		clean   bool
		wantErr bool
	}{
		{name: "clean", clean: true},
		{name: "modified", status: []byte(" M go.mod\x00")},
		{name: "untracked", status: []byte("?? fixture.go\x00")},
		{name: "git failure", gitErr: errors.New("git unavailable"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &Runner{dependencies: Dependencies{Command: func(_ context.Context, binary string, args ...string) ([]byte, error) {
				if binary != "git" || strings.Join(args, " ") != "status --porcelain=v1 -z --untracked-files=all" {
					t.Fatalf("unexpected source status command: %s %v", binary, args)
				}
				return tc.status, tc.gitErr
			}}}
			clean, err := currentGoBinarySourceClean(context.Background(), runner)
			if clean != tc.clean || (err != nil) != tc.wantErr {
				t.Fatalf("source clean = %t, err = %v; want clean = %t, error = %t", clean, err, tc.clean, tc.wantErr)
			}
		})
	}
}

func TestCurrentGoBinaryOracleIsVersionBoundAndCoversControls(t *testing.T) {
	input, err := loadCurrentGoBinaryInput()
	if err != nil {
		t.Fatal(err)
	}
	positives, noAnalysis := 0, 0
	for _, item := range currentGoBinaryCases(input) {
		if item.Expected == measurement.OutcomeReachable {
			positives++
		}
		if item.Expected == measurement.OutcomeNoAnalysis {
			noAnalysis++
		}
		if item.ID != "unversioned-identity" && item.ID != "wrong-version" && !strings.Contains(item.Subject, "@"+input.netVersion) {
			t.Fatalf("case %q is not version-bound: %q", item.ID, item.Subject)
		}
	}
	if positives != 2 || noAnalysis != 5 {
		t.Fatalf("oracle coverage = positives %d no-analysis %d", positives, noAnalysis)
	}
}

func TestCurrentGoBinaryFixtureUsesRootModulePins(t *testing.T) {
	input, err := loadCurrentGoBinaryInput()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(input.goMod), "golang.org/x/net "+input.netVersion) || !strings.Contains(string(input.goSum), "golang.org/x/net "+input.netVersion+" ") {
		t.Fatalf("fixture did not derive the current root x/net pin %s", input.netVersion)
	}
}

func TestCurrentGoBinaryFixtureFollowsDependencyBump(t *testing.T) {
	module := []byte("module github.com/KKloudTarus/synapse-ce\n\ngo 1.27.0\n\nrequire golang.org/x/net v0.60.0\nrequire golang.org/x/text v0.43.0\n")
	sums := []byte("golang.org/x/net v0.60.0 h1:net\ngolang.org/x/net v0.60.0/go.mod h1:netmod\ngolang.org/x/text v0.43.0 h1:text\ngolang.org/x/text v0.43.0/go.mod h1:textmod\n")
	input, err := deriveCurrentGoBinaryInput(module, sums)
	if err != nil {
		t.Fatal(err)
	}
	if input.netVersion != "v0.60.0" || !strings.Contains(string(input.goMod), "golang.org/x/text v0.43.0") || currentGoBinaryCases(input)[0].Subject != "pkg:golang/golang.org/x/net@v0.60.0" {
		t.Fatalf("fixture and oracle did not follow root dependency pins: %+v", input)
	}
	if _, err := deriveCurrentGoBinaryInput(module, sums[:len(sums)-len("golang.org/x/text v0.43.0/go.mod h1:textmod\n")]); err == nil || !strings.Contains(err.Error(), "go.sum lacks") {
		t.Fatalf("missing checksum was accepted: %v", err)
	}
}

func TestCurrentGoBinaryBindingsRequireWorker(t *testing.T) {
	_, err := currentGoBinaryBindings(measurement.ProductionInventory{Cohorts: []measurement.ProductionCohort{{ID: "go", Mode: "binary", Bindings: []measurement.CompositionBinding{{ID: "api", State: measurement.BindingEnabled}}}}})
	if err == nil || !strings.Contains(err.Error(), "api and worker") {
		t.Fatalf("missing worker error = %v", err)
	}
}

func TestCurrentProductionInventoryDoesNotReuseHistoricalCheckpointIdentity(t *testing.T) {
	historicalDigest, err := measurement.DigestProductionInventory(measurement.DefaultProductionInventory())
	if err != nil {
		t.Fatal(err)
	}
	current, err := measurement.CurrentProductionInventory()
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != "synapse-ce-current-go-binary-inventory-v1" {
		t.Fatalf("current contract reused historical inventory ID: %q", current.ID)
	}
	currentDigest, err := measurement.DigestProductionInventory(current)
	if err != nil {
		t.Fatal(err)
	}
	if historicalDigest == currentDigest {
		t.Fatal("current 100-cell inventory reused the historical 95-cell checkpoint identity")
	}
	bindings, err := currentGoBinaryBindings(current)
	if err != nil || len(bindings) != 2 {
		t.Fatalf("current worker contract = %#v, %v", bindings, err)
	}
	for _, cohort := range measurement.DefaultProductionInventory().Cohorts {
		if cohort.ID != "go" || cohort.Mode != "binary" {
			continue
		}
		for _, historical := range cohort.Bindings {
			if historical.ID == "worker" && historical.Configuration == bindings[1].Configuration {
				t.Fatal("enabled worker reused its historical not-wired configuration identity")
			}
		}
	}
}

func TestCurrentGoBinaryScorecardRequiresBothMeasuredBindingsAndRatchets(t *testing.T) {
	dir := t.TempDir()
	writeBindingReport(t, dir, "api", "")
	writeBindingReport(t, dir, "worker", "")
	scorecard, err := RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if scorecard.Decision != "pass" || scorecard.ObservedCells != 14 || len(scorecard.Bindings) != 2 {
		t.Fatalf("complete scorecard = %+v", scorecard)
	}
	for _, binding := range scorecard.Bindings {
		if len(binding.Cases) != 7 || binding.ReachablePrecision != 1 || binding.ReachableRecall != 1 || binding.CoverageRate != 2.0/7 || binding.NoAnalysisRate != 5.0/7 || binding.FalseSuppressions != 0 {
			t.Fatalf("binding score = %+v", binding)
		}
	}
	if err := os.Remove(filepath.Join(dir, "worker.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir); err == nil {
		t.Fatal("missing worker report did not fail closed")
	}
	writeBindingReport(t, dir, "worker", "drop")
	scorecard, err = RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if scorecard.Decision != "fail" || scorecard.Bindings[1].DroppedFindings != 1 {
		t.Fatalf("dropped finding did not fail ratchet: %+v", scorecard)
	}
	writeBindingReport(t, dir, "worker", "exempt")
	scorecard, err = RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if scorecard.Decision != "fail" || scorecard.Bindings[1].FalseSuppressions != 1 {
		t.Fatalf("gate exemption did not fail ratchet: %+v", scorecard)
	}
	writeBindingReport(t, dir, "worker", "miss")
	scorecard, err = RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir)
	if err != nil || scorecard.Decision != "fail" || scorecard.Bindings[1].ReachableRecall >= 1 {
		t.Fatalf("observed missed positive did not lower recall: %+v, %v", scorecard, err)
	}
	writeBindingReport(t, dir, "worker", "identity")
	if _, err := RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("mixed source identity was accepted: %v", err)
	}
	writeBindingReport(t, dir, "worker", "binary")
	if _, err := RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir); err == nil || !strings.Contains(err.Error(), "different binary") {
		t.Fatalf("mixed binary bytes were accepted: %v", err)
	}
}

func TestCurrentGoBinaryScorecardRejectsMixedIdentities(t *testing.T) {
	dir := t.TempDir()
	writeBindingReport(t, dir, "api", "")
	for _, defect := range []string{"dirty", "source_tree", "inventory_id", "inventory_digest", "fixture_digest", "oracle_digest", "toolchain"} {
		t.Run(defect, func(t *testing.T) {
			writeBindingReport(t, dir, "worker", defect)
			if _, err := RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir); err == nil || !strings.Contains(err.Error(), "identity") {
				t.Fatalf("mixed %s identity was accepted: %v", defect, err)
			}
		})
	}
}

func writeBindingReport(t *testing.T, dir, binding, defect string) {
	t.Helper()
	input, err := loadCurrentGoBinaryInput()
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := measurement.CurrentProductionInventory()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := measurement.DigestProductionInventory(inventory)
	if err != nil {
		t.Fatal(err)
	}
	report := CurrentGoBinaryBindingReport{SchemaVersion: CurrentGoBinaryBindingReportSchemaVersion, BindingID: binding, Source: scorecardSource(), SourceClean: true, InventoryID: inventory.ID, InventoryDigest: digest, FixtureDigest: digestCurrentFixture(input), OracleDigest: digestCurrentOracle(currentGoBinaryCases(input)), Toolchain: runtime.Version()}
	for _, item := range currentGoBinaryCases(input) {
		report.Cases = append(report.Cases, CurrentCaseScore{ID: item.ID, ExpectedOutcome: item.Expected, ActualOutcome: item.Expected, ExpectedCoverage: item.Coverage, ActualCoverage: item.Coverage, JudgmentCount: map[measurement.Outcome]int{measurement.OutcomeReachable: 1}[item.Expected], FindingRetained: true, GoBinaryEnabled: item.Enabled, JudgmentsEnabled: item.JudgmentsEnabled, BinaryDigest: "sha256:" + strings.Repeat("a", 64)})
	}
	if defect == "drop" {
		report.Cases[0].FindingRetained = false
	}
	if defect == "exempt" {
		report.Cases[0].GateExempted = true
	}
	if defect == "identity" {
		report.Source.Commit = strings.Repeat("c", 40)
	}
	if defect == "dirty" {
		report.SourceClean = false
	}
	if defect == "source_tree" {
		report.Source.Tree = strings.Repeat("c", 40)
	}
	if defect == "inventory_id" {
		report.InventoryID = "foreign-inventory"
	}
	if defect == "inventory_digest" {
		report.InventoryDigest = "sha256:" + strings.Repeat("c", 64)
	}
	if defect == "fixture_digest" {
		report.FixtureDigest = "sha256:" + strings.Repeat("c", 64)
	}
	if defect == "oracle_digest" {
		report.OracleDigest = "sha256:" + strings.Repeat("c", 64)
	}
	if defect == "toolchain" {
		report.Toolchain = "go0.0.0"
	}
	if defect == "binary" {
		report.Cases[0].BinaryDigest = "sha256:" + strings.Repeat("b", 64)
	}
	if defect == "miss" {
		report.Cases[0].ActualOutcome = measurement.OutcomeNoAnalysis
		report.Cases[0].ActualCoverage = measurement.CoverageUnavailable
		report.Cases[0].JudgmentCount = 0
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, binding+".json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func scorecardSource() RevisionIdentity {
	return RevisionIdentity{ID: AnalyzerSubjectID, Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40)}
}
