package reachbench

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

const CurrentGoBinaryScorecardSchemaVersion = "synapse-reachability-current-go-binary-scorecard-v1"

//go:embed current_go_binary_fixture/go.mod.txt
var currentGoBinaryGoMod []byte

//go:embed current_go_binary_fixture/go.sum.txt
var currentGoBinaryGoSum []byte

//go:embed current_go_binary_fixture/direct.go.txt
var currentGoBinaryDirect []byte

//go:embed current_go_binary_fixture/retained.go.txt
var currentGoBinaryRetained []byte

//go:embed current_go_binary_fixture/retained_called.go.txt
var currentGoBinaryRetainedCalled []byte

type currentGoBinaryCase struct {
	ID       string
	Source   []byte
	Subject  string
	Expected measurement.Outcome
	Coverage measurement.CoverageStatus
}

// CurrentGoBinaryFixture describes one pinned binary and its independent oracle.
type CurrentGoBinaryFixture struct {
	ID               string
	Subject          string
	ExpectedOutcome  measurement.Outcome
	ExpectedCoverage measurement.CoverageStatus
}

func CurrentGoBinaryFixtures() []CurrentGoBinaryFixture {
	fixtures := make([]CurrentGoBinaryFixture, 0, len(currentGoBinaryCases))
	for _, item := range currentGoBinaryCases {
		fixtures = append(fixtures, CurrentGoBinaryFixture{item.ID, item.Subject, item.Expected, item.Coverage})
	}
	return fixtures
}

func MaterializeCurrentGoBinaryFixture(ctx context.Context, workRoot, caseID string) (string, error) {
	for _, item := range currentGoBinaryCases {
		if item.ID == caseID {
			return materializeCurrentGoBinary(ctx, workRoot, item)
		}
	}
	return "", fmt.Errorf("unknown current Go-binary fixture %q", caseID)
}

var currentGoBinaryCases = []currentGoBinaryCase{
	{ID: "versioned-direct-call", Source: currentGoBinaryDirect, Subject: "pkg:golang/golang.org/x/net@v0.59.0", Expected: measurement.OutcomeReachable, Coverage: measurement.CoverageComplete},
	{ID: "versioned-retained-uncalled", Source: currentGoBinaryRetained, Subject: "pkg:golang/golang.org/x/net@v0.59.0", Expected: measurement.OutcomeNoAnalysis, Coverage: measurement.CoverageUnavailable},
	{ID: "versioned-retained-called", Source: currentGoBinaryRetainedCalled, Subject: "pkg:golang/golang.org/x/net@v0.59.0", Expected: measurement.OutcomeReachable, Coverage: measurement.CoverageComplete},
	{ID: "unversioned-identity", Source: currentGoBinaryDirect, Subject: "pkg:golang/golang.org/x/net", Expected: measurement.OutcomeNoAnalysis, Coverage: measurement.CoverageUnavailable},
	{ID: "wrong-version", Source: currentGoBinaryDirect, Subject: "pkg:golang/golang.org/x/net@v0.58.0", Expected: measurement.OutcomeNoAnalysis, Coverage: measurement.CoverageUnavailable},
}

// CurrentGoBinaryScorecard is a current-contract hosted regression result. It
// is intentionally separate from the frozen trusted lifecycle bundle.
type CurrentGoBinaryScorecard struct {
	SchemaVersion   string                `json:"schema_version"`
	Source          RevisionIdentity      `json:"source"`
	InventoryID     string                `json:"inventory_id"`
	InventoryDigest string                `json:"inventory_digest"`
	FixtureDigest   string                `json:"fixture_digest"`
	OracleDigest    string                `json:"oracle_digest"`
	OracleCases     int                   `json:"oracle_cases"`
	Bindings        []CurrentBindingScore `json:"bindings"`
	RequiredCells   int                   `json:"required_cells"`
	ObservedCells   int                   `json:"observed_cells"`
	Decision        string                `json:"decision"`
}

type CurrentBindingScore struct {
	BindingID          string             `json:"binding_id"`
	Cases              []CurrentCaseScore `json:"cases"`
	RequiredCells      int                `json:"required_cells"`
	ObservedCells      int                `json:"observed_cells"`
	CorrectOutcomes    int                `json:"correct_outcomes"`
	CorrectCoverage    int                `json:"correct_coverage"`
	PositiveCells      int                `json:"positive_cells"`
	CorrectPositives   int                `json:"correct_positives"`
	NoAnalysisCells    int                `json:"no_analysis_cells"`
	CorrectNoAnalysis  int                `json:"correct_no_analysis"`
	FalseSuppressions  int                `json:"false_suppressions"`
	DroppedFindings    int                `json:"dropped_findings"`
	ReachablePrecision float64            `json:"reachable_precision"`
	ReachableRecall    float64            `json:"reachable_recall"`
	CoverageRate       float64            `json:"coverage_rate"`
	NoAnalysisRate     float64            `json:"no_analysis_rate"`
	RatchetPassed      bool               `json:"ratchet_passed"`
}

type CurrentCaseScore struct {
	ID               string                     `json:"id"`
	ExpectedOutcome  measurement.Outcome        `json:"expected_outcome"`
	ActualOutcome    measurement.Outcome        `json:"actual_outcome"`
	ExpectedCoverage measurement.CoverageStatus `json:"expected_coverage"`
	ActualCoverage   measurement.CoverageStatus `json:"actual_coverage"`
	JudgmentCount    int                        `json:"judgment_count"`
	FindingRetained  bool                       `json:"finding_retained"`
	GateExempted     bool                       `json:"gate_exempted"`
}

type currentBindingReport struct {
	BindingID string             `json:"binding_id"`
	Cases     []CurrentCaseScore `json:"cases"`
}

func RunCurrentGoBinaryScorecard(ctx context.Context, source RevisionIdentity, reportDir string) (CurrentGoBinaryScorecard, error) {
	if err := validateRevision(source); err != nil {
		return CurrentGoBinaryScorecard{}, fmt.Errorf("current Go-binary scorecard source: %w", err)
	}
	if reportDir == "" {
		return CurrentGoBinaryScorecard{}, errors.New("current Go-binary binding report directory is required")
	}
	inventory, err := measurement.CurrentProductionInventory()
	if err != nil {
		return CurrentGoBinaryScorecard{}, err
	}
	bindings, err := currentGoBinaryBindings(inventory)
	if err != nil {
		return CurrentGoBinaryScorecard{}, err
	}
	inventoryDigest, err := measurement.DigestProductionInventory(inventory)
	if err != nil {
		return CurrentGoBinaryScorecard{}, fmt.Errorf("digest current Go-binary inventory: %w", err)
	}
	fixtureDigest := digestCurrentFixture()
	oracleDigest := digestCurrentOracle()
	scorecard := CurrentGoBinaryScorecard{SchemaVersion: CurrentGoBinaryScorecardSchemaVersion, Source: source, InventoryID: inventory.ID, InventoryDigest: inventoryDigest, FixtureDigest: fixtureDigest, OracleDigest: oracleDigest, OracleCases: len(currentGoBinaryCases), RequiredCells: len(bindings) * len(currentGoBinaryCases)}
	for _, binding := range bindings {
		if err := ctx.Err(); err != nil {
			return CurrentGoBinaryScorecard{}, err
		}
		report, err := readCurrentBindingReport(filepath.Join(reportDir, binding.ID+".json"))
		if err != nil {
			return CurrentGoBinaryScorecard{}, fmt.Errorf("read %s production binding report: %w", binding.ID, err)
		}
		if report.BindingID != binding.ID || len(report.Cases) != len(currentGoBinaryCases) {
			return CurrentGoBinaryScorecard{}, fmt.Errorf("%s production binding report is incomplete or misbound", binding.ID)
		}
		score := CurrentBindingScore{BindingID: binding.ID, RequiredCells: len(currentGoBinaryCases)}
		byID := make(map[string]CurrentCaseScore, len(report.Cases))
		for _, observed := range report.Cases {
			if _, duplicate := byID[observed.ID]; duplicate {
				return CurrentGoBinaryScorecard{}, fmt.Errorf("%s production binding report repeats case %q", binding.ID, observed.ID)
			}
			byID[observed.ID] = observed
		}
		observedReachable := 0
		observedComplete := 0
		observedNoAnalysis := 0
		for _, item := range currentGoBinaryCases {
			observed, ok := byID[item.ID]
			if !ok {
				return CurrentGoBinaryScorecard{}, fmt.Errorf("%s production binding report omits case %q", binding.ID, item.ID)
			}
			if observed.ExpectedOutcome != item.Expected || observed.ExpectedCoverage != item.Coverage || observed.JudgmentCount < 0 || observed.JudgmentCount > 1 {
				return CurrentGoBinaryScorecard{}, fmt.Errorf("%s production binding report has invalid oracle or judgment for %q", binding.ID, item.ID)
			}
			if observed.ActualOutcome != measurement.OutcomeReachable && observed.ActualOutcome != measurement.OutcomeNoAnalysis {
				return CurrentGoBinaryScorecard{}, fmt.Errorf("%s production binding report has invalid outcome for %q", binding.ID, item.ID)
			}
			if observed.ActualCoverage != measurement.CoverageComplete && observed.ActualCoverage != measurement.CoverageUnavailable {
				return CurrentGoBinaryScorecard{}, fmt.Errorf("%s production binding report has invalid coverage for %q", binding.ID, item.ID)
			}
			score.Cases = append(score.Cases, observed)
			scorecard.ObservedCells++
			score.ObservedCells++
			if observed.ActualOutcome == item.Expected {
				score.CorrectOutcomes++
			}
			if observed.ActualCoverage == item.Coverage {
				score.CorrectCoverage++
			}
			if item.Expected == measurement.OutcomeReachable {
				score.PositiveCells++
				if observed.ActualOutcome == item.Expected && observed.JudgmentCount == 1 {
					score.CorrectPositives++
				}
			}
			if item.Expected == measurement.OutcomeNoAnalysis {
				score.NoAnalysisCells++
				if observed.ActualOutcome == item.Expected && observed.JudgmentCount == 0 {
					score.CorrectNoAnalysis++
				}
			}
			if observed.GateExempted {
				score.FalseSuppressions++
			}
			if !observed.FindingRetained {
				score.DroppedFindings++
			}
			if observed.ActualOutcome == measurement.OutcomeReachable {
				observedReachable++
			}
			if observed.ActualOutcome == measurement.OutcomeNoAnalysis {
				observedNoAnalysis++
			}
			if observed.ActualCoverage == measurement.CoverageComplete {
				observedComplete++
			}
		}
		if observedReachable > 0 {
			score.ReachablePrecision = float64(score.CorrectPositives) / float64(observedReachable)
		}
		score.ReachableRecall = float64(score.CorrectPositives) / float64(score.PositiveCells)
		score.CoverageRate = float64(observedComplete) / float64(score.RequiredCells)
		score.NoAnalysisRate = float64(observedNoAnalysis) / float64(score.RequiredCells)
		score.RatchetPassed = score.ObservedCells == score.RequiredCells && score.CorrectOutcomes == score.RequiredCells && score.CorrectCoverage == score.RequiredCells && score.CorrectPositives == score.PositiveCells && score.CorrectNoAnalysis == score.NoAnalysisCells && score.FalseSuppressions == 0 && score.DroppedFindings == 0
		scorecard.Bindings = append(scorecard.Bindings, score)
	}
	sort.Slice(scorecard.Bindings, func(i, j int) bool { return scorecard.Bindings[i].BindingID < scorecard.Bindings[j].BindingID })
	scorecard.Decision = "pass"
	for _, score := range scorecard.Bindings {
		if !score.RatchetPassed {
			scorecard.Decision = "fail"
			break
		}
	}
	return scorecard, nil
}

func readCurrentBindingReport(path string) (currentBindingReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return currentBindingReport{}, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return currentBindingReport{}, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > 64*1024 {
		return currentBindingReport{}, errors.New("binding report must be a small regular file")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024+1))
	decoder.DisallowUnknownFields()
	var report currentBindingReport
	if err := decoder.Decode(&report); err != nil {
		return currentBindingReport{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return currentBindingReport{}, errors.New("binding report contains trailing data")
	}
	return report, nil
}

func materializeCurrentGoBinary(ctx context.Context, workRoot string, item currentGoBinaryCase) (string, error) {
	root := filepath.Join(workRoot, benchmark.SHA256Digest([]byte(item.ID))[7:])
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	for _, file := range []struct {
		name string
		body []byte
	}{{"go.mod", currentGoBinaryGoMod}, {"go.sum", currentGoBinaryGoSum}, {"main.go", item.Source}} {
		if err := os.WriteFile(filepath.Join(root, file.name), file.body, 0o600); err != nil {
			return "", err
		}
	}
	buildCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(buildCtx, "go", "-C", root, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", filepath.Join(root, "reachbench-binary"), ".")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOPROXY=off", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build pinned fixture: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return root, nil
}

func currentGoBinaryBindings(inventory measurement.ProductionInventory) ([]measurement.CompositionBinding, error) {
	for _, cohort := range inventory.Cohorts {
		if cohort.ID != "go" || cohort.Mode != "binary" {
			continue
		}
		var bindings []measurement.CompositionBinding
		for _, binding := range cohort.Bindings {
			if binding.ID != "api" && binding.ID != "worker" {
				continue
			}
			if binding.State != measurement.BindingEnabled {
				return nil, fmt.Errorf("current Go-binary binding %q is not enabled", binding.ID)
			}
			bindings = append(bindings, binding)
		}
		if len(bindings) != 2 {
			return nil, errors.New("current Go-binary scorecard requires enabled api and worker bindings")
		}
		sort.Slice(bindings, func(i, j int) bool { return bindings[i].ID < bindings[j].ID })
		return bindings, nil
	}
	return nil, errors.New("current production inventory lacks go/binary")
}

func digestCurrentFixture() string {
	return benchmark.SHA256Digest(bytesForDigest(currentGoBinaryGoMod, currentGoBinaryGoSum, currentGoBinaryDirect, currentGoBinaryRetained, currentGoBinaryRetainedCalled))
}
func digestCurrentOracle() string {
	parts := make([][]byte, 0, len(currentGoBinaryCases)*4)
	for _, item := range currentGoBinaryCases {
		parts = append(parts, []byte(item.ID), []byte(item.Subject), []byte(item.Expected), []byte(item.Coverage))
	}
	return benchmark.SHA256Digest(bytesForDigest(parts...))
}
func bytesForDigest(parts ...[]byte) []byte {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write(part)
		_, _ = hash.Write([]byte{0})
	}
	return hash.Sum(nil)
}

func WriteCurrentGoBinaryScorecard(path string, scorecard CurrentGoBinaryScorecard) error {
	if scorecard.SchemaVersion != CurrentGoBinaryScorecardSchemaVersion || scorecard.Decision == "" || scorecard.RequiredCells == 0 || scorecard.ObservedCells != scorecard.RequiredCells {
		return errors.New("current Go-binary scorecard is incomplete")
	}
	encoded, err := benchmark.CanonicalJSON(scorecard)
	if err != nil {
		return fmt.Errorf("encode current Go-binary scorecard: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create current Go-binary scorecard output: %w", err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		return fmt.Errorf("write current Go-binary scorecard: %w", err)
	}
	return nil
}
