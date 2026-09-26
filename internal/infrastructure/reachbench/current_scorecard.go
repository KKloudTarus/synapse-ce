package reachbench

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
	"golang.org/x/mod/modfile"
)

const CurrentGoBinaryScorecardSchemaVersion = "synapse-reachability-current-go-binary-scorecard-v2"
const CurrentGoBinaryBindingReportSchemaVersion = "synapse-reachability-go-binary-binding-report-v1"

//go:embed current_go_binary_fixture/direct.go.txt
var currentGoBinaryDirect []byte

//go:embed current_go_binary_fixture/retained.go.txt
var currentGoBinaryRetained []byte

//go:embed current_go_binary_fixture/retained_called.go.txt
var currentGoBinaryRetainedCalled []byte

type currentGoBinaryCase struct {
	ID               string
	Source           []byte
	Subject          string
	Version          string
	Enabled          bool
	JudgmentsEnabled bool
	Expected         measurement.Outcome
	Coverage         measurement.CoverageStatus
}

type currentGoBinaryInput struct {
	goMod      []byte
	goSum      []byte
	netVersion string
}

// CurrentGoBinaryFixture describes one pinned binary and its independent oracle.
type CurrentGoBinaryFixture struct {
	ID               string
	Subject          string
	Version          string
	Enabled          bool
	JudgmentsEnabled bool
	ExpectedOutcome  measurement.Outcome
	ExpectedCoverage measurement.CoverageStatus
}

func CurrentGoBinaryFixtures() ([]CurrentGoBinaryFixture, error) {
	input, err := loadCurrentGoBinaryInput()
	if err != nil {
		return nil, err
	}
	cases := currentGoBinaryCases(input)
	fixtures := make([]CurrentGoBinaryFixture, 0, len(cases))
	for _, item := range cases {
		fixtures = append(fixtures, CurrentGoBinaryFixture{item.ID, item.Subject, item.Version, item.Enabled, item.JudgmentsEnabled, item.Expected, item.Coverage})
	}
	return fixtures, nil
}

func MaterializeCurrentGoBinaryFixture(ctx context.Context, workRoot, caseID string) (string, error) {
	input, err := loadCurrentGoBinaryInput()
	if err != nil {
		return "", err
	}
	for _, item := range currentGoBinaryCases(input) {
		if item.ID == caseID {
			return materializeCurrentGoBinary(ctx, workRoot, item, input)
		}
	}
	return "", fmt.Errorf("unknown current Go-binary fixture %q", caseID)
}

func currentGoBinaryCases(input currentGoBinaryInput) []currentGoBinaryCase {
	versioned := "pkg:golang/golang.org/x/net@" + input.netVersion
	wrong := "v0.0.0"
	if input.netVersion == wrong {
		wrong = "v0.0.1"
	}
	return []currentGoBinaryCase{
		{ID: "versioned-direct-call", Source: currentGoBinaryDirect, Subject: versioned, Version: input.netVersion, Enabled: true, JudgmentsEnabled: true, Expected: measurement.OutcomeReachable, Coverage: measurement.CoverageComplete},
		{ID: "versioned-retained-uncalled", Source: currentGoBinaryRetained, Subject: versioned, Version: input.netVersion, Enabled: true, JudgmentsEnabled: true, Expected: measurement.OutcomeNoAnalysis, Coverage: measurement.CoverageUnavailable},
		{ID: "versioned-retained-called", Source: currentGoBinaryRetainedCalled, Subject: versioned, Version: input.netVersion, Enabled: true, JudgmentsEnabled: true, Expected: measurement.OutcomeReachable, Coverage: measurement.CoverageComplete},
		{ID: "unversioned-identity", Source: currentGoBinaryDirect, Subject: "pkg:golang/golang.org/x/net", Version: input.netVersion, Enabled: true, JudgmentsEnabled: true, Expected: measurement.OutcomeNoAnalysis, Coverage: measurement.CoverageUnavailable},
		{ID: "wrong-version", Source: currentGoBinaryDirect, Subject: "pkg:golang/golang.org/x/net@" + wrong, Version: wrong, Enabled: true, JudgmentsEnabled: true, Expected: measurement.OutcomeNoAnalysis, Coverage: measurement.CoverageUnavailable},
		{ID: "go-binary-disabled", Source: currentGoBinaryDirect, Subject: versioned, Version: input.netVersion, Enabled: false, JudgmentsEnabled: true, Expected: measurement.OutcomeNoAnalysis, Coverage: measurement.CoverageUnavailable},
		{ID: "judgments-disabled", Source: currentGoBinaryDirect, Subject: versioned, Version: input.netVersion, Enabled: true, JudgmentsEnabled: false, Expected: measurement.OutcomeNoAnalysis, Coverage: measurement.CoverageUnavailable},
	}
}

// loadCurrentGoBinaryInput uses the checked-in root module pins. Compiling the
// test already fetches these exact modules; fixture builds remain offline even
// after a dependency update changes the Go module cache key.
func loadCurrentGoBinaryInput() (currentGoBinaryInput, error) {
	root, err := os.Getwd()
	if err != nil {
		return currentGoBinaryInput{}, err
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			return currentGoBinaryInput{}, errors.New("current Go-binary fixture requires the repository go.mod")
		}
		root = parent
	}
	rootMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return currentGoBinaryInput{}, err
	}
	rootSum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		return currentGoBinaryInput{}, err
	}
	return deriveCurrentGoBinaryInput(rootMod, rootSum)
}

func deriveCurrentGoBinaryInput(rootMod, rootSum []byte) (currentGoBinaryInput, error) {
	parsed, err := modfile.Parse("go.mod", rootMod, nil)
	if err != nil {
		return currentGoBinaryInput{}, fmt.Errorf("parse root go.mod: %w", err)
	}
	if parsed.Module == nil || parsed.Module.Mod.Path != "github.com/KKloudTarus/synapse-ce" || parsed.Go == nil {
		return currentGoBinaryInput{}, errors.New("current Go-binary fixture found an unexpected root go.mod")
	}
	versions := map[string]string{}
	for _, item := range parsed.Require {
		if item.Mod.Path == "golang.org/x/net" || item.Mod.Path == "golang.org/x/text" {
			versions[item.Mod.Path] = item.Mod.Version
		}
	}
	if versions["golang.org/x/net"] == "" || versions["golang.org/x/text"] == "" {
		return currentGoBinaryInput{}, errors.New("root go.mod must pin golang.org/x/net and golang.org/x/text")
	}
	var sums []string
	for _, module := range []string{"golang.org/x/net", "golang.org/x/text"} {
		for _, suffix := range []string{"", "/go.mod"} {
			prefix := module + " " + versions[module] + suffix + " "
			var found string
			for _, line := range strings.Split(string(rootSum), "\n") {
				if strings.HasPrefix(line, prefix) {
					found = line
					break
				}
			}
			if found == "" {
				return currentGoBinaryInput{}, fmt.Errorf("root go.sum lacks %s%s; run go mod download before the offline benchmark", module, suffix)
			}
			sums = append(sums, found)
		}
	}
	mod := fmt.Sprintf("module example.invalid/reachbench-binary\n\ngo %s\n\nrequire golang.org/x/net %s\n\nrequire golang.org/x/text %s // indirect\n", parsed.Go.Version, versions["golang.org/x/net"], versions["golang.org/x/text"])
	return currentGoBinaryInput{goMod: []byte(mod), goSum: []byte(strings.Join(sums, "\n") + "\n"), netVersion: versions["golang.org/x/net"]}, nil
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
	Toolchain       string                `json:"toolchain"`
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
	GoBinaryEnabled  bool                       `json:"go_binary_enabled"`
	JudgmentsEnabled bool                       `json:"judgments_enabled"`
	BinaryDigest     string                     `json:"binary_digest"`
}

// CurrentGoBinaryBindingReport carries the identities observed at the test root.
// The scorecard rejects reports whose source or inputs differ from its own.
type CurrentGoBinaryBindingReport struct {
	SchemaVersion   string             `json:"schema_version"`
	BindingID       string             `json:"binding_id"`
	Source          RevisionIdentity   `json:"source"`
	SourceClean     bool               `json:"source_clean"`
	InventoryID     string             `json:"inventory_id"`
	InventoryDigest string             `json:"inventory_digest"`
	FixtureDigest   string             `json:"fixture_digest"`
	OracleDigest    string             `json:"oracle_digest"`
	Toolchain       string             `json:"toolchain"`
	Cases           []CurrentCaseScore `json:"cases"`
}

func NewCurrentGoBinaryBindingReport(ctx context.Context, bindingID string) (CurrentGoBinaryBindingReport, error) {
	if bindingID != "api" && bindingID != "worker" {
		return CurrentGoBinaryBindingReport{}, fmt.Errorf("invalid current Go-binary binding %q", bindingID)
	}
	runner := &Runner{dependencies: DefaultDependencies()}
	harness, err := runner.deriveHarness(ctx)
	if err != nil {
		return CurrentGoBinaryBindingReport{}, fmt.Errorf("derive binding source revision: %w", err)
	}
	clean, err := currentGoBinarySourceClean(ctx, runner)
	if err != nil {
		return CurrentGoBinaryBindingReport{}, err
	}
	input, err := loadCurrentGoBinaryInput()
	if err != nil {
		return CurrentGoBinaryBindingReport{}, err
	}
	inventory, err := measurement.CurrentProductionInventory()
	if err != nil {
		return CurrentGoBinaryBindingReport{}, err
	}
	inventoryDigest, err := measurement.DigestProductionInventory(inventory)
	if err != nil {
		return CurrentGoBinaryBindingReport{}, err
	}
	return CurrentGoBinaryBindingReport{
		SchemaVersion: CurrentGoBinaryBindingReportSchemaVersion,
		BindingID:     bindingID,
		Source:        RevisionIdentity{ID: AnalyzerSubjectID, Commit: harness.Commit, Tree: harness.Tree},
		SourceClean:   clean,
		InventoryID:   inventory.ID, InventoryDigest: inventoryDigest,
		FixtureDigest: digestCurrentFixture(input), OracleDigest: digestCurrentOracle(currentGoBinaryCases(input)),
		Toolchain: runtime.Version(),
	}, nil
}

func RunCurrentGoBinaryScorecard(ctx context.Context, source RevisionIdentity, reportDir string) (CurrentGoBinaryScorecard, error) {
	if err := validateRevision(source); err != nil {
		return CurrentGoBinaryScorecard{}, fmt.Errorf("current Go-binary scorecard source: %w", err)
	}
	if reportDir == "" {
		return CurrentGoBinaryScorecard{}, errors.New("current Go-binary binding report directory is required")
	}
	input, err := loadCurrentGoBinaryInput()
	if err != nil {
		return CurrentGoBinaryScorecard{}, err
	}
	cases := currentGoBinaryCases(input)
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
	fixtureDigest := digestCurrentFixture(input)
	oracleDigest := digestCurrentOracle(cases)
	scorecard := CurrentGoBinaryScorecard{SchemaVersion: CurrentGoBinaryScorecardSchemaVersion, Source: source, InventoryID: inventory.ID, InventoryDigest: inventoryDigest, FixtureDigest: fixtureDigest, OracleDigest: oracleDigest, Toolchain: runtime.Version(), OracleCases: len(cases), RequiredCells: len(bindings) * len(cases)}
	binaryByCase := make(map[string]string, len(cases))
	for _, binding := range bindings {
		if err := ctx.Err(); err != nil {
			return CurrentGoBinaryScorecard{}, err
		}
		report, err := readCurrentBindingReport(filepath.Join(reportDir, binding.ID+".json"))
		if err != nil {
			return CurrentGoBinaryScorecard{}, fmt.Errorf("read %s production binding report: %w", binding.ID, err)
		}
		if report.SchemaVersion != CurrentGoBinaryBindingReportSchemaVersion || report.BindingID != binding.ID || len(report.Cases) != len(cases) {
			return CurrentGoBinaryScorecard{}, fmt.Errorf("%s production binding report is incomplete or misbound", binding.ID)
		}
		if !report.SourceClean || report.Source != source || report.InventoryID != inventory.ID || report.InventoryDigest != inventoryDigest || report.FixtureDigest != fixtureDigest || report.OracleDigest != oracleDigest || report.Toolchain != runtime.Version() {
			return CurrentGoBinaryScorecard{}, fmt.Errorf("%s production binding report identity does not match current source, inputs, or toolchain", binding.ID)
		}
		score := CurrentBindingScore{BindingID: binding.ID, RequiredCells: len(cases)}
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
		for _, item := range cases {
			observed, ok := byID[item.ID]
			if !ok {
				return CurrentGoBinaryScorecard{}, fmt.Errorf("%s production binding report omits case %q", binding.ID, item.ID)
			}
			if observed.ExpectedOutcome != item.Expected || observed.ExpectedCoverage != item.Coverage || observed.GoBinaryEnabled != item.Enabled || observed.JudgmentsEnabled != item.JudgmentsEnabled || observed.JudgmentCount < 0 || observed.JudgmentCount > 1 {
				return CurrentGoBinaryScorecard{}, fmt.Errorf("%s production binding report has invalid oracle or judgment for %q", binding.ID, item.ID)
			}
			if !validCurrentBinaryDigest(observed.BinaryDigest) {
				return CurrentGoBinaryScorecard{}, fmt.Errorf("%s production binding report lacks a binary digest for %q", binding.ID, item.ID)
			}
			if prior, exists := binaryByCase[item.ID]; exists && prior != observed.BinaryDigest {
				return CurrentGoBinaryScorecard{}, fmt.Errorf("api and worker measured different binary bytes for %q", item.ID)
			}
			binaryByCase[item.ID] = observed.BinaryDigest
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

func currentGoBinarySourceClean(ctx context.Context, runner *Runner) (bool, error) {
	status, err := runner.dependencies.Command(ctx, "git", "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return false, fmt.Errorf("check current Go-binary source status: %w", err)
	}
	return len(status) == 0, nil
}

func readCurrentBindingReport(path string) (CurrentGoBinaryBindingReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return CurrentGoBinaryBindingReport{}, err
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil {
		return CurrentGoBinaryBindingReport{}, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > 64*1024 {
		return CurrentGoBinaryBindingReport{}, errors.New("binding report must be a small regular file")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024+1))
	decoder.DisallowUnknownFields()
	var report CurrentGoBinaryBindingReport
	if err := decoder.Decode(&report); err != nil {
		return CurrentGoBinaryBindingReport{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return CurrentGoBinaryBindingReport{}, errors.New("binding report contains trailing data")
	}
	return report, nil
}

func materializeCurrentGoBinary(ctx context.Context, workRoot string, item currentGoBinaryCase, input currentGoBinaryInput) (string, error) {
	root := filepath.Join(workRoot, benchmark.SHA256Digest([]byte(item.ID))[7:])
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	for _, file := range []struct {
		name string
		body []byte
	}{{"go.mod", input.goMod}, {"go.sum", input.goSum}, {"main.go", item.Source}} {
		if err := os.WriteFile(filepath.Join(root, file.name), file.body, 0o600); err != nil {
			return "", err
		}
	}
	buildCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(buildCtx, "go", "-C", root, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", filepath.Join(root, "reachbench-binary"), ".")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOFLAGS=", "GOEXPERIMENT=", "GOWORK=off", "GOPROXY=off", "GOTOOLCHAIN=local")
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

func digestCurrentFixture(input currentGoBinaryInput) string {
	return benchmark.SHA256Digest(bytesForDigest(input.goMod, input.goSum, currentGoBinaryDirect, currentGoBinaryRetained, currentGoBinaryRetainedCalled))
}
func digestCurrentOracle(cases []currentGoBinaryCase) string {
	parts := make([][]byte, 0, len(cases)*7)
	for _, item := range cases {
		parts = append(parts, []byte(item.ID), []byte(item.Subject), []byte(item.Version), []byte(fmt.Sprint(item.Enabled)), []byte(fmt.Sprint(item.JudgmentsEnabled)), []byte(item.Expected), []byte(item.Coverage))
	}
	return benchmark.SHA256Digest(bytesForDigest(parts...))
}

func validCurrentBinaryDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	bytes, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(bytes) == sha256.Size
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
