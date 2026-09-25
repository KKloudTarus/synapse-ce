// Package gobinbenchmark drives the current Go-binary binding regression from
// each production composition root. It is test-only support code.
package gobinbenchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	reachbench "github.com/KKloudTarus/synapse-ce/internal/infrastructure/reachbench"
	analysisuc "github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

const target = "current-go-binary-benchmark"

// Installer is the binding-specific composition function from one production root.
type Installer func(*scauc.Service, *analysisuc.Service, ports.AuditLogger, ports.Clock) error

type report struct {
	BindingID string       `json:"binding_id"`
	Cases     []reportCase `json:"cases"`
}

type reportCase struct {
	ID               string `json:"id"`
	ExpectedOutcome  string `json:"expected_outcome"`
	ActualOutcome    string `json:"actual_outcome"`
	ExpectedCoverage string `json:"expected_coverage"`
	ActualCoverage   string `json:"actual_coverage"`
	JudgmentCount    int    `json:"judgment_count"`
	FindingRetained  bool   `json:"finding_retained"`
	GateExempted     bool   `json:"gate_exempted"`
}

// Run measures one installed production binding. Every fixture passes through
// the real SCA scan path; unsupported inputs retain their source finding and
// produce no reachability judgment.
func Run(t *testing.T, bindingID string, install Installer) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		if strings.TrimSpace(os.Getenv("SYNAPSE_GOBIN_BINDING_REPORT_DIR")) != "" {
			t.Fatal("current Go-binary hosted binding benchmark requires linux/amd64")
		}
		t.Skip("current Go-binary binding benchmark requires linux/amd64")
	}
	if bindingID != "api" && bindingID != "worker" {
		t.Fatalf("unsupported Go-binary binding %q", bindingID)
	}
	if install == nil {
		t.Fatal("Go-binary binding installer is required")
	}
	ctx := context.Background()
	root := t.TempDir()
	result := report{BindingID: bindingID}
	for _, fixture := range reachbench.CurrentGoBinaryFixtures() {
		fixtureRoot, err := reachbench.MaterializeCurrentGoBinaryFixture(ctx, root, fixture.ID)
		if err != nil {
			t.Fatalf("materialize %s: %v", fixture.ID, err)
		}
		outcome, coverage, count, retained, exempted := execute(t, ctx, fixtureRoot, fixture.Subject, string(fixture.ExpectedOutcome), install)
		if outcome != string(fixture.ExpectedOutcome) || coverage != string(fixture.ExpectedCoverage) || !retained || exempted {
			t.Fatalf("%s: outcome=%s coverage=%s retained=%v gate_exempted=%v, want outcome=%s coverage=%s retained=true gate_exempted=false", fixture.ID, outcome, coverage, retained, exempted, fixture.ExpectedOutcome, fixture.ExpectedCoverage)
		}
		result.Cases = append(result.Cases, reportCase{
			ID: fixture.ID, ExpectedOutcome: string(fixture.ExpectedOutcome), ActualOutcome: outcome,
			ExpectedCoverage: string(fixture.ExpectedCoverage), ActualCoverage: coverage,
			JudgmentCount: count, FindingRetained: retained, GateExempted: exempted,
		})
	}
	writeReport(t, bindingID, result)
}

func execute(t *testing.T, ctx context.Context, root, subject, expectedOutcome string, install Installer) (outcome, coverage string, judgmentCount int, findingRetained, gateExempted bool) {
	t.Helper()
	clock := benchmarkClock{now: time.Unix(1_700_000_000, 0).UTC()}
	audit := &benchmarkAudit{}
	store := memory.NewJudgmentStore()
	judgmentSvc, err := analysisuc.NewService(store, benchmarkSealer{}, audit, clock, &benchmarkIDs{})
	if err != nil {
		t.Fatal(err)
	}
	raw := fixtureVulnerability(subject)
	svc := newSCA(t, root, raw, clock, audit)
	if err := install(svc, judgmentSvc, audit, clock); err != nil {
		t.Fatalf("install Go-binary binding: %v", err)
	}
	scan, err := svc.ScanWithOptions(ctx, "benchmark", "current-go-binary-engagement", ports.AcquireRequest{Kind: "local", Value: target}, scauc.ScanOptions{Mode: scauc.ScanModeVulnerabilities})
	if err != nil {
		t.Fatalf("scan %s: %v", subject, err)
	}
	wantFinding := vulnerability.DedupKey(raw.AdvisoryID, raw.Component, raw.Version)
	gateExempted = scan.GateExemptKeys(scan.Findings)[wantFinding]
	var retainedFindingID shared.ID
	for _, item := range scan.Findings {
		if item.DedupKey == wantFinding {
			findingRetained = true
			retainedFindingID = item.ID
			break
		}
	}
	if !findingRetained {
		t.Fatalf("scan did not retain source finding %q", wantFinding)
	}
	judgments, err := store.ListByEngagement(ctx, "current-go-binary-engagement")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range judgments {
		if item.Capability != judgment.CapReachability || item.SubjectKind != judgment.SubjectFinding || item.SubjectID != retainedFindingID {
			t.Fatalf("Go-binary binding judgment is not bound to retained finding %q: %+v", retainedFindingID, item)
		}
		if item.State != judgment.StateConfirmed || !item.Publishable() {
			t.Fatalf("Go-binary binding judgment is not confirmed and publishable: %+v", item)
		}
		claim, ok := item.Claim.(judgment.ReachabilityClaim)
		if !ok || claim.Reachable != judgment.Reachable {
			t.Fatalf("Go-binary binding minted a non-reachable claim: %+v", item)
		}
	}
	wantCount := 0
	if expectedOutcome == "reachable" {
		wantCount = 1
	}
	if len(judgments) != wantCount {
		t.Fatalf("judgments for %s = %d, want %d", subject, len(judgments), wantCount)
	}
	// This is measured case coverage, not a negative-proof claim: a persisted
	// reachable judgment is complete positive coverage; all other cases remain
	// unavailable and never imply suppression or absence.
	if wantCount == 0 {
		return "no_analysis", "unavailable", 0, findingRetained, gateExempted
	}
	return "reachable", "complete", 1, findingRetained, gateExempted
}

func fixtureVulnerability(subject string) vulnerability.RawFinding {
	componentVersion := "v0.59.0"
	if strings.HasSuffix(subject, "@v0.58.0") {
		componentVersion = "v0.58.0"
	}
	return vulnerability.RawFinding{
		Source: "current-go-binary-benchmark", AdvisoryID: "CVE-2026-0001", Component: "golang.org/x/net", Version: componentVersion,
		Ecosystem: "Go", PackagePURL: subject, AffectedSymbols: []string{"golang.org/x/net/idna.ToASCII"}, Severity: shared.SeverityHigh,
	}
}

func newSCA(t *testing.T, root string, raw vulnerability.RawFinding, clock ports.Clock, audit ports.AuditLogger) *scauc.Service {
	t.Helper()
	eng, err := engdom.New("current-go-binary-engagement", "", "current Go binary benchmark", "", clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	eng.Scope = engdom.Scope{InScope: []engdom.Target{{Kind: engdom.TargetRepo, Value: target}}}
	return scauc.NewService(
		engagementRepo{eng: eng}, nil, nil, nil, nil, nil, nil, nil, ports.Provenance{}, clock, audit, shared.SeverityHigh, 0,
		acquirer{root: root}, detector{}, staticSBOM{doc: &sbom.SBOM{Components: []sbom.Component{{Name: raw.Component, Version: raw.Version, PURL: raw.PackagePURL}}}},
		[]ports.DetectionSource{vulnerabilities{raw}}, nil, licenseScanner{}, nil,
	)
}

func writeReport(t *testing.T, bindingID string, result report) {
	t.Helper()
	dir := strings.TrimSpace(os.Getenv("SYNAPSE_GOBIN_BINDING_REPORT_DIR"))
	if dir == "" {
		return
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bindingID+".json"), append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

type engagementRepo struct{ eng *engdom.Engagement }

func (r engagementRepo) Create(context.Context, *engdom.Engagement) error { return nil }
func (r engagementRepo) Update(context.Context, *engdom.Engagement) error { return nil }
func (r engagementRepo) Delete(context.Context, shared.ID) error          { return nil }
func (r engagementRepo) GetByID(context.Context, shared.ID) (*engdom.Engagement, error) {
	return r.eng, nil
}
func (r engagementRepo) GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engdom.Engagement, error) {
	return r.eng, nil
}
func (engagementRepo) GetByHostAssetID(context.Context, shared.ID, shared.ID) (*engdom.Engagement, error) {
	return nil, shared.ErrNotFound
}
func (engagementRepo) GetByProjectID(context.Context, shared.ID, shared.ID) (*engdom.Engagement, error) {
	return nil, shared.ErrNotFound
}
func (engagementRepo) ProjectContexts(context.Context, shared.ID, []shared.ID) (map[shared.ID]*engdom.Engagement, error) {
	return map[shared.ID]*engdom.Engagement{}, nil
}
func (engagementRepo) List(context.Context, shared.ID) ([]*engdom.Engagement, error) { return nil, nil }

type benchmarkClock struct{ now time.Time }

func (c benchmarkClock) Now() time.Time { return c.now }

type benchmarkAudit struct{}

func (*benchmarkAudit) Record(context.Context, ports.AuditEntry) error     { return nil }
func (*benchmarkAudit) RecordOnce(context.Context, ports.AuditEntry) error { return nil }

type benchmarkIDs struct{ next int }

func (g *benchmarkIDs) NewID() shared.ID {
	g.next++
	return shared.ID(fmt.Sprintf("current-go-binary-judgment-%d", g.next))
}

type benchmarkSealer struct{}

func (benchmarkSealer) Seal(context.Context, shared.ID, string, []byte, string) (evidence.Evidence, error) {
	return evidence.Evidence{}, nil
}

type acquirer struct{ root string }

func (a acquirer) Acquire(context.Context, ports.AcquireRequest) (*ports.Workspace, error) {
	return &ports.Workspace{Dir: a.root}, nil
}

type detector struct{}

func (detector) Detect(context.Context, string) ([]ports.DetectedLanguage, error) {
	return []ports.DetectedLanguage{{Name: "Go", Percent: 100}}, nil
}

type staticSBOM struct{ doc *sbom.SBOM }

func (s staticSBOM) Generate(context.Context, string) (*sbom.SBOM, error) { return s.doc, nil }

type vulnerabilities []vulnerability.RawFinding

func (vulnerabilities) Name() string { return "current-go-binary-benchmark" }
func (v vulnerabilities) Scan(context.Context, *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	return append([]vulnerability.RawFinding(nil), v...), nil
}

type licenseScanner struct{}

func (licenseScanner) Scan(context.Context, *sbom.SBOM) ([]ports.LicenseFinding, error) {
	return nil, nil
}
