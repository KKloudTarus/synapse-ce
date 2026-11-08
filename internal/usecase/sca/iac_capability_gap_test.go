package sca

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	reportinfra "github.com/KKloudTarus/synapse-ce/internal/infrastructure/report"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/misconfig"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	reportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/report"
)

// capabilityGapMisconfigScanner reports a capability that could not evaluate its input, with findings from
// the raw scan that remained available.
type capabilityGapMisconfigScanner struct {
	report ports.MisconfigScanReport
}

func (*capabilityGapMisconfigScanner) Name() string { return "capability-gap-iac" }

func (s *capabilityGapMisconfigScanner) ScanConfigs(ctx context.Context, path string) ([]ports.MisconfigRawFinding, error) {
	report, err := s.ScanConfigsReport(ctx, path)
	return report.Findings, err
}

func (s *capabilityGapMisconfigScanner) ScanConfigsReport(context.Context, string) (ports.MisconfigScanReport, error) {
	return s.report, nil
}

// An input a required capability could not evaluate makes IaC coverage partial, so --require-complete
// rejects the run. Execution completing is not the same as the input being assessed.
func TestIaCCapabilityGapMakesCoveragePartial(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	svc.SetMisconfigScanner(&capabilityGapMisconfigScanner{report: ports.MisconfigScanReport{
		UnassessedInputs:  2,
		UnassessedReasons: []string{"kustomization rendering is not enabled for this scan, so overlay patches were not applied"},
	}})
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	outcome, ok := result.engineOutcome("iac")
	if !ok {
		t.Fatal("the iac engine must carry an outcome")
	}
	if outcome.Coverage != scanrun.CoveragePartial || outcome.Reason != scanrun.ReasonAnalysisIncomplete {
		t.Fatalf("iac outcome %+v, want partial/analysis_incomplete", outcome)
	}
	if outcome.Counts[scanrun.MeasureFilesUnscanned] != 2 {
		t.Fatalf("the unassessed input count must be measured, got %v", outcome.Counts)
	}
	if result.EngineCoverage.Complete() {
		t.Fatal("an unassessed capability input must not read as complete coverage")
	}
}

// An attribute inside the documented evaluation contract that did not resolve is reported, and coverage
// stays complete: the contract is published, and the reader is told where evaluation stopped.
func TestIaCUnresolvedAttributesAreReportedWithoutClaimingAGap(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	svc.SetMisconfigScanner(&capabilityGapMisconfigScanner{report: ports.MisconfigScanReport{
		UnresolvedInputs: []string{"main.tf:12: cidr_blocks"},
	}})
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	outcome, _ := result.engineOutcome("iac")
	if outcome.Coverage != scanrun.CoverageComplete {
		t.Fatalf("iac outcome %+v, want complete coverage", outcome)
	}
}

// Both passes use the real scanner on inert files; no rendering or target execution is enabled.
func TestIaCImageRootfsCapabilityCoverage(t *testing.T) {
	for _, tc := range []struct {
		name         string
		workspaceGap bool
		rootfsGap    bool
		unscanned    int64
	}{
		{"rootfs gap", false, true, 1},
		{"workspace gap survives safe rootfs", true, false, 1},
		{"both gaps are counted", true, true, 2},
		{"ordinary manifests", false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workspace, rootfs := t.TempDir(), t.TempDir()
			write := func(dir, name, content string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.workspaceGap {
				write(workspace, "kustomization.yaml", "resources:\n  - pod.yaml\n")
			}
			if tc.rootfsGap {
				write(rootfs, "kustomization.yaml", "resources:\n  - pod.yaml\n")
			}
			write(rootfs, "pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: fixture\nspec:\n  containers:\n    - name: app\n      image: nginx:latest\n      securityContext:\n        privileged: true\n")
			svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: workspace, rootfs: rootfs}, &fakeAudit{}, &fakeDetector{})
			svc.SetMisconfigScanner(misconfig.New())
			result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
			if err != nil {
				t.Fatal(err)
			}
			outcome, ok := result.engineOutcome("iac")
			if !ok || outcome.Execution != scanrun.EngineCompleted {
				t.Fatalf("iac outcome = %+v, present = %v", outcome, ok)
			}
			if tc.unscanned > 0 {
				if outcome.Coverage != scanrun.CoveragePartial || outcome.Reason != scanrun.ReasonAnalysisIncomplete || result.EngineCoverage.Complete() {
					t.Fatalf("unassessed inputs must make coverage partial: %+v", outcome)
				}
			} else if outcome.Coverage != scanrun.CoverageComplete {
				t.Fatalf("ordinary input must have complete iac coverage: %+v", outcome)
			}
			if got := outcome.Counts[scanrun.MeasureFilesUnscanned]; got != tc.unscanned {
				t.Fatalf("files unscanned = %d, want %d", got, tc.unscanned)
			}
			var privileged bool
			for _, f := range result.Findings {
				if f.RuleKey == "kubernetes-privileged" {
					privileged = true
				}
			}
			if !privileged {
				t.Fatal("the raw rootfs privileged-container finding was lost")
			}
		})
	}
}

// Rootfs Terraform diagnostics retain the same bounded-evaluation semantics as workspace diagnostics.
func TestIaCImageRootfsUnresolvedModuleInputs(t *testing.T) {
	for _, tc := range []struct {
		name       string
		root       string
		variable   string
		unresolved bool
	}{
		{
			name: "conflicting explicit and default values",
			root: `module "explicit" {
  source = "./modules/vol"
  encrypted = true
}
module "defaulted" {
  source = "./modules/vol"
}
`,
			variable: `variable "encrypted" {
  default = false
}`,
			unresolved: true,
		},
		{
			name: "missing required input",
			root: `module "missing" {
  source = "./modules/vol"
}
`,
			variable:   `variable "encrypted" {}`,
			unresolved: true,
		},
		{
			name: "evaluated safe input",
			root: `module "safe" {
  source = "./modules/vol"
  encrypted = true
}
`,
			variable: `variable "encrypted" {
  default = false
}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workspace, rootfs := t.TempDir(), t.TempDir()
			childDir := filepath.Join(rootfs, "modules", "vol")
			if err := os.MkdirAll(childDir, 0o755); err != nil {
				t.Fatal(err)
			}
			child := tc.variable + `
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size = 20
  encrypted = var.encrypted
}
`
			for path, content := range map[string]string{
				filepath.Join(rootfs, "main.tf"):   tc.root,
				filepath.Join(childDir, "main.tf"): child,
			} {
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)
			engagements := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
			findings := memory.NewFindingRepository()
			clock := fakeClock{t: time.Unix(0, 0).UTC()}
			svc := NewService(engagements, findings, nil, memory.NewScanResultStore(), nil, nil, nil, nil,
				ports.Provenance{}, clock, &fakeAudit{}, shared.SeverityHigh, 0,
				&fakeAcquirer{dir: workspace, rootfs: rootfs}, &fakeDetector{}, fakeSBOM{}, []ports.DetectionSource{fakeVuln{}}, nil, fakeLic{}, nil)
			svc.SetMisconfigScanner(misconfig.New())
			result, err := svc.Scan(ctx, "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
			if err != nil {
				t.Fatal(err)
			}
			diagnostic := regexp.MustCompile(`modules/vol/main\.tf:[0-9]+: encrypted\b`)
			found := false
			for _, warning := range result.SourceWarnings {
				if strings.Contains(warning, "image-filesystem") && diagnostic.MatchString(warning) {
					found = true
				}
			}
			if found != tc.unresolved {
				t.Fatalf("rootfs encrypted diagnostic present = %v, want %v; warnings: %v", found, tc.unresolved, result.SourceWarnings)
			}
			outcome, ok := result.engineOutcome("iac")
			if !ok || outcome.Coverage != scanrun.CoverageComplete {
				t.Fatalf("bounded unresolved attributes must preserve complete iac coverage: %+v", outcome)
			}
			if !tc.unresolved {
				for _, finding := range result.Findings {
					if finding.RuleKey == "terraform-encryption-disabled" {
						t.Fatal("evaluated encrypted volume must not produce an encryption-disabled finding")
					}
				}
			}
			reports := reportuc.NewService(engagements, findings, nil, nil, nil, svc, clock, "test")
			reports.RegisterFormat(reportuc.FormatHTML, reportinfra.NewHTMLRenderer())
			html, _, _, err := reports.Render(ctx, shared.DefaultTenant, "e1", reportuc.Options{Format: reportuc.FormatHTML})
			if err != nil {
				t.Fatal(err)
			}
			reported := strings.Contains(string(html), "image-filesystem") && diagnostic.Match(html)
			if reported != tc.unresolved {
				t.Fatalf("rendered rootfs encrypted diagnostic present = %v, want %v", reported, tc.unresolved)
			}
			coverage := fmt.Sprintf("Required-engine coverage: %s (%d/%d completed).", result.EngineCoverage.Status, result.EngineCoverage.Completed, result.EngineCoverage.Required)
			if !strings.Contains(string(html), coverage) {
				t.Fatalf("report did not retain actual engine coverage %q", coverage)
			}
			again, _, _, err := reports.Render(ctx, shared.DefaultTenant, "e1", reportuc.Options{Format: reportuc.FormatHTML})
			if err != nil || !bytes.Equal(html, again) {
				t.Fatalf("persisted report was not deterministic: %v", err)
			}
		})
	}
}
