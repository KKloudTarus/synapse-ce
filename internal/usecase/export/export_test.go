package export

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(0, 0).UTC() }

func sampleFindings() []finding.Finding {
	return []finding.Finding{
		{ID: "f1", EngagementID: "e1", Title: "CVE-2020-7471 in django@2.2.0", Severity: shared.SeverityCritical, CVSSVector: "CVSS:3.1/AV:N", Status: finding.StatusOpen, KEV: true, RiskScore: 6.4, DedupKey: "vuln:CVE-2020-7471:django:2.2.0"},
		{ID: "f2", EngagementID: "e1", Title: "CVE-2019-14234 in django@2.2.0", Severity: shared.SeverityMedium, Status: finding.StatusFalsePos, DedupKey: "vuln:CVE-2019-14234:django:2.2.0"},
		{ID: "f3", EngagementID: "e1", Title: "Denied license: GPL-3.0-only", Severity: shared.SeverityMedium, Status: finding.StatusOpen, DedupKey: "license:GPL-3.0-only"},
	}
}

type fakeJudgments struct{ js []judgment.Judgment }

func (f *fakeJudgments) ListByEngagement(context.Context, shared.ID) ([]judgment.Judgment, error) {
	return f.js, nil
}

func mkJudg(subj string, st judgment.State, score int, r judgment.ReachabilityState, tier judgment.ReachabilityTier) judgment.Judgment {
	return judgment.Judgment{
		Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: shared.ID(subj),
		State: st, EvidenceScore: score, Claim: judgment.ReachabilityClaim{Reachable: r, Tier: tier, Confidence: 90},
	}
}

// TestOpenVEXJustificationByTier: a not_affected finding backed by a PUBLISHABLE not_reachable
// judgment gets a tier-grounded justification; proposed/unpublishable judgments are ignored; the
// strongest tier wins; an affected finding is never overridden.
func TestOpenVEXJustificationByTier(t *testing.T) {
	repo := memory.NewFindingRepository()
	ctx := context.Background()
	if err := repo.Upsert(ctx, []finding.Finding{
		{ID: "f2", EngagementID: "e1", Kind: finding.KindSCA, Severity: shared.SeverityMedium, Status: finding.StatusFalsePos, DedupKey: "vuln:CVE-2019-14234:django:2.2.0"},
		{ID: "f1", EngagementID: "e1", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: "vuln:CVE-2020-7471:django:2.2.0"},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewService(repo, fixedClock{}, "v1")
	svc.SetJudgments(&fakeJudgments{js: []judgment.Judgment{
		mkJudg("f2", judgment.StateConfirmed, 80, judgment.NotReachable, judgment.Tier1), // publishable, dep-graph
		mkJudg("f2", judgment.StateConfirmed, 90, judgment.NotReachable, judgment.Tier2), // publishable, stronger -> wins
		mkJudg("f2", judgment.StateProposed, 0, judgment.NotReachable, judgment.Tier2),   // not publishable -> ignored
		mkJudg("f1", judgment.StateConfirmed, 90, judgment.NotReachable, judgment.Tier2), // f1 is affected -> not overridden
	}})

	vex, err := svc.OpenVEX(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]VEXStatement{}
	for _, s := range vex.Statements {
		by[s.Vulnerability.Name] = s
	}
	if s := by["CVE-2019-14234"]; s.Status != "not_affected" || s.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("f2 = %+v, want not_affected + execute-path (strongest publishable tier wins, proposed ignored)", s)
	}
	if s := by["CVE-2020-7471"]; s.Status != "affected" || s.Justification != "" {
		t.Errorf("f1 affected must not get a not_affected justification: %+v", s)
	}
}

func mkVexJudg(subj string, st judgment.State, score int, just vex.OpenVexJustification) judgment.Judgment {
	return judgment.Judgment{
		Capability: judgment.CapVexJustification, SubjectKind: judgment.SubjectFinding, SubjectID: shared.ID(subj),
		State: st, EvidenceScore: score, Claim: judgment.VexJustificationClaim{Justification: just},
	}
}

// TestOpenVEXJustificationFromVexJudgment: a not_affected finding with no reachability proof but a
// CONFIRMED CapVexJustification judgment gets that human-ratified justification; a reachability tier
// (a proof) still WINS over it; a proposed (unpublishable) vex judgment is ignored (falls back to default).
func TestOpenVEXJustificationFromVexJudgment(t *testing.T) {
	repo := memory.NewFindingRepository()
	ctx := context.Background()
	if err := repo.Upsert(ctx, []finding.Finding{
		{ID: "fa", EngagementID: "e1", Kind: finding.KindSCA, Severity: shared.SeverityMedium, Status: finding.StatusFalsePos, DedupKey: "vuln:CVE-1111:libA:1.0"},
		{ID: "fb", EngagementID: "e1", Kind: finding.KindSCA, Severity: shared.SeverityMedium, Status: finding.StatusFalsePos, DedupKey: "vuln:CVE-2222:libB:1.0"},
		{ID: "fc", EngagementID: "e1", Kind: finding.KindSCA, Severity: shared.SeverityMedium, Status: finding.StatusFalsePos, DedupKey: "vuln:CVE-3333:libC:1.0"},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewService(repo, fixedClock{}, "v1")
	svc.SetJudgments(&fakeJudgments{js: []judgment.Judgment{
		mkVexJudg("fa", judgment.StateConfirmed, 80, vex.InlineMitigationsAlreadyExist),  // confirmed, no reachability -> used
		mkJudg("fb", judgment.StateConfirmed, 90, judgment.NotReachable, judgment.Tier2), // reachability tier...
		mkVexJudg("fb", judgment.StateConfirmed, 80, vex.ComponentNotPresent),            //...WINS over this vex justification
		mkVexJudg("fc", judgment.StateProposed, 0, vex.ComponentNotPresent),              // proposed -> unpublishable -> ignored
	}})

	doc, err := svc.OpenVEX(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]VEXStatement{}
	for _, s := range doc.Statements {
		by[s.Vulnerability.Name] = s
	}
	if s := by["CVE-1111"]; s.Status != "not_affected" || s.Justification != "inline_mitigations_already_exist" {
		t.Errorf("fa = %+v, want the confirmed vex justification", s)
	}
	if s := by["CVE-2222"]; s.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("fb = %+v, want the reachability tier to WIN over the vex justification", s)
	}
	if s := by["CVE-3333"]; s.Justification != "vulnerable_code_not_present" {
		t.Errorf("fc = %+v, want the vexStatus default (proposed vex judgment ignored)", s)
	}
}

func TestBuildSARIF(t *testing.T) {
	manifests := func(f finding.Finding) string {
		if f.DedupKey == "vuln:CVE-2020-7471:django:2.2.0" {
			return "requirements.txt"
		}
		return ""
	}
	log := buildSARIF(sampleFindings(), "v1.2.3", SARIFOptions{Manifest: manifests})
	if log.Version != "2.1.0" || log.Schema == "" {
		t.Fatalf("bad header: %+v", log)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "synapse" || run.Tool.Driver.Version != "v1.2.3" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Results) != 3 {
		t.Fatalf("want 3 results, got %d", len(run.Results))
	}
	if run.Results[0].Level != "error" || run.Results[1].Level != "warning" { // critical -> error, medium -> warning
		t.Errorf("levels = %s, %s", run.Results[0].Level, run.Results[1].Level)
	}
	if len(run.Results[0].Locations) != 1 || run.Results[0].Locations[0].LogicalLocations[0].Name != "django@2.2.0" {
		t.Errorf("location = %+v", run.Results[0].Locations)
	}
	var cve *SARIFRule
	for i := range run.Tool.Driver.Rules {
		if run.Tool.Driver.Rules[i].ID == "CVE-2020-7471" {
			cve = &run.Tool.Driver.Rules[i]
		}
	}
	if cve == nil || cve.HelpURI == "" {
		t.Errorf("CVE rule missing helpUri: %+v", run.Tool.Driver.Rules)
	}
}

func TestBuildOpenVEX(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	doc := buildOpenVEX("e1", sampleFindings(), nil, nil, now, "v1.2.3")
	if doc.Context != vexContext || doc.Version != 1 || doc.Author != "Synapse" {
		t.Fatalf("bad header: %+v", doc)
	}
	if len(doc.Statements) != 2 { // 2 vuln findings; the license finding is skipped
		t.Fatalf("want 2 statements, got %d", len(doc.Statements))
	}
	by := map[string]VEXStatement{}
	for _, s := range doc.Statements {
		by[s.Vulnerability.Name] = s
	}
	if s := by["CVE-2020-7471"]; s.Status != "affected" || s.Products[0].ID != "django@2.2.0" {
		t.Errorf("affected stmt = %+v", s)
	}
	if s := by["CVE-2019-14234"]; s.Status != "not_affected" || s.Justification == "" {
		t.Errorf("false-positive should map to not_affected + justification: %+v", s)
	}
}

// TestExportsApplyPublishabilityGate proves SARIF + OpenVEX read through the evidence
// gate via ListPublishableByEngagement: an unproven exploitation finding
// (EvidenceScore < bar) is excluded from BOTH exports – even when it carries a vuln-shaped
// dedup key that OpenVEX's vuln filter would otherwise pass. Red before the gate landed (the Service
// read ListByEngagement, ungated), green after.
func TestExportsApplyPublishabilityGate(t *testing.T) {
	repo := memory.NewFindingRepository()
	ctx := context.Background()
	if err := repo.Upsert(ctx, []finding.Finding{
		{ID: "sca1", EngagementID: "e1", Title: "CVE-2020-7471 in django@2.2.0", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: "vuln:CVE-2020-7471:django:2.2.0"},
		{ID: "exp-unproven", EngagementID: "e1", Title: "Unproven RCE", Kind: finding.KindExploitation, EvidenceScore: 10, Severity: shared.SeverityCritical, Status: finding.StatusOpen, DedupKey: "vuln:CVE-2099-0001:django:2.2.0"},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewService(repo, fixedClock{}, "v1")

	log, err := svc.SARIF(ctx, "e1")
	if err != nil {
		t.Fatalf("sarif: %v", err)
	}
	if n := len(log.Runs[0].Results); n != 1 {
		t.Fatalf("SARIF must export only the 1 publishable finding, got %d", n)
	}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.ID == "CVE-2099-0001" {
			t.Error("SARIF leaked an unproven exploitation finding")
		}
	}

	vex, err := svc.OpenVEX(ctx, "e1")
	if err != nil {
		t.Fatalf("openvex: %v", err)
	}
	if n := len(vex.Statements); n != 1 {
		t.Fatalf("OpenVEX must export only the 1 publishable vuln finding, got %d", n)
	}
	for _, s := range vex.Statements {
		if s.Vulnerability.Name == "CVE-2099-0001" {
			t.Error("OpenVEX leaked an unproven exploitation finding")
		}
	}
}
