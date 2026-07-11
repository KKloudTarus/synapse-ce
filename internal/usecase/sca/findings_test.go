package sca

import (
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCountBelowThreshold(t *testing.T) {
	vulns := []vulnerability.Vulnerability{
		{Severity: shared.SeverityCritical}, {Severity: shared.SeverityHigh},
		{Severity: shared.SeverityMedium}, {Severity: shared.SeverityLow},
		{Severity: shared.SeverityUnknown},                   // unscored → always promoted, never "below"
		{Severity: shared.SeverityLow, Unversioned: true},    // first-party-historic → always promoted, never "below"
		{Severity: shared.SeverityMedium, Unversioned: true}, // ditto – must NOT inflate the count
	}
	// Counts must match buildFindings EXACTLY: only versioned (third-party) sub-floor vulns count.
	cases := map[shared.Severity]int{
		shared.SeverityInfo:   0, // the DEFAULT floor → nothing hidden (the "missing vulns" fix)
		shared.SeverityLow:    0,
		shared.SeverityMedium: 1, // versioned low (unversioned low/medium excluded)
		shared.SeverityHigh:   2, // versioned low + medium (unversioned excluded)
	}
	for floor, want := range cases {
		if got := countBelowThreshold(vulns, floor); got != want {
			t.Errorf("countBelowThreshold(floor=%s) = %d, want %d", floor, got, want)
		}
	}
}

func TestBuildFindings(t *testing.T) {
	res := &ScanResult{
		Vulnerabilities: []vulnerability.Vulnerability{
			{ID: "CVE-1", Component: "django", Version: "2.2.0", Severity: shared.SeverityCritical, FixedVersion: "2.2.28"},
			{ID: "CVE-2", Component: "django", Version: "2.2.0", Severity: shared.SeverityHigh},
			{ID: "CVE-3", Component: "django", Version: "2.2.0", Severity: shared.SeverityMedium},  // below threshold
			{ID: "CVE-4", Component: "django", Version: "2.2.0", Severity: shared.SeverityLow},     // below threshold
			{ID: "CVE-5", Component: "django", Version: "2.2.0", Severity: shared.SeverityUnknown}, // unscored → always promoted
		},
		Licenses: []ports.LicenseFinding{
			{License: "GPL-3.0-only", Verdict: ports.LicenseDeny, Components: []string{"copyleftlib"}},
			{License: "MIT", Verdict: ports.LicenseAllow, Components: []string{"lodash"}}, // not a finding
		},
	}
	now := time.Unix(0, 0).UTC()

	got := buildFindings("eng1", res, now, shared.SeverityHigh, false, nil)

	// critical + high + unknown vulns (3) + denied license (1) = 4; medium/low + allowed license excluded
	if len(got) != 4 {
		t.Fatalf("want 4 findings, got %d: %+v", len(got), got)
	}
	keys := map[string]bool{}
	for _, f := range got {
		keys[f.DedupKey] = true
		if f.ID == "" || f.EngagementID != "eng1" || string(f.Status) != "open" {
			t.Errorf("bad finding: %+v", f)
		}
	}
	if !keys["vuln:CVE-1:django:2.2.0"] || !keys["license:GPL-3.0-only"] {
		t.Errorf("missing expected dedup keys: %v", keys)
	}
	if !keys["vuln:CVE-5:django:2.2.0"] {
		t.Error("unknown-severity vuln must be promoted, never silently dropped")
	}
	if keys["vuln:CVE-3:django:2.2.0"] || keys["vuln:CVE-4:django:2.2.0"] {
		t.Error("medium/low vulns should be below the high threshold")
	}

	// deterministic id across calls (idempotent re-scan)
	again := buildFindings("eng1", res, now.Add(time.Hour), shared.SeverityHigh, false, nil)
	if got[0].ID != again[0].ID {
		t.Errorf("finding id not deterministic: %s vs %s", got[0].ID, again[0].ID)
	}
}

func TestBuildFindingsIgnoreUnfixed(t *testing.T) {
	res := &ScanResult{
		Vulnerabilities: []vulnerability.Vulnerability{
			{ID: "CVE-1", Component: "openssl", Version: "1.1", Severity: shared.SeverityHigh, FixedVersion: "1.1.1"}, // has fix → kept
			{ID: "CVE-2", Component: "openssl", Version: "1.1", Severity: shared.SeverityHigh, FixState: "wont-fix"},  // no fix → suppressed
			{ID: "CVE-3", Component: "openssl", Version: "1.1", Severity: shared.SeverityCritical},                    // no fix → suppressed
			// edge: a source claimed "fixed" but gave no concrete version – promotion keys on
			// FixedVersion, so this is correctly treated as unfixed and suppressed (no false "has-fix").
			{ID: "CVE-4", Component: "openssl", Version: "1.1", Severity: shared.SeverityHigh, FixState: "fixed"},
		},
	}
	now := time.Unix(0, 0).UTC()

	// Floor=info so severity never hides anything; --ignore-unfixed is the only filter under test.
	got := buildFindings("eng1", res, now, shared.SeverityInfo, true, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 finding (only the fixed one), got %d: %+v", len(got), got)
	}
	if got[0].DedupKey != "vuln:CVE-1:openssl:1.1" {
		t.Errorf("kept the wrong finding: %s", got[0].DedupKey)
	}
	// the three no-fix vulns (incl. the fixed-but-versionless edge) are suppressed but
	// COUNTED, never silently lost
	if n := countUnfixedSuppressed(res.Vulnerabilities, shared.SeverityInfo, true); n != 3 {
		t.Errorf("countUnfixedSuppressed = %d, want 3", n)
	}
	// without the flag, nothing is suppressed and all four promote
	if n := countUnfixedSuppressed(res.Vulnerabilities, shared.SeverityInfo, false); n != 0 {
		t.Errorf("countUnfixedSuppressed(off) = %d, want 0", n)
	}
	if all := buildFindings("eng1", res, now, shared.SeverityInfo, false, nil); len(all) != 4 {
		t.Errorf("without --ignore-unfixed want 4 findings, got %d", len(all))
	}
}

func TestAttributeImageLayers(t *testing.T) {
	img := &sbom.ImageInfo{Layers: []sbom.ImageLayer{
		{Index: 0, DiffID: "sha256:base", CreatedBy: "ADD debian rootfs"},
		{Index: 1, DiffID: "sha256:app", CreatedBy: "COPY app /app"},
	}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "1.1", PURL: "pkg:deb/debian/openssl@1.1", LayerID: "sha256:base"}, // OS pkg, base layer
		{Name: "lodash", Version: "4.0.0", PURL: "pkg:npm/lodash@4.0.0", LayerID: "sha256:app"},       // app pkg, app layer
	}}
	vulns := []vulnerability.Vulnerability{
		{ID: "CVE-OS", Component: "openssl", Version: "1.1"},
		{ID: "CVE-APP", Component: "lodash", Version: "4.0.0"},
		{ID: "CVE-UNATTRIBUTED", Component: "ghost", Version: "9"}, // no matching component
	}

	attributeImageLayers(img, doc, vulns)

	// The npm package marks layer 1 as the base/app boundary → layer 0 is the base image.
	if img.BaseLayerCount != 1 {
		t.Fatalf("BaseLayerCount = %d, want 1", img.BaseLayerCount)
	}
	if vulns[0].LayerIndex == nil || *vulns[0].LayerIndex != 0 || !vulns[0].InBaseImage || vulns[0].LayerCreatedBy != "ADD debian rootfs" {
		t.Errorf("OS vuln attribution wrong: %+v", vulns[0])
	}
	if vulns[1].LayerIndex == nil || *vulns[1].LayerIndex != 1 || vulns[1].InBaseImage {
		t.Errorf("app vuln should be in an application layer, not base: %+v", vulns[1])
	}
	if vulns[2].LayerIndex != nil || vulns[2].LayerID != "" || vulns[2].InBaseImage {
		t.Errorf("unattributed vuln must have nil LayerIndex + empty LayerID: %+v", vulns[2])
	}

	// layerNote prose mirrors the attribution.
	if note := layerNote(vulns[0]); note != "Image layer: 0 (base image): ADD debian rootfs" {
		t.Errorf("base layerNote = %q", note)
	}
	if note := layerNote(vulns[1]); note != "Image layer: 1 (application layer): COPY app /app" {
		t.Errorf("app layerNote = %q", note)
	}
	if note := layerNote(vulns[2]); note != "" {
		t.Errorf("unattributed layerNote should be empty, got %q", note)
	}
}

func TestAttributeImageLayersNonImage(t *testing.T) {
	// Non-image scan (img == nil): no panic, no attribution, no layer notes.
	vulns := []vulnerability.Vulnerability{{ID: "CVE-1", Component: "x", Version: "1"}}
	attributeImageLayers(nil, &sbom.SBOM{}, vulns)
	if vulns[0].LayerID != "" || layerNote(vulns[0]) != "" {
		t.Errorf("non-image scan must not attribute layers: %+v", vulns[0])
	}
}

func TestBuildFindingsSAST(t *testing.T) {
	res := &ScanResult{} // no vulns/licenses; SAST only
	now := time.Unix(0, 0).UTC()
	raws := []ports.SASTRawFinding{
		{File: "cmd/app/main.go", Line: 42, RuleID: "weak-hash-md5", CWE: "CWE-327", Severity: shared.SeverityMedium, Title: "Weak hash: MD5", Description: "use SHA-256", OWASP2025: "A04:2025 Cryptographic Failures", EntryPoint: "POST /login", Source: "password/crypto lifecycle", SourceEvidence: "line-local crypto/password lifecycle cue", Sink: "password hashing sink", SinkEvidence: "line 42: password hashing sink", ControlEvidence: "line 40: route POST /login", RouteMiddleware: "line 40: route-level authenticated middleware cue", AuthEvidence: "line 40: route-level authenticated middleware cue", Exposure: "authenticated application route", TrustBoundary: "internet/client-controlled input crosses into server-side password hashing sink", Impact: "possible weak cryptographic protection", Route: "POST /login", AuthScope: "authenticated", DataFlow: "password/crypto lifecycle -> password hashing sink via POST /login", DataFlowEvidence: "not-applicable: finding is about source/lifecycle material rather than request source-to-sink flow", DataFlowConfidence: "not-applicable", Preconditions: "no extra preconditions visible beyond the candidate source/sink path", CounterEvidence: "none observed in bounded local context", ValidationRubric: "source=present; control=present; sink=present; dataflow=not-applicable; counterevidence=none_observed", ValidationMethod: "static-code-understanding", ValidationDisposition: "reportable-static-candidate", Exploitability: "candidate", AttackPath: "attacker reaches login hashing path", Confidence: "high", SeverityRationale: "Pattern severity is medium for CWE-327."},
		{File: "internal/auth/login.go", Line: 7, RuleID: "hardcoded-aws-access-key", CWE: "CWE-798", Severity: shared.SeverityCritical, Title: "Hardcoded AWS access key id", Description: "rotate"},
		{File: "x.go", Line: 1, RuleID: "weak-hash-sha1", CWE: "CWE-327", Severity: shared.SeverityLow, Title: "low", Description: "x"}, // below threshold
	}
	got := buildFindings("eng1", res, now, shared.SeverityMedium, false, raws)
	if len(got) != 2 { // Medium + Critical kept; Low filtered by the threshold
		t.Fatalf("want 2 SAST findings (Low filtered), got %d: %+v", len(got), got)
	}
	var md5 *finding.Finding
	for i := range got {
		if got[i].DedupKey == "sast:weak-hash-md5:cmd/app/main.go:42" {
			md5 = &got[i]
		}
	}
	if md5 == nil {
		t.Fatalf("missing the MD5 SAST finding: %+v", got)
	}
	if md5.Kind != finding.KindSAST || md5.Class != finding.ClassFirstParty || md5.CWE != "CWE-327" || md5.ProposedBy != "" {
		t.Fatalf("SAST finding fields wrong: %+v", md5)
	}
	for _, want := range []string{"AppSec validation envelope", "OWASP/CWE mapping: A04:2025 Cryptographic Failures / CWE-327", "Source: password/crypto lifecycle", "Source evidence:", "Sink/control: password hashing sink", "Sink evidence:", "Control evidence:", "Route middleware:", "Auth evidence:", "Exposure: authenticated application route", "Trust boundary:", "Impact hypothesis:", "Route reachability: POST /login", "Validation receipt: static-code-understanding / reportable-static-candidate", "Preconditions/proof gaps:", "Counterevidence:", "Validation rubric:", "Dataflow:", "Dataflow evidence:", "Dataflow confidence:", "Exploitability validation:", "Attack-path calibration:", "Severity rationale:"} {
		if !strings.Contains(md5.Description, want) {
			t.Fatalf("SAST proof summary missing %q from description:\n%s", want, md5.Description)
		}
	}
	if md5.Confidence != "high" {
		t.Fatalf("SAST confidence should come from analyzer enrichment, got %+v", md5)
	}
	// deterministic SAST is UNGATED + publishable (not an AI claim)
	if md5.RequiresEvidenceGate() || !md5.CanPromote() {
		t.Errorf("deterministic SAST must be ungated + promotable: gate=%v promote=%v", md5.RequiresEvidenceGate(), md5.CanPromote())
	}
	// deterministic id across re-scans (1:1 update, never duplicate)
	again := buildFindings("eng1", res, now.Add(time.Hour), shared.SeverityMedium, false, raws)
	if md5.ID != findingID("eng1", md5.DedupKey) || again[0].ID != got[0].ID {
		t.Error("SAST finding id not deterministic")
	}
}
