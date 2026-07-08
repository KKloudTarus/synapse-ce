package export

import (
	"encoding/json"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// firstPartyFindings mixes the three first-party kinds (SAST/secret/misconfig) that carry a
// "<kind>:<ruleID>:<file>:<line>" dedup key with an SCA vuln that carries "vuln:...".
func firstPartyFindings() []finding.Finding {
	return []finding.Finding{
		{ID: "s1", Title: "MD5 is a weak hash (app/crypto.go:42)", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindSAST, DedupKey: "sast:weak-crypto-md5:app/crypto.go:42"},
		{ID: "k1", Title: "Container runs as root (deploy/pod.yaml:17)", Severity: shared.SeverityMedium, Status: finding.StatusOpen, Kind: finding.KindMisconfig, DedupKey: "misconfig:kubernetes-no-run-as-non-root:deploy/pod.yaml:17"},
		{ID: "x1", Title: "AWS key in source (src/config.ts:8)", Severity: shared.SeverityCritical, Status: finding.StatusOpen, Kind: finding.KindSecret, DedupKey: "secret:aws-access-key:src/config.ts:8"},
		{ID: "v1", Title: "CVE-2020-7471 in django@2.2.0", Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: "vuln:CVE-2020-7471:django:2.2.0"},
	}
}

func TestSARIFPhysicalLocationForFirstParty(t *testing.T) {
	log := buildSARIF(firstPartyFindings(), "v9")
	byRule := map[string]SARIFResult{}
	for _, r := range log.Runs[0].Results {
		byRule[r.RuleID] = r
	}

	// SAST/secret/misconfig -> physical file:line, rule id is the ENGINE rule id (not the whole dedup key).
	cases := []struct {
		rule, uri string
		line      int
		level     string
	}{
		{"weak-crypto-md5", "app/crypto.go", 42, "error"},                   // high -> error
		{"kubernetes-no-run-as-non-root", "deploy/pod.yaml", 17, "warning"}, // medium -> warning
		{"aws-access-key", "src/config.ts", 8, "error"},                     // critical -> error
	}
	for _, c := range cases {
		r, ok := byRule[c.rule]
		if !ok {
			t.Fatalf("missing result for rule %q; rules present: %v", c.rule, keysOf(byRule))
		}
		if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation == nil {
			t.Fatalf("rule %q: want one physical location, got %+v", c.rule, r.Locations)
		}
		phys := r.Locations[0].PhysicalLocation
		if phys.ArtifactLocation.URI != c.uri {
			t.Errorf("rule %q: uri = %q, want %q", c.rule, phys.ArtifactLocation.URI, c.uri)
		}
		if phys.Region == nil || phys.Region.StartLine != c.line {
			t.Errorf("rule %q: region = %+v, want startLine %d", c.rule, phys.Region, c.line)
		}
		if r.Level != c.level {
			t.Errorf("rule %q: level = %q, want %q", c.rule, r.Level, c.level)
		}
		if r.Locations[0].LogicalLocations != nil {
			t.Errorf("rule %q: first-party finding must not carry a logical (module) location", c.rule)
		}
	}

	// The SCA vuln keeps a logical module location and never a physical one.
	v, ok := byRule["CVE-2020-7471"]
	if !ok {
		t.Fatal("missing SCA result")
	}
	if len(v.Locations) != 1 || v.Locations[0].PhysicalLocation != nil {
		t.Fatalf("SCA finding must not have a physical location: %+v", v.Locations)
	}
	if v.Locations[0].LogicalLocations[0].Name != "django@2.2.0" {
		t.Errorf("SCA module location = %+v", v.Locations[0].LogicalLocations)
	}
}

func TestMarshalSARIFValidJSON(t *testing.T) {
	out, err := MarshalSARIF(firstPartyFindings(), "v9")
	if err != nil {
		t.Fatalf("MarshalSARIF: %v", err)
	}
	// Must be valid JSON with the SARIF header a GitHub uploader keys on.
	var log SARIFLog
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" || log.Schema == "" {
		t.Errorf("bad SARIF header: version=%q schema=%q", log.Version, log.Schema)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 4 {
		t.Fatalf("want 1 run with 4 results, got %d run(s)", len(log.Runs))
	}
	// A physical-location result must serialize startLine >= 1 (SARIF requires it).
	for _, r := range log.Runs[0].Results {
		if p := firstNonNilPhysical(r.Locations); p != nil && p.Region != nil && p.Region.StartLine < 1 {
			t.Errorf("result %q has invalid startLine %d", r.RuleID, p.Region.StartLine)
		}
	}
}

func TestFirstPartyLocParsing(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		wantOK bool
		rule   string
		file   string
		line   int
	}{
		{"sast", "sast:weak-crypto-md5:app/main.go:42", true, "weak-crypto-md5", "app/main.go", 42},
		{"secret", "secret:aws-key:a/b/c.env:3", true, "aws-key", "a/b/c.env", 3},
		{"misconfig", "misconfig:dockerfile-run-sudo:Dockerfile:5", true, "dockerfile-run-sudo", "Dockerfile", 5},
		{"path-with-colon", "sast:rule:weird:path.go:7", true, "rule", "weird:path.go", 7},
		{"sca-vuln", "vuln:CVE-2020-7471:django:2.2.0", false, "", "", 0},
		{"license", "license:GPL-3.0-only", false, "", "", 0},
		{"non-numeric-line", "sast:rule:file.go:notaline", false, "", "", 0},
		{"too-few-parts", "sast:rule", false, "", "", 0},
		{"zero-line", "sast:rule:file.go:0", false, "", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, file, line, ok := firstPartyLoc(tt.key)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && (rule != tt.rule || file != tt.file || line != tt.line) {
				t.Errorf("got (%q,%q,%d), want (%q,%q,%d)", rule, file, line, tt.rule, tt.file, tt.line)
			}
		})
	}
}

func TestRuleTitleStripsLocationMarker(t *testing.T) {
	tests := []struct{ in, want string }{
		{"MD5 is a weak hash (app/crypto.go:42)", "MD5 is a weak hash"},
		{"AWS key in source (src/config.ts:8)", "AWS key in source"},
		{"CVE-2020-7471 in django@2.2.0", "CVE-2020-7471 in django@2.2.0"}, // SCA: no marker, unchanged
		{"Some title (not a location)", "Some title (not a location)"},     // parenthetical without :line
		{"Weird (a:b:12)", "Weird"},                                        // path-with-colon marker
		{"No parens at all", "No parens at all"},
	}
	for _, tt := range tests {
		if got := ruleTitle(tt.in); got != tt.want {
			t.Errorf("ruleTitle(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	// The rule entry uses the generic title; the per-result message keeps the located one.
	log := buildSARIF(firstPartyFindings(), "v9")
	var found bool
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.ID == "weak-crypto-md5" {
			found = true
			if r.ShortDescription.Text != "MD5 is a weak hash" {
				t.Errorf("rule shortDescription = %q, want stripped", r.ShortDescription.Text)
			}
		}
	}
	if !found {
		t.Fatal("weak-crypto-md5 rule not registered")
	}
	for _, res := range log.Runs[0].Results {
		if res.RuleID == "weak-crypto-md5" && res.Message.Text != "MD5 is a weak hash (app/crypto.go:42)" {
			t.Errorf("result message = %q, want full located title", res.Message.Text)
		}
	}
}

func TestGatedTaintSASTRuleID(t *testing.T) {
	// A gated E39 taint finding ("sast:ai:<anchor>") gets a stable rule id and no physical location,
	// rather than leaking the per-finding anchor as the rule id.
	fs := []finding.Finding{
		{ID: "t1", Title: "Command injection via tainted flow", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindSAST, DedupKey: "sast:ai:pkg/handler.go.Serve"},
	}
	log := buildSARIF(fs, "v9")
	r := log.Runs[0].Results[0]
	if r.RuleID != "synapse-taint-sast" {
		t.Errorf("gated taint rule id = %q, want synapse-taint-sast", r.RuleID)
	}
	if len(r.Locations) != 0 {
		t.Errorf("gated taint finding should carry no location, got %+v", r.Locations)
	}
}

func keysOf(m map[string]SARIFResult) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func firstNonNilPhysical(locs []SARIFLocation) *SARIFPhysicalLocation {
	for i := range locs {
		if locs[i].PhysicalLocation != nil {
			return locs[i].PhysicalLocation
		}
	}
	return nil
}
