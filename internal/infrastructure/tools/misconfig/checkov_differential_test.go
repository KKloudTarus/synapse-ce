package misconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchid"
)

// competitorManifestPath locates the committed competitor-identity manifest from this package directory.
const competitorManifestPath = "../../../../docs/benchmarks/competitor-identity.json"

// recordCompetitorIdentity captures the competitor's actual reported version and logs it against the pinned
// benchmark identity, so a head-to-head names the exact competitor build that produced it. Comparison-only: an
// unrecordable version or a mismatch is logged, never fatal.
func recordCompetitorIdentity(t *testing.T, tool, bin string, versionArgs ...string) {
	t.Helper()
	observed, err := benchid.CaptureVersion(context.Background(), bin, versionArgs...)
	if err != nil {
		t.Logf("%s identity unrecorded (version command failed: %v)", tool, err)
		return
	}
	m, err := benchid.Load(competitorManifestPath)
	if err != nil {
		t.Logf("%s observed version %q; competitor-identity manifest unreadable (%v)", tool, observed, err)
		return
	}
	exp, ok := m.Expected(tool)
	if !ok {
		t.Logf("%s observed version %q; no pinned identity recorded for it", tool, observed)
		return
	}
	t.Logf("%s identity: observed %q, pinned %q (ruleset: %s)", tool, observed, exp.Version, exp.Ruleset)
	if !benchid.VersionMatches(observed, exp.Version) {
		t.Logf("NOTE: %s version differs from the pinned benchmark version %s; head-to-head numbers may not be comparable to the committed baseline", tool, exp.Version)
	}
}

// checkov_differential_test.go scores the owned IaC misconfiguration engine on a labeled Terraform corpus and,
// when checkov is available, records the owned-vs-checkov head-to-head. Because both engines carry dozens of
// policies per resource, a fair comparison is scoped PER MISCONFIG CATEGORY: each category names a bad fixture
// (the misconfig present) and a good fixture (fixed), plus the owned rule id and the checkov check id that
// represent that category. A tool "detects" a category on a fixture when it flags that fixture with the
// category's own rule/check, so an unrelated policy firing on the good fixture is not counted as a false
// positive for this category. Checkov accuracy is comparison data; the hosted workflow requires a real scan.

// iacCategory is one labeled misconfiguration category with a bad/good fixture pair and the per-tool rule that
// represents the category, so the comparison is like-for-like rather than "any policy fired".
type iacCategory struct {
	name      string
	ext       string // ".tf" for Terraform, ".yaml" for Kubernetes
	bad       string // source with the misconfig present
	good      string // the same resource, fixed
	ownedRule string // owned rule id that represents this category
	checkovID string // checkov check id (CKV_...) that represents this category
	badFile   string
	goodFile  string
	ownedBad  bool // owned flagged the bad fixture for this category
	ownedGood bool // owned flagged the good fixture for this category (a false positive)
	ckovBad   bool
	ckovGood  bool
}

// k8sPod renders a minimal Pod whose one container carries the given securityContext body and whose spec
// carries the given spec body, so each category's bad/good differs only in the field that category represents.
func k8sPod(sc, spec string) string {
	return "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n    image: nginx:1.25\n    securityContext:\n" + sc + spec
}

// iacCorpus is the labeled corpus, scoped to misconfiguration categories both engines cover with a single
// dedicated rule/check, each empirically verified to fire on the bad fixture and not on the fixed one. Every
// category names the owned rule id and the checkov check id that represent it, so the head-to-head compares the
// same misconfiguration in both tools rather than counting any policy that happens to fire.
var iacCorpus = []iacCategory{
	{
		name:      "rds-encryption",
		ext:       ".tf",
		ownedRule: "terraform-encryption-disabled",
		checkovID: "CKV_AWS_16",
		bad:       "resource \"aws_db_instance\" \"r\" {\n  allocated_storage = 10\n  engine = \"mysql\"\n  instance_class = \"db.t3.micro\"\n  storage_encrypted = false\n}\n",
		good:      "resource \"aws_db_instance\" \"r\" {\n  allocated_storage = 10\n  engine = \"mysql\"\n  instance_class = \"db.t3.micro\"\n  storage_encrypted = true\n}\n",
	},
	{
		name:      "sg-open-ingress",
		ext:       ".tf",
		ownedRule: "terraform-open-cidr",
		checkovID: "CKV_AWS_24",
		bad:       "resource \"aws_security_group\" \"s\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n",
		good:      "resource \"aws_security_group\" \"s\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"10.0.0.0/16\"]\n  }\n}\n",
	},
	{
		name:      "s3-public-access-block",
		ext:       ".tf",
		ownedRule: "terraform-public-access-block-disabled",
		checkovID: "CKV_AWS_53",
		bad:       "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n}\nresource \"aws_s3_bucket_public_access_block\" \"b\" {\n  bucket = aws_s3_bucket.b.id\n  block_public_acls = false\n}\n",
		good:      "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n}\nresource \"aws_s3_bucket_public_access_block\" \"b\" {\n  bucket = aws_s3_bucket.b.id\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}\n",
	},
	{
		name:      "k8s-privileged",
		ext:       ".yaml",
		ownedRule: "kubernetes-privileged",
		checkovID: "CKV_K8S_16",
		bad:       k8sPod("      privileged: true\n", ""),
		good:      k8sPod("      privileged: false\n", ""),
	},
	{
		name:      "k8s-host-network",
		ext:       ".yaml",
		ownedRule: "kubernetes-host-network",
		checkovID: "CKV_K8S_19",
		bad:       k8sPod("      privileged: false\n", "  hostNetwork: true\n"),
		good:      k8sPod("      privileged: false\n", "  hostNetwork: false\n"),
	},
	{
		name:      "k8s-priv-escalation",
		ext:       ".yaml",
		ownedRule: "kubernetes-allow-priv-escalation",
		checkovID: "CKV_K8S_20",
		bad:       k8sPod("      allowPrivilegeEscalation: true\n", ""),
		good:      k8sPod("      allowPrivilegeEscalation: false\n", ""),
	},
}

const (
	// Committed owned-engine floors for the IaC corpus: every category's misconfig must be detected on the bad
	// fixture (recall) and not falsely flagged on the fixed fixture (precision).
	iacOwnedRecallFloor    = 1.0
	iacOwnedPrecisionFloor = 1.0
)

// TestIaCOwnedAccuracyAndCheckovDifferential scores the owned misconfig engine per category and records the
// owned-vs-checkov head-to-head when checkov is installed. The owned recall/precision gate; checkov never does.
func TestIaCOwnedAccuracyAndCheckovDifferential(t *testing.T) {
	dir := t.TempDir()
	cats := make([]iacCategory, len(iacCorpus))
	copy(cats, iacCorpus)
	for i := range cats {
		cats[i].badFile = cats[i].name + "_bad" + cats[i].ext
		cats[i].goodFile = cats[i].name + "_good" + cats[i].ext
		if err := os.WriteFile(filepath.Join(dir, cats[i].badFile), []byte(cats[i].bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, cats[i].goodFile), []byte(cats[i].good), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Owned engine: map (file -> set of rule ids) so a category is scored on its own rule.
	findings, err := New().ScanConfigs(context.Background(), dir)
	if err != nil {
		t.Fatalf("owned scan: %v", err)
	}
	ownedByFile := map[string]map[string]bool{}
	for _, f := range findings {
		b := filepath.Base(f.File)
		if ownedByFile[b] == nil {
			ownedByFile[b] = map[string]bool{}
		}
		ownedByFile[b][f.RuleID] = true
	}
	for i := range cats {
		cats[i].ownedBad = ownedByFile[cats[i].badFile][cats[i].ownedRule]
		cats[i].ownedGood = ownedByFile[cats[i].goodFile][cats[i].ownedRule]
	}

	otp, ofp, ofn := 0, 0, 0
	for _, c := range cats {
		if c.ownedBad {
			otp++
		} else {
			ofn++
			t.Errorf("owned missed category %s on %s (rule %s did not fire)", c.name, c.badFile, c.ownedRule)
		}
		if c.ownedGood {
			ofp++
			t.Errorf("owned false-positive: category %s fired %s on the fixed fixture %s", c.name, c.ownedRule, c.goodFile)
		}
	}
	orecall, oprecision := rate(otp, ofn), rate(otp, ofp)
	t.Logf("owned iac: categories=%d tp=%d fp=%d fn=%d recall=%.3f precision=%.3f", len(cats), otp, ofp, ofn, orecall, oprecision)
	if orecall < iacOwnedRecallFloor {
		t.Errorf("owned iac recall %.3f below floor %.3f", orecall, iacOwnedRecallFloor)
	}
	if oprecision < iacOwnedPrecisionFloor {
		t.Errorf("owned iac precision %.3f below floor %.3f", oprecision, iacOwnedPrecisionFloor)
	}

	// Competitor differential (comparison-only): checkov, scoped to the same category check ids.
	ckovByFile, ok := runCheckov(t, dir, cats)
	if !ok {
		t.Log("checkov not on PATH or failed: skipping the owned-vs-checkov differential")
		return
	}
	ctp, cfp, cfn := 0, 0, 0
	for i := range cats {
		cats[i].ckovBad = ckovByFile[cats[i].badFile][cats[i].checkovID]
		cats[i].ckovGood = ckovByFile[cats[i].goodFile][cats[i].checkovID]
		if cats[i].ckovBad {
			ctp++
		} else {
			cfn++
		}
		if cats[i].ckovGood {
			cfp++
		}
	}
	crecall, cprecision := rate(ctp, cfn), rate(ctp, cfp)
	t.Logf("checkov iac: tp=%d fp=%d fn=%d recall=%.3f precision=%.3f", ctp, cfp, cfn, crecall, cprecision)
	t.Logf("iac head-to-head: owned recall %.3f / precision %.3f vs checkov recall %.3f / precision %.3f",
		orecall, oprecision, crecall, cprecision)
}

func rate(tp, other int) float64 {
	if tp+other == 0 {
		return 0
	}
	return float64(tp) / float64(tp+other)
}

// runCheckov runs checkov over the corpus and returns file -> set of failed check ids. ok is false when
// checkov is absent or errors, so the differential is skipped rather than failing (checkov is comparison-only).
func runCheckov(t *testing.T, dir string, cats []iacCategory) (map[string]map[string]bool, bool) {
	t.Helper()
	bin, err := exec.LookPath("checkov")
	if err != nil {
		return nil, false
	}
	recordCompetitorIdentity(t, "checkov", bin, "--version")
	// Bound the run so a pathological checkov cannot hang the suite to the global go-test timeout; a timeout
	// skips (comparison-only), never fails. checkov exits non-zero when it finds failures; capture stdout as
	// the JSON report regardless.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-d", dir, "--compact", "-o", "json")
	out, runErr := cmd.Output()
	if ctx.Err() != nil {
		t.Logf("checkov timed out (%v); skipping the differential", ctx.Err())
		return nil, false
	}
	if len(out) == 0 {
		if runErr != nil {
			t.Logf("checkov command failed: %v", runErr)
			if exitErr, ok := runErr.(*exec.ExitError); ok {
				stderr := exitErr.Stderr
				if len(stderr) > 2048 {
					stderr = stderr[:2048]
				}
				t.Logf("checkov stderr prefix: %s", stderr)
			}
		}
		t.Logf("checkov produced no output; skipping the differential")
		return nil, false
	}
	byFile, err := parseCheckovReport(out, cats)
	if err != nil {
		t.Logf("checkov report incomplete (%v); skipping the differential", err)
		return nil, false
	}
	return byFile, true
}

type checkovFinding struct {
	CheckID  string `json:"check_id"`
	FilePath string `json:"file_path"`
}

type checkovRun struct {
	Results *struct {
		FailedChecks []checkovFinding `json:"failed_checks"`
		PassedChecks []checkovFinding `json:"passed_checks"`
	} `json:"results"`
}

// parseCheckovReport requires observed checks for every fixture. An empty or partial JSON report cannot
// masquerade as a completed comparison with six misses.
func parseCheckovReport(out []byte, cats []iacCategory) (map[string]map[string]bool, error) {
	var runs []checkovRun
	if err := json.Unmarshal(out, &runs); err != nil {
		var single checkovRun
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			return nil, fmt.Errorf("decode Checkov JSON: %w", err2)
		}
		runs = []checkovRun{single}
	}
	if len(runs) == 0 {
		return nil, fmt.Errorf("no Checkov runs")
	}
	required := make(map[string]string, len(cats)*2)
	observed := make(map[string]bool, len(cats)*2)
	for _, c := range cats {
		required[c.badFile] = c.checkovID
		required[c.goodFile] = c.checkovID
	}
	byFile := make(map[string]map[string]bool, len(required))
	for _, run := range runs {
		if run.Results == nil {
			return nil, fmt.Errorf("Checkov run has no results")
		}
		for _, check := range run.Results.PassedChecks {
			if check.CheckID == "" || check.FilePath == "" {
				return nil, fmt.Errorf("Checkov passed check lacks identity or file path")
			}
			name := filepath.Base(check.FilePath)
			if check.CheckID == required[name] {
				observed[name] = true
			}
		}
		for _, check := range run.Results.FailedChecks {
			if check.CheckID == "" || check.FilePath == "" {
				return nil, fmt.Errorf("Checkov failed check lacks identity or file path")
			}
			name := filepath.Base(check.FilePath)
			if check.CheckID == required[name] {
				observed[name] = true
			}
			if byFile[name] == nil {
				byFile[name] = map[string]bool{}
			}
			byFile[name][check.CheckID] = true
		}
	}
	for name, checkID := range required {
		if !observed[name] {
			return nil, fmt.Errorf("no Checkov %s check for fixture %s", checkID, name)
		}
	}
	return byFile, nil
}

func TestCheckovReportRequiresObservedCorpus(t *testing.T) {
	cats := []iacCategory{{badFile: "rds-encryption_bad.tf", goodFile: "rds-encryption_good.tf", checkovID: "CKV_AWS_16"}}
	for _, report := range []string{"[]", "null", "[{}]", `{"results":{}}`, `{"results":{"failed_checks":[{"check_id":"CKV_AWS_16","file_path":"/tmp/rds-encryption_bad.tf"}]}}`, `{"results":{"failed_checks":[{"check_id":"CKV_OTHER","file_path":"/tmp/rds-encryption_bad.tf"}],"passed_checks":[{"check_id":"CKV_OTHER","file_path":"/tmp/rds-encryption_good.tf"}]}}`} {
		if _, err := parseCheckovReport([]byte(report), cats); err == nil {
			t.Fatalf("accepted incomplete Checkov report %s", report)
		}
	}
	report := `{"results":{"failed_checks":[{"check_id":"CKV_AWS_16","file_path":"/tmp/rds-encryption_bad.tf"}],"passed_checks":[{"check_id":"CKV_AWS_16","file_path":"/tmp/rds-encryption_good.tf"}]}}`
	findings, err := parseCheckovReport([]byte(report), cats)
	if err != nil || !findings["rds-encryption_bad.tf"]["CKV_AWS_16"] {
		t.Fatalf("rejected observed Checkov report: findings=%v err=%v", findings, err)
	}
}
