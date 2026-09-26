package secretscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestProviderSecretInCommentIsReported pins the behaviour found on a real service: an AWS access key id on
// a commented-out YAML line was masked away and the scan reported the file clean, while a competitor
// reported the key. A commented-out credential is still committed, still in the history, and usually still
// live, so a rule whose unique prefix IS the signal must read comments.
func TestProviderSecretInCommentIsReported(t *testing.T) {
	dir := t.TempDir()
	// A fake key in the AKIA shape. Not a real credential; the prefix plus 16 uppercase/digits is the rule.
	const fakeAWSKeyID = "AKIA" + "QRSTUVWX2345YZ67"
	yaml := "aws:\n" +
		"  region: ap-southeast-1\n" +
		"  # access-key-id: " + fakeAWSKeyID + "\n"
	if err := os.WriteFile(filepath.Join(dir, "application-dev.yml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	// A generic keyword rule must still ignore a commented example, which is why masking stays the default.
	code := "// password = \"CorrectHorseBatteryStaple99\"\n" +
		"func main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := report.Findings
	var sawAWS bool
	for _, f := range found {
		if f.RuleID == "aws-access-key-id" {
			sawAWS = true
		}
		if f.File == "main.go" {
			t.Errorf("a commented example must stay masked for keyword rules, got %s at main.go:%d", f.RuleID, f.Line)
		}
	}
	if !sawAWS {
		t.Fatalf("commented AWS access key id was not reported; findings=%d", len(found))
	}
}

// TestCommentScanningIsLimitedToPrefixAnchoredRules pins the exclusions. Admitting comments for a generic,
// entropy or structural rule would report every documented example as a live credential.
func TestCommentScanningIsLimitedToPrefixAnchoredRules(t *testing.T) {
	for _, id := range []string{"generic-secret", "generic-high-entropy", "jwt", "db-connection-string"} {
		if commentScannedRuleIDs[id] {
			t.Errorf("%q must not read comments: it is not anchored on a unique provider prefix", id)
		}
	}
	for _, r := range defaultRules() {
		if commentScannedRuleIDs[r.id] && !r.scanComments {
			t.Errorf("rule %q is listed for comment scanning but the flag was not applied", r.id)
		}
	}
}
