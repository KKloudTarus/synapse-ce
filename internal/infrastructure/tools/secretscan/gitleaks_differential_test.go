package secretscan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchid"
)

// competitorManifestPath locates the committed competitor-identity manifest from this package directory.
const competitorManifestPath = "../../../../docs/benchmarks/competitor-identity.json"

// recordCompetitorIdentity captures the competitor's actual reported version and logs it against the pinned
// benchmark identity, so a head-to-head names the exact competitor build that produced it. It is comparison-only:
// an unrecordable version or a mismatch is logged, never fatal.
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

// secretsBenchCase is one labeled secrets-corpus entry. Value is a line of source materialized into its own
// file (one case per file, so a detection's file trivially identifies the case). Real marks a planted secret
// the scanner must find; a non-Real case is a false-positive trap the scanner must NOT flag.
type secretsBenchCase struct {
	name  string
	value string
	real  bool
}

const (
	alnum      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	upperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	digits     = "0123456789"
	gcpAlnum   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)

// synthBody builds a deterministic, high-entropy body of n characters from alphabet, seeded by seed. Building
// the credential bodies at RUNTIME (rather than committing provider-shaped literals) keeps a complete secret
// out of the source tree, so GitHub push protection and repo secret scanners never see one, while the fixed
// seed keeps the corpus and its committed floors stable across runs. The bytes come from a counter-stretched
// SHA-256 so the result is random-looking enough to clear the scanners' entropy checks.
func synthBody(seed string, n int, alphabet string) string {
	out := make([]byte, 0, n)
	for i := 0; len(out) < n; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", seed, i)))
		for _, x := range sum {
			if len(out) >= n {
				break
			}
			out = append(out, alphabet[int(x)%len(alphabet)])
		}
	}
	return string(out)
}

// buildSecretsCorpus constructs the provenance-backed labeled corpus. Each planted value is a fake, non-live
// credential assembled at runtime in the provider's exact format (correct prefix and length), so it matches
// the dedicated provider rule in BOTH scanners and the head-to-head compares like with like; no provider-shaped
// literal is committed. The traps are known non-secrets a precise scanner leaves alone.
func buildSecretsCorpus() []secretsBenchCase {
	awsExample := "AKIA" + "IOSFODNN7" + "EXAMPLE" // AWS's documented example key, split so no full literal is committed
	return []secretsBenchCase{
		// Planted secrets (real): valid provider formats both scanners' dedicated rules recognize.
		{"aws", `aws_key = "AKIA` + synthBody("aws", 16, upperAlnum) + `"`, true},
		{"github", `gh = "ghp_` + synthBody("github", 36, alnum) + `"`, true},
		{"gitlab", `gl = "glpat-` + synthBody("gitlab", 20, alnum) + `"`, true},
		{"slack", `sl = "xoxb-` + synthBody("slackA", 12, digits) + "-" + synthBody("slackB", 12, digits) + "-" + synthBody("slackC", 24, alnum) + `"`, true},
		{"stripe", `st = "sk_live_` + synthBody("stripe", 24, alnum) + `"`, true},
		{"gcp_api", `gcp = "AIza` + synthBody("gcp", 35, gcpAlnum) + `"`, true},
		{"sendgrid", `sg = "SG.` + synthBody("sgA", 22, alnum) + "." + synthBody("sgB", 43, alnum) + `"`, true},
		// False-positive traps (not real): a precise scanner must not flag these.
		{"aws_example", `example = "` + awsExample + `"`, false},
		{"placeholder", `token = "your-api-token-here"`, false},
		{"changeme", `password = "changeme"`, false},
		{"low_entropy", `key = "aaaaaaaaaaaaaaaaaaaaaaaa"`, false},
	}
}

// materializeSecretsCorpus writes each case to its own file (case name -> file) and returns the map of
// filename -> case, so a detection reported against a file identifies the case it hit.
func materializeSecretsCorpus(t *testing.T, dir string) map[string]secretsBenchCase {
	t.Helper()
	corpus := buildSecretsCorpus()
	byFile := make(map[string]secretsBenchCase, len(corpus))
	for _, c := range corpus {
		name := c.name + ".txt"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(c.value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		byFile[name] = c
	}
	return byFile
}

// score reduces a set of flagged files (base filenames) against the corpus into recall/precision. A planted
// case flagged is a true positive; a trap flagged is a false positive; a planted case not flagged is a false
// negative.
func scoreSecrets(flagged map[string]bool, byFile map[string]secretsBenchCase) (tp, fp, fn int, recall, precision float64) {
	for name, c := range byFile {
		hit := flagged[name]
		switch {
		case c.real && hit:
			tp++
		case c.real && !hit:
			fn++
		case !c.real && hit:
			fp++
		}
	}
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	return tp, fp, fn, recall, precision
}

const (
	// Committed owned-engine floors for the secrets corpus, calibrated from a measured run. Recall is the
	// primary gate; precision guards against flagging the traps.
	secretsOwnedRecallFloor    = 1.0
	secretsOwnedPrecisionFloor = 0.85
)

// TestSecretsOwnedAccuracyAndGitleaksDifferential scores the owned secret scanner on a labeled corpus and,
// when gitleaks is available, records the owned-vs-gitleaks head-to-head. The owned recall/precision floors
// gate; the Gitleaks accuracy score is comparison data, while the hosted workflow requires a real scan.
func TestSecretsOwnedAccuracyAndGitleaksDifferential(t *testing.T) {
	dir := t.TempDir()
	byFile := materializeSecretsCorpus(t, dir)

	// Owned engine.
	rep, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("owned scan: %v", err)
	}
	ownedFlagged := map[string]bool{}
	for _, f := range rep.Findings {
		ownedFlagged[filepath.Base(f.File)] = true
	}
	tp, fp, fn, recall, precision := scoreSecrets(ownedFlagged, byFile)
	t.Logf("owned secrets: tp=%d fp=%d fn=%d recall=%.3f precision=%.3f", tp, fp, fn, recall, precision)
	if recall < secretsOwnedRecallFloor {
		t.Errorf("owned secrets recall %.3f below floor %.3f (a planted secret was missed)", recall, secretsOwnedRecallFloor)
	}
	if precision < secretsOwnedPrecisionFloor {
		t.Errorf("owned secrets precision %.3f below floor %.3f (a false-positive trap was flagged)", precision, secretsOwnedPrecisionFloor)
	}

	// Competitor differential (comparison-only). Skip cleanly when gitleaks is not installed.
	gitleaksFlagged, ok := runGitleaks(t, dir, byFile)
	if !ok {
		t.Log("gitleaks not on PATH: skipping the owned-vs-gitleaks differential")
		return
	}
	gtp, gfp, gfn, grecall, gprecision := scoreSecrets(gitleaksFlagged, byFile)
	t.Logf("gitleaks secrets: tp=%d fp=%d fn=%d recall=%.3f precision=%.3f", gtp, gfp, gfn, grecall, gprecision)
	t.Logf("secrets head-to-head: owned recall %.3f / precision %.3f vs gitleaks recall %.3f / precision %.3f",
		recall, precision, grecall, gprecision)
}

// runGitleaks runs gitleaks over the corpus dir and returns the set of flagged files (base names). ok is
// false when gitleaks is not installed, so the caller skips the differential rather than failing.
func runGitleaks(t *testing.T, dir string, byFile map[string]secretsBenchCase) (map[string]bool, bool) {
	t.Helper()
	bin, err := exec.LookPath("gitleaks")
	if err != nil {
		return nil, false
	}
	recordCompetitorIdentity(t, "gitleaks", bin, "version")
	report := filepath.Join(t.TempDir(), "gitleaks.json")
	// --exit-code 0 so a "leaks found" run is not treated as a command failure; --no-git scans the tree.
	cmd := exec.Command(bin, "detect", "-s", dir, "--no-git", "-f", "json", "-r", report, "--exit-code", "0")
	if out, rerr := cmd.CombinedOutput(); rerr != nil {
		// gitleaks is comparison-only: a present-but-erroring binary (a different version whose CLI rejects
		// these flags, a config/permission issue) must SKIP the differential, never fail the build.
		t.Logf("gitleaks present but failed to run (%v); skipping the differential:\n%s", rerr, out)
		return nil, false
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Logf("gitleaks produced no report (%v); skipping the differential", err)
		return nil, false
	}
	flagged, err := parseGitleaksReport(data, byFile)
	if err != nil {
		t.Logf("gitleaks report incomplete (%v); skipping the differential", err)
		return nil, false
	}
	return flagged, true
}

// parseGitleaksReport requires at least one planted case from this pinned corpus. An empty finding-only
// report cannot prove that Gitleaks actually scanned the generated fixture files.
func parseGitleaksReport(data []byte, byFile map[string]secretsBenchCase) (map[string]bool, error) {
	var results []struct {
		File      string `json:"File"`
		StartLine int    `json:"StartLine"`
		RuleID    string `json:"RuleID"`
	}
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("decode Gitleaks JSON: %w", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no Gitleaks findings from the pinned corpus")
	}
	flagged := map[string]bool{}
	plantedFound := false
	for _, r := range results {
		if r.File == "" || r.StartLine < 1 || r.RuleID == "" {
			return nil, fmt.Errorf("Gitleaks finding lacks file, line, or rule identity")
		}
		name := filepath.Base(r.File)
		c, ok := byFile[name]
		if !ok {
			return nil, fmt.Errorf("Gitleaks finding references unknown file %s", name)
		}
		flagged[name] = true
		plantedFound = plantedFound || c.real
	}
	if !plantedFound {
		return nil, fmt.Errorf("no planted secret was observed")
	}
	return flagged, nil
}

func TestGitleaksReportRequiresObservedCorpus(t *testing.T) {
	corpus := map[string]secretsBenchCase{"aws.txt": {name: "aws", real: true}}
	for _, report := range []string{"[]", "null", `[{}]`} {
		if _, err := parseGitleaksReport([]byte(report), corpus); err == nil {
			t.Fatalf("accepted vacuous Gitleaks report %s", report)
		}
	}
	flagged, err := parseGitleaksReport([]byte(`[{"File":"/tmp/aws.txt","StartLine":1,"RuleID":"aws-access-token"}]`), corpus)
	if err != nil || !flagged["aws.txt"] {
		t.Fatalf("rejected observed Gitleaks report: flagged=%v err=%v", flagged, err)
	}
}
