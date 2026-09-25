package ast

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/sastbench"
)

func TestBlindedJavaMethodRetainsFlowAndRemovesMarkers(t *testing.T) {
	source := `// @servlet vuln_count = "1"
class Example {
  void doGet(Request req, Response resp) {
    String input = req.getParameter("query"); /* BAD marker */
    String url = "http://example.test/a*b";
    if (input != null) {
      resp.getWriter().println(input + url); // sink marker
    }
  }
  int getVulnerabilityCount() { return 1; }
}`
	packet := blindedJavaMethod(source, 7)
	if !strings.HasPrefix(packet, "// synapse-sast-proof-context: start_line=3\n") {
		t.Fatalf("packet lacks exact source line mapping: %s", packet)
	}
	for _, want := range []string{"req.getParameter", "getWriter", "http://example.test/a*b"} {
		if !strings.Contains(packet, want) {
			t.Fatalf("packet omitted flow context %q: %s", want, packet)
		}
	}
	for _, forbidden := range []string{"@servlet", "BAD", "marker", "getVulnerabilityCount", "good", "bad"} {
		if strings.Contains(strings.ToLower(packet), strings.ToLower(forbidden)) {
			t.Fatalf("packet leaked %q: %s", forbidden, packet)
		}
	}
	if len(packet) < 100 {
		t.Fatalf("packet too short (%d): %s", len(packet), packet)
	}
}

func TestStripJavaCommentsPreservesFirstByteAfterLineComment(t *testing.T) {
	got := stripJavaComments("x(); // benchmark marker\nreturn;\n")
	if got != "x(); \nreturn;\n" {
		t.Fatalf("line comment removal changed code on the next line: %q", got)
	}
}

func TestBlindedJavaMethodCanonicalizesCheckoutLineEndings(t *testing.T) {
	lf := "void f() {\n  sink(input); // marker\n}\n"
	crlf := strings.ReplaceAll(lf, "\n", "\r\n")
	if got, want := blindedJavaMethod(lf, 2), blindedJavaMethod(crlf, 2); got != want {
		t.Fatalf("line ending differences changed verifier packet: LF=%q CRLF=%q", got, want)
	}
}

func TestWriteSecuribenchDiagnosticReportMarksOutputUnaccepted(t *testing.T) {
	path := t.TempDir() + "/diagnostic.json"
	writeSecuribenchDiagnosticReport(t, path, sastbench.Report{Schema: sastbench.ReportSchemaVersion, Engine: "owned + verifier", Stage: "post-triage"})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "diagnostic-unaccepted") {
		t.Fatalf("diagnostic report lacks unaccepted label: %s", data)
	}
}

func TestSecuribenchExpectedCountsIncludesEmptyScoredCategory(t *testing.T) {
	counts := securibenchExpectedCounts([]sastbench.LabeledCase{{CWE: "CWE-79"}, {CWE: "CWE-79"}, {CWE: "CWE-89"}})
	if len(counts) != len(securibenchScoredCWEs) || counts["CWE-78"] != 0 || counts["CWE-79"] != 2 || counts["CWE-89"] != 1 {
		t.Fatalf("scored CWE counts must retain zero-case categories: %#v", counts)
	}
}

func TestBlindedSourceNameUsesSecretSalt(t *testing.T) {
	name := "Arrays6.java"
	token := blindedSourceName(name, "private-session-salt")
	unsalted := sha256.Sum256([]byte(name))
	if strings.Contains(token, name) || strings.Contains(token, hex.EncodeToString(unsalted[:16])) {
		t.Fatalf("token can be recovered with public unsalted basename hash: %s", token)
	}
	if token == blindedSourceName(name, "other-private-salt") {
		t.Fatal("packet identity must vary with the non-exported session salt")
	}
}

func TestValidatePacketSaltRequiresCryptographicKeyMaterial(t *testing.T) {
	for _, salt := range []string{"", "salt", strings.Repeat("a", 63), strings.Repeat("z", 64)} {
		if err := validatePacketSalt(salt); err == nil {
			t.Fatalf("weak salt %q accepted", salt)
		}
	}
	if err := validatePacketSalt(strings.Repeat("a", 64)); err != nil {
		t.Fatalf("valid 32-byte hex salt rejected: %v", err)
	}
}

func TestVerifyPostTriageBaselineDigest(t *testing.T) {
	data := []byte(`{"schema":"synapse-sast-report-v1"}`)
	digest := sha256.Sum256(data)
	if err := verifyPostTriageBaselineDigest(data, hex.EncodeToString(digest[:])); err != nil {
		t.Fatalf("valid baseline pin rejected: %v", err)
	}
	for _, want := range []string{"", "wrong", strings.Repeat("z", 64), strings.Repeat("0", 64)} {
		if err := verifyPostTriageBaselineDigest(data, want); err == nil {
			t.Fatalf("invalid baseline pin %q accepted", want)
		}
	}
}
