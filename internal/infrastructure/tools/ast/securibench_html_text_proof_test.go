package ast

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/sastbench"
)

// TestSecuribenchHTMLTextProofDiagnostic is the required causal control for the hosted Securibench gate. It
// clears output proof from freshly extracted facts, then confirms the scanner's production result is exactly
// the two callsites independently recognized by the narrow local HTML-text proof.
func TestSecuribenchHTMLTextProofDiagnostic(t *testing.T) {
	root := os.Getenv("SYNAPSE_SECURIBENCH_DIR")
	bin := os.Getenv("SYNAPSE_AST_BIN")
	if root == "" || bin == "" {
		t.Skip("set SYNAPSE_SECURIBENCH_DIR and SYNAPSE_AST_BIN to measure the HTML-text proof")
	}
	srcRoot := root
	if st, err := os.Stat(filepath.Join(root, "src")); err == nil && st.IsDir() {
		srcRoot = filepath.Join(root, "src")
	}
	corpus, err := loadSecuribench(srcRoot)
	if err != nil {
		t.Fatalf("load securibench corpus: %v", err)
	}
	cases := make([]sastbench.LabeledCase, len(corpus.Cases))
	for i, c := range corpus.Cases {
		c.File = filepath.Base(c.File)
		cases[i] = c
	}
	// The baseline uses the same current facts with only the optional proof cleared. Comparing it to an
	// older sidecar binary would conflate this model's effect with unrelated extractor changes.
	detected := runJavaTaintLineAnchoredWithoutOutputProof(t, bin, srcRoot)
	filtered, suppressed := diagnosticHTMLTextProof(t, srcRoot, detected)
	if got, want := strings.Join(suppressed, ","), "Sanitizers2.java:46,Sanitizers6.java:46"; got != want {
		t.Fatalf("HTML-text proof suppressions = %q, want %q", got, want)
	}
	before := sastbench.ScoreByCWE(detected, cases, securibenchScoredCWEs, securibenchLineWindow)
	after := sastbench.ScoreByCWE(filtered, cases, securibenchScoredCWEs, securibenchLineWindow)
	beforeXSS, afterXSS := cweScore(before, "CWE-79"), cweScore(after, "CWE-79")
	if beforeXSS.TP != afterXSS.TP || beforeXSS.FN != afterXSS.FN {
		t.Fatalf("HTML-text proof lost truth coverage: before=%+v after=%+v", beforeXSS, afterXSS)
	}
	if beforeXSS.FP-afterXSS.FP != 2 {
		t.Fatalf("HTML-text proof FP reduction = %d, want 2: before=%+v after=%+v", beforeXSS.FP-afterXSS.FP, beforeXSS, afterXSS)
	}
	production := runJavaTaintLineAnchored(t, bin, srcRoot)
	productionXSS := cweScore(sastbench.ScoreByCWE(production, cases, securibenchScoredCWEs, securibenchLineWindow), "CWE-79")
	if productionXSS.TP != afterXSS.TP || productionXSS.FP != afterXSS.FP || productionXSS.FN != afterXSS.FN {
		t.Fatalf("production proof differs from diagnostic control: production=%+v diagnostic=%+v", productionXSS, afterXSS)
	}
	t.Logf("diagnostic HTML-text proof: CWE-79 TP=%d FP=%d FN=%d -> TP=%d FP=%d FN=%d",
		beforeXSS.TP, beforeXSS.FP, beforeXSS.FN, afterXSS.TP, afterXSS.FP, afterXSS.FN)
}

func cweScore(scores []sastbench.CWEScore, cwe string) sastbench.CWEScore {
	for _, score := range scores {
		if score.CWE == cwe {
			return score
		}
	}
	return sastbench.CWEScore{CWE: cwe}
}

// diagnosticHTMLTextProof removes a finding only if the source proves all of these facts at the same
// callsite: one writer.println call, text/html is selected before it, the argument is exactly
// "<html>" + local-helper-result + "</html>", and that local helper is one of two closed character
// transformations. It rejects every other output context and every helper shape by construction.
func diagnosticHTMLTextProof(t *testing.T, srcRoot string, detected []sastbench.Finding) ([]sastbench.Finding, []string) {
	t.Helper()
	sources := securibenchSourcesByBaseName(t, srcRoot)
	kept := make([]sastbench.Finding, 0, len(detected))
	var suppressed []string
	for _, finding := range detected {
		if finding.CWE != "CWE-79" || !diagnosticHTMLTextSafeCallsite(t, sources[finding.File], finding) {
			kept = append(kept, finding)
			continue
		}
		suppressed = append(suppressed, fmt.Sprintf("%s:%d", finding.File, finding.Line))
	}
	return kept, suppressed
}

func securibenchSourcesByBaseName(t *testing.T, root string) map[string]string {
	t.Helper()
	sources := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !strings.HasSuffix(path, ".java") {
			return nil
		}
		base := filepath.Base(path)
		if _, exists := sources[base]; exists {
			return fmt.Errorf("duplicate Java source basename %q", base)
		}
		sources[base] = path
		return nil
	})
	if err != nil {
		t.Fatalf("index diagnostic proof sources: %v", err)
	}
	return sources
}

func diagnosticHTMLTextSafeCallsite(t *testing.T, path string, finding sastbench.Finding) bool {
	t.Helper()
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read diagnostic proof source %s: %v", path, err)
	}
	return diagnosticHTMLTextSafeSource(string(data), finding.Line)
}

func diagnosticHTMLTextSafeSource(source string, lineNumber int) bool {
	lines := strings.Split(strings.ReplaceAll(source, "\r\n", "\n"), "\n")
	if lineNumber < 1 || lineNumber > len(lines) {
		return false
	}
	line := compactJava(stripJavaComments(lines[lineNumber-1]))
	if line != `writer.println("<html>"+clean+"</html>");` {
		return false
	}
	normalized := compactJava(stripJavaComments(source))
	// A response with multiple writer writes can switch contexts or write raw bytes before the protected
	// fragment. The exact local shape below has one response write and selects HTML before it.
	if strings.Count(normalized, "writer.println(") != 1 ||
		!strings.Contains(normalized, `writer=resp.getWriter();resp.setContentType("text/html");writer.println("<html>"+clean+"</html>");`) {
		return false
	}
	return knownLocalHTMLTextEscaper(normalized)
}

func TestDiagnosticHTMLTextProofRejectsUnsafeContextsAndHelpers(t *testing.T) {
	safe := strings.Join([]string{
		"class Example {",
		"void doGet() {",
		"writer = resp.getWriter();",
		"resp.setContentType(\"text/html\");",
		"writer.println(\"<html>\" + clean + \"</html>\");",
		"}",
		"private static String clean(String name) {",
		"StringBuffer buf = new StringBuffer();",
		"for (int i = 0; i < name.length(); i++) {",
		"char ch = name.charAt(i);",
		"if (Character.isLetter(ch) || Character.isDigit(ch) || ch == '_') { buf.append(ch); } else { buf.append('?'); }",
		"}",
		"return buf.toString();",
		"}",
		"}",
	}, "\n")
	if !diagnosticHTMLTextSafeSource(safe, 5) {
		t.Fatal("complete local character filter in a single HTML-text write was not proved")
	}
	for name, source := range map[string]string{
		"raw writer before protected fragment": strings.Replace(safe, "writer.println(\"<html>\" + clean + \"</html>\");", "writer.println(name);\nwriter.println(\"<html>\" + clean + \"</html>\");", 1),
		"script context":                       strings.Replace(safe, "\"<html>\" + clean + \"</html>\"", "\"<script>\" + clean + \"</script>\"", 1),
		"attribute context":                    strings.Replace(safe, "\"<html>\" + clean + \"</html>\"", "\"<a href=\\\"\" + clean + \"\\\">x</a>\"", 1),
		"event handler context":                strings.Replace(safe, "\"<html>\" + clean + \"</html>\"", "\"<div onclick=\\\"\" + clean + \"\\\">x</div>\"", 1),
		"url context":                          strings.Replace(safe, "\"<html>\" + clean + \"</html>\"", "\"<a href=\\\"/\" + clean + \"\\\">x</a>\"", 1),
		"bypass return":                        strings.Replace(safe, "return buf.toString();", "if (name == null) return name; return buf.toString();", 1),
		"partial encoder":                      strings.Replace(safe, "else { buf.append('?'); }", "else { buf.append(ch); }", 1),
		"unknown output shape":                 strings.Replace(safe, "\"<html>\" + clean + \"</html>\"", "prefix + clean + suffix", 1),
	} {
		if diagnosticHTMLTextSafeSource(source, 5) {
			t.Fatalf("unsafe %s was proved as HTML text", name)
		}
	}
}

func compactJava(source string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, source)
}

// knownLocalHTMLTextEscaper recognizes closed character transformations rather than a helper name. Both
// forms eliminate literal '<' and '>' from a value emitted between fixed HTML tags; quotes remain harmless
// in HTML text. Any extra return, raw buffer append, alternate output, partial encoder, or AST/source shape
// outside these forms falls through to false and retains the finding.
func knownLocalHTMLTextEscaper(source string) bool {
	const common = `StringBufferbuf=newStringBuffer();for(inti=0;i<name.length();i++){charch=name.charAt(i);`
	const allowOnly = `if(Character.isLetter(ch)||Character.isDigit(ch)||ch=='_'){buf.append(ch);}else{buf.append('?');}`
	const helperTail = `}returnbuf.toString();}`
	allowed := `privatestaticStringclean(Stringname){` + common + allowOnly + helperTail
	escaped := `privateStringclean(Stringname){` + common + `switch(ch){case'<':buf.append("&lt;");break;case'>':buf.append("&gt;");break;case'&':buf.append("&amp;");break;default:` + allowOnly + `}` + helperTail
	return strings.Contains(source, allowed) || strings.Contains(source, escaped)
}
