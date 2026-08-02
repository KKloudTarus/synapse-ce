package sast

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestVBCodeOnly(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		code       string
		mustMask   string
		mustRetain string
	}{
		{"apostrophe comment", "Option Strict Off ' On Error Resume Next", "Option Strict Off", "On Error Resume Next", "Option Strict Off"},
		{"REM at statement boundary", "Option Strict Off : REM On Error Resume Next", "Option Strict Off :", "On Error Resume Next", "Option Strict Off :"},
		{"REM inside identifier", "Remember = True", "Remember = True", "", "Remember = True"},
		{"REM after code is not a comment", "Option Strict Off REM text", "Option Strict Off REM text", "", "REM text"},
		{"doubled quote", `Dim text = "a ""quoted"" On Error Resume Next"`, "Dim text =", "On Error Resume Next", "Dim text ="},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := vbCodeOnly(tc.line)
			if len(got) != len(tc.line) || !strings.Contains(got, tc.code) || (tc.mustMask != "" && strings.Contains(got, tc.mustMask)) || !strings.Contains(got, tc.mustRetain) {
				t.Fatalf("vbCodeOnly(%q) = %q", tc.line, got)
			}
		})
	}
}

func TestVBRuleMatchingRespectsCodeAndLiterals(t *testing.T) {
	a := New()
	cases := []struct {
		name string
		id   string
		line string
		want bool
	}{
		{"case insensitive keyword", "vb:on-error-resume-next", "oN eRrOr rEsUmE nExT", true},
		{"code in string", "vb:on-error-resume-next", `Dim text = "On Error Resume Next"`, false},
		{"code in apostrophe comment", "vb:on-error-resume-next", "' On Error Resume Next", false},
		{"code in REM comment", "vb:on-error-resume-next", "REM On Error Resume Next", false},
		{"literal assignment", "vb:hardcoded-password", `Dim password = "secret"`, true},
		{"TODO in apostrophe comment", "vb:todo-marker", "' TODO: complete", true},
		{"TODO in REM comment", "vb:todo-marker", "REM TODO: complete", true},
		{"TODO in string", "vb:todo-marker", `Dim note = "' TODO: complete"`, false},
		{"TODO in identifier", "vb:todo-marker", "todo = 1", false},
		{"TODO in REM identifier", "vb:todo-marker", "Remember = \"' TODO: complete\"", false},
		{"literal sink call", "vb:cleartext-http", `OpenUrl("http://api.example.test")`, true},
		{"literal in comment", "vb:cleartext-http", `' "http://api.example.test"`, false},
		{"literal in assignment remains valid", "vb:cleartext-http", `Dim endpoint = "http://api.example.test"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := patternRule(a, tc.id)
			if r == nil {
				t.Fatalf("missing rule %s", tc.id)
			}
			if got := vbRuleMatches(r, tc.line, vbCodeOnly(tc.line)); got != tc.want {
				t.Fatalf("vbRuleMatches(%s, %q) = %t, want %t", tc.id, tc.line, got, tc.want)
			}
		})
	}
}

func TestVBGenericRulesIgnoreCommentsButKeepExecutableLiterals(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Secrets.VB", "' password = \"notasecretvalue\"\nREM api_key = \"notasecretvalue\"\nDim password = \"strongvalue987\"\n")
	hits, err := func() ([]ports.SASTRawFinding, error) {
		hits, err := New().AnalyzeSource(context.Background(), root)
		return hits, err
	}()
	if err != nil {
		t.Fatal(err)
	}
	var credentials []ports.SASTRawFinding
	for _, hit := range hits {
		if hit.RuleID == "hardcoded-credential" {
			credentials = append(credentials, hit)
		}
	}
	if len(credentials) != 1 || credentials[0].Line != 3 {
		t.Fatalf("hardcoded credential findings = %+v, want executable assignment on line 3", credentials)
	}
}

func TestVBPrecisionBoundaries(t *testing.T) {
	cases := []struct {
		name string
		id   string
		line string
		want bool
	}{
		{"Process.Start variable single argument", "vb:process-start-var", "Process.Start(command)", true},
		{"Process.Start fixed executable two arguments", "vb:process-start-var", `Process.Start("dotnet", "--info")`, false},
		{"Process.Start variable executable two arguments", "vb:process-start-var", `Process.Start(command, "--info")`, true},
		{"ordinary Async Sub event handler", "vb:async-sub-api", "Private Async Sub Save_Click(sender As Object, e As EventArgs) Handles Save.Click", false},
		{"non-event Async Sub", "vb:async-sub-api", "Private Async Sub RefreshAsync()", true},
		{"floating assignment", "vb:floating-point-equality", "ratio = 0.1", false},
		{"floating condition", "vb:floating-point-equality", "If ratio = 0.1 Then", true},
		{"identifier contains key", "vb:hardcoded-crypto-key", `Dim monkey = "banana"`, false},
		{"key identifier", "vb:hardcoded-crypto-key", `Dim encryptionKey = "secret"`, true},
		{"identifier contains iv", "vb:static-iv", `Dim arrival = "station"`, false},
		{"IV identifier", "vb:static-iv", `Dim iv = "static"`, true},
		{"unrelated result receiver", "vb:task-result", "order.Result", false},
		{"async call result receiver", "vb:task-result", "LoadAsync().Result", true},
		{"unrelated abort receiver", "vb:thread-abort", "worker.Abort()", false},
		{"thread receiver", "vb:thread-abort", "workerThread.Abort()", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := patternRule(New(), tc.id)
			if r == nil {
				t.Fatalf("missing rule %s", tc.id)
			}
			if got := vbRuleMatches(r, tc.line, vbCodeOnly(tc.line)); got != tc.want {
				t.Fatalf("vbRuleMatches(%s, %q) = %t, want %t", tc.id, tc.line, got, tc.want)
			}
		})
	}
}

func TestVBExtensionGate(t *testing.T) {
	for _, ext := range []string{".vbs", ".bas", ".vbhtml"} {
		t.Run(ext, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "sample"+ext)
			if err := os.WriteFile(path, []byte("On Error Resume Next\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			hits, err := func() ([]ports.SASTRawFinding, error) {
				hits, err := New().AnalyzeSource(context.Background(), root)
				return hits, err
			}()
			if err != nil {
				t.Fatal(err)
			}
			if hasSASTRule(hits, "vb:on-error-resume-next") {
				t.Fatalf("VB rule fired for %s: %+v", ext, hits)
			}
		})
	}
}

func TestVBEmptyCatchContext(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
		line int
	}{
		{"empty", "Try\nCatch\nEnd Try", true, 2},
		{"comment only", "Try\nCatch\n    ' ignored\n    REM ignored\nEnd Try", true, 2},
		{"non-empty", "Try\nCatch\n    Report(ex)\nEnd Try", false, 0},
		{"sibling catch", "Try\nCatch\nCatch ex As IOException\n    Report(ex)\nEnd Try", true, 2},
		{"finally", "Try\nCatch\nFinally\n    CleanUp()\nEnd Try", true, 2},
		{"nested try", "Try\nCatch\n    Try\n        Work()\n    Catch\n    End Try\n    Report(ex)\nEnd Try", true, 5},
		{"nested non-empty catch", "Try\nCatch\n    Try\n    Catch\n        Report(ex)\n    End Try\n    Report(ex)\nEnd Try", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := analyzeVB(t, tc.src)
			got := hasSASTRule(hits, "vb:empty-catch")
			if got != tc.want {
				t.Fatalf("empty-catch = %t, want %t: %+v", got, tc.want, hits)
			}
			if tc.want {
				lines := findingLines(hits, "vb:empty-catch")
				if len(lines) != 1 || lines[0] != tc.line {
					t.Fatalf("empty-catch lines = %v, want [%d]", lines, tc.line)
				}
			}
		})
	}
}

func TestVBIDisposableContext(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"undisposed", "Sub Read()\n    Dim reader = New StreamReader(path)\nEnd Sub", true},
		{"dispose receiver", "Sub Read()\n    Dim reader = New StreamReader(path)\n    reader.Dispose()\nEnd Sub", false},
		{"Call dispose receiver", "Sub Read()\n    Dim reader = New StreamReader(path)\n    Call reader.Dispose()\nEnd Sub", false},
		{"If Then dispose receiver", "Sub Read()\n    Dim reader = New StreamReader(path)\n    If ready Then reader.Dispose()\nEnd Sub", false},
		{"colon dispose receiver", "Sub Read()\n    Dim reader = New StreamReader(path) : reader.Dispose()\nEnd Sub", false},
		{"close receiver", "Sub Read()\n    Dim reader = New StreamReader(path)\n    reader.Close()\nEnd Sub", false},
		{"other receiver", "Sub Read()\n    Dim reader = New StreamReader(path)\n    otherReader.Dispose()\nEnd Sub", true},
		{"using", "Sub Read()\n    Using reader = New StreamReader(path)\n    End Using\nEnd Sub", false},
		{"member boundary", "Sub First()\n    Dim reader = New StreamReader(path)\nEnd Sub\nSub Second()\n    reader.Dispose()\nEnd Sub", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := analyzeVB(t, tc.src)
			got := hasSASTRule(hits, "vb:idisposable-not-disposed")
			if got != tc.want {
				t.Fatalf("idisposable finding = %t, want %t: %+v", got, tc.want, hits)
			}
			if tc.want && findingLine(hits, "vb:idisposable-not-disposed") != 2 {
				t.Fatalf("idisposable line = %d, want 2", findingLine(hits, "vb:idisposable-not-disposed"))
			}
		})
	}
}

func analyzeVB(t *testing.T, source string) []ports.SASTRawFinding {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Sample.vb"), []byte(source+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hits, err := func() ([]ports.SASTRawFinding, error) {
		hits, err := New().AnalyzeSource(context.Background(), root)
		return hits, err
	}()
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

func findingLine(hits []ports.SASTRawFinding, id string) int {
	lines := findingLines(hits, id)
	if len(lines) == 0 {
		return 0
	}
	return lines[0]
}

func findingLines(hits []ports.SASTRawFinding, id string) []int {
	var lines []int
	for _, hit := range hits {
		if hit.RuleID == id {
			lines = append(lines, hit.Line)
		}
	}
	return lines
}
