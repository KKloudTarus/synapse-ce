package codeanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAnalyzerNotebookRulesAndPythonReuse(t *testing.T) {
	root := t.TempDir()
	bearer := strings.Join([]string{"Bearer", strings.Repeat("a", 26)}, " ")
	data := `{
		"metadata":{"kernelspec":{"name":"python3","language":"python"}},
		"cells":[
			{"cell_type":"markdown","source":"token = 'not-a-real-secret'"},
			{"cell_type":"code","source":"value = value\n!pip install requests\n!cat $path","execution_count":2,"outputs":[{"output_type":"stream","text":"` + bearer + `"}]},
			{"cell_type":"code","source":"pass","execution_count":1,"outputs":[]}
		]
	}`
	writeNotebook(t, root, data)
	findings := notebookAnalysis(t, root)
	got := ruleFiles(findings)
	for _, ruleID := range []string{"reliability-self-assignment", "ipynb-unpinned-cell-dependency", "ipynb-shell-magic-injection", "ipynb-bearer-token-in-output", "ipynb-secret-in-output", "ipynb-non-linear-execution"} {
		if _, ok := got[ruleID]; !ok {
			t.Errorf("missing %s in %+v", ruleID, findings)
		}
	}
	if got["reliability-self-assignment"] != "analysis.ipynb#cell-2" {
		t.Errorf("Python finding location = %q", got["reliability-self-assignment"])
	}
	if _, ok := got["ipynb-hardcoded-credential"]; ok {
		t.Errorf("markdown cell produced credential finding: %+v", findings)
	}
}

func TestAnalyzerNotebookRuleCorpus(t *testing.T) {
	aws := "ASIA" + "ABCDEFGHIJKLMNOP"
	bearer := strings.Join([]string{"Bearer", strings.Repeat("a", 26)}, " ")
	credential := strings.Repeat("a", 15)
	cases := []struct {
		name, notebook, rule string
	}{
		{"credential", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","source":"api_key = '` + credential + `'"}]}`, "ipynb-hardcoded-credential"},
		{"private-key", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"stream","text":"-----BEGIN PRIVATE KEY-----"}]}]}`, "ipynb-private-key-in-output"},
		{"aws-rich-output", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"execute_result","data":{"text/plain":"` + aws + `"}}]}]}`, "ipynb-aws-access-key-in-output"},
		{"password-url", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"stream","text":"https://user:` + credential + `@example.com"}]}]}`, "ipynb-password-url-in-output"},
		{"script", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"display_data","data":{"text/html":"<script>document.write(value)</script>"}}]}]}`, "ipynb-html-script-output"},
		{"path", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"error","traceback":["Traceback /home/alice/private.py"]}]}]}`, "ipynb-traceback-sensitive-path"},
		{"system", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","source":"%system cat ${path}"}]}`, "ipynb-system-magic-injection"},
		{"bash", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","source":"%%bash\ncat $path"}]}`, "ipynb-bash-cell-magic-injection"},
		{"stale", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","execution_count":null,"outputs":[{"output_type":"stream","text":"old"}]}]}`, "ipynb-stale-output"},
		{"missing-kernel", `{"metadata":{"kernelspec":{}},"cells":[]}`, "ipynb-missing-kernelspec"},
		{"pinned-mixed", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","source":"!pip install requests==2.31 urllib3"}]}`, "ipynb-unpinned-cell-dependency"},
		{"json-output", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"execute_result","data":{"application/json":{"token":"` + bearer + `"}}}]}]}`, "ipynb-bearer-token-in-output"},
		{"prefixed-credential", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","source":"client_secret = '` + credential + `'"}]}`, "ipynb-hardcoded-credential"},
		{"conda-range", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","source":"%conda install numpy>=1.26"}]}`, "ipynb-unpinned-cell-dependency"},
		{"stale-image", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","execution_count":null,"outputs":[{"output_type":"display_data","data":{"image/png":"abc"}}]}]}`, "ipynb-stale-output"},
		{"traceback-path", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"error","traceback":["Traceback /home/alice/private.py"]}]}]}`, "ipynb-traceback-sensitive-path"},
		{"json-credential", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"execute_result","data":{"application/json":{"client_secret":"` + credential + `"}}}]}]}`, "ipynb-secret-in-output"},
		{"encrypted-key", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"stream","text":"-----BEGIN ENCRYPTED PRIVATE KEY-----"}]}]}`, "ipynb-private-key-in-output"},
		{"pgp-key", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"stream","text":"-----BEGIN PGP PRIVATE KEY BLOCK-----"}]}]}`, "ipynb-private-key-in-output"},
		{"markdown-token", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"display_data","data":{"text/markdown":"` + bearer + `"}}]}]}`, "ipynb-bearer-token-in-output"},
		{"svg-script", `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"display_data","data":{"image/svg+xml":"<script>document.write(value)</script>"}}]}]}`, "ipynb-html-script-output"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeNotebook(t, root, tc.notebook)
			if _, ok := ruleFiles(notebookAnalysis(t, root))[tc.rule]; !ok {
				t.Fatalf("missing %s", tc.rule)
			}
		})
	}
}

func TestAnalyzerNotebookCompliantCases(t *testing.T) {
	root := t.TempDir()
	writeNotebook(t, root, `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","source":"!pip install requests==2.31.0\n!cat /tmp/file\n%system ls /tmp\n%%bash\necho ready","execution_count":1,"outputs":[{"output_type":"stream","text":"completed"}]}]}`)
	got := ruleFiles(notebookAnalysis(t, root))
	for _, ruleID := range []string{
		"ipynb-secret-in-output", "ipynb-hardcoded-credential", "ipynb-private-key-in-output", "ipynb-aws-access-key-in-output", "ipynb-bearer-token-in-output", "ipynb-password-url-in-output", "ipynb-html-script-output", "ipynb-traceback-sensitive-path",
		"ipynb-shell-magic-injection", "ipynb-system-magic-injection", "ipynb-bash-cell-magic-injection",
		"ipynb-non-linear-execution", "ipynb-unpinned-cell-dependency", "ipynb-stale-output", "ipynb-missing-kernelspec",
	} {
		if _, ok := got[ruleID]; ok {
			t.Errorf("unexpected compliant finding %s: %+v", ruleID, got)
		}
	}
}

func TestAnalyzerNotebookFlagsDuplicateExecutionCount(t *testing.T) {
	root := t.TempDir()
	writeNotebook(t, root, `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","execution_count":1},{"cell_type":"code","execution_count":1}]}`)
	if _, ok := ruleFiles(notebookAnalysis(t, root))["ipynb-non-linear-execution"]; !ok {
		t.Fatal("duplicate execution count was not flagged")
	}
}

func TestAnalyzerNotebookDoesNotFlagPathWithoutTraceback(t *testing.T) {
	root := t.TempDir()
	writeNotebook(t, root, `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"stream","text":"saved /home/alice/data.csv"}]}]}`)
	if _, ok := ruleFiles(notebookAnalysis(t, root))["ipynb-traceback-sensitive-path"]; ok {
		t.Fatal("path without traceback was flagged")
	}
}

func TestAnalyzerNotebookOnlyChecksPathsInsideTracebacks(t *testing.T) {
	root := t.TempDir()
	writeNotebook(t, root, `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"error","traceback":["Traceback: failed"]},{"output_type":"stream","text":"saved /home/alice/data.csv"}]}]}`)
	if _, ok := ruleFiles(notebookAnalysis(t, root))["ipynb-traceback-sensitive-path"]; ok {
		t.Fatal("non-traceback path was attributed to a separate traceback")
	}
}

func TestAnalyzerNotebookDoesNotTreatRoutineScriptsAsInjection(t *testing.T) {
	for _, output := range []string{
		`<scripture>text</scripture>`,
		`<script>renderChart()</script>`,
		`<script src="https://cdn.plot.ly/plotly.js"></script><script>Plotly.newPlot("chart", data)</script>`,
		`<script>Bokeh.embed.embed_item(item, "plot")</script>`,
	} {
		t.Run(output, func(t *testing.T) {
			root := t.TempDir()
			writeNotebook(t, root, `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"display_data","data":{"text/html":`+strconv.Quote(output)+`}}]}]}`)
			if _, ok := ruleFiles(notebookAnalysis(t, root))["ipynb-html-script-output"]; ok {
				t.Fatalf("routine script output was flagged: %s", output)
			}
		})
	}
}

func TestAnalyzerNotebookFlagsScriptEventHandler(t *testing.T) {
	root := t.TempDir()
	writeNotebook(t, root, `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"display_data","data":{"text/html":"<script onload=\"run()\"></script>"}}]}]}`)
	if _, ok := ruleFiles(notebookAnalysis(t, root))["ipynb-html-script-output"]; !ok {
		t.Fatal("script event handler was not flagged")
	}
}

func TestAnalyzerNotebookIgnoresRoutineTracebackPaths(t *testing.T) {
	for _, path := range []string{
		`/home/alice/.venv/lib/python3.12/site-packages/pandas/core/frame.py`,
		`/usr/lib/python3/dist-packages/numpy/__init__.py`,
		`C:\Users\alice\venv\Lib\site-packages\flask\app.py`,
	} {
		t.Run(path, func(t *testing.T) {
			root := t.TempDir()
			writeNotebook(t, root, `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"error","traceback":["Traceback: `+path+`"]}]}]}`)
			if _, ok := ruleFiles(notebookAnalysis(t, root))["ipynb-traceback-sensitive-path"]; ok {
				t.Fatalf("routine traceback path was flagged: %s", path)
			}
		})
	}
}

func TestAnalyzerNotebookFlagsWindowsProjectTracebackPath(t *testing.T) {
	root := t.TempDir()
	writeNotebook(t, root, `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","outputs":[{"output_type":"error","traceback":["Traceback: C:\\Users\\alice\\project\\private.py"]}]}]}`)
	if _, ok := ruleFiles(notebookAnalysis(t, root))["ipynb-traceback-sensitive-path"]; !ok {
		t.Fatal("Windows project traceback path was not flagged")
	}
}

func TestAnalyzerNotebookCapsFindings(t *testing.T) {
	root := t.TempDir()
	cell := `{"cell_type":"code","source":"api_key = '` + strings.Repeat("a", 15) + `'"}`
	writeNotebook(t, root, `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[`+strings.TrimSuffix(strings.Repeat(cell+",", maxFindings+1), ",")+`]}`)
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != maxFindings {
		t.Fatalf("finding count = %d, want cap %d", len(findings), maxFindings)
	}
}

func TestAnalyzerNotebookAcceptsExactCondaPins(t *testing.T) {
	root := t.TempDir()
	writeNotebook(t, root, `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","source":"%conda install numpy==1.26.4"}]}`)
	if _, ok := ruleFiles(notebookAnalysis(t, root))["ipynb-unpinned-cell-dependency"]; ok {
		t.Fatal("exact conda pin was flagged")
	}
}

func TestAnalyzerNotebookAcceptsPinnedPipOptionsAndExtras(t *testing.T) {
	root := t.TempDir()
	writeNotebook(t, root, `{"metadata":{"kernelspec":{"name":"python3","language":"python"}},"cells":[{"cell_type":"code","source":"!pip install --index-url https://pypi.org/simple requests[socks]==2.31.0"}]}`)
	if _, ok := ruleFiles(notebookAnalysis(t, root))["ipynb-unpinned-cell-dependency"]; ok {
		t.Fatal("pinned pip install was flagged")
	}
}

func writeNotebook(t *testing.T, root, data string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "analysis.ipynb"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func notebookAnalysis(t *testing.T, root string) []struct{ RuleID, File string } {
	t.Helper()
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	out := make([]struct{ RuleID, File string }, len(findings))
	for i, finding := range findings {
		out[i] = struct{ RuleID, File string }{finding.RuleID, finding.File}
	}
	return out
}

func ruleFiles(findings []struct{ RuleID, File string }) map[string]string {
	got := map[string]string{}
	for _, finding := range findings {
		got[finding.RuleID] = finding.File
	}
	return got
}
