package sast

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPHPRulesIgnoreCommentsAndLiterals(t *testing.T) {
	call := "e" + "val($input);"
	root := t.TempDir()
	writeFile(t, root, "Safe.php", strings.Join([]string{
		"<?php",
		"// " + call,
		"# " + call,
		"/*", call, "*/",
		"$single = '" + strings.ReplaceAll(call, "'", "\\'") + "';",
		"$double = \"" + call + "\";",
		"$escaped = \"quoted \\\\" + call + "\";",
		"$heredoc = <<<TEXT", call, "TEXT;",
		"$nowdoc = <<<'TEXT'", call, "TEXT;",
	}, "\n"))

	if hits := findingsByRule(t, root)["php:eval-usage"]; len(hits) != 0 {
		t.Fatalf("php:eval-usage findings = %d, want 0: %+v", len(hits), hits)
	}
}

func TestPHPRulesKeepExecutableCode(t *testing.T) {
	call := "e" + "val($input);"
	root := t.TempDir()
	writeFile(t, root, "unsafe.php", "<?php\n$single = '"+strings.ReplaceAll(call, "'", "\\'")+"';\n"+call+"\n")

	hits := findingsByRule(t, root)["php:eval-usage"]
	if len(hits) != 1 || hits[0].Line != 3 {
		t.Fatalf("php:eval-usage findings = %+v, want one executable hit on line 3", hits)
	}
}

func TestPHPLexContinuedQuoteClosesAtColumnZero(t *testing.T) {
	state := phpLexState{}
	state.codeOnly(`$text = "continued`)
	state.codeOnly(`";`)
	raw := `eval($_GET['code']);`
	if code := state.codeOnly(raw); strings.TrimSpace(code) == "" {
		t.Fatalf("code after continued quote remained masked: %q", code)
	}
}

func TestPHPLexHeredocAllowsTrailingDelimiter(t *testing.T) {
	state := phpLexState{}
	state.codeOnly(`$parts = [<<<TEXT`)
	state.codeOnly(`content`)
	code := state.codeOnly(`TEXT; eval($_GET['code']);`)
	if !strings.Contains(code, "eval") {
		t.Fatalf("code after heredoc delimiter remained masked: %q", code)
	}
}

func TestPHPGenericRulesRequireExecutableSink(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "safe.php", "<?php\n$text = \"eval(\" . $_GET['code'];\n$example = \"libxml_disable_entity_loader(false)\";\n")
	byRule := findingsByRule(t, root)
	for _, id := range []string{"dynamic-code-eval", "xxe-insecure-xml-parsing"} {
		if hits := byRule[id]; len(hits) != 0 {
			t.Fatalf("string-only sink emitted %s: %+v", id, hits)
		}
	}
}

func TestPHPTemplatesOnlyScanPHPTags(t *testing.T) {
	for _, name := range []string{"view.phtml", "view.php", "view.inc"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, `<script>eval($input)</script>
<div data-password="production-secret"></div>
<?php eval($input); ?>`)
			byRule := findingsByRule(t, root)
			if hits := byRule["php:eval-usage"]; len(hits) != 1 || hits[0].Line != 3 {
				t.Fatalf("PHP-tag eval findings = %+v, want line 3 only", hits)
			}
			if hits := byRule["hardcoded-credential"]; len(hits) != 0 {
				t.Fatalf("template HTML emitted credential finding: %+v", hits)
			}
		})
	}
}

func TestPHPMalformedOpenTagMakesPHPSourceTemplate(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "view.php", `<div><?phpfoo(); md5($password); ?></div>`)
	byRule := findingsByRule(t, root)
	for _, id := range []string{"php:md5-usage", "php:weak-password-hash", "weak-hash-md5"} {
		if hits := byRule[id]; len(hits) != 0 {
			t.Fatalf("malformed template emitted %s: %+v", id, hits)
		}
	}
}

func TestPHPOpenTagRequiresWhitespace(t *testing.T) {
	for _, tc := range []struct {
		line         string
		wantTagSize  int
		wantOpen     int
		wantOpenSize int
	}{
		{"<?phpfoo", 0, -1, 0},
		{"<?PHP\t", 5, 0, 5},
		{"<?php", 5, 0, 5},
		{"<?=", 3, 0, 3},
		{"<? echo", 2, 0, 2},
		{"<?xml version=\"1.0\"?>", 0, -1, 0},
		{"<?phpfoo <?php echo 1;", 0, 9, 5},
	} {
		t.Run(tc.line, func(t *testing.T) {
			if got := phpTagSizeAt(tc.line, 0); got != tc.wantTagSize {
				t.Fatalf("phpTagSizeAt(%q) = %d, want %d", tc.line, got, tc.wantTagSize)
			}
			open, size := phpOpenTag(tc.line, 0)
			if open != tc.wantOpen || size != tc.wantOpenSize {
				t.Fatalf("phpOpenTag(%q) = (%d, %d), want (%d, %d)", tc.line, open, size, tc.wantOpen, tc.wantOpenSize)
			}
		})
	}
}

func TestPHPClosingTagIgnoresMaskedContent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "unsafe.php", `<?php
$quoted = "?>";
$heredoc = <<<TEXT
?>
TEXT;
$nowdoc = <<<'TEXT'
?>
TEXT;
// ?>
<?php
/* ?> */
?>`)
	hits := findingsByRule(t, root)["php:closing-tag"]
	if len(hits) != 1 || hits[0].Line != 12 {
		t.Fatalf("closing-tag findings = %+v, want one real tag on line 12", hits)
	}
	writeFile(t, root, "view.phtml", "<?php ?>")
	if hits := findingsByRule(t, root)["php:closing-tag"]; len(hits) != 1 {
		t.Fatalf(".phtml closing tag findings = %+v, want source-only hit only", hits)
	}
}

func TestPHPClosingTagExcludedFromMultilinePHTMLPass(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "view.phtml", "<?php\nfoo(\n); ?>\n")
	if hits := findingsByRule(t, root)["php:closing-tag"]; len(hits) != 0 {
		t.Fatalf(".phtml multiline closing tag findings = %+v, want none", hits)
	}
}

func TestPHPClosingTagEndsLineComment(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "view.php", `<?php // comment ?>
<div title="unterminated>
<?php eval($input); ?>`)
	if hits := findingsByRule(t, root)["php:eval-usage"]; len(hits) != 1 || hits[0].Line != 3 {
		t.Fatalf("post-comment-tag eval findings = %+v, want line 3", hits)
	}
}

func TestPHPShortOpenTagInTemplate(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "view.phtml", "<?xml version=\"1.0\"?>\n<div password=\"production-secret\"><? EVAL($input); ?>\n")
	byRule := findingsByRule(t, root)
	for _, id := range []string{"php:short-open-tag", "php:eval-usage"} {
		if hits := byRule[id]; len(hits) != 1 || hits[0].Line != 2 {
			t.Fatalf("%s findings = %+v, want one line 2 hit", id, hits)
		}
	}
	if hits := byRule["hardcoded-credential"]; len(hits) != 0 {
		t.Fatalf("template prefix emitted generic credential finding: %+v", hits)
	}
}

func TestPHPBacktickCommandMasksContents(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "unsafe.php", "<?php\n$output = `printf '\\`'; EVAL($_GET['code']);`;\n")
	byRule := findingsByRule(t, root)
	if hits := byRule["php:backtick-command"]; len(hits) != 1 || hits[0].Line != 2 {
		t.Fatalf("backtick-command findings = %+v, want one line 2 hit", hits)
	}
	if hits := byRule["php:eval-usage"]; len(hits) != 0 {
		t.Fatalf("eval usage inside backtick command findings = %+v, want none", hits)
	}
}

func TestPHPTaglessSourceStillScans(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "bootstrap.inc", "EVAL($_GET['code']);\n")
	if hits := findingsByRule(t, root)["php:eval-usage"]; len(hits) != 1 {
		t.Fatalf("tagless PHP findings = %+v", hits)
	}
}

func TestPHPAttributeDoesNotStartComment(t *testing.T) {
	state := newPHPLexState(false, true)
	state.views("<?php")
	line := "#[Deprecated] function old(): void { eval($input); }"
	view := state.views(line)
	if !phpRuleMatches(phpPatternRule(New(), "php:eval-usage"), view.text, view.code) {
		t.Fatalf("attribute line was masked: text=%q code=%q", view.text, view.code)
	}
	root := t.TempDir()
	writeFile(t, root, "unsafe.php", "<?php\n"+line+"\n")
	if hits := findingsByRule(t, root)["php:eval-usage"]; len(hits) != 1 || hits[0].Line != 2 {
		t.Fatalf("attribute-masked eval findings = %+v", hits)
	}
}

func TestPHPIncludeExtensionIsScanned(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "bootstrap.inc", "EVAL($_GET['code']);\n")
	if hits := findingsByRule(t, root)["php:eval-usage"]; len(hits) != 1 {
		t.Fatalf(".inc PHP findings = %+v", hits)
	}
}

func TestPHPMultilineStatementMatches(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "unsafe.php", "<?php\nHEADER(\n  \"Location: \" . $_GET['next']\n);\n")
	if hits := findingsByRule(t, root)["php:header-injection"]; len(hits) != 1 || hits[0].Line != 2 {
		t.Fatalf("multiline header findings = %+v, want line 2", hits)
	}
}

func TestPHPSinkAnchorMustBeExecutable(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "safe.php", `<?php
$example = "header(" . $_GET['next'];
`)
	if hits := findingsByRule(t, root)["php:header-injection"]; len(hits) != 0 {
		t.Fatalf("string sink emitted header injection: %+v", hits)
	}
}

func TestPHPLexMaskPreservesOffsets(t *testing.T) {
	call := "e" + "val($_GET['code'])"
	state := phpLexState{}
	raw := "$text = \"" + call + "\"; " + call + "; // " + call
	masked := state.codeOnly(raw)
	if len(masked) != len(raw) {
		t.Fatalf("masked length = %d, want %d", len(masked), len(raw))
	}
	if !phpRuleMatches(phpPatternRule(New(), "php:eval-usage"), raw, masked) {
		t.Fatalf("executable PHP eval was masked: %q", masked)
	}
}

func TestPHPLineViewsRespectTagsAndLiterals(t *testing.T) {
	for _, tc := range []struct {
		name, file, source string
		want               int
	}{
		{"tagless phtml", "view.phtml", `<div>eval($input)</div>`, 0},
		{"literal tagless php", "unsafe.php", `$example = "<?php";
eval($input);`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, tc.file, tc.source)
			if got := len(findingsByRule(t, root)["php:eval-usage"]); got != tc.want {
				t.Fatalf("eval findings = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPHPStatementContinuesAfterSameLinePrefix(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "unsafe.php", "<?php\nnoop(); HEADER(\n  \"Location: \" . $_GET['next']\n);\n")
	hits := findingsByRule(t, root)["php:header-injection"]
	if len(hits) != 1 || hits[0].Line != 2 {
		t.Fatalf("header findings = %+v, want line 2", hits)
	}
}

func TestPHPSuperglobalsAreCaseSensitiveSources(t *testing.T) {
	for _, tc := range []struct {
		name, superglobal, wantSource string
	}{
		{"canonical", "$_GET", "HTTP query parameter"},
		{"lowercase", "$_get", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := "eval(" + tc.superglobal + "['code']);"
			hits, _, err := New().scanLines(context.Background(), "unsafe.php", ".php", []string{"<?php", line}, projectContext{}, map[string]bool{}, maxFindings)
			if err != nil {
				t.Fatal(err)
			}
			var evals []ports.SASTRawFinding
			for _, hit := range hits {
				if hit.RuleID == "php:eval-usage" {
					evals = append(evals, hit)
				}
			}
			hits = evals
			if len(hits) != 1 || hits[0].Source != tc.wantSource {
				t.Fatalf("%s findings = %+v, want source %q", tc.superglobal, hits, tc.wantSource)
			}
			if tc.wantSource == "unknown" && strings.Contains(hits[0].SourceEvidence, "HTTP") {
				t.Fatalf("%s evidence = %q, want no HTTP classification", tc.superglobal, hits[0].SourceEvidence)
			}
		})
	}
}

func TestPHPSecurityAnchorsAndCasefold(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "unsafe.php", `<?php
$error = "error_log(" . $password;
ErRoR_LoG($token);
HeAdEr("Location: " . $_GET['next']);
HEADER("Location: " . $_get['next']);
`)
	byRule := findingsByRule(t, root)
	if hits := byRule["php:sensitive-log"]; len(hits) != 1 || hits[0].Line != 3 {
		t.Fatalf("sensitive-log findings = %+v, want line 3", hits)
	}
	if hits := byRule["php:header-injection"]; len(hits) != 1 || hits[0].Line != 4 {
		t.Fatalf("header findings = %+v, want line 4", hits)
	}
	if hits := byRule["php:open-redirect-request"]; len(hits) != 1 || hits[0].Line != 4 {
		t.Fatalf("redirect findings = %+v, want line 4", hits)
	}
}

func TestPHPExtraExtensionsAreScanned(t *testing.T) {
	for _, ext := range []string{".inc", ".php5", ".module", ".phar"} {
		root := t.TempDir()
		writeFile(t, root, "unsafe"+ext, "eval($input);")
		if hits := findingsByRule(t, root)["php:eval-usage"]; len(hits) != 1 {
			t.Fatalf("%s findings = %+v", ext, hits)
		}
	}
}

func TestPHPSpecializedRulesOwnGenericMatches(t *testing.T) {
	a := New()
	for _, tc := range []struct {
		line       string
		owner      string
		suppressed []string
	}{
		{`$db->query("SELECT * FROM users WHERE id=" . $_GET['id']);`, "php:sql-concat", []string{"generic-sql-dynamic-execute"}},
		{`shell_exec($_GET['command']);`, "php:command-exec", []string{"generic-command-injection-sink"}},
		{`unserialize($_GET['payload']);`, "php:unserialize-untrusted", []string{"unsafe-deserialization-generic"}},
		{"e" + "val($_GET['code']);", "php:eval-usage", []string{"dynamic-code-eval"}},
		{`md5($password);`, "php:weak-password-hash", []string{"weak-hash-md5"}},
		{`file_get_contents($_GET['url']);`, "php:ssrf-file-get-contents", []string{"generic-ssrf-request-url"}},
		{`readfile($_GET['path']);`, "php:file-read-request-path", []string{"path-traversal-file-access"}},
		{`header("Location: " . $_GET['next']);`, "php:open-redirect-request", []string{"open-redirect-user-url"}},
	} {
		hits, _, err := a.scanLines(context.Background(), "Unsafe.php", ".php", []string{tc.line, `$password = "production-secret";`}, projectContext{}, map[string]bool{}, maxFindings)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, hit := range hits {
			seen[hit.RuleID] = true
		}
		if !seen[tc.owner] {
			t.Fatalf("%q missing specialized rule %q: %+v", tc.line, tc.owner, hits)
		}
		for _, generic := range tc.suppressed {
			if seen[generic] {
				t.Fatalf("%q emitted duplicate generic rule %q: %+v", tc.line, generic, hits)
			}
		}
		if !seen["hardcoded-credential"] {
			t.Fatalf("%q hid unrelated generic rule: %+v", tc.line, hits)
		}
	}
}
