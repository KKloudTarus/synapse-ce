package sast

import (
	"path/filepath"
	"testing"
)

func TestScalaRulesIgnoreStringsAndComments(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Safe.scala", `object Safe {
  val marker = "???"
  val help = "call println(value) and return"
  val nullText = "x = null;"
  val rounded = 3.14.toInt
  val widened = 3.14.toLong
  val doubled = 3.toDouble
  val parsed = parser(input: String).toInt
  val answer = 42 // replace ??? later
  /* outer ???
     /* nested println(value) */
     return null;
  */
  val text = """???
println(value)
return null;
"""
}
`)

	findings := findingsByRule(t, root)
	for _, ruleID := range []string{
		"scala:string-to-int",
		"scala:string-to-long",
		"scala:string-to-double",
		"scala:unimplemented-expression",
		"scala:println-logging",
		"scala:return-keyword",
		"scala:null-usage",
	} {
		if got := len(findings[ruleID]); got != 0 {
			t.Errorf("%s findings = %d, want 0: %+v", ruleID, got, findings[ruleID])
		}
	}
}

func TestScalaRulesKeepExecutableCodeAndAmmoniteSupport(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Main.scala", `object Main {
  def unfinished: String = ???
  def port: Int = sys.env("PORT").toInt
  def size: Long = System.getenv("MAX_SIZE").toLong
  def ratio: Double = scala.io.StdIn.readLine().toDouble
  def log(): Unit = println("started")
}
`)
	writeFile(t, root, "script.sc", `println("from ammonite")
`)

	findings := findingsByRule(t, root)
	for ruleID, want := range map[string]int{
		"scala:unimplemented-expression": 1,
		"scala:string-to-int":            1,
		"scala:string-to-long":           1,
		"scala:string-to-double":         1,
		"scala:println-logging":          2,
	} {
		if got := len(findings[ruleID]); got != want {
			t.Errorf("%s findings = %d, want %d: %+v", ruleID, got, want, findings[ruleID])
		}
	}
}

func TestScalaSQLInterpolationRequiresExecutableSink(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Queries.scala", `object Queries {
  val help = "connection.prepareStatement(s\"SELECT * FROM users WHERE id = $userId\")"
  // connection.prepareStatement(s"SELECT * FROM users WHERE id = $userId")
  val ignored = 1 /* connection.prepareStatement(s"SELECT * FROM users WHERE id = $userId") */
  val statement = connection.prepareStatement(s"SELECT * FROM users WHERE id = $userId")
}
`)
	writeFile(t, root, "Triple.scala", `object Triple {
  val statement = connection.executeQuery(s"""SELECT * FROM users WHERE id = $userId""")
}
`)

	findings := findingsByRule(t, root)["scala:sql-interpolation"]
	if len(findings) != 2 {
		t.Fatalf("SQL interpolation findings = %d, want 2: %+v", len(findings), findings)
	}
	wantLines := map[string]int{
		filepath.FromSlash("Queries.scala"): 5,
		filepath.FromSlash("Triple.scala"):  2,
	}
	for _, finding := range findings {
		if want, ok := wantLines[finding.File]; !ok || finding.Line != want {
			t.Fatalf("unexpected SQL interpolation location: %+v", finding)
		}
	}
}

func TestScalaMaskingDoesNotHideGenericRules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Secrets.scala", `object Secrets {
  val password = "production-credential-value"
}
`)
	findings := findingsByRule(t, root)["hardcoded-credential"]
	if len(findings) != 1 {
		t.Fatalf("generic credential findings = %d, want 1: %+v", len(findings), findings)
	}
}

func TestScalaLexMaskPreservesOffsets(t *testing.T) {
	state := scalaLexState{}
	raw := `val value = "???"; val result = ??? // println(value)`
	masked := state.codeOnly(raw)
	if len(masked) != len(raw) {
		t.Fatalf("masked length = %d, want %d", len(masked), len(raw))
	}
	if got := scalaRuleIDsForLine(masked); got != "scala:unimplemented-expression" {
		t.Fatalf("executable rule = %q, want scala:unimplemented-expression; masked=%q", got, masked)
	}
}

func scalaRuleIDsForLine(line string) string {
	rules := langPackRules()
	for i := range rules {
		rule := &rules[i]
		if rule.id == "scala:unimplemented-expression" && rule.re.MatchString(line) {
			return rule.id
		}
	}
	return ""
}
