package sast

import (
	"path/filepath"
	"testing"
)

func TestRubyRulesIgnoreCommentsStringsAndLiterals(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "safe.rb", `class Safe
  HELP = "skip_before_action :verify_authenticity_token"
  QUERY = 'User.where("email = #{params[:email]}")'
  COMMAND = %q{system(params[:command])}
  REGEX = %r{params[:pattern]}
  DOC_PATTERN = /skip_before_action :verify_authenticity_token/
  # params.permit!
  # Digest::MD5.hexdigest(payload)
=begin
  redirect_to params[:next]
  eval(params[:expression])
=end
  DOCUMENT = <<~TEXT
    YAML.load(params[:payload])
    OpenSSL::SSL::VERIFY_NONE
  TEXT

  def value
    42 # rescue nil
  end
end
`)

	findings := findingsByRule(t, root)
	for _, ruleID := range []string{
		"rb:skip-csrf",
		"rb:sql-interpolation",
		"rb:command-tainted-argument",
		"rb:permit-all-params",
		"rb:weak-hash",
		"rb:open-redirect",
		"rb:eval-request-data",
		"rb:unsafe-yaml-load",
		"rb:ssl-verify-none",
		"rb:rescue-nil",
	} {
		if got := len(findings[ruleID]); got != 0 {
			t.Errorf("%s findings = %d, want 0: %+v", ruleID, got, findings[ruleID])
		}
	}
}

func TestRubyRulesDetectRepresentativeFamilies(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "users_controller.rb", `class UsersController < ApplicationController
  skip_before_action :verify_authenticity_token
  skip_before_action :authenticate_user!

  def create
    user = User.create(params[:user])
    redirect_to params[:next]
  end

  def preview
    @content = params[:content].html_safe
  end

  def run
    system(params[:command])
  end
end

checksum = Digest::MD5.hexdigest(payload)
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
$registry = {}
`)

	findings := findingsByRule(t, root)
	for ruleID, want := range map[string]int{
		"rb:skip-csrf":                1,
		"rb:skip-authentication":      1,
		"rb:mass-assignment":          1,
		"rb:open-redirect":            1,
		"rb:xss-html-safe":            1,
		"rb:command-tainted-argument": 1,
		"rb:weak-hash":                1,
		"rb:ssl-verify-none":          1,
		"rb:global-variable":          1,
	} {
		if got := len(findings[ruleID]); got != want {
			t.Errorf("%s findings = %d, want %d: %+v", ruleID, got, want, findings[ruleID])
		}
	}
}

func TestRubyInterpolatedSinkRequiresExecutableCode(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "queries.rb", `class Queries
  HELP = "User.where(\"email = '#{params[:email]}'\")"
  # User.where("email = '#{params[:email]}'")
  def lookup
    User.where("email = '#{params[:email]}'")
  end

  def command
    system("convert #{params[:file]}")
  end
end
`)

	findings := findingsByRule(t, root)
	if got := len(findings["rb:sql-interpolation"]); got != 1 {
		t.Fatalf("SQL interpolation findings = %d, want 1: %+v", got, findings["rb:sql-interpolation"])
	}
	if got := len(findings["rb:command-injection"]); got != 1 {
		t.Fatalf("command injection findings = %d, want 1: %+v", got, findings["rb:command-injection"])
	}
	if findings["rb:sql-interpolation"][0].Line != 5 {
		t.Fatalf("SQL finding line = %d, want 5", findings["rb:sql-interpolation"][0].Line)
	}
	if findings["rb:command-injection"][0].Line != 9 {
		t.Fatalf("command finding line = %d, want 9", findings["rb:command-injection"][0].Line)
	}
}

func TestRubyCommandInjectionCoversLiteralCommandForms(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "shell.rb", "shell = \x60convert #{params[:file]}\x60\n")
	writeFile(t, root, "percent.rb", "percent = %x(curl #{params[:url]})\n")
	writeFile(t, root, "safe.rb", "safe = %x(echo safe) # \x60echo #{params[:url]}\x60\n")

	findings := findingsByRule(t, root)["rb:command-injection"]
	if len(findings) != 2 {
		t.Fatalf("command literal findings = %d, want 2: %+v", len(findings), findings)
	}
	for _, finding := range findings {
		if finding.Line != 1 || (finding.File != "shell.rb" && finding.File != "percent.rb") {
			t.Fatalf("unexpected command literal finding: %+v", finding)
		}
	}
}

func TestRubyERBOnlyScansExecutableTags(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "show.html.erb", "<p>params.permit!</p>\n<%# params.permit! %>\n<%= params.permit! %>\n")
	findings := findingsByRule(t, root)["rb:permit-all-params"]
	if len(findings) != 1 || findings[0].Line != 3 {
		t.Fatalf("ERB findings = %+v, want one executable-tag finding on line 3", findings)
	}
}

func TestRubyExtensionlessDSLFilesAreScanned(t *testing.T) {

	root := t.TempDir()
	writeFile(t, root, "Rakefile", `task :legacy do
  File.exists?("config.yml")
end
`)
	writeFile(t, root, "Gemfile", `source URI.escape(registry_url)
`)

	findings := findingsByRule(t, root)
	if got := len(findings["rb:file-exists-deprecated"]); got != 1 {
		t.Fatalf("Rakefile findings = %d, want 1: %+v", got, findings["rb:file-exists-deprecated"])
	}
	if got := len(findings["rb:uri-escape-deprecated"]); got != 1 {
		t.Fatalf("Gemfile findings = %d, want 1: %+v", got, findings["rb:uri-escape-deprecated"])
	}
}

func TestRubyMaskingDoesNotHideGenericRules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "secrets.rb", `class Secrets
  PASSWORD = "production-credential-value"
end
`)
	findings := findingsByRule(t, root)["hardcoded-credential"]
	if len(findings) != 1 {
		t.Fatalf("generic credential findings = %d, want 1: %+v", len(findings), findings)
	}
}

func TestRubyMultilineLiteralsAndEmbeddedDocsRemainMasked(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "literals.rb", "MESSAGE = \"safe\nparams.permit!\n\"\n=begin\n=ending\nparams.permit!\n=end\nDOC = <<sql\nparams.permit!\nsql\n")
	if findings := findingsByRule(t, root)["rb:permit-all-params"]; len(findings) != 0 {
		t.Fatalf("masked multiline literal findings = %+v, want none", findings)
	}
}

func TestRubyAppendWithoutWhitespaceIsNotAHeredoc(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "append.rb", "items<<value\nparams.permit!\n")
	if findings := findingsByRule(t, root)["rb:permit-all-params"]; len(findings) != 1 || findings[0].Line != 2 {
		t.Fatalf("append operator findings = %+v, want one finding on line 2", findings)
	}
}

func TestRubyLexMaskPreservesOffsetsAndAppendOperator(t *testing.T) {
	state := rubyLexState{}
	raw := `items << value; marker = "params.permit!"; params.permit! # redirect_to params[:next]`
	masked := state.codeOnly(raw)
	if len(masked) != len(raw) {
		t.Fatalf("masked length = %d, want %d", len(masked), len(raw))
	}
	if !stringsContainsAt(masked, "items << value", 0) {
		t.Fatalf("append operator was mistaken for heredoc: %q", masked)
	}
	if got := rubyRuleIDsForLine(raw, masked); got != "rb:permit-all-params" {
		t.Fatalf("executable rule = %q, want rb:permit-all-params; masked=%q", got, masked)
	}
}

func TestRubySourceExtension(t *testing.T) {
	for path, want := range map[string]string{
		"app/model.rb":        ".rb",
		"tasks/release.rake":  ".rake",
		"views/show.html.erb": ".erb",
		"Gemfile":             ".rb",
		"Rakefile":            ".rb",
		"README":              "",
	} {
		if got := sastSourceExt(filepath.FromSlash(path)); got != want {
			t.Errorf("sastSourceExt(%q) = %q, want %q", path, got, want)
		}
	}
}

func rubyRuleIDsForLine(raw, code string) string {
	rules := langPackRules()
	for i := range rules {
		rule := &rules[i]
		if rule.id == "rb:permit-all-params" && rubyRuleMatches(rule, raw, code) {
			return rule.id
		}
	}
	return ""
}

func stringsContainsAt(value, fragment string, at int) bool {
	return at >= 0 && at+len(fragment) <= len(value) && value[at:at+len(fragment)] == fragment
}
