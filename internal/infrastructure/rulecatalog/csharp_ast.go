package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type csharpASTRuleSpec struct {
	key, name, cwe, compliant, noncompliant, remediation, description string
	type_                                                             rule.Type
	quality                                                           rule.Quality
	severity                                                          shared.Severity
}

// csharpASTRules are the C# structural rules emitted by the synapse-ast tree-sitter sidecar
// (internal/infrastructure/tools/astwalk). They catch multi-line/structural issues a line regex cannot.
func csharpASTRules() []rule.Rule {
	specs := []csharpASTRuleSpec{
		{"csharp-ast-empty-catch", "Empty catch block", "CWE-390",
			"try {\n    Work();\n} catch (IOException e) {\n    _log.Warn(e, \"failed\");\n}",
			"try {\n    Work();\n} catch (Exception e) {\n}",
			"Handle the expected exception, or at least log it; do not swallow the failure silently.",
			"a catch clause with an empty body",
			rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"csharp-ast-missing-switch-default", "switch without a default", "CWE-478",
			"switch (state) {\n    case State.Open: Open(); break;\n    default: throw new InvalidOperationException();\n}",
			"switch (state) {\n    case State.Open: Open(); break;\n}",
			"Add a default section (even one that throws) so unhandled values are not silently ignored.",
			"a switch statement with no default section",
			rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
	}
	rules := make([]rule.Rule, 0, len(specs))
	for _, s := range specs {
		rules = append(rules, rule.Rule{
			Key: rule.Key(s.key), Name: s.name, Language: "C#", Type: s.type_, Qualities: []rule.Quality{s.quality}, DefaultSeverity: s.severity,
			Tags: []string{"csharp", "ast"}, CWE: optionalCWE(s.cwe), OWASP: []string{},
			Description: "Detects " + s.description + " in C# source.",
			Rationale:   "This rule reports a C# structure that reduces reliability or maintainability, detected on the syntax tree.\n\nSource: https://learn.microsoft.com/en-us/dotnet/csharp/",
			Remediation: s.remediation, CompliantExample: s.compliant, NoncompliantExample: s.noncompliant, RemediationEffort: 15, Detection: rule.DetectionAST,
		})
	}
	return rules
}
