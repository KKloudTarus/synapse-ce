package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type phpASTRuleSpec struct {
	key, name, cwe, compliant, noncompliant, remediation, description string
	type_                                                             rule.Type
	quality                                                           rule.Quality
	severity                                                          shared.Severity
}

// phpASTRules are the PHP structural rules emitted by the synapse-ast tree-sitter sidecar
// (internal/infrastructure/tools/astwalk). They catch multi-line/structural issues a line regex
// cannot, and use the `php-ast-` key prefix to stay distinct from the generated `php:` pattern pack.
func phpASTRules() []rule.Rule {
	specs := []phpASTRuleSpec{
		{"php-ast-empty-catch", "Empty catch block", "CWE-390",
			"try {\n    work();\n} catch (Throwable $e) {\n    $this->log->warning($e->getMessage());\n}",
			"try {\n    work();\n} catch (Throwable $e) {\n}",
			"Handle the expected exception, or at least log it; do not swallow the failure silently.",
			"a catch clause with an empty body",
			rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"php-ast-missing-switch-default", "switch without a default", "CWE-478",
			"switch ($state) {\n    case 'open': open(); break;\n    default: throw new RuntimeException();\n}",
			"switch ($state) {\n    case 'open': open(); break;\n}",
			"Add a default case (even one that throws) so unhandled values are not silently ignored.",
			"a switch statement with no default case",
			rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
	}
	rules := make([]rule.Rule, 0, len(specs))
	for _, s := range specs {
		rules = append(rules, rule.Rule{
			Key: rule.Key(s.key), Name: s.name, Language: "PHP", Type: s.type_, Qualities: []rule.Quality{s.quality}, DefaultSeverity: s.severity,
			Tags: []string{"php", "ast"}, CWE: optionalCWE(s.cwe), OWASP: []string{},
			Description: "Detects " + s.description + " in PHP source.",
			Rationale:   "This rule reports a PHP structure that reduces reliability or maintainability, detected on the syntax tree.\n\nSource: https://www.php.net/manual/en/",
			Remediation: s.remediation, CompliantExample: s.compliant, NoncompliantExample: s.noncompliant, RemediationEffort: 15, Detection: rule.DetectionAST,
		})
	}
	return rules
}
