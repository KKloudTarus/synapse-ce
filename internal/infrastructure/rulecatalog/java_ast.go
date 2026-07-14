package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type javaASTRuleSpec struct {
	key, name, cwe, compliant, noncompliant, remediation, description string
	type_                                                             rule.Type
	quality                                                           rule.Quality
	severity                                                          shared.Severity
}

// javaASTRules are the Java structural rules emitted by the synapse-ast tree-sitter sidecar
// (internal/infrastructure/tools/astwalk). They catch multi-line/structural issues a line regex cannot.
func javaASTRules() []rule.Rule {
	specs := []javaASTRuleSpec{
		{"java-ast-empty-method", "Empty method body", "", "void handle() {\n    process(event);\n}", "void handle() {}", "Implement the method, or if it is intentionally empty, add a comment explaining why.", "an empty non-abstract method body", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"java-ast-missing-switch-default", "switch without a default", "CWE-478", "switch (state) {\n    case OPEN: open(); break;\n    default: throw new IllegalStateException();\n}", "switch (state) {\n    case OPEN: open(); break;\n}", "Add a default branch (even one that throws) so unhandled values are not silently ignored.", "a switch statement with no default branch", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"java-ast-nested-try", "Nested try statement", "", "try {\n    step1();\n    step2();\n} catch (IOException e) {\n    log.warn(\"failed\", e);\n}", "try {\n    try {\n        step1();\n    } finally {\n        cleanup();\n    }\n} catch (IOException e) {\n    log.warn(\"failed\", e);\n}", "Extract the inner try into its own method to flatten the control flow.", "a try statement nested directly inside another try", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"java-ast-empty-if-block", "Empty if block", "", "if (ready) {\n    start();\n}", "if (ready) {\n}", "Remove the empty if, or add the intended body.", "an if statement with an empty body", rule.TypeBug, rule.QualityReliability, shared.SeverityLow},
		{"java-ast-collapsible-if", "Collapsible if statement", "", "if (a && b) {\n    run();\n}", "if (a) {\n    if (b) {\n        run();\n    }\n}", "Combine the two conditions with && into a single if.", "an if whose only statement is another if with no else", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
	}
	rules := make([]rule.Rule, 0, len(specs))
	for _, s := range specs {
		rules = append(rules, rule.Rule{
			Key: rule.Key(s.key), Name: s.name, Language: "Java", Type: s.type_, Qualities: []rule.Quality{s.quality}, DefaultSeverity: s.severity,
			Tags: []string{"java", "ast"}, CWE: optionalCWE(s.cwe), OWASP: []string{},
			Description: "Detects " + s.description + " in Java source.",
			Rationale:   "This rule reports a Java structure that reduces reliability or maintainability, detected on the syntax tree.\n\nSource: https://docs.oracle.com/javase/specs/",
			Remediation: s.remediation, CompliantExample: s.compliant, NoncompliantExample: s.noncompliant, RemediationEffort: 15, Detection: rule.DetectionAST,
		})
	}
	return rules
}
