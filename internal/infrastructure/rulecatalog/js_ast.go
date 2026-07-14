package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// jsASTRules are the JavaScript structural rules emitted by the synapse-ast tree-sitter sidecar
// (internal/infrastructure/tools/astwalk). They catch structural issues a line regex cannot.
func jsASTRules() []rule.Rule {
	specs := []javaASTRuleSpec{
		{"js-ast-empty-function", "Empty function body", "", "function handle(e) {\n    process(e);\n}", "function handle(e) {}", "Implement the function, or document why it is intentionally empty.", "an empty named function body", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"js-ast-missing-switch-default", "switch without a default", "CWE-478", "switch (state) {\n    case 1: open(); break;\n    default: fail();\n}", "switch (state) {\n    case 1: open(); break;\n}", "Add a default case so unhandled values are not silently ignored.", "a switch statement with no default case", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"js-ast-too-many-params", "Function has too many parameters", "", "function configure(options) {\n    apply(options);\n}", "function configure(host, port, timeout, tls, user, pass, retries, backoff) {\n    connect(host, port);\n}", "Pass an options object instead of a long parameter list.", "a function declared with more than seven parameters", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"js-ast-long-function", "Overly long function", "", "function build() {\n    return assemble(parts);\n}", "function build() {\n    // more than fifty sequential statements\n    return result;\n}", "Split the function into smaller, focused functions.", "a function with an excessive number of statements", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"js-ast-too-many-returns", "Function has too many return statements", "", "function classify(x) {\n    return lookup(x);\n}", "function classify(x) {\n    if (x === 1) return 1;\n    if (x === 2) return 2;\n    if (x === 3) return 3;\n    if (x === 4) return 4;\n    if (x === 5) return 5;\n    if (x === 6) return 6;\n    return 0;\n}", "Reduce the number of exit points; use a lookup or a single result variable.", "a function with many return statements", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"js-ast-large-class", "Class has too many methods", "", "class Small {\n    a() {}\n    b() {}\n}", "class God {\n    // more than twenty methods\n    a() {}\n    b() {}\n}", "Split the class along its distinct responsibilities.", "a class declaring an excessive number of methods", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"js-ast-identical-branches", "if and else branches are identical", "", "if (found) {\n    save();\n} else {\n    discard();\n}", "if (found) {\n    save();\n} else {\n    save();\n}", "Remove the redundant branch, or fix the branch that is wrong.", "an if whose then and else blocks are identical", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"js-ast-return-in-finally", "return inside finally", "", "try {\n    return compute();\n} finally {\n    cleanup();\n}", "try {\n    return compute();\n} finally {\n    return fallback();\n}", "Do not return from finally; it discards the try/catch result or exception.", "a return statement inside a finally block", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"js-ast-deep-nesting", "Deeply nested control flow", "", "function handle(x) {\n    if (!x) return;\n    process(x);\n}", "function handle(x) {\n    if (a) {\n        for (const i of items) {\n            while (b) {\n                try {\n                    if (c) run();\n                } finally { cleanup(); }\n            }\n        }\n    }\n}", "Flatten the logic with guard clauses and by extracting nested blocks into functions.", "control flow nested more than four levels deep", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityMedium},
		{"js-ast-nested-loop", "Deeply nested loops", "", "for (const row of grid) {\n    process(row);\n}", "for (let i = 0; i < n; i++) {\n    for (let j = 0; j < n; j++) {\n        for (let k = 0; k < n; k++) {\n            sum += grid[i][j][k];\n        }\n    }\n}", "Extract inner loops into functions, or rework the algorithm to reduce nesting.", "three or more loops nested inside one another", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityMedium},
		{"js-ast-complex-condition", "Overly complex boolean condition", "", "if (isEligible(request)) {\n    accept();\n}", "if (a && b && c && d && e && f) {\n    accept();\n}", "Extract the sub-conditions into well-named boolean variables or helper functions.", "a boolean condition combining many && or || operators", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"js-ast-high-complexity", "Function has high cyclomatic complexity", "", "function score(order) {\n    return table[order.type];\n}", "function score(order) {\n    // many if/else, loops, and && / || branches\n    return computed;\n}", "Reduce the number of decision points by extracting helper functions or using a lookup.", "a function with many decision points (if/loop/case/catch/&& /||)", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityMedium},
		{"js-ast-switch-many-cases", "switch has too many cases", "", "function label(status) {\n    return LABELS[status];\n}", "switch (status) {\n    // more than fifteen case labels\n    case 'a': return 1;\n    case 'b': return 2;\n}", "Model a large case set with a lookup object instead of a long switch.", "a switch statement with a very large number of case labels", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
	}
	rules := make([]rule.Rule, 0, len(specs))
	for _, s := range specs {
		rules = append(rules, rule.Rule{
			Key: rule.Key(s.key), Name: s.name, Language: "JavaScript/TypeScript", Type: s.type_, Qualities: []rule.Quality{s.quality}, DefaultSeverity: s.severity,
			Tags: []string{"javascript", "ast"}, CWE: optionalCWE(s.cwe), OWASP: []string{},
			Description: "Detects " + s.description + " in JavaScript/TypeScript source.",
			Rationale:   "This rule reports a JavaScript structure that reduces reliability or maintainability, detected on the syntax tree.\n\nSource: https://developer.mozilla.org/en-US/docs/Web/JavaScript",
			Remediation: s.remediation, CompliantExample: s.compliant, NoncompliantExample: s.noncompliant, RemediationEffort: 15, Detection: rule.DetectionAST,
		})
	}
	return rules
}
