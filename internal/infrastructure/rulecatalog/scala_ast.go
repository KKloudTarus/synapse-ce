package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func scalaASTRules() []rule.Rule {
	return []rule.Rule{
		{
			Key:             rule.Key("scala:cognitive-complexity"),
			Name:            "Function has high cognitive complexity",
			Language:        "Scala",
			Type:            rule.TypeCodeSmell,
			Qualities:       []rule.Quality{rule.QualityMaintainability},
			DefaultSeverity: shared.SeverityMedium,
			Tags:            []string{"scala", "maintainability", "complexity"},
			Detection:       rule.DetectionAST,
			Description:     "A Scala function has nesting-aware cognitive complexity above the supported threshold.",
			Rationale:       "Deeply nested control flow increases the amount of state and context a reader must retain, making changes harder to review and test.\n\nSource: https://docs.scala-lang.org/style/",
			Remediation:     "Use guard clauses, extract focused functions, and replace deeply nested conditionals with composable expressions or domain types.",
			CompliantExample: `def classify(value: Int): String =
  if (value > 0) "positive" else "other"`,
			NoncompliantExample: `def classify(value: Int): String = {
  if (value > 0) {
    if (value > 1) {
      if (value > 2) {
        if (value > 3) {
          if (value > 4) {
            if (value > 5) "large" else "medium"
          } else "small"
        } else "small"
      } else "small"
    } else "small"
  } else "other"
}`,
			RemediationEffort: 60,
		},
	}
}
