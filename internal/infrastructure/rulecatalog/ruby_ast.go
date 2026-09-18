package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func rubyASTRules() []rule.Rule {
	return []rule.Rule{
		{
			Key:             rule.Key("rb:cognitive-complexity"),
			Name:            "Method has high cognitive complexity",
			Language:        "Ruby",
			Type:            rule.TypeCodeSmell,
			Qualities:       []rule.Quality{rule.QualityMaintainability},
			DefaultSeverity: shared.SeverityMedium,
			Tags:            []string{"ruby", "maintainability", "complexity"},
			Detection:       rule.DetectionAST,
			Description:     "A Ruby method has nesting-aware cognitive complexity above the supported threshold.",
			Rationale:       "Deeply nested branches and loops force readers to retain more context, increasing change risk and making behavior harder to test.\n\nSource: https://rubystyle.guide/",
			Remediation:     "Use guard clauses, extract focused methods, and replace deeply nested conditional logic with small objects or explicit tables.",
			CompliantExample: `def classify(value)
  value.positive? ? "positive" : "other"
end`,
			NoncompliantExample: `def classify(value)
  if value > 0
    if value > 1
      if value > 2
        if value > 3
          if value > 4
            if value > 5
              "large"
            else
              "medium"
            end
          else
            "small"
          end
        else
          "small"
        end
      else
        "small"
      end
    else
      "small"
    end
  else
    "other"
  end
end`,
			RemediationEffort: 60,
		},
		{
			Key:             rule.Key("rb:duplicate-when-condition"),
			Name:            "Duplicate when condition",
			Language:        "Ruby",
			Type:            rule.TypeBug,
			Qualities:       []rule.Quality{rule.QualityReliability},
			DefaultSeverity: shared.SeverityMedium,
			Tags:            []string{"ruby", "reliability", "dead-code"},
			CWE:             []string{"CWE-561"},
			Detection:       rule.DetectionAST,
			Description:     "A case/when branch repeats the condition of an earlier when in the same case expression.",
			Rationale:       "Ruby evaluates when clauses top to bottom and executes the first match, so a branch whose condition duplicates an earlier one is dead code. It usually signals a copy-paste error where a different condition was intended.\n\nSource: https://cwe.mitre.org/data/definitions/561.html",
			Remediation:     "Remove the duplicate branch, or correct its condition to the value that was intended.",
			CompliantExample: `case status
when :active then start
when :paused then hold
else stop
end`,
			NoncompliantExample: `case status
when :active then start
when :active then hold
else stop
end`,
			RemediationEffort: 5,
		},
	}
}
