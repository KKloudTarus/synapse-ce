package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func kotlinMetricRules() []rule.Rule {
	return []rule.Rule{{
		Key:                 "kotlin-cognitive-complexity",
		Name:                "High cognitive complexity",
		Language:            "Kotlin",
		Type:                rule.TypeCodeSmell,
		Qualities:           []rule.Quality{rule.QualityMaintainability},
		DefaultSeverity:     shared.SeverityMedium,
		Tags:                []string{"kotlin", "maint"},
		CWE:                 []string{"CWE-1120"},
		OWASP:               []string{},
		Description:         "Detects Kotlin functions whose nesting-aware cognitive complexity exceeds the maintainability threshold.",
		Rationale:           "Nested and interrupted control flow increases the effort needed to understand, test, and safely change a function.\n\nSource: https://cwe.mitre.org/data/definitions/1120.html",
		Remediation:         "Use guard clauses and extract focused functions until the control flow is straightforward.",
		CompliantExample:    "fun label(value: Int): String = if (value > 0) \"positive\" else \"other\"",
		NoncompliantExample: "fun classify(items: List<Item>) {\n    for (item in items) {\n        if (item.ready) {\n            when (item.kind) {\n                Kind.A -> if (item.valid) save(item)\n                else -> if (item.retryable) retry(item)\n            }\n        }\n    }\n}",
		RemediationEffort:   60,
		Detection:           rule.DetectionMetric,
	}}
}
