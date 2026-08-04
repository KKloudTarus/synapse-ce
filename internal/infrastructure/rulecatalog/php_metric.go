package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func phpMetricRules() []rule.Rule {
	return []rule.Rule{{
		Key:                 "php:cognitive-complexity",
		Name:                "High cognitive complexity",
		Language:            "PHP",
		Type:                rule.TypeCodeSmell,
		Qualities:           []rule.Quality{rule.QualityMaintainability},
		DefaultSeverity:     shared.SeverityMedium,
		Tags:                []string{"php", "maint"},
		CWE:                 []string{"CWE-1120"},
		OWASP:               []string{},
		Description:         "Detects PHP functions whose nesting-aware cognitive complexity exceeds the maintainability threshold.",
		Rationale:           "Nested and interrupted control flow increases the effort needed to understand, test, and safely change a function.\n\nSource: https://cwe.mitre.org/data/definitions/1120.html",
		Remediation:         "Use guard clauses and extract focused functions until the control flow is straightforward.",
		CompliantExample:    "function label(int $value): string { return $value > 0 ? 'positive' : 'other'; }",
		NoncompliantExample: "function classify(array $items): void {\n    foreach ($items as $item) {\n        if ($item->ready) {\n            switch ($item->kind) {\n                case 'a':\n                    if ($item->valid) {\n                        while ($item->pending) {\n                            if ($item->retryable) { retry($item); }\n                        }\n                    }\n                    break;\n                default:\n                    if ($item->retryable) { retry($item); }\n            }\n        }\n    }\n}",
		RemediationEffort:   60,
		Detection:           rule.DetectionMetric,
	}}
}
