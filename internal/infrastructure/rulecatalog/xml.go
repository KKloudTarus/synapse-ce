package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func xmlRules() []rule.Rule {
	return []rule.Rule{
		{
			Key:                 "xml:not-well-formed",
			Name:                "XML document is not well formed",
			Language:            "XML",
			Type:                rule.TypeBug,
			Qualities:           []rule.Quality{rule.QualityReliability},
			DefaultSeverity:     shared.SeverityMedium,
			Tags:                []string{"xml", "well-formedness"},
			CWE:                 []string{},
			OWASP:               []string{},
			Description:         "Detects XML files that cannot be parsed as a single well-formed document.",
			Rationale:           "XML processors are required to reject documents that violate well-formedness constraints, so malformed configuration can fail at load time or be ignored by downstream tooling.\n\nSource: https://www.w3.org/TR/xml/",
			Remediation:         "Fix the XML structure so tags are properly nested, each document has one root element, and markup syntax is valid.",
			CompliantExample:    "<service><name>api</name></service>",
			NoncompliantExample: "<service><name>api</service>",
			RemediationEffort:   5,
			Detection:           rule.DetectionParse,
		},
		{
			Key:                 "xml:duplicate-attribute",
			Name:                "Duplicate XML attribute",
			Language:            "XML",
			Type:                rule.TypeBug,
			Qualities:           []rule.Quality{rule.QualityReliability},
			DefaultSeverity:     shared.SeverityLow,
			Tags:                []string{"xml", "well-formedness", "attributes"},
			CWE:                 []string{},
			OWASP:               []string{},
			Description:         "Detects an XML start tag that repeats the same attribute name.",
			Rationale:           "XML well-formedness requires each attribute name to appear at most once on a single start tag; duplicates make the element invalid and can create ambiguous configuration values.\n\nSource: https://www.w3.org/TR/xml/",
			Remediation:         "Keep a single value for the attribute and remove the duplicate, or split distinct meanings into differently named attributes.",
			CompliantExample:    "<service name=\"api\" role=\"worker\" />",
			NoncompliantExample: "<service name=\"api\" name=\"worker\" />",
			RemediationEffort:   5,
			Detection:           rule.DetectionParse,
		},
	}
}
