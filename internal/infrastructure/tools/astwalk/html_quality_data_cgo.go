//go:build cgo

package astwalk

type htmlQualityRule struct {
	kind        string
	id          string
	cwe         string
	severity    string
	title       string
	description string
}

var htmlRuntimeRules = map[string]htmlQualityRule{
	"doctype-missing": {
		kind:        "reliability",
		id:          "html:doctype-missing",
		cwe:         "",
		severity:    "low",
		title:       "Missing HTML DOCTYPE declaration",
		description: "Full HTML document has no DOCTYPE declaration. Add <!DOCTYPE html> at the beginning of the file.",
	},
	"doctype-invalid": {
		kind:        "reliability",
		id:          "html:doctype-invalid",
		cwe:         "",
		severity:    "low",
		title:       "Invalid, misplaced, or duplicate DOCTYPE declaration",
		description: "DOCTYPE declaration is misplaced, duplicated, malformed, or does not specify html.",
	},
	"duplicate-attribute": {
		kind:        "reliability",
		id:          "html:duplicate-attribute",
		cwe:         "",
		severity:    "low",
		title:       "Duplicate attribute on HTML element",
		description: "The same attribute name appears more than once on a single element tag.",
	},
	"duplicate-id": {
		kind:        "reliability",
		id:          "html:duplicate-id",
		cwe:         "",
		severity:    "low",
		title:       "Duplicate ID in HTML document",
		description: "Multiple elements expose the same decoded, literal ID attribute value.",
	},
	"invalid-id": {
		kind:        "reliability",
		id:          "html:invalid-id",
		cwe:         "",
		severity:    "low",
		title:       "Invalid HTML element ID",
		description: "Literal element ID attribute is empty or contains HTML whitespace characters.",
	},
	"unclosed-tag": {
		kind:        "reliability",
		id:          "html:unclosed-tag",
		cwe:         "",
		severity:    "medium",
		title:       "Unclosed HTML element",
		description: "Non-void element requiring an explicit end tag is left unclosed.",
	},
	"unexpected-end-tag": {
		kind:        "reliability",
		id:          "html:unexpected-end-tag",
		cwe:         "",
		severity:    "medium",
		title:       "Unexpected HTML end tag",
		description: "End tag appears with no matching open element or for a void element.",
	},
	"nonvoid-self-closing": {
		kind:        "reliability",
		id:          "html:nonvoid-self-closing",
		cwe:         "",
		severity:    "medium",
		title:       "Self-closing syntax on non-void HTML element",
		description: "Self-closing syntax /> used on a non-void HTML element outside foreign content.",
	},
	"nested-form": {
		kind:        "reliability",
		id:          "html:nested-form",
		cwe:         "",
		severity:    "medium",
		title:       "Nested HTML form element",
		description: "A form element is nested inside another form element.",
	},
	"duplicate-document-element": {
		kind:        "reliability",
		id:          "html:duplicate-document-element",
		cwe:         "",
		severity:    "low",
		title:       "Duplicate explicit document element",
		description: "More than one explicit html, head, or body element appears in the document.",
	},
}
