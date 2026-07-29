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
	"target-blank-noopener": {
		kind:        "security",
		id:          "html:target-blank-noopener",
		cwe:         "1022",
		severity:    "medium",
		title:       "target=\"_blank\" without noopener or noreferrer",
		description: "Element opens link or form in target=\"_blank\" without noopener or noreferrer in rel.",
	},
	"inline-event-handler": {
		kind:        "security",
		id:          "html:inline-event-handler",
		cwe:         "79",
		severity:    "medium",
		title:       "Inline event handler attribute",
		description: "Element contains an inline event handler attribute (e.g. onclick).",
	},
	"javascript-url": {
		kind:        "security",
		id:          "html:javascript-url",
		cwe:         "79",
		severity:    "high",
		title:       "javascript: pseudo-protocol URL attribute",
		description: "URL attribute uses javascript: scheme.",
	},
	"iframe-sandbox-missing": {
		kind:        "security",
		id:          "html:iframe-sandbox-missing",
		cwe:         "693",
		severity:    "medium",
		title:       "Missing iframe sandbox attribute",
		description: "iframe with usable src or srcdoc lacks a sandbox attribute.",
	},
	"iframe-sandbox-escape": {
		kind:        "security",
		id:          "html:iframe-sandbox-escape",
		cwe:         "693",
		severity:    "high",
		title:       "iframe sandbox allow-scripts and allow-same-origin escape combination",
		description: "iframe sandbox enables both allow-scripts and allow-same-origin, allowing sandbox escape.",
	},
	"insecure-form-action": {
		kind:        "security",
		id:          "html:insecure-form-action",
		cwe:         "319",
		severity:    "medium",
		title:       "Insecure HTTP form action URL",
		description: "Form or form submission control submits data over insecure HTTP.",
	},
	"active-content-over-http": {
		kind:        "security",
		id:          "html:active-content-over-http",
		cwe:         "319",
		severity:    "high",
		title:       "Active network content loaded over HTTP",
		description: "External active script, iframe, object, embed, or stylesheet loaded over insecure HTTP.",
	},
	"external-resource-no-integrity": {
		kind:        "security",
		id:          "html:external-resource-no-integrity",
		cwe:         "353",
		severity:    "medium",
		title:       "External script or stylesheet missing Subresource Integrity (SRI)",
		description: "Absolute HTTP/HTTPS script or stylesheet is missing a valid non-empty integrity attribute.",
	},
}
