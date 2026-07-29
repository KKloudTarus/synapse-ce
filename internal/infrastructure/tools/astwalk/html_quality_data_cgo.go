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
	"img-alt-missing": {
		kind: "quality", id: "html:img-alt-missing", severity: "medium",
		title: "Image is missing an alt attribute", description: "Visible img element has no complete alt attribute.",
	},
	"area-alt-missing": {
		kind: "quality", id: "html:area-alt-missing", severity: "medium",
		title: "Image map area is missing alternative text", description: "Area with a usable href has no meaningful alt text.",
	},
	"input-image-alt-missing": {
		kind: "quality", id: "html:input-image-alt-missing", severity: "medium",
		title: "Image input is missing alternative text", description: "Input with type=image has no meaningful alt text.",
	},
	"object-fallback-missing": {
		kind: "quality", id: "html:object-fallback-missing", severity: "medium",
		title: "Object element has no fallback content", description: "Object element has no meaningful fallback text or non-param fallback element.",
	},
	"iframe-title-missing": {
		kind: "quality", id: "html:iframe-title-missing", severity: "medium",
		title: "Iframe is missing an accessible title", description: "Iframe has no non-empty title or usable ARIA name.",
	},
	"html-title-missing": {
		kind: "quality", id: "html:html-title-missing", severity: "medium",
		title: "HTML document is missing a meaningful title", description: "Full HTML document has no meaningful title element directly under head.",
	},
	"missing-lang": {
		kind: "quality", id: "html:missing-lang", severity: "low",
		title: "HTML document is missing a language", description: "Explicit root html element has no meaningful lang attribute.",
	},
	"label-missing": {
		kind: "quality", id: "html:label-missing", severity: "medium",
		title: "Form control is missing an accessible label", description: "Form control has no associated label or other supported accessible name.",
	},
	"button-name-missing": {
		kind: "quality", id: "html:button-name-missing", severity: "medium",
		title: "Button is missing an accessible name", description: "Button control has no supported static accessible name.",
	},
	"link-name-missing": {
		kind: "quality", id: "html:link-name-missing", severity: "medium",
		title: "Link is missing an accessible name", description: "Link has no supported static accessible name.",
	},
	"fieldset-legend-missing": {
		kind: "quality", id: "html:fieldset-legend-missing", severity: "medium",
		title: "Fieldset is missing a meaningful legend", description: "Fieldset grouping multiple controls has no first-child legend or ARIA name.",
	},
	"table-caption-missing": {
		kind: "quality", id: "html:table-caption-missing", severity: "low",
		title: "Data table is missing a caption", description: "Data table has no meaningful caption or supported ARIA name.",
	},
	"table-header-reference-missing": {
		kind: "quality", id: "html:table-header-reference-missing", severity: "medium",
		title: "Table header reference does not resolve", description: "Table cell headers attribute is empty or references a missing header in another table.",
	},
	"heading-empty": {
		kind: "quality", id: "html:heading-empty", severity: "medium",
		title: "Heading has no accessible name", description: "Visible native or ARIA heading has no supported static accessible name.",
	},
	"heading-order": {
		kind: "quality", id: "html:heading-order", severity: "low",
		title: "Heading level is skipped", description: "Heading level increases by more than one from the previous visible heading.",
	},
	"main-landmark-missing": {
		kind: "quality", id: "html:main-landmark-missing", severity: "low",
		title: "HTML document is missing a main landmark", description: "Full HTML document has no visible native or ARIA main landmark.",
	},
	"duplicate-main-landmark": {
		kind: "quality", id: "html:duplicate-main-landmark", severity: "low",
		title: "Main landmarks need unique accessible names", description: "Second or later visible main landmark is unnamed or repeats an earlier main landmark name.",
	},
	"tabindex-positive": {
		kind: "quality", id: "html:tabindex-positive", severity: "low",
		title: "Positive tabindex overrides natural focus order", description: "Literal tabindex value is greater than zero.",
	},
	"accesskey-used": {
		kind: "quality", id: "html:accesskey-used", severity: "low",
		title: "Accesskey attribute is used", description: "Non-empty accesskey can conflict with browser and assistive-technology shortcuts.",
	},
	"autofocus-used": {
		kind: "quality", id: "html:autofocus-used", severity: "low",
		title: "Autofocus attribute is used", description: "Autofocus can unexpectedly move keyboard and assistive-technology focus.",
	},
	"nested-interactive-control": {
		kind: "quality", id: "html:nested-interactive-control", severity: "medium",
		title: "Interactive control is nested inside another control", description: "Sequentially focusable element is nested inside a strict interactive control.",
	},
	"aria-hidden-focusable": {
		kind: "quality", id: "html:aria-hidden-focusable", severity: "medium",
		title: "ARIA-hidden subtree contains a focusable element", description: "Element hidden from accessibility APIs remains keyboard focusable itself or contains a focusable descendant.",
	},
	"aria-hidden-body": {
		kind: "quality", id: "html:aria-hidden-body", severity: "medium",
		title: "Document body is hidden from accessibility APIs", description: "Explicit body element declares aria-hidden=true.",
	},
	"aria-reference-missing": {
		kind: "quality", id: "html:aria-reference-missing", severity: "medium",
		title: "ARIA ID reference does not resolve", description: "ARIA relationship attribute is empty or references an ID absent from the document.",
	},
	"aria-role-invalid": {
		kind: "quality", id: "html:aria-role-invalid", severity: "medium",
		title: "ARIA role list has no valid concrete role", description: "Non-empty role attribute contains no valid concrete WAI-ARIA role token.",
	},
	"aria-required-attribute-missing": {
		kind: "quality", id: "html:aria-required-attribute-missing", severity: "medium",
		title: "ARIA role is missing a required property", description: "Explicit ARIA role lacks one or more required non-empty ARIA properties.",
	},
	"role-img-name-missing": {
		kind: "quality", id: "html:role-img-name-missing", severity: "medium",
		title: "ARIA image is missing an accessible name", description: "Visible element with role=img has no supported static accessible name.",
	},
	"meta-refresh-used": {
		kind: "quality", id: "html:meta-refresh-used", severity: "medium",
		title: "Meta refresh requires accessibility review", description: "Syntactically valid static meta refresh or redirect requires accessibility and usability review.",
	},
	"viewport-zoom-disabled": {
		kind: "quality", id: "html:viewport-zoom-disabled", severity: "medium",
		title: "Viewport configuration restricts zoom", description: "Viewport directive disables user scaling or sets maximum scale below two.",
	},
	"media-autoplay": {
		kind: "quality", id: "html:media-autoplay", severity: "low",
		title: "Unmuted media autoplays", description: "Audio or video uses autoplay without muted.",
	},
	"deprecated-tag": {
		kind: "quality", id: "html:deprecated-tag", severity: "low",
		title: "Deprecated HTML element is used", description: "Obsolete HTML element should be replaced with modern semantic markup.",
	},
	"deprecated-attribute": {
		kind: "quality", id: "html:deprecated-attribute", severity: "low",
		title: "Deprecated HTML attribute is used", description: "Element uses an obsolete or contextually deprecated HTML attribute.",
	},
}
