//go:build cgo

package astwalk

import (
	stdhtml "html"
	"sort"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

func htmlTrimASCIIWhitespace(val string) string {
	start := 0
	for start < len(val) && (val[start] == ' ' || val[start] == '\t' || val[start] == '\n' || val[start] == '\r' || val[start] == '\f') {
		start++
	}
	end := len(val)
	for end > start && (val[end-1] == ' ' || val[end-1] == '\t' || val[end-1] == '\n' || val[end-1] == '\r' || val[end-1] == '\f') {
		end--
	}
	return val[start:end]
}

func htmlDecodedAttributeValue(attr *htmlAttrInfo) (string, bool) {
	if attr == nil || !attr.complete || !attr.hasValue {
		return "", false
	}
	decoded := stdhtml.UnescapeString(attr.value)
	return decoded, true
}

func htmlFirstCompleteAttribute(attrs []htmlAttrInfo, name string) *htmlAttrInfo {
	lower := htmlASCIILower(name)
	for i := range attrs {
		if attrs[i].lowerName == lower && attrs[i].complete {
			return &attrs[i]
		}
	}
	return nil
}

func htmlAttributeTokens(attr *htmlAttrInfo) []string {
	tokens := htmlAttributeIDReferenceTokens(attr)
	for index := range tokens {
		tokens[index] = htmlASCIILower(tokens[index])
	}
	return tokens
}

func htmlAttributeIDReferenceTokens(attr *htmlAttrInfo) []string {
	val, ok := htmlDecodedAttributeValue(attr)
	if !ok {
		return nil
	}
	var tokens []string
	start := -1
	for i := 0; i <= len(val); i++ {
		var isSpace bool
		if i < len(val) {
			b := val[i]
			isSpace = (b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f')
		} else {
			isSpace = true
		}
		if isSpace {
			if start >= 0 {
				tokens = append(tokens, val[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	return tokens
}

func htmlHasAttributeToken(attr *htmlAttrInfo, token string) bool {
	lowerToken := htmlASCIILower(token)
	for _, t := range htmlAttributeTokens(attr) {
		if t == lowerToken {
			return true
		}
	}
	return false
}

func htmlNormalizeLiteralURL(attr *htmlAttrInfo) (string, bool) {
	if attr == nil || !attr.complete || !attr.hasValue {
		return "", false
	}
	raw := attr.value
	decoded := stdhtml.UnescapeString(raw)
	if htmlIsTemplateExpression(raw) || htmlIsTemplateExpression(decoded) {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(decoded); i++ {
		c := decoded[i]
		if c != '\t' && c != '\n' && c != '\r' {
			b.WriteByte(c)
		}
	}
	s := b.String()
	start := 0
	for start < len(s) && s[start] <= 0x20 {
		start++
	}
	end := len(s)
	for end > start && s[end-1] <= 0x20 {
		end--
	}
	return s[start:end], true
}

func htmlURLScheme(url string) string {
	if len(url) == 0 {
		return ""
	}
	first := url[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
		return ""
	}
	for i := 1; i < len(url); i++ {
		c := url[i]
		if c == ':' {
			return htmlASCIILower(url[:i])
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.' {
			continue
		}
		return ""
	}
	return ""
}

func htmlIsAbsoluteHTTPURL(url string) bool {
	return strings.HasPrefix(htmlASCIILower(url), "http://")
}

func htmlIsAbsoluteHTTPSURL(url string) bool {
	return strings.HasPrefix(htmlASCIILower(url), "https://")
}

func htmlIsStylesheetLink(tagName string, attrs []htmlAttrInfo) bool {
	if tagName != "link" {
		return false
	}
	relAttr := htmlFirstCompleteAttribute(attrs, "rel")
	if relAttr == nil {
		return false
	}
	return htmlHasAttributeToken(relAttr, "stylesheet")
}

type htmlSecurityCandidate struct {
	offset uint32
	rule   string
	line   int
	order  int
}

func collectHTMLSecurityCandidates(
	tagNode *sitter.Node,
	tagName string,
	attrs []htmlAttrInfo,
	src []byte,
) []htmlSecurityCandidate {
	if tagNode == nil {
		return nil
	}

	startText := tagNode.Content(src)
	if !strings.HasSuffix(strings.TrimSpace(startText), ">") || tagNode.HasError() {
		return nil
	}

	var candidates []htmlSecurityCandidate
	orderIdx := 0

	addCandidate := func(ruleKey string, line int, offset uint32) {
		candidates = append(candidates, htmlSecurityCandidate{
			offset: offset,
			rule:   ruleKey,
			line:   line,
			order:  orderIdx,
		})
		orderIdx++
	}

	// 1. html:target-blank-noopener
	// a[target], area[target], form[target]
	if tagName == "a" || tagName == "area" || tagName == "form" {
		targetAttr := htmlFirstCompleteAttribute(attrs, "target")
		targetVal, targetHasVal := htmlDecodedAttributeValue(targetAttr)
		if targetHasVal && htmlASCIILower(htmlTrimASCIIWhitespace(targetVal)) == "_blank" {
			shouldCheck := false
			if tagName == "form" {
				shouldCheck = true
			} else {
				hrefAttr := htmlFirstCompleteAttribute(attrs, "href")
				hrefVal, hrefHasVal := htmlDecodedAttributeValue(hrefAttr)
				if hrefHasVal && htmlTrimASCIIWhitespace(hrefVal) != "" {
					shouldCheck = true
				}
			}
			if shouldCheck {
				relAttr := htmlFirstCompleteAttribute(attrs, "rel")
				hasNoOpener := htmlHasAttributeToken(relAttr, "noopener")
				hasNoReferrer := htmlHasAttributeToken(relAttr, "noreferrer")
				if !hasNoOpener && !hasNoReferrer {
					addCandidate("target-blank-noopener", targetAttr.line, targetAttr.byteOffset)
				}
			}
		}
	}

	// 2. html:inline-event-handler
	seenAttrs := make(map[string]bool)
	for i := range attrs {
		attr := &attrs[i]
		if seenAttrs[attr.lowerName] {
			continue
		}
		seenAttrs[attr.lowerName] = true

		if attr.complete && attr.hasValue && strings.HasPrefix(attr.lowerName, "on") && len(attr.lowerName) >= 3 {
			third := attr.lowerName[2]
			if third >= 'a' && third <= 'z' {
				decodedVal := htmlTrimASCIIWhitespace(stdhtml.UnescapeString(attr.value))
				if decodedVal != "" {
					addCandidate("inline-event-handler", attr.line, attr.byteOffset)
				}
			}
		}
	}

	// 3. html:javascript-url
	var jsURLAttr *htmlAttrInfo
	switch tagName {
	case "a", "area":
		jsURLAttr = htmlFirstCompleteAttribute(attrs, "href")
	case "form":
		jsURLAttr = htmlFirstCompleteAttribute(attrs, "action")
	case "button", "input":
		jsURLAttr = htmlFirstCompleteAttribute(attrs, "formaction")
	case "iframe":
		jsURLAttr = htmlFirstCompleteAttribute(attrs, "src")
	}
	if normURL, ok := htmlNormalizeLiteralURL(jsURLAttr); ok {
		if htmlURLScheme(normURL) == "javascript" {
			addCandidate("javascript-url", jsURLAttr.line, jsURLAttr.byteOffset)
		}
	}

	// 4. html:iframe-sandbox-missing & 5. html:iframe-sandbox-escape
	if tagName == "iframe" {
		srcAttr := htmlFirstCompleteAttribute(attrs, "src")
		srcVal, srcHasVal := htmlDecodedAttributeValue(srcAttr)
		hasUsableSrc := srcHasVal && htmlTrimASCIIWhitespace(srcVal) != ""

		srcdocAttr := htmlFirstCompleteAttribute(attrs, "srcdoc")
		srcdocVal, srcdocHasVal := htmlDecodedAttributeValue(srcdocAttr)
		hasUsableSrcdoc := srcdocHasVal && htmlTrimASCIIWhitespace(srcdocVal) != ""

		sandboxAttr := htmlFirstCompleteAttribute(attrs, "sandbox")
		if sandboxAttr == nil {
			if hasUsableSrc || hasUsableSrcdoc {
				var chosenSource *htmlAttrInfo
				if hasUsableSrc && hasUsableSrcdoc {
					if srcAttr.byteOffset < srcdocAttr.byteOffset {
						chosenSource = srcAttr
					} else {
						chosenSource = srcdocAttr
					}
				} else if hasUsableSrc {
					chosenSource = srcAttr
				} else if hasUsableSrcdoc {
					chosenSource = srcdocAttr
				}
				addCandidate("iframe-sandbox-missing", chosenSource.line, chosenSource.byteOffset)
			}
		} else if sandboxAttr.complete && sandboxAttr.hasValue {
			if htmlHasAttributeToken(sandboxAttr, "allow-scripts") && htmlHasAttributeToken(sandboxAttr, "allow-same-origin") {
				addCandidate("iframe-sandbox-escape", sandboxAttr.line, sandboxAttr.byteOffset)
			}
		}
	}

	// 6. html:insecure-form-action
	var actionAttr *htmlAttrInfo
	switch tagName {
	case "form":
		actionAttr = htmlFirstCompleteAttribute(attrs, "action")
	case "button", "input":
		actionAttr = htmlFirstCompleteAttribute(attrs, "formaction")
	}
	if normURL, ok := htmlNormalizeLiteralURL(actionAttr); ok {
		if htmlIsAbsoluteHTTPURL(normURL) {
			addCandidate("insecure-form-action", actionAttr.line, actionAttr.byteOffset)
		}
	}

	// 7. html:active-content-over-http
	var activeURLAttr *htmlAttrInfo
	switch tagName {
	case "script", "iframe", "embed":
		activeURLAttr = htmlFirstCompleteAttribute(attrs, "src")
	case "object":
		activeURLAttr = htmlFirstCompleteAttribute(attrs, "data")
	case "link":
		if htmlIsStylesheetLink(tagName, attrs) {
			activeURLAttr = htmlFirstCompleteAttribute(attrs, "href")
		}
	}
	if normURL, ok := htmlNormalizeLiteralURL(activeURLAttr); ok {
		if htmlIsAbsoluteHTTPURL(normURL) {
			addCandidate("active-content-over-http", activeURLAttr.line, activeURLAttr.byteOffset)
		}
	}

	// 8. html:external-resource-no-integrity
	var sriURLAttr *htmlAttrInfo
	switch tagName {
	case "script":
		sriURLAttr = htmlFirstCompleteAttribute(attrs, "src")
	case "link":
		if htmlIsStylesheetLink(tagName, attrs) {
			sriURLAttr = htmlFirstCompleteAttribute(attrs, "href")
		}
	}
	if normURL, ok := htmlNormalizeLiteralURL(sriURLAttr); ok {
		if htmlIsAbsoluteHTTPURL(normURL) || htmlIsAbsoluteHTTPSURL(normURL) {
			integrityAttr := htmlFirstCompleteAttribute(attrs, "integrity")
			integrityVal, integrityHasVal := htmlDecodedAttributeValue(integrityAttr)
			if !integrityHasVal || htmlTrimASCIIWhitespace(integrityVal) == "" {
				addCandidate("external-resource-no-integrity", sriURLAttr.line, sriURLAttr.byteOffset)
			}
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].offset != candidates[j].offset {
			return candidates[i].offset < candidates[j].offset
		}
		return candidates[i].order < candidates[j].order
	})

	return candidates
}
