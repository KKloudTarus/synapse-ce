//go:build cgo

package astwalk

import (
	stdhtml "html"
	"sort"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	maxHTMLPerRule    = 20
	maxHTMLTotal      = 100
	maxTrackedIDs     = 4096
	maxHTMLAttributes = 256
	maxHTMLDepth      = 256
)

type htmlCollector struct {
	findings []QualityFinding
	perRule  map[string]int
	total    int
	rel      string
}

func newHTMLCollector(rel string) *htmlCollector {
	return &htmlCollector{
		findings: make([]QualityFinding, 0, 16),
		perRule:  make(map[string]int),
		rel:      rel,
	}
}

func (c *htmlCollector) emit(ruleKey string, line int) bool {
	if c.total >= maxHTMLTotal {
		return false
	}
	if c.perRule[ruleKey] >= maxHTMLPerRule {
		return false
	}
	rule, ok := htmlRuntimeRules[ruleKey]
	if !ok {
		return false
	}
	if line < 1 {
		line = 1
	}
	c.findings = append(c.findings, QualityFinding{
		Kind:        rule.kind,
		Rule:        rule.id,
		CWE:         rule.cwe,
		Severity:    rule.severity,
		Title:       rule.title,
		Description: rule.description,
		File:        c.rel,
		Line:        line,
	})
	c.perRule[ruleKey]++
	c.total++
	return true
}

func htmlIsVoidElement(tag string) bool {
	switch tag {
	case "area", "base", "br", "col", "embed", "hr", "img", "input",
		"link", "meta", "param", "source", "track", "wbr",
		"basefont", "bgsound", "frame", "keygen":
		return true
	}
	return false
}

func htmlHasOptionalEndTag(tag string) bool {
	switch tag {
	case "html", "head", "body", "li", "dt", "dd", "p", "rt", "rp",
		"optgroup", "option", "colgroup", "thead", "tbody", "tfoot",
		"tr", "td", "th":
		return true
	}
	return false
}

func htmlIsInForeignContent(node *sitter.Node, src []byte, maxDepth int) bool {
	depth := 0
	for p := node.Parent(); p != nil && depth < maxDepth; p = p.Parent() {
		depth++
		tName := htmlTagNameWithSrc(p, src)
		if tName == "svg" || tName == "math" {
			return true
		}
	}
	return false
}

func htmlIsTemplateExpression(val string) bool {
	return strings.Contains(val, "{{") ||
		strings.Contains(val, "{%") ||
		strings.Contains(val, "${") ||
		strings.Contains(val, "<%")
}

func htmlASCIIWhitespace(val string) bool {
	for i := 0; i < len(val); i++ {
		b := val[i]
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' {
			return true
		}
	}
	return false
}

func htmlASCIILower(value string) string {
	b := make([]byte, len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func htmlTagNameWithSrc(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	switch node.Type() {
	case "script_element":
		return "script"
	case "style_element":
		return "style"
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		ch := node.Child(i)
		if ch.Type() == "tag_name" {
			return htmlASCIILower(ch.Content(src))
		}
		if ch.Type() == "start_tag" || ch.Type() == "self_closing_tag" || ch.Type() == "end_tag" {
			return htmlTagNameWithSrc(ch, src)
		}
	}
	return ""
}

type htmlAttrInfo struct {
	name       string
	lowerName  string
	value      string
	hasValue   bool
	complete   bool
	node       *sitter.Node
	line       int
	byteOffset uint32
}

func parseHTMLAttributes(tagNode *sitter.Node, src []byte) []htmlAttrInfo {
	if tagNode == nil {
		return nil
	}
	var attrs []htmlAttrInfo
	for i := 0; i < int(tagNode.ChildCount()) && len(attrs) < maxHTMLAttributes; i++ {
		ch := tagNode.Child(i)
		if ch.Type() != "attribute" {
			continue
		}
		var nameNode *sitter.Node
		var valNode *sitter.Node
		for j := 0; j < int(ch.ChildCount()); j++ {
			c := ch.Child(j)
			switch c.Type() {
			case "attribute_name":
				nameNode = c
			case "attribute_value", "quoted_attribute_value":
				valNode = c
			}
		}
		attrName := ""
		if nameNode != nil {
			attrName = nameNode.Content(src)
		} else {
			attrName = ch.Content(src)
			if idx := strings.IndexAny(attrName, "= \t\n\r"); idx >= 0 {
				attrName = attrName[:idx]
			}
		}

		rawCh := ch.Content(src)
		complete := !ch.HasError()
		if nameNode == nil || attrName == "" {
			complete = false
		}

		attrVal := ""
		hasValue := false
		if valNode != nil {
			hasValue = true
			if valNode.HasError() {
				complete = false
			}
			rawVal := valNode.Content(src)
			if valNode.Type() == "quoted_attribute_value" {
				if len(rawVal) >= 2 && ((rawVal[0] == '"' && rawVal[len(rawVal)-1] == '"') || (rawVal[0] == '\'' && rawVal[len(rawVal)-1] == '\'')) {
					attrVal = rawVal[1 : len(rawVal)-1]
				} else {
					complete = false
				}
			} else {
				attrVal = rawVal
			}
		} else {
			if strings.Contains(rawCh, "=") {
				complete = false
			}
		}

		attrs = append(attrs, htmlAttrInfo{
			name:       attrName,
			lowerName:  htmlASCIILower(attrName),
			value:      attrVal,
			hasValue:   hasValue,
			complete:   complete,
			node:       ch,
			line:       int(ch.StartPoint().Row) + 1,
			byteOffset: ch.StartByte(),
		})
	}
	return attrs
}

func htmlFindings(root *sitter.Node, src []byte, rel string) []QualityFinding {
	if root == nil {
		return nil
	}
	collector := newHTMLCollector(rel)

	seenIDs := make(map[string]bool)
	seenDocElems := make(map[string]bool)
	unclosedEmittedOffset := make(map[uint32]bool)

	firstElementLine := 0
	firstElementByte := -1
	var validElementCount int
	var doctypeNodes []*sitter.Node

	// AST Traversal Stack
	type stackItem struct {
		node  *sitter.Node
		depth int
	}

	var nodes []*sitter.Node
	workStack := []stackItem{{node: root, depth: 0}}
	traversalComplete := true

	for len(workStack) > 0 {
		item := workStack[len(workStack)-1]
		workStack = workStack[:len(workStack)-1]
		n := item.node
		if n == nil {
			continue
		}

		nodes = append(nodes, n)

		if item.depth < maxHTMLDepth {
			for i := int(n.ChildCount()) - 1; i >= 0; i-- {
				ch := n.Child(i)
				if ch != nil {
					workStack = append(workStack, stackItem{node: ch, depth: item.depth + 1})
				}
			}
		} else if n.ChildCount() > 0 {
			traversalComplete = false
		}
	}

	// First pass: locate top-level DOCTYPEs and valid elements
	for _, n := range nodes {
		switch n.Type() {
		case "doctype":
			if n.Parent() == nil || n.Parent().Type() != "doctype" {
				doctypeNodes = append(doctypeNodes, n)
			}
		case "element", "script_element", "style_element":
			line := int(n.StartPoint().Row) + 1
			byteOff := int(n.StartByte())
			if firstElementByte < 0 || byteOff < firstElementByte {
				firstElementByte = byteOff
				firstElementLine = line
			}
			validElementCount++
		}
	}

	// DOCTYPE Checks (doctype-missing & doctype-invalid)
	hasInvalidDoctype := false

	for idx, docNode := range doctypeNodes {
		line := int(docNode.StartPoint().Row) + 1
		docByte := int(docNode.StartByte())
		rawText := strings.TrimSpace(docNode.Content(src))
		lowerText := strings.ToLower(rawText)

		isInvalid := false

		if idx > 0 {
			isInvalid = true
		}

		if firstElementByte >= 0 && docByte > firstElementByte {
			isInvalid = true
		}

		if !strings.HasPrefix(lowerText, "<!doctype") || !strings.HasSuffix(rawText, ">") {
			isInvalid = true
		} else {
			parts := strings.Fields(rawText)
			if len(parts) < 2 {
				isInvalid = true
			} else {
				docTypeName := strings.ToLower(parts[1])
				docTypeName = strings.TrimSuffix(docTypeName, ">")
				if docTypeName != "html" {
					isInvalid = true
				}
			}
		}

		if isInvalid {
			hasInvalidDoctype = true
			collector.emit("doctype-invalid", line)
		}
	}

	if validElementCount > 0 && len(doctypeNodes) == 0 && !hasInvalidDoctype {
		missingLine := firstElementLine
		if missingLine < 1 {
			missingLine = 1
		}
		collector.emit("doctype-missing", missingLine)
	}

	maintainabilityFacts := htmlBuildMaintainabilityFacts(nodes, src, traversalComplete)
	maintainabilityState := &htmlMaintainabilityState{
		nestedInteractiveSeen: make(map[uint32]bool),
		mainLandmarkNames:     make(map[string]bool),
	}

	// Main node inspection pass for other rules
	for _, n := range nodes {
		ntype := n.Type()

		switch ntype {
		case "start_tag", "self_closing_tag":
			line := int(n.StartPoint().Row) + 1
			tName := htmlTagNameWithSrc(n, src)
			attrs := parseHTMLAttributes(n, src)

			type tagFindingCandidate struct {
				offset uint32
				rule   string
				line   int
				order  int
			}

			var tagCandidates []tagFindingCandidate
			orderIdx := 0

			addCandidate := func(ruleKey string, line int, offset uint32) {
				tagCandidates = append(tagCandidates, tagFindingCandidate{
					offset: offset,
					rule:   ruleKey,
					line:   line,
					order:  orderIdx,
				})
				orderIdx++
			}

			// Rule 3: html:duplicate-attribute
			seenTagAttrs := make(map[string]bool)
			var firstIDAttr *htmlAttrInfo

			for idx := range attrs {
				attr := &attrs[idx]
				if seenTagAttrs[attr.lowerName] {
					addCandidate("duplicate-attribute", attr.line, attr.byteOffset)
				} else {
					seenTagAttrs[attr.lowerName] = true
				}

				if attr.lowerName == "id" && firstIDAttr == nil {
					firstIDAttr = attr
				}
			}

			// Rules 4 & 5: html:duplicate-id & html:invalid-id
			if firstIDAttr != nil {
				if !firstIDAttr.hasValue {
					addCandidate("invalid-id", firstIDAttr.line, firstIDAttr.byteOffset)
				} else {
					rawVal := firstIDAttr.value
					decodedVal := stdhtml.UnescapeString(rawVal)

					if !htmlIsTemplateExpression(rawVal) && !htmlIsTemplateExpression(decodedVal) {
						if decodedVal == "" || htmlASCIIWhitespace(decodedVal) {
							addCandidate("invalid-id", firstIDAttr.line, firstIDAttr.byteOffset)
						} else {
							if seenIDs[decodedVal] {
								addCandidate("duplicate-id", firstIDAttr.line, firstIDAttr.byteOffset)
							} else {
								if len(seenIDs) < maxTrackedIDs {
									seenIDs[decodedVal] = true
								}
							}
						}
					}
				}
			}

			// Rule 10: html:duplicate-document-element
			if tName == "html" || tName == "head" || tName == "body" {
				if seenDocElems[tName] {
					addCandidate("duplicate-document-element", line, n.StartByte())
				} else {
					seenDocElems[tName] = true
				}
			}

			// Rule 8: html:nonvoid-self-closing
			if ntype == "self_closing_tag" {
				if !htmlIsVoidElement(tName) && !htmlIsInForeignContent(n, src, maxHTMLDepth) {
					addCandidate("nonvoid-self-closing", line, n.StartByte())
				}
			}

			// Rule 6: html:unclosed-tag check for standalone start_tag
			if ntype == "start_tag" && tName != "" && !htmlIsVoidElement(tName) && !htmlHasOptionalEndTag(tName) {
				parent := n.Parent()
				isClosed := false
				if parent != nil && (parent.Type() == "element" || parent.Type() == "script_element" || parent.Type() == "style_element") {
					for i := 0; i < int(parent.ChildCount()); i++ {
						ch := parent.Child(i)
						if ch.Type() == "end_tag" {
							endName := htmlTagNameWithSrc(ch, src)
							if endName == tName {
								isClosed = true
								break
							}
						}
					}
				}
				if !isClosed && !unclosedEmittedOffset[n.StartByte()] {
					startText := n.Content(src)
					if strings.HasSuffix(strings.TrimSpace(startText), ">") {
						unclosedEmittedOffset[n.StartByte()] = true
						addCandidate("unclosed-tag", line, n.StartByte())
					}
				}
			}

			// Security rules inspection
			secCandidates := collectHTMLSecurityCandidates(n, tName, attrs, src)
			for _, sc := range secCandidates {
				addCandidate(sc.rule, sc.line, sc.offset)
			}

			maintCandidates := collectHTMLMaintainabilityCandidates(
				n,
				tName,
				attrs,
				src,
				maintainabilityFacts,
				maintainabilityState,
			)
			for _, mc := range maintCandidates {
				addCandidate(mc.rule, mc.line, mc.offset)
			}

			sort.SliceStable(tagCandidates, func(i, j int) bool {
				if tagCandidates[i].offset != tagCandidates[j].offset {
					return tagCandidates[i].offset < tagCandidates[j].offset
				}
				return tagCandidates[i].order < tagCandidates[j].order
			})

			for _, tc := range tagCandidates {
				collector.emit(tc.rule, tc.line)
			}

		case "element", "script_element", "style_element":
			line := int(n.StartPoint().Row) + 1
			tName := htmlTagNameWithSrc(n, src)

			// Rule 9: html:nested-form
			if tName == "form" {
				depth := 0
				for p := n.Parent(); p != nil && depth < maxHTMLDepth; p = p.Parent() {
					depth++
					pName := htmlTagNameWithSrc(p, src)
					if pName == "template" {
						break
					}
					if pName == "form" {
						collector.emit("nested-form", line)
						break
					}
				}
			}

			// Rule 6: html:unclosed-tag
			if tName != "" && !htmlIsVoidElement(tName) && !htmlHasOptionalEndTag(tName) {
				hasSelfClosingTag := false
				for i := 0; i < int(n.ChildCount()); i++ {
					if n.Child(i).Type() == "self_closing_tag" {
						hasSelfClosingTag = true
						break
					}
				}

				if !hasSelfClosingTag {
					startTagNode := n.Child(0)
					if startTagNode != nil && (startTagNode.Type() == "start_tag" || ntype == "script_element" || ntype == "style_element") {
						startText := startTagNode.Content(src)
						if strings.HasSuffix(strings.TrimSpace(startText), ">") {
							hasEndTag := false
							for i := 0; i < int(n.ChildCount()); i++ {
								ch := n.Child(i)
								if ch.Type() == "end_tag" {
									endName := htmlTagNameWithSrc(ch, src)
									if endName == tName {
										hasEndTag = true
										break
									}
								}
							}
							if !hasEndTag && !unclosedEmittedOffset[startTagNode.StartByte()] {
								unclosedEmittedOffset[startTagNode.StartByte()] = true
								collector.emit("unclosed-tag", line)
							}
						}
					}
				}
			}

		case "erroneous_end_tag":
			line := int(n.StartPoint().Row) + 1
			collector.emit("unexpected-end-tag", line)

		case "ERROR":
			raw := strings.TrimSpace(n.Content(src))
			line := int(n.StartPoint().Row) + 1
			if strings.HasPrefix(raw, "</") && strings.HasSuffix(raw, ">") {
				collector.emit("unexpected-end-tag", line)
			}

		case "</":
			next := n.NextSibling()
			if next != nil && next.Type() == ">" {
				line := int(n.StartPoint().Row) + 1
				collector.emit("unexpected-end-tag", line)
			}

		case "end_tag":
			tName := htmlTagNameWithSrc(n, src)
			line := int(n.StartPoint().Row) + 1
			if htmlIsVoidElement(tName) {
				collector.emit("unexpected-end-tag", line)
			} else if n.Parent() == nil || n.Parent().Type() == "document" {
				collector.emit("unexpected-end-tag", line)
			} else if n.Parent().Type() == "element" && htmlTagNameWithSrc(n.Parent(), src) != tName {
				collector.emit("unexpected-end-tag", line)
			}
		}
	}

	return collector.findings
}
