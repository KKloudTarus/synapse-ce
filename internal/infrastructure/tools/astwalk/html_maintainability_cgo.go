//go:build cgo

package astwalk

import (
	stdhtml "html"
	"sort"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

type htmlMaintainabilityFacts struct {
	explicitHTML *sitter.Node
	explicitHead *sitter.Node
	explicitBody *sitter.Node

	idElements  map[string]*sitter.Node
	labelsByFor map[string][]*sitter.Node

	firstFieldsetChildren map[uint32]*sitter.Node
	firstFieldsetLegends  map[uint32]*sitter.Node
	firstDetailsSummaries map[uint32]*sitter.Node
	traversalComplete     bool

	idsComplete       bool
	labelsComplete    bool
	hasUsableTitle    bool
	titleScanComplete bool
	hasUsableMain     bool
}

type htmlMaintainabilityState struct {
	lastHeadingLevel      int
	mainLandmarkCount     int
	mainLandmarkNames     map[string]bool
	mainMissingEmitted    bool
	nestedInteractiveSeen map[uint32]bool
}

type htmlMaintainabilityCandidate struct {
	rule   string
	line   int
	offset uint32
	order  int
}

type htmlNameMode int

const (
	htmlNameGeneric htmlNameMode = iota
	htmlNameControl
	htmlNameButton
	htmlNameLink
	htmlNameHeading
	htmlNameIframe
	htmlNameRoleImg
	htmlNameLandmark
	htmlNameFieldset
	htmlNameTable
)

type htmlNameBudget struct {
	nodes     int
	bytes     int
	visited   map[uint32]bool
	exhausted bool
}

type htmlNameResult struct {
	value      string
	present    bool
	reliable   bool
	comparable bool
}

type htmlScanResult struct {
	found    bool
	reliable bool
}

type htmlImplicitRoleResult struct {
	role  string
	known bool
}

func htmlElementForTag(tagNode *sitter.Node) *sitter.Node {
	if tagNode == nil {
		return nil
	}
	parent := tagNode.Parent()
	if parent == nil {
		return nil
	}
	switch parent.Type() {
	case "element", "script_element", "style_element":
		return parent
	}
	return nil
}

func htmlStartTagForElement(element *sitter.Node) *sitter.Node {
	if element == nil {
		return nil
	}
	if element.Type() == "start_tag" || element.Type() == "self_closing_tag" {
		return element
	}
	for i := 0; i < int(element.ChildCount()); i++ {
		child := element.Child(i)
		if child.Type() == "start_tag" || child.Type() == "self_closing_tag" {
			return child
		}
	}
	return nil
}

func htmlCompleteTag(tagNode *sitter.Node, src []byte) bool {
	if tagNode == nil || tagNode.HasError() {
		return false
	}
	return strings.HasSuffix(strings.TrimSpace(tagNode.Content(src)), ">")
}

func htmlDecodedTrimmedAttribute(attr *htmlAttrInfo) (string, bool) {
	value, ok := htmlDecodedAttributeValue(attr)
	if !ok {
		return "", false
	}
	return htmlTrimASCIIWhitespace(value), true
}

func htmlUsableAttribute(attr *htmlAttrInfo) bool {
	value, ok := htmlDecodedTrimmedAttribute(attr)
	return ok && value != ""
}

func htmlKnownStaticNonEmptyAttribute(attr *htmlAttrInfo) bool {
	value, ok := htmlDecodedTrimmedAttribute(attr)
	if !ok || value == "" || htmlIsTemplateExpression(attr.value) || htmlIsTemplateExpression(value) {
		return false
	}
	return true
}

func htmlAttributeLiteralLower(attrs []htmlAttrInfo, name string) (string, bool) {
	attr := htmlFirstCompleteAttribute(attrs, name)
	value, ok := htmlDecodedTrimmedAttribute(attr)
	if !ok || htmlIsTemplateExpression(attr.value) || htmlIsTemplateExpression(value) {
		return "", false
	}
	return htmlASCIILower(value), true
}

func htmlFirstValidConcreteRole(attrs []htmlAttrInfo) (string, *htmlAttrInfo, bool) {
	roleAttr := htmlFirstCompleteAttribute(attrs, "role")
	value, ok := htmlDecodedTrimmedAttribute(roleAttr)
	if !ok || value == "" || htmlIsTemplateExpression(roleAttr.value) || htmlIsTemplateExpression(value) {
		return "", roleAttr, false
	}
	for _, token := range htmlAttributeTokens(roleAttr) {
		if htmlConcreteARIARoles[token] {
			return token, roleAttr, true
		}
	}
	return "", roleAttr, false
}

func htmlRoleIs(attrs []htmlAttrInfo, roles ...string) bool {
	role, _, ok := htmlFirstValidConcreteRole(attrs)
	if !ok {
		return false
	}
	for _, wanted := range roles {
		if role == wanted {
			return true
		}
	}
	return false
}

func htmlInputType(attrs []htmlAttrInfo) (string, bool) {
	attr := htmlFirstCompleteAttribute(attrs, "type")
	if attr == nil {
		return "text", true
	}
	value, ok := htmlDecodedTrimmedAttribute(attr)
	if !ok {
		return "", false
	}
	if htmlIsTemplateExpression(attr.value) || htmlIsTemplateExpression(value) {
		return "", false
	}
	if value == "" {
		return "text", true
	}
	return htmlASCIILower(value), true
}

func htmlBuildMaintainabilityFacts(nodes []*sitter.Node, src []byte, traversalComplete bool) *htmlMaintainabilityFacts {
	facts := &htmlMaintainabilityFacts{
		idElements:            make(map[string]*sitter.Node),
		labelsByFor:           make(map[string][]*sitter.Node),
		firstFieldsetChildren: make(map[uint32]*sitter.Node),
		firstFieldsetLegends:  make(map[uint32]*sitter.Node),
		firstDetailsSummaries: make(map[uint32]*sitter.Node),
		traversalComplete:     traversalComplete,
		idsComplete:           traversalComplete,
		labelsComplete:        traversalComplete,
		titleScanComplete:     traversalComplete,
	}

	for _, node := range nodes {
		if node == nil {
			continue
		}
		switch node.Type() {
		case "element", "script_element", "style_element":
		default:
			continue
		}
		parent := node.Parent()
		if parent == nil {
			continue
		}
		switch parent.Type() {
		case "element", "script_element", "style_element":
		default:
			continue
		}
		parentTag := htmlStartTagForElement(parent)
		if parentTag == nil {
			continue
		}
		parentName := htmlTagNameWithSrc(parentTag, src)
		parentOffset := parent.StartByte()
		if parentName == "fieldset" {
			firstChild := facts.firstFieldsetChildren[parentOffset]
			if firstChild == nil || node.StartByte() < firstChild.StartByte() {
				facts.firstFieldsetChildren[parentOffset] = node
			}
		}

		childTag := htmlStartTagForElement(node)
		childName := ""
		if childTag != nil {
			childName = htmlTagNameWithSrc(childTag, src)
		}
		if parentName == "fieldset" && childName == "legend" {
			firstLegend := facts.firstFieldsetLegends[parentOffset]
			if firstLegend == nil || node.StartByte() < firstLegend.StartByte() {
				facts.firstFieldsetLegends[parentOffset] = node
			}
		}
		if parentName != "details" || childName != "summary" {
			continue
		}
		firstSummary := facts.firstDetailsSummaries[parentOffset]
		if firstSummary == nil || node.StartByte() < firstSummary.StartByte() {
			facts.firstDetailsSummaries[parentOffset] = node
		}
	}

	for _, node := range nodes {
		if node == nil || (node.Type() != "start_tag" && node.Type() != "self_closing_tag") || !htmlCompleteTag(node, src) {
			continue
		}
		if htmlIsInsideTemplate(node, src) {
			continue
		}
		tagName := htmlTagNameWithSrc(node, src)
		element := htmlElementForTag(node)
		attrs := parseHTMLAttributes(node, src)

		switch tagName {
		case "html":
			if facts.explicitHTML == nil {
				facts.explicitHTML = element
			}
		case "head":
			if facts.explicitHead == nil {
				facts.explicitHead = element
			}
		case "body":
			if facts.explicitBody == nil {
				facts.explicitBody = element
			}
		}

		if idAttr := htmlFirstCompleteAttribute(attrs, "id"); idAttr != nil && idAttr.hasValue {
			id := stdhtml.UnescapeString(idAttr.value)
			if id != "" {
				if _, exists := facts.idElements[id]; !exists {
					if len(facts.idElements) < maxTrackedIDs {
						facts.idElements[id] = node
					} else {
						facts.idsComplete = false
					}
				}
			}
		}

		if tagName == "label" {
			if forAttr := htmlFirstCompleteAttribute(attrs, "for"); forAttr != nil && forAttr.hasValue {
				target := stdhtml.UnescapeString(forAttr.value)
				if target != "" {
					if len(facts.labelsByFor[target]) < maxHTMLRelationTokens {
						facts.labelsByFor[target] = append(facts.labelsByFor[target], node)
					} else {
						facts.labelsComplete = false
					}
				}
			}
		}
	}

	for _, node := range nodes {
		if node == nil || (node.Type() != "start_tag" && node.Type() != "self_closing_tag") || !htmlCompleteTag(node, src) {
			continue
		}
		if htmlIsInsideTemplate(node, src) {
			continue
		}
		tagName := htmlTagNameWithSrc(node, src)
		element := htmlElementForTag(node)
		switch tagName {
		case "title":
			if facts.explicitHead != nil && element != nil && element.Parent() != nil &&
				element.Parent().StartByte() == facts.explicitHead.StartByte() {
				result := htmlVisibleDescendantText(node, src, false, false, newHTMLNameBudget())
				if result.present {
					facts.hasUsableTitle = true
				}
				if !result.reliable {
					facts.titleScanComplete = false
				}
			}
		case "main":
			attrs := parseHTMLAttributes(node, src)
			if htmlUsableMainLandmark(node, tagName, attrs, src) {
				facts.hasUsableMain = true
			}
		default:
			attrs := parseHTMLAttributes(node, src)
			if htmlRoleIs(attrs, "main") && htmlUsableMainLandmark(node, tagName, attrs, src) {
				facts.hasUsableMain = true
			}
		}
	}

	return facts
}

func htmlResolvedIDElement(facts *htmlMaintainabilityFacts, token string, src []byte) *sitter.Node {
	if facts == nil {
		return nil
	}
	reference := facts.idElements[token]
	if reference == nil || htmlIsInsideTemplate(reference, src) {
		return nil
	}
	return reference
}

func htmlTagHasHiddenState(attrs []htmlAttrInfo, includeAriaHidden bool) bool {
	if htmlFirstCompleteAttribute(attrs, "hidden") != nil || htmlFirstCompleteAttribute(attrs, "inert") != nil {
		return true
	}
	if includeAriaHidden {
		value, ok := htmlAttributeLiteralLower(attrs, "aria-hidden")
		return ok && value == "true"
	}
	return false
}

func htmlIsStaticallyHidden(tagNode *sitter.Node, src []byte, includeAriaHidden bool) bool {
	if tagNode == nil {
		return false
	}
	if htmlTagHasHiddenState(parseHTMLAttributes(tagNode, src), includeAriaHidden) {
		return true
	}
	depth := 0
	for parent := htmlElementForTag(tagNode); parent != nil && depth < maxHTMLDepth; parent = parent.Parent() {
		depth++
		if parent.Type() != "element" && parent.Type() != "script_element" && parent.Type() != "style_element" {
			continue
		}
		parentTag := htmlStartTagForElement(parent)
		if parentTag == nil || parentTag.StartByte() == tagNode.StartByte() {
			continue
		}
		if htmlTagNameWithSrc(parentTag, src) == "template" {
			return true
		}
		if htmlTagHasHiddenState(parseHTMLAttributes(parentTag, src), includeAriaHidden) {
			return true
		}
	}
	return false
}

func htmlIsInsideTemplate(tagNode *sitter.Node, src []byte) bool {
	depth := 0
	for parent := htmlElementForTag(tagNode); parent != nil && depth < maxHTMLDepth; parent = parent.Parent() {
		depth++
		if parent.Type() != "element" {
			continue
		}
		parentTag := htmlStartTagForElement(parent)
		if parentTag != nil && parentTag.StartByte() != tagNode.StartByte() && htmlTagNameWithSrc(parentTag, src) == "template" {
			return true
		}
	}
	return false
}

func newHTMLNameBudget() *htmlNameBudget {
	return &htmlNameBudget{visited: make(map[uint32]bool)}
}

func htmlNormalizedName(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func htmlNameFromAttribute(attr *htmlAttrInfo) htmlNameResult {
	value, ok := htmlDecodedTrimmedAttribute(attr)
	if !ok || value == "" {
		return htmlNameResult{reliable: true, comparable: true}
	}
	if htmlIsTemplateExpression(attr.value) || htmlIsTemplateExpression(value) {
		return htmlNameResult{present: true, reliable: true}
	}
	return htmlNameResult{
		value:      htmlNormalizedName(value),
		present:    true,
		reliable:   true,
		comparable: true,
	}
}

func htmlVisibleDescendantText(
	tagNode *sitter.Node,
	src []byte,
	allowImageAlt bool,
	includeHidden bool,
	budget *htmlNameBudget,
) htmlNameResult {
	if tagNode == nil {
		return htmlNameResult{reliable: true, comparable: true}
	}
	if !includeHidden && htmlIsStaticallyHidden(tagNode, src, true) {
		return htmlNameResult{reliable: true, comparable: true}
	}
	element := htmlElementForTag(tagNode)
	if element == nil {
		return htmlNameResult{reliable: true, comparable: true}
	}

	type item struct {
		node  *sitter.Node
		depth int
	}
	stack := make([]item, 0, int(element.ChildCount()))
	for i := int(element.ChildCount()) - 1; i >= 0; i-- {
		stack = append(stack, item{node: element.Child(i), depth: 0})
	}

	var parts []string
	comparable := true
	for len(stack) > 0 {
		if budget.nodes >= maxHTMLNameNodes || budget.bytes >= maxHTMLNameBytes {
			budget.exhausted = true
			break
		}
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		node := current.node
		if node == nil {
			continue
		}
		if current.depth > maxHTMLDepth {
			budget.exhausted = true
			continue
		}
		budget.nodes++

		switch node.Type() {
		case "comment", "script_element", "style_element", "ERROR", "start_tag", "self_closing_tag", "end_tag":
			continue
		case "text":
			raw := node.Content(src)
			remaining := maxHTMLNameBytes - budget.bytes
			if len(raw) > remaining {
				raw = raw[:remaining]
				budget.exhausted = true
			}
			budget.bytes += len(raw)
			decoded := htmlNormalizedName(stdhtml.UnescapeString(raw))
			if decoded != "" {
				parts = append(parts, decoded)
				if htmlIsTemplateExpression(raw) || htmlIsTemplateExpression(decoded) {
					comparable = false
				}
			}
			continue
		case "element":
			childTag := htmlStartTagForElement(node)
			if childTag != nil {
				childName := htmlTagNameWithSrc(childTag, src)
				if childName == "script" || childName == "style" || childName == "template" ||
					(!includeHidden && htmlIsStaticallyHidden(childTag, src, true)) {
					continue
				}
				if allowImageAlt && childName == "img" {
					alt := htmlNameFromAttribute(htmlFirstCompleteAttribute(parseHTMLAttributes(childTag, src), "alt"))
					if alt.present {
						if alt.comparable {
							parts = append(parts, alt.value)
						} else {
							comparable = false
							parts = append(parts, "dynamic-name")
						}
					}
				}
			}
		}

		for i := int(node.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, item{node: node.Child(i), depth: current.depth + 1})
		}
	}

	value := htmlNormalizedName(strings.Join(parts, " "))
	return htmlNameResult{
		value:      value,
		present:    value != "",
		reliable:   !budget.exhausted,
		comparable: comparable,
	}
}

func htmlAncestorLabel(tagNode *sitter.Node, src []byte) *sitter.Node {
	depth := 0
	for parent := htmlElementForTag(tagNode); parent != nil && depth < maxHTMLDepth; parent = parent.Parent() {
		depth++
		if parent.Type() != "element" {
			continue
		}
		parentTag := htmlStartTagForElement(parent)
		if parentTag != nil && parentTag.StartByte() != tagNode.StartByte() && htmlTagNameWithSrc(parentTag, src) == "label" {
			return parentTag
		}
	}
	return nil
}

func htmlStaticAccessibleName(
	element *sitter.Node,
	tagName string,
	attrs []htmlAttrInfo,
	facts *htmlMaintainabilityFacts,
	src []byte,
	mode htmlNameMode,
) htmlNameResult {
	return htmlStaticAccessibleNameAtDepth(
		element,
		tagName,
		attrs,
		facts,
		src,
		mode,
		newHTMLNameBudget(),
		0,
		false,
	)
}

func htmlStaticAccessibleNameAtDepth(
	element *sitter.Node,
	tagName string,
	attrs []htmlAttrInfo,
	facts *htmlMaintainabilityFacts,
	src []byte,
	mode htmlNameMode,
	budget *htmlNameBudget,
	depth int,
	includeHidden bool,
) htmlNameResult {
	if element == nil {
		return htmlNameResult{reliable: true, comparable: true}
	}
	if depth > maxHTMLReferenceDepth || budget.nodes >= maxHTMLNameNodes || budget.bytes >= maxHTMLNameBytes {
		budget.exhausted = true
		return htmlNameResult{}
	}
	if depth > 0 && tagName == "template" {
		return htmlNameResult{reliable: true, comparable: true}
	}
	if budget.visited[element.StartByte()] {
		return htmlNameResult{reliable: true, comparable: true}
	}
	budget.visited[element.StartByte()] = true
	defer delete(budget.visited, element.StartByte())

	labelledBy := htmlFirstCompleteAttribute(attrs, "aria-labelledby")
	if value, ok := htmlDecodedTrimmedAttribute(labelledBy); ok && value != "" {
		if htmlIsTemplateExpression(labelledBy.value) || htmlIsTemplateExpression(value) {
			return htmlNameResult{present: true, reliable: true}
		}
		tokens := htmlAttributeIDReferenceTokens(labelledBy)
		if len(tokens) > maxHTMLRelationTokens {
			budget.exhausted = true
			return htmlNameResult{}
		}
		var names []string
		comparable := true
		reliable := true
		for _, token := range tokens {
			reference := htmlResolvedIDElement(facts, token, src)
			if reference == nil {
				if !facts.idsComplete {
					reliable = false
				}
				continue
			}
			refAttrs := parseHTMLAttributes(reference, src)
			refName := htmlTagNameWithSrc(reference, src)
			result := htmlStaticAccessibleNameAtDepth(
				reference,
				refName,
				refAttrs,
				facts,
				src,
				htmlNameGeneric,
				budget,
				depth+1,
				true,
			)
			reliable = reliable && result.reliable
			comparable = comparable && result.comparable
			if result.present {
				if result.comparable {
					names = append(names, result.value)
				} else {
					names = append(names, "dynamic-name")
				}
			}
		}
		combined := htmlNormalizedName(strings.Join(names, " "))
		if combined != "" {
			return htmlNameResult{
				value:      combined,
				present:    true,
				reliable:   reliable && !budget.exhausted,
				comparable: comparable,
			}
		}
		if !reliable || budget.exhausted {
			return htmlNameResult{}
		}
	}

	if result := htmlNameFromAttribute(htmlFirstCompleteAttribute(attrs, "aria-label")); result.present {
		return result
	}

	switch {
	case tagName == "img" || tagName == "area":
		if result := htmlNameFromAttribute(htmlFirstCompleteAttribute(attrs, "alt")); result.present {
			return result
		}
	case tagName == "input":
		inputType, known := htmlInputType(attrs)
		if known {
			switch inputType {
			case "image":
				if result := htmlNameFromAttribute(htmlFirstCompleteAttribute(attrs, "alt")); result.present {
					return result
				}
			case "button":
				if result := htmlNameFromAttribute(htmlFirstCompleteAttribute(attrs, "value")); result.present {
					return result
				}
			case "submit", "reset":
				return htmlNameResult{value: inputType, present: true, reliable: true, comparable: true}
			}
		}
	}

	if mode == htmlNameIframe || mode == htmlNameLink || mode == htmlNameControl ||
		mode == htmlNameRoleImg || mode == htmlNameLandmark || mode == htmlNameFieldset || mode == htmlNameTable {
		if result := htmlNameFromAttribute(htmlFirstCompleteAttribute(attrs, "title")); result.present {
			return result
		}
	}

	if mode == htmlNameRoleImg || mode == htmlNameLandmark {
		return htmlNameResult{reliable: !budget.exhausted, comparable: true}
	}

	if mode == htmlNameControl {
		if label := htmlAncestorLabel(element, src); label != nil &&
			!htmlIsStaticallyHidden(label, src, true) {
			if result := htmlVisibleDescendantText(label, src, true, false, budget); result.present {
				return result
			}
		}
		if idAttr := htmlFirstCompleteAttribute(attrs, "id"); idAttr != nil && idAttr.hasValue {
			id := stdhtml.UnescapeString(idAttr.value)
			for _, label := range facts.labelsByFor[id] {
				if result := htmlVisibleDescendantText(label, src, true, false, budget); result.present {
					return result
				}
			}
			if !facts.labelsComplete {
				return htmlNameResult{}
			}
		}
	}

	if mode == htmlNameFieldset {
		firstChild := htmlFirstFieldsetElementChild(htmlElementForTag(element), facts)
		if firstChild != nil {
			firstTag := htmlStartTagForElement(firstChild)
			if firstTag != nil && htmlTagNameWithSrc(firstTag, src) == "legend" {
				return htmlVisibleDescendantText(firstTag, src, true, false, budget)
			}
		}
		return htmlNameResult{reliable: !budget.exhausted, comparable: true}
	}

	if mode == htmlNameTable {
		tableElement := htmlElementForTag(element)
		if tableElement == nil {
			return htmlNameResult{reliable: !budget.exhausted, comparable: true}
		}
		for i := 0; i < int(tableElement.ChildCount()); i++ {
			child := tableElement.Child(i)
			switch child.Type() {
			case "element", "script_element", "style_element":
			default:
				continue
			}
			childTag := htmlStartTagForElement(child)
			if childTag != nil && htmlTagNameWithSrc(childTag, src) == "caption" {
				return htmlVisibleDescendantText(childTag, src, true, false, budget)
			}
		}
		return htmlNameResult{reliable: !budget.exhausted, comparable: true}
	}

	allowImageAlt := mode == htmlNameButton || mode == htmlNameLink || mode == htmlNameHeading || mode == htmlNameGeneric
	return htmlVisibleDescendantText(element, src, allowImageAlt, includeHidden, budget)
}

func htmlFirstFieldsetElementChild(element *sitter.Node, facts *htmlMaintainabilityFacts) *sitter.Node {
	if element == nil || facts == nil {
		return nil
	}
	return facts.firstFieldsetChildren[element.StartByte()]
}

func htmlFirstFieldsetLegend(element *sitter.Node, facts *htmlMaintainabilityFacts) *sitter.Node {
	if element == nil || facts == nil {
		return nil
	}
	return facts.firstFieldsetLegends[element.StartByte()]
}

func htmlNodeIsDescendantOf(node, ancestor *sitter.Node) bool {
	if node == nil || ancestor == nil {
		return false
	}
	for current := node; current != nil; current = current.Parent() {
		if current.StartByte() == ancestor.StartByte() && current.EndByte() == ancestor.EndByte() {
			return true
		}
	}
	return false
}

func htmlDisabledByFieldset(tagNode *sitter.Node, src []byte, facts *htmlMaintainabilityFacts) bool {
	element := htmlElementForTag(tagNode)
	depth := 0
	for parent := element; parent != nil && depth < maxHTMLDepth; parent = parent.Parent() {
		depth++
		if parent.Type() != "element" {
			continue
		}
		parentTag := htmlStartTagForElement(parent)
		if parentTag == nil || htmlTagNameWithSrc(parentTag, src) != "fieldset" {
			continue
		}
		fieldsetAttrs := parseHTMLAttributes(parentTag, src)
		if htmlFirstCompleteAttribute(fieldsetAttrs, "disabled") == nil {
			continue
		}
		firstLegend := htmlFirstFieldsetLegend(parent, facts)
		if firstLegend != nil {
			legendTag := htmlStartTagForElement(firstLegend)
			if legendTag != nil && htmlNodeIsDescendantOf(element, firstLegend) {
				continue
			}
		}
		return true
	}
	return false
}

func htmlIsFirstSummary(tagNode *sitter.Node, src []byte, facts *htmlMaintainabilityFacts) bool {
	element := htmlElementForTag(tagNode)
	if element == nil || element.Parent() == nil || element.Parent().Type() != "element" || facts == nil {
		return false
	}
	parent := element.Parent()
	parentTag := htmlStartTagForElement(parent)
	if parentTag == nil || htmlTagNameWithSrc(parentTag, src) != "details" {
		return false
	}
	firstSummary := facts.firstDetailsSummaries[parent.StartByte()]
	if firstSummary == nil {
		return false
	}
	firstTag := htmlStartTagForElement(firstSummary)
	return firstTag != nil && firstTag.StartByte() == tagNode.StartByte()
}

func htmlLiteralTabIndex(attrs []htmlAttrInfo) (int, bool) {
	attr := htmlFirstCompleteAttribute(attrs, "tabindex")
	value, ok := htmlDecodedTrimmedAttribute(attr)
	if !ok || value == "" || htmlIsTemplateExpression(attr.value) || htmlIsTemplateExpression(value) {
		return 0, false
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return number, true
}

func htmlIsSequentiallyFocusable(
	tagNode *sitter.Node,
	src []byte,
	ignoreAriaHidden bool,
	facts *htmlMaintainabilityFacts,
) bool {
	if tagNode == nil || !htmlCompleteTag(tagNode, src) || htmlIsInsideTemplate(tagNode, src) ||
		htmlIsStaticallyHidden(tagNode, src, !ignoreAriaHidden) {
		return false
	}
	tagName := htmlTagNameWithSrc(tagNode, src)
	attrs := parseHTMLAttributes(tagNode, src)
	tabIndex, hasTabIndex := htmlLiteralTabIndex(attrs)
	if hasTabIndex && tabIndex < 0 {
		return false
	}
	disabledControl := tagName == "button" || tagName == "input" || tagName == "select" ||
		tagName == "textarea" || tagName == "option" || tagName == "optgroup" ||
		tagName == "fieldset"
	if disabledControl && (htmlFirstCompleteAttribute(attrs, "disabled") != nil || htmlDisabledByFieldset(tagNode, src, facts)) {
		return false
	}
	if inputType, known := htmlInputType(attrs); tagName == "input" && known && inputType == "hidden" {
		return false
	}
	if hasTabIndex && tabIndex >= 0 {
		return true
	}

	switch tagName {
	case "a", "area":
		return htmlFirstCompleteAttribute(attrs, "href") != nil
	case "button", "select", "textarea", "iframe":
		return true
	case "input":
		inputType, known := htmlInputType(attrs)
		return known && inputType != "hidden"
	case "summary":
		return htmlIsFirstSummary(tagNode, src, facts)
	case "audio", "video":
		return htmlFirstCompleteAttribute(attrs, "controls") != nil
	}

	contentEditable := htmlFirstCompleteAttribute(attrs, "contenteditable")
	if contentEditable != nil {
		if !contentEditable.hasValue {
			return true
		}
		value := htmlASCIILower(htmlTrimASCIIWhitespace(stdhtml.UnescapeString(contentEditable.value)))
		if htmlIsTemplateExpression(contentEditable.value) || htmlIsTemplateExpression(value) {
			return false
		}
		return value == "" || value == "true" || value == "plaintext-only"
	}
	return false
}

func htmlIsStrictInteractive(tagNode *sitter.Node, src []byte, facts *htmlMaintainabilityFacts) bool {
	if tagNode == nil || htmlIsStaticallyHidden(tagNode, src, true) {
		return false
	}
	tagName := htmlTagNameWithSrc(tagNode, src)
	attrs := parseHTMLAttributes(tagNode, src)
	switch tagName {
	case "a":
		if htmlFirstCompleteAttribute(attrs, "href") != nil {
			return true
		}
	case "button":
		return true
	case "summary":
		return htmlIsFirstSummary(tagNode, src, facts)
	}
	return htmlRoleIs(attrs, "button", "link")
}

func htmlHasStrictInteractiveAncestor(tagNode *sitter.Node, src []byte, facts *htmlMaintainabilityFacts) bool {
	depth := 0
	for parent := htmlElementForTag(tagNode); parent != nil && depth < maxHTMLDepth; parent = parent.Parent() {
		depth++
		if parent.Type() != "element" {
			continue
		}
		parentTag := htmlStartTagForElement(parent)
		if parentTag != nil && parentTag.StartByte() != tagNode.StartByte() && htmlIsStrictInteractive(parentTag, src, facts) {
			return true
		}
	}
	return false
}

func htmlHasFocusableSelfOrDescendant(tagNode *sitter.Node, src []byte, facts *htmlMaintainabilityFacts) bool {
	if htmlIsSequentiallyFocusable(tagNode, src, true, facts) {
		return true
	}
	element := htmlElementForTag(tagNode)
	if element == nil {
		return false
	}
	type item struct {
		node  *sitter.Node
		depth int
	}
	stack := []item{{node: element, depth: 0}}
	seen := 0
	for len(stack) > 0 && seen < maxHTMLNameNodes {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.node == nil || current.depth > maxHTMLDepth {
			continue
		}
		seen++
		if current.node.Type() == "element" && current.node.StartByte() != element.StartByte() {
			childTag := htmlStartTagForElement(current.node)
			if childTag != nil {
				if htmlIsSequentiallyFocusable(childTag, src, true, facts) {
					return true
				}
				childName := htmlTagNameWithSrc(childTag, src)
				childAttrs := parseHTMLAttributes(childTag, src)
				if childName == "template" || htmlTagHasHiddenState(childAttrs, false) {
					continue
				}
			}
		}
		for i := int(current.node.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, item{node: current.node.Child(i), depth: current.depth + 1})
		}
	}
	return false
}

func htmlNearestAncestorTable(tagNode *sitter.Node, src []byte) *sitter.Node {
	depth := 0
	for parent := htmlElementForTag(tagNode); parent != nil && depth < maxHTMLDepth; parent = parent.Parent() {
		depth++
		if parent.Type() != "element" {
			continue
		}
		parentTag := htmlStartTagForElement(parent)
		if parentTag != nil && htmlTagNameWithSrc(parentTag, src) == "table" {
			return parentTag
		}
	}
	return nil
}

func htmlHasDescendantTag(
	tagNode *sitter.Node,
	src []byte,
	stopAtSameTag bool,
	wanted func(string, []htmlAttrInfo) bool,
) htmlScanResult {
	element := htmlElementForTag(tagNode)
	if element == nil {
		return htmlScanResult{reliable: true}
	}
	type item struct {
		node  *sitter.Node
		depth int
	}
	stack := []item{{node: element, depth: 0}}
	seen := 0
	rootName := htmlTagNameWithSrc(tagNode, src)
	reliable := true
	for len(stack) > 0 {
		if seen >= maxHTMLNameNodes {
			reliable = false
			break
		}
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.node == nil {
			continue
		}
		if current.depth > maxHTMLDepth {
			reliable = false
			continue
		}
		seen++
		if current.node.Type() == "element" && current.node.StartByte() != element.StartByte() {
			childTag := htmlStartTagForElement(current.node)
			if childTag != nil {
				childName := htmlTagNameWithSrc(childTag, src)
				childAttrs := parseHTMLAttributes(childTag, src)
				if wanted(childName, childAttrs) {
					return htmlScanResult{found: true, reliable: true}
				}
				if childName == "template" || (stopAtSameTag && childName == rootName) {
					continue
				}
			}
		}
		for i := int(current.node.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, item{node: current.node.Child(i), depth: current.depth + 1})
		}
	}
	return htmlScanResult{reliable: reliable}
}

func htmlApplicableLabelControl(tagName string, attrs []htmlAttrInfo) bool {
	switch tagName {
	case "select", "textarea":
		return true
	case "input":
		inputType, known := htmlInputType(attrs)
		if !known {
			return false
		}
		switch inputType {
		case "hidden", "button", "submit", "reset", "image":
			return false
		}
		return true
	}
	return false
}

func htmlUsableMainLandmark(tagNode *sitter.Node, tagName string, attrs []htmlAttrInfo, src []byte) bool {
	if htmlIsStaticallyHidden(tagNode, src, true) {
		return false
	}
	role, _, hasRole := htmlFirstValidConcreteRole(attrs)
	if tagName == "main" {
		return !hasRole || (role != "none" && role != "presentation")
	}
	return hasRole && role == "main"
}

func htmlHeadingLevel(tagName string, attrs []htmlAttrInfo) (int, bool) {
	if len(tagName) == 2 && tagName[0] == 'h' && tagName[1] >= '1' && tagName[1] <= '6' {
		return int(tagName[1] - '0'), true
	}
	if !htmlRoleIs(attrs, "heading") {
		return 0, false
	}
	levelAttr := htmlFirstCompleteAttribute(attrs, "aria-level")
	value, ok := htmlDecodedTrimmedAttribute(levelAttr)
	if !ok || htmlIsTemplateExpression(levelAttr.value) || htmlIsTemplateExpression(value) {
		return 0, false
	}
	level, err := strconv.Atoi(value)
	return level, err == nil && level >= 1
}

func htmlIsHeading(tagName string, attrs []htmlAttrInfo) bool {
	if len(tagName) == 2 && tagName[0] == 'h' && tagName[1] >= '1' && tagName[1] <= '6' {
		return true
	}
	return htmlRoleIs(attrs, "heading")
}

func htmlImplicitRole(tagName string, attrs []htmlAttrInfo) htmlImplicitRoleResult {
	switch tagName {
	case "button":
		return htmlImplicitRoleResult{role: "button", known: true}
	case "a":
		if htmlFirstCompleteAttribute(attrs, "href") != nil {
			return htmlImplicitRoleResult{role: "link", known: true}
		}
	case "h1", "h2", "h3", "h4", "h5", "h6":
		return htmlImplicitRoleResult{role: "heading", known: true}
	case "meter":
		return htmlImplicitRoleResult{role: "meter", known: true}
	case "select":
		if htmlFirstCompleteAttribute(attrs, "multiple") != nil {
			return htmlImplicitRoleResult{role: "listbox", known: true}
		}
		sizeAttr := htmlFirstCompleteAttribute(attrs, "size")
		if sizeAttr == nil {
			return htmlImplicitRoleResult{role: "combobox", known: true}
		}
		sizeValue, ok := htmlDecodedTrimmedAttribute(sizeAttr)
		if ok && (htmlIsTemplateExpression(sizeAttr.value) || htmlIsTemplateExpression(sizeValue)) {
			return htmlImplicitRoleResult{}
		}
		if ok {
			if size, err := strconv.Atoi(sizeValue); err == nil && size > 1 {
				return htmlImplicitRoleResult{role: "listbox", known: true}
			}
		}
		return htmlImplicitRoleResult{role: "combobox", known: true}
	case "input":
		inputType, known := htmlInputType(attrs)
		if !known {
			return htmlImplicitRoleResult{}
		}
		switch inputType {
		case "checkbox":
			return htmlImplicitRoleResult{role: "checkbox", known: true}
		case "radio":
			return htmlImplicitRoleResult{role: "radio", known: true}
		case "range":
			return htmlImplicitRoleResult{role: "slider", known: true}
		case "number":
			return htmlImplicitRoleResult{role: "spinbutton", known: true}
		}
	}
	return htmlImplicitRoleResult{known: true}
}

func htmlRequiredARIAPropertiesPresent(attrs []htmlAttrInfo, properties []string) bool {
	for _, property := range properties {
		attr := htmlFirstCompleteAttribute(attrs, property)
		value, ok := htmlDecodedTrimmedAttribute(attr)
		if !ok || value == "" {
			return false
		}
	}
	return true
}

func htmlObjectHasFallback(tagNode *sitter.Node, src []byte) htmlScanResult {
	text := htmlVisibleDescendantText(tagNode, src, true, false, newHTMLNameBudget())
	if text.present {
		return htmlScanResult{found: true, reliable: true}
	}
	element := htmlHasDescendantTag(tagNode, src, false, func(name string, _ []htmlAttrInfo) bool {
		return name != "" && name != "param" && name != "script" && name != "style" && name != "template"
	})
	if element.found {
		return element
	}
	return htmlScanResult{reliable: text.reliable && element.reliable}
}

func htmlFieldsetControlCount(tagNode *sitter.Node, src []byte) int {
	element := htmlElementForTag(tagNode)
	if element == nil {
		return 0
	}
	type item struct {
		node  *sitter.Node
		depth int
	}
	stack := []item{{node: element, depth: 0}}
	count := 0
	seen := 0
	for len(stack) > 0 && seen < maxHTMLNameNodes && count < 2 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.node == nil || current.depth > maxHTMLDepth {
			continue
		}
		seen++
		if current.node.Type() == "element" && current.node.StartByte() != element.StartByte() {
			childTag := htmlStartTagForElement(current.node)
			if childTag != nil {
				childName := htmlTagNameWithSrc(childTag, src)
				childAttrs := parseHTMLAttributes(childTag, src)
				if htmlIsStaticallyHidden(childTag, src, true) {
					continue
				}
				if htmlApplicableLabelControl(childName, childAttrs) {
					count++
				}
				if childName == "fieldset" || childName == "template" {
					continue
				}
			}
		}
		for i := int(current.node.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, item{node: current.node.Child(i), depth: current.depth + 1})
		}
	}
	return count
}

func htmlScriptTypeDeprecated(attr *htmlAttrInfo) bool {
	if attr == nil {
		return false
	}
	if !attr.hasValue {
		return true
	}
	value := htmlASCIILower(htmlTrimASCIIWhitespace(stdhtml.UnescapeString(attr.value)))
	if htmlIsTemplateExpression(attr.value) || htmlIsTemplateExpression(value) {
		return false
	}
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = htmlTrimASCIIWhitespace(value[:semi])
	}
	return value == "" || htmlJavaScriptMIMEEssences[value]
}

func htmlValidMetaRefreshContent(contentAttr *htmlAttrInfo) bool {
	if contentAttr == nil || !contentAttr.hasValue {
		return false
	}
	content := htmlTrimASCIIWhitespace(stdhtml.UnescapeString(contentAttr.value))
	if content == "" || htmlIsTemplateExpression(contentAttr.value) || htmlIsTemplateExpression(content) {
		return false
	}

	delayText := content
	remainder := ""
	if semi := strings.IndexByte(content, ';'); semi >= 0 {
		delayText = htmlTrimASCIIWhitespace(content[:semi])
		remainder = htmlTrimASCIIWhitespace(content[semi+1:])
	}
	if !htmlValidMetaRefreshDelay(delayText) {
		return false
	}
	if remainder == "" {
		return true
	}

	lowerRemainder := htmlASCIILower(remainder)
	if strings.HasPrefix(lowerRemainder, "url") {
		afterURL := htmlTrimASCIIWhitespace(remainder[len("url"):])
		if strings.HasPrefix(afterURL, "=") {
			return htmlTrimASCIIWhitespace(afterURL[1:]) != ""
		}
	}
	return true
}

func htmlValidMetaRefreshDelay(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func htmlViewportDisablesZoom(contentAttr *htmlAttrInfo) bool {
	if contentAttr == nil || !contentAttr.hasValue {
		return false
	}
	content := stdhtml.UnescapeString(contentAttr.value)
	if htmlIsTemplateExpression(contentAttr.value) || htmlIsTemplateExpression(content) {
		return false
	}
	directives := strings.FieldsFunc(content, func(r rune) bool { return r == ',' || r == ';' })
	for _, directive := range directives {
		parts := strings.SplitN(directive, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := htmlASCIILower(htmlTrimASCIIWhitespace(parts[0]))
		value := htmlASCIILower(htmlTrimASCIIWhitespace(parts[1]))
		switch name {
		case "user-scalable":
			if value == "no" || value == "0" {
				return true
			}
		case "maximum-scale":
			number, err := strconv.ParseFloat(value, 64)
			if err == nil && number >= 0 && number < 2 {
				return true
			}
		}
	}
	return false
}

func collectHTMLMaintainabilityCandidates(
	tagNode *sitter.Node,
	tagName string,
	attrs []htmlAttrInfo,
	src []byte,
	facts *htmlMaintainabilityFacts,
	state *htmlMaintainabilityState,
) []htmlMaintainabilityCandidate {
	if tagNode == nil || facts == nil || !facts.traversalComplete || state == nil || !htmlCompleteTag(tagNode, src) ||
		htmlIsInsideTemplate(tagNode, src) || htmlIsInForeignContent(tagNode, src, maxHTMLDepth) {
		return nil
	}

	var candidates []htmlMaintainabilityCandidate
	order := 0
	add := func(rule string, line int, offset uint32) {
		candidates = append(candidates, htmlMaintainabilityCandidate{
			rule: rule, line: line, offset: offset, order: order,
		})
		order++
	}
	startLine := int(tagNode.StartPoint().Row) + 1

	role, roleAttr, hasConcreteRole := htmlFirstValidConcreteRole(attrs)
	hidden := htmlIsStaticallyHidden(tagNode, src, true)

	if tagName == "img" && !hidden && role != "none" && role != "presentation" {
		if htmlFirstCompleteAttribute(attrs, "alt") == nil {
			add("img-alt-missing", startLine, tagNode.StartByte())
		}
	}

	if tagName == "area" && !hidden && htmlKnownStaticNonEmptyAttribute(htmlFirstCompleteAttribute(attrs, "href")) {
		alt := htmlFirstCompleteAttribute(attrs, "alt")
		if !htmlUsableAttribute(alt) {
			if alt != nil {
				add("area-alt-missing", alt.line, alt.byteOffset)
			} else {
				add("area-alt-missing", startLine, tagNode.StartByte())
			}
		}
	}

	if tagName == "input" && !hidden {
		if inputType, known := htmlInputType(attrs); known && inputType == "image" {
			alt := htmlFirstCompleteAttribute(attrs, "alt")
			if !htmlUsableAttribute(alt) {
				if alt != nil {
					add("input-image-alt-missing", alt.line, alt.byteOffset)
				} else {
					add("input-image-alt-missing", startLine, tagNode.StartByte())
				}
			}
		}
	}

	if tagName == "object" {
		fallback := htmlObjectHasFallback(tagNode, src)
		if fallback.reliable && !fallback.found {
			add("object-fallback-missing", startLine, tagNode.StartByte())
		}
	}

	if tagName == "iframe" && !hidden {
		name := htmlStaticAccessibleName(tagNode, tagName, attrs, facts, src, htmlNameIframe)
		if name.reliable && !name.present {
			title := htmlFirstCompleteAttribute(attrs, "title")
			if title != nil {
				add("iframe-title-missing", title.line, title.byteOffset)
			} else {
				add("iframe-title-missing", startLine, tagNode.StartByte())
			}
		}
	}

	element := htmlElementForTag(tagNode)
	if tagName == "html" && facts.explicitHTML != nil && element != nil && element.StartByte() == facts.explicitHTML.StartByte() {
		if !facts.hasUsableTitle && facts.titleScanComplete {
			add("html-title-missing", startLine, tagNode.StartByte())
		}
		lang := htmlFirstCompleteAttribute(attrs, "lang")
		if !htmlUsableAttribute(lang) {
			if lang != nil {
				add("missing-lang", lang.line, lang.byteOffset)
			} else {
				add("missing-lang", startLine, tagNode.StartByte())
			}
		}
		if facts.explicitBody == nil && !facts.hasUsableMain && !state.mainMissingEmitted {
			add("main-landmark-missing", startLine, tagNode.StartByte())
			state.mainMissingEmitted = true
		}
	}

	if tagName == "body" && facts.explicitBody != nil && element != nil && element.StartByte() == facts.explicitBody.StartByte() &&
		!facts.hasUsableMain && !state.mainMissingEmitted {
		add("main-landmark-missing", startLine, tagNode.StartByte())
		state.mainMissingEmitted = true
	}

	if !hidden && htmlApplicableLabelControl(tagName, attrs) {
		name := htmlStaticAccessibleName(tagNode, tagName, attrs, facts, src, htmlNameControl)
		if name.reliable && !name.present {
			add("label-missing", startLine, tagNode.StartByte())
		}
	}

	isButton := tagName == "button" || (hasConcreteRole && role == "button")
	if tagName == "input" {
		if inputType, known := htmlInputType(attrs); known {
			switch inputType {
			case "image":
				isButton = false
			case "button", "submit", "reset":
				isButton = true
			}
		}
	}
	if !hidden && isButton {
		name := htmlStaticAccessibleName(tagNode, tagName, attrs, facts, src, htmlNameButton)
		if name.reliable && !name.present {
			add("button-name-missing", startLine, tagNode.StartByte())
		}
	}

	isLink := tagName != "area" && ((tagName == "a" && htmlFirstCompleteAttribute(attrs, "href") != nil) ||
		(hasConcreteRole && role == "link"))
	if !hidden && isLink {
		name := htmlStaticAccessibleName(tagNode, tagName, attrs, facts, src, htmlNameLink)
		if name.reliable && !name.present {
			add("link-name-missing", startLine, tagNode.StartByte())
		}
	}

	if tagName == "fieldset" && !hidden && htmlFieldsetControlCount(tagNode, src) >= 2 {
		name := htmlStaticAccessibleName(tagNode, tagName, attrs, facts, src, htmlNameFieldset)
		if name.reliable && !name.present {
			add("fieldset-legend-missing", startLine, tagNode.StartByte())
		}
	}

	if !hidden && (tagName == "table" || (hasConcreteRole && (role == "table" || role == "grid" || role == "treegrid"))) {
		isDataTable := hasConcreteRole && (role == "table" || role == "grid" || role == "treegrid")
		if tagName == "table" && role != "none" && role != "presentation" && !isDataTable {
			result := htmlHasDescendantTag(tagNode, src, true, func(name string, _ []htmlAttrInfo) bool {
				return name == "th"
			})
			isDataTable = result.found
		}
		if isDataTable {
			name := htmlStaticAccessibleName(tagNode, tagName, attrs, facts, src, htmlNameTable)
			if name.reliable && !name.present {
				add("table-caption-missing", startLine, tagNode.StartByte())
			}
		}
	}

	if tagName == "td" || tagName == "th" {
		headers := htmlFirstCompleteAttribute(attrs, "headers")
		if headers != nil {
			value, ok := htmlDecodedTrimmedAttribute(headers)
			if !ok {
				add("table-header-reference-missing", headers.line, headers.byteOffset)
			} else if !htmlIsTemplateExpression(headers.value) && !htmlIsTemplateExpression(value) {
				tokens := htmlAttributeIDReferenceTokens(headers)
				invalid := len(tokens) == 0
				if len(tokens) <= maxHTMLRelationTokens {
					currentTable := htmlNearestAncestorTable(tagNode, src)
					for _, token := range tokens {
						ref := htmlResolvedIDElement(facts, token, src)
						if ref == nil {
							if facts.idsComplete {
								invalid = true
							}
							break
						}
						if htmlTagNameWithSrc(ref, src) != "th" {
							invalid = true
							break
						}
						refTable := htmlNearestAncestorTable(ref, src)
						if currentTable == nil || refTable == nil || currentTable.StartByte() != refTable.StartByte() {
							invalid = true
							break
						}
					}
					if invalid {
						add("table-header-reference-missing", headers.line, headers.byteOffset)
					}
				}
			}
		}
	}

	if htmlIsHeading(tagName, attrs) {
		if !hidden {
			name := htmlStaticAccessibleName(tagNode, tagName, attrs, facts, src, htmlNameHeading)
			if name.reliable && !name.present {
				add("heading-empty", startLine, tagNode.StartByte())
			}
		}
	}
	if level, isHeading := htmlHeadingLevel(tagName, attrs); isHeading && !hidden {
		if state.lastHeadingLevel > 0 && level > state.lastHeadingLevel+1 {
			add("heading-order", startLine, tagNode.StartByte())
		}
		state.lastHeadingLevel = level
	}

	if htmlUsableMainLandmark(tagNode, tagName, attrs, src) {
		state.mainLandmarkCount++
		name := htmlStaticAccessibleName(tagNode, tagName, attrs, facts, src, htmlNameLandmark)
		if state.mainLandmarkCount == 1 {
			if name.present && name.reliable && name.comparable {
				state.mainLandmarkNames[htmlASCIILower(name.value)] = true
			}
		} else if name.reliable {
			if !name.present {
				add("duplicate-main-landmark", startLine, tagNode.StartByte())
			} else if name.comparable {
				key := htmlASCIILower(name.value)
				if state.mainLandmarkNames[key] {
					add("duplicate-main-landmark", startLine, tagNode.StartByte())
				} else {
					state.mainLandmarkNames[key] = true
				}
			}
		}
	}

	if tabIndex := htmlFirstCompleteAttribute(attrs, "tabindex"); tabIndex != nil {
		if value, ok := htmlLiteralTabIndex(attrs); ok && value > 0 {
			add("tabindex-positive", tabIndex.line, tabIndex.byteOffset)
		}
	}

	if accessKey := htmlFirstCompleteAttribute(attrs, "accesskey"); accessKey != nil && htmlKnownStaticNonEmptyAttribute(accessKey) {
		add("accesskey-used", accessKey.line, accessKey.byteOffset)
	}

	if autofocus := htmlFirstCompleteAttribute(attrs, "autofocus"); autofocus != nil {
		add("autofocus-used", autofocus.line, autofocus.byteOffset)
	}

	if htmlIsSequentiallyFocusable(tagNode, src, false, facts) && htmlHasStrictInteractiveAncestor(tagNode, src, facts) &&
		!state.nestedInteractiveSeen[tagNode.StartByte()] {
		state.nestedInteractiveSeen[tagNode.StartByte()] = true
		add("nested-interactive-control", startLine, tagNode.StartByte())
	}

	ariaHidden := htmlFirstCompleteAttribute(attrs, "aria-hidden")
	if value, ok := htmlAttributeLiteralLower(attrs, "aria-hidden"); ok && value == "true" {
		if htmlHasFocusableSelfOrDescendant(tagNode, src, facts) {
			add("aria-hidden-focusable", ariaHidden.line, ariaHidden.byteOffset)
		}
		if tagName == "body" {
			add("aria-hidden-body", ariaHidden.line, ariaHidden.byteOffset)
		}
	}

	for idx := range attrs {
		attr := &attrs[idx]
		if !htmlARIAReferenceAttributes[attr.lowerName] || htmlFirstCompleteAttribute(attrs, attr.lowerName) != attr {
			continue
		}
		value, ok := htmlDecodedTrimmedAttribute(attr)
		if !ok {
			add("aria-reference-missing", attr.line, attr.byteOffset)
			continue
		}
		if htmlIsTemplateExpression(attr.value) || htmlIsTemplateExpression(value) {
			continue
		}
		tokens := htmlAttributeIDReferenceTokens(attr)
		invalid := len(tokens) == 0
		if len(tokens) > maxHTMLRelationTokens {
			continue
		}
		for _, token := range tokens {
			if htmlResolvedIDElement(facts, token, src) == nil {
				invalid = facts.idsComplete
				break
			}
		}
		if invalid {
			add("aria-reference-missing", attr.line, attr.byteOffset)
		}
	}

	if roleAttr != nil {
		value, ok := htmlDecodedTrimmedAttribute(roleAttr)
		if ok && value != "" && !htmlIsTemplateExpression(roleAttr.value) && !htmlIsTemplateExpression(value) && !hasConcreteRole {
			add("aria-role-invalid", roleAttr.line, roleAttr.byteOffset)
		}
	}

	implicitRole := htmlImplicitRole(tagName, attrs)
	if !hidden && hasConcreteRole && roleAttr != nil && implicitRole.known && implicitRole.role != role {
		if required := htmlARIARequiredProperties[role]; len(required) > 0 {
			applicable := role != "separator" || htmlIsSequentiallyFocusable(tagNode, src, false, facts)
			if applicable && !htmlRequiredARIAPropertiesPresent(attrs, required) {
				add("aria-required-attribute-missing", roleAttr.line, roleAttr.byteOffset)
			}
		}
	}

	if hasConcreteRole && role == "img" && !hidden {
		alt := htmlFirstCompleteAttribute(attrs, "alt")
		if !(tagName == "img" && alt == nil) {
			name := htmlStaticAccessibleName(tagNode, tagName, attrs, facts, src, htmlNameRoleImg)
			if name.reliable && !name.present {
				add("role-img-name-missing", roleAttr.line, roleAttr.byteOffset)
			}
		}
	}

	if tagName == "meta" {
		httpEquiv := htmlFirstCompleteAttribute(attrs, "http-equiv")
		httpEquivValue, httpEquivOK := htmlAttributeLiteralLower(attrs, "http-equiv")
		content := htmlFirstCompleteAttribute(attrs, "content")
		if httpEquivOK && httpEquivValue == "refresh" && htmlValidMetaRefreshContent(content) {
			add("meta-refresh-used", httpEquiv.line, httpEquiv.byteOffset)
		}

		nameValue, nameOK := htmlAttributeLiteralLower(attrs, "name")
		if nameOK && nameValue == "viewport" && htmlViewportDisablesZoom(content) {
			add("viewport-zoom-disabled", content.line, content.byteOffset)
		}
	}

	if (tagName == "audio" || tagName == "video") &&
		htmlFirstCompleteAttribute(attrs, "autoplay") != nil &&
		htmlFirstCompleteAttribute(attrs, "muted") == nil {
		autoplay := htmlFirstCompleteAttribute(attrs, "autoplay")
		add("media-autoplay", autoplay.line, autoplay.byteOffset)
	}

	if htmlDeprecatedTags[tagName] {
		add("deprecated-tag", startLine, tagNode.StartByte())
	}

	seenAttribute := make(map[string]bool)
	for idx := range attrs {
		attr := &attrs[idx]
		if seenAttribute[attr.lowerName] || !attr.complete {
			continue
		}
		seenAttribute[attr.lowerName] = true
		isDeprecated := htmlAlwaysDeprecatedAttributes[attr.lowerName] ||
			(htmlDeprecatedAttributes[tagName] != nil && htmlDeprecatedAttributes[tagName][attr.lowerName])
		if tagName == "script" && attr.lowerName == "type" {
			isDeprecated = htmlScriptTypeDeprecated(attr)
		}
		if tagName == "input" && (attr.lowerName == "maxlength" || attr.lowerName == "size") {
			inputType, known := htmlInputType(attrs)
			isDeprecated = known && inputType == "number"
		}
		if isDeprecated {
			add("deprecated-attribute", attr.line, attr.byteOffset)
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].offset != candidates[j].offset {
			return candidates[i].offset < candidates[j].offset
		}
		return candidates[i].order < candidates[j].order
	})
	return candidates
}
