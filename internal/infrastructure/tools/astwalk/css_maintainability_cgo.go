//go:build cgo

package astwalk

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

type cssMaintContext struct {
	src                 []byte
	rel                 string
	offsets             []int
	collector           *cssCollector
	selectorOccurrences map[cssScopedDigest]cssOccurrence
	mediaOccurrences    map[cssScopedDigest]cssOccurrence
	importOccurrences   map[[32]byte]cssOccurrence
	keyframeOccurrences map[cssScopedName]cssOccurrence
	fontFaceOccurrences map[[32]byte]cssOccurrence
}

type cssMaintBlockContext uint8

const (
	cssMaintBlockDefault cssMaintBlockContext = iota
	cssMaintBlockPage
	cssMaintBlockGrouping
	cssMaintBlockKeyframe
)

func newCSSMaintContext(src []byte, rel string, collector *cssCollector) *cssMaintContext {
	return &cssMaintContext{
		src:                 src,
		rel:                 rel,
		offsets:             cssNewlineOffsets(src),
		collector:           collector,
		selectorOccurrences: make(map[cssScopedDigest]cssOccurrence),
		mediaOccurrences:    make(map[cssScopedDigest]cssOccurrence),
		importOccurrences:   make(map[[32]byte]cssOccurrence),
		keyframeOccurrences: make(map[cssScopedName]cssOccurrence),
		fontFaceOccurrences: make(map[[32]byte]cssOccurrence),
	}
}

func collectCSSMaintainabilityFindings(root *sitter.Node, src []byte, rel string, collector *cssCollector) {
	ctx := newCSSMaintContext(src, rel, collector)
	ctx.walkMaintainabilityNode(root, nil, 0)
}

func trackCSSOccurrence[K comparable](items map[K]cssOccurrence, key K, line int) bool {
	if _, exists := items[key]; exists {
		return true
	}
	if len(items) >= cssMaxTrackedItems {
		return false
	}
	items[key] = cssOccurrence{Line: line}
	return false
}

func (ctx *cssMaintContext) walkMaintainabilityNode(n *sitter.Node, scopeChain []string, depth int) {
	if depth > cssMaxMaintainabilityDepth {
		return
	}
	if n == nil {
		return
	}

	typ := n.Type()

	if typ == "comment" {
		ctx.checkTodoComment(n)
	}

	if n.IsMissing() {
		return
	}
	if n.IsError() {
		for i := 0; i < int(n.ChildCount()); i++ {
			ctx.walkMaintainabilityNode(n.Child(i), scopeChain, depth+1)
		}
		return
	}

	keyword := ""
	if typ == "at_rule" || typ == "media_statement" || typ == "keyframes_statement" || typ == "import_statement" || typ == "font_face_statement" {
		keyword = ctx.getAtRuleKeyword(n)
	}

	if typ == "rule_set" {
		// Recover through malformed siblings without producing semantic findings
		// from the malformed rule itself.
		if !n.HasError() {
			ctx.checkRuleSet(n, scopeChain)
		}
	} else if typ == "block" {
		// A parser-recovery block can be structurally empty while its source is
		// incomplete. It is not an empty declaration block for this rule family.
		if !n.HasError() {
			parentType := n.Parent().Type()
			parentKeyword := ctx.getAtRuleKeyword(n.Parent())
			if blockContext, ok := cssMaintainabilityBlockContext(parentType, parentKeyword); ok {
				ctx.checkBlockMaintainability(n, blockContext)
			}
		}
	} else if typ == "media_statement" || keyword == "@media" {
		ctx.checkMediaStatement(n, scopeChain, depth)
	} else if typ == "keyframes_statement" || strings.Contains(keyword, "keyframes") {
		ctx.checkKeyframesStatementMaint(n, scopeChain, keyword)
	} else if typ == "import_statement" || keyword == "@import" {
		ctx.checkImportStatementMaint(n)
	} else if typ == "font_face_statement" || keyword == "@font-face" {
		ctx.checkFontFaceStatementMaint(n)
	}

	childScope := scopeChain
	if isGroupingAtRule(typ, keyword) {
		prelude := ctx.getNodePrelude(n)
		if prelude != "" {
			childScope = append([]string(nil), scopeChain...)
			childScope = append(childScope, groupingAtRuleKeyword(typ, keyword)+"\x00"+prelude)
		}
	}

	for i := 0; i < int(n.ChildCount()); i++ {
		ctx.walkMaintainabilityNode(n.Child(i), childScope, depth+1)
	}
}

func cssMaintainabilityBlockContext(parentType, parentKeyword string) (cssMaintBlockContext, bool) {
	switch {
	case parentType == "rule_set":
		return cssMaintBlockDefault, true
	case parentType == "keyframe_block":
		return cssMaintBlockKeyframe, true
	case parentType == "page_statement" || parentKeyword == "@page":
		return cssMaintBlockPage, true
	case isGroupingAtRule(parentType, parentKeyword):
		return cssMaintBlockGrouping, true
	case parentType == "at_rule" && parentKeyword == "":
		return cssMaintBlockDefault, true
	default:
		return cssMaintBlockDefault, false
	}
}

func groupingAtRuleKeyword(typ, keyword string) string {
	if keyword != "" {
		return keyword
	}
	switch typ {
	case "media_statement":
		return "@media"
	case "supports_statement":
		return "@supports"
	case "layer_statement":
		return "@layer"
	case "container_statement":
		return "@container"
	case "scope_statement":
		return "@scope"
	default:
		return ""
	}
}

func (ctx *cssMaintContext) getAtRuleKeyword(n *sitter.Node) string {
	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		b := ctx.nodeBytes(c)
		if len(b) > 0 && b[0] == '@' {
			return strings.ToLower(string(b))
		}
	}
	return ""
}

func isGroupingAtRule(typ, keyword string) bool {
	return typ == "media_statement" || typ == "supports_statement" ||
		typ == "layer_statement" || typ == "container_statement" || typ == "scope_statement" ||
		keyword == "@media" || keyword == "@supports" || keyword == "@layer" || keyword == "@container" || keyword == "@scope"
}

func (ctx *cssMaintContext) getNodePrelude(n *sitter.Node) string {
	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if c.Type() == "media_query_list" || c.Type() == "feature_query" || c.Type() == "selectors" || c.Type() == "selector" {
			canon := canonicalizeCSSPrelude(ctx.nodeBytes(c))
			if canon.Complete {
				return canon.Text
			}
		}
	}

	b := ctx.nodeBytes(n)
	braceIdx := bytes.IndexByte(b, '{')
	if braceIdx != -1 {
		kw := ctx.getAtRuleKeyword(n)
		var preludeBytes []byte
		if kw != "" && len(kw) < braceIdx {
			preludeBytes = b[len(kw):braceIdx]
		} else {
			preludeBytes = b[:braceIdx]
		}
		canon := canonicalizeCSSPrelude(preludeBytes)
		if canon.Complete {
			return canon.Text
		}
	}

	return ""
}

func (ctx *cssMaintContext) nodeBytes(n *sitter.Node) []byte {
	start := int(n.StartByte())
	end := int(n.EndByte())
	if start < 0 || end > len(ctx.src) || start >= end {
		return nil
	}
	return ctx.src[start:end]
}

func (ctx *cssMaintContext) lineOf(byteOffset int) int {
	return cssLineForOffset(ctx.offsets, byteOffset)
}

func (ctx *cssMaintContext) checkTodoComment(n *sitter.Node) {
	b := ctx.nodeBytes(n)
	if len(b) > cssMaxPreludeBytes {
		return
	}
	content := string(b)

	for pos := 0; pos < len(content); {
		marker := ""
		for _, candidate := range []string{"TODO", "FIXME"} {
			if strings.HasPrefix(content[pos:], candidate) {
				marker = candidate
				break
			}
		}
		if marker == "" {
			pos++
			continue
		}

		leftOk := pos == 0 || !isAlphaNum(content[pos-1])
		end := pos + len(marker)
		rightOk := end == len(content) || !isAlphaNum(content[end])
		if leftOk && rightOk {
			markerOffset := int(n.StartByte()) + pos
			ctx.collector.add(cssFindingAtLine("todo-marker", ctx.rel, ctx.lineOf(markerOffset)))
		}
		pos = end
	}
}

func isAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func (ctx *cssMaintContext) checkRuleSet(n *sitter.Node, scopeChain []string) {
	var selectorsNode *sitter.Node

	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if c.Type() != "block" {
			selectorsNode = c
		}
	}

	if selectorsNode != nil {
		selBytes := ctx.nodeBytes(selectorsNode)
		canon := canonicalizeCSSSelectorPrelude(selBytes)

		if canon.Complete && canon.Text != "" {
			line := ctx.lineOf(int(selectorsNode.StartByte()))
			scopeHash := computeCSSScopeHash(scopeChain)
			digest := computeCSSScopedDigest(scopeHash, canon.Text)

			if trackCSSOccurrence(ctx.selectorOccurrences, digest, line) {
				ctx.collector.add(cssFindingAtLine("duplicate-selector", ctx.rel, line))
			}

			ctx.checkSelectorListMetrics(selectorsNode)
		}
	}
}

func (ctx *cssMaintContext) checkSelectorListMetrics(selNode *sitter.Node) {
	line := ctx.lineOf(int(selNode.StartByte()))
	items := splitCSSSelectorItems(string(ctx.nodeBytes(selNode)))

	if len(items) > 8 {
		ctx.collector.add(cssFindingAtLine("selector-list-too-long", ctx.rel, line))
	}

	for _, item := range items {
		leadingWhitespace := cssLeadingWhitespaceBytes([]byte(item.text))
		canon := canonicalizeCSSSelectorPrelude([]byte(strings.TrimSpace(item.text)))
		if !canon.Complete || canon.Text == "" {
			continue
		}
		selectorLine := ctx.lineOf(int(selNode.StartByte()) + item.offset + leadingWhitespace)
		selector := canon.Text

		if hasCSSIDSelector(selector) {
			ctx.collector.add(cssFindingAtLine("id-selector-overuse", ctx.rel, selectorLine))
		}

		classAttrPseudo, typePseudoElem := computeCSSSelectorSpecificity(selector)
		if classAttrPseudo >= 4 || typePseudoElem >= 5 {
			ctx.collector.add(cssFindingAtLine("selector-specificity-high", ctx.rel, selectorLine))
		}

		if computeCSSSelectorDepth(selector) > 4 {
			ctx.collector.add(cssFindingAtLine("selector-depth-high", ctx.rel, selectorLine))
		}

		if isCSSOverqualifiedSelector(selector) {
			ctx.collector.add(cssFindingAtLine("overqualified-selector", ctx.rel, selectorLine))
		}

		if _, ok := hasCSSLegacyPseudoElement(selector); ok {
			ctx.collector.add(cssFindingAtLine("legacy-pseudo-element", ctx.rel, selectorLine))
		}
	}
}

func (ctx *cssMaintContext) checkBlockMaintainability(block *sitter.Node, blockContext cssMaintBlockContext) {
	blockStartLine := ctx.lineOf(int(block.StartByte()))

	var decls []*sitter.Node
	for i := 0; i < int(block.ChildCount()); i++ {
		c := block.Child(i)
		if c.Type() == "declaration" {
			decls = append(decls, c)
		}
	}

	if blockContext == cssMaintBlockGrouping {
		return
	}

	if blockContext == cssMaintBlockPage {
		for _, d := range decls {
			propName, _, _, _ := ctx.parseDeclarationNode(d)
			if _, ok := cssLegacyProperties[propName]; ok {
				ctx.collector.add(cssFindingAtLine("legacy-property", ctx.rel, ctx.lineOf(int(d.StartByte()))))
			}
		}
		return
	}

	if len(decls) == 0 {
		hasChildRule := false
		for i := 0; i < int(block.ChildCount()); i++ {
			if block.Child(i).Type() == "rule_set" {
				hasChildRule = true
				break
			}
		}
		if !hasChildRule {
			ctx.collector.add(cssFindingAtLine("empty-block", ctx.rel, blockStartLine))
		}
	}

	if len(decls) > 20 {
		ctx.collector.add(cssFindingAtLine("declaration-block-too-large", ctx.rel, blockStartLine))
	}

	var declaredProps []string
	var propLines []int
	var propIsImportant []bool

	for _, d := range decls {
		propName, valBytes, valueOffset, important := ctx.parseDeclarationNode(d)
		if propName == "" {
			continue
		}

		declLine := ctx.lineOf(int(d.StartByte()))
		isCustom := strings.HasPrefix(propName, "--")

		if important && !isCustom {
			ctx.collector.add(cssFindingAtLine("important-overuse", ctx.rel, declLine))
		}

		if !isCustom {
			valStr := string(valBytes)

			ctx.checkZeroWithUnit(valStr, valueOffset)

			if propName == "font-family" {
				ctx.checkFontNoFallback(valStr, declLine)
			}

			if propName == "z-index" {
				ctx.checkNegativeZIndex(valStr, declLine)
			}

			if _, ok := cssLegacyProperties[propName]; ok {
				ctx.collector.add(cssFindingAtLine("legacy-property", ctx.rel, declLine))
			}

			ctx.checkRedundantValueList(propName, valStr, declLine)

			declaredProps = append(declaredProps, propName)
			propLines = append(propLines, declLine)
			propIsImportant = append(propIsImportant, important)
		}
	}

	for i, p := range declaredProps {
		if std, ok := cssVendorStandardPairs[p]; ok {
			hasStd := false
			for _, p2 := range declaredProps {
				if p2 == std {
					hasStd = true
					break
				}
			}
			if !hasStd {
				ctx.collector.add(cssFindingAtLine("vendor-prefix-no-standard", ctx.rel, propLines[i]))
			}
		}
	}

	for i, p := range declaredProps {
		if short, ok := cssShorthandMap[p]; ok {
			for j := i + 1; j < len(declaredProps); j++ {
				if declaredProps[j] == short && propIsImportant[i] == propIsImportant[j] {
					ctx.collector.add(cssFindingAtLine("shorthand-redundant", ctx.rel, propLines[i]))
					break
				}
			}
		}
	}
}

func (ctx *cssMaintContext) parseDeclarationNode(d *sitter.Node) (propName string, valBytes []byte, valueOffset int, important bool) {
	importantStart := -1
	for i := 0; i < int(d.ChildCount()); i++ {
		c := d.Child(i)
		if c.Type() == "property_name" {
			propName = strings.ToLower(string(ctx.nodeBytes(c)))
		} else if c.Type() == "important" {
			important = true
			importantStart = int(c.StartByte()) - int(d.StartByte())
		}
	}

	dBytes := ctx.nodeBytes(d)
	colonIdx := bytes.IndexByte(dBytes, ':')
	if colonIdx != -1 {
		valueEnd := len(dBytes)
		if importantStart >= colonIdx+1 && importantStart <= len(dBytes) {
			valueEnd = importantStart
		}
		rawValue := dBytes[colonIdx+1 : valueEnd]
		leadingWhitespace := cssLeadingWhitespaceBytes(rawValue)
		valBytes = bytes.TrimSuffix(bytes.TrimSpace(rawValue), []byte(";"))
		valueOffset = int(d.StartByte()) + colonIdx + 1 + leadingWhitespace
	}
	return propName, valBytes, valueOffset, important
}

func cssLeadingWhitespaceBytes(value []byte) int {
	for i, b := range value {
		switch b {
		case ' ', '\t', '\n', '\r', '\f':
		default:
			return i
		}
	}
	return len(value)
}

func (ctx *cssMaintContext) checkZeroWithUnit(valStr string, valueOffset int) {
	for _, offset := range scanCSSZeroLengthDimensions(valStr) {
		ctx.collector.add(cssFindingAtLine("zero-with-unit", ctx.rel, ctx.lineOf(valueOffset+offset)))
	}
}

func hasCSSZeroLengthDimension(value string) bool {
	return len(scanCSSZeroLengthDimensions(value)) > 0
}

func scanCSSZeroLengthDimensions(value string) []int {
	if len(value) > cssMaxPreludeBytes {
		return nil
	}

	var offsets []int
	parenDepth := 0
	for i := 0; i < len(value); {
		if strings.HasPrefix(value[i:], "/*") {
			end := strings.Index(value[i+2:], "*/")
			if end < 0 {
				return nil
			}
			i += end + 4
			continue
		}
		if value[i] == '\'' || value[i] == '"' {
			next, ok := skipCSSQuoted(value, i)
			if !ok {
				return nil
			}
			i = next
			continue
		}

		numberEnd, zero := scanCSSZeroNumber(value, i)
		if numberEnd != i {
			unitEnd := numberEnd
			for unitEnd < len(value) && isCSSASCIIAlpha(value[unitEnd]) {
				unitEnd++
			}
			if zero && unitEnd > numberEnd &&
				(unitEnd == len(value) || !isCSSIdentifierChar(value[unitEnd])) &&
				cssZeroLengthUnits[strings.ToLower(value[numberEnd:unitEnd])] {
				offsets = append(offsets, i)
			}
			i = unitEnd
			continue
		}

		if isCSSIdentifierStart(value[i]) {
			nameEnd := scanCSSIdentifier(value, i)
			if nameEnd < len(value) && value[nameEnd] == '(' {
				name := strings.ToLower(value[i:nameEnd])
				if name == "var" || name == "env" || name == "url" {
					next, ok := skipCSSFunction(value, nameEnd)
					if !ok {
						return nil
					}
					i = next
					continue
				}
			}
			i = nameEnd
			continue
		}

		switch value[i] {
		case '(':
			parenDepth++
			if parenDepth > cssMaxSelectorDepth {
				return nil
			}
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		}
		i++
	}
	return offsets
}

func scanCSSZeroNumber(value string, start int) (int, bool) {
	if start >= len(value) || (start > 0 && isCSSNumberAdjacent(value[start-1])) {
		return start, false
	}

	i := start
	if value[i] == '+' || value[i] == '-' {
		i++
		if i == len(value) {
			return start, false
		}
	}

	digits := 0
	nonZero := false
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		nonZero = nonZero || value[i] != '0'
		digits++
		i++
	}
	if i+1 < len(value) && value[i] == '.' && value[i+1] >= '0' && value[i+1] <= '9' {
		i++
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			nonZero = nonZero || value[i] != '0'
			digits++
			i++
		}
	}
	if digits == 0 {
		return start, false
	}

	if i < len(value) && (value[i] == 'e' || value[i] == 'E') {
		exponentStart := i
		i++
		if i < len(value) && (value[i] == '+' || value[i] == '-') {
			i++
		}
		exponentDigits := i
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
		}
		if i == exponentDigits {
			i = exponentStart
		}
	}
	return i, !nonZero
}

func skipCSSQuoted(value string, start int) (int, bool) {
	quote := value[start]
	for i := start + 1; i < len(value); i++ {
		if value[i] == '\\' {
			i++
			continue
		}
		if value[i] == quote {
			return i + 1, true
		}
	}
	return len(value), false
}

func skipCSSFunction(value string, openParen int) (int, bool) {
	depth := 1
	for i := openParen + 1; i < len(value); {
		if strings.HasPrefix(value[i:], "/*") {
			end := strings.Index(value[i+2:], "*/")
			if end < 0 {
				return len(value), false
			}
			i += end + 4
			continue
		}
		if value[i] == '\'' || value[i] == '"' {
			next, ok := skipCSSQuoted(value, i)
			if !ok {
				return len(value), false
			}
			i = next
			continue
		}
		switch value[i] {
		case '(':
			depth++
			if depth > cssMaxSelectorDepth {
				return len(value), false
			}
		case ')':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
		i++
	}
	return len(value), false
}

func hasCSSRuntimeValueFunction(value string) bool {
	if len(value) > cssMaxPreludeBytes {
		return true
	}

	for i := 0; i < len(value); {
		if strings.HasPrefix(value[i:], "/*") {
			end := strings.Index(value[i+2:], "*/")
			if end < 0 {
				return true
			}
			i += end + 4
			continue
		}
		if value[i] == '\'' || value[i] == '"' {
			next, ok := skipCSSQuoted(value, i)
			if !ok {
				return true
			}
			i = next
			continue
		}
		if value[i] == '\\' {
			i += 2
			continue
		}
		if !isCSSIdentifierStart(value[i]) {
			i++
			continue
		}

		nameEnd := scanCSSIdentifier(value, i)
		if nameEnd < len(value) && value[nameEnd] == '(' {
			name := value[i:nameEnd]
			if strings.EqualFold(name, "var") || strings.EqualFold(name, "env") {
				return true
			}
			if strings.EqualFold(name, "url") {
				next, ok := skipCSSFunction(value, nameEnd)
				if !ok {
					return true
				}
				i = next
				continue
			}
		}
		i = nameEnd
	}
	return false
}

func hasCSSASCIIInsensitivePrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

func scanCSSIdentifier(value string, start int) int {
	i := start
	for i < len(value) && isCSSIdentifierChar(value[i]) {
		i++
	}
	return i
}

func isCSSIdentifierStart(b byte) bool {
	return isCSSASCIIAlpha(b) || b >= 0x80 || b == '_' || b == '-'
}

func isCSSIdentifierChar(b byte) bool {
	return isCSSIdentifierStart(b) || (b >= '0' && b <= '9')
}

func isCSSASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isCSSNumberAdjacent(b byte) bool {
	return isCSSIdentifierChar(b) || b == '.' || b == '%' || b == '#' || b == '@' || b == '\\'
}

func (ctx *cssMaintContext) checkFontNoFallback(valStr string, line int) {
	if hasCSSRuntimeValueFunction(valStr) {
		return
	}
	valStr = strings.TrimSuffix(strings.TrimSpace(valStr), ";")
	if cssWideKeywords[strings.ToLower(valStr)] {
		return
	}
	parts := strings.Split(valStr, ",")
	lastToken := strings.TrimSpace(parts[len(parts)-1])

	if (strings.HasPrefix(lastToken, "\"") && strings.HasSuffix(lastToken, "\"")) ||
		(strings.HasPrefix(lastToken, "'") && strings.HasSuffix(lastToken, "'")) {
		ctx.collector.add(cssFindingAtLine("font-no-fallback", ctx.rel, line))
		return
	}

	lastPart := strings.ToLower(lastToken)
	if !cssGenericFontFamilies[lastPart] {
		ctx.collector.add(cssFindingAtLine("font-no-fallback", ctx.rel, line))
	}
}

func (ctx *cssMaintContext) checkNegativeZIndex(valStr string, line int) {
	if hasCSSRuntimeValueFunction(valStr) || hasCSSASCIIInsensitivePrefix(strings.TrimSpace(valStr), "calc(") {
		return
	}
	trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(valStr), ";"))
	if value, err := strconv.Atoi(trimmed); err == nil && value < 0 {
		ctx.collector.add(cssFindingAtLine("negative-zindex", ctx.rel, line))
	}
}

func (ctx *cssMaintContext) checkRedundantValueList(propName, valStr string, line int) {
	eligible := map[string]bool{
		"margin": true, "padding": true, "inset": true,
		"border-color": true, "border-style": true, "border-width": true,
		"scroll-margin": true, "scroll-padding": true,
	}
	if !eligible[propName] {
		return
	}

	if hasCSSRuntimeValueFunction(valStr) {
		return
	}

	tokens := strings.Fields(strings.TrimSuffix(strings.TrimSpace(valStr), ";"))
	if len(tokens) < 2 || len(tokens) > 4 {
		return
	}

	isRedundant := false
	if len(tokens) == 2 && tokens[0] == tokens[1] {
		isRedundant = true
	} else if len(tokens) == 3 && tokens[0] == tokens[2] {
		isRedundant = true
	} else if len(tokens) == 4 && tokens[0] == tokens[2] && tokens[1] == tokens[3] {
		isRedundant = true
	} else if len(tokens) == 4 && tokens[1] == tokens[3] {
		isRedundant = true
	}

	if isRedundant {
		ctx.collector.add(cssFindingAtLine("redundant-value-list", ctx.rel, line))
	}
}

func (ctx *cssMaintContext) checkMediaStatement(n *sitter.Node, scopeChain []string, depth int) {
	line := ctx.lineOf(int(n.StartByte()))
	prelude := ctx.getNodePrelude(n)

	if prelude != "" {
		scopeHash := computeCSSScopeHash(scopeChain)
		digest := computeCSSScopedDigest(scopeHash, prelude)

		if trackCSSOccurrence(ctx.mediaOccurrences, digest, line) {
			ctx.collector.add(cssFindingAtLine("duplicate-media-query", ctx.rel, line))
		}
	}
}

func (ctx *cssMaintContext) checkKeyframesStatementMaint(n *sitter.Node, scopeChain []string, keyword string) {
	line := ctx.lineOf(int(n.StartByte()))
	var kfName string

	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if c.Type() == "keyframes_name" || c.Type() == "custom_property_name" || c.Type() == "identifier" {
			kfName = string(ctx.nodeBytes(c))
		}
	}

	if kfName == "" {
		b := ctx.nodeBytes(n)
		fields := strings.Fields(string(b))
		if len(fields) >= 2 {
			kfName = fields[1]
		}
	}

	if kfName != "" {
		if keyword == "" {
			keyword = "@keyframes"
		}
		scopeHash := computeCSSScopeHash(scopeChain)
		scopedName := cssScopedName{ScopeHash: scopeHash, Keyword: keyword, Name: kfName}

		if trackCSSOccurrence(ctx.keyframeOccurrences, scopedName, line) {
			ctx.collector.add(cssFindingAtLine("duplicate-keyframes", ctx.rel, line))
		}
	}
}

func (ctx *cssMaintContext) checkImportStatementMaint(n *sitter.Node) {
	line := ctx.lineOf(int(n.StartByte()))
	canon := canonicalizeCSSPrelude(ctx.nodeBytes(n))

	if canon.Complete {
		h := sha256.Sum256([]byte(canon.Text))
		if trackCSSOccurrence(ctx.importOccurrences, h, line) {
			ctx.collector.add(cssFindingAtLine("duplicate-import", ctx.rel, line))
		}
	}
}

func (ctx *cssMaintContext) checkFontFaceStatementMaint(n *sitter.Node) {
	line := ctx.lineOf(int(n.StartByte()))
	var descPairs []string
	complete := true

	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if c.Type() == "block" {
			for j := 0; j < int(c.ChildCount()); j++ {
				d := c.Child(j)
				if d.Type() == "declaration" {
					prop, valBytes, _, _ := ctx.parseDeclarationNode(d)
					if prop != "" {
						canonVal := canonicalizeCSSPrelude(valBytes)
						if !canonVal.Complete {
							complete = false
							break
						}
						descPairs = append(descPairs, prop+"="+canonVal.Text)
					}
				}
			}
		}
		if !complete {
			break
		}
	}

	if complete && len(descPairs) > 0 {
		sort.Strings(descPairs)
		h := sha256.Sum256([]byte(strings.Join(descPairs, ";")))
		if trackCSSOccurrence(ctx.fontFaceOccurrences, h, line) {
			ctx.collector.add(cssFindingAtLine("duplicate-font-face", ctx.rel, line))
		}
	}
}
