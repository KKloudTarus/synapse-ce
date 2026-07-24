//go:build cgo

package astwalk

import (
	"crypto/sha256"
	"sort"
	"strconv"
	"strings"
	"unicode"

	sitter "github.com/smacker/go-tree-sitter"
)

type cssDeclarationAnalysis struct {
	framingSound    bool
	valueASTSound   bool
	hexRecoveryOnly bool
	valueStart      int
	valueEnd        int
}

func scanCSSInvalidHexColors(value []byte, absoluteOffset int, rel string, offsets []int, collector *cssCollector) {
	insideSingleQuote := false
	insideDoubleQuote := false
	insideComment := false
	functionStack := []string{}

	i := 0
	n := len(value)

	for i < n {
		if insideComment {
			if i+1 < n && value[i] == '*' && value[i+1] == '/' {
				insideComment = false
				i += 2
			} else {
				i++
			}
			continue
		}
		if !insideSingleQuote && !insideDoubleQuote && i+1 < n && value[i] == '/' && value[i+1] == '*' {
			insideComment = true
			i += 2
			continue
		}

		c := value[i]

		if insideSingleQuote {
			if c == '\\' {
				i += 2
				continue
			}
			if c == '\'' {
				insideSingleQuote = false
			}
			i++
			continue
		}

		if insideDoubleQuote {
			if c == '\\' {
				i += 2
				continue
			}
			if c == '"' {
				insideDoubleQuote = false
			}
			i++
			continue
		}

		if c == '\'' {
			insideSingleQuote = true
			i++
			continue
		}
		if c == '"' {
			insideDoubleQuote = true
			i++
			continue
		}

		if c == '(' {
			j := i - 1
			for j >= 0 && (value[j] == ' ' || value[j] == '\t' || value[j] == '\n' || value[j] == '\r') {
				j--
			}
			fnEnd := j + 1
			for j >= 0 && ((value[j] >= 'a' && value[j] <= 'z') || (value[j] >= 'A' && value[j] <= 'Z') || value[j] == '-') {
				j--
			}
			fnName := string(value[j+1 : fnEnd])
			fnName = strings.ToLower(fnName)
			functionStack = append(functionStack, fnName)
			i++
			continue
		}
		if c == ')' {
			if len(functionStack) > 0 {
				functionStack = functionStack[:len(functionStack)-1]
			}
			i++
			continue
		}

		if c == '#' {
			suppressed := false
			for _, fn := range functionStack {
				if fn == "url" || fn == "var" || fn == "env" {
					suppressed = true
					break
				}
			}

			if suppressed {
				i++
				continue
			}

			startIdx := i
			i++
			for i < n {
				b := value[i]
				if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') || (b >= 'g' && b <= 'z') || (b >= 'G' && b <= 'Z') || b == '-' || b > 127 || b == '\\' {
					i++
				} else {
					break
				}
			}

			token := string(value[startIdx+1 : i])

			hasEscapeOrNonAscii := false
			for k := 0; k < len(token); k++ {
				if token[k] == '\\' || token[k] > 127 {
					hasEscapeOrNonAscii = true
					break
				}
			}

			if !hasEscapeOrNonAscii {
				isValidHex := true
				for k := 0; k < len(token); k++ {
					b := token[k]
					if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
						isValidHex = false
						break
					}
				}
				tokenLen := len(token)
				if !isValidHex || (tokenLen != 3 && tokenLen != 4 && tokenLen != 6 && tokenLen != 8) {
					collector.add(cssFindingAtLine("invalid-hex-color", rel, cssLineForOffset(offsets, absoluteOffset+startIdx)))
				}
			}
			continue
		}

		i++
	}
}

type cssQualityRule struct {
	kind        string
	id          string
	cwe         string
	severity    string
	title       string
	description string
}

var cssRules = map[string]cssQualityRule{
	"duplicate-property":          {"reliability", "css:duplicate-property", "", "low", "Duplicate property declaration", "Repeated identical property declaration in one block."},
	"invalid-hex-color":           {"reliability", "css:invalid-hex-color", "", "low", "Invalid hexadecimal color token", "Invalid hexadecimal color token."},
	"unknown-property":            {"reliability", "css:unknown-property", "", "low", "Unknown CSS property", "Property absent from the W3C property inventory."},
	"invalid-unit":                {"reliability", "css:invalid-unit", "", "low", "Invalid CSS unit", "Dimension using an unknown CSS unit."},
	"invalid-keyframe-selector":   {"reliability", "css:invalid-keyframe-selector", "", "medium", "Invalid keyframe offset", "Proven-invalid keyframe offset."},
	"negative-animation-duration": {"reliability", "css:negative-animation-duration", "", "medium", "Negative animation duration", "Negative literal animation duration."},
	"invalid-font-weight":         {"reliability", "css:invalid-font-weight", "", "low", "Invalid font weight", "Literal font weight outside 1–1000."},
	"negative-flex-factor":        {"reliability", "css:negative-flex-factor", "", "low", "Negative flex factor", "Negative flex-grow or flex-shrink factor."},
}

func cssFindingAtLine(key string, rel string, line int) QualityFinding {
	r := cssRules[key]
	return QualityFinding{
		Kind:        r.kind,
		Rule:        r.id,
		CWE:         r.cwe,
		Severity:    r.severity,
		Title:       r.title,
		Description: r.description,
		File:        rel,
		Line:        line,
	}
}

func cssNewlineOffsets(src []byte) []int {
	var offsets []int
	for i, b := range src {
		if b == '\n' {
			offsets = append(offsets, i)
		}
	}
	return offsets
}

func cssLineForOffset(offsets []int, offset int) int {
	line := sort.Search(len(offsets), func(i int) bool {
		return offsets[i] >= offset
	})
	return line + 1
}

type cssCollector struct {
	findings []QualityFinding
	counts   map[string]int
	total    int
}

func (c *cssCollector) add(f QualityFinding) {
	if c.total >= 100 {
		return
	}
	if c.counts[f.Rule] >= 20 {
		return
	}
	c.findings = append(c.findings, f)
	if c.counts == nil {
		c.counts = make(map[string]int)
	}
	c.counts[f.Rule]++
	c.total++
}

type cssContext int

const (
	ctxNormal cssContext = iota
	ctxDescriptor
	ctxKeyframes
)

var cssDescriptorAtRules = map[string]bool{
	"@font-face":           true,
	"@property":            true,
	"@counter-style":       true,
	"@font-feature-values": true,
	"@page":                true,
	"@color-profile":       true,
	"@font-palette-values": true,
}

func cssAtRuleKeyword(n *sitter.Node, src []byte) string {
	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if c.Type() == "at_keyword" {
			return strings.ToLower(c.Content(src))
		}
	}
	return ""
}

type cssStackFrame struct {
	node *sitter.Node
	ctx  cssContext
}

type cssValueStackFrame struct {
	node         *sitter.Node
	depth        int
	insideString bool
	insideUrl    bool
	suppressed   bool
}

type cssStructureFrame struct {
	node  *sitter.Node
	depth int
}

type cssDeclFingerprint struct {
	digest    [32]byte
	important bool
}

func normalizeCSSValueFingerprint(valSlice []byte) (digest [32]byte, important bool) {
	var cleaned []byte
	insideSingleQuote := false
	insideDoubleQuote := false
	insideComment := false

	n := len(valSlice)
	i := 0

	for i < n {
		if insideComment {
			if i+1 < n && valSlice[i] == '*' && valSlice[i+1] == '/' {
				insideComment = false
				i += 2
			} else {
				i++
			}
			continue
		}
		if !insideSingleQuote && !insideDoubleQuote && i+1 < n && valSlice[i] == '/' && valSlice[i+1] == '*' {
			insideComment = true
			i += 2
			continue
		}

		c := valSlice[i]
		if insideSingleQuote {
			if c == '\\' {
				cleaned = append(cleaned, c)
				if i+1 < n {
					cleaned = append(cleaned, valSlice[i+1])
					i += 2
					continue
				}
			}
			if c == '\'' {
				insideSingleQuote = false
			}
			cleaned = append(cleaned, c)
			i++
			continue
		}
		if insideDoubleQuote {
			if c == '\\' {
				cleaned = append(cleaned, c)
				if i+1 < n {
					cleaned = append(cleaned, valSlice[i+1])
					i += 2
					continue
				}
			}
			if c == '"' {
				insideDoubleQuote = false
			}
			cleaned = append(cleaned, c)
			i++
			continue
		}
		if c == '\'' {
			insideSingleQuote = true
			cleaned = append(cleaned, c)
			i++
			continue
		}
		if c == '"' {
			insideDoubleQuote = true
			cleaned = append(cleaned, c)
			i++
			continue
		}

		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if len(cleaned) > 0 && cleaned[len(cleaned)-1] != ' ' {
				cleaned = append(cleaned, ' ')
			}
			i++
			continue
		}

		cleaned = append(cleaned, c)
		i++
	}

	str := strings.TrimSpace(string(cleaned))

	lowerStr := strings.ToLower(str)
	if idx := strings.LastIndex(lowerStr, "!important"); idx != -1 {
		suffix := strings.TrimSpace(str[idx+len("!important"):])
		if suffix == "" || suffix == ";" {
			important = true
			str = strings.TrimSpace(str[:idx])
		}
	} else if strings.HasSuffix(str, ";") {
		str = strings.TrimSuffix(str, ";")
		str = strings.TrimSpace(str)
	}

	digest = sha256.Sum256([]byte(str))
	return digest, important
}

func cssFindings(root *sitter.Node, src []byte, rel string) []QualityFinding {
	if root == nil {
		return nil
	}
	collector := &cssCollector{counts: make(map[string]int)}
	offsets := cssNewlineOffsets(src)

	stack := []cssStackFrame{{node: root, ctx: ctxNormal}}
	for len(stack) > 0 {
		frame := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n := frame.node
		ctx := frame.ctx

		childCtx := ctx
		if n.Type() == "at_rule" {
			keyword := cssAtRuleKeyword(n, src)
			if cssDescriptorAtRules[keyword] {
				childCtx = ctxDescriptor
			}
		} else if n.Type() == "keyframes_statement" {
			childCtx = ctxKeyframes
			checkKeyframesStatement(n, src, rel, offsets, collector)
		}

		if n.Type() == "block" && (ctx == ctxNormal || ctx == ctxKeyframes) {
			checkCssBlock(n, src, rel, offsets, collector, ctx)
		}

		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, cssStackFrame{node: n.Child(i), ctx: childCtx})
		}
	}

	return collector.findings
}

func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return true
		}
	}
	return false
}

func isIsolatedHexError(n *sitter.Node, src []byte) bool {
	val := n.Content(src)
	if len(val) == 0 || val[0] != '#' {
		return false
	}
	for i := 0; i < len(val); i++ {
		c := val[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ':' || c == ';' || c == '{' || c == '}' {
			return false
		}
	}
	return true
}

func analyzeDeclarationStructure(decl *sitter.Node, src []byte) (analysis cssDeclarationAnalysis, complete bool) {
	if decl.IsMissing() {
		return analysis, false
	}

	hasColon := false
	hasProperty := false
	declStart := int(decl.StartByte())
	declEnd := int(decl.EndByte())
	declSlice := src[declStart:declEnd]
	colonOffset := strings.IndexByte(string(declSlice), ':')
	if colonOffset != -1 {
		hasColon = true
		analysis.valueStart = declStart + colonOffset + 1
		analysis.valueEnd = declEnd
	}

	isMalformedRecovery := false
	hasHexRecovery := false

	propCount := 0
	colonCount := 0

	stack := make([]cssStructureFrame, 0, 32)
	for i := int(decl.ChildCount()) - 1; i >= 0; i-- {
		stack = append(stack, cssStructureFrame{node: decl.Child(i), depth: 1})
	}

	for len(stack) > 0 {
		frame := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n := frame.node

		if frame.depth > 256 {
			return analysis, false // depth cap exceeded
		}

		if n.IsMissing() {
			isMalformedRecovery = true
		}

		typ := n.Type()
		if typ == "property_name" {
			hasProperty = true
			propCount++
		}
		if typ == ":" || n.Content(src) == ":" {
			colonCount++
		}

		if typ == "ERROR" {
			if isIsolatedHexError(n, src) {
				hasHexRecovery = true
			} else {
				isMalformedRecovery = true
			}
		}

		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, cssStructureFrame{node: n.Child(i), depth: frame.depth + 1})
		}
	}

	if hasHexRecovery && analysis.valueStart < analysis.valueEnd && analysis.valueEnd <= len(src) {
		valSlice := src[analysis.valueStart:analysis.valueEnd]
		valStr := strings.TrimSpace(string(valSlice))
		valStr = strings.TrimSuffix(valStr, ";")
		valStr = strings.TrimSpace(valStr)

		if strings.HasPrefix(valStr, "#") {
			rest := valStr[1:]
			if strings.ContainsAny(rest, " \t\n\r:") {
				isMalformedRecovery = true
			}
		} else {
			isMalformedRecovery = true
		}
	}

	if propCount > 1 || colonCount > 1 {
		isMalformedRecovery = true
	}

	analysis.framingSound = hasProperty && hasColon
	if analysis.framingSound {
		if !isMalformedRecovery && !hasHexRecovery {
			analysis.valueASTSound = true
		} else if !isMalformedRecovery && hasHexRecovery {
			analysis.hexRecoveryOnly = true
		}
		// valueStart and valueEnd were already set above
	}

	return analysis, true
}

func checkCssBlock(block *sitter.Node, src []byte, rel string, offsets []int, collector *cssCollector, ctx cssContext) {
	type decl struct {
		prop string
		fp   cssDeclFingerprint
		line int
	}
	seen := make(map[string][]decl)

	for i := 0; i < int(block.ChildCount()); i++ {
		n := block.Child(i)
		if n.Type() == "declaration" {

			var propNode *sitter.Node
			for j := 0; j < int(n.ChildCount()); j++ {
				if n.Child(j).Type() == "property_name" {
					propNode = n.Child(j)
					break
				}
			}
			if propNode == nil {
				continue
			}

			rawProp := propNode.Content(src)
			prop := strings.ToLower(rawProp)

			isCustom := strings.HasPrefix(prop, "--")
			isVendor := strings.HasPrefix(prop, "-webkit-") || strings.HasPrefix(prop, "-moz-") || strings.HasPrefix(prop, "-ms-") || strings.HasPrefix(prop, "-o-")
			hasEscapeOrNonASCII := strings.ContainsRune(rawProp, '\\') || hasNonASCII(rawProp)
			isLegacyHack := strings.HasPrefix(prop, "*") || strings.HasPrefix(prop, "_")

			analysis, complete := analyzeDeclarationStructure(n, src)
			if !analysis.framingSound || !complete {
				continue
			}

			// Source slice scanning for hex colors (suppressed on custom properties)
			if !isCustom && (analysis.valueASTSound || analysis.hexRecoveryOnly) && analysis.valueStart < analysis.valueEnd && analysis.valueEnd <= len(src) {
				valSlice := src[analysis.valueStart:analysis.valueEnd]
				scanCSSInvalidHexColors(valSlice, analysis.valueStart, rel, offsets, collector)
			}

			if !analysis.valueASTSound {
				continue
			}

			if !isCustom && !isVendor && !hasEscapeOrNonASCII && !isLegacyHack {
				if !cssKnownPropertySet[prop] {
					collector.add(cssFindingAtLine("unknown-property", rel, cssLineForOffset(offsets, int(propNode.StartByte()))))
				}
			}

			fp := cssDeclFingerprint{}
			if analysis.valueStart < analysis.valueEnd && analysis.valueEnd <= len(src) {
				valSlice := src[analysis.valueStart:analysis.valueEnd]
				digest, imp := normalizeCSSValueFingerprint(valSlice)
				fp.digest = digest
				fp.important = imp
			}

			isCompleteValues := checkDeclarationValuesIterative(n, src, rel, offsets, collector, prop, isCustom, ctx)

			if isCompleteValues && !isCustom {
				line := cssLineForOffset(offsets, int(propNode.StartByte()))
				d := decl{prop: prop, fp: fp, line: line}

				isDuplicate := false
				for _, prev := range seen[prop] {
					if prev.fp.digest == fp.digest && prev.fp.important == fp.important {
						isDuplicate = true
						break
					}
				}
				if isDuplicate {
					collector.add(cssFindingAtLine("duplicate-property", rel, line))
				}
				seen[prop] = append(seen[prop], d)
			}
		}
	}
}

func checkDeclarationValuesIterative(decl *sitter.Node, src []byte, rel string, offsets []int, collector *cssCollector, prop string, isCustom bool, ctx cssContext) bool {
	isComplete := true

	stack := make([]cssValueStackFrame, 0, 32)
	for i := int(decl.ChildCount()) - 1; i >= 0; i-- {
		stack = append(stack, cssValueStackFrame{
			node:         decl.Child(i),
			depth:        1,
			insideString: false,
			insideUrl:    false,
			suppressed:   false,
		})
	}

	var topLevelDurationTokens []*sitter.Node
	var topLevelFontWeightTokens []*sitter.Node
	var topLevelFlexTokens []*sitter.Node

	for len(stack) > 0 {
		frame := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n := frame.node

		if frame.depth > 256 {
			isComplete = false
			continue
		}

		typ := n.Type()

		if typ == "property_name" {
			continue
		}
		if typ == "important" {
			continue
		}
		if typ == "comment" {
			continue
		}

		childInsideString := frame.insideString
		if typ == "string_value" {
			childInsideString = true
		}

		childInsideUrl := frame.insideUrl
		childSuppressed := frame.suppressed

		if typ == "call_expression" {
			var fnName string
			for i := 0; i < int(n.ChildCount()); i++ {
				if n.Child(i).Type() == "function_name" {
					fnName = strings.ToLower(n.Child(i).Content(src))
					break
				}
			}
			if fnName == "url" {
				childInsideUrl = true
			} else if fnName == "var" || fnName == "env" {
				childSuppressed = true
			}
		}

		if !isCustom && !childInsideString && !childInsideUrl && !childSuppressed {
			if typ == "integer_value" || typ == "float_value" {
				for i := 0; i < int(n.ChildCount()); i++ {
					if n.Child(i).Type() == "unit" {
						unitNode := n.Child(i)
						unit := strings.ToLower(unitNode.Content(src))
						if !hasNonASCII(unit) && !strings.ContainsRune(unit, '\\') && unit != "%" {
							if !cssKnownUnits[unit] {
								collector.add(cssFindingAtLine("invalid-unit", rel, cssLineForOffset(offsets, int(unitNode.StartByte()))))
							}
						}
					}
				}
			}
		}

		if frame.depth == 1 && !childSuppressed {
			if prop == "animation-duration" && (typ == "integer_value" || typ == "float_value") {
				topLevelDurationTokens = append(topLevelDurationTokens, n)
			}
			if prop == "font-weight" && (typ == "integer_value" || typ == "float_value" || typ == "plain_value") {
				topLevelFontWeightTokens = append(topLevelFontWeightTokens, n)
			}
			if (prop == "flex-grow" || prop == "flex-shrink") && (typ == "integer_value" || typ == "float_value" || typ == "plain_value") {
				topLevelFlexTokens = append(topLevelFlexTokens, n)
			}
		}

		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, cssValueStackFrame{
				node:         n.Child(i),
				depth:        frame.depth + 1,
				insideString: childInsideString,
				insideUrl:    childInsideUrl,
				suppressed:   childSuppressed,
			})
		}
	}

	if prop == "animation-duration" {
		for _, v := range topLevelDurationTokens {
			val := v.Content(src)
			numStr := val
			unit := ""
			for i := 0; i < int(v.ChildCount()); i++ {
				child := v.Child(i)
				if child.Type() == "unit" {
					unit = strings.ToLower(child.Content(src))
					numStr = strings.TrimSuffix(val, child.Content(src))
					break
				}
			}
			if unit != "s" && unit != "ms" {
				continue
			}
			num, err := strconv.ParseFloat(numStr, 64)
			if err == nil && num < 0 {
				collector.add(cssFindingAtLine("negative-animation-duration", rel, cssLineForOffset(offsets, int(v.StartByte()))))
			}
		}
	}

	if prop == "font-weight" && len(topLevelFontWeightTokens) == 1 {
		v := topLevelFontWeightTokens[0]
		val := v.Content(src)
		num, err := strconv.ParseFloat(val, 64)
		if err == nil {
			if num < 1 || num > 1000 {
				collector.add(cssFindingAtLine("invalid-font-weight", rel, cssLineForOffset(offsets, int(v.StartByte()))))
			}
		}
	}

	if (prop == "flex-grow" || prop == "flex-shrink") && len(topLevelFlexTokens) == 1 {
		v := topLevelFlexTokens[0]
		val := v.Content(src)
		num, err := strconv.ParseFloat(val, 64)
		if err == nil && num < 0 {
			collector.add(cssFindingAtLine("negative-flex-factor", rel, cssLineForOffset(offsets, int(v.StartByte()))))
		}
	}

	return isComplete
}

func checkKeyframesStatement(kfNode *sitter.Node, src []byte, rel string, offsets []int, collector *cssCollector) {
	if kfNode == nil || kfNode.IsMissing() {
		return
	}
	start := int(kfNode.StartByte())
	end := int(kfNode.EndByte())
	if start >= end || end > len(src) {
		return
	}

	statementSlice := src[start:end]
	insideSingleQuote := false
	insideDoubleQuote := false
	insideComment := false

	openBraceIdx := -1
	for i := 0; i < len(statementSlice); i++ {
		if insideComment {
			if i+1 < len(statementSlice) && statementSlice[i] == '*' && statementSlice[i+1] == '/' {
				insideComment = false
				i++
			}
			continue
		}
		if !insideSingleQuote && !insideDoubleQuote && i+1 < len(statementSlice) && statementSlice[i] == '/' && statementSlice[i+1] == '*' {
			insideComment = true
			i++
			continue
		}
		c := statementSlice[i]
		if insideSingleQuote {
			if c == '\\' {
				i++
				continue
			}
			if c == '\'' {
				insideSingleQuote = false
			}
			continue
		}
		if insideDoubleQuote {
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				insideDoubleQuote = false
			}
			continue
		}
		if c == '\'' {
			insideSingleQuote = true
			continue
		}
		if c == '"' {
			insideDoubleQuote = true
			continue
		}

		if c == '{' {
			openBraceIdx = i
			break
		}
	}

	if openBraceIdx == -1 || openBraceIdx >= len(statementSlice)-1 {
		return
	}

	outerBraceWasClosed := len(statementSlice) > openBraceIdx+1 && statementSlice[len(statementSlice)-1] == '}'

	if !outerBraceWasClosed {
		return
	}

	bodyStart := start + openBraceIdx + 1
	bodyEnd := end - 1
	if bodyStart >= bodyEnd {
		return
	}

	body := src[bodyStart:bodyEnd]

	type cssKeyframeCandidate struct {
		start int
		end   int
	}

	var candidates []cssKeyframeCandidate
	braceDepth := 0
	preludeStart := 0
	insideSingleQuote = false
	insideDoubleQuote = false
	insideComment = false

	for i := 0; i < len(body); i++ {
		if insideComment {
			if i+1 < len(body) && body[i] == '*' && body[i+1] == '/' {
				insideComment = false
				i++
			}
			continue
		}
		if !insideSingleQuote && !insideDoubleQuote && i+1 < len(body) && body[i] == '/' && body[i+1] == '*' {
			insideComment = true
			i++
			continue
		}

		c := body[i]
		if insideSingleQuote {
			if c == '\\' {
				i++
				continue
			}
			if c == '\'' {
				insideSingleQuote = false
			}
			continue
		}
		if insideDoubleQuote {
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				insideDoubleQuote = false
			}
			continue
		}
		if c == '\'' {
			insideSingleQuote = true
			continue
		}
		if c == '"' {
			insideDoubleQuote = true
			continue
		}

		if c == '{' {
			if braceDepth == 0 {
				candidates = append(candidates, cssKeyframeCandidate{
					start: bodyStart + preludeStart,
					end:   bodyStart + i,
				})
			}
			braceDepth++
		} else if c == '}' {
			braceDepth--
			if braceDepth == 0 {
				preludeStart = i + 1
			}
		}
	}

	if braceDepth != 0 || insideSingleQuote || insideDoubleQuote || insideComment {
		return
	}

	for _, cand := range candidates {
		if cand.start < cand.end && cand.end <= len(src) {
			preludeSlice := src[cand.start:cand.end]
			analyzeKeyframePrelude(preludeSlice, cand.start, rel, offsets, collector)
		}
	}
}

func analyzeKeyframePrelude(prelude []byte, absoluteOffset int, rel string, offsets []int, collector *cssCollector) {
	insideComment := false
	n := len(prelude)
	i := 0
	var components []string
	var compOffsets []int
	compStart := 0

	for i < n {
		if insideComment {
			if i+1 < n && prelude[i] == '*' && prelude[i+1] == '/' {
				insideComment = false
				i += 2
			} else {
				i++
			}
			continue
		}
		if i+1 < n && prelude[i] == '/' && prelude[i+1] == '*' {
			insideComment = true
			i += 2
			continue
		}

		if prelude[i] == ',' {
			components = append(components, string(prelude[compStart:i]))
			compOffsets = append(compOffsets, absoluteOffset+compStart)
			compStart = i + 1
		}
		i++
	}

	if insideComment {
		return
	}

	components = append(components, string(prelude[compStart:n]))
	compOffsets = append(compOffsets, absoluteOffset+compStart)

	for idx, comp := range components {
		compRaw := comp
		comp = strings.TrimSpace(comp)
		if comp == "" {
			continue
		}

		if strings.ContainsRune(comp, '"') || strings.ContainsRune(comp, '\'') {
			return
		}

		lowerComp := strings.ToLower(comp)
		if lowerComp == "from" || lowerComp == "to" {
			continue
		}

		if strings.ContainsAny(lowerComp, " \t\n\r") {
			continue
		}

		hasPercent := strings.HasSuffix(lowerComp, "%")
		numStr := lowerComp
		if hasPercent {
			numStr = strings.TrimSuffix(lowerComp, "%")
		}

		num, err := strconv.ParseFloat(numStr, 64)
		if err == nil {
			firstNonWS := 0
			for firstNonWS < len(compRaw) && (compRaw[firstNonWS] == ' ' || compRaw[firstNonWS] == '\t' || compRaw[firstNonWS] == '\n' || compRaw[firstNonWS] == '\r') {
				firstNonWS++
			}
			if !hasPercent {
				collector.add(cssFindingAtLine("invalid-keyframe-selector", rel, cssLineForOffset(offsets, compOffsets[idx]+firstNonWS)))
			} else {
				if num < 0 || num > 100 {
					collector.add(cssFindingAtLine("invalid-keyframe-selector", rel, cssLineForOffset(offsets, compOffsets[idx]+firstNonWS)))
				}
			}
		}
	}
}
