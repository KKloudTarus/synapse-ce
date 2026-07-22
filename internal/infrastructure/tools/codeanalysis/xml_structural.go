package codeanalysis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type xmlTerminalFailure struct {
	kind        string
	reportLine  int
	startOffset int64
	endOffset   int64
}

type xmlStructuralResult struct {
	Findings []ports.CodeAnalysisRawFinding
	Terminal *xmlTerminalFailure
}

func scanXMLStructural(rel string, content []byte, parserFailureOffset int64) xmlStructuralResult {
	res := xmlStructuralResult{
		Findings: []ports.CodeAnalysisRawFinding{},
	}

	line := 1
	i := 0

	type elem struct {
		name string
		line int
	}
	var elemStack []elem
	var nsStack []map[string]string

	rootsSeen := 0

	advance := func(n int) {
		for j := 0; j < n && i+j < len(content); j++ {
			if content[i+j] == '\n' {
				line++
			}
		}
		i += n
	}

	var recoveryLost bool

Outer:
	for i < len(content) {
		if parserFailureOffset >= 0 && int64(i) >= parserFailureOffset {
			recoveryLost = true
			break Outer
		}
		if content[i] == '&' && i+1 < len(content) && content[i+1] == '#' {
			startLine := line

			consumed, finding, terminal := checkCharRef(content, i+2, startLine, rel, false)
			consumed += 2

			if finding != nil {
				res.Findings = append(res.Findings, *finding)
				if terminal {
					if res.Terminal == nil {
						res.Terminal = &xmlTerminalFailure{
							kind:        finding.RuleID,
							reportLine:  startLine,
							startOffset: int64(i),
							endOffset:   int64(i + consumed),
						}
					}
					recoveryLost = true
					break Outer
				}
			}
			advance(consumed)
			continue
		}

		if content[i] == '<' {
			if hasPrefixExact(content, i, "<!--") {
				commentStart := i
				startLine := line
				advance(4)

				end := i
				for end < len(content) {
					if hasPrefixExact(content, end, "-->") {
						break
					}
					end++
				}

				if end < len(content) {
					commentBody := string(content[i:end])
					if strings.Contains(commentBody, "--") || strings.HasSuffix(commentBody, "-") {
						res.Findings = append(res.Findings, xmlRawFinding(
							xmlInvalidCommentRuleID,
							rel,
							startLine,
							"Comment contains '--' or ends with '-'.",
						))
						if res.Terminal == nil {
							res.Terminal = &xmlTerminalFailure{
								kind:        xmlInvalidCommentRuleID,
								reportLine:  startLine,
								startOffset: int64(commentStart),
								endOffset:   int64(end + 3),
							}
						}
						recoveryLost = true
						break Outer
					}
					advance(end - i + 3)
				} else {
					res.Findings = append(res.Findings, xmlRawFinding(
						xmlInvalidCommentRuleID,
						rel,
						startLine,
						"Unterminated comment.",
					))
					if res.Terminal == nil {
						res.Terminal = &xmlTerminalFailure{
							kind:        xmlInvalidCommentRuleID,
							reportLine:  startLine,
							startOffset: int64(len(content)),
							endOffset:   int64(len(content)),
						}
					}
					recoveryLost = true
					break Outer
				}
				continue
			}

			if hasPrefixExact(content, i, "<![CDATA[") {
				advance(9)
				end := i
				for end < len(content) {
					if hasPrefixExact(content, end, "]]>") {
						break
					}
					end++
				}
				if end < len(content) {
					advance(end - i + 3)
				} else {
					recoveryLost = true
					break Outer
				}
				continue
			}

			if hasPrefixExact(content, i, "<?") {
				advance(2)
				end := i
				for end < len(content) {
					if hasPrefixExact(content, end, "?>") {
						break
					}
					end++
				}
				if end < len(content) {
					advance(end - i + 2)
				} else {
					recoveryLost = true
					break Outer
				}
				continue
			}

			if hasPrefixExact(content, i, "<!DOCTYPE") {
				advance(9)
				inStr := false
				var q byte
				bracketDepth := 0
				for i < len(content) {
					if !inStr && hasPrefixExact(content, i, "<!--") {
						commentStart := i
						commentStartLine := line
						advance(4)

						end := i
						for end < len(content) {
							if hasPrefixExact(content, end, "-->") {
								break
							}
							end++
						}

						if end < len(content) {
							commentBody := string(content[i:end])
							if strings.Contains(commentBody, "--") || strings.HasSuffix(commentBody, "-") {
								res.Findings = append(res.Findings, xmlRawFinding(
									xmlInvalidCommentRuleID,
									rel,
									commentStartLine,
									"Comment contains '--' or ends with '-'.",
								))
								if res.Terminal == nil {
									res.Terminal = &xmlTerminalFailure{
										kind:        xmlInvalidCommentRuleID,
										reportLine:  commentStartLine,
										startOffset: int64(commentStart),
										endOffset:   int64(end + 3),
									}
								}
								recoveryLost = true
								break Outer
							}
							advance(end - i + 3)
						} else {
							res.Findings = append(res.Findings, xmlRawFinding(
								xmlInvalidCommentRuleID,
								rel,
								commentStartLine,
								"Unterminated comment.",
							))
							if res.Terminal == nil {
								res.Terminal = &xmlTerminalFailure{
									kind:        xmlInvalidCommentRuleID,
									reportLine:  commentStartLine,
									startOffset: int64(len(content)),
									endOffset:   int64(len(content)),
								}
							}
							recoveryLost = true
							break Outer
						}
						continue
					}

					if !inStr && (content[i] == '"' || content[i] == '\'') {
						inStr = true
						q = content[i]
					} else if inStr && content[i] == q {
						inStr = false
					} else if !inStr {
						if content[i] == '[' {
							bracketDepth++
						} else if content[i] == ']' {
							bracketDepth--
						} else if content[i] == '>' && bracketDepth <= 0 {
							break
						}
					}
					advance(1)
				}
				if i < len(content) {
					advance(1)
				} else {
					recoveryLost = true
					break Outer
				}
				continue
			}

			// End tag
			if hasPrefixExact(content, i, "</") {
				tagStart := i
				startLine := line
				advance(2)
				end := i
				for end < len(content) && content[end] != '>' && !isXMLSpaceByte(content[end]) {
					end++
				}
				name := string(content[i:end])

				endTagSyntaxValid := true
				if !isValidXMLName(name) {
					endTagSyntaxValid = false
				}
				cursor := end
				for cursor < len(content) && content[cursor] != '>' {
					if !isXMLSpaceByte(content[cursor]) {
						endTagSyntaxValid = false
					}
					cursor++
				}
				if cursor >= len(content) {
					endTagSyntaxValid = false
				}

				for end < len(content) && content[end] != '>' {
					end++
				}
				if end < len(content) {
					advance(end - i + 1)
				} else {
					recoveryLost = true
					break Outer
				}
				tagEnd := i

				if !endTagSyntaxValid {
					recoveryLost = true
					break Outer
				}

				if len(elemStack) > 0 {
					top := elemStack[len(elemStack)-1]
					if top.name != name {
						found := -1
						for j := len(elemStack) - 1; j >= 0; j-- {
							if elemStack[j].name == name {
								found = j
								break
							}
						}

						if found != -1 {
							res.Findings = append(res.Findings, xmlRawFinding(
								xmlMismatchedTagRuleID,
								rel,
								startLine,
								fmt.Sprintf("Mismatched end tag </%s>. Expected </%s>.", name, top.name),
							))
							if res.Terminal == nil {
								res.Terminal = &xmlTerminalFailure{
									kind:        xmlMismatchedTagRuleID,
									reportLine:  startLine,
									startOffset: int64(tagStart),
									endOffset:   int64(tagEnd),
								}
							}
							elemStack = elemStack[:found]
							nsStack = nsStack[:found]
							recoveryLost = true
							break Outer
						} else {
							res.Findings = append(res.Findings, xmlRawFinding(
								xmlMismatchedTagRuleID,
								rel,
								startLine,
								fmt.Sprintf("Mismatched end tag </%s> with no matching open element.", name),
							))
							if res.Terminal == nil {
								res.Terminal = &xmlTerminalFailure{
									kind:        xmlMismatchedTagRuleID,
									reportLine:  startLine,
									startOffset: int64(tagStart),
									endOffset:   int64(tagEnd),
								}
							}
							recoveryLost = true
							break Outer
						}
					} else {
						elemStack = elemStack[:len(elemStack)-1]
						if len(nsStack) > 0 {
							nsStack = nsStack[:len(nsStack)-1]
						}
					}
				} else {
					res.Findings = append(res.Findings, xmlRawFinding(
						xmlMismatchedTagRuleID,
						rel,
						startLine,
						fmt.Sprintf("Mismatched end tag </%s> with no open element.", name),
					))
					if res.Terminal == nil {
						res.Terminal = &xmlTerminalFailure{
							kind:        xmlMismatchedTagRuleID,
							reportLine:  startLine,
							startOffset: int64(tagStart),
							endOffset:   int64(tagEnd),
						}
					}
					recoveryLost = true
					break Outer
				}

				if recoveryLost {
					break Outer
				}
				continue
			}

			// Start tag
			if hasPrefixExact(content, i, "<") {
				tagStart := i
				startLine := line

				advance(1)

				end := i
				for end < len(content) && content[end] != '>' && content[end] != '/' && !isXMLSpaceByte(content[end]) {
					end++
				}
				name := string(content[i:end])
				if !isValidXMLName(name) {
					recoveryLost = true
					break Outer
				}

				advance(end - i)

				type attrToken struct {
					name        string
					val         string
					startOffset int
					nameLine    int
					valueLine   int
				}
				var attrs []attrToken
				selfClosing := false

				for i < len(content) && content[i] != '>' && content[i] != '/' {
					if isXMLSpaceByte(content[i]) {
						advance(1)
						continue
					}

					nameLine := line
					attrStart := i
					for i < len(content) && content[i] != '=' && content[i] != '>' && !isXMLSpaceByte(content[i]) && content[i] != '/' {
						advance(1)
					}
					attrName := string(content[attrStart:i])

					if !isValidXMLName(attrName) {
						recoveryLost = true
						break Outer
					}

					for i < len(content) && isXMLSpaceByte(content[i]) {
						advance(1)
					}

					attrVal := ""
					valStart := 0
					var valueLine int
					if i < len(content) && content[i] == '=' {
						advance(1)
						for i < len(content) && isXMLSpaceByte(content[i]) {
							advance(1)
						}
						if i < len(content) && (content[i] == '"' || content[i] == '\'') {
							q := content[i]
							advance(1)
							valStart = i
							valueLine = line
							for i < len(content) && content[i] != q {
								advance(1)
							}
							if i < len(content) && content[i] == q {
								attrVal = string(content[valStart:i])
								advance(1)

								vBytes := []byte(attrVal)
								vLine := valueLine
								vIdx := 0
								for vIdx < len(vBytes) {
									if vBytes[vIdx] == '\n' {
										vLine++
									}
									if vBytes[vIdx] == '&' && vIdx+1 < len(vBytes) && vBytes[vIdx+1] == '#' {
										vConsumed, vFinding, vTerminal := checkCharRef(vBytes, vIdx+2, vLine, rel, true)
										vConsumed += 2
										if vFinding != nil {
											res.Findings = append(res.Findings, *vFinding)
											if vTerminal {
												if res.Terminal == nil {
													res.Terminal = &xmlTerminalFailure{
														kind:        vFinding.RuleID,
														reportLine:  vLine,
														startOffset: int64(valStart + vIdx),
														endOffset:   int64(valStart + len(attrVal) + 1),
													}
												}
												recoveryLost = true
												break Outer
											}
										}
										vIdx += vConsumed
										continue
									}
									vIdx++
								}
							} else {
								recoveryLost = true
								break Outer
							}
						} else {
							recoveryLost = true
							break Outer
						}
					} else {
						recoveryLost = true
						break Outer
					}
					attrs = append(attrs, attrToken{name: attrName, val: attrVal, startOffset: valStart, nameLine: nameLine, valueLine: valueLine})
				}

				if i < len(content) && content[i] == '>' {
					advance(1)
				} else if i+1 < len(content) && content[i] == '/' && content[i+1] == '>' {
					selfClosing = true
					advance(2)
				} else {
					recoveryLost = true
					break Outer
				}
				tagEnd := i

				if len(elemStack) == 0 {
					rootsSeen++
					if rootsSeen > 1 {
						res.Findings = append(res.Findings, xmlRawFinding(
							xmlMultipleRootElementsRuleID,
							rel,
							startLine,
							"Multiple root elements detected.",
						))
						if res.Terminal == nil {
							res.Terminal = &xmlTerminalFailure{
								kind:        xmlMultipleRootElementsRuleID,
								reportLine:  startLine,
								startOffset: int64(tagStart),
								endOffset:   int64(tagEnd),
							}
						}
						recoveryLost = true
						break Outer
					}
				}

				newNs := make(map[string]string)
				for _, attr := range attrs {
					if attr.name == "xmlns" {
						newNs[""] = attr.val
					} else if strings.HasPrefix(attr.name, "xmlns:") {
						newNs[strings.TrimPrefix(attr.name, "xmlns:")] = attr.val
					}
				}

				resolvePrefix := func(prefix string) (string, bool) {
					if prefix == "xml" {
						return "http://www.w3.org/XML/1998/namespace", true
					}
					if prefix == "xmlns" {
						return "http://www.w3.org/2000/xmlns/", true
					}
					if uri, ok := newNs[prefix]; ok {
						return uri, true
					}
					for j := len(nsStack) - 1; j >= 0; j-- {
						if uri, ok := nsStack[j][prefix]; ok {
							return uri, true
						}
					}
					return "", false
				}

				rawSeen := make(map[string]bool)
				expandedAttrs := make(map[string]bool)

				for _, attr := range attrs {
					// Duplicate check for raw literal QNames (before namespace expansion).
					// Emitting here ensures it is barrier-aware and won't fire after a parser failure.
					if rawSeen[attr.name] {
						res.Findings = append(res.Findings, xmlRawFinding(
							xmlDuplicateAttributeRuleID,
							rel,
							attr.nameLine,
							fmt.Sprintf("Duplicate attribute %q.", attr.name),
						))
						continue
					}
					rawSeen[attr.name] = true

					if attr.name == "xmlns" || strings.HasPrefix(attr.name, "xmlns:") {
						continue
					}
					parts := strings.Split(attr.name, ":")
					local := attr.name
					uri := ""
					resolved := true
					if len(parts) == 2 {
						uri, resolved = resolvePrefix(parts[0])
						local = parts[1]
					}

					// If the prefix is undeclared, don't flag as expanded duplicate (will be flagged as undeclared prefix)
					if !resolved {
						continue
					}

					key := fmt.Sprintf("{%s}%s", uri, local)
					if expandedAttrs[key] {
						res.Findings = append(res.Findings, xmlRawFinding(
							xmlDuplicateAttributeRuleID,
							rel,
							attr.nameLine,
							fmt.Sprintf("Duplicate attribute %q.", attr.name),
						))
					} else {
						expandedAttrs[key] = true
					}
				}

				checkPrefix := func(qname string, reportLine int) {
					parts := strings.Split(qname, ":")
					if len(parts) == 2 {
						prefix := parts[0]
						_, resolved := resolvePrefix(prefix)
						if !resolved {
							res.Findings = append(res.Findings, xmlRawFinding(
								xmlUndeclaredPrefixRuleID,
								rel,
								reportLine,
								fmt.Sprintf("Undeclared namespace prefix %q.", prefix),
							))
						}
					}
				}

				checkPrefix(name, startLine)
				for _, attr := range attrs {
					checkPrefix(attr.name, attr.nameLine)
				}

				// Character references are now checked during attribute parsing.

				if !selfClosing {
					elemStack = append(elemStack, elem{name: name, line: startLine})
					nsStack = append(nsStack, newNs)
				}
				continue
			}
		}

		advance(1)
	}

	// If the generic parser failed before EOF but the structural scanner never
	// reached that offset (e.g. early break), treat recovery as lost so we do
	// not emit unclosed-element from an untrustworthy stack.
	if parserFailureOffset >= 0 &&
		parserFailureOffset < int64(len(content)) &&
		res.Terminal == nil {
		recoveryLost = true
	}

	if !recoveryLost && len(elemStack) > 0 {
		e := elemStack[len(elemStack)-1]
		res.Findings = append(res.Findings, xmlRawFinding(
			xmlUnclosedElementRuleID,
			rel,
			e.line,
			fmt.Sprintf("Unclosed element <%s>.", e.name),
		))
		if res.Terminal == nil {
			res.Terminal = &xmlTerminalFailure{
				kind:        xmlUnclosedElementRuleID,
				reportLine:  e.line,
				startOffset: int64(len(content)),
				endOffset:   int64(len(content)),
			}
		}
	}

	return res
}

func checkCharRef(content []byte, startIdx, line int, rel string, inAttr bool) (consumed int, finding *ports.CodeAnalysisRawFinding, terminal bool) {
	end := startIdx
	isHex := false
	if end < len(content) && content[end] == 'x' {
		isHex = true
		end++
	}

	for end < len(content) {
		c := content[end]
		if isHex {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				break
			}
		} else {
			if !(c >= '0' && c <= '9') {
				break
			}
		}
		end++
	}

	if end < len(content) && content[end] == ';' {
		refStr := string(content[startIdx:end])
		if !isValidCharRef(refStr) {
			msgRef := refStr
			if len(msgRef) > 10 {
				msgRef = msgRef[:10] + "..."
			}
			msg := fmt.Sprintf("Invalid character reference: &#%s;", msgRef)
			if inAttr {
				msg = fmt.Sprintf("Invalid character reference in attribute: &#%s;", msgRef)
			}
			f := xmlRawFinding(xmlInvalidCharacterReferenceRuleID, rel, line, msg)
			return end - startIdx + 1, &f, true
		}
		return end - startIdx + 1, nil, false
	}

	msg := "Malformed character reference missing semicolon."
	if inAttr {
		msg = "Malformed character reference missing semicolon in attribute."
	}
	f := xmlRawFinding(xmlInvalidCharacterReferenceRuleID, rel, line, msg)
	return end - startIdx, &f, true
}

func isValidCharRef(ref string) bool {
	if len(ref) == 0 {
		return false
	}
	var val uint64
	var err error
	if ref[0] == 'x' {
		val, err = strconv.ParseUint(ref[1:], 16, 32)
	} else if ref[0] == 'X' {
		return false
	} else {
		val, err = strconv.ParseUint(ref, 10, 32)
	}
	if err != nil {
		return false
	}
	return val == 0x9 || val == 0xA || val == 0xD ||
		(val >= 0x20 && val <= 0xD7FF) ||
		(val >= 0xE000 && val <= 0xFFFD) ||
		(val >= 0x10000 && val <= 0x10FFFF)
}

func isValidXMLName(name string) bool {
	if name == "" {
		return false
	}
	parts := strings.Split(name, ":")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if !isXMLNameStartByte(part[0]) {
			return false
		}
		for i := 1; i < len(part); i++ {
			if !isXMLNameByte(part[i]) {
				return false
			}
		}
	}
	return true
}
