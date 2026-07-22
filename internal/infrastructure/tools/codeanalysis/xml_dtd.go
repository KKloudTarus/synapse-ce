package codeanalysis

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxEntityExpansionLimit = 2000
	maxEntityGraphDepth     = 20
	maxEntityDeclarations   = 500
)

type entityDecl struct {
	name    string
	val     string
	line    int
	isParam bool
	isExt   bool
}

func parseDeclaredEntities(content []byte) map[string]string {
	out := make(map[string]string)
	decls := scanEntityDeclarations(content)
	for _, d := range decls {
		if !d.isParam {
			out[d.name] = d.val
		}
	}
	return out
}

func scanEntityDeclarations(content []byte) []entityDecl {
	var decls []entityDecl
	line := 1
	for i := 0; i < len(content); {
		if content[i] == '\n' {
			line++
			i++
			continue
		}
		if content[i] != '<' {
			i++
			continue
		}

		switch {
		case hasPrefix(content, i, "<!--"):
			i = skipUntil(content, i+4, []byte("-->"), &line)
			continue
		case hasPrefix(content, i, "<![CDATA["):
			i = skipUntil(content, i+9, []byte("]]>"), &line)
			continue
		case i+1 < len(content) && content[i+1] == '?':
			i = skipUntil(content, i+2, []byte("?>"), &line)
			continue
		case hasPrefix(content, i, "<!ENTITY") || hasPrefix(content, i, "<!entity"):
			declStartLine := line
			i += 8
			i = skipXMLSpace(content, i, &line)

			isParam := false
			if i < len(content) && content[i] == '%' {
				isParam = true
				i++
				i = skipXMLSpace(content, i, &line)
			}

			nameStart := i
			for i < len(content) && isXMLNameByte(content[i]) {
				i++
			}
			if nameStart == i {
				continue
			}
			name := string(content[nameStart:i])

			i = skipXMLSpace(content, i, &line)

			isExt := false
			val := ""

			// Check for SYSTEM or PUBLIC
			if hasWordPrefix(content, i, "SYSTEM") || hasWordPrefix(content, i, "system") {
				isExt = true
			} else if hasWordPrefix(content, i, "PUBLIC") || hasWordPrefix(content, i, "public") {
				isExt = true
			}

			// Capture literal value if quotes exist before '>'
			quoteStart := skipToQuote(content, i, &line)
			if quoteStart < len(content) {
				q := content[quoteStart]
				valStart := quoteStart + 1
				valEnd := skipXMLAttributeValue(content, quoteStart, &line)
				if valEnd > valStart {
					if content[valEnd-1] == q {
						val = string(content[valStart : valEnd-1])
					} else {
						val = string(content[valStart:valEnd])
					}
				}
			}

			i = skipUntil(content, i, []byte(">"), &line)

			decls = append(decls, entityDecl{
				name:    name,
				val:     val,
				line:    declStartLine,
				isParam: isParam,
				isExt:   isExt,
			})
			if len(decls) >= maxEntityDeclarations {
				return decls
			}
		default:
			i++
		}
	}
	return decls
}

func scanXMLDTD(rel string, content []byte) []ports.CodeAnalysisRawFinding {
	var out []ports.CodeAnalysisRawFinding

	line := 1
	doctypeLine := 0
	hasExtDTD := false

	// Scan DOCTYPE
	for i := 0; i < len(content); {
		if content[i] == '\n' {
			line++
			i++
			continue
		}
		if content[i] != '<' {
			i++
			continue
		}
		switch {
		case hasPrefix(content, i, "<!--"):
			i = skipUntil(content, i+4, []byte("-->"), &line)
		case hasPrefix(content, i, "<![CDATA["):
			i = skipUntil(content, i+9, []byte("]]>"), &line)
		case i+1 < len(content) && content[i+1] == '?':
			i = skipUntil(content, i+2, []byte("?>"), &line)
		case hasPrefix(content, i, "<!DOCTYPE") || hasPrefix(content, i, "<!doctype"):
			doctypeLine = line
			endDoc := skipUntil(content, i+9, []byte(">"), &line)
			docChunk := string(content[i:endDoc])
			if containsKeyword(docChunk, "SYSTEM") || containsKeyword(docChunk, "PUBLIC") {
				hasExtDTD = true
				out = append(out, xmlRawFinding(
					xmlExternalDTDRuleID,
					rel,
					doctypeLine,
					"External DOCTYPE reference can lead to XML External Entity (XXE) vulnerabilities or server-side request forgery.",
				))
			}
			i = endDoc
		default:
			i++
		}
	}

	// Scan Entities
	decls := scanEntityDeclarations(content)
	hasExtEntity := false
	hasExtParamEntity := false
	hasEntityExpansion := false

	internalMap := make(map[string]string)
	internalLines := make(map[string]int)

	for _, d := range decls {
		if d.isExt {
			if d.isParam {
				hasExtParamEntity = true
				out = append(out, xmlRawFinding(
					xmlExternalParamEntityRuleID,
					rel,
					d.line,
					fmt.Sprintf("External parameter entity %q can lead to XXE attacks or out-of-band data exfiltration.", d.name),
				))
			} else {
				hasExtEntity = true
				out = append(out, xmlRawFinding(
					xmlExternalEntityRuleID,
					rel,
					d.line,
					fmt.Sprintf("External general entity %q can lead to file disclosure or XXE vulnerabilities.", d.name),
				))
			}
		} else if !d.isParam {
			internalMap[d.name] = d.val
			internalLines[d.name] = d.line
		}
	}

	// Analyze internal entity expansion graphs
	reportedExpansion := make(map[string]bool)
	for name, val := range internalMap {
		declLine := internalLines[name]
		visited := make(map[string]bool)
		isDangerous, _ := hasDangerousExpansion(name, val, internalMap, visited, 0)
		if isDangerous {
			hasEntityExpansion = true
			if !reportedExpansion[name] {
				reportedExpansion[name] = true
				out = append(out, xmlRawFinding(
					xmlEntityExpansionRuleID,
					rel,
					declLine,
					fmt.Sprintf("Entity %q has a recursive or excessive expansion structure susceptible to entity-expansion DoS (Billion Laughs).", name),
				))
			}
		}
	}

	// Noise control for doctype-present
	if doctypeLine > 0 && !hasExtDTD && !hasExtEntity && !hasExtParamEntity && !hasEntityExpansion {
		out = append(out, xmlRawFinding(
			xmlDoctypePresentRuleID,
			rel,
			doctypeLine,
			"XML DOCTYPE declaration is present. Review parser configuration to ensure DTD processing and entity expansion are disabled.",
		))
	}

	return out
}

func hasDangerousExpansion(name, val string, decls map[string]string, visited map[string]bool, depth int) (bool, int) {
	if depth > maxEntityGraphDepth {
		return true, maxEntityExpansionLimit + 1
	}
	if visited[name] {
		return true, maxEntityExpansionLimit + 1 // Cycle / self-reference
	}
	visited[name] = true
	defer func() { visited[name] = false }()

	refs := extractEntityRefs(val)
	total := len(val)

	for _, ref := range refs {
		refVal, exists := decls[ref]
		if !exists {
			continue
		}
		isDangerous, refExpandedSize := hasDangerousExpansion(ref, refVal, decls, visited, depth+1)
		if isDangerous {
			return true, maxEntityExpansionLimit + 1
		}
		total += refExpandedSize
		if total > maxEntityExpansionLimit {
			return true, total
		}
	}
	return false, total
}

func extractEntityRefs(val string) []string {
	var refs []string
	for i := 0; i < len(val); i++ {
		if val[i] == '&' && i+1 < len(val) && val[i+1] != '#' {
			start := i + 1
			end := start
			for end < len(val) && (isXMLNameByte(val[end])) {
				if val[end] == ';' {
					break
				}
				end++
			}
			if end < len(val) && val[end] == ';' && end > start {
				refs = append(refs, val[start:end])
			}
		}
	}
	return refs
}

func hasWordPrefix(content []byte, i int, word string) bool {
	if i+len(word) > len(content) {
		return false
	}
	if !strings.EqualFold(string(content[i:i+len(word)]), word) {
		return false
	}
	if i+len(word) < len(content) {
		next := content[i+len(word)]
		if !isXMLSpaceByte(next) && next != '>' && next != '[' {
			return false
		}
	}
	return true
}

func containsKeyword(s, kw string) bool {
	return strings.Contains(strings.ToUpper(s), kw)
}

func isXMLSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

func skipToQuote(content []byte, i int, line *int) int {
	for i < len(content) {
		if content[i] == '\n' {
			*line++
		}
		if content[i] == '>' {
			return len(content)
		}
		if content[i] == '"' || content[i] == '\'' {
			return i
		}
		i++
	}
	return i
}
