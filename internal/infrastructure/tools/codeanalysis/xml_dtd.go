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
	_, _, decls := parseXMLDeclarations(content)
	for _, d := range decls {
		if !d.isParam {
			out[d.name] = d.val
		}
	}
	return out
}

func scanXMLDTD(rel string, content []byte) []ports.CodeAnalysisRawFinding {
	var out []ports.CodeAnalysisRawFinding

	doctypeLine, hasExtDTD, decls := parseXMLDeclarations(content)

	if hasExtDTD {
		out = append(out, xmlRawFinding(
			xmlExternalDTDRuleID,
			rel,
			doctypeLine,
			"External DOCTYPE reference can lead to XML External Entity (XXE) vulnerabilities or server-side request forgery.",
		))
	}

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
		return true, maxEntityExpansionLimit + 1
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

func isXMLSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

type lexState int

const (
	stateNormal lexState = iota
	stateDoctype
	stateInternalSubset
	stateEntity
)

func parseXMLDeclarations(content []byte) (int, bool, []entityDecl) {
	line := 1
	var doctypeLine int
	var hasExtDTD bool
	var decls []entityDecl
	var entityBuf []byte
	var doctypeBuf []byte
	var entityStartLine int

	state := stateNormal

	i := 0
	for i < len(content) {
		if content[i] == '\n' {
			line++
		}

		if (state == stateNormal || state == stateInternalSubset) && content[i] == '<' {
			if hasPrefixExact(content, i, "<!--") {
				i = skipUntilExact(content, i+4, "-->", &line)
				continue
			}
			if hasPrefixExact(content, i, "<?") {
				i = skipUntilExact(content, i+2, "?>", &line)
				continue
			}
			if hasPrefixExact(content, i, "<![CDATA[") {
				i = skipUntilExact(content, i+9, "]]>", &line)
				continue
			}
		}

		switch state {
		case stateNormal:
			if content[i] == '<' && hasPrefixExact(content, i, "<!DOCTYPE") {
				if i+9 < len(content) && isXMLSpaceByte(content[i+9]) {
					doctypeLine = line
					state = stateDoctype
					doctypeBuf = doctypeBuf[:0]
					i += 9
					continue
				}
			}
			i++

		case stateDoctype:
			if content[i] == '"' || content[i] == '\'' {
				q := content[i]
				doctypeBuf = append(doctypeBuf, q)
				i++
				for i < len(content) {
					if content[i] == '\n' {
						line++
					}
					doctypeBuf = append(doctypeBuf, content[i])
					if content[i] == q {
						i++
						break
					}
					i++
				}
				continue
			}
			if content[i] == '[' {
				if checkExternalDTD(doctypeBuf) {
					hasExtDTD = true
				}
				state = stateInternalSubset
				i++
				continue
			}
			if content[i] == '>' {
				if checkExternalDTD(doctypeBuf) {
					hasExtDTD = true
				}
				state = stateNormal
				i++
				continue
			}
			doctypeBuf = append(doctypeBuf, content[i])
			i++

		case stateInternalSubset:
			if content[i] == ']' {
				state = stateNormal
				i++
				continue
			}
			if content[i] == '<' && hasPrefixExact(content, i, "<!ENTITY") {
				if i+8 < len(content) && isXMLSpaceByte(content[i+8]) {
					state = stateEntity
					entityBuf = entityBuf[:0]
					entityStartLine = line
					i += 8
					continue
				}
			}
			if content[i] == '"' || content[i] == '\'' {
				q := content[i]
				i++
				for i < len(content) {
					if content[i] == '\n' {
						line++
					}
					if content[i] == q {
						i++
						break
					}
					i++
				}
				continue
			}
			i++

		case stateEntity:
			if content[i] == '"' || content[i] == '\'' {
				q := content[i]
				entityBuf = append(entityBuf, q)
				i++
				for i < len(content) {
					if content[i] == '\n' {
						line++
					}
					entityBuf = append(entityBuf, content[i])
					if content[i] == q {
						i++
						break
					}
					i++
				}
				continue
			}
			if content[i] == '>' {
				if decl := parseEntityBuffer(entityBuf); decl != nil {
					decl.line = entityStartLine
					decls = append(decls, *decl)
					if len(decls) >= maxEntityDeclarations {
						return doctypeLine, hasExtDTD, decls
					}
				}
				state = stateInternalSubset
				i++
				continue
			}
			entityBuf = append(entityBuf, content[i])
			i++
		}
	}
	return doctypeLine, hasExtDTD, decls
}

func hasPrefixExact(content []byte, i int, prefix string) bool {
	if i+len(prefix) > len(content) {
		return false
	}
	for j := 0; j < len(prefix); j++ {
		if content[i+j] != prefix[j] {
			return false
		}
	}
	return true
}

func skipUntilExact(content []byte, i int, suffix string, line *int) int {
	for i < len(content) {
		if content[i] == '\n' {
			*line++
		}
		if hasPrefixExact(content, i, suffix) {
			return i + len(suffix)
		}
		i++
	}
	return i
}

func checkExternalDTD(buf []byte) bool {
	tokens := parseTokensQuoteAware(string(buf))
	for _, t := range tokens {
		if t == "SYSTEM" || t == "PUBLIC" {
			return true
		}
	}
	return false
}

func parseEntityBuffer(buf []byte) *entityDecl {
	tokens := parseTokensQuoteAware(string(buf))
	if len(tokens) == 0 {
		return nil
	}

	isParam := false
	idx := 0
	if tokens[idx] == "%" {
		isParam = true
		idx++
	} else if strings.HasPrefix(tokens[idx], "%") && len(tokens[idx]) > 1 {
		isParam = true
		tokens[idx] = tokens[idx][1:]
	}

	if idx >= len(tokens) {
		return nil
	}
	name := tokens[idx]
	idx++

	isExt := false
	val := ""

	if idx < len(tokens) {
		if tokens[idx] == "SYSTEM" || tokens[idx] == "PUBLIC" {
			isExt = true
			idx++
			if isExt && tokens[idx-1] == "PUBLIC" && idx < len(tokens) {
				idx++
			}
		}

		if idx < len(tokens) {
			val = stripQuotes(tokens[idx])
		}
	}

	return &entityDecl{
		name:    name,
		val:     val,
		isParam: isParam,
		isExt:   isExt,
	}
}

func stripQuotes(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func parseTokensQuoteAware(s string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	var quoteChar rune

	for _, r := range s {
		if inQuote {
			current.WriteRune(r)
			if r == quoteChar {
				inQuote = false
				tokens = append(tokens, current.String())
				current.Reset()
			}
		} else {
			if r == '"' || r == '\'' {
				inQuote = true
				quoteChar = r
				current.WriteRune(r)
			} else if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(r)
			}
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}
