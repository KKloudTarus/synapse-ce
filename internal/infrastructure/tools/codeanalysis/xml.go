package codeanalysis

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	xmlNotWellFormedRuleID      = "xml:not-well-formed"
	xmlDuplicateAttributeRuleID = "xml:duplicate-attribute"
)

type xmlRule struct {
	id       string
	title    string
	severity shared.Severity
}

func builtinXMLRules() []xmlRule {
	return []xmlRule{
		{
			id:       xmlNotWellFormedRuleID,
			title:    "XML document is not well formed",
			severity: shared.SeverityMedium,
		},
		{
			id:       xmlDuplicateAttributeRuleID,
			title:    "Duplicate XML attribute",
			severity: shared.SeverityLow,
		},
	}
}

func isXMLSource(ext, lang string) bool {
	if lang == "XML" {
		return true
	}
	switch ext {
	case ".xml", ".xsd", ".xsl", ".xslt", ".wsdl":
		return true
	default:
		return false
	}
}

func scanXMLFile(rel string, content []byte) []ports.CodeAnalysisRawFinding {
	out := scanXMLDuplicateAttributes(rel, content)
	if f, ok := scanXMLWellFormed(rel, content); ok {
		out = append(out, f)
	}
	return out
}

func xmlRawFinding(id, title string, severity shared.Severity, rel string, line int, desc string) ports.CodeAnalysisRawFinding {
	if line <= 0 {
		line = 1
	}
	return ports.CodeAnalysisRawFinding{
		Kind:        kindReliability,
		RuleID:      id,
		CWE:         "",
		Severity:    severity,
		Title:       title,
		Description: desc,
		File:        rel,
		Line:        line,
	}
}

func scanXMLWellFormed(rel string, content []byte) (ports.CodeAnalysisRawFinding, bool) {
	dec := xml.NewDecoder(bytes.NewReader(content))
	rootCount := 0
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if rootCount == 0 && len(bytes.TrimSpace(content)) > 0 {
				return xmlRawFinding(
					xmlNotWellFormedRuleID,
					"XML document is not well formed",
					shared.SeverityMedium,
					rel,
					1,
					"XML parsing reached the end of the file without a document element.",
				), true
			}
			return ports.CodeAnalysisRawFinding{}, false
		}
		if err != nil {
			line, _ := dec.InputPos()
			var syntaxErr *xml.SyntaxError
			if errors.As(err, &syntaxErr) && syntaxErr.Line > 0 {
				line = syntaxErr.Line
			}
			msg := strings.TrimSpace(err.Error())
			return xmlRawFinding(
				xmlNotWellFormedRuleID,
				"XML document is not well formed",
				shared.SeverityMedium,
				rel,
				line,
				"XML parsing failed before the full document could be read: "+msg+".",
			), true
		}
		switch tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				rootCount++
				if rootCount > 1 {
					line, _ := dec.InputPos()
					return xmlRawFinding(
						xmlNotWellFormedRuleID,
						"XML document is not well formed",
						shared.SeverityMedium,
						rel,
						line,
						"XML parsing found more than one top-level document element.",
					), true
				}
			}
			depth++
		case xml.EndElement:
			if depth > 0 {
				depth--
			}
		}
	}
}

func scanXMLDuplicateAttributes(rel string, content []byte) []ports.CodeAnalysisRawFinding {
	var out []ports.CodeAnalysisRawFinding
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
		case i+1 < len(content) && content[i+1] == '!':
			i = skipUntil(content, i+2, []byte(">"), &line)
			continue
		case i+1 < len(content) && content[i+1] == '/':
			i++
			continue
		case i+1 >= len(content) || !isXMLNameStartByte(content[i+1]):
			i++
			continue
		}

		i += 2 // skip '<' and first name byte
		for i < len(content) && isXMLNameByte(content[i]) {
			if content[i] == '\n' {
				line++
			}
			i++
		}

		seen := map[string]int{}
		for i < len(content) {
			i = skipXMLSpace(content, i, &line)
			if i >= len(content) {
				return out
			}
			if content[i] == '>' {
				i++
				break
			}
			if content[i] == '/' && i+1 < len(content) && content[i+1] == '>' {
				i += 2
				break
			}

			attrLine := line
			nameStart := i
			for i < len(content) && isXMLNameByte(content[i]) {
				i++
			}
			if nameStart == i {
				if content[i] == '\n' {
					line++
				}
				i++
				continue
			}
			name := string(content[nameStart:i])
			if _, ok := seen[name]; ok {
				desc := fmt.Sprintf("Element start tag repeats attribute %q, which violates XML well-formedness and can make configuration interpretation ambiguous.", name)
				out = append(out, xmlRawFinding(
					xmlDuplicateAttributeRuleID,
					"Duplicate XML attribute",
					shared.SeverityLow,
					rel,
					attrLine,
					desc,
				))
			} else {
				seen[name] = attrLine
			}

			i = skipXMLSpace(content, i, &line)
			if i < len(content) && content[i] == '=' {
				i++
				i = skipXMLSpace(content, i, &line)
				i = skipXMLAttributeValue(content, i, &line)
			}
		}
	}
	return out
}

func hasPrefix(content []byte, i int, prefix string) bool {
	return i+len(prefix) <= len(content) && string(content[i:i+len(prefix)]) == prefix
}

func skipUntil(content []byte, i int, marker []byte, line *int) int {
	for i < len(content) {
		if len(marker) > 0 && i+len(marker) <= len(content) && bytes.Equal(content[i:i+len(marker)], marker) {
			return i + len(marker)
		}
		if content[i] == '\n' {
			*line = *line + 1
		}
		i++
	}
	return i
}

func skipXMLSpace(content []byte, i int, line *int) int {
	for i < len(content) {
		switch content[i] {
		case ' ', '\t', '\r':
			i++
		case '\n':
			*line = *line + 1
			i++
		default:
			return i
		}
	}
	return i
}

func skipXMLAttributeValue(content []byte, i int, line *int) int {
	if i >= len(content) {
		return i
	}
	quote := content[i]
	if quote != '"' && quote != '\'' {
		return i
	}
	i++
	for i < len(content) {
		if content[i] == '\n' {
			*line = *line + 1
		}
		if content[i] == quote {
			return i + 1
		}
		i++
	}
	return i
}

func isXMLNameStartByte(b byte) bool {
	return b == ':' || b == '_' || b >= 0x80 || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isXMLNameByte(b byte) bool {
	return isXMLNameStartByte(b) || b == '-' || b == '.' || (b >= '0' && b <= '9')
}
