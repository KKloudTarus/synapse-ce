package codeanalysis

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	domainrule "github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	xmlNotWellFormedRuleID             = "xml:not-well-formed"
	xmlDuplicateAttributeRuleID        = "xml:duplicate-attribute"
	xmlExternalEntityRuleID            = "xml:external-entity"
	xmlExternalDTDRuleID               = "xml:external-dtd"
	xmlExternalParamEntityRuleID       = "xml:external-parameter-entity"
	xmlXIncludeRuleID                  = "xml:xinclude"
	xmlEntityExpansionRuleID           = "xml:entity-expansion"
	xmlDoctypePresentRuleID            = "xml:doctype-present"
	xmlExternalSchemaLocationRuleID    = "xml:external-schema-location"
	xmlHardcodedSecretRuleID           = "xml:hardcoded-secret" // #nosec G101 -- Stable rule identifier, not a credential.
	xmlMismatchedTagRuleID             = "xml:mismatched-tag"
	xmlUnclosedElementRuleID           = "xml:unclosed-element"
	xmlMultipleRootElementsRuleID      = "xml:multiple-root-elements"
	xmlUndeclaredPrefixRuleID          = "xml:undeclared-prefix"
	xmlInvalidCharacterReferenceRuleID = "xml:invalid-character-reference"
	xmlInvalidCommentRuleID            = "xml:invalid-comment"
)

type xmlRule struct {
	id       string
	title    string
	kind     string
	cwe      string
	severity shared.Severity
	ruleType domainrule.Type
	quality  domainrule.Quality
}

func builtinXMLRules() []xmlRule {
	return []xmlRule{
		{
			id:       xmlNotWellFormedRuleID,
			title:    "XML document is not well formed",
			kind:     kindReliability,
			cwe:      "",
			severity: shared.SeverityMedium,
			ruleType: domainrule.TypeBug,
			quality:  domainrule.QualityReliability,
		},
		{
			id:       xmlDuplicateAttributeRuleID,
			title:    "Duplicate XML attribute",
			kind:     kindReliability,
			cwe:      "",
			severity: shared.SeverityLow,
			ruleType: domainrule.TypeBug,
			quality:  domainrule.QualityReliability,
		},
		{
			id:       xmlExternalEntityRuleID,
			title:    "External general entity declaration",
			kind:     kindSAST,
			cwe:      "CWE-611",
			severity: shared.SeverityHigh,
			ruleType: domainrule.TypeVulnerability,
			quality:  domainrule.QualitySecurity,
		},
		{
			id:       xmlExternalDTDRuleID,
			title:    "External DOCTYPE declaration",
			kind:     kindSAST,
			cwe:      "CWE-611",
			severity: shared.SeverityHigh,
			ruleType: domainrule.TypeVulnerability,
			quality:  domainrule.QualitySecurity,
		},
		{
			id:       xmlExternalParamEntityRuleID,
			title:    "External parameter entity declaration",
			kind:     kindSAST,
			cwe:      "CWE-611",
			severity: shared.SeverityHigh,
			ruleType: domainrule.TypeVulnerability,
			quality:  domainrule.QualitySecurity,
		},
		{
			id:       xmlXIncludeRuleID,
			title:    "XInclude element in XML document",
			kind:     kindSAST,
			cwe:      "CWE-611",
			severity: shared.SeverityHigh,
			ruleType: domainrule.TypeVulnerability,
			quality:  domainrule.QualitySecurity,
		},
		{
			id:       xmlEntityExpansionRuleID,
			title:    "Dangerous XML entity expansion structure",
			kind:     kindSAST,
			cwe:      "CWE-776",
			severity: shared.SeverityMedium,
			ruleType: domainrule.TypeSecurityHotspot,
			quality:  domainrule.QualitySecurity,
		},
		{
			id:       xmlDoctypePresentRuleID,
			title:    "XML DOCTYPE declaration present",
			kind:     kindSAST,
			cwe:      "CWE-611",
			severity: shared.SeverityMedium,
			ruleType: domainrule.TypeSecurityHotspot,
			quality:  domainrule.QualitySecurity,
		},
		{
			id:       xmlExternalSchemaLocationRuleID,
			title:    "External XML schema location reference",
			kind:     kindSAST,
			cwe:      "CWE-611",
			severity: shared.SeverityMedium,
			ruleType: domainrule.TypeSecurityHotspot,
			quality:  domainrule.QualitySecurity,
		},
		{
			id:       xmlHardcodedSecretRuleID,
			title:    "Hardcoded secret in XML configuration",
			kind:     kindSAST,
			cwe:      "CWE-798",
			severity: shared.SeverityMedium,
			ruleType: domainrule.TypeSecurityHotspot,
			quality:  domainrule.QualitySecurity,
		},
		{
			id:       xmlMismatchedTagRuleID,
			title:    "Mismatched XML end tag",
			kind:     kindReliability,
			cwe:      "",
			severity: shared.SeverityMedium,
			ruleType: domainrule.TypeBug,
			quality:  domainrule.QualityReliability,
		},
		{
			id:       xmlUnclosedElementRuleID,
			title:    "Unclosed XML element",
			kind:     kindReliability,
			cwe:      "",
			severity: shared.SeverityMedium,
			ruleType: domainrule.TypeBug,
			quality:  domainrule.QualityReliability,
		},
		{
			id:       xmlMultipleRootElementsRuleID,
			title:    "Multiple XML root elements",
			kind:     kindReliability,
			cwe:      "",
			severity: shared.SeverityMedium,
			ruleType: domainrule.TypeBug,
			quality:  domainrule.QualityReliability,
		},
		{
			id:       xmlUndeclaredPrefixRuleID,
			title:    "Undeclared XML namespace prefix",
			kind:     kindReliability,
			cwe:      "",
			severity: shared.SeverityMedium,
			ruleType: domainrule.TypeBug,
			quality:  domainrule.QualityReliability,
		},
		{
			id:       xmlInvalidCharacterReferenceRuleID,
			title:    "Invalid XML character reference",
			kind:     kindReliability,
			cwe:      "",
			severity: shared.SeverityMedium,
			ruleType: domainrule.TypeBug,
			quality:  domainrule.QualityReliability,
		},
		{
			id:       xmlInvalidCommentRuleID,
			title:    "Invalid XML comment syntax",
			kind:     kindReliability,
			cwe:      "",
			severity: shared.SeverityLow,
			ruleType: domainrule.TypeBug,
			quality:  domainrule.QualityReliability,
		},
	}
}

var xmlRulesByID map[string]xmlRule

func init() {
	xmlRulesByID = make(map[string]xmlRule)
	for _, r := range builtinXMLRules() {
		xmlRulesByID[r.id] = r
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
	declaredEntities := parseDeclaredEntities(content)

	var out []ports.CodeAnalysisRawFinding

	// 1. Lexical / DTD Scan
	out = append(out, scanXMLDTD(rel, content)...)

	// 2. XInclude, Schema Locations, Hardcoded Secrets
	out = append(out, scanXMLSecurityTokens(rel, content, declaredEntities)...)

	// 3. Well-formedness check (with custom entity pre-registration).
	// This runs first to obtain parserFailureOffset, which is used as a
	// hard barrier for all downstream scanners.
	var parserFailureOffset int64 = -1
	if f, offset, ok := scanXMLWellFormed(rel, content, declaredEntities); ok {
		parserFailureOffset = offset
		out = append(out, f)
	}

	// 4. Structural scan (comments, char refs, namespaces, structure, duplicate attrs).
	// Raw duplicate-attribute detection has been moved into the structural scanner so
	// it is subject to the same parserFailureOffset barrier.
	structuralRes := scanXMLStructural(rel, content, parserFailureOffset)

	// Suppress the generic parser failure when the structural scanner identified a
	// more specific terminal rule at the same offset.
	for _, sf := range structuralRes.Findings {
		if structuralRes.Terminal != nil && sf.RuleID == structuralRes.Terminal.kind &&
			parserFailureOffset >= structuralRes.Terminal.startOffset &&
			parserFailureOffset <= structuralRes.Terminal.endOffset {
			for i, gen := range out {
				if gen.RuleID == xmlNotWellFormedRuleID {
					out = append(out[:i], out[i+1:]...)
					break
				}
			}
		}
		out = append(out, sf)
	}

	sortXMLFindings(out)
	return out
}

func sortXMLFindings(findings []ports.CodeAnalysisRawFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Description < findings[j].Description
	})
}

func xmlRawFinding(id string, rel string, line int, desc string) ports.CodeAnalysisRawFinding {
	if line <= 0 {
		line = 1
	}
	r, ok := xmlRulesByID[id]
	if !ok {
		return ports.CodeAnalysisRawFinding{
			Kind:        kindReliability,
			RuleID:      id,
			Severity:    shared.SeverityMedium,
			Title:       id,
			Description: desc,
			File:        rel,
			Line:        line,
		}
	}
	return ports.CodeAnalysisRawFinding{
		Kind:        r.kind,
		RuleID:      r.id,
		CWE:         r.cwe,
		Severity:    r.severity,
		Title:       r.title,
		Description: desc,
		File:        rel,
		Line:        line,
	}
}

func scanXMLWellFormed(rel string, content []byte, declaredEntities map[string]string) (ports.CodeAnalysisRawFinding, int64, bool) {
	dec := xml.NewDecoder(bytes.NewReader(content))
	if len(declaredEntities) > 0 {
		dec.Entity = make(map[string]string)
		for name, val := range declaredEntities {
			if val != "" {
				dec.Entity[name] = val
			} else {
				dec.Entity[name] = "placeholder"
			}
		}
	}
	rootCount := 0
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if rootCount == 0 && len(bytes.TrimSpace(content)) > 0 {
				return xmlRawFinding(
					xmlNotWellFormedRuleID,
					rel,
					1,
					"XML parsing reached the end of the file without a document element.",
				), dec.InputOffset(), true
			}
			return ports.CodeAnalysisRawFinding{}, 0, false
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
				rel,
				line,
				"XML parsing failed before the full document could be read: "+msg+".",
			), dec.InputOffset(), true
		}
		switch tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				rootCount++
				if rootCount > 1 {
					line, _ := dec.InputPos()
					return xmlRawFinding(
						xmlNotWellFormedRuleID,
						rel,
						line,
						"XML parsing found more than one top-level document element.",
					), dec.InputOffset(), true
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
