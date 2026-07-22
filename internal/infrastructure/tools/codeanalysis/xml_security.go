package codeanalysis

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func scanXMLSecurityTokens(rel string, content []byte, declaredEntities map[string]string) []ports.CodeAnalysisRawFinding {
	var out []ports.CodeAnalysisRawFinding

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

	type xmlElementFrame struct {
		name string
		line int
		text strings.Builder
	}
	var stack []*xmlElementFrame

	for {
		posLine, _ := dec.InputPos()
		if posLine <= 0 {
			posLine = 1
		}

		tok, err := dec.Token()
		if err != nil || tok == nil {
			break
		}

		switch t := tok.(type) {
		case xml.StartElement:
			frame := &xmlElementFrame{name: t.Name.Local, line: posLine}
			stack = append(stack, frame)

			// 1. Check XInclude
			if isXIncludeElement(t) {
				out = append(out, xmlRawFinding(
					xmlXIncludeRuleID,
					rel,
					posLine,
					"XInclude element can be exploited for file inclusion or XXE vulnerabilities.",
				))
			}

			// 2. Check Schema Location & Hardcoded Secret in Attributes
			nsMap := buildNamespaceMap(t.Attr)

			for _, attr := range t.Attr {
				attrName := attr.Name.Local
				attrSpace := attr.Name.Space

				// Check external schema location
				if isXsiSchemaAttr(attrName, attrSpace, nsMap) {
					if isExternalSchemaLocation(attrName, attr.Value) {
						out = append(out, xmlRawFinding(
							xmlExternalSchemaLocationRuleID,
							rel,
							posLine,
							fmt.Sprintf("External XML schema location detected in attribute %q.", attrName),
						))
					}
				}

				// Check hardcoded secret in attribute
				if isHardcodedSecretField(attrName, attr.Value) {
					out = append(out, xmlRawFinding(
						xmlHardcodedSecretRuleID,
						rel,
						posLine,
						fmt.Sprintf("Hardcoded secret detected in attribute %q.", attrName),
					))
				}
			}

		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(t)
			}

		case xml.EndElement:
			if len(stack) > 0 {
				frame := stack[len(stack)-1]
				stack = stack[:len(stack)-1]

				text := strings.TrimSpace(frame.text.String())
				if text != "" && isHardcodedSecretField(frame.name, text) {
					out = append(out, xmlRawFinding(
						xmlHardcodedSecretRuleID,
						rel,
						frame.line,
						fmt.Sprintf("Hardcoded secret detected in element <%s>.", frame.name),
					))
				}
			}
		}
	}

	return out
}

func isXIncludeElement(e xml.StartElement) bool {
	return e.Name.Local == "include" && e.Name.Space == "http://www.w3.org/2001/XInclude"
}

func buildNamespaceMap(attrs []xml.Attr) map[string]string {
	m := make(map[string]string)
	for _, a := range attrs {
		if a.Name.Space == "xmlns" {
			m[a.Name.Local] = a.Value
		} else if a.Name.Local == "xmlns" {
			m[""] = a.Value
		}
	}
	return m
}

func isXsiSchemaAttr(local, space string, nsMap map[string]string) bool {
	if space == "http://www.w3.org/2001/XMLSchema-instance" {
		return local == "schemaLocation" || local == "noNamespaceSchemaLocation"
	}
	// Fallback prefix check
	parts := strings.Split(local, ":")
	if len(parts) == 2 {
		prefix := parts[0]
		attrLocal := parts[1]
		if nsMap[prefix] == "http://www.w3.org/2001/XMLSchema-instance" || prefix == "xsi" {
			return attrLocal == "schemaLocation" || attrLocal == "noNamespaceSchemaLocation"
		}
	}
	return false
}

func isExternalSchemaLocation(attrName, val string) bool {
	val = strings.TrimSpace(val)
	if val == "" {
		return false
	}

	var locations []string
	if strings.Contains(attrName, "noNamespaceSchemaLocation") {
		locations = []string{val}
	} else {
		// schemaLocation contains pairs: namespace location namespace location
		tokens := strings.Fields(val)
		if len(tokens) == 1 {
			locations = tokens
		} else {
			for i := 1; i < len(tokens); i += 2 {
				locations = append(locations, tokens[i])
			}
		}
	}

	for _, loc := range locations {
		if isExternalURI(loc) {
			return true
		}
	}
	return false
}

func isExternalURI(uri string) bool {
	u := strings.TrimSpace(uri)
	lower := strings.ToLower(u)

	if strings.HasPrefix(lower, "urn:") {
		return false
	}

	if strings.HasPrefix(u, "//") {
		return true
	}

	schemes := []string{"http:", "https:", "ftp:", "file:", "jar:"}
	for _, s := range schemes {
		if strings.HasPrefix(lower, s) {
			return true
		}
	}
	return false
}

var secretKeyNames = map[string]bool{
	"password":     true,
	"passwd":       true,
	"pwd":          true,
	"secret":       true,
	"clientsecret": true,
	"apikey":       true,
	"accesskey":    true,
	"privatekey":   true,
	"token":        true,
}

func isHardcodedSecretField(fieldName, value string) bool {
	normName := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(fieldName, "-", ""), "_", ""))
	if !secretKeyNames[normName] {
		return false
	}

	val := strings.TrimSpace(value)
	if len(val) < 6 {
		return false // Require minimum length
	}

	// Skip if numeric only
	if isNumericOnly(val) {
		return false
	}

	// Skip interpolation / placeholders
	if strings.HasPrefix(val, "${") || strings.HasPrefix(val, "$") ||
		strings.HasPrefix(val, "{{") || strings.HasPrefix(val, "#{") ||
		(strings.HasPrefix(val, "@") && strings.HasSuffix(val, "@")) ||
		strings.HasPrefix(val, "env:") || strings.HasPrefix(val, "vault:") {
		return false
	}

	// Skip masked or dummy placeholders
	upper := strings.ToUpper(val)
	if strings.Contains(upper, "***") || strings.Contains(upper, "XXX") ||
		strings.Contains(upper, "CHANGE_ME") || strings.Contains(upper, "CHANGEME") ||
		strings.Contains(upper, "TODO") || strings.Contains(upper, "EXAMPLE") ||
		strings.Contains(upper, "YOUR_") || strings.Contains(upper, "DUMMY") ||
		strings.Contains(val, "secretKeyRef") {
		return false
	}

	return true
}

func isNumericOnly(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
