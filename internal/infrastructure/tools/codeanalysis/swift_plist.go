package codeanalysis

import (
	"bytes"
	"encoding/xml"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	swiftATSDisabledRuleID = "swift:ats-disabled"
	maxPlistDepth          = 64
	maxPlistValues         = maxFindings * 8
)

type plistValue struct {
	kind string
	line int
	dict map[string]plistValue
}

type plistParser struct {
	dec        *xml.Decoder
	content    []byte
	lineStarts []int
	values     int
	limited    bool
}

func newPlistParser(content []byte) plistParser {
	lineStarts := []int{0}
	for i, b := range content {
		if b == '\n' {
			lineStarts = append(lineStarts, i+1)
		}
	}
	return plistParser{
		dec:        xml.NewDecoder(bytes.NewReader(content)),
		content:    content,
		lineStarts: lineStarts,
	}
}

func (p *plistParser) startLine() int {
	offset := int(p.dec.InputOffset())
	if offset > len(p.content) {
		offset = len(p.content)
	}
	for offset > 0 && p.content[offset-1] != '<' {
		offset--
	}
	return sort.SearchInts(p.lineStarts, offset+1)
}

// scanSwiftATSPlist parses only XML property-list key/value structure. It does
// not inspect plain text, binary plists, or unrelated XML keys.
func scanSwiftATSPlist(rel string, content []byte) []ports.CodeAnalysisRawFinding {
	findings, _ := scanSwiftATSPlistWithTruncation(rel, content)
	return findings
}

func scanSwiftATSPlistWithTruncation(rel string, content []byte) ([]ports.CodeAnalysisRawFinding, bool) {
	p := newPlistParser(content)
	for {
		tok, err := p.dec.Token()
		if err != nil {
			return nil, false
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		// A property list must be the document element. A nested <plist> in
		// arbitrary XML named Info.plist is not an Apple configuration file.
		if start.Name.Space != "" || start.Name.Local != "plist" {
			return nil, false
		}
		value, ok := p.parseValue(1)
		if !ok || value.kind != "dict" || !consumePlistEnd(p.dec, start.Name) {
			return nil, p.limited
		}
		ats, ok := value.dict["NSAppTransportSecurity"]
		if !ok || ats.kind != "dict" {
			return nil, false
		}
		out := make([]ports.CodeAnalysisRawFinding, 0, 4)
		emit := func(v plistValue, detail string) {
			if v.kind != "true" || len(out) >= maxFindings {
				return
			}
			out = append(out, ports.CodeAnalysisRawFinding{
				Kind:        kindSAST,
				RuleID:      swiftATSDisabledRuleID,
				CWE:         "CWE-319",
				Severity:    shared.SeverityHigh,
				Title:       "App Transport Security allows insecure loads",
				Description: detail,
				File:        rel,
				Line:        v.line,
			})
		}
		emit(ats.dict["NSAllowsArbitraryLoads"], "App Transport Security globally allows arbitrary cleartext loads.")
		emit(ats.dict["NSAllowsArbitraryLoadsInWebContent"], "App Transport Security permits arbitrary cleartext loads in web content.")
		emit(ats.dict["NSAllowsArbitraryLoadsForMedia"], "App Transport Security permits arbitrary cleartext loads for media.")
		if domains, ok := ats.dict["NSExceptionDomains"]; ok && domains.kind == "dict" {
			names := make([]string, 0, len(domains.dict))
			for domain := range domains.dict {
				names = append(names, domain)
			}
			sort.Strings(names)
			for _, domain := range names {
				config := domains.dict[domain]
				if config.kind != "dict" {
					continue
				}
				for _, key := range []string{"NSExceptionAllowsInsecureHTTPLoads", "NSTemporaryExceptionAllowsInsecureHTTPLoads"} {
					emit(config.dict[key], "App Transport Security permits insecure HTTP loads for domain "+domain+".")
				}
			}
		}
		return out, false
	}
}

func consumePlistEnd(dec *xml.Decoder, name xml.Name) bool {
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if end, ok := tok.(xml.EndElement); ok && end.Name == name {
			return true
		}
		chars, ok := tok.(xml.CharData)
		if !ok || strings.TrimSpace(string(chars)) != "" {
			return false
		}
	}
}

func consumePlistKey(dec *xml.Decoder, name xml.Name) (string, bool) {
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		switch tok := tok.(type) {
		case xml.CharData:
			text.Write([]byte(tok))
		case xml.EndElement:
			if tok.Name != name {
				return "", false
			}
			return text.String(), true
		default:
			return "", false
		}
	}
}

func (p *plistParser) parseValue(depth int) (plistValue, bool) {
	if depth > maxPlistDepth {
		p.limited = true
		return plistValue{}, false
	}
	for {
		tok, err := p.dec.Token()
		if err != nil {
			return plistValue{}, false
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Space != "" {
			return plistValue{}, false
		}
		p.values++
		if p.values > maxPlistValues {
			p.limited = true
			return plistValue{}, false
		}
		line := p.startLine()
		switch start.Name.Local {
		case "dict":
			v := plistValue{kind: "dict", line: line, dict: map[string]plistValue{}}
			for {
				tok, err := p.dec.Token()
				if err != nil {
					return plistValue{}, false
				}
				if end, ok := tok.(xml.EndElement); ok && end.Name == start.Name {
					return v, true
				}
				if chars, ok := tok.(xml.CharData); ok && strings.TrimSpace(string(chars)) == "" {
					continue
				}
				keyStart, ok := tok.(xml.StartElement)
				if !ok || keyStart.Name.Space != "" || keyStart.Name.Local != "key" {
					return plistValue{}, false
				}
				key, ok := consumePlistKey(p.dec, keyStart.Name)
				if !ok {
					return plistValue{}, false
				}
				child, ok := p.parseValue(depth + 1)
				if !ok || strings.TrimSpace(key) == "" {
					return plistValue{}, false
				}
				v.dict[key] = child
			}
		case "true", "false":
			if !consumePlistEnd(p.dec, start.Name) {
				return plistValue{}, false
			}
			return plistValue{kind: start.Name.Local, line: line}, true
		case "string", "integer", "real", "data", "date":
			if !consumePlistEnd(p.dec, start.Name) {
				return plistValue{}, false
			}
			return plistValue{kind: start.Name.Local, line: line}, true
		case "array":
			if !p.skipValue(start.Name, depth) {
				return plistValue{}, false
			}
			return plistValue{kind: start.Name.Local, line: line}, true
		default:
			return plistValue{}, false
		}
	}
}

func (p *plistParser) skipValue(name xml.Name, depth int) bool {
	for {
		tok, err := p.dec.Token()
		if err != nil {
			return false
		}
		switch tok := tok.(type) {
		case xml.EndElement:
			return tok.Name == name
		case xml.StartElement:
			if tok.Name.Space != "" {
				return false
			}
			if depth >= maxPlistDepth {
				p.limited = true
				return false
			}
			p.values++
			if p.values > maxPlistValues {
				p.limited = true
				return false
			}
			if !p.skipValue(tok.Name, depth+1) {
				return false
			}
		}
	}
}
