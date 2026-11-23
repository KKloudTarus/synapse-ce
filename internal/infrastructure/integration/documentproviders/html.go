package documentproviders

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"html"
	"io"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const sourcePrefix = "<!--synapse-source:"

type htmlSource struct {
	Title, Storage, Marker string
	Files                  map[string]string `json:",omitempty"`
}

type attachmentRenderer func(name, id string, image bool) string

type canonicalFrame struct {
	name       string
	attachment bool
	linkOpened bool
}

// encodeCanonicalDocumentHTML turns the small storage markup language into a
// byte-stable document. The provider supplies only the already-owned attachment
// location; parsing, validation and the tamper-evident source envelope remain
// identical for every document provider.
func encodeCanonicalDocumentHTML(title, storage, marker string, files map[string]string, render attachmentRenderer) ([]byte, error) {
	if title == "" || len(title) > 4096 || len(storage) > 1<<20 || !validMarker(marker) || len(files) > 256 || render == nil {
		return nil, shared.ErrValidation
	}
	for name, id := range files {
		if !validAttachmentName(name) || !safeID(id) {
			return nil, shared.ErrValidation
		}
	}

	decoder := xml.NewDecoder(strings.NewReader("<root xmlns:ac=\"urn:ac\" xmlns:ri=\"urn:ri\">" + storage + "</root>"))
	var visible strings.Builder
	stack := make([]canonicalFrame, 0, 8)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, shared.ErrValidation
		}
		switch t := token.(type) {
		case xml.StartElement:
			if err := canonicalStart(&stack, t, files, render, &visible); err != nil {
				return nil, err
			}
		case xml.EndElement:
			if err := canonicalEnd(&stack, t, &visible); err != nil {
				return nil, err
			}
		case xml.CharData:
			if len(stack) == 0 || stack[len(stack)-1].name == "attachment" {
				if strings.TrimSpace(string(t)) != "" {
					return nil, shared.ErrValidation
				}
				continue
			}
			visible.WriteString(html.EscapeString(string(t)))
		default:
			return nil, shared.ErrValidation
		}
	}
	if len(stack) != 0 {
		return nil, shared.ErrValidation
	}
	source, err := json.Marshal(htmlSource{Title: title, Storage: storage, Marker: marker, Files: files})
	if err != nil {
		return nil, shared.ErrValidation
	}
	return []byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>" + html.EscapeString(title) + "</title></head><body>" + visible.String() + sourcePrefix + base64.StdEncoding.EncodeToString(source) + "--></body></html>"), nil
}

func canonicalStart(stack *[]canonicalFrame, start xml.StartElement, files map[string]string, render attachmentRenderer, visible *strings.Builder) error {
	name := start.Name.Local
	if len(*stack) == 0 {
		if name != "root" {
			return shared.ErrValidation
		}
		*stack = append(*stack, canonicalFrame{name: name})
		return nil
	}
	parent := &(*stack)[len(*stack)-1]
	switch name {
	case "h1", "p":
		if len(start.Attr) != 0 || parent.name != "root" {
			return shared.ErrValidation
		}
		visible.WriteString("<" + name + ">")
	case "code":
		// The release document carries the evidence-chain head and the content
		// hash as inline code inside a paragraph, so code is admitted at the root
		// and inside one paragraph. Nesting beyond that is still refused.
		if len(start.Attr) != 0 || (parent.name != "root" && parent.name != "p") {
			return shared.ErrValidation
		}
		visible.WriteString("<code>")
	case "link", "image":
		if len(start.Attr) != 0 || parent.name == "link" || parent.name == "image" || parent.name == "attachment" || parent.name == "plain-text-link-body" {
			return shared.ErrValidation
		}
	case "plain-text-link-body":
		if len(start.Attr) != 0 || parent.name != "link" || !parent.attachment {
			return shared.ErrValidation
		}
	case "attachment":
		if len(start.Attr) != 1 || start.Attr[0].Name.Local != "filename" || start.Attr[0].Name.Space != "urn:ri" && start.Attr[0].Name.Space != "" || (parent.name != "link" && parent.name != "image") || parent.attachment {
			return shared.ErrValidation
		}
		filename := start.Attr[0].Value
		id := files[filename]
		if !validAttachmentName(filename) || !safeID(id) {
			return shared.ErrValidation
		}
		parent.attachment = true
		if parent.name == "link" {
			visible.WriteString(render(filename, id, false))
			parent.linkOpened = true
		} else {
			visible.WriteString(render(filename, id, true))
		}
	default:
		return shared.ErrValidation
	}
	*stack = append(*stack, canonicalFrame{name: name})
	return nil
}

func canonicalEnd(stack *[]canonicalFrame, end xml.EndElement, visible *strings.Builder) error {
	if len(*stack) == 0 || (*stack)[len(*stack)-1].name != end.Name.Local {
		return shared.ErrValidation
	}
	frame := (*stack)[len(*stack)-1]
	*stack = (*stack)[:len(*stack)-1]
	switch frame.name {
	case "h1", "p", "code":
		visible.WriteString("</" + frame.name + ">")
	case "link":
		if !frame.attachment || !frame.linkOpened {
			return shared.ErrValidation
		}
		visible.WriteString("</a>")
	case "image":
		if !frame.attachment {
			return shared.ErrValidation
		}
	}
	return nil
}

func decodeCanonicalDocumentHTML(data []byte, encode func(string, string, string, map[string]string) ([]byte, error)) (htmlSource, error) {
	text := string(data)
	index := strings.LastIndex(text, sourcePrefix)
	if index < 0 {
		return htmlSource{}, docError(200, "unmanaged_body", false)
	}
	end := strings.Index(text[index:], "-->")
	if end < 0 {
		return htmlSource{}, docError(200, "unmanaged_body", false)
	}
	raw, err := base64.StdEncoding.DecodeString(text[index+len(sourcePrefix) : index+end])
	if err != nil {
		return htmlSource{}, docError(200, "invalid_source", false)
	}
	var source htmlSource
	if json.Unmarshal(raw, &source) != nil {
		return htmlSource{}, docError(200, "invalid_source", false)
	}
	canonical, err := encode(source.Title, source.Storage, source.Marker, source.Files)
	if err != nil || !bytes.Equal(canonical, data) {
		return htmlSource{}, docError(200, "remote_content_changed", false)
	}
	return source, nil
}
