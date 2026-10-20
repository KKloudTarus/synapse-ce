package documentproviders

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"html"
	"io"
	"net/url"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// encodeGraphHTML keeps the structured source in an inert canonical comment and
// renders attachment references as same-folder relative paths. It never embeds a
// Graph or SharePoint URL supplied by the provider.
func encodeGraphHTML(title, storage, marker string, files map[string]string) ([]byte, error) {
	if title == "" || len(title) > 4096 || len(storage) > 1<<20 || !validMarker(marker) || len(files) > 256 {
		return nil, shared.ErrValidation
	}
	for name, id := range files {
		if !validAttachmentName(name) || !safeID(id) {
			return nil, shared.ErrValidation
		}
	}
	decoder := xml.NewDecoder(strings.NewReader("<root xmlns:ac=\"urn:ac\" xmlns:ri=\"urn:ri\">" + storage + "</root>"))
	var visible strings.Builder
	inLink, inImage, linkOpened := false, false, false
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
			switch t.Name.Local {
			case "root", "h1", "p", "code", "plain-text-link-body":
				if t.Name.Local == "h1" || t.Name.Local == "p" || t.Name.Local == "code" {
					if len(t.Attr) != 0 {
						return nil, shared.ErrValidation
					}
					visible.WriteString("<" + t.Name.Local + ">")
				}
			case "link":
				if inLink || inImage || len(t.Attr) != 0 {
					return nil, shared.ErrValidation
				}
				inLink, linkOpened = true, false
			case "image":
				if inLink || inImage || len(t.Attr) != 0 {
					return nil, shared.ErrValidation
				}
				inImage = true
			case "attachment":
				filename := ""
				for _, attr := range t.Attr {
					if attr.Name.Local != "filename" || filename != "" {
						return nil, shared.ErrValidation
					}
					filename = attr.Value
				}
				if !validAttachmentName(filename) || !safeID(files[filename]) {
					return nil, shared.ErrValidation
				}
				relative := "./" + url.PathEscape(filename)
				if inImage {
					visible.WriteString("<img alt=\"" + html.EscapeString(filename) + "\" src=\"" + html.EscapeString(relative) + "\">")
				} else if inLink && !linkOpened {
					visible.WriteString("<a href=\"" + html.EscapeString(relative) + "\" rel=\"noreferrer\">")
					linkOpened = true
				} else {
					return nil, shared.ErrValidation
				}
			default:
				return nil, shared.ErrValidation
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "h1", "p", "code":
				visible.WriteString("</" + t.Name.Local + ">")
			case "link":
				if !linkOpened {
					return nil, shared.ErrValidation
				}
				visible.WriteString("</a>")
				inLink, linkOpened = false, false
			case "image":
				inImage = false
			}
		case xml.CharData:
			visible.WriteString(html.EscapeString(string(t)))
		default:
			return nil, shared.ErrValidation
		}
	}
	if inLink || inImage {
		return nil, shared.ErrValidation
	}
	source, _ := json.Marshal(htmlSource{Title: title, Storage: storage, Marker: marker, Files: files})
	return []byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>" + html.EscapeString(title) + "</title></head><body>" + visible.String() + sourcePrefix + base64.StdEncoding.EncodeToString(source) + "--></body></html>"), nil
}

func decodeGraphHTML(data []byte) (htmlSource, error) {
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
	canonical, err := encodeGraphHTML(source.Title, source.Storage, source.Marker, source.Files)
	if err != nil || !bytes.Equal(canonical, data) {
		return htmlSource{}, docError(200, "remote_content_changed", false)
	}
	return source, nil
}

func validAttachmentName(name string) bool {
	return name != "" && len(name) <= 255 && name != "report.html" && name != graphManifestName && !strings.ContainsAny(name, "/\\\r\n\x00")
}
