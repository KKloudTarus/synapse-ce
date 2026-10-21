package documentproviders

import (
	"html"
	"net/url"
)

// encodeGraphHTML keeps the structured source in an inert canonical comment and
// renders attachment references as same-folder relative paths. It never embeds a
// Graph or SharePoint URL supplied by the provider.
func encodeGraphHTML(title, storage, marker string, files map[string]string) ([]byte, error) {
	return encodeCanonicalDocumentHTML(title, storage, marker, files, graphAttachmentHTML)
}

func graphAttachmentHTML(filename, _ string, image bool) string {
	relative := "./" + url.PathEscape(filename)
	if image {
		return "<img alt=\"" + html.EscapeString(filename) + "\" src=\"" + html.EscapeString(relative) + "\">"
	}
	return "<a href=\"" + html.EscapeString(relative) + "\" rel=\"noreferrer\">"
}

func decodeGraphHTML(data []byte) (htmlSource, error) {
	return decodeCanonicalDocumentHTML(data, encodeGraphHTML)
}

func validAttachmentName(name string) bool {
	return name != "" && len(name) <= 255 && name != "report.html" && name != graphManifestName && !containsUnsafeAttachmentRune(name)
}

func containsUnsafeAttachmentRune(name string) bool {
	for _, r := range name {
		if r == '/' || r == '\\' || r == '?' || r == '#' || r == '\r' || r == '\n' || r == 0 {
			return true
		}
	}
	return false
}
