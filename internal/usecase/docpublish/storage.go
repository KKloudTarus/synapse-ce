package docpublish

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"strings"
)

func xmlText(v string) string {
	var out bytes.Buffer
	_ = xml.EscapeText(&out, []byte(v))
	return out.String()
}

// storageDocument emits a closed set of elements. Artifact text is always an XML
// text node; it cannot create macros, scripts, mentions or remote image requests.
func storageDocument(c ports.DocumentCommand) string {
	var out strings.Builder
	out.WriteString("<h1>" + xmlText(c.Artifact.Title) + "</h1>")
	for _, p := range c.Artifact.Paragraphs {
		out.WriteString("<p>" + xmlText(p) + "</p>")
	}
	out.WriteString(`<p><ac:link><ri:attachment ri:filename="` + xmlText(pdfName(c)) + `" /><ac:plain-text-link-body><![CDATA[PDF report]]></ac:plain-text-link-body></ac:link></p>`)
	for _, image := range c.Artifact.Images {
		out.WriteString(`<ac:image><ri:attachment ri:filename="` + xmlText(image.Name) + `" /></ac:image>`)
	}
	head := c.Artifact.EvidenceHead
	if head == "" {
		head = "none (no verified evidence-chain head is available)"
	}
	out.WriteString("<p>Evidence chain head: <code>" + xmlText(head) + "</code></p>")
	out.WriteString("<p>Content SHA-256: <code>" + c.Intent.ContentHash + "</code></p>")
	out.WriteString("<p>" + xmlText(c.Intent.Marker) + "</p>")
	return out.String()
}

func pdfName(c ports.DocumentCommand) string { return "report-" + c.Intent.ContentHash[:16] + ".pdf" }
func attachments(c ports.DocumentCommand) []ports.DocumentImage {
	out := make([]ports.DocumentImage, 0, 1+len(c.Artifact.Images))
	out = append(out, ports.DocumentImage{Name: pdfName(c), MediaType: "application/pdf", Data: c.Artifact.PDF})
	out = append(out, c.Artifact.Images...)
	return out
}
func uploadKey(i int, image ports.DocumentImage) string {
	return fmt.Sprintf("attachment:%d:%s", i, digest(image.Data))
}
func validateLiterals(p ports.DocumentProvider, a ports.DocumentArtifact) error {
	values := append([]string{a.Title, a.SourceRevision}, a.Paragraphs...)
	if a.EvidenceHead != "" {
		values = append(values, a.EvidenceHead)
	}
	for _, v := range values {
		if err := p.ValidateDocumentText(v); err != nil {
			return err
		}
	}
	for _, image := range a.Images {
		if err := p.ValidateDocumentText(image.Name); err != nil {
			return err
		}
	}
	return nil
}
