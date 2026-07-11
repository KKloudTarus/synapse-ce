package report

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// tinyPNG is a minimal valid 1x1 PNG for exhibit-embedding tests.
var tinyPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
	0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x62, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
	0x42, 0x60, 0x82,
}

func docWithImage() ports.ReportDocument {
	d := sampleDoc()
	d.Sections = append(d.Sections, ports.ReportSection{
		Heading:    "Evidence Exhibits",
		Paragraphs: []string{"Captured evidence."},
		Images: []ports.ReportImage{
			{Caption: "login.png  ·  sha256 deadbeefcafe", MIME: "image/png", Data: tinyPNG, SHA256: "deadbeefcafe"},
		},
	})
	return d
}

func TestHTMLEmbedsImageAsDataURI(t *testing.T) {
	out, err := NewHTMLRenderer().Render(context.Background(), docWithImage())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(out)
	// The data URI must be present and NOT replaced by html/template's unsafe-URL
	// marker (#ZgotmplZ) – i.e. imageDataURI correctly returns a trusted template.URL.
	if !strings.Contains(s, "<img src=\"data:image/png;base64,") {
		t.Error("expected an inline data-URI <img>")
	}
	if strings.Contains(s, "ZgotmplZ") {
		t.Error("html/template stripped the data URI as unsafe – imageDataURI must return template.URL")
	}
	if !strings.Contains(s, "<figcaption>login.png") {
		t.Error("expected the exhibit caption")
	}
}

func TestHTMLImageRenderDeterministic(t *testing.T) {
	r := NewHTMLRenderer()
	a, _ := r.Render(context.Background(), docWithImage())
	b, _ := r.Render(context.Background(), docWithImage())
	if !bytes.Equal(a, b) {
		t.Error("HTML with an image must render byte-deterministically")
	}
}

func TestDOCXEmbedsImagePartAndRelationship(t *testing.T) {
	out, err := NewDOCXRenderer().Render(context.Background(), docWithImage())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	files := unzipDOCX(t, out)

	// The image bytes are stored verbatim as a media part.
	media, ok := files["word/media/image1.png"]
	if !ok || !bytes.Equal(media, tinyPNG) {
		t.Fatal("expected word/media/image1.png with the exact image bytes")
	}
	// Content types declare the png default.
	if ct := string(files["[Content_Types].xml"]); !strings.Contains(ct, `Extension="png" ContentType="image/png"`) {
		t.Error("[Content_Types].xml must declare the png default")
	}
	// A relationship ties the drawing to the media part.
	rels := string(files["word/_rels/document.xml.rels"])
	if !strings.Contains(rels, `/relationships/image`) || !strings.Contains(rels, `Target="media/image1.png"`) {
		t.Errorf("document.xml.rels must carry the image relationship: %s", rels)
	}
	// document.xml references the picture by the same relationship id and is well-formed.
	docXML := files["word/document.xml"]
	ds := string(docXML)
	if !strings.Contains(ds, "<w:drawing>") || !strings.Contains(ds, `r:embed="rId1001"`) {
		t.Error("document.xml must contain an inline drawing referencing the image rId")
	}
	if !strings.Contains(ds, "Evidence Exhibits") {
		t.Error("exhibits heading missing from document.xml")
	}
	if err := xmlWellFormed(docXML); err != nil {
		t.Errorf("document.xml is not well-formed XML: %v", err)
	}
	if err := xmlWellFormed(files["[Content_Types].xml"]); err != nil {
		t.Errorf("[Content_Types].xml is not well-formed: %v", err)
	}
}

func TestDOCXImageRenderDeterministic(t *testing.T) {
	r := NewDOCXRenderer()
	a, _ := r.Render(context.Background(), docWithImage())
	b, _ := r.Render(context.Background(), docWithImage())
	if !bytes.Equal(a, b) {
		t.Error("DOCX with an image must render byte-deterministically (stable seal)")
	}
}

func unzipDOCX(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("open docx zip: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		out[f.Name] = b
	}
	return out
}

// xmlWellFormed confirms the bytes parse as XML (every token decodes).
func xmlWellFormed(b []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
