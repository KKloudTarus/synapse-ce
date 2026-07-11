// DOCX report renderer. Consultancies live in Word, so the report ships as a real
// OOXML.docx – hand-built (no third-party DOCX dependency, matching the
// "light pure-Go" preference) so we fully control the bytes.
//
// Determinism (reproducible-report / chain-of-custody): the document content is a pure
// function of ports.ReportDocument, every ZIP entry uses a FIXED modification time,
// and the parts are written in a FIXED order – so identical engagement data yields
// byte-identical output and a reproducible SHA-256 seal. All dynamic text is
// XML-escaped (operator-authored finding text is untrusted).
package report

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"image"
	_ "image/gif"  // register GIF DecodeConfig
	_ "image/jpeg" // register JPEG DecodeConfig
	_ "image/png"  // register PNG DecodeConfig
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// EMU (English Metric Units) per pixel at 96 DPI, and the printable content width for
// a Letter page with 1in margins – used to size inline images deterministically.
const (
	emuPerPx        = 9525
	contentWidthEMU = 5943600 // 6.5in * 914400 EMU/in
)

// docxEpoch pins every ZIP entry's timestamp so the archive bytes don't vary with
// wall-clock time – the report's own GeneratedAt lives in the document text.
var docxEpoch = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// DOCXRenderer implements ports.DocRenderer for Word (.docx) output.
type DOCXRenderer struct{}

var _ ports.DocRenderer = (*DOCXRenderer)(nil)

// NewDOCXRenderer returns a Word report renderer.
func NewDOCXRenderer() *DOCXRenderer { return &DOCXRenderer{} }

// docxImage is one embedded image: its package part, relationship, and EMU display
// size. Assigned deterministically in section/image order.
type docxImage struct {
	seq      int    // global 1-based index (unique drawing/docPr id across the document)
	relID    string // e.g. "rId1001"
	target   string // relative to word/, e.g. "media/image1.png"
	partName string // full part name, e.g. "word/media/image1.png"
	ext      string // png|jpg|gif
	data     []byte
	emuW     int64
	emuH     int64
}

// collectImages assigns each image its embed metadata, returning the result keyed by
// section so documentXML can look an image up structurally (bySection[si][ii]) rather
// than re-walking in lockstep with a shared counter. flattenImages yields the same
// images in global order for the media parts + relationships.
func collectImages(doc ports.ReportDocument) [][]docxImage {
	bySection := make([][]docxImage, len(doc.Sections))
	n := 0
	for si, sec := range doc.Sections {
		bySection[si] = make([]docxImage, len(sec.Images))
		for ii, im := range sec.Images {
			n++
			ext := extForMIME(im.MIME)
			w, h := imageEMU(im.Data)
			bySection[si][ii] = docxImage{
				seq:      n,
				relID:    fmt.Sprintf("rId10%02d", n),
				target:   fmt.Sprintf("media/image%d.%s", n, ext),
				partName: fmt.Sprintf("word/media/image%d.%s", n, ext),
				ext:      ext,
				data:     im.Data,
				emuW:     w,
				emuH:     h,
			}
		}
	}
	return bySection
}

// flattenImages returns every image in global (section, then image) order.
func flattenImages(bySection [][]docxImage) []docxImage {
	var imgs []docxImage
	for _, sec := range bySection {
		imgs = append(imgs, sec...)
	}
	return imgs
}

// Render builds a minimal but valid OOXML.docx package for the document, embedding
// any image exhibits as inline pictures.
func (DOCXRenderer) Render(_ context.Context, doc ports.ReportDocument) ([]byte, error) {
	bySection := collectImages(doc)
	imgs := flattenImages(bySection)
	textParts := []struct{ name, body string }{
		{"[Content_Types].xml", contentTypesXML(imgs)},
		{"_rels/.rels", relsXML},
		{"word/_rels/document.xml.rels", docRelsXML(imgs)},
		{"word/styles.xml", stylesXML},
		{"word/document.xml", documentXML(doc, bySection)},
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range textParts {
		hdr := &zip.FileHeader{Name: p.name, Method: zip.Deflate, Modified: docxEpoch}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, fmt.Errorf("docx zip entry %s: %w", p.name, err)
		}
		if _, err := w.Write([]byte(p.body)); err != nil {
			return nil, fmt.Errorf("docx write %s: %w", p.name, err)
		}
	}
	// Media parts are already-compressed image bytes – Store (no deflate); fixed order
	// + fixed modtime keep the archive byte-deterministic.
	for _, im := range imgs {
		hdr := &zip.FileHeader{Name: im.partName, Method: zip.Store, Modified: docxEpoch}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, fmt.Errorf("docx media entry %s: %w", im.partName, err)
		}
		if _, err := w.Write(im.data); err != nil {
			return nil, fmt.Errorf("docx write %s: %w", im.partName, err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("docx finalize: %w", err)
	}
	return buf.Bytes(), nil
}

// documentXML assembles word/document.xml from the report document. bySection holds
// the embed metadata for each section's images (bySection[si][ii] ↔ Sections[si].
// Images[ii]) so the lookup is structural, not a counter walked in lockstep.
func documentXML(doc ports.ReportDocument, bySection [][]docxImage) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n")
	b.WriteString(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" ` +
		`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" ` +
		`xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"><w:body>`)

	b.WriteString(para("Title", doc.Title, false))
	b.WriteString(para("Subtitle", doc.Subtitle, false))

	for si, sec := range doc.Sections {
		b.WriteString(para("Heading1", sec.Heading, false))
		for _, p := range sec.Paragraphs {
			b.WriteString(para("", p, false))
		}
		if sec.Table != nil {
			b.WriteString(tableXML(sec.Table))
		}
		for ii, im := range sec.Images {
			b.WriteString(drawingXML(bySection[si][ii]))
			b.WriteString(para("Caption", im.Caption, false))
		}
	}

	// A trailing empty paragraph keeps Word happy when a section ends in a table,
	// then the section properties (Letter, 1in margins).
	b.WriteString(`<w:p/>`)
	b.WriteString(`<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>`)
	b.WriteString(`</w:body></w:document>`)
	return b.String()
}

// drawingXML renders an inline picture (the canonical wp:inline + pic:pic shape),
// using the image's global seq as the unique drawing/docPr/cNvPr id.
func drawingXML(im docxImage) string {
	id := fmt.Sprintf("%d", im.seq)
	cx := fmt.Sprintf("%d", im.emuW)
	cy := fmt.Sprintf("%d", im.emuH)
	return `<w:p><w:r><w:drawing>` +
		`<wp:inline distT="0" distB="0" distL="0" distR="0">` +
		`<wp:extent cx="` + cx + `" cy="` + cy + `"/>` +
		`<wp:docPr id="` + id + `" name="Exhibit ` + id + `"/>` +
		`<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">` +
		`<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">` +
		`<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">` +
		`<pic:nvPicPr><pic:cNvPr id="` + id + `" name="Exhibit ` + id + `"/><pic:cNvPicPr/></pic:nvPicPr>` +
		`<pic:blipFill><a:blip r:embed="` + im.relID + `"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>` +
		`<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="` + cx + `" cy="` + cy + `"/></a:xfrm>` +
		`<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>` +
		`</pic:pic></a:graphicData></a:graphic></wp:inline>` +
		`</w:drawing></w:r></w:p>`
}

// imageEMU returns the display size in EMU, capped to the printable content width with
// aspect preserved. An image that fails to decode falls back to a safe default box.
func imageEMU(data []byte) (int64, int64) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	w, h := 600, 400
	if err == nil && cfg.Width > 0 && cfg.Height > 0 {
		w, h = cfg.Width, cfg.Height
	}
	cx := int64(w) * emuPerPx
	cy := int64(h) * emuPerPx
	if cx > contentWidthEMU {
		cy = cy * contentWidthEMU / cx
		cx = contentWidthEMU
	}
	return cx, cy
}

// extForMIME maps an allowed raster MIME to its file extension (png|jpg|gif).
func extForMIME(mime string) string {
	switch mime {
	case "image/jpeg":
		return "jpg"
	case "image/gif":
		return "gif"
	default:
		return "png"
	}
}

// contentTypesXML builds [Content_Types].xml, adding a Default for each distinct image
// extension present so Word knows how to read the media parts.
func contentTypesXML(imgs []docxImage) string {
	exts := map[string]string{} // ext -> content type
	for _, im := range imgs {
		switch im.ext {
		case "jpg":
			exts["jpg"] = "image/jpeg"
		case "gif":
			exts["gif"] = "image/gif"
		default:
			exts["png"] = "image/png"
		}
	}
	var defs strings.Builder
	for _, ext := range []string{"png", "jpg", "gif"} { // fixed order → deterministic
		if ct, ok := exts[ext]; ok {
			defs.WriteString(`<Default Extension="` + ext + `" ContentType="` + ct + `"/>`)
		}
	}
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` + defs.String() +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>`
}

// docRelsXML builds word/_rels/document.xml.rels: the styles relationship plus one
// image relationship per embedded picture.
func docRelsXML(imgs []docxImage) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n")
	b.WriteString(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`)
	b.WriteString(`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`)
	for _, im := range imgs {
		b.WriteString(`<Relationship Id="` + im.relID + `" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="` + im.target + `"/>`)
	}
	b.WriteString(`</Relationships>`)
	return b.String()
}

// para renders a paragraph with an optional named style; multi-line text becomes
// line breaks within the paragraph.
func para(style, textVal string, bold bool) string {
	var b strings.Builder
	b.WriteString(`<w:p>`)
	if style != "" {
		// style is always a hardcoded constant, but escape it anyway so this stays
		// injection-safe if a dynamic style name is ever passed.
		b.WriteString(`<w:pPr><w:pStyle w:val="` + esc(style) + `"/></w:pPr>`)
	}
	b.WriteString(runs(textVal, bold))
	b.WriteString(`</w:p>`)
	return b.String()
}

// runs renders the run content for a paragraph/cell, turning newlines into <w:br/>.
func runs(textVal string, bold bool) string {
	rpr := ""
	if bold {
		rpr = `<w:rPr><w:b/></w:rPr>`
	}
	normalized := strings.ReplaceAll(textVal, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")
	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteString(`<w:r>` + rpr + `<w:br/></w:r>`)
		}
		b.WriteString(`<w:r>` + rpr + `<w:t xml:space="preserve">` + esc(line) + `</w:t></w:r>`)
	}
	return b.String()
}

// tableXML renders a bordered table; the header row is bold.
func tableXML(t *ports.ReportTable) string {
	var b strings.Builder
	b.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/><w:tblBorders>`)
	for _, edge := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
		b.WriteString(`<w:` + edge + ` w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>`)
	}
	b.WriteString(`</w:tblBorders></w:tblPr>`)
	if len(t.Headers) > 0 {
		b.WriteString(rowXML(t.Headers, true))
	}
	for _, row := range t.Rows {
		b.WriteString(rowXML(row, false))
	}
	b.WriteString(`</w:tbl>`)
	return b.String()
}

func rowXML(cells []string, header bool) string {
	var b strings.Builder
	b.WriteString(`<w:tr>`)
	for _, c := range cells {
		b.WriteString(`<w:tc><w:tcPr/><w:p>` + runs(c, header) + `</w:p></w:tc>`)
	}
	b.WriteString(`</w:tr>`)
	return b.String()
}

// esc XML-escapes dynamic text for inclusion in document.xml.
func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// relsXML and stylesXML are static; [Content_Types].xml and document.xml.rels are
// built per-document (contentTypesXML/docRelsXML) because images add parts + rels.
const relsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`

const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:pPr><w:spacing w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="40"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:pPr><w:spacing w:after="240"/></w:pPr><w:rPr><w:color w:val="666666"/><w:sz w:val="20"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="240" w:after="60"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Caption"><w:name w:val="caption"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="160"/></w:pPr><w:rPr><w:i/><w:color w:val="666666"/><w:sz w:val="18"/></w:rPr></w:style></w:styles>`
