package documentproviders

import (
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// releaseStorageDocument mirrors storageDocument in
// internal/usecase/docpublish/storage.go: the markup every document provider
// receives for a real release. The use case cannot be imported here (the
// dependency rule points inward), so the shape is restated. Change it in step
// with that function.
func releaseStorageDocument(pdf, hash, marker string) string {
	return `<h1>Engagement report</h1>` +
		`<p>Scope: one repository.</p>` +
		`<p><ac:link><ri:attachment ri:filename="` + pdf + `" /><ac:plain-text-link-body><![CDATA[PDF report]]></ac:plain-text-link-body></ac:link></p>` +
		`<p>Evidence chain head: <code>none (no verified evidence-chain head is available)</code></p>` +
		`<p>Content SHA-256: <code>` + hash + `</code></p>` +
		`<p>` + marker + `</p>`
}

// TestEveryRendererAcceptsTheReleaseDocument is the regression for a release
// that reached the body step and could not render it: the document carries
// inline code inside a paragraph, and a renderer that refuses it turns every
// publication into an uncertain outcome with nothing written.
func TestEveryRendererAcceptsTheReleaseDocument(t *testing.T) {
	const (
		marker = "synapse-intent-c745bcf226ebaf2baa5a7fa28789ddc0"
		hash   = "dfbce70dcf1c54af9540601a7401830fdf61386d8ac888c9fbebc56320054bed"
		pdf    = "report-dfbce70dcf1c54af.pdf"
	)
	storage := releaseStorageDocument(pdf, hash, marker)
	for _, tc := range []struct {
		name   string
		files  map[string]string
		encode func(string, string, string, map[string]string) ([]byte, error)
		decode func([]byte) (htmlSource, error)
	}{
		{name: "google drive", files: map[string]string{pdf: "1AbCdEfGhIjKlMnOpQ"}, encode: encodeDocumentHTML, decode: driveSource},
		{name: "microsoft graph", files: map[string]string{pdf: "1AbCdEfGhIjKlMnOpQ"}, encode: encodeGraphHTML, decode: decodeGraphHTML},
		{name: "s3-compatible", files: map[string]string{pdf: "fdcbb6a27c4a1b2e3f4051627384950a"}, encode: encodeS3HTML, decode: decodeS3HTML},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rendered, err := tc.encode("Engagement report", storage, marker, tc.files)
			if err != nil {
				t.Fatalf("render the release document: %v", err)
			}
			if !strings.Contains(string(rendered), "<code>"+hash+"</code>") {
				t.Fatalf("the content hash must stay visible as inline code: %s", rendered)
			}
			source, err := tc.decode(rendered)
			if err != nil {
				t.Fatalf("decode the rendered document: %v", err)
			}
			if source.Storage != storage || source.Marker != marker {
				t.Fatalf("the stored source must round-trip exactly: %+v", source)
			}
		})
	}
}

// TestInlineCodeNestingStaysBounded keeps the admitted nesting to the one shape
// the release document uses. Anything deeper is still refused.
func TestInlineCodeNestingStaysBounded(t *testing.T) {
	const marker = "synapse-intent-c745bcf226ebaf2baa5a7fa28789ddc0"
	for _, storage := range []string{
		`<p><code><code>x</code></code></p>`,
		`<p><p>x</p></p>`,
		`<code><p>x</p></code>`,
		`<p><h1>x</h1></p>`,
		`<p><code class="x">x</code></p>`,
	} {
		if _, err := encodeS3HTML("T", storage, marker, nil); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("storage %q must be refused, got %v", storage, err)
		}
	}
}

func driveSource(data []byte) (htmlSource, error) {
	return decodeCanonicalDocumentHTML(data, encodeDocumentHTML)
}
