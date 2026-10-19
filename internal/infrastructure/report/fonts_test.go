package report

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/image/font/sfnt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const vietnamesePDFText = "Báo cáo bảo mật — Kiểm tra phân quyền: ĐđĂăÂâÊêÔôƠơƯư àáảãạ èéẻẽẹ ìíỉĩị òóỏõọ ùúủũụ ỳýỷỹỵ"

var vietnameseGlyphCoverage = vietnamesePDFText + vietnameseExtendedRunes()

func vietnameseExtendedRunes() string {
	var runes strings.Builder
	for r := rune(0x1EA0); r <= 0x1EF9; r++ {
		runes.WriteRune(r)
	}
	return runes.String()
}

func TestReportFontsCoverVietnamese(t *testing.T) {
	for _, candidate := range []struct {
		name string
		data []byte
	}{
		{name: "regular", data: reportRegularFont},
		{name: "bold", data: reportBoldFont},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			font, err := sfnt.Parse(candidate.data)
			if err != nil {
				t.Fatalf("parse %s font: %v", candidate.name, err)
			}
			var buffer sfnt.Buffer
			for _, r := range vietnameseGlyphCoverage {
				if r == ' ' {
					continue
				}
				glyph, err := font.GlyphIndex(&buffer, r)
				if err != nil {
					t.Fatalf("look up %q in %s font: %v", r, candidate.name, err)
				}
				if glyph == 0 {
					t.Fatalf("%s font has no glyph for %q", candidate.name, r)
				}
			}
		})
	}
}

func TestPDFRenderersEmbedUnicodeFontAndPreserveVietnamese(t *testing.T) {
	at := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	renderer := NewRenderer()
	cases := []struct {
		name   string
		render func() ([]byte, error)
	}{
		{
			name: "report",
			render: func() ([]byte, error) {
				return renderer.Render(context.Background(), &engagement.Engagement{Name: vietnamesePDFText}, nil, ports.ReportInsight{}, at, "v1")
			},
		},
		{
			name: "document artifact",
			render: func() ([]byte, error) {
				return renderer.RenderDocumentArtifact(context.Background(), ports.DocumentArtifact{
					Title:          vietnamesePDFText,
					Paragraphs:     []string{vietnamesePDFText},
					SourceRevision: "test-revision",
					GeneratedAt:    at,
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pdf, err := tc.render()
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if !bytes.Contains(pdf, []byte("/FontFile2")) {
				t.Fatal("PDF does not embed a TrueType Unicode font")
			}
			if text := extractPDFText(t, pdf); !strings.Contains(strings.Join(strings.Fields(text), " "), vietnamesePDFText) {
				t.Fatalf("extracted PDF text lost Vietnamese glyphs: %q", text)
			}
		})
	}
}

func extractPDFText(t *testing.T, pdf []byte) string {
	t.Helper()
	path, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext is not installed")
	}
	directory := t.TempDir()
	input := filepath.Join(directory, "report.pdf")
	if err := os.WriteFile(input, pdf, 0o600); err != nil {
		t.Fatalf("write PDF for text extraction: %v", err)
	}
	output, err := exec.Command(path, "-enc", "UTF-8", input, "-").Output()
	if err != nil {
		t.Fatalf("extract PDF text: %v", err)
	}
	return string(output)
}
