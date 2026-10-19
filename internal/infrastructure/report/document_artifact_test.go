package report

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestRenderDocumentArtifactDeterministicWithVietnamese(t *testing.T) {
	artifact := ports.DocumentArtifact{
		Title:          "Tổng kết chất lượng dự án",
		Paragraphs:     []string{"Báo cáo dùng dữ liệu đã lưu và đã xác minh.", "Không có nội dung do mô hình tạo."},
		EvidenceHead:   strings.Repeat("a", 64),
		SourceRevision: "analysis:quality-2026-10",
		GeneratedAt:    time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC),
	}
	renderer := NewRenderer()
	first, err := renderer.RenderDocumentArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	second, err := renderer.RenderDocumentArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatalf("repeat render: %v", err)
	}
	if !bytes.HasPrefix(first, []byte("%PDF-")) {
		t.Fatalf("artifact projection is not PDF: %q", first[:min(8, len(first))])
	}
	if !bytes.Equal(first, second) {
		t.Fatal("artifact PDF must be deterministic for identical stored input")
	}
}
