package report

import (
	"context"
	"fmt"
	"strings"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RenderDocumentArtifact projects a bounded stored-source artifact to a
// deterministic PDF. The caller owns source authorization and image attachment
// uploads; this renderer only presents already-validated text and provenance.
func (Renderer) RenderDocumentArtifact(_ context.Context, artifact ports.DocumentArtifact) ([]byte, error) {
	if err := validDocumentArtifactProjection(artifact); err != nil {
		return nil, err
	}
	at := artifact.GeneratedAt.UTC()
	cfg, err := documentConfig(at)
	if err != nil {
		return nil, err
	}
	m := maroto.New(cfg)
	m.AddRow(16, text.NewCol(12, artifact.Title, props.Text{Size: 18, Style: fontstyle.Bold, Align: align.Center}))
	m.AddRow(6, text.NewCol(12,
		"Generated "+at.Format("2006-01-02 15:04 UTC")+" · Stored-source document projection",
		props.Text{Size: 8, Align: align.Center, Color: gray()}))
	section(m, "Source provenance")
	m.AddRow(5, text.NewCol(12, "Source revision: "+artifact.SourceRevision, props.Text{Size: 8, Color: gray()}))
	evidenceHead := artifact.EvidenceHead
	if evidenceHead == "" {
		evidenceHead = "none (no verified evidence-chain head is available)"
	}
	m.AddRow(5, text.NewCol(12, "Evidence head (sha256): "+evidenceHead, props.Text{Size: 8, Color: gray()}))
	if len(artifact.Images) > 0 {
		m.AddRow(5, text.NewCol(12, fmt.Sprintf("Verified attachments: %d (uploaded separately to preserve page restriction order).", len(artifact.Images)), props.Text{Size: 8, Color: gray()}))
	}
	section(m, "Summary")
	for _, paragraph := range artifact.Paragraphs {
		m.AddRow(7, text.NewCol(12, paragraph, props.Text{Size: 9}))
	}
	section(m, "Provenance")
	m.AddRow(8, text.NewCol(12,
		"This document is rendered from stored, verified records. No generated or model-authored content is included.",
		props.Text{Size: 7, Align: align.Center, Color: gray()}))
	doc, err := m.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate document artifact PDF: %w", err)
	}
	return pinModDate(doc.GetBytes()), nil
}

func validDocumentArtifactProjection(artifact ports.DocumentArtifact) error {
	if strings.TrimSpace(artifact.Title) == "" || strings.TrimSpace(artifact.SourceRevision) == "" || artifact.GeneratedAt.IsZero() || len(artifact.Paragraphs) == 0 {
		return fmt.Errorf("invalid document artifact PDF projection")
	}
	return nil
}

var _ ports.DocumentArtifactPDFRenderer = (*Renderer)(nil)
