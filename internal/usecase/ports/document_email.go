package ports

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DocumentPDFMail is assembled from a frozen stored-source artifact. Relay and
// BeforeData exist only at execution; neither belongs in a job or audit payload.
type DocumentPDFMail struct {
	Recipient  string
	Subject    string
	Text       string
	HTML       string
	Filename   string
	PDF        []byte
	MessageID  shared.ID
	Relay      *SMTPRelayConfig
	BeforeData func(context.Context) error
}
type DocumentEmailResult struct {
	Accepted  bool
	Ambiguous bool
	Retryable bool
	ErrorCode string
}
type DocumentPDFSender interface {
	SendDocumentPDF(context.Context, DocumentPDFMail) DocumentEmailResult
}
